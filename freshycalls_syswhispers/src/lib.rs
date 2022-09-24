#![allow(dead_code)]

use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PEB, ntpsapi::PEB_LDR_DATA};
use std::{arch::asm, collections::BTreeMap, ffi::CStr};
use sysinfo::{ProcessExt, SystemExt};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64},
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
    },
};

const NTDLL_HASH: u32 = 0x1edab0ed;
const NT_OPEN_PROCESS_HASH: u32 = 0x4b82f718;
const NT_ALLOCATE_VIRTUAL_MEMORY_HASH: u32 = 0xf783b8ec;
const NT_PROTECT_VIRTUAL_MEMORY_HASH: u32 = 0x50e92888;
const NT_WRITE_VIRTUAL_MEMORY_HASH: u32 = 0xc3170192;
const NT_CREATE_THREAD_EX_HASH: u32 = 0xaf18cfb0;

// Do unit testing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        env_logger::init();

        let ntdll_base_address = unsafe {
            get_loaded_module_by_hash(NTDLL_HASH).expect("Failed to get loaded module by name")
        };

        log::debug!("[+] NTDLL Address: {:p}", ntdll_base_address);

        let nt_open_process_syscall =
            freshycalls_syswhispers(ntdll_base_address, NT_OPEN_PROCESS_HASH)
                .expect("Failed to call freshycalls/syswhispers");
        let nt_allocate_virtual_memory_syscall =
            freshycalls_syswhispers(ntdll_base_address, NT_ALLOCATE_VIRTUAL_MEMORY_HASH)
                .expect("Failed to call freshycalls/syswhispers");
        let nt_protect_virtual_memory_syscall =
            freshycalls_syswhispers(ntdll_base_address, NT_PROTECT_VIRTUAL_MEMORY_HASH)
                .expect("Failed to call freshycalls/syswhispers");
        let nt_write_virtual_memory_syscall =
            freshycalls_syswhispers(ntdll_base_address, NT_WRITE_VIRTUAL_MEMORY_HASH)
                .expect("Failed to call freshycalls/syswhispers");
        let nt_create_thread_ex_syscall =
            freshycalls_syswhispers(ntdll_base_address, NT_CREATE_THREAD_EX_HASH)
                .expect("Failed to call freshycalls/syswhispers");

        log::debug!("[+] NtOpenProcess Syscall: {:#x}", nt_open_process_syscall);
        log::debug!(
            "[+] NtAllocateVirtualMemory Syscall: {:#x}",
            nt_allocate_virtual_memory_syscall
        );
        log::debug!(
            "[+] NtProtectVirtualMemory Syscall: {:#x}",
            nt_protect_virtual_memory_syscall
        );
        log::debug!(
            "[+] NtWriteVirtualMemory Syscall: {:#x}",
            nt_write_virtual_memory_syscall
        );
        log::debug!("[+] NtCreateThreadEx: {:#x}", nt_create_thread_ex_syscall);

        // Tested on Microsoft Windows 10 Home  10.0.19044 N/A Build 19044 (Unit test will fail in other build versions if syscalls IDs are different)
        assert_eq!(nt_open_process_syscall, 0x26);
        assert_eq!(nt_allocate_virtual_memory_syscall, 0x18);
        assert_eq!(nt_protect_virtual_memory_syscall, 0x50);
        assert_eq!(nt_write_virtual_memory_syscall, 0x3a);
        assert_eq!(nt_create_thread_ex_syscall, 0xc1);

        //assert_eq!(nt_create_thread_ex_syscall, 0x1337); // testing fail test
    }
}

pub fn freshycalls_syswhispers(module_base: *mut u8, module_hash: u32) -> Option<u16> {
    let mut nt_exports = BTreeMap::new();

    for (name, addr) in unsafe { get_exports_by_name(module_base) } {
        //
        // FreshyCalls
        //

        /*
            // Check to see if stubs starts with Nt but not with Ntdll

            if name.starts_with("Nt") && !name.starts_with("Ntdll") {
                nt_exports.insert(name, addr);
            }

        */

        //
        // Syswhispers2 Patch
        //

        // Check to see if stubs starts with Zw and replace with Nt
        if name.starts_with("Zw") {
            nt_exports.insert(name.replace("Zw", "Nt"), addr);
        }
    }

    let mut nt_exports_vec: Vec<(String, usize)> = Vec::from_iter(nt_exports);
    // sort all Nt functions by address
    nt_exports_vec.sort_by_key(|k| k.1);

    // First Nt addresses has system call number of 0 and so on...

    let mut syscall_number: u16 = 0;

    for exports in nt_exports_vec {
        if module_hash == dbj2_hash(exports.0.as_bytes()) {
            return Some(syscall_number);
        }
        syscall_number += 1;
    }

    return None;
}

/// Get process ID by name
pub fn get_process_id_by_name(target_process: &str) -> usize {
    let mut system = sysinfo::System::new();
    system.refresh_all();

    let mut process_id: usize = 0;

    for process in system.process_by_name(target_process) {
        process_id = process.pid();
    }
    return process_id;
}

/// Gets a pointer to IMAGE_NT_HEADERS32 x86
#[cfg(target_arch = "x86")]
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<*mut IMAGE_NT_HEADERS32> {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_headers =
        (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ {
        return None;
    }

    return Some(nt_headers);
}

/// Gets a pointer to IMAGE_NT_HEADERS32 x86_64
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<*mut IMAGE_NT_HEADERS64> {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_headers =
        (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ {
        return None;
    }

    return Some(nt_headers);
}

/// Gets a pointer to the Thread Environment Block (TEB)
#[cfg(target_arch = "x86")]
pub unsafe fn get_teb() -> *mut ntapi::ntpebteb::TEB {
    let teb: *mut ntapi::ntpebteb::TEB;
    asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);
    teb
}

/// Get a pointer to the Thread Environment Block (TEB)
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_teb() -> *mut ntapi::ntpebteb::TEB {
    let teb: *mut ntapi::ntpebteb::TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

/// Get a pointer to the Process Environment Block (PEB)
pub unsafe fn get_peb() -> *mut PEB {
    let teb = get_teb();
    let peb = (*teb).ProcessEnvironmentBlock;
    peb
}

/// Get loaded module by hash
pub unsafe fn get_loaded_module_by_hash(module_hash: u32) -> Option<*mut u8> {
    let peb = get_peb();
    let peb_ldr_data_ptr = (*peb).Ldr as *mut PEB_LDR_DATA;

    let mut module_list =
        (*peb_ldr_data_ptr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() {
        let dll_buffer_ptr = (*module_list).BaseDllName.Buffer;
        let dll_length = (*module_list).BaseDllName.Length as usize;
        let dll_name_slice = core::slice::from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        if module_hash == dbj2_hash(dll_name_slice) {
            return Some((*module_list).DllBase as _);
        }

        module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }

    return None;
}

/// Get the address of an export by hash
pub unsafe fn get_exports_by_name(module_base: *mut u8) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();
    let nt_headers = get_nt_headers(module_base).unwrap();

    let export_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY;

    let names = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32,
        (*export_directory).NumberOfNames as _,
    );

    let functions = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );

    let ordinals = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    for i in 0..(*export_directory).NumberOfNames {
        let name_addr = (module_base as usize + names[i as usize] as usize) as *const i8;

        if let Ok(name) = CStr::from_ptr(name_addr).to_str() {
            let ordinal = ordinals[i as usize] as usize;

            exports.insert(
                name.to_string(),
                module_base as usize + functions[ordinal] as usize,
            );
        }
    }

    return exports;
}

/// Generate a unique hash
pub fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];
        if cur == 0 {
            iter += 1;
            continue;
        }
        if cur >= ('a' as u8) {
            cur -= 0x20;
        }
        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    return hsh;
}

/// Get the length of a C String
pub fn get_cstr_len(pointer: *const char) -> usize {
    let mut tmp: u64 = pointer as u64;

    unsafe {
        while *(tmp as *const u8) != 0 {
            tmp += 1;
        }
    }
    (tmp - pointer as u64) as _
}

/// Checks to see if the architecture x86 or x86_64
pub fn is_wow64() -> bool {
    // A usize is 4 bytes on 32 bit and 8 bytes on 64 bit
    if std::mem::size_of::<usize>() == 4 {
        return false;
    }

    return true;
}
