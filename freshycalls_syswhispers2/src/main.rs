use std::collections::BTreeMap;

use pemadness::get_exports_by_name;

use crate::pemadness::{dbj2_hash, get_loaded_module_by_hash};

mod pemadness;

const NTDLL_HASH: u32 = 0x1edab0ed;

fn main() {
    env_logger::init();

    let ntdll_base_address = unsafe {
        get_loaded_module_by_hash(NTDLL_HASH).expect("Failed to get loaded module by name")
    };

    log::debug!("[+] NTDLL Address: {:p}", ntdll_base_address);

    let syscall_no =
        freshycalls_syswhispers2(ntdll_base_address, dbj2_hash("NtOpenProcess".as_bytes()))
            .expect("Failed to call syswhispers2");

    log::debug!("[+] System Call Number: {:#x}", syscall_no);
}

fn freshycalls_syswhispers2(module_base: *mut u8, module_hash: u32) -> Option<u16> {
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

    for x in &nt_exports_vec {
        log::debug!("{}, {:#x}", x.0, x.1);
    }

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
