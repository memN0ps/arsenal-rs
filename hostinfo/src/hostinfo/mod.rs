use std::mem::size_of;

use ntapi::winapi::{
    shared::ntdef::NT_SUCCESS,
    um::{processenv::SetCurrentDirectoryW, winnt::OSVERSIONINFOEXW},
};

use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, MAX_PATH, NO_ERROR, NTSTATUS, PSID},
    Globalization::{MultiByteToWideChar, CP_UTF8},
    NetworkManagement::IpHelper::{GetAdaptersInfo, IP_ADAPTER_INFO},
    Security::{
        GetTokenInformation, IsWellKnownSid, TokenElevation, TokenIntegrityLevel, WinHighLabelSid,
        WinLowLabelSid, WinMediumLabelSid, WinSystemLabelSid, WinUntrustedLabelSid,
        TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_QUERY_SOURCE,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
        Environment::GetCurrentDirectoryW,
        SystemInformation::{
            ComputerNameDnsDomain, ComputerNamePhysicalDnsFullyQualified, GetComputerNameExW,
        },
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, IsWow64Process, OpenProcessToken,
            QueryFullProcessImageNameW,
        },
        WindowsProgramming::GetUserNameW,
    },
};

/// Gets the username and returns a Result
pub fn get_username() -> Result<String, String> {
    let mut username = [0u16; MAX_PATH as usize];
    let mut username_len = username.len() as u32;

    if unsafe { GetUserNameW(username.as_mut_ptr(), &mut username_len) == 0 } {
        return Err("Failed to call 2nd GetUserNameW in get_username function".to_owned());
    }

    return Ok(String::from_utf16(&username)
        .unwrap()
        .trim_end_matches("\0")
        .to_owned());
}

/// Gets the hostname and returns a Result
pub fn get_hostname() -> Result<String, String> {
    let mut computer_name = [0u16; MAX_PATH as usize];
    let mut comptuer_name_len = computer_name.len() as u32;

    if unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsFullyQualified,
            computer_name.as_mut_ptr(),
            &mut comptuer_name_len,
        ) == 0
    } {
        return Err(
            "Failed to call the 2nd GetComputerNameExW in get_hostname function".to_owned(),
        );
    }

    return Ok(String::from_utf16(&computer_name)
        .unwrap()
        .trim_end_matches("\0")
        .to_owned());
}

/// Gets the domain name and returns the Result
pub fn get_domain_name() -> Result<String, String> {
    let mut domain_name = [0u16; MAX_PATH as usize];
    let mut domain_name_len = domain_name.len() as u32;

    if unsafe {
        GetComputerNameExW(
            ComputerNameDnsDomain,
            domain_name.as_mut_ptr(),
            &mut domain_name_len,
        ) == 0
    } {
        return Err("Failed to call the 2nd GetComputerNameExW function".to_owned());
    }

    return Ok(String::from_utf16(&domain_name)
        .unwrap()
        .trim_end_matches("\0")
        .to_owned());
}

/// Gets the IPV4 address and returns a Result
pub fn get_internal_ip() -> Result<String, String> {
    let mut length = 0;

    unsafe { GetAdaptersInfo(std::ptr::null_mut(), &mut length) };

    let mut adapter_info = unsafe { std::mem::zeroed::<IP_ADAPTER_INFO>() };

    if unsafe { GetAdaptersInfo(&mut adapter_info, &mut length) != NO_ERROR } {
        return Err(
            "Failed to call the 2nd GetAdaptersInfo get_adapter_information function".to_owned(),
        );
    }

    return Ok(
        std::str::from_utf8(&adapter_info.IpAddressList.IpAddress.String)
            .unwrap()
            .trim_end_matches("\0")
            .to_owned(),
    );
}

/// Gets the name of the executable file for the specified process
pub fn get_process_name() -> Result<String, String> {
    let mut process_name = [0u16; MAX_PATH as usize];
    let mut process_len = process_name.len() as u32;

    if unsafe {
        QueryFullProcessImageNameW(
            GetCurrentProcess(),
            0,
            process_name.as_mut_ptr(),
            &mut process_len,
        ) == 0
    } {
        return Err("Failed to call GetModuleFileNameW from get_process_name".to_owned());
    }

    return Ok(String::from_utf16(&process_name)
        .unwrap()
        .trim_end_matches("\0")
        .to_owned());
}

/// Gets and returns the process ID
pub fn get_process_id() -> u32 {
    return unsafe { GetCurrentProcessId() };
}

/// Gets the parent process ID of the current process
pub fn get_parent_process_id() -> Result<u32, String> {
    let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if snapshot_handle == 0 {
        return Err(
            "Failed to call CreateToolhelp32Snapshot in get_parent_process_id function".to_owned(),
        );
    }

    let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed::<PROCESSENTRY32>() };
    entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(snapshot_handle, &mut entry) } == 0 {
        return Err("Failed to call Process32First".to_owned());
    }

    loop {
        if entry.th32ProcessID == unsafe { GetCurrentProcessId() } {
            break;
        }

        if unsafe { Process32Next(snapshot_handle, &mut entry) } == 0 {
            return Err("Failed to call Process32Next".to_owned());
        }
    }

    return Ok(entry.th32ParentProcessID);
}

/// Get the process architecture
pub fn get_process_architecture() -> Result<String, String> {
    let mut tmp = 0;

    if unsafe { IsWow64Process(GetCurrentProcess(), &mut tmp) == 0 } {
        return Err("Failed to call IsWow64Process in get_process_architecture".to_owned());
    }

    let is_wow64 = match tmp {
        0 => false,
        _ => true,
    };

    if is_wow64 {
        return Ok("x86".to_owned());
    }

    return Ok("x86_64".to_owned());
}

/// Gets the process integrity and returns a Result
pub fn get_process_integrity() -> Result<String, String> {
    let mut token_handle = 0;

    // Get handle to token of the current process
    let token_res = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_QUERY_SOURCE,
            &mut token_handle,
        )
    };

    if token_res == 0 {
        return Err(
            "Error failed to get token OpenProcessToken in get_process_integrity function"
                .to_owned(),
        );
    }

    let mut size = 0;

    //Allocate the according to the size for the information contained in TOKEN_MANDATORY_LABEL structure
    //https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
    unsafe {
        GetTokenInformation(
            token_handle as _,
            TokenIntegrityLevel,
            std::ptr::null_mut(),
            0,
            &mut size,
        )
    };

    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err("Error TokenIntegrityBuffer to small".to_owned());
    }

    let mut tml = vec![0u8; size as usize];

    // Get information about an access token (TOKEN_MANDATORY_LABEL): https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
    let token_info_res = unsafe {
        //https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
        GetTokenInformation(
            token_handle,
            TokenIntegrityLevel,
            tml.as_mut_ptr() as *mut _,
            size,
            &mut size,
        )
    };

    if token_info_res == 0 {
        return Err("Error failed to get token information".to_owned());
    }

    //https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label
    let token_mandatory_level = tml.as_ptr() as *const TOKEN_MANDATORY_LABEL;
    //https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid_and_attributes
    let sid = unsafe { (*token_mandatory_level).Label.Sid as PSID };

    // Did not use ConvertStringSidToSid or EqualSid as alternatives

    unsafe {
        if IsWellKnownSid(sid, WinUntrustedLabelSid) == 1 {
            return Ok("Untrusted".to_owned());
        } else if IsWellKnownSid(sid, WinLowLabelSid) == 1 {
            return Ok("Low".to_owned());
        } else if IsWellKnownSid(sid, WinMediumLabelSid) == 1 {
            return Ok("Medium".to_owned());
        } else if IsWellKnownSid(sid, WinHighLabelSid) == 1 {
            return Ok("High".to_owned());
        } else if IsWellKnownSid(sid, WinSystemLabelSid) == 1 {
            return Ok("System".to_owned());
        }
    }

    return Ok("Unknown".to_owned());
}

pub fn is_elevated() -> Result<bool, String> {
    let mut token_handle = 0;

    // Get handle to token of the current process
    let token_res = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_QUERY_SOURCE,
            &mut token_handle,
        )
    };

    if token_res == 0 {
        return Err("Error failed to get token OpenProcessToken".to_owned());
    }

    let mut token_information = unsafe { std::mem::zeroed::<TOKEN_ELEVATION>() };
    let token_information_length = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
    let mut out = 0;

    if (unsafe {
        GetTokenInformation(
            token_handle,
            TokenElevation,
            &mut token_information as *mut _ as *mut _,
            token_information_length,
            &mut out,
        )
    } == 0)
    {
        return Err("Failed to call GetTokenInformation in is_elevated function".to_owned());
    }

    if token_information.TokenIsElevated == 0 {
        return Ok(false);
    }

    return Ok(true);
}

//
// Below are the commands only not host information (should go into seperate module)
//

#[allow(dead_code)]
/// Get the current directory for the current process, returns a Result
pub fn get_current_directory() -> Result<String, String> {
    let mut current_directory = [0u16; MAX_PATH as usize];
    let current_directory_len = current_directory.len() as u32;

    if unsafe { GetCurrentDirectoryW(current_directory_len, current_directory.as_mut_ptr()) == 0 } {
        return Err(
            "Failed to call GetCurrentDirectoryW in get_current_directory function".to_owned(),
        );
    }

    return Ok(String::from_utf16(&current_directory)
        .unwrap()
        .trim_end_matches("\0")
        .to_owned());
}

#[allow(dead_code)]
/// converts from utf8 slice to utf16 wide-string and returns a vector of u16
pub fn utf8_to_utf16(slice: &str) -> Vec<u16> {
    let mut wide_str = vec![0u16; slice.len() * 2];

    unsafe {
        MultiByteToWideChar(
            CP_UTF8,
            0,
            slice.as_bytes().as_ptr(),
            slice.len() as _,
            wide_str.as_mut_ptr(),
            wide_str.len() as _,
        )
    };

    return wide_str;
}

#[allow(dead_code)]
/// Changes the current directory for the current process, returns a Result
pub fn change_current_directory(path: &str) -> Result<String, String> {
    let path = utf8_to_utf16(path);

    if unsafe { SetCurrentDirectoryW(path.as_ptr()) == 0 } {
        return Err(
            "Failed to SetCurrentDirectoryW in change_current_directory function".to_owned(),
        );
    }

    return Ok(String::from_utf16(&path)
        .unwrap()
        .trim_end_matches("\0")
        .to_owned());
}

#[link(name = "ntdll")]
extern "system" {
    pub fn RtlGetVersion(lpVersionInformation: *mut OSVERSIONINFOEXW) -> NTSTATUS;
}

#[allow(dead_code)]
/// Gets the build information and returns a Result
pub fn get_os_information() -> Result<(u32, u32, u8, u16, u32), String> {
    let mut os_version_info = unsafe { std::mem::zeroed::<OSVERSIONINFOEXW>() };

    let status = unsafe { RtlGetVersion(&mut os_version_info) };

    if !NT_SUCCESS(status) {
        return Err("Failed to call RtlGetVersion in get_os_information function".to_owned());
    }

    return Ok((
        os_version_info.dwMajorVersion,
        os_version_info.dwMinorVersion,
        os_version_info.wProductType,
        os_version_info.wServicePackMajor,
        os_version_info.dwBuildNumber,
    ));
}
