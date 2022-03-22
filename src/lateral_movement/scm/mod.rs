
use std::{thread, time};
use anyhow::Result;
use std::io::Error;
use std::ptr::null;
use std::ffi::CString;

use winapi::um::winsvc::{
    OpenSCManagerA,
    SC_MANAGER_CREATE_SERVICE,
    SC_HANDLE__,
    CreateServiceA,
    SERVICE_ALL_ACCESS,
};

use winapi::um::winnt::{
    SERVICE_WIN32_OWN_PROCESS,
    SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL,
};

#[derive(Debug, Clone)]
pub struct PSExec {
    pub computer_name: String,
    pub binary_path: String,
    pub service_name: String,
    pub display_name: String
}

impl PSExec {
    pub fn new(input_computer_name: String, input_binary_path: String, input_service_name: Option<String>, input_display_name: Option<String>) -> Self {
        if let Some(input_service_name) = input_service_name {
            if let Some(input_display_name) = input_display_name {
                return Self {
                    computer_name: input_computer_name,
                    binary_path: input_binary_path,
                    service_name: input_service_name,
                    display_name: input_display_name,
                }
            }
            return Self {
                computer_name: input_computer_name,
                binary_path: input_binary_path,
                service_name: input_service_name,
                display_name: "mimiRust Service".to_string(),
            }
        }
        Self {
            computer_name: input_computer_name,
            binary_path: input_binary_path,
            service_name: "mimiRust".to_string(),
            display_name: "mimiRust Service".to_string(),
        }
    }

    pub fn execute(config: Self) -> bool {
        let handle = open_service_manager(config.computer_name.clone());

        if !create_service(handle, config.computer_name.clone(), config.service_name, config.display_name, config.binary_path) {
            println!("[*] Failed to create service on endpoint with error: {}", Error::last_os_error());
        }

        return true;
    }
}

fn open_service_manager(computer_name: String) -> *mut SC_HANDLE__ {
    unsafe {
        let cstring = CString::new(computer_name).unwrap();
        let handle: *mut SC_HANDLE__ = OpenSCManagerA(cstring.as_ptr(), null(), SC_MANAGER_CREATE_SERVICE);
        if handle == 0 as *mut SC_HANDLE__ {
            println!("[!] Failed to open service manager with error: {:?}", Error::last_os_error());
            std::process::exit(0x100);
        }
        return handle;
    }
}

fn create_service(service_manager: *mut SC_HANDLE__, computer_name: String, service_name: String, display_name: String, binary_path: String) -> bool {
    unsafe {

        let handle = CreateServiceA(
            service_manager,
            CString::new(service_name).unwrap().as_ptr(),
            CString::new(display_name).unwrap().as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            CString::new(binary_path).unwrap().as_ptr(),
            null(),
            0 as *mut u32,
            null(),
            null(),
            null(),
        );

        if handle == 0 as *mut SC_HANDLE__ {
            println!("{:?}", Error::last_os_error());
        }
    }
    return true;
}

fn start_service(computer_name: String, service_name: String) -> bool {
    todo!();
}

fn stop_service(computer_name: String, service_name: String) -> bool {
    todo!();
}

fn delete_service(computer_name: String, service_name: String) -> bool {
    todo!();
}

fn close_handle() -> bool {
    todo!();
}