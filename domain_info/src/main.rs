use windows_sys::Win32::{Networking::ActiveDirectory::{DsGetDcNameA, DOMAIN_CONTROLLER_INFOA}, Foundation::ERROR_SUCCESS};

fn main() {
    let mut domain_controller_info: *mut DOMAIN_CONTROLLER_INFOA = std::ptr::null_mut();
    let status = unsafe {
        DsGetDcNameA(
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut domain_controller_info,
        )
    };

    if status != ERROR_SUCCESS {
        panic!("Failed to get domain controller info");
    }

    let domain_controller_name = unsafe { (*domain_controller_info).DomainControllerName };
    let domain_controller_address = unsafe { (*domain_controller_info).DomainControllerAddress };
    let domain_controller_address_type = unsafe { (*domain_controller_info).DomainControllerAddressType };
    let domain_guid = unsafe { (*domain_controller_info).DomainGuid };
    let domain_name = unsafe { (*domain_controller_info).DomainName };
    let dns_forest_name = unsafe { (*domain_controller_info).DnsForestName };
    let flags = unsafe { (*domain_controller_info).Flags };
    let dc_side_name = unsafe { (*domain_controller_info).DcSiteName };
    let client_side_name = unsafe { (*domain_controller_info).ClientSiteName };

    println!("Domain Controller Name: {}", unsafe { std::ffi::CStr::from_ptr(domain_controller_name as _).to_str().unwrap() });
    println!("Domain Controller Address: {}", unsafe { std::ffi::CStr::from_ptr(domain_controller_address as _).to_str().unwrap() });
    println!("Domain Controller Address Type: {}", domain_controller_address_type);
    println!("Domain GUID: {:?} {:?} {:?} {:?}", domain_guid.data1, domain_guid.data2, domain_guid.data3, domain_guid.data4);
    println!("Domain Name: {}", unsafe { std::ffi::CStr::from_ptr(domain_name as _).to_str().unwrap() });
    println!("DNS Forest Name: {}", unsafe { std::ffi::CStr::from_ptr(dns_forest_name as _).to_str().unwrap() });
    println!("Flags: {}", flags);
    println!("DC Site Name: {}", unsafe { std::ffi::CStr::from_ptr(dc_side_name as _).to_str().unwrap() });
    println!("Client Site Name: {}", unsafe { std::ffi::CStr::from_ptr(client_side_name as _).to_str().unwrap() });
}