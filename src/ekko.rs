use windows_sys::Win32::{System::{Diagnostics::Debug::{CONTEXT, IMAGE_NT_HEADERS64, RtlCaptureContext}, Threading::{CreateEventW, CreateTimerQueue, CreateTimerQueueTimer, WT_EXECUTEINTIMERTHREAD}, LibraryLoader::{GetProcAddress, GetModuleHandleA}, SystemServices::IMAGE_DOS_HEADER}, Foundation::{HANDLE, UNICODE_STRING}};
use std::{mem::zeroed, ptr::null_mut, ffi::c_void};

pub fn ekko(sleep_time: u32) {
    let ctx_thread: CONTEXT = unsafe { zeroed::<CONTEXT>() };
    let rop_prot_rw: CONTEXT = unsafe { zeroed::<CONTEXT>() };
    let rop_mem_enc: CONTEXT = unsafe { zeroed::<CONTEXT>() };
    let rop_delay: CONTEXT = unsafe { zeroed::<CONTEXT>() };
    let rop_mem_dec: CONTEXT = unsafe { zeroed::<CONTEXT>() };
    let rop_prot_rx: CONTEXT = unsafe { zeroed::<CONTEXT>() };
    let rop_set_evt: CONTEXT = unsafe { zeroed::<CONTEXT>() };

    //let h_timer_queue: HANDLE = 0;
    let mut h_new_timer: HANDLE = 0;
    //let h_event: HANDLE = 0;
    //let image_base: *mut c_void = null_mut();
    //let image_size: u32 = 0;
    let old_protect = 0;

    // This can be a randomly generated key
    let key_buf: [i8; 16] = [0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];
    let key: UNICODE_STRING = unsafe { zeroed::<UNICODE_STRING>() };
    let img: UNICODE_STRING = unsafe { zeroed::<UNICODE_STRING>() };

    //let nt_continue: *mut c_void = null_mut();
    //let sys_func032: *mut c_void = null_mut();

    let h_event = unsafe { CreateEventW(null_mut(), 0, 0, null_mut()) };
    let h_timer_queue = unsafe { CreateTimerQueue() };

    let nt_continue = unsafe { GetProcAddress(GetModuleHandleA("ntdll".as_ptr()), "NtContinue".as_ptr()) };
    let sys_func032 = unsafe { GetProcAddress(GetModuleHandleA("Ntdll".as_ptr()), "SystemFunction032".as_ptr()) };

    let image_base = unsafe { GetModuleHandleA(null_mut()) };
    let dos_header = image_base as *mut IMAGE_DOS_HEADER;
    let nt_headesr = unsafe { (*dos_header).e_lfanew as *mut IMAGE_NT_HEADERS64 };
    let image_size = unsafe { (*nt_headesr).OptionalHeader.SizeOfImage };

    key.Buffer = key_buf.as_mut_ptr() as *mut u16;
    key.Length = key_buf.len() as _; // 16
    key.MaximumLength = key_buf.len() as _; // 16

    img.Buffer = image_base as *mut u16;

    type fnRtlCaptureContext = unsafe extern "system" fn(contextrecord: *mut CONTEXT);
    let sucesss = unsafe { 
        CreateTimerQueueTimer(&mut h_new_timer, h_timer_queue, Some(fnRtlCaptureContext), &ctx_thread as *const _ as *const _, 0, 0, WT_EXECUTEINTIMERTHREAD)
    };
    
    if (sucesss != 0) {

    }
}