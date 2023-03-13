use ntapi::{ntxcapi::NtContinue, winapi::um::errhandlingapi::GetLastError};
use std::{
    ffi::c_void,
    mem::zeroed,
    ptr::{null, null_mut},
};
use winapi::{
    shared::ntdef::BOOLEAN,
    um::winnt::{CONTEXT, PCONTEXT, RtlCaptureContext},
};
use windows_sys::Win32::{
    Foundation::{HANDLE, UNICODE_STRING},
    System::{
        Diagnostics::Debug::IMAGE_NT_HEADERS64,
        LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
        Memory::{VirtualProtect, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE},
        SystemServices::IMAGE_DOS_HEADER,
        Threading::{
            CreateEventW, CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueue, SetEvent,
            WaitForSingleObject, WT_EXECUTEINTIMERTHREAD,
        },
        WindowsProgramming::INFINITE,
    },
};

pub unsafe extern "system" fn call_rtl_capture_context(param0: *mut c_void, _param1: BOOLEAN) {
    // Retrieves a context record in the context of the caller.
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlcapturecontext
    RtlCaptureContext(param0.cast());
}

pub unsafe extern "system" fn call_nt_continue(param0: *mut c_void, _param1: BOOLEAN) {
    // You can use NtContinue after processing exception for continue executing thread. System uses NtContinue also in APC processing.
    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FNtContinue.html
    //https://doxygen.reactos.org/d6/d9e/include_2reactos_2wine_2winternl_8h.html#ac28b5db9f434d0762d6bebc7dcdd608f
    NtContinue(param0.cast(), 0);
}

pub fn ekko(sleep_time: u32) {
    let mut h_new_timer: HANDLE = 0;
    let mut old_protect: u32 = 0;

    // This can be a randomly generated key
    let mut key_buf: [i8; 16] = [
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55,
    ];
    let mut key: UNICODE_STRING = unsafe { zeroed::<UNICODE_STRING>() };
    let mut img: UNICODE_STRING = unsafe { zeroed::<UNICODE_STRING>() };

    // Creates or opens a named or unnamed event object.
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventw
    let h_event = unsafe { CreateEventW(null(), 0, 0, null()) };
    log::info!("[+] h_event: {:#x}", h_event);

    if h_event == 0 {
        panic!("[!] CreateEventW failed with error: {}", unsafe {
            GetLastError()
        });
    }

    // Creates a queue for timers. Timer-queue timers are lightweight objects that enable you to specify a callback function to be called at a specified time.
    // https://learn.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-createtimerqueue
    let h_timer_queue = unsafe { CreateTimerQueue() };
    log::info!("[+] h_timer_queue: {:#x}", h_timer_queue);

    if h_timer_queue == 0 {
        panic!("[!] CreateTimerQueue failed with error: {}", unsafe {
            GetLastError()
        });
    }

    let sys_func032 = unsafe {
        GetProcAddress(
            LoadLibraryA("Advapi32.dll\0".as_ptr()),
            "SystemFunction032\0".as_ptr(),
        )
    };

    if sys_func032.is_none() {
        panic!("[!] SystemFunction032 not found");
    }

    log::info!("[+] SystemFunction032: {:#x}", sys_func032.unwrap() as u64);

    let image_base = unsafe { GetModuleHandleA(null_mut()) };
    let dos_header = image_base as *mut IMAGE_DOS_HEADER;
    let nt_headers =
        unsafe { (dos_header as u64 + (*dos_header).e_lfanew as u64) as *mut IMAGE_NT_HEADERS64 };
    let image_size = unsafe { (*nt_headers).OptionalHeader.SizeOfImage };

    log::info!("[+] Image Base: {:#x}", image_base as u64);
    log::info!("[+] Image Size: {:#x}", image_size as u64);

    key.Buffer = key_buf.as_mut_ptr() as *mut u16;
    key.Length = key_buf.len() as u16; // 16
    key.MaximumLength = key_buf.len() as u16; // 16

    img.Buffer = image_base as *mut u16;
    img.Length = image_size as u16;
    img.MaximumLength = image_size as u16;

    log::info!("[+] Calling CreateTimerQueueTimer with ctx_thread");
    pause();   
    
    // Contains processor-specific register data. The system uses CONTEXT structures to perform various internal operations.
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
    #[repr(align(16))] struct ProperlyAlignedContext(pub CONTEXT);
    let mut ctx_thread = unsafe { std::mem::zeroed::<ProperlyAlignedContext>() };
    let ctx_thread_ptr : PCONTEXT = &mut ctx_thread.0;
    
    // Creates a timer-queue timer. This timer expires at the specified due time, then after every specified period. When the timer expires, the callback function is called.
    // https://learn.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-createtimerqueuetimer 
    let result = unsafe {
        CreateTimerQueueTimer(
            &mut h_new_timer,
            h_timer_queue,
            Some(call_rtl_capture_context),
            ctx_thread_ptr as _,
            0,
            0,
            WT_EXECUTEINTIMERTHREAD,
        )
    };

    if result == 0 {
        panic!("[!] CreateTimerQueueTimer failed with error: {}", unsafe {
            GetLastError()
        });
    }

    log::info!("[+] Calling WaitForSingleObject for 0x32 ms");
    // Waits until the specified object is in the signaled state or the time-out interval elapses.
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    unsafe {
        WaitForSingleObject(h_event, 0x32);
    }

    log::info!("[+] Copying ctx_thread to rop chains");
    // Clone not required as it implements the copy trait
    let mut rop_prot_rw = ctx_thread.0.clone();
    let mut rop_mem_enc = ctx_thread.0.clone();
    let mut rop_delay = ctx_thread.0.clone();
    let mut rop_mem_dec = ctx_thread.0.clone();
    let mut rop_prot_rx = ctx_thread.0.clone();
    let mut rop_set_evt = ctx_thread.0.clone();

    log::info!("[+] Building ROP chain");
    // pub unsafe extern "system" fn VirtualProtect(lpaddress: *const c_void, dwsize: usize, flnewprotect: PAGE_PROTECTION_FLAGS, lpfloldprotect: *mut PAGE_PROTECTION_FLAGS) -> BOOL
    // https://docs.rs/windows-sys/latest/windows_sys/Win32/System/Memory/fn.VirtualProtect.html
    rop_prot_rw.Rsp = -8 as isize as u64;
    rop_prot_rw.Rip = VirtualProtect as u64;
    rop_prot_rw.Rcx = image_base as *const c_void as u64;
    rop_prot_rw.Rdx = image_size as u64;
    rop_prot_rw.R8 = PAGE_READWRITE as u64;
    rop_prot_rw.R9 = &mut old_protect as *mut PAGE_PROTECTION_FLAGS as u64;
    dump_virtual_protect_context(&rop_prot_rw);

    // https://doxygen.reactos.org/df/d13/sysfunc_8c.html#a66d55017b8625d505bd6c5707bdb9725
    // NTSTATUS WINAPI SystemFunction032(struct ustring *data, const struct ustring *key)
    // pub unsafe extern "system" fn SystemFunction032(randombuffer: *mut UNICODE_STRING, key: *const UNICODE_STRING) -> BOOLEAN
    rop_mem_enc.Rsp = -8 as isize as u64;
    rop_mem_enc.Rip = sys_func032.unwrap() as u64;
    rop_mem_enc.Rcx = &mut img as *mut UNICODE_STRING as *mut c_void as u64;
    rop_mem_enc.Rdx = &key as *const UNICODE_STRING as *const c_void as u64;
    dump_system_function036_context(&rop_mem_enc);

    // pub unsafe extern "system" fn WaitForSingleObject(hhandle: HANDLE, dwmilliseconds: u32) -> WIN32_ERROR
    // https://docs.rs/windows-sys/latest/windows_sys/Win32/System/Threading/fn.WaitForSingleObject.html
    rop_delay.Rsp = -8 as isize as u64;
    rop_delay.Rip = WaitForSingleObject as u64;
    rop_delay.Rcx = -1 as isize as u64; // NtCurrentProcess
    rop_delay.Rdx = sleep_time as u64;
    dump_wait_for_single_object_context(&rop_delay);

    // https://doxygen.reactos.org/df/d13/sysfunc_8c.html#a66d55017b8625d505bd6c5707bdb9725
    // NTSTATUS WINAPI SystemFunction032(struct ustring *data, const struct ustring *key)
    // pub unsafe extern "system" fn SystemFunction032(randombuffer: *mut UNICODE_STRING, key: *const UNICODE_STRING) -> BOOLEAN
    rop_mem_dec.Rsp = -8 as isize as u64;
    rop_mem_dec.Rip = sys_func032.unwrap() as u64;
    rop_mem_dec.Rcx = &mut img as *mut UNICODE_STRING as *mut c_void as u64;
    rop_mem_enc.Rdx = &key as *const UNICODE_STRING as *const c_void as u64;
    dump_system_function036_context(&rop_mem_dec);

    // pub unsafe extern "system" fn VirtualProtect(lpaddress: *const c_void, dwsize: usize, flnewprotect: PAGE_PROTECTION_FLAGS, lpfloldprotect: *mut PAGE_PROTECTION_FLAGS) -> BOOL
    // https://docs.rs/windows-sys/latest/windows_sys/Win32/System/Memory/fn.VirtualProtect.html
    rop_prot_rx.Rsp = -8 as isize as u64;
    rop_prot_rx.Rip = VirtualProtect as u64;
    rop_prot_rx.Rcx = image_base as *const c_void as u64;
    rop_prot_rx.Rdx = image_size as u64;
    rop_prot_rx.R8 = PAGE_EXECUTE_READ as u64;
    rop_prot_rx.R9 = &mut old_protect as *mut u32 as u64;
    dump_virtual_protect_context(&rop_prot_rx);

    // https://docs.rs/windows-sys/latest/windows_sys/Win32/System/Threading/fn.SetEvent.html
    // pub unsafe extern "system" fn SetEvent(hevent: HANDLE) -> BOOL
    rop_set_evt.Rsp = -8 as isize as u64;
    rop_set_evt.Rip = SetEvent as u64;
    rop_set_evt.Rcx = h_event as u64;
    dump_set_event_context(&rop_set_evt);

    log::info!("[+] Rop chain built");
    log::info!("[+] Queue timers");

    let result = unsafe {
        CreateTimerQueueTimer(
            &mut h_new_timer,
            h_timer_queue,
            Some(call_nt_continue),
            &rop_prot_rw as *const _ as *const _,
            100,
            0,
            WT_EXECUTEINTIMERTHREAD,
        )
    };
    if result == 0 {
        panic!(
            "[!] Failed calling CreateTimerQueueTimer with rop_prot_rw (VirtualProtect RW) {:#x}",
            unsafe { GetLastError() }
        );
    }

    let result = unsafe {
        CreateTimerQueueTimer(
            &mut h_new_timer,
            h_timer_queue,
            Some(call_nt_continue),
            &rop_mem_enc as *const _ as *const _,
            200,
            0,
            WT_EXECUTEINTIMERTHREAD,
        )
    };
    if result == 0 {
        panic!(
            "[!] Failed calling CreateTimerQueueTimer with rop_mem_enc (SystemFunction032) {:#x}",
            unsafe { GetLastError() }
        );
    }

    let result = unsafe {
        CreateTimerQueueTimer(
            &mut h_new_timer,
            h_timer_queue,
            Some(call_nt_continue),
            &rop_delay as *const _ as *const _,
            300,
            0,
            WT_EXECUTEINTIMERTHREAD,
        )
    };
    if result == 0 {
        panic!(
            "[!] Failed calling CreateTimerQueueTimer with rop_delay (WaitForSingleObject) {:#x}",
            unsafe { GetLastError() }
        );
    }

    let result = unsafe {
        CreateTimerQueueTimer(
            &mut h_new_timer,
            h_timer_queue,
            Some(call_nt_continue),
            &rop_mem_dec as *const _ as *const _,
            400,
            0,
            WT_EXECUTEINTIMERTHREAD,
        )
    };
    if result == 0 {
        panic!(
            "[!] Failed calling CreateTimerQueueTimer with rop_mem_dec (SystemFunction032) {:#x}",
            unsafe { GetLastError() }
        );
    }

    let result = unsafe {
        CreateTimerQueueTimer(
            &mut h_new_timer,
            h_timer_queue,
            Some(call_nt_continue),
            &rop_prot_rx as *const _ as *const _,
            500,
            0,
            WT_EXECUTEINTIMERTHREAD,
        )
    };
    if result == 0 {
        panic!(
            "[!] Failed calling CreateTimerQueueTimer with rop_prot_rx (VirtualProtect RX) {:#x}",
            unsafe { GetLastError() }
        );
    }

    let result = unsafe {
        CreateTimerQueueTimer(
            &mut h_new_timer,
            h_timer_queue,
            Some(call_nt_continue),
            &rop_set_evt as *const _ as *const _,
            600,
            0,
            WT_EXECUTEINTIMERTHREAD,
        )
    };

    if result == 0 {
        panic!(
            "[!] Failed calling CreateTimerQueueTimer with rop_set_evt (SetEvent) {:#x}",
            unsafe { GetLastError() }
        );
    }

    log::info!("[+] Waiting for event...");

    unsafe {
        WaitForSingleObject(h_event, INFINITE);
    } //0xFFFFFFFF

    log::info!("[+] Finished waiting for event");

    // Deletes a timer queue. Any pending timers in the queue are canceled and deleted.
    // https://learn.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-deletetimerqueue
    unsafe {
        DeleteTimerQueue(h_timer_queue);
    }
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

fn dump_virtual_protect_context(rop: &CONTEXT) {
    log::info!(
        "[+] RSP: {:#x} RIP: {:#x} -> VirtualProtect({:#x}, {:#x}, {:#x}, {:#x})",
        rop.Rsp,
        rop.Rip,
        rop.Rcx,
        rop.Rdx,
        rop.R8,
        rop.R9
    );
}

fn dump_system_function036_context(rop: &CONTEXT) {
    log::info!(
        "[+] RSP: {:#x} RIP: {:#x} -> SystemFunction032({:#x}, {:#x})",
        rop.Rsp,
        rop.Rip,
        rop.Rcx,
        rop.Rdx
    );
}

fn dump_wait_for_single_object_context(rop: &CONTEXT) {
    log::info!(
        "[+] RSP: {:#x} RIP: {:#x} -> WaitForSingleObject({:#x}, {:#x})",
        rop.Rsp,
        rop.Rip,
        rop.Rcx,
        rop.Rdx
    );
}

fn dump_set_event_context(rop: &CONTEXT) {
    log::info!(
        "[+] RSP: {:#x} RIP: {:#x} -> SetEvent({:#x})",
        rop.Rsp,
        rop.Rip,
        rop.Rcx
    );
}
