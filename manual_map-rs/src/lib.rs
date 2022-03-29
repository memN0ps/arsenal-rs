use std::ptr::null_mut;
use winapi::{um::{winnt::DLL_PROCESS_ATTACH, winuser::{MessageBoxA, MB_OK}}, shared::minwindef::{HINSTANCE, DWORD, LPVOID}};

/* 
// Change accordingly: code to execute inside target process (PoC)
fn entry_point(_base: LPVOID) {
}

/// Small wrapper for the entry point
unsafe extern "system" fn dll_attach_wrapper(base: winapi::shared::minwindef::LPVOID) -> u32 {
    entry_point(base);
    0
}*/

/// DllMain is the main function that gets called when the dll is first attached
#[no_mangle]
pub unsafe extern "stdcall" fn DllMain(_hinst_dll: HINSTANCE, fdw_reason: DWORD, _lpv_reserved: LPVOID) {
    if fdw_reason == DLL_PROCESS_ATTACH {
        MessageBoxA(null_mut(), "Hello\0".as_ptr() as _, "World\0".as_ptr() as _ , MB_OK);
    }
}