use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE};
use winapi::um::winnt::DLL_PROCESS_ATTACH;
use winapi::um::winuser::MessageBoxA;

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _module: HINSTANCE,
    call_reason: DWORD,
    _reserved: LPVOID,
) -> BOOL {
    if call_reason == DLL_PROCESS_ATTACH {
        MessageBoxA(
            0 as _,
            "Rust DLL injected!\0".as_ptr() as _,
            "Rust DLL\0".as_ptr() as _,
            0x0,
        );

        TRUE
    } else {
        TRUE
    }
}
