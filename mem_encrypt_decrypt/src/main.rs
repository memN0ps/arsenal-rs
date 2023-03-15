use ntapi::winapi::shared::ntdef::{NTSTATUS, NT_SUCCESS};
use obfstr::obfstr;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::UNICODE_STRING;
use windows_sys::Win32::Security::Authentication::Identity::SystemFunction040;
use windows_sys::Win32::{
    Security::Authentication::Identity::SystemFunction041,
    System::{
        Diagnostics::Debug::IMAGE_NT_HEADERS64, LibraryLoader::GetModuleHandleA,
        SystemServices::IMAGE_DOS_HEADER,
    },
};

fn main() {
    env_logger::init();

    let image_base = unsafe { GetModuleHandleA(null_mut()) };
    let dos_header = image_base as *mut IMAGE_DOS_HEADER;
    let nt_headers =
        unsafe { (dos_header as u64 + (*dos_header).e_lfanew as u64) as *mut IMAGE_NT_HEADERS64 };
    let image_size = unsafe { (*nt_headers).OptionalHeader.SizeOfImage };

    let mut encrypted_image_buffer = rtl_encrypt_memory(image_base, image_size as usize)
        .expect(obfstr!("Failed to decrypt memory!"));
    log::info!(
        "SystemFunction040: Encrypted image base at {:#x} successfully! Encrypted buffer address: {:p}",
        image_base, encrypted_image_buffer.as_mut_ptr()
    );

    let mut decrypted_image_buffer = rtl_decrypt_memory(image_base, image_size as usize)
        .expect(obfstr!("Failed to decrypt memory!"));
    log::info!(
        "SystemFunction041: Decrypted image base {:#x} successfully! Decrypted buffer address: {:p}",
        image_base, decrypted_image_buffer.as_mut_ptr()
    );

    let mut secret = "1234567890ABCDEF\0".as_bytes().to_vec();
    let mut encrypted_buffer =
        encrypt_or_decrypt_mem_region_with_key(image_base, image_size as _, &mut secret)
            .expect(obfstr!("Failed to encrypt memory with key!"));
    log::info!("SystemFunction032: Encrypted buffer with key {:#x} successfully! Encrypted buffer address: {:p}", image_base, encrypted_buffer.as_mut_ptr());

    let mut decrypted_buffer =
        encrypt_or_decrypt_mem_region_with_key(image_base, image_size as _, &mut secret)
            .expect(obfstr!("Failed to decrypt memory with key!"));
    log::info!("SystemFunction032: Decrypted buffer with key {:#x} successfully! Decrypted buffer address: {:p}", image_base, decrypted_buffer.as_mut_ptr());
}

fn rtl_encrypt_memory(image_base: isize, image_size: usize) -> Result<Vec<u8>, ()> {
    let mut image_buffer: Vec<u8> =
        unsafe { std::slice::from_raw_parts_mut(image_base as *mut u8, image_size).to_vec() };

    // The RtlEncryptMemory function encrypts memory contents.
    // The encrypted contents can be decrypted by a subsequent call to the RtlDecryptMemory function.
    // Note: This function has no associated import library.
    // This function is available as a resource named SystemFunction040 in Advapi32.dll.
    // You must use the LoadLibrary and GetProcAddress functions to dynamically link to Advapi32.dll.
    // https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlencryptmemory
    // https://docs.rs/windows-sys/latest/windows_sys/Win32/Security/Authentication/Identity/fn.SystemFunction040.html
    let status =
        unsafe { SystemFunction040(image_buffer.as_mut_ptr() as _, image_buffer.len() as u32, 0) };

    if !NT_SUCCESS(status) {
        return Err(());
    }

    Ok(image_buffer)
}

fn rtl_decrypt_memory(image_base: isize, image_size: usize) -> Result<Vec<u8>, ()> {
    let mut image_buffer: Vec<u8> =
        unsafe { std::slice::from_raw_parts_mut(image_base as *mut u8, image_size).to_vec() };

    // The RtlDecryptMemory function decrypts memory contents previously encrypted by the RtlEncryptMemory function.
    // Note: This function has no associated import library.
    // This function is available as a resource named SystemFunction041 in Advapi32.dll.
    // You must use the LoadLibrary and GetProcAddress functions to dynamically link to Advapi32.dll.
    // https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtldecryptmemory
    // https://docs.rs/windows-sys/latest/windows_sys/Win32/Security/Authentication/Identity/fn.SystemFunction041.html
    let status =
        unsafe { SystemFunction041(image_buffer.as_mut_ptr() as _, image_buffer.len() as u32, 0) };

    if !NT_SUCCESS(status) {
        return Err(());
    }

    Ok(image_buffer)
}

extern "system" {
    fn SystemFunction032(data: *mut UNICODE_STRING, key: *const UNICODE_STRING) -> NTSTATUS;
}

fn encrypt_or_decrypt_mem_region_with_key(
    image_base: isize,
    image_size: usize,
    secret: &mut Vec<u8>,
) -> Result<Vec<u8>, ()> {
    let mut image_buffer: Vec<u8> =
        unsafe { std::slice::from_raw_parts_mut(image_base as *mut u8, image_size).to_vec() };

    // https://doxygen.reactos.org/df/d13/sysfunc_8c.html#a66d55017b8625d505bd6c5707bdb9725
    let key = UNICODE_STRING {
        Length: secret.len() as u16,
        MaximumLength: secret.len() as u16,
        Buffer: secret.as_mut_ptr() as *mut u16,
    };

    let mut data = UNICODE_STRING {
        Length: image_buffer.len() as u16,
        MaximumLength: image_buffer.len() as u16,
        Buffer: image_buffer.as_mut_ptr() as *mut u16,
    };

    let status = unsafe { SystemFunction032(&mut data, &key) };

    if !NT_SUCCESS(status) {
        return Err(());
    }

    Ok(image_buffer)
}
