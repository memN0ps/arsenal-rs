fn main() {
    let ntdll = "ntdll.dll".as_bytes();
    println!("ntdll.dll: {:#x}", dbj2_hash(ntdll));

    let nt_open_process = "NtOpenProcess".as_bytes();
    println!("NtOpenProcess: {:#x}", dbj2_hash(nt_open_process));

    let nt_allocate_virtual_memory = "NtAllocateVirtualMemory".as_bytes();
    println!(
        "NtAllocateVirtualMemory: {:#x}",
        dbj2_hash(nt_allocate_virtual_memory)
    );

    let nt_protect_virtual_memory = "NtProtectVirtualMemory".as_bytes();
    println!(
        "NtProtectVirtualMemory: {:#x}",
        dbj2_hash(nt_protect_virtual_memory)
    );

    let nt_write_virtual_memory = "NtWriteVirtualMemory".as_bytes();
    println!(
        "NtWriteVirtualMemory: {:#x}",
        dbj2_hash(nt_write_virtual_memory)
    );

    let nt_create_thread_ex = "NtCreateThreadEx".as_bytes();
    println!("NtCreateThreadEx: {:#x}", dbj2_hash(nt_create_thread_ex));
}

//credits: janoglezcampos / @httpyxel / yxel
pub fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];
        if cur == 0 {
            iter += 1;
            continue;
        }
        if cur >= ('a' as u8) {
            cur -= 0x20;
        }
        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    return hsh;
}
