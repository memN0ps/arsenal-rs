use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpebteb::PEB,
    ntpsapi::PEB_LDR_DATA,
    winapi::um::winnt::{
        IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    },
};

/// Get section header by hash
pub unsafe fn get_section_header_by_hash(module_base: *mut u8, section_hash: u32) -> Option<*mut IMAGE_SECTION_HEADER> {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let section_header = (&(*nt_headers).OptionalHeader as *const _ as usize
        + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize)
        as *mut IMAGE_SECTION_HEADER;

    for i in 0..(*nt_headers).FileHeader.NumberOfSections as usize {
        let section_name = (*section_header.add(i)).Name;
        //log::info!("{}", std::str::from_utf8(&section_name).unwrap());

        if section_hash == dbj2_hash(&section_name) {
            return Some(section_header);
        }
    }

    None
}

/// Get loaded module by hash
pub unsafe fn get_loaded_module_by_hash(module_hash: u32) -> Option<*mut u8> {
    let peb = get_peb();
    let peb_ldr_data_ptr = (*peb).Ldr as *mut PEB_LDR_DATA;

    let mut module_list =
        (*peb_ldr_data_ptr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() {
        let dll_buffer_ptr = (*module_list).BaseDllName.Buffer;
        let dll_length = (*module_list).BaseDllName.Length as usize;
        let dll_name_slice = core::slice::from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        if module_hash == dbj2_hash(dll_name_slice) {
            return Some((*module_list).DllBase as _);
        }

        module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }

    return None;
}

/// Gets a pointer to the Thread Environment Block (TEB)
#[cfg(target_arch = "x86")]
pub unsafe fn get_teb() -> *mut ntapi::ntpebteb::TEB {
    let teb: *mut ntapi::ntpebteb::TEB;
    asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);
    teb
}

/// Get a pointer to the Thread Environment Block (TEB)
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_teb() -> *mut ntapi::ntpebteb::TEB {
    use std::arch::asm;

    let teb: *mut ntapi::ntpebteb::TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

/// Get a pointer to the Process Environment Block (PEB)
pub unsafe fn get_peb() -> *mut PEB {
    let teb = get_teb();
    let peb = (*teb).ProcessEnvironmentBlock;
    peb
}

/// Generate a unique hash
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
