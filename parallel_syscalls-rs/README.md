# ParallelSyscalls

Rust version of MDSec's ParallelSyscalls research: https://github.com/mdsecactivebreach/ParallelSyscalls/ and https://www.mdsec.co.uk/2022/01/edr-parallel-asis-through-analysis/

This code can be used to load a fresh copy of `ntdll.dll` using system calls.

![ntdlll](./ntdll.png)


## Example

1. Import the "parallel_syscalls" library
2. Create a function pointer type such as `NtCreateThreadEx` https://docs.rs/ntapi/0.3.6/ntapi/ntpsapi/fn.NtCreateThreadEx.html
3. Call the function `gimme_the_loot("ntdll.dll")` to load a fresh copy of NTDLL using MDSec's ParallelSyscalls technique
4. Call the function `get_function_address(ptr_ntdll, "NtCreateThreadEx")` and pass in NTDLL's base address and the function's system call number you want to retrieve
5. Call `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` to allocate memory for the syscall stub (note that this is not optimal from an OPSEC perspective)
6. Call `build_syscall_stub(syscall_region as *mut c_void, syscall_nt_create_thread_ex as u32)` and pass the memory region and the address of the function to copy the syscall stub inside the allocated memory region.
7. Call `transmute::<_, NtCreateThreadEx>(nt_create_thread_ex)` to turn a pointer into a function pointer`
8. Call the function as you would normally `syscall_nt_create_thread_ex(&mut thread_handle, GENERIC_ALL, null_mut(), GetCurrentProcess(), null_mut(), null_mut(), 0, 0, 0, 0, null_mut())`
9. Profit \x90

```rust
use std::{ptr::null_mut, intrinsics::transmute};
use ntapi::ntpsapi::PPS_ATTRIBUTE_LIST;
use winapi::{um::{memoryapi::VirtualAlloc, winnt::{ACCESS_MASK, GENERIC_ALL, MEM_RESERVE, MEM_COMMIT, PAGE_EXECUTE_READWRITE}, processthreadsapi::GetCurrentProcess}, shared::{ntdef::{PHANDLE, POBJECT_ATTRIBUTES, HANDLE, PVOID, NTSTATUS, NT_SUCCESS}, minwindef::ULONG, basetsd::SIZE_T}, ctypes::c_void};

mod parallel_syscalls;

// Function to call
type NtCreateThreadEx = unsafe extern "system" fn(
    ThreadHandle: PHANDLE, 
    DesiredAccess: ACCESS_MASK, 
    ObjectAttributes: POBJECT_ATTRIBUTES, 
    ProcessHandle: HANDLE, 
    StartRoutine: PVOID, 
    Argument: PVOID, 
    CreateFlags: ULONG, 
    ZeroBits: SIZE_T, 
    StackSize: SIZE_T, 
    MaximumStackSize: SIZE_T, 
    AttributeList: PPS_ATTRIBUTE_LIST
) -> NTSTATUS;

const MAX_SYSCALL_STUB_SIZE: u32 = 64;

fn main() {

    // Dynamically get the base address of a fresh copy of ntdll.dll using mdsec's technique
    let ptr_ntdll = parallel_syscalls::gimme_the_loot("ntdll");

    if ptr_ntdll.is_null() {
        panic!("Pointer to ntdll is null");
    }

    //get function address
    let syscall_nt_create_thread_ex = parallel_syscalls::get_function_address(ptr_ntdll, "NtCreateThreadEx");

    // Allocate memory for the system call (not optimal from opsec perspective)
    let syscall_region = unsafe { VirtualAlloc(null_mut(), MAX_SYSCALL_STUB_SIZE as usize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) as usize };

    if syscall_region == 0 {
        panic!("Failed to allocate memory using VirtualAlloc in main");
    }


    let nt_create_thread_ex = unsafe { parallel_syscalls::build_syscall_stub(syscall_region as *mut c_void, syscall_nt_create_thread_ex as u32) };
    
    // Example
    unsafe {
        let syscall_nt_create_thread_ex = transmute::<_, NtCreateThreadEx>(nt_create_thread_ex);
        let mut thread_handle : *mut c_void = null_mut();

        let status = syscall_nt_create_thread_ex(&mut thread_handle, GENERIC_ALL, null_mut(), GetCurrentProcess(), null_mut(), null_mut(), 0, 0, 0, 0, null_mut());

        if !NT_SUCCESS(status) {
            panic!("Failed to call NtCreateThreadEx");
        }

        println!("[+] Thread Handle: {:?} and Status: {:?}", thread_handle, status);
    }
}
```


## References

* https://www.mdsec.co.uk/2022/01/edr-parallel-asis-through-analysis/
* https://github.com/mdsecactivebreach/ParallelSyscalls/
* https://github.com/cube0x0/ParallelSyscalls/
* https://github.com/frkngksl/ParallelNimcalls/
* https://doc.rust-lang.org/book/
* https://github.com/microsoft/windows-rs
* https://crates.io/crates/ntapi
* https://crates.io/crates/winapi
* https://crates.io/crates/bstr
* https://twitter.com/MrUn1k0d3r (MrUn1k0d3r's Discord community)
* https://github.com/felix-rs/ntcall-rs/
* https://github.com/Kudaes/DInvoke_rs
* https://github.com/kmanc/remote_code_oxidation
* https://github.com/zorftw/kdmapper-rs
* https://github.com/trickster0/OffensiveRust
* https://twitter.com/rustlang - (Rust Community Discord: Nick12#9400, B3NNY#8794, MaulingMonkey#1444, Zuix#4359, WithinRafael#7014, Jess Gaming#8850 and many more)


