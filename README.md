# ParallelSyscalls

Rust version of MDSec's ParallelSyscalls research: https://github.com/mdsecactivebreach/ParallelSyscalls/ and https://www.mdsec.co.uk/2022/01/edr-parallel-asis-through-analysis/

This code can be used to load a fresh copy of `NTDLL.dll` using system calls and extract system calls from the fresh copy of `NTDLL.dll` to call any Win32 API function of your choice. This may allow you to evade AV/EDR detections. Please note that the syscall stubs are allocated using `RWX` memory created using `VirtualAlloc()`, which is not optimal from an OPSEC perspective.


Writing a tool with a blog post by self-research has learn a lot more than anything I've ever done: https://memn0ps.github.io/Parallel-Syscalls/


## Why Rust?

Why not? Rust is awesome! A low-level statically (compiled) and strongly typed systems programming language that is faster than C/C++, allowing you to achieve memory safety, concurrency and perform low-level tasks writing high-level code with an excellent compiler, community and documentation. I have moved away from my old favourite languages C/C++/C#, and started my new Rusty adventure.

This project has allowed me to learn about Rust Windows Internals and enhance my red teaming skills. I'm relatively new to Rust, but I firmly believe Rust is the future for robust programs, red teaming and malware development.

![ntdlll](./ntdll.png)

## Example

1. Import the "parallel_syscalls" library using `mod parallel_syscalls;`

2. Create a function pointer type such as `NtCreateThreadEx` https://docs.rs/ntapi/0.3.6/ntapi/ntpsapi/fn.NtCreateThreadEx.html

3. Call the function `get_module_base_address("ntdll")` to load a fresh copy of NTDLL using MDSec's Parallel Syscalls technique.

4. Call the function `get_function_address(ptr_ntdll, "NtCreateThreadEx")` and pass in NTDLL's base address and the system call number of the function you want to retrieve.

5. Call `build_syscall_stub(syscall_nt_create_thread_ex)` and the address of the function to allocate memory and copy the syscall stub to the allocated memory region.

6. Call `transmute::<_, NtCreateThreadEx>(nt_create_thread_ex)` to turn a pointer into a function pointer`

7. Call the function as you would normally `syscall_nt_create_thread_ex(&mut thread_handle, GENERIC_ALL, null_mut(), GetCurrentProcess(), null_mut(), null_mut(), 0, 0, 0, 0, null_mut())`

8. Profit \x90

```rust
use std::{ptr::null_mut, intrinsics::transmute};
use ntapi::ntpsapi::PPS_ATTRIBUTE_LIST;
use winapi::{um::{winnt::{ACCESS_MASK, GENERIC_ALL}, processthreadsapi::GetCurrentProcess}, shared::{ntdef::{PHANDLE, POBJECT_ATTRIBUTES, HANDLE, PVOID, NTSTATUS, NT_SUCCESS}, minwindef::ULONG, basetsd::SIZE_T}, ctypes::c_void};

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


fn main() {

    // Dynamically get the base address of a fresh copy of ntdll.dll using mdsec's technique
    let ptr_ntdll = parallel_syscalls::get_module_base_address("ntdll");

    if ptr_ntdll.is_null() {
        panic!("Pointer to ntdll is null");
    }

    //get function address
    let syscall_nt_create_thread_ex = parallel_syscalls::get_function_address(ptr_ntdll, "NtCreateThreadEx");

    //build system call stub
    let nt_create_thread_ex = parallel_syscalls::build_syscall_stub(syscall_nt_create_thread_ex as u32);
    
    // Convert to function pointer
    let syscall_nt_create_thread_ex = unsafe { transmute::<_, NtCreateThreadEx>(nt_create_thread_ex) };
    let mut thread_handle : *mut c_void = null_mut();

    // Call the function pointer in the memory region
    let status = unsafe { syscall_nt_create_thread_ex(&mut thread_handle, GENERIC_ALL, null_mut(), GetCurrentProcess(), null_mut(), null_mut(), 0, 0, 0, 0, null_mut()) };

    if !NT_SUCCESS(status) {
        panic!("Failed to call NtCreateThreadEx");
    }

    println!("[+] Thread Handle: {:?} and Status: {:?}", thread_handle, status);
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
* https://twitter.com/rustlang - (Rust Community Discord: Nick12#9400, B3NNY#8794, MaulingMonkey#1444, Zuix#4359, WithinRafael#7014, Jess Gaming#8850, madfrog#5492 and many more)


