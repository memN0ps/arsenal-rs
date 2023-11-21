<<<<<<< HEAD
## Rusty Arsenal

**Disclaimer: These projects are proof-of-concepts (PoCs) and are not intended for production use. They were created for 
fun, to learn Rust, and to experiment with the language. Additionally, they serve as tools for research and development 
as well as educational purposes. They will not be supported or maintained. Use at your own risk.**
=======
# Portable Executable (PE) Memory

A lightweight library for parsing Portable Executable (PE) files in memory using `winapi/ntapi`, with `no_std` support

## Features

- Supports `x64` only.
- Everything is in the `.text` section
- Support for `no_std`
- Unit testing for all functions
- Get a pointer to IMAGE_DOS_HEADER
- Get a pointer to IMAGE_NT_HEADERS
- Get a pointer to the Thread Environment Block (TEB)
- Get a pointer to the Process Environment Block (PEB)
- Get loaded module by hash
- Get section header by hash
- Get the address of an export by hash
- Process image relocations (rebase image)
- Process image import table (resolve imports)
- Generate a unique dbj2 hash
- Get the length of a C String
- Checks to see if the architecture `x86` or `x86_64`
- Convert a combo pattern to bytes without wildcards
- Pattern or Signature scan a region of memory

## FAQ

1. Why did I make this library? 

I wanted to learn about parsing portable executable (PE) files in Rust, even though there is a much better crate [pelite](https://docs.rs/pelite/latest/pelite/), and I need it for some of my projects. I wanted something that supports `no_std` for smaller file sizes and for Windows kernel, hypervisor (x86) and UEFI programming.

2. Why do you use unsafe functions rather than unsafe only in some places? 

I know that using this code/library aligns differently with Rust's best security practices. Still, I wanted to use C-style coding, and I got tired of typing `unsafe` over and over again. I usually would not do this if the project were big and serious, so please use it at your own risk. Typing unsafe repeatedly also looks dirty and makes it harder to read the code IMHO.

3. Why do you use winapi/ntapi? 

* The `windows-rs` crate does not support `no_std`, but the `windows-sys` crate does. 
* The `winapi/ntapi` crates existed before Microsoft's crate, `winapi/ntapi` are more user-friendly/idiomatic
* The `ntpai` crate uses `winapi` so they're better compatible together
* Microsoft does not support all native `Nt` API functionality.
* Preference for the low-level nature of `winapi/ntapi` and having custom abstractions tuned for a specific purpose.
* The `winapi/ntapi` crates feel similar to C programming.

4. Why do you not use "proper" Rust, and why do you use `no_std`? When making projects such as [Reflective DLL Injection](https://github.com/memN0ps/rdi-rs) or [Shellcode Reflective DLL Injection](https://github.com/memN0ps/srdi-rs), it is not possible to use heap allocated memory, anything dynamically sized must be put on a stack, and all external functions can't be used until you resolve imports. Supporting `no_std` is required if you want to make the file size smaller or for Windows kernel, hypervisor (x86) or UEFI programming. When self-loading or emulating `LoadLibraryA`, your code needs to be entirely self-contained and not rely on `libc` or any other (implicit) external API; otherwise, it becomes dependent on the loader.

## References and Credits

* https://discord.com/invite/rust-lang-community (Rust Community #windows-dev channel)
* https://github.com/janoglezcampos/rust_syscalls/
* https://github.com/not-matthias/mmap/
* https://github.com/Ben-Lichtman/reloader/
* https://github.com/2vg/blackcat-rs/
* https://github.com/Kudaes/DInvoke_rs/
* https://github.com/zorftw/kdmapper-rs/
* https://github.com/MrElectrify/mmap-loader-rs/
* https://github.com/kmanc/remote_code_oxidation
* https://github.com/trickster0/OffensiveRust
* https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
* https://crates.io/crates/pelite
* https://guidedhacking.com/threads/external-internal-pattern-scanning-guide.14112/
* https://guidedhacking.com/resources/guided-hacking-x64-cheat-engine-sigmaker-plugin-ce-7-2.319/
* https://github.com/frk1/hazedumper-rs/
* [not-matthais](https://github.com/not-matthias/) and Jessie#1111
* https://github.com/Jakobzs/patternscanner/
* https://github.com/pseuxide/toy-arms/
>>>>>>> pemem-rs/main
