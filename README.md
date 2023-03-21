## Reflective Loader in Rust (4KB in size)

A small reflective loader PoC in Rust. I remade this from my old project, which is almost the same but smaller file size: https://github.com/memN0ps/arsenal-rs/tree/main/rdi-rs

## Features

More coming soon, maybe or maybe I'll modify the Shellcode Reflective DLL Injection project to work better: https://github.com/memN0ps/srdi-rs

## Example

Bring your own injector (BYOI) or the simple injector in this PoC for testing.

1. Open `notepad.exe` 

2. Build the `reflective_loader` project in release.
```
PS C:\Users\developer\Documents\GitHub\rdi-rs\reflective_loader> cargo build --release
   Compiling reflective_loader v0.1.0 (C:\Users\developer\Documents\GitHub\rdi-rs\reflective_loader)
    Finished release [optimized] target(s) in 0.48s
PS C:\Users\developer\Documents\GitHub\rdi-rs\reflective_loader>
```

2. Set the Powershell environment variable for debugging and `cargo run`

```
C:\Users\developer\Documents\GitHub\rdi-rs\inject> $Env:RUST_LOG="info"

PS C:\Users\developer\Documents\GitHub\rdi-rs\inject> cargo run

[2023-03-21T09:29:31Z INFO  inject] [+] Process ID: 3028
[2023-03-21T09:29:31Z INFO  inject] [+] IMAGE_DOS_HEADER: 0x7ff72e8080d0
[2023-03-21T09:29:31Z INFO  inject] [+] IMAGE_NT_HEADERS: 0x7ff72e8081a8
[2023-03-21T09:29:31Z INFO  inject] [+] Process handle: 244
[2023-03-21T09:29:31Z INFO  inject] [+] Remote allocated memory region for the dll: 0x19162c10000
[2023-03-21T09:29:31Z INFO  inject] [+] Local Reflective Loader Address/offset: 0x7ff72e8084d0
[2023-03-21T09:29:31Z INFO  inject] [+] Remote Reflective Loader Address/offset: 0x19162c10400
[2023-03-21T09:29:31Z INFO  inject] [+] entry_point: 0x19162c1151b
[2023-03-21T09:29:31Z INFO  inject] [+] Injection Completed
```

3. You should see the following

![poc](poc.png)

Note: This is just a PoC, and there are still some OPSEC to worry about. I'll leave that as an exercise for the user. I have included the references below for you to check out to weaponize this for red team engagements.

## Credits / References / Motivation / Thanks

* https://github.com/Cracked5pider/KaynLdr
* https://github.com/realoriginal/titanldr-ng
* https://github.com/boku7/BokuLoader
* https://github.com/kyleavery/AceLdr
* https://github.com/stephenfewer/ReflectiveDLLInjection/
* https://github.com/dismantl/ImprovedReflectiveDLLInjection
* https://github.com/monoxgas/sRDI
* https://github.com/johnthagen/min-sized-rust
* https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html
* https://www.netspi.com/blog/technical/adversary-simulation/srdi-shellcode-reflective-dll-injection/
* https://discord.com/invite/rust-lang-community (Rust Community #windows-dev channel)