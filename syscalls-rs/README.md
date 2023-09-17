# Syscalls - A direct or indirect Syscall library in Rust

The Rust version of `Freshycalls` or `Syswhispers 1 or 2 or 3` diverges in its approach from the C/C++/Python versions. While it shares similar techniques, this project doesn't generate header/ASM files or output like them. Instead, it functions as a library. Inspired by a friend [@janoglezcampos](https://github.com/janoglezcampos/rust_syscalls/) ([@httpyxel](https://twitter.com/httpyxel)), I created this project to explore the FreshyCalls/SysWhispers technique that `rust_syscalls` doesn't employ.

## Usage

1. Add the library to your Rust `Cargo.toml` file by setting the git repository or local path and choosing the direct or indirect system call feature by setting `_DIRECT_` or `_INDIRECT_` as a feature. Please note you can only choose direct `_DIRECT_` or `_INDIRECT_` not both.

```toml
[dependencies]
syscalls = { path = "../syscalls-rs/syscalls",  features = ["_DIRECT_"] }
```

```toml
[dependencies]
syscalls = { path = "../syscalls-rs/syscalls",  features = ["_INDIRECT_"] }
```

2. Make use of the library

```rust
use syscalls;
```

3. Dynamically retrieve the `SSN` and/or `syscall` instruction from `ntdll.dll` even if functions are hooked and call any function using direct and/or indirect `syscall`. Note that when calling a function using the `syscall` macro the string will be obfuscated by hashing (`NtClose` in this example).

```rust
unsafe { syscall!("NtClose", process_handle) };
```

## References and Credits

* https://github.com/am0nsec/HellsGate - [smelly__vx](https://twitter.com/smelly__vx) (@RtlMateusz) and Paul Laîné ([@am0nsec](https://twitter.com/am0nsec))
* https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf
* https://blog.sektor7.net/#!res/2021/halosgate.md - [@Reenz0h / @SEKTOR7net](https://twitter.com/SEKTOR7net)
* https://github.com/trickster0/TartarusGate ([trickster0 / @trickster012](https://twitter.com/trickster012))
* https://trickster0.github.io/posts/Halo's-Gate-Evolves-to-Tartarus-Gate/
* https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/ [@KlezVirus](https://twitter.com/KlezVirus)
* https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/ - [@modexpblog](https://twitter.com/modexpblog)
* https://github.com/janoglezcampos/rust_syscalls/ - [@httpyxel](https://twitter.com/httpyxel)
* https://kylemistele.medium.com/a-beginners-guide-to-edr-evasion-b98cc076eb9a - [@AliceCliment](https://twitter.com/AliceCliment)
* https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/
* https://github.com/crummie5/FreshyCalls - [@ElephantSe4l](https://twitter.com/ElephantSe4l)
* https://github.com/jthuraisamy/SysWhispers - [@Jackson_T](https://twitter.com/Jackson_T)
* https://github.com/jthuraisamy/SysWhispers2 - [@Jackson_T](https://twitter.com/Jackson_T)
* https://github.com/klezVirus/SysWhispers3 - [@klezVirus](https://twitter.com/KlezVirus)
