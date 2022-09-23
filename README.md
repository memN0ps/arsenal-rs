# Hell's Gate / Halo's Gate / Tartarus' Gate and FreshyCalls / SysWhispers2 in Rust

I named this project `Mordor` because Hell's Gate / Halo's Gate / Tartarus' Gate remind me of the [Black Gate of Mordor](https://shadowofwar.fandom.com/wiki/Black_Gate) in [The Lord of the Rings](https://en.wikipedia.org/wiki/The_Lord_of_the_Rings_(film_series)) for some weird reason haha and the project needs a cool name so why not?

![BlackGate](./blackgate.png)
**Credits to [Middle-earth: Shadow of War Wiki](https://shadowofwar.fandom.com/wiki/Black_Gate)**


## TODO (Development in progress)

* Make it user friendly by using system call macros and adding usage to README.md
* Port to Syswhisper3

## Hooking

Hooking is a technique used to intercept calls to pre-existing functions or redirect the execution flow of a legitimate API to another location in memory. This memory location could be controlled by an attacker, anti-virus (AV), end-point detection and response (EDR), or anti-cheat (AC).

`Inline Hooking:` This allows us to replace the targeted function's first few bytes (assembly instructions) with a jump instruction to redirect execution flow to another location in memory.

`Import Address Table Hooking (IAT hooking):` The Import Address table is a lookup table of function pointers for functions imported from DLLs or executables. IAT hooking allows us to replace the function address in the Import Address Table with another to redirect the program's execution flow.

![BlackGate](./hooking.png)
**Credits to [Kyle Mistele](https://kylemistele.medium.com/a-beginners-guide-to-edr-evasion-b98cc076eb9a)**

## Description

### What is Hell's Gate / Halo's Gate / Tartarus' Gate?

Hell's Gate is a process injection technique that allows us to search for a number of bytes called the syscall stub, from the `ntdll.dll` module to extract the system call numbers and save them in a dedicated memory table, which is then used to call system APIs directly. However, the limitation of Hell's Gate is that it needs access to a clean `ntdll.dll` module if the functions are hooked. Otherwise, it cannot populate the needed syscall numbers and eventually fails to deliver native API calls. To address this problem, a twin sister was born called Halo's Gate, which is just a patch to Hell's Gate based on a very simple observation.

When a hooked is placed on a function (`jmp <address>`) we won't be able to dynamically retrieve the syscall numbers, so to address this problem we can look at the system call numbers of the neighboring functions and adjust the calculations accordingly to get our system call number, because syscall ID in the syscall stub follow each other incrementally.


Hell's Gate only checks for a sequence of bytes in the following order `4c8bd1b8`, which looks like this in assembly:

```asm
mov r10, rcx
mov eax, <syscall>
```

Halo's gate does the same as Hell's Gate but with an additional check to see if there is a hook in place by checking if the first byte of the export is `e9` (`jmp`) and if there is a hook in place then Halo's gate starts to look at the neighboring functions and adjust the calculations accordingly to get our system call number, since the syscall ID in the syscall stub follows each other incrementally.

However, not all EDRs hook in the same location (at the start of the function). What if EDRs hooks right after `mov r10, rcx` (`4c8bd1`)? This will break our code.

Tartarus' Gate solves this issue by adding an additional check to Halo's gate by searching for these bytes sequentially `4c8bd1e9` as well, which looks like this in assembly.

```asm
mov r10, rcx
jmp <address>
```

However, if all functions are hooked then we can find the first one and unhook all one by one starting from call ID 0. This method is called Veles' Reek at [SEKTOR7](https://www.sektor7.net/).

## FreshyCalls / SysWhispers1 / SysWhispers2 / SysWhispers3

"*FreshyCalls tries to make the use of syscalls comfortable and simple, without generating too much boilerplate and in modern C++! Doesn't it bother you to have to define every syscall stub or function within a module? Or having to depend on the Windows version for the syscalls? Well, forget about all that. FreshyCalls makes use of some features implemented from C++11 such as the variadic templates along with some custom mini-shellcode to avoid this.*" - crummie5


*"The usage for [Syswhispers2](https://github.com/jthuraisamy/SysWhispers2) is almost identical to [SysWhispers1](https://github.com/jthuraisamy/SysWhispers) but you don't have to specify which versions of Windows to support. Most of the changes are under the hood. It no longer relies on [@j00ru](https://twitter.com/j00ru)'s [syscall tables](https://github.com/j00ru/windows-syscalls), and instead uses the "[sorting by system call address](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)" technique popularized by [@modexpblog](https://twitter.com/modexpblog). This significantly reduces the size of the syscall stubs.*" - crummie5


"*The usage for `SysWhispers3` is pretty similar to [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2), with the following exceptions:

- It also supports x86/WoW64
- It supports syscalls instruction replacement with an EGG (to be dynamically replaced)
- It supports direct jumps to syscalls in x86/x64 mode (in WOW64 it's almost standard)
- It supports direct jumps to random syscalls (borrowing [@ElephantSeal's idea](https://twitter.com/ElephantSe4l/status/1488464546746540042))

A better explanation of these features are better outlined I the blog post [NoSysWhisper](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/)*" - Kelzvirus


## In a nutshell:

`Hell's Gate:` This will parse `ntdll.dll` to find the starting of the syscall stub (`4c8bd1b8`) and then retrieve the syscall ID. However, if the syscall stub is hooked then our code will break.

`Halo's Gate:` The same as Hell’s Gate, but adds an additional check to see if the first hooks are in place by checking if the first byte is `e9` (`jmp`) and if there is a hook in place then Halo's gate starts to look at the neighboring functions and adjust the calculations accordingly to get our system call number since the syscall ID in the syscall stub follows each other incrementally.

`Tartarus' Gate`: The same Halo's Gate but adds an additional check to see if the syscall stub is hooked on the second line, after the assembly instructions `mov r10, rcx` by searching the following sequence of bytes: `4c8bd1e9.

`FreshyCalls:` This will search functions starting with `Nt` in the `Export Directory` and sorts them by addresses and the lowest address is the syscall identifier `0`.

`Syswhispers2:` The same as `FreshyCalls`, but this will search for `Zw` functions in the `Export Directory` and store the name by replacing `Zw` with `Nt`.


Exercise for the reader by: An excellent blog by [Alice Climent-Pommeret](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/)


## References and Credits

* https://github.com/am0nsec/HellsGate - [smelly__vx](https://twitter.com/smelly__vx) (@RtlMateusz) and Paul Laîné ([@am0nsec](https://twitter.com/am0nsec))
* https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf
* https://blog.sektor7.net/#!res/2021/halosgate.md - [@Reenz0h / @SEKTOR7net](https://twitter.com/SEKTOR7net)
* https://github.com/trickster0/TartarusGate ([trickster0 / @trickster012](https://twitter.com/trickster012))
* https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/
* https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/ - [@modexpblog](https://twitter.com/modexpblog)
* https://github.com/janoglezcampos/rust_syscalls/
* https://kylemistele.medium.com/a-beginners-guide-to-edr-evasion-b98cc076eb9a
* https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/

* https://github.com/crummie5/FreshyCalls - crummie5
* https://github.com/jthuraisamy/SysWhispers - jthuraisamy
* https://github.com/jthuraisamy/SysWhispers2 - jthuraisamy
* https://github.com/klezVirus/SysWhispers3 - [@klezVirus](https://twitter.com/KlezVirus)