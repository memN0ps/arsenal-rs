# Hell's Gate / Halo's Gate / Tartarus' Gate and FreshyCalls / SysWhispers2 in Rust

I named this project `Mordor` because Hell's Gate / Halo's Gate / Tartarus' Gate remind me of the [Black Gate of Mordor](https://shadowofwar.fandom.com/wiki/Black_Gate) in [The Lord of the Rings](https://en.wikipedia.org/wiki/The_Lord_of_the_Rings_(film_series)) for some weird reason haha and the project needs a cool name so why not?

![BlackGate](./blackgate.png)
**Credits to [Middle-earth: Shadow of War Wiki](https://shadowofwar.fandom.com/wiki/Black_Gate)**


## TODO (Development in progress)

* Make it more user friendly
* Add usage to README.md
* Add System call / assembly macros
* Decide on if I want to keep it a library or something that generates output files like SysWhispers1, SysWhispers2, SysWhispers3

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

The `FreshyCalls` technique searches the `Export Directory` for functions starting with `Nt` (excluding `Ntdll`) and sorts them by addresses. Surprisingly the lowest address is syscall number 0 and the next one will be syscall numbers 1 and 2 and 3... You can verify this in x64 dbg or Windbg yourself.

Syswhispers2 does the same thing but instead of searching for the `Nt` functions inside the export directory of  `ntdll.dll` it searches for functions starting with `Zw`. Surprisingly `Zw` functions and `Nt` functions point to the same syscall stubs and will have the same system call number.

Here we can verify that:
![syswhisper2](./syswhisper2_example1.PNG)

![syswhisper2](./syswhisper2_example2.PNG)


The difference between `Zw` anmd `Nt` functions are explained by [Microsoft here](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines):

"*The Windows native operating system services API is implemented as a set of routines that run in kernel mode. These routines have names that begin with the prefix Nt or Zw. Kernel-mode drivers can call these routines directly. User-mode applications can access these routines by using system calls.

With a few exceptions, each native system services routine has two slightly different versions that have similar names but different prefixes. For example, calls to NtCreateFile and ZwCreateFile perform similar operations and are, in fact, serviced by the same kernel-mode system routine.

For system calls from user mode, the Nt and Zw versions of a routine behave identically. For calls from a kernel-mode driver, the Nt and Zw versions of a routine differ in how they handle the parameter values that the caller passes to the routine.

A kernel-mode driver calls the Zw version of a native system services routine to inform the routine that the parameters come from a trusted, kernel-mode source. In this case, the routine assumes that it can safely use the parameters without first validating them. However, if the parameters might be from either a user-mode source or a kernel-mode source, the driver instead calls the Nt version of the routine, which determines, based on the history of the calling thread, whether the parameters originated in user mode or kernel mode*"


## In a nutshell:

`Hell's Gate:` This will parse `ntdll.dll` to find the starting of the syscall stub (`4c8bd1b8`) and then retrieve the syscall ID. However, if the syscall stub is hooked then our code will break.

`Halo's Gate:` The same as Hell’s Gate, but adds an additional check to see if the first hooks are in place by checking if the first byte is `e9` (`jmp`) and if there is a hook in place then Halo's gate starts to look at the neighboring functions and adjust the calculations accordingly to get our system call number since the syscall ID in the syscall stub follows each other incrementally.

`Tartarus' Gate`: The same Halo's Gate but adds an additional check to see if the syscall stub is hooked on the second line, after the assembly instructions `mov r10, rcx` by searching the following sequence of bytes: `4c8bd1e9.

`FreshyCalls:` This will search functions starting with `Nt` in the `Export Directory` and sorts them by addresses and the lowest address is the syscall identifier `0`.

`SysWhispers1:` Uses the OS version information to select the correct system call number.

`Syswhispers2:` The same as `FreshyCalls`, but this will search for `Zw` functions in the `Export Directory` and store the name by replacing `Zw` with `Nt`.

`SysWhispers3` This is very similar to `SysWhispers2` with the exception that it also supports `x86/WoW64`, `syscalls instruction replacement with an EGG (to be dynamically replaced)`, `direct jumps to syscalls in x86/x64 mode (in WOW64 it's almost standard)`, `direct jumps to random syscalls` (borrowing [@ElephantSeal's idea](https://twitter.com/ElephantSe4l/status/1488464546746540042)).

Exercise for the reader by: An excellent blog by [Alice Climent-Pommeret](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/) and [Kelzvirus](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/)


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