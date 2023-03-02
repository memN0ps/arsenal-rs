## Freeze (Sacrificing a Suspended Processes)

## Usage

```
PS C:\Users\memN0ps\Documents\GitHub\arsenal-rs\suspended_process_ntdll_unhooker> cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target\debug\suspended_process_ntdll_unhooker.exe`
[2023-03-02T02:40:17Z INFO  suspended_process_ntdll_unhooker] Freeze
[2023-03-02T02:40:17Z INFO  suspended_process_ntdll_unhooker::freeze] [+] Process Name: C:\Windows\System32\notepad.exe
[2023-03-02T02:40:17Z INFO  suspended_process_ntdll_unhooker::freeze] [+] Process ID: 7276
[2023-03-02T02:40:17Z INFO  suspended_process_ntdll_unhooker::freeze] [+] NTDLL Address: 0x00007fff6ec50000
[2023-03-02T02:40:17Z INFO  suspended_process_ntdll_unhooker::freeze] [+] Source: 0x7fff6ec51000
[2023-03-02T02:40:17Z INFO  suspended_process_ntdll_unhooker::freeze] [+] Destination: 0x7fff6ec51000
[2023-03-02T02:40:17Z INFO  suspended_process_ntdll_unhooker::freeze] [+] Size: 1232896
[2023-03-02T02:40:17Z INFO  suspended_process_ntdll_unhooker::freeze] Success
```

### Theory

This process injection technique allows us to create a process in a suspended state, read the `.text` section of `ntdll.dll` from the newly created remote process and write it to the `.text` section of our local process's `ntdll.dll`. System DLLs are naturally loaded as part of the startup process, but EDRs hook functions inside `ntdll.dll` after the process starts. This means that if we create a process in a suspended state and copy the `.text` section of `ntdll.dll` to our `.text` section of `ntdll.dll` then we have a unhooked/fresh copy in memory and can call functions normally. Once the process is resumed, EDRs hooks functions inside `ntdll.dll`.


1. We create a new process in a `suspended` state using `CreateProcessA()`.

2. We get the base address of the `ntdll.dll` module for the current process. Note we can also get the base address of `ntdll.dll` in the remote process that we created with `CreateProcessA()`. However, the base address of all DLLs, specifically `"Known System DLLs"`, is the same for all processes and is randomized once via Address Space Layout Randomization (ASLR), at boot time.

3. We read the `.text` section of the remote process's NTDLL module, using `ReadProcessMemory`, and write it to the `.text` section of the local process's NTDLL module.

4. We should be able to call functions normally as all of the functions inside `ntdll.dll` are not hooked anymore.


## Practical Test

<will test soon...>

### Cons

* CreateProcess in a suspended state (EDRs kernel driver will get notified via `PsSetCreateProcessNotifyRoutine`)
* ReadProcessMemory
* WriteProcessMemory
* EDRs could perform integrity checks to see if functions are still hooked or not inside `ntdll.dll` of each process. But do they?


### Note

* Release: Comment out `env_logger::init();` to prevent log 

* Debug: Keep `env_logger::init();` and run `$Env:RUST_LOG="info"` to show logs.

## Credits / References

* https://www.optiv.com/insights/source-zero/blog/sacrificing-suspended-processes
* https://github.com/optiv/Freeze/