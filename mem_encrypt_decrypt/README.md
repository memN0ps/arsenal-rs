## Memory Encrypt/Decrypt

A small PoC to encrypt/decrypt a memory region or image base using `SystemFunction040` and `SystemFunction041` or encrypt/decrypt using a key with `SystemFunction032`.

## Credits/References

* https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlencryptmemory
* https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtldecryptmemory
* https://docs.rs/windows-sys/latest/windows_sys/Win32/Security/Authentication/Identity/fn.SystemFunction040.html
* https://docs.rs/windows-sys/latest/windows_sys/Win32/Security/Authentication/Identity/fn.SystemFunction041.html
* https://doxygen.reactos.org/df/d13/sysfunc_8c.html#a66d55017b8625d505bd6c5707bdb9725
