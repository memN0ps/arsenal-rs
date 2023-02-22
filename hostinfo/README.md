## Agent Information

A simple library that retrieves information about the host: this was made ages ago (months), but I forgot to upload it like many others.

```
$Env:RUST_LOG="debug"
```

## Example

### Medium Integrity

```
PS C:\Users\memN0ps\Documents\GitHub\hostinfo> cargo run
   Compiling hostinfo v0.1.0 (C:\Users\memN0ps\Documents\GitHub\hostinfo)
    Finished dev [unoptimized + debuginfo] target(s) in 0.50s
     Running `target\debug\hostinfo.exe`
[2023-02-22T23:46:25Z INFO  hostinfo] ID: bd3ae7d9-6816-44aa-9070-a182660983e5
[2023-02-22T23:46:25Z INFO  hostinfo] Username: memN0ps
[2023-02-22T23:46:25Z INFO  hostinfo] Hostname: DebugVM
[2023-02-22T23:46:25Z INFO  hostinfo] Domain:
[2023-02-22T23:46:25Z INFO  hostinfo] IP: 192.168.130.130
[2023-02-22T23:46:25Z INFO  hostinfo] Process: C:\Users\memN0ps\Documents\GitHub\hostinfo\target\debug\hostinfo.exe
[2023-02-22T23:46:25Z INFO  hostinfo] PID: 7572
[2023-02-22T23:46:25Z INFO  hostinfo] PPID: 4408
[2023-02-22T23:46:25Z INFO  hostinfo] Arch: x86_64
[2023-02-22T23:46:25Z INFO  hostinfo] Integrity: Medium
[2023-02-22T23:46:25Z INFO  hostinfo] Elevated: false
PS C:\Users\memN0ps\Documents\GitHub\hostinfo>
```

## High Integrity

```
PS C:\Users\memN0ps\Documents\GitHub\hostinfo> .\target\debug\hostinfo.exe
[2023-02-22T23:47:26Z INFO  hostinfo] ID: e2b46236-6cab-419c-a920-bc9e484bc0ff
[2023-02-22T23:47:26Z INFO  hostinfo] Username: memN0ps
[2023-02-22T23:47:26Z INFO  hostinfo] Hostname: DebugVM
[2023-02-22T23:47:26Z INFO  hostinfo] Domain:
[2023-02-22T23:47:26Z INFO  hostinfo] IP: 192.168.130.130
[2023-02-22T23:47:26Z INFO  hostinfo] Process: C:\Users\memN0ps\Documents\GitHub\hostinfo\target\debug\hostinfo.exe
[2023-02-22T23:47:26Z INFO  hostinfo] PID: 11776
[2023-02-22T23:47:26Z INFO  hostinfo] PPID: 13160
[2023-02-22T23:47:26Z INFO  hostinfo] Arch: x86_64
[2023-02-22T23:47:26Z INFO  hostinfo] Integrity: High
[2023-02-22T23:47:26Z INFO  hostinfo] Elevated: true
PS C:\Users\memN0ps\Documents\GitHub\hostinfo>
```

## Credits / References

* [C5pider](https://twitter.com/C5pider): https://github.com/HavocFramework/Havoc