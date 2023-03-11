# Ekko in Rust

A small sleep obfuscation technique that uses `CreateTimerQueueTimer` Win32 API in Rust. This is ported from C https://github.com/Cracked5pider/Ekko/ to Rust.

## Debugging

For debugging uncomment `env_logger::init();` in main and set Powershell environment variable to `$Env:RUST_LOG="info"`.

## Credits / References

- [@C5pider](https://twitter.com/C5pider) https://github.com/Cracked5pider/Ekko/
- [Austin Hudson (@SecIdiot)](https://twitter.com/ilove2pwn_) https://suspicious.actor/2022/05/05/mdsec-nighthawk-study.html
- Originally discovered by [Peter Winter-Smith](peterwintrsmith) and used in MDSec’s Nighthawk
- Thanks for contributing [@trickster012](https://twitter.com/trickster012)
- https://learn.microsoft.com/
- Rust Lang Community Discord: https://discord.com/invite/rust-lang-community