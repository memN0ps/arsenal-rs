# MimiRust - Hacking the Windows operating system to hand us the keys to the kingdom with Rust.

```

    ███▄ ▄███▓ ██▓ ███▄ ▄███▓ ██▓ ██▀███   █    ██   ██████ ▄▄▄█████▓
    ▓██▒▀█▀ ██▒▓██▒▓██▒▀█▀ ██▒▓██▒▓██ ▒ ██▒ ██  ▓██▒▒██    ▒ ▓  ██▒ ▓▒
    ▓██    ▓██░▒██▒▓██    ▓██░▒██▒▓██ ░▄█ ▒▓██  ▒██░░ ▓██▄   ▒ ▓██░ ▒░
    ▒██    ▒██ ░██░▒██    ▒██ ░██░▒██▀▀█▄  ▓▓█  ░██░  ▒   ██▒░ ▓██▓ ░
    ▒██▒   ░██▒░██░▒██▒   ░██▒░██░░██▓ ▒██▒▒▒█████▓ ▒██████▒▒  ▒██▒ ░
    ░ ▒░   ░  ░░▓  ░ ▒░   ░  ░░▓  ░ ▒▓ ░▒▓░░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░  ▒ ░░
    ░  ░      ░ ▒ ░░  ░      ░ ▒ ░  ░▒ ░ ▒░░░▒░ ░ ░ ░ ░▒  ░ ░    ░
    ░      ░    ▒ ░░      ░    ▒ ░  ░░   ░  ░░░ ░ ░ ░  ░  ░    ░
           ░    ░         ░    ░     ░        ░           ░

                    written in Rust by ThottySploity
            mimiRust $ means it's running without elevated privileges
             mimiRust # means it's running with elevated privileges
              mimiRust @ means it's running with system privileges


    mimiRust @ ?

    Choose one of the following options:

      passwords:
              • dump-credentials             Dumps systems credentials through Wdigest.
              • dump-hashes                  Dumps systems NTLM hashes (requires SYSTEM permissions).
              • clear                        Clears the screen of any past output.
              • exit                         Moves to top level menu

      pivioting:
              • shell <SHELL COMMAND>        Execute a shell command through cmd, returns output.
              • clear                        Clears the screen of any past output.
              • exit                         Moves to top level menu
              • (W.I.P)psexec                Executes a service on another system.
              • (W.I.P)pth                   Pass-the-Hash to run a command on another system.
              • (W.I.P)golden-ticket         Creates a golden ticket for a user account with the domain.

      privilege:
              • spawn-path <SPAWN_PATH>      Spawn program with SYSTEM permissions from location.
              • clear                        Clears the screen of any past output.
              • exit                         Moves to top level menu

    mimiRust @ passwords
    mimiRust::passwords @ dump-credentials
```

MimiRust is a post-exploitation tool that can be used within redteam operations. Like the name suggests the entire project is made within the Rust language. MimiRust is capable of the following actions:

* Spawning any process as SYSTEM
* Executing shell commands
* Extracting Windows passwords out of memory through the wdigest attack vector.
* Extracting Windows NTLM hashes from user accounts (aes / des) & (md5 / rc4)


Todo:

* PSExec to create and start a service on another endpoint.
* PtH (Pass-The-Hash)
* Kerberos Golden Ticket
* lsa patch to get NTLM hashes from LSASS (Local Security Authority Subsystem Service)

**Maybe in the future I will make API calls obfuscated and strings polymorphic**

## Quick usage:

MimiRust can be ran in two different ways: from the command line using mimiRust.exe --help or in the shell by running the executable without any command line arguments. For help with the program type one of the following into mimiRust:

* `mimiRust # ?`
* `mimiRust # h`
* `mimiRust # help`

You will now be required to type in the module that you want to access, current modules are:

* passwords
* pivioting
* privilege

## Dumping credentials from memory through wdigest

```
mimiRust::passwords # dump-credentials
mimiRust.exe --dump-credentials
```

## Dumping NTLM hashes from user accounts

```
mimiRust::passwords @ dump-hashes
mimiRust.exe --dump-hashes
```

## Executing shell commands

```
mimiRust::pivioting $ shell whoami
```

## Spawning a process with SYSTEM

```
mimiRust::privilege # spawn-path cmd.exe
mimiRust.exe -s cmd.exe
```

## Demo

Click on the demo to get a higher resolution

![demo](./demo.gif)

## Disclaimer

I am not responsible for what you do with the information and code provided. This is intended for professional or educational purposes only.

## Author

### Why was MimiRust made

MimiRust was created as a project by a first years Cyber Security Bachelors student. The reason for this is because I was too bored learning about business processes in a Security Bachelors that I decided to just start for myself.

## Credits / References

* Benjamin DELPY ([@gentilkiwi](https://twitter.com/gentilkiwi)) - https://github.com/gentilkiwi/mimikatz

* Author: ThottySploity