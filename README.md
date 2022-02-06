# MimiRust - Hacking the Windows operating system to hand us the keys to the kingdom with Rust.

<code>

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


    mimiRust $ ?

    dump-credentials             Dumps systems credentials through Wdigest
    dump-hashes                  Dumps systems NTLM hashes (requires SYSTEM permissions)
    spawn-path <SPAWN_PATH>      Spawn program with SYSTEM permissions from location
    shell <SHELL COMMAND>        Execute a shell command through cmd, returns output
    exit                         Exits out of mimiRust



    mimiRust $

</code>
<p>MimiRust is a post-exploitation tool that can be used within redteam operations. Like the name suggests the entire project is made within the Rust language. MimiRust is capable of the following actions:</p>
<ul>
  <li>Spawning any process as SYSTEM</li>
  <li>Executing shell commands</li>
  <li>Extracting Windows passwords out of memory through the wdigest attack vector.</li>
  <li>Extracting Windows NTLM hashes from user accounts (aes / des)</li>
</ul><br>
<p>Todo:</p>
<ul>
  <li>Extracting Windows NTLM hashes from user accounts (md5 / rc4)</li>
</ul>

<h2>Quick usage:</h2>
<p>MimiRust can be ran in two different ways: from the command line using mimiRust.exe --help or in the shell by running the executable without any command line arguments. For help with the program type one of the following into mimiRust;</p>
<ul>
  <li><code>mimiRust # ?</code></li>
  <li><code>mimiRust # h</code></li>
  <li><code>mimiRust # help</code></li>
</ul>

### Dumping plaintext credentials from memory through wdigest ###
<code>mimiRust # dump-credentials</code><br>
<code>mimiRust.exe --dump-credentials</code>

### Dumping NTLM hashes from user accounts ###
<code>mimiRust @ dump-hashes</code><br>
<code>mimiRust.exe --dump-hashes</code>

### Executing shell commands ###
<code>mimiRust $ shell whoami</code>

### Spawning a process with SYSTEM ###
<code>mimiRust # spawn-path cmd.exe</code><br>
<code>mimiRust.exe -s cmd.exe</code>

<br>
<h2>Why was MimiRust made</h2>
<p>I was bored in my first year of my CyberSecurity bachelors, as there wasn't anything cyber related being taught. Thus I decided I was going to start my own project, I already knew of Mimikatz for a while and why it was used however I did not know how it did it's thing, so to get this knowledge I decided to start learning how it does it's thing and thus mimiRust was created.</p>
<br>
<h2>Future plans</h2>
<p>For the future I want to add more functionality/capability to MimiRust (like getting NTLM hashes) so it can be fully employed inside of redteam operations.</p>
<br>
<h2>Demo</h2>
https://vimeo.com/673938805
