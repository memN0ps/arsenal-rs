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
  <li>PtH (Pass-The-Hash)</li>
  <li>Kerberos Golden Ticket</li>
</ul>

<small><strong>Maybe in the future I will make it polymorphic and obfuscate the strings (also polymorphic) and API calls.</strong></small>


<h2>Quick usage:</h2>
<p>MimiRust can be ran in two different ways: from the command line using mimiRust.exe --help or in the shell by running the executable without any command line arguments. For help with the program type one of the following into mimiRust;</p>
<ul>
  <li><code>mimiRust # ?</code></li>
  <li><code>mimiRust # h</code></li>
  <li><code>mimiRust # help</code></li>
</ul>

<br><h3>Dumping plaintext credentials from memory through wdigest</h3>
<code>mimiRust # dump-credentials</code><br>
<code>mimiRust.exe --dump-credentials</code>
<br>

<br><h3>Dumping NTLM hashes from user accounts</h3>
<code>mimiRust @ dump-hashes</code><br>
<code>mimiRust.exe --dump-hashes</code>
<br>

<br><h3>Executing shell commands</h3>
<code>mimiRust $ shell whoami</code>
<br>

<br><h3>Spawning a process with SYSTEM</h3>
<code>mimiRust # spawn-path cmd.exe</code><br>
<code>mimiRust.exe -s cmd.exe</code>

<h2>Demo</h2>
<small>click on the demo to get a higher resolution</small>
<img src="https://github.com/ThottySploity/mimiRust/blob/main/demo.gif" alt="mimiRust Demo" width="100%">

<br>
<h2>Author</h2>
<h3>Why was MimiRust made</h3>
<p>I was bored in my first year of my CyberSecurity bachelors, as there wasn't anything cyber related being taught. Thus I decided I was going to start my own project, I already knew of Mimikatz for a while and why it was used. However I did not know how it did it's thing, so to get this knowledge I decided to start learning how it does it's thing and thus mimiRust was created.</p>
<br>
<h3>Future plans</h3>
<p>In the future I want to add PtH (Pass-The-Hash) and Kerberos Golden tickets into mimiRust.</p>
<br>
