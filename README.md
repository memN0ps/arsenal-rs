# MimiRust - Hacking the Windows operating system to hand us the keys to the kingdom with Rust.
<p>MimiRust is a program based on the wdigest attack vector implementation employed within Mimikatz. MimiRust has been made to extract pain-text passwords out of the memory of certain Windows operating systems. Also like the name suggests MimiRust has been made in the Rust language.</p>
<h2>Which operating systems does MimiRust support</h2>
<p>It supports the following operating systems:</p>
<ul>
  <li>Win7 x64</li>
  <li>Windows Server 2008 x64</li>
  <li>Windows Server 2008R2 x64</li>
  <li>Win8 x64</li>
  <li>Windows Server 2012 x64</li>
  <li>Windows Server 2012R2 x64</li>
  <li>Win10_1507(and before 1903) x64</li>
</ul>
<small>Note: out of some tests it turned out that it does not dump credentials with some of the above operating systems. (however on other installations of the same operating system it did.)</small><br>
<br>
<h2>Why was MimiRust made</h2>
<p>I was bored in my first year of my CyberSecurity bachelors, as there wasn't anything cyber related being taught. Thus I decided I was going to start my own project, I already knew of Mimikatz for a while and why it was used however I did not know how it did it's thing though, so to get this knowledge I decided to start learning how it does it's thing and thus mimiRust was created.</p>
<br>
<h2>Future plans</h2>
<p>For the future I want to add more functionality/capability to MimiRust (like getting NTLM hashes) so it can be fully employed inside of redteam operations.</p>
<br>
<h2>Demo</h2>
![](https://raw.github.com/ThottySploity/mimiRust/main/demo.gif)
