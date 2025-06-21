# What is Myth Stealer 
Security researchers at Trellix identified a fully undetected information stealer called Myth Stealer. Written in Rust, this malware has been marketed on Telegram since late December 2024. It was initially offered as a free trial for users to test its functionality and capabilities, before evolving into a subscription-based model. 

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/telegrampost.png" >

</picture>
Figure 1: Telegram Post

# How is this Malware distributed 
The malware is distributed through fraudulent gaming websites in the following formats:

1: Password-protected RAR file

2: RAR archive containing the stealer executable and additional game-related files

3: ZIP archive containing supplementary files, including [README.md](http://README.md) with game installation instructions

4: Standalone EXE file 

# Myth Stealer Infection Chain
1: User visits a gaming website and downloads cracked software. 

2: Once executed, the malware displays a fake window to appear legitimate while decrypting and executing malicious code in the background.

3: Once decrypted and downloaded on the victim's machine, the stealer targets both Gecko-based and Chromium-based browsers, extracting sensitive data including passwords and cookies.

# Myth Stealer Capabilities 
Capabilities include stealing cookies, passwords, and auto-fill information. In addition, Myth Stealer has Anti-Analysis Techniques as well:

1. String obfuscation
2. System checks

# Analysis 

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/VT.png" >

</picture>
Figure 2: Virus Total Score

In my statistical analysis, I found that the file was classified as a console application, originating from a gaming website that distributes cracked software. Using DIE (Detect It Easy), while the program initially identified the code as C/C++, it was actually written in Rust using AMD64 architecture with a MinGW compiler. 

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/DIE.PNG" >

</picture>

Figure 3: Detect It Easy (DIE) 

# Entropy 
Analysis of the file's entropy shows it is heavily obfuscated, with 98 percent of the content being packed. This explains its large file size of 64 MB

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/Entropy.PNG" >

</picture>

Figure 4: Entropy 7.8

The file is divided into 8 sections, with the .rdata section being packed. This section contains read-only data such as strings, tables, and the encrypted payload. Due to the high level of obfuscation, performing statistical analysis on the Myth Stealer is difficult. 

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/entropy2.png" >

</picture>
Figure 5: Section 2 of the file is packed. 

# Strings

Despite the file's high entropy, I identified several unique strings that revealed insights about the stealer's library and capabilities: 

1: GetCurrentThreadID

2: GetProcAddress

3: GetClipboardData

4: /rustc/4eb161250e340c8f48f66e2b929ef4a5bed7z181\library\core

5: VirtualProtect

6: LockResource

7: %Sectigo Public Code Signing CA EV R360

8: kernel32.dll

# Execution
Upon execution, I received a game installation guide. However, the malware was simultaneously gathering information about its environment. It executed a query to check if it was running in a virtual environment. Below is a screenshot of the syscalls made. As shown, the malware uses NtCreateFile to check if specific files exist within the System32\drivers directory. 

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/setup.png" >

</picture>

Figure 6: Setup Pop up page

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/VM%20detection.PNG" >

</picture>

Figure 7: Checking if its within an virtual enviorment.

# New Process Creation (conhost.exe) 

After the initial execution of the parent process, a new process called conhost.exe was created. While conhost.exe is a legitimate Windows process, attackers often create a malicious version to mask their malware. Further analysis of this process revealed that the command line used "DllPath: empty" to load a DLL file into the infected machine. Additionally, the process created a mutex to prevent the malware from reinfecting the system and overloading it, which could raise suspicion. 
<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/mutex%20creation.PNG" >

</picture>

Figure 8: Mutex Creation

# Registry Modification 
The malware also made registry modifications in the USER registry to establish persistence within the machine and set it as normal activity. 
<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/regsitry.PNG" >

</picture>

Figure 9: Registry Modification

# Network Activity 
During network analysis, my machine made three DNS queries over port 80 to these domains:

myth[.]cocukporno[.]lol

disocrd[.]com

api[.]ipify[.]org

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/DNS%20request.PNG" >

</picture>

Figure 10: DNS request via port 80 

Analysis of the IP addresses reveals that all domains are hosted on Content Delivery Networks (CDNs), a technique threat actors use to mask their traffic. All domains have been flagged as malicious in VirusTotal. The domain api[.]ipify[.]org is commonly used by attackers to collect victims' IP addresses and system information. Network traffic analysis revealed a POST request to this domain, and examination of the captured PCAP showed a myth.zip file being transmitted. This suggests the domain serves as the Command and Control (C2) server. Further investigation of cocukporno[.]lol showed it was registered only 300 days ago, indicating it's a relatively new domain. 

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/Domain%201.png" >

</picture>

Figure 11:cocukporno[.]lol

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/whois%20domain.png" >

</picture>

Figure 12: Domain for cocukporno[.]lol

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/domain%202.png" >

</picture>

Figure 13:disocrd[.]com

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/domain%203.png" >

</picture>

Figure 14: api[.]ipify[.]org

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/HTTP%20Post.PNG" >

</picture>

Figure 15: POST Request being sent back to cocukporno[.]lol domain

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Mtyth%20Stealer/wireshark.PNG" >

</picture>

Figure 16: Wireshark Obfuscated Post Request with a Zip file

# Conclusion
The newly emerged Rust-based info stealer, Myth Stealer, continues to evolve across versions, making it increasingly difficult for security solutions to detect. Its use of string obfuscation, stealthy C2 communication, and features like fake window display demonstrate the threat actors' sophisticated techniques. The malware's ongoing development by its creators poses a serious risk to users. To combat this evolving stealer, organizations need continuous monitoring, swift response to alerts, and proactive threat management. Users must remain vigilant and exercise caution when downloading software from third-party sites.









