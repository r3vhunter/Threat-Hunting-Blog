# What is the Amatera Stealer 

Proofpoint has identified a new threat called the Amatera Stealer, a rebranded version of ACR stealer. While Amatera shares significant code overlap, features, and capabilities with ACR stealer, it has undergone substantial development and enhancement to emerge as a distinct potential threat in the cyber landscape. The image below shows the Amatera Stealer's pricing panel. Prices range from $200 to $1,500, depending on the duration of access required by the attacker. 

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Amatera_Stealer/Figure_1.png" >

</picture>

Figure 1: Amatera Stealer Subscription model 


When users navigate to the panel, they must first create an account. Once account creation is successful, attackers can purchase access to the product for various durations: 

- One month: $199
- Three months: $499
- Six months: $899
- One Year: $1499

# Makware Capabilities

Amatera Stealer primarily targets information from installed software such as browsers and crypto wallets, with its specific targets depending on configuration options received from its command and control (C2) server. It accomplishes this by scanning the file system using glob-syntax search patterns through the NtCreateFile and NtQueryDirectoryFile functions. Here's what the stealer specifically targets: 

- Stealing files on disk for file paths pertaining to software wallets
- Stealing files on disk that match a specific extension or keyword
- Stealing browsing data relating to Cookies, Web Forums, Profile Data (Web history)
- Bypasses App Bound Encryption for Chrome-related browsers by injecting a shellcode into the browser which causes it to copy sensitive files to a location that can be exfiltrated by the malware.
- Stealing information from extensions such as password managers and crypto wallets.
- Stealing email information from connection management software such as FTP and SSH.
- Run secondary payloads with extensions of .exe, .cmd, .dll, and .ps1 using the ShellExecuteA Windows API.
- Downloading and executing a .ps1 script using PowerShell’s DownloadString and executing it using Invoke-Expression ( IEX).

# Malware Distribution
Amatera was distributed through a campaign via ClearFake website injects between April and May 2025. ClearFake is a sophisticated malicious JavaScript framework first discovered in the wild in July 2023. Attackers use this framework to compromise WordPress plugins and other content management-based websites to deliver malware disguised as fake browser updates. In the case of the Amatera Stealer, victims receive a notification prompting them to update their browser. When victims click on the update button, the JavaScript downloads the malicious Amatera stealer onto their system. 

# Amatera Stealer Analysis 


<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Amatera_Stealer/Figure_2.png" >

</picture>
Figure 2: Virus Total Score on Sample


<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Amatera_Stealer/Figure_8.png" >

</picture>

The Amatera Stealer is malware written in C++ that operates as a Malware-as-a-Service (MaaS). The malware was compiled using Visual Studio and designed for AMD64 architecture.. 

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Amatera_Stealer/Figure_3.png" >

</picture>
Figure 3: DIE(Detect It Easy) File informaitn 

# File Entropy 

Looking at the entropy of the file, sixty-six percent of the file is not packed. This could be because the file includes a GUI to appear legitimate to victims. As mentioned earlier, attackers are utilizing the ClearFake campaign to deliver Amatera via fake browser updates. An examination of the PE header and file sections confirms that none of the sections are packed. 

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Amatera_Stealer/Figure_4.png" >

</picture>

Figure 4: File Entropy 

# Strings 

Due to sixty-six percent of the file is not obfuscated, I came across a few unique strings: 

- CreateRemoteThread
- ReadProcessMemory
- GetCurrentProcess
- CheckRemoteDebuggerPresent
- SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
- %appdata%\Telegram Desktop\tdata
- afdprox[.]icu
- SOFTWARE\Microsoft\Cryptography
- HARDWARE\DESCRIPTION\System\BIOS
- "app_bound_encrypted_key":”
- FindFirstFileW
- desktop_wallets
- LoalLibraryW
- ElavatorShell.exe

From the unique strings discovered, the victim seems the victim navigated to a suspicious domain utilizing a (icu) domain. The stealer is disguising itself as a file called elavator.exe. This is an application that provides remote access to computers from anywhere. And with this app, users can control their computer from their mobile device, allowing them to manage their files. Once executed the stealer will start gathering information on the user’s machine.


# Malware Network Traffic 

From the unique strings discovered, the victim seems the victim navigated to a suspicious domain utilizing a (icu) domain. The stealer is disguising itself as a file called elavator.exe. This is an application that provides remote access to computers from anywhere. And with this app, users can control their computer from their mobile device, allowing them to manage their files. Once executed the stealer will start gathering information on the user’s machine.

<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Amatera_Stealer/Figure_5.png" >

</picture>

Figure 5: File information from Threat Zone. 


<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Amatera_Stealer/Figure_6.png" >

</picture>

Figure 6: Attackers masking their IP traffic. 


<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Amatera_Stealer/Figure_7.png" >

</picture>

Figure: Traffic being analyzed in Wireshark where the HTTP request from domian is sending obfuscated text back to the victim. 


# TTPS(Tactics Techniuques and Procedures


<picture>
<img src="https://github.com/r3vhunter/Threat-Hunting-Blog/blob/master/_posts/Amatera_Stealer/Figure_9.png" >

</picture>




