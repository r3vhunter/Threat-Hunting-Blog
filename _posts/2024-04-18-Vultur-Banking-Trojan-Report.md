---
layout:
title: Android Vultur Banking Trojan 
---

# Threat: Vultur

# Target: Finacial Sector

# Observations 

The Android banking tojan known as Vultur hads resurfaced with a suite of new features and mproved anti-analysis and evasion of techniques. Vulture was first known in early 2021. Vultur is able to leverage Android's accessibility services APIs to ececute malicious actions.
Security researchers found a new version og the VUltur banking trojan for Android that includes more advanced remote control capabilities and an improved evasion mechanism. At the end of 2023, mobile secuiry platform Zimperium included 
Vlutur in its top 10 most active banking trojans for the year. Nine of Vlutur variants targeted 122 banking apps in 15 countries. 

The more evasive version of Vultur spreads to victims through a hybrid attack that relies on SMS phsihing and phone calls that trick the targets into installing a version of the malware that masquarades as the McAfee 
Secuirty app. 

Vultur's Infeciton Chain 
1: Starts with the victim receiving an SMS message alerting of an unauthroized transaction and instructing to call a provided number for guidance. 
2: The call is answered by a fraudster who persuades the victim to open the link arriving with a second SMS,which directs to a site that offers a modified version of Macafee Security App. 
3: The new modified version of the trojaniozed Macafee App is installed which also has the Brunhilda malware dropper. Brunhilda is responsible for hosting malicious applications on the Google Play Store. As illustrated below
the dropper decrypts and executes a total of 3 Vultar-related patyloads, giving the threat actors total control over the victim's maobile device.These files will obtain access to the Accessibility Sercvices, initalize the remote control systems, and establish a connection with the C2 server. 


<picture>

<img src=https://www.bleepstatic.com/images/news/u/1220909/2024/Android/07/infection-chain.jpg width="400">

</picture>

<br>


New Feratures in Vultur
Vultur is able to remotely interact with the infected device hrough the use of Android's Acessibility Sercvices. With this new capability, Attackers can now send commandsin ordfer to perform cliocks, scrolls, and swipe gestures. 
The attacker sends messages to the C2 server by using Firebase Cloud Messaging (FCM) provided by Google. 

Analysis 

Virus Total 

<picture>

<img src="_posts/Vultur_Folder_Images/Screenshot 2024-04-04 161612.png" width="800">

</picture>

<br>

In the sample I have attained here is some information below regarding the Hash edef007f1ca60fdf75a7d5c5ffe09f1fc3fb560153633ec18c5ddb46cc75ea21


Triage

<picture>

<img src=Triage report .png width="400">

</picture>

<br>


Signatures

Accquires the wake lock
Reads information about phone network operator.
Checks the prescence of a debugger
Uses Crypto APIs: This could potentially encrypt the user data. 

Process: com[.]wsandroid.suite


When unpacking the zip file the following appeared folders appeared and three files.  

<picture>

<img src=https://github.com/r3vhunter/r3vhunter.github.io/blob/main/Screenshot%202024-04-04%20174542.png width="400"> 

</picture>

<br>

Within the APK package for the Security MacaFee it uses two languages BASIC and Kotlin  and the library used for the malware is Basic4Android. The APK file also has multiple DEX nad ELF32 files in there as well. \
I provided a screenshot below when analyzing the APK file using Detect It Easy (DIE). 

<picture>

<img src=APK file Analysis DIE.png width="400"> 

</picture>

<br>


Check the Entropy and ninety eight percent of the APK file for MacAfee secuirty is packed. 


<picture>

<img src=Entropy DIE.png width="400"> 

</picture>


Check the Hex Values as well and as you can see from the image below, its mostly encrpted, but we can see a dex file within the APK's memory. 

<picture>

<img src=Hex snapshot.png width="400"> 

</picture>




The message sent by the malware operator through FCM can caontain a command, whichm, upon reciet triggers, the execution of corresponding fucntionality within the malware. This will elimate the ongoing connection 
with the device. Here is a screenshot of the code snippet below regarding Vultar's ability to perform clicks and scrolls using Acessbility Services.

<picture>

<img src=https://github.com/r3vhunter/r3vhunter.github.io/blob/main/Code%20Snippet%20using%20Accessibility%20services.%20.png width="400"> 

</picture>

<br>


Capabilities
. Rmotely Interact with the infected device using Android's Accessibility Services and perfom clicks, scrolls, and swipe gestures. 
. Use Firebase Cloud Messaging (FCM): A messaging service provided by Googel to send commands from the C2 server to the indfected device. 
. Using FCM the attacker sends a message to te messaging service and the message will contain a command, which will trigger the execution within the malware within the device.



Infection Chain 

The infection starts when the victim receives an SMS message alerting an unauthorized transaction and instructing the victim to call the number within the SMS for provided asisstance. The call is then answered by a faudster who persuades
the victim to open the second SMS message that was sent to them by the fraudster. The SMS link will direct the victim to a site that offers a modified version of McAfee Secuirty Apps. The new modified version of McAfee is installed, which also has the Brunhilda malware dropper. 
Brunhilda is a malware that is responsible fort hosting malicious applications on the Google Play Store. As illustrated below the dropper drops threee payloads, giving the threat actors total control over the victim's mobile device. The three payloads will obtain access to the victim's Accessibility Services on their phone and initialize the RCE to establish connection to the C2 server.



<picture>

<img infection chain.png width="400"> 

</picture>

<br>

Infection Chain 


Vultur Obfuscation techniques

Vultur latest variants now adopt AES encryption and Base64 encoding in their HTTP requests. Variants of Vultur in 2022, Brunhilda and Vultur did not have encrpyted HTTP traffic, but did use string obfuscation in Vultur and Brunhilda when being delivered to the victim's Android Device. \




<picture>

<img HTTP traffic.png width="400"> 

</picture>

<br>

AES and Base64 Encrypted traffic for the bot registration. 




Vulur Execution FLow
The Brunhilda dropper in this campaign is a modifie dversion of the legitimate McAfee Secuirty App.


<picture>

<img McAffe screenshot.png width="400"> 

</picture>

<br>

Once installed the device is registered to a C2 sever and the C2 is prtovided with the following informaiton: 
- Malware package name: com[.]wsandroid.suite package
- Android Version 
- Device model 
- Language and Country Code
- Base 64 encoded list of installed applications
- Tag

Then the server respons eias decrypted and stored in a SharedPreference key named 9bd25f13-c3f8-4503-ab34-4bbd63004b6e, and once the bot regestration si successfult, the 3 stages of the Vultur payload will be decrpyted. 


Vultur Payloads

In order for the attacker to have full access to the remote decvice, Vultur has three stages and each stages have their own functionality. The sample that I analyzed was the Brunhilda dropper with the package file name, com[.]wsandroid.suite. 

The First Payload obtains Accessibility Service Periviliages and installs the next Vultur APK file. The reason attackers want this is because Apps with Accessibility Service Permission can have full visibility over UI events, both from the system and from 3rd party apps. The accessibliity service is great for assisitn usersm but for attackers they can perform keyloggiong, grant additional permissions, and monitor other apps.



<picture>

<img Vultur 1.png width="400"> 

</picture>

<br>


The payload will then display a fake error meesage saying  "Your system is not safe, Service McAfee master Proterction turned off. For using full device protection turn on." Once the victim clicks on turn on, the Shared Preference key is set to true. 
And the attacke hash full permission to drop the next stage of Vultur. 

Vultur Payload 2
The second payload contains tools such as AlphaVNc, ngrop setup, and screen recording. The payload uses an Android Acessibility Suite package called com[.]google[.]android[.]marvin[.]talkback. This package will be used to reference methods used in the final payload to gain 
full acess to the device. 

Vultur Payload 3
The final executable iks a Dalvik Executable file (DEX). The DEX file holds VUltur's core functionality. The file contains all the C2 methods used to communicate from bot to C2 server. FCM commands are used in communication from C2 server to bot.



<picture>

<img FCM commands .png width="400"> 

</picture>

<br>

Decompikled code where FCM commands are being used. 


Recommendations 
It is always a good idea to check the permissions an app requests when installed and make sure that you consnet only to those needed for the app's core fucntionality. And recently on April 3, 2024, Google spokesperson stated that Android users are automatically protected 
against known versions of this malware by Google Play Protect, which is on by default on Android devices with Gole Play services. Google Play Protect can also warn users to block apps known to exhibit malicious behavior, even when those apps come from sources outside of Play. 

Conclusion 
