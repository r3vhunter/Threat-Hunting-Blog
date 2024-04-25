

# What is Cerber 

Cerber(aka C3rb3r) ransomware operates as a semi-private Ransomware-AS-a-Service(RaaS) and was the first obsevers in 2016. Cerber oeprations peaked between 2016 and 2017. From 2020 onward, there have been spradic Cerber campignss with contemporary payloads supporting both Linux and Windows operating systems. In late 2023, Cerber resurfaced again in a new campaign targeting ecxposed Atlassian Confluence Data Center and Server prodcuts using CVE-2023-22518. There is a large amount of copverage on the Windows variant, however there is very little about the Linux variant. In this report we are going to discuss the Linux variant.


# Cerber Execution Flow 

In Cerber's new campign the attacker leverages CVE-2023-22518 to gain access to vulnerable instances of Confluence. CVE-2023-22518 is an improper authorization vulnerability that allows an attacker to reset the Confluence application to reset the Confluence application to create a new admin account using an unporotected configuration endpoint used by the setup wizard. 


Figure 1: Traffic creating a new admin account


Once an administrator account is created, it can be used to upload and install maliicous code bia admin panel. The attacker will then use a web shell to download and run the Cerber payload. In the files owned by the confluence user. If it was running a higher privilged userw, it would not only encrpyrt the user's data within the Confluence application but will encrpyt all files on the system. 


# File Analysis 

The ransomware consits of three highly obfuscated C++ payloads, compiled as aa 64-bit Executbale and Linable Format (ELF, the foormat for executable binary files on Linux) and packed with UPX. UPX is a very common packer used by many threat actors. UPX alloed the actual program code to be stored and encoded in the binary. And when the binary gets executed, it gets extracted into memory and executed ("unpacked"). The reason its extracted into memory is to prevent any security software from scanning the paylaod. 


# Primary Payload
# Hash(4ed46b98d047f5ed26553c6f4fded7209933ca9632b998d265870e3557a5cdfe)

 The primary payload is packed with UPX, and its main purpose is to set up the enviorment and gather the other payloads to run. Below I described the execution sequence as follows: 

 1: Once the payload is executedm it unpacks itself and creats a file in the directory /var/locl/0init-ld.lo. Creating a fikle here will prevent duplicate execution of the ransomware. 
 2: Once the file is created, it connects to C2 server 45.145.6.112 and gets the second payload agttydck, a log checker. It retireves the log checker by doing GET/agttydcki64 and writing the payload to a temporary directory /tmp/agttydck.bat. 
 3: The second payload is then executed with /tmp and ck.log. 
 4: Once the second payload is done, the main paylaod checks if the log file at /tmp/ck.log it wrote exits, If the file exits, then the promary payload will then preoceed to delete itslef and agttydcki64 from the disk. 
 5: It then downloads the encryptor payload and drop it in /tmp/agttydcb.bat 


# AGTTYDCK
# Hash (1849bc76e4f9f09fc6c88d5de1a7cb304f9bc9d338f5a823b7431694457345bd)

The second payload is the log checker, and it serves as a permission chekcer. When run, it concatenates each argument passed to it and delimits with forward slashes to obtain a full path. Then it tries to open the file in write mode and if ther is a success it returns a 0. If it is unsuccessful, it returns 1. 


# Payload 3 (ce51278578b1a24c0fc5f8a739265e88f6f8b32632cf31bf7c142571eb22e243) 

The encrpytor encrypts files ont he filesystem. The payload is UPX packed, Upon execution, the apyload 


 


 






