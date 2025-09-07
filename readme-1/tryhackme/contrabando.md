---
description: Never tell me the odds. - by TryHackMe and hadrian3689
---

# Contrabando

***

Platform:[ Tryhackme](https://tryhackme.com/room/contrabando)

Difficulty: Hard

***

#### Scanning and Enumeration

Nmap scan :

```
┌──(ghost㉿kali)-[~/tryhackme/contrabando]
└─$ sudo nmap -Pn -A -p- --min-rate 3000 contrabando.thm -oN nmap.full
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-05 23:42 EDT
Nmap scan report for contrabando.thm (10.201.13.98)
Host is up (0.31s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 41:ed:cf:46:58:c8:5d:41:04:0a:32:a0:10:4a:83:3b (RSA)
|   256 e8:f9:24:5b:e4:b0:37:4f:00:9d:5c:d3:fb:54:65:0a (ECDSA)
|_  256 57:fd:4a:1b:12:ac:7c:90:80:88:b8:5a:5b:78:30:79 (ED25519)
80/tcp open  http    Apache httpd 2.4.55 ((Unix))
|_http-server-header: Apache/2.4.55 (Unix)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Potentially risky methods: TRACE
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 4.X|2.6.X|3.X|5.X (97%)
OS CPE: cpe:/o:linux:linux_kernel:4.15 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:5
Aggressive OS guesses: Linux 4.15 (97%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (91%), Linux 4.15 - 5.19 (91%), Linux 5.0 - 5.14 (91%), Linux 2.6.32 - 3.10 (91%), Linux 5.4 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap scan found 2 ports open on the target machine:

* 22 (SSH)
* 80 (HTTP)

Port 80 (HTTP):

<figure><img src="../../.gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

A static site was hosted with a link to `http://contrabando.thm/page/home.html` and nothing interesting even in the source code.

<figure><img src="../../.gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>

On visiting `http://contrabando.thm/page/home.html` , it shows that their password generator is currently down and again nothing interested in the source code.

While enumerating more and intercepting those requests and response via burp suite, I found there were two different Apache servers we are dealing with.

* Request for `http://contrabando.thm`&#x20;

<figure><img src="../../.gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

* Request for `http://contrabando.thm/page/home.html`&#x20;

<figure><img src="../../.gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

