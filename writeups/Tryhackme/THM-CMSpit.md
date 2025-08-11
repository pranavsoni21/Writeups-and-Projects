# CMSpit

---

Platform: [Tryhackme](https://tryhackme.com/room/cmspit)

Difficulty: Medium

Initial Access: NoSQL injection on Vulnerable CMS

Privilege Escalation: Vulnerable exiftool binary & misconfigured permissions

---

Nmap Scan:

```bash
┌──(ghost㉿kali)-[~/tryhackme/CMSpit]
└─$ cat nmap.full  
# Nmap 7.95 scan initiated Sun Aug 10 23:22:36 2025 as: /usr/lib/nmap/nmap -Pn -A -p- --min-rate 4000 -oN nmap.full 10.201.61.230
Warning: 10.201.61.230 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.201.61.230
Host is up (0.25s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7f:25:f9:40:23:25:cd:29:8b:28:a9:d9:82:f5:49:e4 (RSA)
|   256 0a:f4:29:ed:55:43:19:e7:73:a7:09:79:30:a8:49:1b (ECDSA)
|_  256 2f:43:ad:a3:d1:5b:64:86:33:07:5d:94:f9:dc:a4:01 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-title: Authenticate Please!
|_Requested resource was /auth/login?to=/
|_http-trane-info: Problem with XML parsing of /evox/about
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Ports | Methodology |
| --- | --- |
| 22 (SSH) | Potentially for later use |
| 80 (HTTP) | Apache httpd version 2.4.18 running, maybe vulnerable and also revealing an endpoint `/auth/login?to=/` |

---

### What is the name of the Content Management System (CMS) installed on the server?

Port 80:

![image.png](image.png)

Answer: Cockpit CMS is running on the target machine.

---

### What is the version of the Content Management System (CMS) installed on the server?

Looking at the source code of that login page, revealed version no. of CMS.

![image.png](image%201.png)

---

### What is the path that allow user enumeration?

Again source code revealed the potential path for user enumeration.

![image.png](image%202.png)

---

### How many users can you identify when you reproduce the user enumeration attack?

Searching on google about vulnerabilities related to that particular version of CMS revealed a public exploit CVE-2020-35848.

![image.png](image%203.png)

searched that edb-id on with searchsploit and found that PoC.

![image.png](image%204.png)

Copied that PoC on my working directory.

![image.png](image%205.png)

Running that script revealed 4 usernames: `admin, darkStar7471, skidy, ekoparty`

![image.png](image%206.png)

---

### What is the path that allows you to change user account passwords?

PoC script revealed which path it is using to reset user’s password

![image.png](image%207.png)

---

### Compromise the Content Management System (CMS). What is Skidy's email?

Getting user details through that same Poc revealed skidy’s email.

![image.png](image%208.png)

Moving forwards, changed skidy’s password with that same script follow up.

![image.png](image%209.png)

Logged in to skidy’s account via that CMS login page.

![image.png](image%2010.png)

![image.png](image%2011.png)

While enumerating that CMS found an endpoind, where we can upload a file ( our favourite file php-reverse-shell.php)

![image.png](image%2012.png)

Uploaded php-reverse-shell.php file on that CMS and triggered that to get reverse shell back.

![image.png](image%2013.png)

![image.png](image%2014.png)

---

### What is the web flag?

Web flag is in the directory /var/www/html/cockpit

![image.png](image%2015.png)

---

### Compromise the machine and enumerate collections in the document database installed in the server. What is the flag in the database?

While enumerating for internal services running on the machine, found a port 27017(default port for mongodb) open and listening internally. Most probably mongodb is running on that.

![image.png](image%2016.png)

Spawned mongodb shell.

![image.png](image%2017.png)

Listed all databases present

![image.png](image%2018.png)

Used sudousersbak database and listed all collections stored in it.

![image.png](image%2019.png)

Grabbed that flag data

![image.png](image%2020.png)

---

### What is the user.txt flag?

While enumerating that database, also found a collection named user, opening that collection revealed a username `stux` and it’s password.

![image.png](image%2021.png)

Logged in to stux’s account via ssh

![image.png](image%2022.png)

Grabbed user flag

![image.png](image%2023.png)

---

### What is the CVE number for the vulnerability affecting the binary assigned to the system user?

Exploring stux’s sudo privileges revealed that stux can run exiftool binary with sudo privileges.

![image.png](image%2024.png)

Let’s check version of exiftool binary present in the target machine.

![image.png](image%2025.png)

Searching for exploit related to this particular version of exiftool on google again revealed one more public exploit and its PoC.

![image.png](image%2026.png)

---

### What is the utility used to create the PoC file?

PoC script revealed what utility it is using to create the PoC file.

![image.png](image%2027.png)

---

### Escalate your privileges. What is the flag in root.txt?

As stux can run exiftool with sudo privileges, stux can read root.txt file using a normal feature of exiftool.

![image.png](image%2028.png)

---

That’s it for this machine.✅