# CMSpit

***

Platform: [Tryhackme](https://tryhackme.com/room/cmspit)

Difficulty: Medium

Initial Access: NoSQL injection on Vulnerable CMS

Privilege Escalation: Vulnerable exiftool binary & misconfigured permissions

***

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

| Ports     | Methodology                                                                                             |
| --------- | ------------------------------------------------------------------------------------------------------- |
| 22 (SSH)  | Potentially for later use                                                                               |
| 80 (HTTP) | Apache httpd version 2.4.18 running, maybe vulnerable and also revealing an endpoint `/auth/login?to=/` |

***

### What is the name of the Content Management System (CMS) installed on the server?

Port 80:

<figure><img src="https://github.com/user-attachments/assets/4f286489-e46f-4418-a269-88929d14c38c" alt=""><figcaption></figcaption></figure>

Answer: Cockpit CMS is running on the target machine.

***

### What is the version of the Content Management System (CMS) installed on the server?

Looking at the source code of that login page, revealed version no. of CMS.

<figure><img src="https://github.com/user-attachments/assets/54d541ff-05a1-4959-8d7d-d5c8db6e740c" alt=""><figcaption></figcaption></figure>

***

### What is the path that allow user enumeration?

Again source code revealed the potential path for user enumeration.

<figure><img src="https://github.com/user-attachments/assets/0184d3d5-8221-456d-a7e0-dc25a596cd9c" alt=""><figcaption></figcaption></figure>

***

### How many users can you identify when you reproduce the user enumeration attack?

Searching on google about vulnerabilities related to that particular version of CMS revealed a public exploit CVE-2020-35848.

<figure><img src="https://github.com/user-attachments/assets/44087450-c59e-48b8-bd58-c3e306a83947" alt=""><figcaption></figcaption></figure>

searched that edb-id on with searchsploit and found that PoC.

<figure><img src="https://github.com/user-attachments/assets/ab65cba2-d1da-487a-a829-33ea9dd834f6" alt=""><figcaption></figcaption></figure>

Copied that PoC on my working directory.

<figure><img src="https://github.com/user-attachments/assets/4c8beffa-9409-4698-94a9-2d8373a37907" alt=""><figcaption></figcaption></figure>

Running that script revealed 4 usernames: `admin, darkStar7471, skidy, ekoparty`

<figure><img src="https://github.com/user-attachments/assets/cc37beab-e08c-4e89-bb5b-70a321d1f7da" alt=""><figcaption></figcaption></figure>

***

### What is the path that allows you to change user account passwords?

PoC script revealed which path it is using to reset user’s password

<figure><img src="https://github.com/user-attachments/assets/b925b249-2997-4770-a7ad-27d4b4eab198" alt=""><figcaption></figcaption></figure>

***

### Compromise the Content Management System (CMS). What is Skidy's email?

Getting user details through that same Poc revealed skidy’s email.

<figure><img src="https://github.com/user-attachments/assets/6def551c-e082-41ea-b334-520cd70fe4fb" alt=""><figcaption></figcaption></figure>

Moving forwards, changed skidy’s password with that same script follow up.

<figure><img src="https://github.com/user-attachments/assets/1d250e31-9b0b-4b2e-b70b-df2888bad532" alt=""><figcaption></figcaption></figure>

Logged in to skidy’s account via that CMS login page.

&#x20;

<figure><img src="https://github.com/user-attachments/assets/045c0986-11ef-4169-a012-e122a77b1f13" alt=""><figcaption></figcaption></figure>

<figure><img src="https://github.com/user-attachments/assets/37345f4d-e439-4d77-b3cc-193d31a13ebc" alt=""><figcaption></figcaption></figure>

While enumerating that CMS found an endpoind, where we can upload a file ( our favourite file php-reverse-shell.php)

<figure><img src="https://github.com/user-attachments/assets/fa87a343-af57-49ae-81c5-5f7c52d7c23d" alt=""><figcaption></figcaption></figure>

Uploaded php-reverse-shell.php file on that CMS and triggered that to get reverse shell back.

&#x20;

<figure><img src="https://github.com/user-attachments/assets/69333f57-6f7e-4180-95fc-ba62fc17558e" alt=""><figcaption></figcaption></figure>

<figure><img src="https://github.com/user-attachments/assets/fa921ed7-1e3e-4aee-8146-74d8c7036679" alt=""><figcaption></figcaption></figure>

***

### What is the web flag?

Web flag is in the directory /var/www/html/cockpit

<figure><img src="https://github.com/user-attachments/assets/fb7cd833-82aa-4acf-9c0f-8e0395e188c7" alt=""><figcaption></figcaption></figure>

***

### Compromise the machine and enumerate collections in the document database installed in the server. What is the flag in the database?

While enumerating for internal services running on the machine, found a port 27017(default port for mongodb) open and listening internally. Most probably mongodb is running on that.

<figure><img src="https://github.com/user-attachments/assets/d55b270a-466b-4300-89c3-b4bb3e17950b" alt=""><figcaption></figcaption></figure>

Spawned mongodb shell.

<figure><img src="https://github.com/user-attachments/assets/3b1cdf93-b6a0-4c55-b42a-bb3fee3e72fa" alt=""><figcaption></figcaption></figure>

Listed all databases present

<figure><img src="https://github.com/user-attachments/assets/6a150b4d-6279-4266-aaf6-a3101837edc1" alt=""><figcaption></figcaption></figure>

Used sudousersbak database and listed all collections stored in it.

<figure><img src="https://github.com/user-attachments/assets/f88f0dd7-6c3d-4c42-80bc-86ed159c834c" alt=""><figcaption></figcaption></figure>

Grabbed that flag data

<figure><img src="https://github.com/user-attachments/assets/4ad2a975-5390-4559-98fe-a8928d3065e7" alt=""><figcaption></figcaption></figure>

***

### What is the user.txt flag?

While enumerating that database, also found a collection named user, opening that collection revealed a username `stux` and it’s password.

<figure><img src="https://github.com/user-attachments/assets/09590660-8dc7-44fa-8e2e-ec6cae0f9c08" alt=""><figcaption></figcaption></figure>

Logged in to stux’s account via ssh

<figure><img src="https://github.com/user-attachments/assets/c8139103-ee08-41a7-9f0f-c48bcce234ba" alt=""><figcaption></figcaption></figure>

Grabbed user flag

<figure><img src="https://github.com/user-attachments/assets/80727a59-4ecf-47e5-bf88-fd66f170a105" alt=""><figcaption></figcaption></figure>

***

### What is the CVE number for the vulnerability affecting the binary assigned to the system user?

Exploring stux’s sudo privileges revealed that stux can run exiftool binary with sudo privileges.

<figure><img src="https://github.com/user-attachments/assets/9846c99e-0c06-49a3-b3a6-30dc160d6b45" alt=""><figcaption></figcaption></figure>

Let’s check version of exiftool binary present in the target machine.

<figure><img src="https://github.com/user-attachments/assets/583473ba-49aa-46fa-8091-f8f279865f18" alt=""><figcaption></figcaption></figure>

Searching for exploit related to this particular version of exiftool on google again revealed one more public exploit and its PoC.

<figure><img src="https://github.com/user-attachments/assets/2fdd32b0-34d1-41c9-bc1a-c61335f24ebd" alt=""><figcaption></figcaption></figure>

***

### What is the utility used to create the PoC file?

PoC script revealed what utility it is using to create the PoC file.

<figure><img src="https://github.com/user-attachments/assets/4fe6dfac-8e15-46ab-80a8-f02488f00857" alt=""><figcaption></figcaption></figure>

***

### Escalate your privileges. What is the flag in root.txt?

As stux can run exiftool with sudo privileges, stux can read root.txt file using a normal feature of exiftool.

<figure><img src="https://github.com/user-attachments/assets/7e1feb4e-38f2-440d-9fd1-f009f7684d2e" alt=""><figcaption></figcaption></figure>

***

That’s it for this machine.✅
