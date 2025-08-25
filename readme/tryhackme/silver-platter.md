---
description: Can you breach the server? - by TeneBrae93
---

# Silver Platter

***

Platform: [Tryhackme](https://tryhackme.com/room/silverplatter)

Difficulty: Medium

Initial Access: Brute forcing + IDOR vulnerability

Privilege Escalation: Weak group permissions + Password reuse

***

### Recon

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ sudo nmap -Pn -A -p- --min-rate 3000 -oN nmap.full 10.201.111.54
```

| Ports | Service Running                 |
| ----- | ------------------------------- |
| 22    | OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 |
| 80    | http nginx 1.18.0 (Ubuntu)      |
| 8080  | http-proxy                      |

Port 80:

A static website is hosted on port 80.

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

contact tab revealed a potential valid username - `scr1ptkiddy`

<figure><img src="../../.gitbook/assets/image 6.png" alt=""><figcaption></figcaption></figure>

Directory brute forcing found nothing interesting.

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ feroxbuster -u 'http://10.201.106.249/' -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```

<figure><img src="../../.gitbook/assets/image 1.png" alt=""><figcaption></figcaption></figure>

Moving onto port 8080, there was also a 404 not found page found.

<figure><img src="../../.gitbook/assets/image 2.png" alt=""><figcaption></figcaption></figure>

Directory brute forcing on port 8080 found 2 new endpoints- `/website` and `/console`

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ feroxbuster -u 'http://10.201.106.249:8080/' -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```

<figure><img src="../../.gitbook/assets/image 3.png" alt=""><figcaption></figcaption></figure>

*   /website

    Noting interesting again, just a forbidden note.

<figure><img src="../../.gitbook/assets/image 4.png" alt=""><figcaption></figcaption></figure>

*   /console

    Again 404 not found page.

<figure><img src="../../.gitbook/assets/image 5.png" alt=""><figcaption></figcaption></figure>

After a lot of enumeration I found that room creater given us a hint on that same contact page. `silverpeas`

<figure><img src="../../.gitbook/assets/image 6.png" alt=""><figcaption></figcaption></figure>

That’s the endpoint which I was looking for and at that endpoint I found a login form.

<figure><img src="../../.gitbook/assets/image 7.png" alt=""><figcaption></figcaption></figure>

Here I tried brute-forcing as we have a username, but not found any valid passwords from rockyou.txt wordlist.

Then I just captured and save words available on the website hosted on port 80 and from that password list, I found a valid password for user `scr1ptkiddy`

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ cewl http://10.201.106.249 > passwords.txt
```

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ hydra -l scr1ptkiddy -P passwords.txt 10.201.106.249 -s 8080 http-post-form "/silverpeas/AuthenticationServlet:Login=^USER^&Password=^PASS^&DomainId=0:F=Login or password incorrect"
```

<figure><img src="../../.gitbook/assets/image 8.png" alt=""><figcaption></figcaption></figure>

***

### User flag

Successfully logged into scr1ptkiddy’s account.

<figure><img src="../../.gitbook/assets/image 9.png" alt=""><figcaption></figcaption></figure>

In “my notification” section, I found it was querying id parameter like these ID=5, probably an IDOR vulnerability.

<figure><img src="../../.gitbook/assets/image 10.png" alt=""><figcaption></figcaption></figure>

For confirmation I intercepted that request with burp and tried to change ID no. to 6 and I found a sensitive information there, tim’s ssh password.

<figure><img src="../../.gitbook/assets/image 11.png" alt=""><figcaption></figcaption></figure>

Logged in to tim’s account via ssh and grabbed user flag.

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ ssh tim@10.201.106.249
```

<figure><img src="../../.gitbook/assets/image 12.png" alt=""><figcaption></figcaption></figure>

***

### Root flag

3 other users were also present in the machine - `ssm-user`, `tyler`, `ubuntu`

<figure><img src="../../.gitbook/assets/image 13.png" alt=""><figcaption></figcaption></figure>

While enumerating machine for privilege escalation, user tim’s `adm` group permission helped us to enumerate /var/log directory.

<figure><img src="../../.gitbook/assets/image 14.png" alt=""><figcaption></figcaption></figure>

There when I searched for entries related to user tyler, found a database password.

```bash
tim@ip-10-201-106-249:/var/log$ grep -iR tyler
```

<figure><img src="../../.gitbook/assets/image 15.png" alt=""><figcaption></figcaption></figure>

When I tried to log into user tyler’s account with that passwords, it was successful. Which means maybe password was reused.

<figure><img src="../../.gitbook/assets/image 16.png" alt=""><figcaption></figcaption></figure>

As tyler have full sudo privileges on the machine, I turned it into a root’s shell with `sudo su`&#x20;

<figure><img src="../../.gitbook/assets/image 17.png" alt=""><figcaption></figcaption></figure>

Grabbed the root flag.

<figure><img src="../../.gitbook/assets/image 18.png" alt=""><figcaption></figcaption></figure>

***

That’s it for this machine.✅
