# Silver Platter

Can you breach the server? - by TeneBrae93

---

Platform: [Tryhackme](https://tryhackme.com/room/silverplatter)

Difficulty: Medium

Initial Access: Brute forcing + IDOR vulnerability

Privilege Escalation: Weak group permissions + Password reuse

---

### Recon

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ sudo nmap -Pn -A -p- --min-rate 3000 -oN nmap.full 10.201.111.54
```

| Ports | Service Running |
| --- | --- |
| 22 | OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 |
| 80 | http nginx 1.18.0 (Ubuntu) |
| 8080 | http-proxy |

Port 80:

A static website is hosted on port 80.

![image.png](image.png)

contact tab revealed a potential valid username - `scr1ptkiddy`

Directory brute forcing found nothing interesting.

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ feroxbuster -u 'http://10.201.106.249/' -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```

![image.png](image%201.png)

Moving onto port 8080, there was also a 404 not found page found. 

![image.png](image%202.png)

Directory brute forcing on port 8080 found 2 new endpoints- `/website` and `/console`

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ feroxbuster -u 'http://10.201.106.249:8080/' -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```

![image.png](image%203.png)

- /website
    
    Noting interesting again, just a forbidden note.
    
    ![image.png](image%204.png)
    
- /console
    
    Again 404 not found page.
    
    ![image.png](image%205.png)
    

After a lot of enumeration I found that room creater given us a hint on that same contact page. `silverpeas`

![image.png](image%206.png)

That’s the endpoint which I was looking for and at that endpoint I found a login form.

![image.png](image%207.png)

Here I tried bruteforcing as we have a username, but not found any valid passwords from rockyou.txt wordlist.

Then I just captured and save words availabe on the website hosted on port 80 and from that password list, I found a valid password for user `scr1ptkiddy`

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ cewl http://10.201.106.249 > passwords.txt
```

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ hydra -l scr1ptkiddy -P passwords.txt 10.201.106.249 -s 8080 http-post-form "/silverpeas/AuthenticationServlet:Login=^USER^&Password=^PASS^&DomainId=0:F=Login or password incorrect"
```

![image.png](image%208.png)

---

### User flag

Successfully logged into scr1ptkiddy’s account.

![image.png](image%209.png)

In “my notification” section, I found it was querying id parameter like these ID=5, probably an IDOR vulnerability.

![image.png](image%2010.png)

For confirmation I intercepted that request with burp and tried to change ID no. to 6 and I found a sensitive information there, tim’s ssh password.

![image.png](image%2011.png)

Logged in to tim’s account via ssh and grabbed user flag.

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ ssh tim@10.201.106.249
```

![image.png](image%2012.png)

---

### Root flag

3 other users were also present in the machine - `ssm-user`, `tyler`, `ubuntu`

![image.png](image%2013.png)

While enumerating machine for privilege eescalation, user tim’s `adm` group permission helped us to enumerate /var/log directory.

![image.png](image%2014.png)

There when I searched for entries related to user tyler, found a database password.

```bash
tim@ip-10-201-106-249:/var/log$ grep -iR tyler
```

![image.png](image%2015.png)

When I tried to log into user tyler’s account with that passwords, it was successfull. Which means maybe password was reused.

![image.png](image%2016.png)

As tyler have full sudo privileges on the machine, I turned it into a root’s shell wih `sudo su` .

![image.png](image%2017.png)

Grabbed the root flag.

![image.png](image%2018.png)

---

That’s it for this machine.✅
