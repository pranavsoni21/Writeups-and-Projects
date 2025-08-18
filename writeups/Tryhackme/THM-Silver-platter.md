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

<img width="1908" height="799" alt="image" src="https://github.com/user-attachments/assets/63ecbe86-b1f1-4356-aac4-7d0cf7430105" />

contact tab revealed a potential valid username - `scr1ptkiddy`

Directory brute forcing found nothing interesting.

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ feroxbuster -u 'http://10.201.106.249/' -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```

<img width="1273" height="690" alt="image 1" src="https://github.com/user-attachments/assets/45316532-c3a9-4feb-aa53-63e162adea99" />

Moving onto port 8080, there was also a 404 not found page found. 

<img width="1919" height="219" alt="image 2" src="https://github.com/user-attachments/assets/13861357-3930-40bb-976b-2d6334321298" />

Directory brute forcing on port 8080 found 2 new endpoints- `/website` and `/console`

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ feroxbuster -u 'http://10.201.106.249:8080/' -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```

<img width="1541" height="582" alt="image 3" src="https://github.com/user-attachments/assets/acda4c10-aeab-4ff3-9d64-cbd6a243733e" />

- /website
    
    Noting interesting again, just a forbidden note.
    
    <img width="1919" height="185" alt="image 4" src="https://github.com/user-attachments/assets/bd7baf90-1689-4457-98ce-b85d2e3a6204" />
    
- /console
    
    Again 404 not found page.
    
    <img width="1918" height="125" alt="image 5" src="https://github.com/user-attachments/assets/9bd05f81-c9ec-44e6-a868-f2b51275ca7d" />
    

After a lot of enumeration I found that room creater given us a hint on that same contact page. `silverpeas`

<img width="849" height="441" alt="image 6" src="https://github.com/user-attachments/assets/cd649da1-be8f-479a-a326-706053f58ad1" />

That’s the endpoint which I was looking for and at that endpoint I found a login form.

<img width="1919" height="606" alt="image 7" src="https://github.com/user-attachments/assets/820603c6-6078-46e0-aed2-18d0ad183942" />

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

<img width="1907" height="391" alt="image 8" src="https://github.com/user-attachments/assets/87c6bfb2-ff3d-4597-8c01-19d471c46273" />

---

### User flag

Successfully logged into scr1ptkiddy’s account.

<img width="1919" height="621" alt="image 9" src="https://github.com/user-attachments/assets/f70fdf84-01d4-4c84-9ca4-6ce62fae9ca7" />

In “my notification” section, I found it was querying id parameter like these ID=5, probably an IDOR vulnerability.

<img width="1917" height="716" alt="image 10" src="https://github.com/user-attachments/assets/bb01dbe7-667f-47fe-a891-e77d0b9b7708" />

For confirmation I intercepted that request with burp and tried to change ID no. to 6 and I found a sensitive information there, tim’s ssh password.

<img width="1873" height="573" alt="image 11" src="https://github.com/user-attachments/assets/d0a312a9-fc18-4d7d-bc6e-450825c30e2f" />

Logged in to tim’s account via ssh and grabbed user flag.

```bash
┌──(ghost㉿kali)-[~/tryhackme/silver-platter]
└─$ ssh tim@10.201.106.249
```

<img width="1393" height="257" alt="image 12" src="https://github.com/user-attachments/assets/25b51bda-9a78-4524-bf39-c2d17c1490f2" />

---

### Root flag

3 other users were also present in the machine - `ssm-user`, `tyler`, `ubuntu`

<img width="1397" height="232" alt="image 13" src="https://github.com/user-attachments/assets/6f8552af-bff3-43c4-badf-e7187fc07104" />

While enumerating machine for privilege eescalation, user tim’s `adm` group permission helped us to enumerate /var/log directory.

<img width="1696" height="228" alt="image 14" src="https://github.com/user-attachments/assets/2f544927-31e1-408d-a232-f58ac45b3f29" />

There when I searched for entries related to user tyler, found a database password.

```bash
tim@ip-10-201-106-249:/var/log$ grep -iR tyler
```

<img width="1905" height="100" alt="image 15" src="https://github.com/user-attachments/assets/592a4723-3665-4ae1-9348-858abb28816a" />

When I tried to log into user tyler’s account with that passwords, it was successfull. Which means maybe password was reused.

<img width="1481" height="105" alt="image 16" src="https://github.com/user-attachments/assets/e39e9ed8-2f3c-4cef-b8e5-6c83bd34439c" />

As tyler have full sudo privileges on the machine, I turned it into a root’s shell wih `sudo su` .

<img width="1714" height="252" alt="image 17" src="https://github.com/user-attachments/assets/cbc73591-9b33-4075-91fa-0476b6468247" />

Grabbed the root flag.

<img width="1628" height="480" alt="image 18" src="https://github.com/user-attachments/assets/5a05a47a-bb91-4b90-b682-645acd9d388e" />

---

That’s it for this machine.✅
