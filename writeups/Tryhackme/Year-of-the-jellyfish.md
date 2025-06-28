## Year of the jellyfish

Started with nmap scan:

# TryHackMe - Year of the Jellyfish
**Platform:** TryHackMe  
**Difficulty:** Hard
**Category:** Linux / Web / Enumeration  
**Date:** 2025-06-27  
**Status:** ✅ Rooted

---

## 1. Reconnaissance

###  Nmap Scan

```bash
nmap -Pn -O -sC -A -p- --min-rate=3000 -oN nmap.full 18.201.190.247
Open ports:
21/tcp   open  tcpwrapped
22/tcp   open  tcpwrapped
80/tcp   open  tcpwrapped
|_http-title: Did not follow redirect to https://robyns-petshop.thm/
|_http-server-header: Apache/2.4.29 (Ubuntu)
443/tcp  open  tcpwrapped
|_http-title: 400 Bad Request
|_http-server-header: Apache/2.4.29 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=robyns-petshop.thm/organizationName=Robyns Petshop/stateOrProvinceName=South West/countryName=GB
| Subject Alternative Name: DNS:robyns-petshop.thm, DNS:monitorr.robyns-petshop.thm, DNS:beta.robyns-petshop.thm, DNS:dev.robyns-petshop.thm
8096/tcp open  tcpwrapped
```
- Port 21: tried to connect via anonymous login, but failed. Not vulnerable
- Port 22: Open ssh
- Port 80: redirected to https://robyns-petshop.thm/
- Port 443: Found subdomains ( robyns-petshop.thm monitorr.robyns-petshop.thm beta.robyns-petshop.thm dev.robyns-petshop.thm )
- Port 8096: Useless for now atleast , found nothing.

### Enumerating subdomains:
#### robyns-petshop.thm
![image](https://github.com/user-attachments/assets/099e77ee-3116-4c1a-b39d-8ea856503c3c)
Nothing interesting, looks like running on pico cms, i didn't enumerate it.

#### monitorr.robyns-petshop.thm
![image](https://github.com/user-attachments/assets/a488f4ff-6d44-47c1-9298-6365ab7d3033)
It seems interesting, because looks like it is a type of software to monitor website status or whatever and version no. is also given below that page: Monitorr 1.7.6m

#### beta.robyns-petshop.thm
![image](https://github.com/user-attachments/assets/f277f6fd-a673-456f-b6f0-8b93f9943b43)
Nothing interesting here too, left it for later.

#### dev.robyns-petshop.thm
![image](https://github.com/user-attachments/assets/da411f49-66f2-42f1-8f97-a002ecb9685f)
Same as robyns-petshop.thm , but looks like its for developer, ran dirbuster on this url and left it for later.

## 2. Initial access
Started finding exploit for monitorr 1.7.6m on google and found interesting results: Remote code execution vulnerability.
![image](https://github.com/user-attachments/assets/6ac25d84-c4d9-48ec-a5bf-858d6d368c7a)
Downloaded that exploit and ran it on out attacker machine.
![image](https://github.com/user-attachments/assets/c8f96aac-1c14-4777-ad9d-b6a3480baacd)
We have to some editing on that exploit code to make it run , like make that request to run without TLS verification check, and that target server was detecting if it's automated or it's human who is requesting web page , based on cookie, so that we have to just play a little bit with that exploit code and make it run:

![Screenshot 2025-06-28 092256](https://github.com/user-attachments/assets/c765138c-6332-43cc-8fac-4e42b134cc10)
![Screenshot 2025-06-28 092202](https://github.com/user-attachments/assets/441f28a6-21e7-456a-8172-06f3e848fcdc)

Added "cookie: isHuman=1" header in our web request to make it run than, have to play with file extension too, and after hit and trial found "png.phtml" extension is working and now we have successfully uploaded our shell, triggered it in browser and got our reverse shell.

![Screenshot 2025-06-28 092216](https://github.com/user-attachments/assets/c2504f54-5b20-4faa-90a4-0f825b0bbd1f)
![image](https://github.com/user-attachments/assets/7ef0b374-f876-4e1c-a2e6-88befa10549f)
![image](https://github.com/user-attachments/assets/d49e6dce-fbbb-409d-b111-62f0611018f6)
![image](https://github.com/user-attachments/assets/3fa4f254-8a83-4d70-a564-ee434876306b)

## 3. Privilege escalation
Started with some basic privesc commands, found nothing of interest except for when searched for suid binaries:
```bash
www-data@petshop:/var/www$ find / -perm -4000 -type f 2>/dev/null
```
Found 2 interesting binaries:
1. /usr/lib/snapd/snap-confine
2. /usr/bin/pkexec

Started with /usr/lib/snapd/snap-confine:
Searched on google for any exploit related to privesc via snapd and found a exploit named "dirty_sock" :
You can check that out on : https://github.com/initstring/dirty_sock
So, basically that exploit was for version no. 2.37.1 and below and our target's snapd version was 2.32.5 means it is vulnerable to that exploit.

![image](https://github.com/user-attachments/assets/3731fb7d-5a86-4b0f-b88f-2ffde113d55a)

Downloaded v2 of that exploit on our attacker machine and transfered it to target machine via python server.
And ran that exploit:

![image](https://github.com/user-attachments/assets/eee51024-02a4-4b3f-979d-b3426d2bf194)

I didn't know why it gave me some error, but it worked and made a new user named "dirty_sock". Now we can swith to that user and that user had full sudo access, so we can switch to root user and get our root flag.

![image](https://github.com/user-attachments/assets/246e2771-1c22-4947-9319-ed782e496e2b)
![image](https://github.com/user-attachments/assets/9e671982-6339-427c-9602-a11ddb88a2a0)

## 4. Key takeaways
1. In hard level machines, we have to play a little bit with publicly available exploit code. Not a piece of cake(download & run).
2. Intercepting requests via burp was the most important part of this machine, because that's how I figured out target's behaviour.
3. While listening via netcat, make sure to use the same port which was found open while nmap scanning. (Firewall) 


⚠️ Note
This writeup is for educational purposes. Flags are redacted as per THM's guidelines.




