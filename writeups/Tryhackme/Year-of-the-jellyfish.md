## Year of the jellyfish

Started with nmap scan:

# TryHackMe - Year of the Jellyfish
**Platform:** TryHackMe  
**Difficulty:** Hard
**Category:** Linux / Web / Enumeration  
**Date:** 2025-06-27  
**Status:** ✅ Rooted

---

## 🧭 1. Reconnaissance

### 🔍 Nmap Scan

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


