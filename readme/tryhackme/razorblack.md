---
description: >-
  These guys call themselves hackers. Can you show them who's the boss ?? - by
  Xyan1d3
icon: chart-network
layout:
  width: default
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# Razorblack

***

Platform: [TryHackMe](https://tryhackme.com/room/raz0rblack)

Difficulty: Medium

Machine : Windows AD

***

* Found NFS port open → Mounted and found sbradley flag + an excel sheet of usernames.
* Crafted a user list & tested them for ‘DNRPA’ → Found ‘twilliams’ don’t require pre-auth & got its Kerberos hash
* Cracked that hash and got plaintext password.

\[twilliams]✅

* Sprayed that password via nxc and found a user ‘sbradley’ whose status shows : Password must change.
* Change sbradley’s password via smbpasswd.py

\[sbradley]✅

* With sbradley’s pass enumerated smb shares and got a suspicious share ‘trash’.
* In that share found a chat-log file and a zip file.
* Cracked that zip file, uncompressed it and got system.hive & ntds.dit file.
* Extracted ntds with secretsdump.py
* Tested all those hashed with username ‘lvetrova’ and found hash of her account.

\[lvetrova]✅

* With ldapdomaindump, I found out lvetrova has winrm access and xyan1d3 also have these access.
* With twilliams credentials, perfomed kerberoasting and got kerberos hash of xyan1d3.
* Cracked that hash with john and found password for xyan1d3.

\[Xyan1d3]✅

* Logged in to both lvetrova and xyan1d3’s account and got their flags.
* User xyan1d3 has SEBACKUPPRIVILEGE enabled, it means it can read any files.
* Get NTDS.dit file SYSTEM.hive file from that machine.
* With secretsdump extracted them.
* Got administrator’s hash.

\[Administrator]✅

* Logged in to administrator’s account via evil-winRM and get root flag + cookies.
