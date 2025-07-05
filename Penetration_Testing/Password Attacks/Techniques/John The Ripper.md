### Content
- [Cracking modes](#cracking-modes)
- [Cracking files](#cracking-files)
	- [Crack BitLocker Encrypted VHD](#crack-bitlocker-encrypted-vhd)

> [!Note]
> 
> - `john --format=[] --wordlist=[] /hash/file`
> - List the formats available: `john --list=formats`
>   
> ##### Identifying hash formats:
> - Consult [JtR's sample hash documentation](https://openwall.info/wiki/john/sample-hashes)
> - See [this list by PentestMonkey](https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)
> - Use a tool like [hashID](https://github.com/psypanda/hashID)
>   
> 	`hashid -j '$6$ues25dIanlctrWxg$......'`

---
## Cracking modes

`Single crack mode` is a rule-based cracking technique that is most useful when targeting Linux credentials. It generates password candidates based on the victim's username, home directory name, and [GECOS](https://en.wikipedia.org/wiki/Gecos_field) values (full name, room number, phone number, etc.).

```bash
# Cracking janedoe:x:1000:1000:Jane Doe,Room 1015,(234)555-1410,(234)555-1411:/home/janedoe:/usr/bin/zsh
$ john --single passwd
```

`Wordlist mode` is used to crack passwords with a dictionary attack.

```bash
$ john --wordlist=<wordlist_file> <hash_file>
```

`Incremental mode` is a powerful, brute-force-style password cracking mode that generates candidate passwords based on a statistical model ([Markov chains](https://en.wikipedia.org/wiki/Markov_chain)).

```bash 
$ john --incremental <hash_file>

# JtR uses predefined incremental modes specified in its configuration file (`john.conf`)
# which define character sets and password lengths.
# You can customize these or define your own to target passwords that use special characters or specific patterns.
$ grep '# Incremental modes' -A 100 /etc/john/john.conf
```

---
## Cracking files

Multiple `"2john"` tools come with JtR that can be used to process files and produce hashes compatible with JtR.

```bash
$ <tool> <file_to_crack> > file.hash

# List the available tools
$ locate *2john* 

# Cracking SSH keys
# Attempting to read a password-protected SSH key with ssh-keygen will prompt the user for a passphrase.
$ ssh-keygen -yf ~/.ssh/id_rsa

Enter passphrase for "/home/xyz/.ssh/id_rsa":

$ ssh2john.py SSH.private > ssh.hash
$ john --wordlist=rockyou.txt ssh.hash
$ john ssh.hash --show

# Cracking Microsoft Office Documents:
$ office2john.py Protected.docx > protected-docx.hash
$ john --wordlist=rockyou.txt protected-docx.hash
$ john protected-docx.hash --show

# Cracking PDFs
$ pdf2john.py PDF.pdf > pdf.hash
$ john --wordlist=rockyou.txt pdf.hash
$ john pdf.hash --show
```

**Crack archives**
An extensive list of archive types can be found on [FileInfo.com](https://fileinfo.com/filetypes/compressed)

```bash
# Download All File Extensions
$ curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt

# Cracking ZIP
$ zip2john ZIP.zip > zip.hash
$ john --wordlist=rockyou.txt zip.hash
$ john zip.hash --show
```

> Other tools are often used to protect archives with a password. For example, with `tar`, `openssl` or `gpg` is used to encrypt the archives.

```bash
# Using the tool file, we can obtain information about the specified file's format.
$ file GZIP.gzip 

GZIP.gzip: openssl enc'd data with salted password'

# It's difficult to crack openssl files with john, because it will give us many false positive
# Use openssl instead 
$ for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
# look in the current folder again to check if the cracking of the archive was successful.
$ ls

customers.csv  GZIP.gzip  rockyou.txt
```

#### Crack BitLocker Encrypted VHD
```bash
$ bitlocker2john -i Backup.vhd > backup.hashes
$ grep "bitlocker\$0" backup.hashes > backup.hash
$ hashcat -m 22100 backup.hash usr/share/wordlists/rockyou.txt -o backup.cracked
$ cat backup.cracked
# After cracking the password, transfer the encrypted virtual drive to a windows machine and mount it
# Double click it and the windows will prompt us for a password.
```

---
