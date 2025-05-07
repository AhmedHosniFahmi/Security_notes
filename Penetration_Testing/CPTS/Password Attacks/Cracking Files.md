### Content
- [Hunting For Files](#hunting-for-files)
- [Crack Files with John](#crack-files-with-john)
---
## Hunting For Files

Find specific files with specific extensions:
``` bash
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

Find SSH keys:
``` bash
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```

Find Encrypted SSH keys:
``` bash
$ cat /home/user/.ssh/SSH.private

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2109D25CC91F8DBFCEB0F7589066B2CC
...SNIP...
```
---
## Crack Files with John

`John The Ripper` has many different scripts to generate hashes from files that we can then use for cracking.
``` bash
$ locate *2john*

/usr/bin/bitlocker2john
/usr/bin/dmg2john
/usr/bin/gpg2john
/usr/bin/hccap2john
/usr/bin/keepass2john
/usr/bin/putty2john
/usr/bin/racf2john
/usr/bin/rar2john
...SNIP...
```

Cracking SSH keys:
``` bash
$ ssh2john.py SSH.private > ssh.hash
$ john --wordlist=rockyou.txt ssh.hash
$ john ssh.hash --show
```

Cracking Microsoft Office Documents:
``` bash
$ office2john.py Protected.docx > protected-docx.hash
$ john --wordlist=rockyou.txt protected-docx.hash
$ john protected-docx.hash --show
```

Cracking PDFs
``` bash
$ pdf2john.py PDF.pdf > pdf.hash
$ john --wordlist=rockyou.txt pdf.hash
$ john pdf.hash --show
```

##### Crack archives
An extensive list of archive types can be found on [FileInfo.com](https://fileinfo.com/filetypes/compressed)
``` bash
# Download All File Extensions
$ curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt
```

Cracking ZIP
``` bash
$ zip2john ZIP.zip > zip.hash
$ john --wordlist=rockyou.txt zip.hash
$ john zip.hash --show
```

> Other tools are often used to protect the corresponding archives with a password. For example, with `tar`, the tool `openssl` or `gpg` is used to encrypt the archives.

``` bash
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


Cracking BitLocker Encrypted Drives
``` bash
$ bitlocker2john -i Backup.vhd > backup.hashes
$ grep "bitlocker\$0" backup.hashes > backup.hash
$ hashcat -m 22100 backup.hash usr/share/wordlists/rockyou.txt -o backup.cracked
$ cat backup.cracked
# After cracking the password, transfer the encrypted virtual drive to a windows machine and mount it, double click it and the windows will prompt us for a password.
```