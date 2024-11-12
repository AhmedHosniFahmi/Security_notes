## Basic usage
``` bash
medusa [target_options] [credential_options] -M module [module_options]
```
* `-h <host>` / `-H targets.txt`
* `-u <username>` / `-U usernames.txt`
* `-p PASSWORD` / `-P FILE`
* `-M MODULE` Define the specific module to use for the attack (e.g., `ssh`, `ftp`, `http`).
* `-t TASKS` Define the number of parallel login attempts to run.
* `-f` / `-F` Stop after the first successful login, either on the current host (`-f`) or any host (`-F`).
* `-n PORT`
Testing for Empty or Default Passwords:
``` bash
medusa -h 10.0.0.5 -U usernames.txt -e ns -M service_name
# Checks for empty passwords (`-e n`).
# Checks forpasswords matching the username (`-e s`).
```
---
## Medusa Services

| Medusa Module    | Usage Example                                                                                                               |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------- |
| FTP              | `medusa -M ftp -h 192.168.1.100 -u admin -P passwords.txt`                                                                  |
| HTTP             | `medusa -M http -h www.example.com -U users.txt -P passwords.txt -m DIR:/login.php -m FORM:username=^USER^&password=^PASS^` |
| IMAP             | `medusa -M imap -h mail.example.com -U users.txt -P passwords.txt`                                                          |
| MySQL            | `medusa -M mysql -h 192.168.1.100 -u root -P passwords.txt`                                                                 |
| POP3             | `medusa -M pop3 -h mail.example.com -U users.txt -P passwords.txt`                                                          |
| RDP              | `medusa -M rdp -h 192.168.1.100 -u admin -P passwords.txt`                                                                  |
| SSHv2            | `medusa -M ssh -h 192.168.1.100 -u root -P passwords.txt`                                                                   |
| Subversion (SVN) | `medusa -M svn -h 192.168.1.100 -u admin -P passwords.txt`                                                                  |
| Telnet           | `medusa -M telnet -h 192.168.1.100 -u admin -P passwords.txt`                                                               |
| VNC              | `medusa -M vnc -h 192.168.1.100 -P passwords.txt`                                                                           |
| Web Form         | `medusa -M web-form -h www.example.com -U users.txt -P passwords.txt -m FORM:"username=^USER^&password=^PASS^:F=Invalid"`   |

---
#### SSH
``` bash
medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh 
```
#### HTTP
Targeting Multiple Web Servers with Basic HTTP Authentication
``` bash
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET 
```
---
