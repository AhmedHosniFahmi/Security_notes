### Content
- [Cracking Linux Credentials](#cracking-linux-credentials)
- [Credential Hunting](#credential-hunting)
---
## Cracking Linux Credentials
If the attacker had admin privileges over the system to access `shadow` and `passwd` files.
1. Unshadow
	``` bash
	$ sudo cp /etc/passwd /tmp/passwd.bak
	$ sudo cp /etc/shadow /tmp/shadow.bak
	$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
	```
2. Hashcat - Cracking Unshadowed Hashes
	``` bash
	hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
	```

> [!Note]
> In case of using MD5 hashing algorithm, Collect the hashes into a file, one hash value per line, then use the next command to crack them.
> `hashcat -m 500 -a 0 md5-hashes.list rockyou.txt`

---
## Credential Hunting
There are man resources than can contain credentials:
- Files:
	``` bash
	# Configs
	for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
	# Search for specific words inside the config file (ex: user, password, pass)
	for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
	
	# Databases
	for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
	
	# Notes
	find /home/* -type f -name "*.txt" -o ! -name "*.*"
	
	# Scripts
	for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
	
	# Cronjobs
	find /etc -type d -name '*cron*' -exec sh -c 'echo "Parent Directory: $1"; ls -lah "$1"' sh {} \;
	ls -la /etc/cron.*/
	
	# SSH Keys
	# Files that contain a private SSH key
	grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
	# Files that contain a public SSH key
	grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
	```
- Logs
	``` bash
	# Some strings we can use to find interesting content in the logs
	for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep \
	"accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" \
	$i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep \
	"accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
	```
- `.bash_history` on the user home directory.
- Memory and Cache
	- [mimipenguin](https://github.com/huntergregal/mimipenguin) can be used to dump credentials from the running processes and memory.
		``` bash
		$ sudo python3 mimipenguin.py # or sudo bash mimipenguin.sh
		```
	- [LaZagne](https://github.com/AlessandroZ/LaZagne/tree/master) can be used to dump credentials from various services.
		``` bash
		$ python3 laZagne.py all
		```
- Browsers
	- `Mozilla Firefox` browser stores the credentials encrypted in a hidden folder.
		``` bash
		$ ls -l .mozilla/firefox/ | grep default 
		
		drwx------ 11 user user 4096 Jan 28 16:02 1bplpd86.default-release
		drwx------  2 user user 4096 Jan 28 13:30 lfx3lvhb.default
		
		cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
		```
		- The tool [Firefox Decrypt](https://github.com/unode/firefox_decrypt) is excellent for decrypting these credentials
			``` bash
			python3.9 firefox_decrypt.py
			```
		- We can also use [LaZagne](https://github.com/AlessandroZ/LaZagne/tree/master) with `browsers` flag
			``` bash
			python3 laZagne.py browsers
			```
