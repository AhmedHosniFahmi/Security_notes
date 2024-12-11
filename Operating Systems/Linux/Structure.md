### Content
- [Credentials Storage](#credentials-storage)
---
# Credentials Storage
- Linux-based distributions can use many different authentication mechanisms.
- [Pluggable Authentication Modules](https://web.archive.org/web/20220622215926/http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html) (`PAM`) is a commonly used standard mechanism.
	- Modules used for it are called `pam_unix.so` or `pam_unix2.so`, located in `/usr/lib/x86_x64-linux-gnu/security/` in Debian based dist.
	- PAM also has many other service modules, such as LDAP, mount, or Kerberos.
#### /etc/passwd
- Password Format: 
	- `<LoginName>:<PasswordInfo>:<UID>:<GUID>:<FullName,Comments>:<HomeDirectory>:<Shell>`
		- The `<PasswordInfo>` field can be:
			- Empty which means that the user don't need a password to login.
			- `x` which means that the user's password hash is stored on `/etc/shadow`
#### /etc/shadow
- Password Format: 
	- `<Username>:<EncryptedPassword>:<lastPWchange>:<MinPWage>:<MaxPWage>:<WarningPeriod>:<InactivityPeriod>:<ExpDate>:<Unused>`
		- `<EncryptedPassword>` can be:
			- Empty which means that the user don't need a password to login.
			- `!` or `*` which means the user cannot log in with a Unix password, Kerberos or key-based auth can be supported.
			- `$<type>$<salt>$<hashed>`, Encryption type can be:
				- `$1$` – MD5
				- `$2a$` – Blowfish
				- `$2y$` – Eksblowfish
				- `$5$` – SHA-256
				- `$6$` – SHA-512
#### /etc/security/opasswd
- `/etc/security/opasswd` stores old passwords so that PAM library can prevent using old passwords.
	- In case that the user had more than one old password, the passwords will be separated with `,`
---

