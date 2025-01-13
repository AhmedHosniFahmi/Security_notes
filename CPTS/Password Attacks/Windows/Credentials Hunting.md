Once we have access to a target, we can hunt stored credentials stored on it.
- Key Terms to Search: Passwords, Passphrases, Keys, Username, User account, Creds, Users, Passkeys, Passphrases, configuration, dbcredential, dbpassword, pwd, Login, Credentials. using findstr:
	``` Powershell
	findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
	```
- We can transfer [Lazagne](https://github.com/AlessandroZ/LaZagne/releases/) to the target host, using the [Transfer Files Technique](#transfer-files-technique) discussed above then run it with the next command
	``` CMD
	C:\> start lazagne.exe all
	```
- Other places we should keep in mind when credential hunting:
	- Group Policy and scripts in the SYSVOL share.
	- Look at IT shares.
	- Passwords in the AD user or computer description fields.
---
