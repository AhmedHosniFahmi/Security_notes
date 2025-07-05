### Content

- [CMD](#cmd)
- [Lazagne](#lazagne)
- [Files of Interest](#files-of-interest)

---
### CMD

Once we have access to a target, we can hunt stored credentials stored on it.
- Key Terms to Search: Passwords, Passphrases, Keys, Username, User account, Creds, Users, Passkeys, Passphrases, configuration, dbcredential, dbpassword, pwd, Login, Credentials. using findstr:
  
``` Powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

---
### Lazagne

 [Lazagne](https://github.com/AlessandroZ/LaZagne/releases/)
  
``` CMD
C:\> start lazagne.exe all
```

- Other places we should keep in mind when credential hunting:
	- Group Policy and scripts in the SYSVOL share.
	- Look at IT shares.
	- Passwords in the AD user or computer description fields.

---
### Files of Interest

Some local files of interest may include:

```TXT
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

We may also come across `.kdbx` KeePass database files, OneNote notebooks, files such as `passwords.*`, `pass.*`, `creds.*`, scripts, other configuration files, virtual hard drive files, and more that we can target to extract sensitive information from to elevate our privileges and further our access.