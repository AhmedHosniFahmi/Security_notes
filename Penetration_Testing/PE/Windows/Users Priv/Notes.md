### Content

- [Enabling disabled privileges](#enabling-disabled-privileges)
- [Techniques, Detection and Recommendations](#techniques-detection-and-recommendations)

> [!Important]
> - `whoami /priv` will give you a listing of all user rights assigned to your current user. Some rights are only available to administrative users and can only be listed/leveraged when running an elevated CMD or PowerShell session.
> 	- When a privilege is listed for our account in the `Disabled` state, it means that the account has the specific privilege assigned. Still, it cannot be used in an access token to perform the associated actions until it is enabled.
> - More details about privileges and rights [here](../../../../Operating%20Systems/Windows/Privileges%20and%20Rights#User%20Rights%20Assignment)

---
### Enabling disabled privileges

Using this [script](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) we can enable a privilege at a time.

``` PowerShell
# Enable SeDebugPrivilege on the current process
PS C:\> .\Adjust-Privilege.ps1 -Privilege SeDebugPrivilege

# Disable SeImpersonatePrivilege on process with PID 1234
PS C:\> .\Adjust-Privilege.ps1 -Privilege SeImpersonatePrivilege -ProcessId 1234 -Disable
```

Using this [script](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) we can enable every obtained and disabled privileged.

```powershell
PS C:\htb> Import-Module .\Enable-Privilege.ps1
PS C:\htb> .\EnableAllTokenPrivs.ps1
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                              State
============================= ======================================== =======
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Enabled
```

---
## Techniques, Detection and Recommendations

https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672

https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e