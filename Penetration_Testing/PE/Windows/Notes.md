### Content

- [Enabling Disabled Privileges](#enabling-disabled-privileges)
- [Built-In Groups](#built-in-groups)
- [Bypassing UAC Using UACME](#bypassing-uac-using-uacme)
- 

> [!Note]
> 
> When using `whoami /priv` and seeing a privilege in the `Disabled` state, it means that the account has the specific privilege assigned. Still, it cannot be used in an access token to perform the associated actions until it is enabled.
> 
> - [4672(S) Event: Special privileges assigned to new logon.](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
> - [Windows Privilege Abuse: Auditing, Detection, and Defense](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e)
> - [Here](https://ss64.com/nt/syntax-security_groups.html) is a listing of all built-in Windows groups along with a detailed description of each.
> - [Here](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory) is listing of privileged accounts and groups in Active Directory.

---
## Enabling Disabled Privileges

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
## Built-In Groups

Always check these groups and include a list of each group's members as an appendix in our report for the client to review and determine if access is still necessary.

| [Backup Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-backupoperators)            | [Event Log Readers](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-eventlogreaders) | [DnsAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-dnsadmins)              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Hyper-V Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-hypervadministrators) | [Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-printoperators)    | [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) |

More groups and their description

| **Group**                   | **Description**                                                                                                                                                                                                                                                                                                                                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Default Administrators      | Domain Admins and Enterprise Admins are "super" groups.                                                                                                                                                                                                                                                                                                                                                       |
| Server Operators            | Members can modify services, access SMB shares, and backup files.                                                                                                                                                                                                                                                                                                                                             |
| Backup Operators            | Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs.                                                                                                             |
| Print Operators             | Members can log on to DCs locally and "trick" Windows into loading a malicious driver.                                                                                                                                                                                                                                                                                                                        |
| Hyper-V Administrators      | If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins.                                                                                                                                                                                                                                                                           |
| Account Operators           | Members can modify non-protected accounts and groups in the domain.                                                                                                                                                                                                                                                                                                                                           |
| Remote Desktop Users        | Members are not given any useful permissions by default but are often granted additional rights such as `Allow Login Through Remote Desktop Services` and can move laterally using the RDP protocol.                                                                                                                                                                                                          |
| Remote Management Users     | Members can log on to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs).                                                                                                                                                                                                                                                                                    |
| Group Policy Creator Owners | Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU.                                                                                                                                                                                                                                                                         |
| Schema Admins               | Members can modify the Active Directory schema structure and backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL.                                                                                                                                                                                                                                                  |
| DNS Admins                  | Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to [create a WPAD record](https://web.archive.org/web/20231115070425/https://cube0x0.github.io/Pocing-Beyond-DA/). |

---
## Bypassing UAC Using UACME

The [UACMe](https://github.com/hfiref0x/UACME) repo features a comprehensive list of UAC bypasses, which can be used from the command line.

See this [Video](https://www.youtube.com/watch?v=RXX0FHM9SEk) illustrating how to use it.

---
## Access Rights for a Service

> [Resource](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)

- We can see which user is starting a specific service `sc qc <serviceName>`
- We can check the privileges of the groups over a service using the service viewer/controller [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice), which is part of the Sysinternals suite. `.\PsService.exe security <serviceName>`

| Access right                              | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **SERVICE_ALL_ACCESS** (0xF01FF)          | Includes **STANDARD_RIGHTS_REQUIRED** in addition to all access rights in this table.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| **SERVICE_CHANGE_CONFIG** (0x0002)        | Required to call the [**ChangeServiceConfig**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-changeserviceconfiga) or [**ChangeServiceConfig2**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-changeserviceconfig2a) function to change the service configuration. Because this grants the caller the right to change the executable file that the system runs, it should be granted only to administrators.                                                                                                               |
| **SERVICE_ENUMERATE_DEPENDENTS** (0x0008) | Required to call the [**EnumDependentServices**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-enumdependentservicesa) function to enumerate all the services dependent on the service.                                                                                                                                                                                                                                                                                                                                                              |
| **SERVICE_INTERROGATE** (0x0080)          | Required to call the [**ControlService**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-controlservice) function to ask the service to report its status immediately.                                                                                                                                                                                                                                                                                                                                                                                |
| **SERVICE_PAUSE_CONTINUE** (0x0040)       | Required to call the [**ControlService**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-controlservice) function to pause or continue the service.                                                                                                                                                                                                                                                                                                                                                                                                   |
| **SERVICE_QUERY_CONFIG** (0x0001)         | Required to call the [**QueryServiceConfig**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-queryserviceconfiga) and [**QueryServiceConfig2**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-queryserviceconfig2a) functions to query the service configuration.                                                                                                                                                                                                                                                            |
| **SERVICE_QUERY_STATUS** (0x0004)         | Required to call the [**QueryServiceStatus**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-queryservicestatus) or [**QueryServiceStatusEx**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-queryservicestatusex) function to ask the service control manager about the status of the service.  <br>Required to call the [**NotifyServiceStatusChange**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-notifyservicestatuschangea) function to receive notification when a service changes status. |
| **SERVICE_START** (0x0010)                | Required to call the [**StartService**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-startservicea) function to start the service.                                                                                                                                                                                                                                                                                                                                                                                                                  |
| **SERVICE_STOP** (0x0020)                 | Required to call the [**ControlService**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-controlservice) function to stop the service.                                                                                                                                                                                                                                                                                                                                                                                                                |
| **SERVICE_USER_DEFINED_CONTROL**(0x0100)  | Required to call the [**ControlService**](https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-controlservice) function to specify a user-defined control code.                                                                                                                                                                                                                                                                                                                                                                                             |
