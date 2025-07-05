### Content

- [Overview](#overview)
- [Event Log Readers Abuse](#event-log-readers-abuse)
	- [wevtutil](#wevtutil)
	- [Get-WinEvent](#get-winevent)

---
#### Overview

Suppose [auditing of process creation](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation) events and corresponding command line values is enabled. In that case, this information is saved to the Windows security event log as event ID [4688: A new process has been created](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688). Organizations may enable logging of process command lines to help defenders monitor and identify possibly malicious behavior and identify binaries that should not be present on a system.

Administrators or members of the [Event Log Readers](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255\(v=ws.11\)?redirectedfrom=MSDN#event-log-readers) group have permission to access this log. It is conceivable that system administrators might want to add power users or developers into this group to perform certain tasks without having to grant them administrative access.

---
### Event Log Readers Abuse

Many Windows commands support passing a password as a parameter, and if auditing of process command lines is enabled, this sensitive information will be captured.

We can query Windows events from the command line using the [wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) utility and the [Get-WinEvent](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.1) PowerShell cmdlet.

##### wevtutil

```PowerShell
PS C:\> wevtutil qe Security /rd:true /f:text | Select-String "/user"

# Specify alternate credentials for wevtutil using the parameters /u and /p
PS C:\> wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```

##### Get-WinEvent

>Note: Searching the `Security` event log with `Get-WInEvent` requires administrator access or permissions adjusted on the registry key `HKLM\System\CurrentControlSet\Services\Eventlog\Security`. Membership in just the `Event Log Readers` group is not sufficient.

```PowerShell
# filter for process creation events (4688), which contain /user in the process command line.
PS C:\> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}

#The cmdlet can also be run as another user with the -Credential parameter.
```

> [!Tip]
> Other logs include PowerShell Operational log, which may also contain sensitive information or credentials if script block or module logging is enabled. This log is accessible to unprivileged users.


---
