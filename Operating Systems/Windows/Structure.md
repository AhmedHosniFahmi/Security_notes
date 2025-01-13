### Content
- [Credentials Storage](#credentials-storage)
	- [LSASS](#lsass)
	- [SAM Database](#sam-database)
	- [NTDS.DIT](#ntds.dit)
	- [Credential Manager](#credential-manager)
- [Important Directories](#important-directories)
- [Environment Variables](#environment-variables)
---
# Credentials Storage

<img src="https://academy.hackthebox.com/storage/modules/147/Auth_process1.png" style="height:80%;width:90%;">

### LSASS
- Local Security Authority Subsystem Service is collection of modules and has access to all authentication processes that can be found in `C:\Windows\System32\Lsass.exe`.
- This service is responsible for the local system security policy, user authentication, and sending security audit logs to the Event log.
- Upon initial logon, LSASS will:
	- Cache creds locally on the memory.
	- Create [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens).
	- Enforce security policies and write to Windows [security log](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging-security).
- It consists of the following authentication packages:

| Authentication Packages | Description                                                                                                        |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Lsasrv.dll              | The LSA Server service both enforces security policies and acts as the security package manager for the LSA.       |
| Msv1_0.dll              | Authentication package for local machine logons that don't require custom authentication.                          |
| Samsrv.dll              | The Security Accounts Manager stores local security accounts, enforces locally stored policies, and supports APIs. |
| Kerberos.dll            | Security package loaded by the LSA for Kerberos-based authentication on a machine.                                 |
| Netlogon.dll            | Network-based logon service.                                                                                       |
| Ntdsa.dll               | This library is used to create new records and folders in the Windows registry.                                    |
### SAM Database
- The Security Accounts Manager database file in Windows operating systems stores users' passwords.
- It can be used to authenticate local and remote users.
- User passwords are stored in a hash format NTLM/LM in registry structure.
- Located in `C:\Windows\system32\config\SAM` and mounted on HKLM/SAM.
- If the system assigned to a workgroup, it handles the SAM database locally and stores all existing users locally in this database.
- If the system is domain joined, The DC must validate the credentials from AD database `ntds.dit` on `C:\Windows\ntds.dit`.
### NTDS.DIT
- New Technology Directory Service [directory information tree](https://docs.oracle.com/cd/E19901-01/817-7607/dit.html) located in `C:\Windows\NTDS\ntds.dit`
- DB file that stores the data in Active Directory, including but not limited to:
	- User accounts (username & password hash)
	- Group accounts
	- Computer accounts
	- Group policy objects
- Exists and synchronized across all the DCs.
### Credential Manager
- Built-in feature on Windows that allows users to save the credentials they use to access various network resources and websites.
- Located in `C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\`.
---
# Important Directories

| Name:               | Location:                            | Description:                                                                                                                                                                                                                                                                     |
| ------------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| %SYSTEMROOT%\Temp   | `C:\Windows\Temp`                    | Global directory containing temporary system files accessible to all users on the system. All users, regardless of authority, are provided full read, write, and execute permissions in this directory. Useful for dropping files as a low-privilege user on the system.         |
| %TEMP%              | `C:\Users\<user>\AppData\Local\Temp` | Local directory containing a user's temporary files accessible only to the user account that it is attached to. Provides full ownership to the user that owns this folder. Useful when the attacker gains control of a local/domain joined user account.                         |
| %PUBLIC%            | `C:\Users\Public`                    | Publicly accessible directory allowing any interactive logon account full access to read, write, modify, execute, etc., files and subfolders within the directory. Alternative to the global Windows Temp Directory as it's less likely to be monitored for suspicious activity. |
| %ProgramFiles%      | `C:\Program Files`                   | folder containing all 64-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system.                                                                                                                               |
| %ProgramFiles(x86)% | `C:\Program Files (x86)`             | Folder containing all 32-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system.                                                                                                                               |

---
# Environment Variables
Full list [here](https://ss64.com/nt/syntax-variables.html).

| Variable Name         | Description                                                                                                                                                                                                                                                                               |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `%PATH%`              | Specifies a set of directories(locations) where executable programs are located.                                                                                                                                                                                                          |
| `%OS%`                | The current operating system on the user's workstation.                                                                                                                                                                                                                                   |
| `%SYSTEMROOT%`        | Expands to `C:\Windows`. A system-defined read-only variable containing the Windows system folder. Anything Windows considers important to its core functionality is found here, including important data, core system binaries, and configuration files.                                 |
| `%LOGONSERVER%`       | Provides us with the login server for the currently active user followed by the machine's hostname. We can use this information to know if a machine is joined to a domain or workgroup.                                                                                                  |
| `%USERPROFILE%`       | Provides us with the location of the currently active user's home directory. Expands to `C:\Users\{username}`.                                                                                                                                                                            |
| `%ProgramFiles%`      | Equivalent of `C:\Program Files`. This location is where all the programs are installed on an `x64` based system.                                                                                                                                                                         |
| `%ProgramFiles(x86)%` | Equivalent of `C:\Program Files (x86)`. This location is where all 32-bit programs running under `WOW64` are installed. Note that this variable is only accessible on a 64-bit host. It can be used to indicate what kind of host we are interacting with. (`x86` vs. `x64` architecture) |