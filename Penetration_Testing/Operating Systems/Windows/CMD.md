### Content
- [Gathering System Information](#gathering-system-information)
- [Environment Variables](#environment-variables)
- [Finding Files, Directories and Information](#finding-files-directories-and-information)
- [Managing Services](#managing-services)

> [!Note]
> [Microsoft Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands) has a complete listing of the commands.
> [ss64](https://ss64.com/nt/) Is a handy quick reference for anything command-line related, including CMD, PowerShell, Bash.

---
# Gathering System Information

| Command          | Description                                                                                                                                |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `systeminfo`     | System information                                                                                                                         |
| `hostname`       | Machine name                                                                                                                               |
| `whoami /priv`   | Check user's privilege                                                                                                                     |
| `whoami /groups` | Check user's groups                                                                                                                        |
| `net user`       | All users on the host                                                                                                                      |
| `net localgroup` | All groups that exist on the machine                                                                                                       |
| `net group`      | All groups on the domain                                                                                                                   |
| `net share`      | Shared resources on the host                                                                                                               |
| `net view `      | any shared resources the host you are issuing the command against knows of.<br>This includes domain resources, shares, printers, and more. |
| `ver`            | Windows version                                                                                                                            |
| `ipconfig /all`  | Every network adapter attached                                                                                                             |
| `arp /a`         | Find additional hosts                                                                                                                      |

---
# Environment Variables

- View with: `echo %PATH%` or `set %PATH%`
- Create with: 
	- For the current session `set varName=Value`
	- For permanent var `setx <varName> <value> <parameters>`

---
# Finding Files, Directories and Information

``` powershell
# Search for a file recursively, we can use wildcards *.txt
C:\> where /R C:\Users\student\ bio.txt
# find how many files the folder and its subdirectories contain.  
C:\> dir n: /a-d /s /b | find /c ":\"  
# search for specific names in files such as cred, passwords, users, secrets.  
C:\> dir n:\*cred* /s /b  
# search for a specific word within a text file  
C:\> findstr /s /i cred n:\*.*
```
---
# Managing Services
``` Powershell
# Query All Active Services
C:\> sc query type= service #wmic service list brief #tasklist /svc #net start
# Stop a sercive (Windows defender), to start it, sc start <service>
C:\> sc stop windefend
# Disable a servic
sc config bits start= disabled
```