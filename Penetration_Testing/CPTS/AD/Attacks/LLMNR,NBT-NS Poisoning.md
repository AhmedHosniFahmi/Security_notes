### Content
1. [LLMNR/NBT-NS Poisoning - from Linux](#llmnr/nbt-ns-poisoning---from-linux)
2. [LLMNR/NBT-NS Poisoning - from Windows](#llmnr/nbt-ns-poisoning---from-windows)
3. [Remediation](#remediation)
---

> [!Note]
> [Link-Local Multicast Name Resolution](https://datatracker.ietf.org/doc/html/rfc4795) (LLMNR) and [NetBIOS Name Service](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc940063(v=technet.10)?redirectedfrom=MSDN) (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails.
> - If a machine attempts to resolve a host but DNS resolution fails, typically, the machine will try to ask all other machines on the local network for the correct host address via LLMNR.
> - LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. It uses port `5355` over UDP natively.
> - If LLMNR fails, the NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. NBT-NS utilizes port `137` over UDP.

- LLMNR/NBT-NS are used for name resolution, **ANY** host on the network can reply.
- This is where we come in with `Responder` to poison these requests. With network access, we can spoof an authoritative name resolution source by responding to LLMNR and NBT-NS traffic as if we have an answer for the requesting host.
- This poisoning effort is done to get the victims to communicate with our system by pretending that our rogue system knows the location of the requested host.
- If the requested host requires name resolution or authentication actions, we can capture the NetNTLM hash and subject it to an offline brute force attack in an attempt to retrieve the cleartext password.

##### Scenario
1. A host attempts to connect to the print server at \\print01.inlanefreight.local, but accidentally types in \\printer01.inlanefreight.local.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of \\printer01.inlanefreight.local.
4. The attacker (us with `Responder` running) responds to the host stating that it is the \\printer01.inlanefreight.local that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

Several tools can be used to attempt LLMNR & NBT-NS poisoning:

|**Tool**|**Description**|
|---|---|
|[Responder](https://github.com/lgandx/Responder)|Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.|
|[Inveigh](https://github.com/Kevin-Robertson/Inveigh)|Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks.|
|[Metasploit](https://www.metasploit.com/)|Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks.|

---
#### LLMNR/NBT-NS Poisoning - from Linux
Responder
``` bash
$ sudo responder -I ens224 
# Cracking an NTLMv2 Hash With Hashcat
$ hashcat -m 5600 ntlmv2_list.txt /usr/share/wordlists/rockyou.txt
```
---
#### LLMNR/NBT-NS Poisoning - from Windows
Inveigh `administrator priv required`
``` Powershell
### Powershell version
PS C:\> Import-Module .\Inveigh.ps1
# List all available parameters
PS C:\> (Get-Command Invoke-Inveigh).Parameters 
# LLMNR and NBNS spoofing, and output to the console and write to a file
PS C:\> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

### exe c# version
PS C:\> .\Inveigh.exe
# when clicking esc, a command line utility will become available for us
# list all available commands
C(0:0) NTLMv1(0:0) NTLMv2(5:25)> help
# list all unique ntlmV2 hashes captured
C(0:0) NTLMv1(0:0) NTLMv2(5:33)> GET NTLMV2UNIQUE
```

---
#### Remediation

Mitre ATT&CK lists this technique as [ID: T1557.001](https://attack.mitre.org/techniques/T1557/001), `Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay`.

1. **Disabling LLMNR**
   `Group plicy management -> (right click on the default domain policy and click on edit, the group policy management editor will open ) -> Computer Configuration  -> Policies -> Administrative Templates -> Network -> DNS Client -> (enable) "Turn OFF Multicast Name Resolution."`
<img src="https://academy.hackthebox.com/storage/modules/143/llmnr_disable.png" style="height:65%; width:75%;">

2. **Disabling NBT-NS**
   NBT-NS cannot be disabled via Group Policy and must be disabled locally on each host.
   We can do this by opening `Network and Sharing Center -> Control Panel -> Change adapter settings -> right click on the adapter and view its properties -> Internet Protocol Version 4 (TCP/IPv4) -> properties -> advanced -> WINS -> (check) Disable NetBIOS over TCP/IP`.
<img src="https://academy.hackthebox.com/storage/modules/143/disable_nbtns.png" style="height:65%; width:75%;">


While it is not possible to disable NBT-NS directly via GPO, we can create a PowerShell script under and save it a `.ps1` file and go to: 
`Group plicy management -> Add new GPO (Disbale NetBIOS policy) by righ click on any OU -> (right click on the created policy and click on edit, the group policy management editor will open ) -> Computer Configuration  -> Policies -> Windows Settings -> Script (Startup/Shutdown) -> Startup -> PowerShell Scripts -> select "For this GPO, run scripts in the following order" (Run Windows PowerShell scripts first) -> Add (choose the script)`
``` Powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
```
For these changes to occur, we would have to either reboot the target system or restart the network adapter.
<img src="https://academy.hackthebox.com/storage/modules/143/nbtns_gpo.png" style="height:65%; width:75%;">

To push this out to all hosts in a domain, we could create a GPO using `Group Policy Management` on the Domain Controller and host the script on the SYSVOL share in the scripts folder and then call it via its UNC path such as:

`\\inlanefreight.local\SYSVOL\INLANEFREIGHT.LOCAL\scripts`
Once the GPO is applied to specific OUs and those hosts are restarted, the script will run at the next reboot and disable NBT-NS, provided that the script still exists on the SYSVOL share and is accessible by the host over the network.

<img src="https://academy.hackthebox.com/storage/modules/143/nbtns_gpo_dc.png" style="height:85%; width:85%;">

---

It is not always possible to disable LLMNR and NetBIOS, and therefore we need ways to detect this type of attack behavior. One way is to use the attack against the attackers by injecting LLMNR and NBT-NS requests for non-existent hosts across different subnets and alerting if any of the responses receive answers which would be indicative of an attacker spoofing name resolution responses. This [blog post](https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/) explains this method more in-depth.

Furthermore, hosts can be monitored for traffic on ports UDP 5355 and 137, and event IDs [4697](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697) and [7045](https://www.manageengine.com/products/active-directory-audit/kb/system-events/event-id-7045.html) can be monitored for. Finally, we can monitor the registry key `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` for changes to the `EnableMulticast` DWORD value. A value of `0` would mean that LLMNR is disabled.
