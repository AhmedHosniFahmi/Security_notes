```powershell
# On windows 10/11
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"

# On windows server
Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature
Import-Module ActiveDirectory
```