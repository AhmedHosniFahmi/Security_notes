### Content



---
#### Overview

- Resource-Based constrained delegation shifts the delegation management to the final resource.
- A trust list is created on the resource, Any account on this trusted list has the right to delegate authentication to access the resource.
- Unlike the other two types of delegation, the resource has the right to modify its own trusted list.
- If a service account adds one or more accounts to its trusted list, it updates its `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute in the directory.

Adding a computer to the trusted list:

```PowerShell
PS C:\Tools> Import-Module ActiveDirectory
PS C:\Tools> Set-ADComputer DBSRV -PrincipalsAllowedToDelegateToAccount (Get-ADComputer WEBSRV)
```

<img src="/assets/resource_based_constrained_delegation_msds.png" style="display: block; margin:auto; width:60%; height:60%;">

A TGS request is made by the service account to access a specific resource. A copy of the user's TGS ticket is embedded in this request. The Domain Controller will then check that this service is indeed in the trusted list of the requested resource. If this is the case, it will provide the service with a TGS ticket to access this resource as the user.

---

