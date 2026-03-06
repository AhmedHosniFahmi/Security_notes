### Content

- [What is a trust](#what-is-a-trust)
- [Enumeration](#enumeration)

---
## What is a trust

A trust used to establish a link between the authentication systems of two domains or forests.

Types of trusts:
- `Parent-child` The child domain has a two-way transitive trust with the parent domain.
- `Cross-link` A trust between child domains to speed up authentication.
- `External` Non-transitive trust between two domains in separate forests which are not already joined by a forest trust.
- `Tree-root` Two-way transitive trust between a forest root domain and a new tree root domain.
- `Forest` Transitive trust between two forest root domains.

<img src="/assets/trusts-diagram.png" style="height:50%;width:70%;display: block; margin:auto;">

Trusts can be:
- `Transitive trust` means that trust is extended to objects that the child domain trusts.
	- If Domain A trusts Domain B, and Domain B has a transitive trust with Domain C, then Domain A will trust Domain C.
- `Non-transitive trust`, only the child domain itself is trusted.
	- Domain A trusts Domain B only, regardless of any trusts Domain B might have with other domains.

| Transitive                                                            | Non-Transitive                              |
| --------------------------------------------------------------------- | ------------------------------------------- |
| Shared, 1 to many                                                     | Direct trust                                |
| The trust is shared with anyone in the forest                         | Not extended to next level child domains    |
| Forest, tree-root, parent-child, and cross-link trusts are transitive | Typical for external or custom trust setups |

<img src="/assets/transitive-trusts.png" style="height:50%;width:60%;display: block; margin:auto;">

Trusts can be set up in two directions:
- `One-way trust`: Users in a `trusted` domain can access resources in a trusting domain, not vice-versa.
- `Bidirectional trust`: Users from both trusting domains can access resources in the other domain.

---
## Enumeration

``` Powershell
# ActiveDirectory module
PS C:\> Get-ADTrust -Filter *

# PowerView
PS C:\> Get-DomainTrust 
PS C:\> Get-DomainTrustMapping

# netdom on CMD
PS C:\> netdom query /domain:inlanefreight.local trust
# query domain controllers
PS C:\> netdom query /domain:inlanefreight.local dc
# query workstations and servers
PS C:\> netdom query /domain:inlanefreight.local workstation
```



We can also use BloodHound to visualize these trust relationships by using the `Map Domain Trusts` pre-built query. Here we can easily see that two bidirectional trusts exist.