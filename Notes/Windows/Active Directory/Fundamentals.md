### Content

- [What is AD](#what-is-ad)
- [AD Key Terminologies](#ad-key-terminologies)
---
## What is AD
- [Active Directory (AD)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview) is a directory service for Windows network environments. It is a distributed, hierarchical structure that allows for centralized management of an organization's resources, including users, computers, groups, network devices and file shares, group policies, servers and workstations, and trusts.
- AD provides authentication and authorization functions within a Windows domain environment.
- AD is essentially a large database accessible to all users within the domain, regardless of their privilege level.
---
## AD Key Terminologies:
#### Object
An object can be defined as ANY resource present within an Active Directory environment such as OUs, printers, users, domain controllers, etc.
#### Attributes
Every object in Active Directory has an associated set of [attributes](https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all) used to define characteristics of the given object. All attributes in AD have an associated LDAP name that can be used when performing LDAP queries, such as `displayName` for `Full Name` and `given name` for `First Name`.
#### Schema
The Active Directory [schema](https://docs.microsoft.com/en-us/windows/win32/ad/schema) is essentially the blueprint of any enterprise environment. It defines what types of objects can exist in the AD database and their associated attributes. It lists definitions corresponding to AD objects and holds information about each object.
#### Domain
A domain is a logical group of objects such as computers, users, OUs, groups, etc. Domains can operate entirely independently of one another or be connected via trust relationships.
#### Tree
A tree is a collection of Active Directory domains that begins at a single root domain. Each domain in a tree shares a boundary with the other domains. A parent-child trust relationship is formed when a domain is added under another domain in a tree. Two trees in the same forest cannot share a name (namespace). All domains in a tree share a standard Global Catalog which contains all information about objects that belong to the tree.
#### Forest
A forest is a collection of AD trees. It is the topmost container and contains all of the AD objects introduced below, including but not limited to domains, users, groups, computers, and Group Policy objects. Each forest operates independently but may have various trust relationships with other forests.
#### Container
Container objects hold other objects and have a defined place in the directory subtree hierarchy.
#### Leaf
Leaf objects do not contain other objects and are found at the end of the subtree hierarchy.
#### Global Unique Identifier (GUID)
A [GUID](https://docs.microsoft.com/en-us/windows/win32/adschema/a-objectguid) is a unique 128-bit value assigned when an object is created and stored in the `ObjectGUID` attribute and it never changes as long as that object exists in the domain. This GUID value is unique across the enterprise, similar to a MAC address. Every single object created by Active Directory is assigned a GUID (user, group, computer, domain, domain controller, etc.), we can query for `objectGUID` value using PowerShell or search for it by specifying its distinguished name, GUID, SID, or SAM account name. Searching in Active Directory by GUID value is probably the most accurate and reliable way to find the exact object you are looking for.
#### Security principals
[Security principals](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals) are anything that the operating system can authenticate, including users, computer accounts, or even threads/processes that run in the context of a user or computer account. In AD, security principles are domain objects that can manage access to other resources within the domain. We can also have local user accounts and security groups used to control access to resources on only that specific computer. These are not managed by AD but rather by the [Security Accounts Manager (SAM)](https://en.wikipedia.org/wiki/Security_Account_Manager).
#### Security Identifier (SID)
A [security identifier](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals), or SID is used as a unique identifier for a security principal or security group. Every account, group, or process has its own unique SID, which, in an AD environment, is issued by the domain controller and stored in a secure database. A SID can only be used once. Even if the security principle is deleted, it can never be used again in that environment to identify another user or group. When a user logs in, the system creates an access token for them which contains the user's SID, the rights they have been granted, and the SIDs for any groups that the user is a member of. This token is used to check rights whenever the user performs an action on the computer. There are also [well-known SIDs](https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers) that are used to identify generic users and groups. These are the same across all operating systems.
#### Distinguished Name (DN)











<img src="https://academy.hackthebox.com/storage/modules/74/whyad5.png" style="height:70%; width:70%;">