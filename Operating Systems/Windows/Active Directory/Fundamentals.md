### Content

- [What is AD](#what-is-ad)
- [AD Key Terminologies](#ad-key-terminologies)
- [Active Directory Structure](#active-directory-structure)
---
# What is AD
- [Active Directory (AD)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview) is a directory service for Windows network environments. It is a distributed, hierarchical structure that allows for centralized management of an organization's resources, including users, computers, groups, network devices and file shares, group policies, servers and workstations, and trusts.
- AD provides authentication and authorization functions within a Windows domain environment.
- AD is essentially a large database accessible to all users within the domain, regardless of their privilege level.
---
# AD Key Terminologies
#### Object
- An object can be defined as ANY resource present within an Active Directory environment such as:
	- `Users` Security principals and have a SID and a GUID. and have many possible  [attributes](http://www.kouti.com/tables/userattributes.htm),(all possible attributes [here](https://www.easy365manager.com/how-to-get-all-active-directory-user-object-attributes/)).
		- Considered a security principal and has a security identifier (SID) and a global unique identifier (GUID).
		- User objects have many possible [attributes](http://www.kouti.com/tables/userattributes.htm), ALL possible attributes as detailed [here](https://www.easy365manager.com/how-to-get-all-active-directory-user-object-attributes/).
	- `Contacts` Only has a GUID.
	- `Printers` Only has a GUID.
	- `Computers` Security principals and have a SID and a GUID.
	- `Shared Folders` Only has a GUID.
	- `Groups` Security principals and have a SID and a GUID, can have many [attributes](http://www.selfadsi.org/group-attributes.htm).
	- `Organizational Units (OUs)`
		- A container that systems administrators can use to store similar objects.
		- We may have a top-level OU and then child OUs under it.
	- `Domain`
	- `Domain Controllers`
	- `Sites` A set of computers connected using high-speed links. Used to make replication across domain controllers run efficiently.
	- `Built-in` A container that holds [default groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups) in an AD domain.
	- `Foreign Security Principals`
		- Object created in AD to represent a security principal that belongs to a trusted external forest.
		- FSP is a placeholder object that holds the SID of the foreign object.
		- Windows uses this SID to resolve the object's name via the trust relationship.
		- FSPs are created in a specific container named ForeignSecurityPrincipals.

<img src="https://academy.hackthebox.com/storage/modules/74/adobjects.png" style="height:55%; width:55%;">

#### Attributes
- Every object in Active Directory has an associated set of [attributes](https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all) used to define characteristics of the given object.
- All attributes in AD have an associated LDAP name that can be used when performing LDAP queries, such as `displayName` for `Full Name` and `given name` for `First Name`.
#### Schema
- The Active Directory [schema](https://docs.microsoft.com/en-us/windows/win32/ad/schema) is essentially the blueprint of any enterprise environment.
- It defines what types of objects can exist in the AD database and their associated attributes.
- It lists definitions corresponding to AD objects and holds information about each object.
#### Domain
- A domain is a logical group of objects such as computers, users, OUs, groups, etc.
- Domains can operate entirely independently of one another or be connected via trust relationships.
#### Tree
- A tree is a collection of Active Directory domains that begins at a single root domain.
- Each domain in a tree shares a boundary with the other domains.
- A parent-child trust relationship is formed when a domain is added under another domain in a tree.
- Two trees in the same forest cannot share a name (namespace).
- All domains in a tree share a standard Global Catalog which contains all information about objects that belong to the tree.
#### Forest
- A forest is a collection of AD trees. It is the topmost container and contains all of the AD objects introduced below, including but not limited to domains, users, groups, computers, and Group Policy objects.
- Each forest operates independently but may have various trust relationships with other forests.
#### Global Unique Identifier (GUID)
- A [GUID](https://docs.microsoft.com/en-us/windows/win32/adschema/a-objectguid) is a unique 128-bit value assigned when an object is created and stored in the `ObjectGUID` attribute and it never changes as long as that object exists in the domain. This GUID value is unique across the enterprise, similar to a MAC address.
- Every single object created by Active Directory is assigned a GUID (user, group, computer, domain, domain controller, etc.), we can query for `objectGUID` value using PowerShell or search for it by specifying its distinguished name, GUID, SID, or SAM account name.
- Searching in Active Directory by GUID value is probably the most accurate and reliable way to find the exact object you are looking for.
#### Security principals
- [Security principals](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals) are anything that the operating system can authenticate, including users, computer accounts, or even threads/processes that run in the context of a user or computer account.
- In AD, security principles are domain objects that can manage access to other resources within the domain.
- We can also have local user accounts and security groups used to control access to resources on only that specific computer, and they are managed by the [Security Accounts Manager (SAM)](https://en.wikipedia.org/wiki/Security_Account_Manager).
#### Security Identifier (SID)
- A [security identifier](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals), or SID is used as a unique identifier for a security principal or security group.
- Every account, group, or process has its own unique SID, which, in an AD environment, is issued by the domain controller and stored in a secure database.
- A SID can only be used once. Even if the security principle is deleted, it can never be used again in that environment to identify another user or group.
- When a user logs in, the system creates an access token for them which contains the user's SID, the rights they have been granted, and the SIDs for any groups that the user is a member of. This token is used to check rights whenever the user performs an action on the computer.
- There are also [well-known SIDs](https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers) that are used to identify generic users and groups. These are the same across all operating systems.
#### Distinguished Name (DN) & Relative Distinguished Name (RDN)
- DN
	- A [Distinguished Name (DN)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names) describes the full path to an object in AD 
	- Example for DN (`cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local`).
- RDN
	- A [Relative Distinguished Name (RDN)](https://docs.microsoft.com/en-us/windows/win32/ad/object-names-and-identities) is a single component of the Distinguished Name that identifies the object as unique from other objects at the current level in the naming hierarchy.
	- It's forbidden to have objects with the same DN under the same parent container, but it's allowed to have objects with the same RDN.

<img src="https://academy.hackthebox.com/storage/modules/74/dn_rdn2.png" style="height:70%; width:70%;">

#### sAMAccountName
- The [sAMAccountName](https://docs.microsoft.com/en-us/windows/win32/ad/naming-properties#samaccountname) is the user's logon name. Here it would just be `bjones`. It must be a unique value and 20 or fewer characters.
#### userPrincipalName
- The [userPrincipalName](https://social.technet.microsoft.com/wiki/contents/articles/52250.active-directory-user-principal-name.aspx) attribute is another way to identify users in AD.
- This attribute consists of a prefix (user name) and a suffix (domain name) in the format of `UserAccountName@DoaminName`.
- This attribute is not mandatory.
#### FSMO Roles
- To resolve this single point of failure model, Microsoft separated the various responsibilities that a DC can have into [Flexible Single Master Operation (FSMO)](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/fsmo-roles) roles.
- Each time a new domain is added to a forest, only the RID Master, PDC Emulator, and Infrastructure Master roles are assigned to the new domain.
- **Per Forest**
	- **Schema Master**
		- Manages the read/write copy of the Active Directory schema.
		- Controls the structure and attributes of objects stored in Active Directory.
		- Responsible for making changes to the schema, such as adding or modifying attributes.
	- **Domain Naming Master**
		- Manages domain names within the forest.
		- Ensures the uniqueness of domain names across the entire forest.
		- Controls the addition or removal of domains from the forest.
- **Per Domain**
	- **Relative Identifier (RID) Master**
		- Allocates unique Relative Identifiers (RIDs) to objects within a domain.
		- Ensures that each object in the domain has a unique security identifier (SID).
		- Prevents SID conflicts by managing RID pools.
	- **Primary Domain Controller (PDC) Emulator**
		- Provides backward compatibility for older Windows clients.
		- Handles authentication requests, password changes, and time synchronization.
		- Acts as the primary source for Group Policy updates within the domain.
	- **Infrastructure Master**
		- Updates references to objects in other domains within the same forest.
		- Translates GUIDs, SIDs, and DNs between domains.
		- Ensures that cross-domain object references are properly maintained.
		- Only relevant in domains where not all domain controllers are also Global Catalog servers.
		- If this role is not functioning properly, Access Control Lists (ACLs) will show SIDs instead of fully resolved names.
#### Global Catalog
- A [global catalog (GC)](https://docs.microsoft.com/en-us/windows/win32/ad/global-catalog) is a domain controller that stores full copy of all objects in the current domain and a partial copy of objects that belong to other domains in the forest.
- The GC allows both users and applications to find information about any objects in ANY domain in the forest.
#### Read-Only Domain Controller (RODC)
- A [Read-Only Domain Controller (RODC)](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema) has a read-only Active Directory database.
- No AD account passwords are cached on an RODC (other than the RODC computer account & RODC KRBTGT passwords.)
#### Replication
- [Replication](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts) happens in AD when AD objects are updated and transferred from one Domain Controller to another.
#### Service Principal Name (SPN)
- A [Service Principal Name (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names) uniquely identifies a service instance.
- They are used by Kerberos authentication to associate an instance of a service with a logon account, allowing a client application to request the service to authenticate an account without needing to know the account name.
#### Group Policy Object (GPO)
- [Group Policy Objects (GPOs)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-objects) are virtual collections of policy settings.
- Each GPO has a unique GUID.
- A GPO can contain local file system settings or Active Directory settings.
- GPO settings can be applied to all users and computers within the domain or defined more granularly at the OU level.
#### Access Control List (ACL)
- An [Access Control List (ACL)](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) is the ordered collection of Access Control Entries (ACEs) that apply to an object.
#### Access Control Entries (ACEs)
- Each [Access Control Entry (ACE)](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-entries) in an ACL identifies a trustee (user account, group account, or logon session) and lists the access rights that are allowed, denied, or audited for the given trustee.
#### Discretionary Access Control List (DACL)
- DACLs define which security principles are granted or denied access to an object; it contains a list of ACEs.
- If an object does NOT have a DACL, then the system will grant full access to everyone, but if the DACL has no ACE entries, the system will deny all access attempts.
#### System Access Control Lists (SACL)
- Allows for administrators to log access attempts that are made to secured objects.
- ACEs specify the types of access attempts that cause the system to generate a record in the security event log.
#### Fully Qualified Domain Name (FQDN)
- A FQDN is the complete name for a specific computer or host. ex `DC01.INLANEFREIGHT.LOCAL`
- It is written with the hostname and domain name in the format `[host name].[domain name].[tld]`.
- This is used to specify an object's location in the tree hierarchy of DNS.
- The FQDN can be used to locate hosts in an Active Directory without knowing the IP address.
#### Tombstone
- A [tombstone](https://ldapwiki.com/wiki/Wiki.jsp?page=Tombstone) is a container object in AD that holds deleted AD objects.
- If an object is deleted in a domain that does not have an AD Recycle Bin, it will become a tombstone object.
- When an object is deleted, the object remains for a set period of time known as the `tombstoneLifetime`, and the `isDeleted` attribute is set to `TRUE` and it will be stripped of most of its attributes and placed in the `Deleted Objects` container
- Once an object exceeds the `Tombstone Lifetime`, it will be entirely removed.
- For the duration of the `tombstoneLifetime` It can be recovered, but any attributes that were lost can no longer be recovered.
#### AD Recycle Bin
- When the [AD Recycle Bin](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944) is enabled, any deleted objects are preserved for a period of time, facilitating restoration if needed.
- Sysadmins can set how long an object remains in a deleted, recoverable state. If this is not specified, the object will be restorable for a default value of 60 days.
#### SYSVOL
- The [SYSVOL](https://social.technet.microsoft.com/wiki/contents/articles/8548.active-directory-sysvol-and-netlogon.aspx) folder, or share, stores copies of public files in the domain such as system policies, Group Policy settings, logon/logoff scripts.
- The contents of the SYSVOL folder are replicated to all DCs within the environment using File Replication Services (FRS) and Distributed File System Replication (DFSR).
- By default, SYSVOL includes 2 folders:
	1. **Policies** `Default location:  %SystemRoot%\SYSVOL\SYSVOL\_<domain_name>_\Policies`
	2. **Scripts** `Default location:  %SystemRoot%\SYSVOL\SYSVOL\_<domain_name>_\scripts`
- Read more about the SYSVOL structure [here](https://networkencyclopedia.com/sysvol-share/#Components-and-Structure).
#### AdminSDHolder
- The [AdminSDHolder](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) object is used to manage ACLs for members of built-in groups in AD marked as privileged.
- It acts as a container that holds the Security Descriptor applied to members of protected groups.
- The SDProp (SD Propagator) process runs on a schedule on the PDC Emulator Domain Controller.
- When this process runs, it checks members of protected groups to ensure that the correct ACL is applied to them.
- It runs every hour by default.
#### dsHeuristics
- The [dsHeuristics](https://docs.microsoft.com/en-us/windows/win32/adschema/a-dsheuristics) attribute is a string value set on the Directory Service object used to define multiple forest-wide configuration settings.
- One of these settings is to exclude built-in groups from the [Protected Groups](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) list. Groups in this list are protected from modification via the `AdminSDHolder` object.
- If a group is excluded via the `dsHeuristics` attribute, then any changes that affect it will not be reverted when the SDProp process runs.
#### adminCount
- The [adminCount](https://docs.microsoft.com/en-us/windows/win32/adschema/a-admincount) attribute determines whether or not the SDProp process protects a user.
- If the value is set to `0` or not specified, the user is not protected.
- If the attribute value is set to `1` or `value`, the user often have elevated privileges.
- Attackers will often look for accounts with the `adminCount` attribute set to `1` to target in an internal environment.
#### Active Directory Users and Computers (ADUC)
- GUI console commonly used for managing users, groups, computers, and contacts in AD.
- Changes with ADUC can be done via PowerShell.
#### ADSI Edit
- GUI tool used to manage objects in AD.
- Provides access to far more than is available in ADUC and can be used to set or delete any attribute available on an object, add, remove, and move objects as well.
#### sIDHistory
- [sIDHistory](https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unsecure-sid-history-attribute) attribute holds any SIDs that an object was assigned previously.
- Used in migrations so a user can maintain the same level of access when migrated from one domain to another.
- Can be abused if set insecurely, allowing an attacker to gain prior elevated access that an account had before a migration if SID Filtering (or removing SIDs from another domain from a user's access token that could be used for elevated access) is not enabled.
#### NTDS.DIT
- The NTDS.DIT file stored on a Domain Controller at `C:\Windows\NTDS\` and it's a database that stores AD data such as information about user and group objects, group membership, and, most important to attackers and penetration testers, the password hashes for all users in the domain.
- If the setting [Store password with reversible encryption](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) is enabled, then the NTDS.DIT will also store the cleartext passwords for all users created or who changed their password after this policy was set.
---
# Active Directory Structure
- AD is arranged in a hierarchical tree structure.
- Forest is the highest level and it can contain one or more domains, which can themselves have nested subdomains.
- Forests and domains can be linked together via trust relationships.

<img src="https://academy.hackthebox.com/storage/modules/74/ad_forests.png" style="height:70%; width:70%;">
<img src="https://academy.hackthebox.com/storage/modules/74/ilflog2.png" style="height:70%; width:70%;">

### Domain and Forest Functional Levels
- Active Directory Domain Services (AD DS) functional levels determine the features and capabilities of an AD environment based on the versions of Windows Server running on domain controllers.
##### 1. Domain Functional Level (DFL):
- **Scope:** Applies to a specific domain.
- **Impact:** Determines the features that all domain controllers (DCs) in the domain can use.
- **Requirement:** All DCs in the domain must run a Windows Server version compatible with the functional level.
##### 2. Forest Functional Level (FFL):
- **Scope:** Applies to the entire forest.
- **Impact:** Determines the features available across the forest and all domains within it.
- **Requirement:** All domains in the forest must operate at a domain functional level that supports the forest level.
#### Trusts
- A trust used to establish a link between the authentication systems of two domains or forests.
- Types of trusts:
	- `Parent-child` The child domain has a two-way transitive trust with the parent domain.
	- `Cross-link` A trust between child domains to speed up authentication.
	- `External` Non-transitive trust between two domains in separate forests which are not already joined by a forest trust.
	- `Tree-root` Two-way transitive trust between a forest root domain and a new tree root domain.
	- `Forest` Transitive trust between two forest root domains.
- Trusts can be transitive or non-transitive:
	- `Transitive trust` means that trust is extended to objects that the child domain trusts.
		- If Domain A trusts Domain B, and Domain B has a transitive trust with Domain C, then Domain A will trust Domain C.
	- `Non-transitive trust`, only the child domain itself is trusted.
		- Domain A trusts Domain B only, regardless of any trusts Domain B might have with other domains.
- Trusts can be one-way or two-way (bidirectional).

<img src="https://academy.hackthebox.com/storage/modules/74/trusts-diagram.png" style="height:60%;width:80%;">

---

