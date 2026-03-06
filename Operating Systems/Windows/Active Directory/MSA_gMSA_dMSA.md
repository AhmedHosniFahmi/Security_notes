### Content

- [Overview](#overview)
- [Managed Service Account (MSA)](#managed-service-account-(msa))
- [Group Managed Service Account (gMSA)](#group-managed-service-account-(gmsa))
- [Delegated Managed Service Account (dMSA)](#delegated-managed-service-account-(dmsa))

---
### Overview

Active Directory Domain Services (ADDS) service accounts are special accounts used by applications or services to interact with network resources.

**Originally** these were often standard user accounts with static passwords, leading to security risks such as kerberoasting.

As a solution, Microsoft introduced:

- [Managed Service Accounts (MSA)](https://techcommunity.microsoft.com/blog/askds/managed-service-accounts-understanding-implementing-best-practices-and-troublesh/397009) -> in Windows Server 2008 R2 and Windows 7
- [group Managed Service Accounts (gMSA)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview) -> in Windows Server 2012
- [Delegated Managed Service Accounts (dMSA)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) -> in Windows Server 2025

---
#### Managed Service Account (MSA)

- MSA is a domain account tied to a single host.
- ADDS automatically manages its password, eliminating manual updates.
- A MSA can only be used on one computer, and you must configure that specific host as the account’s owner.
- MSAs simplify password management for services on single servers but cannot be shared across multiple systems.
	- Complex, automatically generated password (240 bytes = 120 characters), updated every 30 D by default.

MSA object class inheritance structure is a user and a computer at the same time, just like a computer account. Although it doesn't have an object class of **person** like a computer account typically would; instead it has ***msDS-ManagedServiceAccount***. All Managed Service Accounts are created (by default) in the `CN=Managed Service Accounts, DC=<domain>, DC=<com>` container. You can see this by configuring `DSA.MSC` to show `Advanced Features`.

---

#### Group Managed Service Account (gMSA)

- A `gMSA` extends MSAs by allowing multiple hosts to use the same account.
- ADDS stores a long, randomly generated password for the `gMSA`, and any authorized host can retrieve the current password to run services. Which makes `gMSAs` ideal for load balanced services or clusters. 
- he password is auto rotated by ADDS and fetched as needed by hosts set in the `PrincipalsAllowedToRetrieveManagedPassword` attribute in the service account.

---

#### Delegated Managed Service Account (dMSA)

- A dMSA is a new type of service account in (AD) that expands on the capabilities of (gMSAs).
- A key feature of dMSAs is the ability to migrate existing non managed service accounts into dMSAs.
- This migration flow tightly couples the dMSA to the superseded account.
- The primary goal of dMSA is to enhance security and simplify credential management for services, especially during transitions from older accounts.
- dMSA authentication is linked to a device’s identity, and the cryptographic secrets for the account are kept such that they cannot be retrieved in plaintext from ADDS by an admin or host, and the secret exists only on the domain controller. It is derived in part from the machine’s own credentials. This means even if a host is authorized to use a dMSA, it doesn’t get a reusable password hash. It receives a Kerberos ticket or key uniquely tied to that machine.

> In practice, a dMSA often starts as a replacement for an existing user based service account. The dMSA takes over the identity and permissions of that legacy account through a migration process, but with far stronger protections on the credentials.
> 
> The migration operation flow with details can be reviewed in [akami blog](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory?&vid=badsuccessor-demo-video).

---