# dMSA

`Delegated Managed Service Account` is a new account introduced in Windows Server 2025 allowing migration from a traditional service account to a machine account with managed and fully randomized keys, while disabling original service account passwords.

**Authentication for dMSA is linked to the device identity**, which means that only specified machine identities mapped in Active Directory (AD) can access the account.

Using dMSA helps to prevent harvesting credentials using a compromised account (`kerberoasting`), which is a common issue with traditional service accounts.

dMSA allows users to create them as a standalone account, or to replace an existing standard service account. When a dMSA supersedes an existing account, authentication to that existing account using its password is blocked. The request is redirected to the Local Security Authority (LSA) to authenticate using dMSA, which has access to everything the previous account could access in AD.


