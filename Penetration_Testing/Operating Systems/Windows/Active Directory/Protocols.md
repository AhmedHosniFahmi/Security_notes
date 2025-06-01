### Content
- [Kerberos](#kerberos)
- [LDAP](#ldap)
- [MSRPC](#msrpc)
- [Authentication Methods](#authentication-methods)
	- [LM](#lm)
	- [NT Hash (NTLM)](#nt-hash-(ntlm))
	- [NTLMv1 (Net-NTLMv1)](#ntlmv1-(net-ntlmv1))
	- [NTLMv2 (Net-NTLMv2)](#ntlmv2-(net-ntlmv2))
---
# Kerberos
Network-based authentication protocol that uses secret-key cryptography to verify the identity of users and services.
All actors have to synchronize the time between them.
The Kerberos protocol uses **port 88 (both TCP and UDP).**
##### Components in Kerberos:
1. **Key Distribution Center (KDC)**:
	1. Central authority that manages authentication.
	2. Have two sub-components:
		1. **Authentication Server (AS)**: Handles initial authentication requests.
		2. **Ticket Granting Server (TGS)**: Issues service tickets for accessing resources.
2. **Client**: The user or application requesting authentication.
3. **Service**: The resource or application the client wants to access.
4. **Tickets**:
	1. **Ticket Granting Ticket (TGT)**: Proof of authentication, used to request service tickets.
	2. **Ticket Granting Service (TGS)**: Allows access to a specific service.
5. **Session Key**: Temporary key used to encrypt communication between two parties during a session.

``` mermaid
sequenceDiagram
    participant Client
    participant AS as KDC (AS)
    participant TGS as KDC (TGS)
    participant Service as Service
    
	Note over Client,AS: AS-REQ
    rect rgb(255,255,255)
    Client-)AS: [1] TGT Ticket (Client's identity, Timestamp)
    Note over Client,AS: Encrypted using client hash
    Note over AS: Decrypt TGT Ticket using client hash 
    end
    
    Note over Client,AS: AS-REP
    rect rgb(255,255,255)
    AS--)Client: [2] TGT (Client's identity, Expiration time, Session key)
    Note over AS,Client: Encrypted using TGS secret
    
	AS--)Client: [3] (Session key)
    Note over AS,Client: Encrypted using client hash
    Note over Client: Decrypt session key using the client hash
    Note over Client: Create authenticator (Client's identity)
    Note over Client: Encrypt authenticator using session key
    end
    
    Note over Client,TGS: TGS-REQ
    rect rgb(255,255,255)
    Client-)TGS: [4] TGS Ticket (TGT(Client's identity, Expiration time, Session key), Service Name) + (Authenticator)
    Note over TGS: Decrypt TGT using TGS secret (extract session key)
    Note over TGS: Decrypt authenticator using extracted session key
    Note over TGS: Check TGT identity and authenticator identity
    end
    
    Note over Client,TGS: TGS-REP
    rect rgb(255,255,255)
    TGS--)Client: [5] TGS (Client's identity, New Session key)
    Note over TGS,Client: Encrypted with Service's Secret
    
	TGS--)Client: [6] (New Session key)
    Note over TGS,Client: Encrypted usig old session key from [3]
	Note over Client: Decrypt new session key using the old one
    Note over Client: Create authenticator (client's identity)
    Note over Client: Encrypt authenticator using new session key
    end
    
    Note over Client,Service: AP-REQ
    rect rgb(255,255,255)
    Client-)Service: [7] TGS (New Session key, Client's Identity) + (Authenticator)
    Note over Service: Decrypt TGS
    Note over Service: Decrypt Authenticator
    Note over Service: Compare Identities
    Note over Service: Check client permessions
    end
    
    Note over Client,Service: AP-REP
    rect rgb(255,255,255)
    Service--)Client: [8] (Timestamp) Encrypted with last session key
    end
```
---
# LDAP
- LDAP is how systems in the network environment can "speak" to AD.
- LDAP uses port 389, and LDAP over SSL (LDAPS) communicates over port 636.
- The relationship between AD and LDAP can be compared to Apache and HTTP.
- LDAP authentication messages are sent in cleartext by default.
#### AD LDAP Authentication Types
1. `Simple Authentication` Includes:
	1. `Anonymous Authentication`: No credentials are supplied.
	2. `Unauthenticated Authentication`: A username is provided, but no password is required. 
	3. `Username/Password Authentication`: A BIND request with a username and password.
2. `SASL Authentication`: [The Simple Authentication and Security Layer (SASL)](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer) uses other authentication services, such as Kerberos.


<div style="display: flex; justify-content: center;"><img src="https://academy.hackthebox.com/storage/modules/74/LDAP_auth.png" style="height:60%;width:80%;"></div>

---
## MSRPC

MSRPC is Microsoft's implementation of Remote Procedure Call (RPC), an interprocess communication technique used for client-server model-based applications.
Windows systems use MSRPC to access systems in Active Directory using four key RPC interfaces:

|Interface Name|Description|
|---|---|
|`lsarpc`|A set of RPC calls to the [Local Security Authority (LSA)](https://networkencyclopedia.com/local-security-authority-lsa/) system which manages the local security policy on a computer, controls the audit policy, and provides interactive authentication services. LSARPC is used to perform management on domain security policies.|
|`netlogon`|Netlogon is a Windows process used to authenticate users and other services in the domain environment. It is a service that continuously runs in the background.|
|`samr`|Remote SAM (samr) provides management functionality for the domain account database, storing information about users and groups. IT administrators use the protocol to manage users, groups, and computers by enabling admins to create, read, update, and delete information about security principles. Attackers (and pentesters) can use the samr protocol to perform reconnaissance about the internal domain using tools such as [BloodHound](https://github.com/BloodHoundAD/) to visually map out the AD network and create "attack paths" to illustrate visually how administrative access or full domain compromise could be achieved. Organizations can [protect](https://stealthbits.com/blog/making-internal-reconnaissance-harder-using-netcease-and-samri1o/) against this type of reconnaissance by changing a Windows registry key to only allow administrators to perform remote SAM queries since, by default, all authenticated domain users can make these queries to gather a considerable amount of information about the AD domain.|
|`drsuapi`|drsuapi is the Microsoft API that implements the Directory Replication Service (DRS) Remote Protocol which is used to perform replication-related tasks across Domain Controllers in a multi-DC environment. Attackers can utilize drsuapi to [create a copy of the Active Directory domain database](https://attack.mitre.org/techniques/T1003/003/) (NTDS.dit) file to retrieve password hashes for all accounts in the domain, which can then be used to perform Pass-the-Hash attacks to access more systems or cracked offline using a tool such as Hashcat to obtain the cleartext password to log in to systems using remote management protocols such as Remote Desktop (RDP) and WinRM.

---
# Authentication Methods
- `LM` and `NTLM` here are the hash names.
- `NTLMv1` and `NTLMv2` are authentication protocols that utilize the `LM` or `NT` hash.

| **Hash/<br>Protocol** | **Cryptographic technique**                          | **Mutual Authentication** | **Message Type**                | **Trusted Third Party**                         |
| --------------------- | ---------------------------------------------------- | ------------------------- | ------------------------------- | ----------------------------------------------- |
| `NTLM`                | Symmetric key cryptography                           | No                        | Random number                   | Domain Controller                               |
| `NTLMv1`              | Symmetric key cryptography                           | No                        | MD4 hash, random number         | Domain Controller                               |
| `NTLMv2`              | Symmetric key cryptography                           | No                        | MD4 hash, random number         | Domain Controller                               |
| `Kerberos`            | Symmetric key cryptography & asymmetric cryptography | Yes                       | Encrypted ticket using DES, MD5 | Domain Controller/Key Distribution Center (KDC) |
### LM
- Old and weak.
- LAN Manager hashes are stored in:
	- SAM database on windows hosts.
	- NTDS.DIT on a Domain Controller.
- Passwords using LM are:
	- Limited to 14 chars
	- Not case sensitive because they are converted to uppercase before generating the hashed value.
- The algorithm:
	- If the password is less than 14 chars, padded with NULL chars to reach 14 chars.
	- Split the 14 chars into 2 chunks.
	- 2 DES keys are created from each chunk.
	- Encrypt the string `KGS!@#$%` twice, each with a key, which will create two 8-byte ciphertexts.
	- Concatenate the 2 ciphertexts resulting in an LM hash.
### NT Hash (NTLM)
- NT LAN Manager hashes are stronger.
- It's challenge-response authentication protocol.
- The protocol has two hashed password values to choose from to perform authentication:
	- LM hash
	- NT hash, which is the MD4 hash of the little-endian UTF-16 value of the password. `MD4(UTF-16-LE(password))`
- NTLM is vulnerable to pass the hash `PtH` attack
	- An NTLM hash looks like this: `<UserName>:<RelativeIdentifier(RID)>:<LM hash>:<NT hash>:::`
	- Use [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) to exploit PtH vuln:
		``` bash
		crackmapexec smb <IP> -u <UserName> -H <NT hash>
		```
``` mermaid
sequenceDiagram
	Participant C as Client
	Participant DC as Domain Controller (Server)
	
	C-)DC: NTLM Negotiate Message
	DC--)C: NTLM Challenge Message
	C-)DC: NTLM Authenticate Message
	C-)DC: Netlogon_network_info
	DC--)C: Netlogon_Validation_SAM_info
```
### NTLMv1 (Net-NTLMv1)
- NTLMv1 uses both the NT and the LM hash.
- Attacker can capture the hash using a tool such as [Responder](https://github.com/lgandx/Responder) or via an [NTLM relay attack](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html).
- The protocol is used for network authentication, and the Net-NTLMv1 hash is created from a challenge/response algorithm.
- Example `<UserName>::<DomainName(or)HostName>:<ServerChallenge>:<NTLMv1 Response>:<ClientChallenge>`
``` mermaid
sequenceDiagram
    participant Client
    participant Server

    Client-)Server: Negotiate Protocol
    Server--)Client: Server Challenge, random 8-byte (SC)

    Note left of Client: Compute NT/LM-Hash padded with 5-bytes-0
    Note left of Client: Split it into: K1 | K2 | K3
    Note left of Client: DES(K1, C), DES(K2, C), DES(K3, C)
    Client-)Server: Response = DES(K1, C) | DES(K2, C) | DES(K3, C)

    Note left of Server: Compare Received with Expected Response
```
### NTLMv2 (Net-NTLMv2)
- Created as a stronger alternative to NTLMv1.
- Example `<UserName>::<Domain(or)HostName>:<SC>:<LMv2>:<NTv2>`
``` mermaid
sequenceDiagram
	Participant C as CLient
	Participant S as Server

	C-)S: Negotiate Protocol
	S--)C: Challenge (SC: 8-byte random)
	Note left of C: Generate CC (8-byte random)
	Note left of C: Construct CC* (X, time, CC2, domain name)
	Note left of C: v2-Hash = HMAC-MD5(NT-Hash, user name, domain name)
	Note left of C: LMv2 = HMAC-MD5(v2-Hash, SC, CC)
	Note left of C: NTv2 = HMAC-MD5(v2-Hash, SC, CC*)
	C-)S: Response = LMv2 | CC | NTv2 | CC*
```
---