### Content
- [Double Hop Problem](#double-hop-problem)
- [Credential Delegation](#credential-delegation)
- [Kerberos Delegation](#kerberos-delegation)
	- [Unconstrained Delegation](#unconstrained-delegation)
	- [Constrained Delegation](#constrained-delegation)
	- [Resource-Based Constrained Delegation](#resource-based-constrained-delegation)

> [!Important]
> Resources: 
> - [ATTL4S](https://attl4s.github.io/)

---
# Double Hop Problem

- The problem arises when an attacker attempts to use Kerberos authentication across two (or more) hops.
- When we perform Kerberos authentication, we get a "TGS" to access the requested resource (i.e., a single machine).
	- If the first service is using a resource on another machine, we will fail because all the service has about us is a TGS.
- On the contrary, when we use a password to authenticate, that NTLM hash is stored in our session and can be used elsewhere without issue.

**The solutions are credential or kerberos delegation.**

---
# Credential Delegation

The act of sending some credential material to the service, so that the service can use it to impersonate clients in the network if needed.

| Configuration                               | Note                                                                                                                     |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| CredSSP                                     | `Server` is configured to support CredSSP.<br>`Client` trusts server and passes full credentials without any constraint. |
| Just Enough Administration (JEA)            | `Server` is configured with hardcoded credentials.<br>`Client` connects and works with those credentials.                |
| PSSessionConfiguration using RunAs          | `Server` is configured with hardcoded credentials<br>`Client` connects and works with those credentials                  |
| PS Remoting cmdlets with “-Credential” flag | `Server` does not need any configuration<br>`Client` connects and specifies credentials on the spot when needed          |

Solving double hop problem with `CredSSP`.

<img src="/assets/credssp_solve_double_hop.png" style="display: block; margin:auto; width:80%; height:60%;">

Why not (NTLM hash) delegation is not an optimal solution:
- Would depend on the password / NTLM hash of clients
- Credentials would need to be verified on the Domain Controller on each authentication.
- Having tons of NTLM hashes cached in a server is a risk.

<img src="/assets/ntlm_hash_delegation.png" style="display: block; margin:auto; width:80%; height:60%;">

---
# Kerberos Delegation

- Does not depend on the original user password or NTLM hashes.
- Authentication is based on Tickets and session keys. 
	- The are trusted by default and not verified by a DC on each access as the TGS is encrypted with the service hash itself.
- Having Tickets and session keys cached in a server is less riskier having NTLM hashes


## Unconstrained Delegation

- If unconstrained delegation is configured in the service, the client delegated a copy of his TGT to the service server.
- The service then can act on behalf  of the client in the network by using his TGT.
- Setting up this delegation requires domain or enterprise admin privileges. `SeEnableDelegation`

- If an attacker got control over that service machine, it's possible to dump all the TGTs in the memory.

> Set up unconstrained delegation on a service

<img src="/assets/unconstrained_delegation_settings.png" style="display: block; margin:auto; width:80%; height:60%;">

> How does unconstrained delegations works with a web service that's used as GUI for CIFS on another machine.

<img src="/assets/how_does_unconstrained_delegation_work.png" style="display: block; margin:auto; width:80%; height:60%;">

## Constrained Delegation



## Resource-Based Constrained Delegation
