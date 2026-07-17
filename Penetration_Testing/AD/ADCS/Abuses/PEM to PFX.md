### Content

- [OpenSSL (Cross-Platform)](#openssl-(cross-platform))
- [Certutil (Windows Native)](#certutil-(windows-native))
- [Python cryptography library](#python-cryptography-library)
- [gettgtpkinit.py](#gettgtpkinit.py)

> All the methods to convert PEM certificate to PFX certificate

```
# Save the private key and certificate to separate files if required
# cert.key (from -----BEGIN RSA PRIVATE KEY----- to -----END RSA PRIVATE KEY-----)
# cert.pem (from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE-----)
```

---
### OpenSSL (Cross-Platform)

```bash
# Linux
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx -passout pass:

# Windows
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in .\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Requires both cert and key to be in the same `cert.pem` file. 

---

### Certutil (Windows Native)

```powershell
certutil -MergePFX .\cert.pem .\cert.pfx
```

Requires the cert and key to be in **separate files**. No third-party tools needed.

---

### Python cryptography library

```python
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate

# Load cert and key
with open("cert.pem", "rb") as f:
    cert_data = f.read()

cert = load_pem_x509_certificate(cert_data)
key = load_pem_private_key(cert_data, password=None)

# Export to PFX with no password
pfx = pkcs12.serialize_key_and_certificates(
    name=None,
    key=key,
    cert=cert,
    cas=None,
    encryption_algorithm=NoEncryption()
)

with open("cert.pfx", "wb") as f:
    f.write(pfx)
```

---

### gettgtpkinit.py

https://github.com/dirkjanm/PKINITtools/tree/master

Getting a TGT using `gettgtpkinit.py`:

```bash
# Some impacket-based tools accept PEM directly, skipping PFX conversion entirely
$ gettgtpkinit.py <DOMAIN>/Administrator -cert-pem ~/cert.pem -key-pem ~/cert.key ~/Administrator.ccache
```

---