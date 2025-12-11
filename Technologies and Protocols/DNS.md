### Content

- [Types of DNS Servers](#types-of-dns-servers)
	- [DNS Root Server](#dns-root-server)
	- [Authoritative Name Server](#authoritative-name-server)
	- [Non-Authoritative Name Server](#non-authoritative-name-server)
	- [Caching DNS Server](#caching-dns-server)
	- [Forwarding Server](#forwarding-server)
	- [Resolver](#resolver)
- [DNS Records](#dns-records)
	- [A](#a)
	- [AAAA](#aaaa)
	- [MX](#mx)
	- [NS](#ns)
	- [TXT](#txt)
	- [CNAME](#cname)
	- [PTR](#ptr)
	- [SOA](#soa)
- [Zone File](#zone-file)
	- [SOA (Start of Authority) Records](#soa-(start-of-authority)-records)
	- [Zone Transfer](#zone-transfer)

---

>[!Note] 
> - DNS (Domain Name Server) is a system for resolving computer names into IPs.
> 	- It can also provide different types of information:
> 		- Mail servers
> 		- The authoritative for the domain
> 		- Other record types (`TXT`, `SRV`, `CNAME`)
> - DNS is unencrypted by default, Solutions?
> 	- Apply DNS over TLS (`DoT`) or DNS over HTTPS (`DoH`)
> 	- Use the network protocol `DNSCrypt` which encrypts the connection between clients and NS.

<img src="/assets/dns_query.png">

<img src="/assets/dns_query_iterative.png">

---
### Types of DNS Servers

##### DNS Root Server

The root servers of the DNS are responsible for the top-level domains (`TLD`). As the last instance, they are only requested if the name server does not respond.

##### Authoritative Name Server

Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is official, definitive, and must be trusted as the correct source for that zone. If an authoritative name server cannot answer a client's query, the root name server takes over at that point.

##### Non-Authoritative Name Server

Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying.

##### Caching DNS Server

Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage.

##### Forwarding Server

Forwarding servers perform only one function: they forward DNS queries to another DNS server.

##### Resolver

Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router.

---
### DNS Records

#### A

IPv4 address of the requested domain.

#### AAAA

IPv6 address of the requested domain.
 
#### MX

Returns the responsible mail servers as a result.

#### NS

Returns the DNS servers (nameservers) of the domain.

#### TXT

This record can contain various information. such as but not limited to:

- Domain owner ship verification
- Email security (`SPF`, `DKIM`, `DMARC`)

#### CNAME

Canonical name record serves as an alias for another domain name. Forwards one domain or subdomain to another domain, does NOT provide an IP address.

> For example, suppose` blog.example.com` has a `CNAME` record with a value of `example.com` (without the "blog"). This means when a DNS server hits the DNS records for `blog.example.com`, it actually triggers another DNS lookup to example.com, returning `example.com` IP address via its A record. In this case we would say that `example.com` is the canonical name (or true name) of blog.example.com.
  
#### PTR

The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.

#### SOA

Start of authority (SOA) record stores important information about a domain or zone such as the email address of the administrator, when the domain was last updated, and how long the server should wait between refreshes.

---
### Zone File

- A `zone file` is a text file that describes a DNS zone completely.
- There must be precisely one `SOA` record (usually located in the beginning) and at least one `NS` record.

Example of a zone file:

```json
;
; BIND reverse data file for local loopback interface
;
$ORIGIN domain.com
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

      IN     MX     10     mx.domain.com.
      IN     MX     20     mx2.domain.com.

             IN     A       10.129.14.5

server1      IN     A       10.129.14.5
server2      IN     A       10.129.14.7
ns1          IN     A       10.129.14.2
ns2          IN     A       10.129.14.3

ftp          IN     CNAME   server1
mx           IN     CNAME   server1
mx2          IN     CNAME   server2
www          IN     CNAME   server2
```

#### SOA (Start of Authority) Records:

```json
$ORIGIN domain.com
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day
```

An SOA (Start of Authority) record is an essential part of a DNS zone file and provides important information about the zone's configuration and management. It includes the following fields:

**Primary Name Server (NS):** `dns1.domain.com`

- This field specifies the primary authoritative name server for the zone.
- It indicates the DNS server responsible for serving the zone's DNS records and managing updates to the zone.
- For example: ns1.example.com.

**Responsible Person's Email Address (Email):** `hostmaster.domain.com` --> `hostmaster@domain.com`

- This field specifies the email address of the responsible person or administrator overseeing the zone.
- It is typically written with a dot replaced by an "@" symbol.

**Serial Number:**

- The serial number is a unique identifier for the zone's DNS records.
- It is typically a numeric value and is incremented each time the zone's records are updated.
- In the given example, the serial number is `2001062501`, which suggests that it was last updated or modified on June 25, 2001.
- The serial number helps in determining the freshness of DNS data during zone transfers between DNS servers.

**Retry:**

- The retry value specifies the amount of time (in seconds) that secondary DNS servers should wait before attempting to retry a failed zone transfer or refresh attempt.
- If a secondary DNS server fails to contact the authoritative DNS server during the refresh interval, it will wait for the retry interval to elapse before making another attempt.
- The retry value is typically shorter than the refresh value to ensure timely retries.
- For example, a retry value of 3600 seconds (1 hour) means the secondary DNS server will wait for 1 hour before retrying a failed zone transfer or refresh.

**Refresh:**

- The refresh value indicates how often (in seconds) secondary DNS servers should check the authoritative DNS server for updates.
- It specifies the interval at which secondary servers should attempt to refresh their copies of the zone's records from the primary authoritative server.
- In the provided example with a refresh value of 21600 seconds (6 hours), the secondary DNS servers will contact the authoritative server to update their copies of the zone's records at least once every hour.

**Expire:**

- The expire value sets the maximum time (in seconds) that secondary DNS servers can use a zone's data without successfully refreshing it from the authoritative server.
- If a secondary server fails to refresh the zone within the specified expire interval, it will consider the zone expired and stop responding to DNS queries for that zone.
- In the provided configuration, the expire value is set to 604800 seconds (7 days).

**Minimum TTL (Negative TTL):** `$TTL 86400`

- The Minimum TTL (Negative TTL) is a value that specifies how long a negative DNS response, indicating the non-existence of a DNS record, should be cached by DNS resolvers or clients.
- It is used when a query is made for a resource record that does not exist. The Minimum TTL determines the caching duration for negative responses, such as "NXDOMAIN" or "NODATA" responses.
- This value is separate from the TTL values of actual existing DNS records and is typically a lower value.
- It ensures that DNS resolvers or clients cache the negative response for a specified duration before attempting to query the authoritative DNS server again for the same non-existent record.

#### Zone Transfer

Zone transfer refers to the transfer of zone's file or just the difference between two servers. Since a DNS failure usually has severe consequences for a company, the zone file is almost invariably kept identical on several name servers.

- Generally happens over TCP port 53.
- This procedure is abbreviated `Asynchronous Full Transfer Zone` (`AXFR`).

The slave fetches the `SOA` record of the relevant zone from the master at certain intervals, the so-called refresh time, usually one hour, and compares the serial numbers. If the serial number of the SOA record of the master is greater than that of the slave, the data sets no longer match.

<img src="/assets/ig_dns_zone_transfers_1.png">

Example of a domain that would let any entity to conduct a zone transfer:

```bash
$ dig axfr zonetransfer.me @nsztm1.digi.ninja

; <<>> DiG 9.20.15-2-Debian <<>> axfr zonetransfer.me @nsztm1.digi.ninja
;; global options: +cmd
zonetransfer.me.        7200    IN      SOA     nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
zonetransfer.me.        7200    IN      DNSKEY  256 3 7 AwEAAapoL+InQBYx2oi3dI424+dEDFgnVW0cOINfCY3jLrngZxBsEur8 ByhMOQsxoIOYu/7b3c8tj2BwlQquqxZe79QHSW78fK7D+bP/8AosnBG5 K5gJXEvphEtJ9x8/X0Y971XaW9lLmtJ6h4AXsrbgTr2g9KOiPSIbvDPM W8qLMaQkTm89hvPc+NuzrOEOPNhoXs/iPM+SQzrvTBfr6y0w2yPtYYdW I1kN76OQBxh0xjIdlyT0QKiohKq2bybPROJO7K3NlDc8oaOZoXH5/RfL DQzxzXyYSV8fLwimUeulo7YA11I/AHQ7DsUsFu2S2vxGCyR8nmx9gYbN 4sBvTF2i5eM=
zonetransfer.me.        301     IN      TXT     "google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
zonetransfer.me.        7200    IN      MX      0 ASPMX.L.GOOGLE.COM.
zonetransfer.me.        7200    IN      MX      10 ALT1.ASPMX.L.GOOGLE.COM.
zonetransfer.me.        7200    IN      MX      10 ALT2.ASPMX.L.GOOGLE.COM.
zonetransfer.me.        7200    IN      MX      20 ASPMX2.GOOGLEMAIL.COM.
zonetransfer.me.        7200    IN      MX      20 ASPMX3.GOOGLEMAIL.COM.
zonetransfer.me.        7200    IN      MX      20 ASPMX4.GOOGLEMAIL.COM.
zonetransfer.me.        7200    IN      MX      20 ASPMX5.GOOGLEMAIL.COM.
zonetransfer.me.        7200    IN      A       5.196.105.14
zonetransfer.me.        7200    IN      NS      nsztm1.digi.ninja.
zonetransfer.me.        7200    IN      NS      nsztm2.digi.ninja.
zonetransfer.me.        7200    IN      CERT    PKIX 0 0 MIIDvTCCAqUCFHh5BGzOrlYrXo5h90ipm0aDUEz9MA0GCSqGSIb3DQEB CwUAMIGaMQswCQYDVQQGEwJHQjEYMBYGA1UECAwPU291dGggWW9ya3No aXJlMRIwEAYDVQQHDAlTaGVmZmllbGQxEjAQBgNVBAoMCURpZ2luaW5q YTEQMA4GA1UECwwHSGFja2luZzEYMBYGA1UEAwwPem9uZXRyYW5zZmVy Lm1lMR0wGwYJKoZIhvcNAQkBFg56dG1AZGlnaS5uaW5qYTAeFw0yNTA3 MDIxMzU1MTNaFw0yNjA3MDIxMzU1MTNaMIGaMQswCQYDVQQGEwJHQjEY MBYGA1UECAwPU291dGggWW9ya3NoaXJlMRIwEAYDVQQHDAlTaGVmZmll bGQxEjAQBgNVBAoMCURpZ2luaW5qYTEQMA4GA1UECwwHSGFja2luZzEY MBYGA1UEAwwPem9uZXRyYW5zZmVyLm1lMR0wGwYJKoZIhvcNAQkBFg56 dG1AZGlnaS5uaW5qYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC ggEBALzYVM9WlBqOKU1lmnKJkKdIEZOhkscHQktEJORXCismSWV3Ffbs Lw7D3sfCc0h9ecZglsYvFUmEM0I0noYtuHPAlF2+FotVuoFrYuMYrEQo Zs4kuORIEx8pwHMZQUSM6KwVVLIB/FE956GfovgxGxWs33QaTKATAVCh D9KTLf6wVh/eC+0GI6mbvGvjqZFmmV/SYmmkdqEBWB7q3+SByfVrUohC A2GO30dwk6vUBtIj+J+i4SzKzLXIvFEfbCirMPQvdflgwPbjwp+cWG7o UBvfQZfZbaTp+9+V8FoBl0f8fGj/Mae1n0rSV5hnuXot8d3PAoAWQtW3 HJUv1nEboAMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAXop6ftpV2/r7 tkXqFCsMwub7ZBd12U14nsBon+X7K5Nr6obrVAtnWO+XwD8x2UgvYIQB uRLK9LOX6VYoiWMVrItIN8KRSsin5eJe4tzewsNGrVtkVbbKULViCeBt DgmImk8rkZeWU1uNOsq0t/wd3GUZe2CM9DpKVhPFhc9Uq3pYbAsidYlp SApuuj8ka3L+VruzJVwveyKTUkWAsN1iSv7BGgEF0039WW3IEv1ZP81c AdWFy1fx+tuteM6Iz5xkx1tp0/eLtb39cnKFQnrs8itDG2j3yBc3CClY mw4NNU2nODN4COt7uzXBez6iIFSNqQjVyFyomtPn4ae0cYRHEw==
zonetransfer.me.        300     IN      HINFO   "Casio fx-700G" "Windows XP"
_acme-challenge.zonetransfer.me. 301 IN TXT     "6Oa05hbUJ9xSsvYy7pApQvwCUSSGgxvrbdizjePEsZI"
_sip._tcp.zonetransfer.me. 14000 IN     SRV     0 0 5060 www.zonetransfer.me.
14.105.196.5.IN-ADDR.ARPA.zonetransfer.me. 7200 IN PTR www.zonetransfer.me.
asfdbauthdns.zonetransfer.me. 7900 IN   AFSDB   1 asfdbbox.zonetransfer.me.
asfdbbox.zonetransfer.me. 7200  IN      A       127.0.0.1
asfdbvolume.zonetransfer.me. 7800 IN    AFSDB   1 asfdbbox.zonetransfer.me.
canberra-office.zonetransfer.me. 7200 IN A      202.14.81.230
cmdexec.zonetransfer.me. 300    IN      TXT     "; ls"
contact.zonetransfer.me. 2592000 IN     TXT     "Remember to call or email Pippa on +44 123 4567890 or pippa@zonetransfer.me when making DNS changes"
dc-office.zonetransfer.me. 7200 IN      A       143.228.181.132
deadbeef.zonetransfer.me. 7201  IN      AAAA    dead:beaf::
dr.zonetransfer.me.     300     IN      LOC     53 20 56.558 N 1 38 33.526 W 0.00m 1m 10000m 10m
DZC.zonetransfer.me.    7200    IN      TXT     "AbCdEfG"
email.zonetransfer.me.  2222    IN      NAPTR   1 1 "P" "E2U+email" "" email.zonetransfer.me.zonetransfer.me.
email.zonetransfer.me.  7200    IN      A       74.125.206.26
Hello.zonetransfer.me.  7200    IN      TXT     "Hi to Josh and all his class"
home.zonetransfer.me.   7200    IN      A       127.0.0.1
Info.zonetransfer.me.   7200    IN      TXT     "ZoneTransfer.me service provided by Robin Wood - robin@digi.ninja. See http://digi.ninja/projects/zonetransferme.php for more information."
internal.zonetransfer.me. 300   IN      NS      intns1.zonetransfer.me.
internal.zonetransfer.me. 300   IN      NS      intns2.zonetransfer.me.
intns1.zonetransfer.me. 300     IN      A       81.4.108.41
intns2.zonetransfer.me. 300     IN      A       5.196.105.10
office.zonetransfer.me. 7200    IN      A       4.23.39.254
ipv6actnow.org.zonetransfer.me. 7200 IN AAAA    2001:67c:2e8:11::c100:1332
owa.zonetransfer.me.    7200    IN      A       207.46.197.32
robinwood.zonetransfer.me. 302  IN      TXT     "Robin Wood"
rp.zonetransfer.me.     321     IN      RP      robin.zonetransfer.me. robinwood.zonetransfer.me.
sip.zonetransfer.me.    3333    IN      NAPTR   2 3 "P" "E2U+sip" "!^.*$!sip:customer-service@zonetransfer.me!" .
sqli.zonetransfer.me.   300     IN      TXT     "' or 1=1 --"
sshock.zonetransfer.me. 7200    IN      TXT     "() { :]}; echo ShellShocked"
staging.zonetransfer.me. 7200   IN      CNAME   www.sydneyoperahouse.com.
alltcpportsopen.firewall.test.zonetransfer.me. 301 IN A 127.0.0.1
testing.zonetransfer.me. 301    IN      CNAME   www.zonetransfer.me.
vpn.zonetransfer.me.    4000    IN      A       174.36.59.154
www.zonetransfer.me.    7200    IN      A       5.196.105.14
xss.zonetransfer.me.    300     IN      TXT     "'><script>alert('Boo')</script>"
zonetransfer.me.        7200    IN      SOA     nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
;; Query time: 111 msec
;; SERVER: 81.4.108.41#53(nsztm1.digi.ninja) (TCP)
;; WHEN: Wed Dec 10 18:14:42 EET 2025
;; XFR size: 52 records (messages 1, bytes 3339)

```
