### Content

- [Miscellaneous](#miscellaneous)
- [Enumerating DNS Records](#enumerating-dns-records)
- [Enumerating Subdomains](#enumerating-subdomains)
	- [Active subdomain Enum](#active-subdomain-enum)
		- [Zone Transfer](#zone-transfer)
		- [Brute Force Enumeration](#brute-force-enumeration)
	- [Passive Subdomain Enum](#passive-subdomain-enum)
- [Virtual Hosts](#virtual-hosts)
- [Dorking](#dorking)

---
### Miscellaneous 

> Check  `/robots.txt` and `./well-known/`

```bash
# Banner Grabbing (Add -L to follow redirections)
$ curl -I inlanefreight.com 

# Checking the WAF solution in front of the application
$ wafw00f inlanefreight.com

# nikto can reveal the website technology stack
$ nikto -h https://www.inlanefreight.com -Tuning b

# Crawling
$ python3 ReconSpider.py https://inlanefreight.com

# Automate the whole process,,,, use the flag --full, but watchout :}
$ finalrecon --headers --whois --url http://inlanefreight.com
```

---
### Enumerating DNS Records

```bash
# Performs a specific record lookup for the domain.
$ dig domain.com [A, AAAA, MX, NS, TXT, CNAME, SOA]

# Specifies a specific name server to query; in this case 1.1.1.1
$ dig @1.1.1.1 domain.com

# Shows the full path of DNS resolution.
$ dig +trace domain.com

# Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name.
# You may need to specify a name server.
$ dig -x 192.168.1.1

# Provides a short, concise answer to the query.
$ dig +short domain.com

# Retrieves all available DNS records for the domain
$ dig domain.com ANY
```

> Many DNS servers ignore `ANY` queries to reduce load and prevent abuse.

---
### Enumerating Subdomains

- Subdomains are represented by `A` (or `AAAA` for IPv6) records, which map the subdomain name to its corresponding IP address.
- `CNAME` records might be used to create aliases for subdomains, pointing them to other domains or subdomains.

#### Active subdomain Enum

##### Zone Transfer

Misconfigured server might inadvertently leak a complete list of subdomains.

```bash
$ dig axfr example.com @10.129.14.128
$ dig axfr @ns1.server.com example.com
```

Administrators often use broader `allow-transfer` ACLs internally, assuming the internal network is fully trusted. If misconfigured, **any host on the internal subnet** can retrieve internal DNS data.

```bash
$ dig axfr subdomain.example.com @10.129.14.128
```

##### Brute Force Enumeration

``` bash
# add the IP to /etc/hosts  
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/ -fs 900 -t 200 -v

# Match HTTP status codes, or "all" for everything. (default: 200-299,301,302,307,401,403,405,500)
ffuf  -v -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.thetoppers.htb/  --mc all


# Using dnsenum
$ dnsenum --enum inlanefreight.com -f  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Using subfinder
$ subfinder -d inlanefreight.com -v
```

### Passive Subdomain Enum

1. Certificate Transparency (CT) logs and public repositories of SSL/TLS certificates include a list of associated subdomains in their Subject Alternative Name (SAN) field.
2. Search Engines Dorking. (filter results to show only subdomains related to the target domain.)

```bash
# crt.sh lookup

$ curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
*.dev.facebook.com
dev.facebook.com
devvm1958.ftw3.facebook.com
...
```

---
### Virtual Hosts

```bash
$ gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain -t 200 -k 

$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```

---
### Dorking

> [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)

| Operator                | Example                                             | Example Description                                                                     |
| :---------------------- | :-------------------------------------------------- | :-------------------------------------------------------------------------------------- |
| `site:`                 | `site:example.com`                                  | Find all publicly accessible pages on example.com.                                      |
| `inurl:`                | `inurl:login`                                       | Search for login pages on any website.                                                  |
| `filetype:`             | `filetype:pdf`                                      | Find downloadable PDF documents.                                                        |
| `intitle:`              | `intitle:"confidential report"`                     | Look for documents titled "confidential report" or similar variations.                  |
| `intext:` or `inbody:`  | `intext:"password reset"`                           | Identify webpages containing the term “password reset”.                                 |
| `cache:`                | `cache:example.com`                                 | View the cached version of example.com to see its previous content.                     |
| `link:`                 | `link:example.com`                                  | Identify websites linking to example.com.                                               |
| `related:`              | `related:example.com`                               | Discover websites similar to example.com.                                               |
| `info:`                 | `info:example.com`                                  | Get basic details about example.com, such as its title and description.                 |
| `define:`               | `define:phishing`                                   | Get a definition of "phishing" from various sources.                                    |
| `numrange:`             | `site:example.com numrange:1000-2000`               | Find pages on example.com containing numbers between 1000 and 2000.                     |
| `allintext:`            | `allintext:admin password reset`                    | Search for pages containing both "admin" and "password reset" in the body text.         |
| `allinurl:`             | `allinurl:admin panel`                              | Look for pages with "admin" and "panel" in the URL.                                     |
| `allintitle:`           | `allintitle:confidential report 2023`               | Search for pages with "confidential," "report," and "2023" in the title.                |
| `AND`                   | `site:example.com AND (inurl:admin OR inurl:login)` | Find admin or login pages specifically on example.com.                                  |
| `OR`                    | `"linux" OR "ubuntu" OR "debian"`                   | Search for webpages mentioning Linux, Ubuntu, or Debian.                                |
| `NOT`                   | `site:bank.com NOT inurl:login`                     | Find pages on bank.com excluding login pages.                                           |
| `*` (wildcard)          | `site:socialnetwork.com filetype:pdf user* manual`  | Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com. |
| `..` (range search)     | `site:ecommerce.com "price" 100..500`               | Look for products priced between 100 and 500 on an e-commerce website.                  |
| `" "` (quotation marks) | `"information security policy"`                     | Find documents mentioning the exact phrase "information security policy".               |
| `-` (minus sign)        | `site:news.com -inurl:sports`                       | Search for news articles on news.com excluding sports-related content.                  |

More examples:

- Finding Login Pages:
    - `site:example.com inurl:login`
    - `site:example.com (inurl:login OR inurl:admin)`
- Identifying Exposed Files:
    - `site:example.com filetype:pdf`
    - `site:example.com (filetype:xls OR filetype:docx)`
- Uncovering Configuration Files:
    - `site:example.com inurl:config.php`
    - `site:example.com (ext:conf OR ext:cnf)` (searches for extensions commonly used for configuration files)
- Locating Database Backups:
    - `site:example.com inurl:backup`
    - `site:example.com filetype:sql`