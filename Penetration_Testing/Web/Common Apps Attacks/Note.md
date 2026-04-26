### Content

- [Discovery Structure](#discovery-structure)
- [eyewitness](#eyewitness)
- [Aquatone](#aquatone)

---
## Discovery Structure

Discovery phase structure may look like: 
`External Penetration Test - <Client Name>`

- `Scope` (including in-scope IP addresses/ranges, URLs, any fragile hosts, testing timeframes, and any limitations or other relative information we need handy)
- `Client Points of Contact`
- `Credentials`
- `Discovery/Enumeration`
    - `Scans`
    - `Live hosts`
- `Application Discovery`
    - `Scans`
    - `Interesting/Notable Hosts`
- `Exploitation`
    - `<Hostname or IP>`
    - `<Hostname or IP>`
- `Post-Exploitation`
    - `<Hostname or IP>`
    - `<Hostname or IP>`

[EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) and [Aquatone](https://github.com/michenriksen/aquatone) can be fed raw Nmap XML scan output (Aquatone can also take Masscan XML; EyeWitness can take Nessus XML output) and be used to quickly inspect all hosts running web applications and take screenshots of each. The screenshots are then assembled into a report that we can work through in the web browser to assess the web attack surface.

---

let's say we have the scope

```bash
$ cat scope_list 

app.inlanefreight.local
dev.inlanefreight.local
drupal-dev.inlanefreight.local
drupal-qa.inlanefreight.local
drupal-acc.inlanefreight.local
drupal.inlanefreight.local
blog.inlanefreight.local
10.129.166.160
```

Nmap scanning

```bash
$ sudo nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list 

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-18 09:47 CST
Nmap scan report for app.inlanefreight.local (10.129.166.160)
Host is up (0.34s latency).
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for dev.inlanefreight.local (10.129.166.160)
Host is up (0.042s latency).
rDNS record for 10.129.166.160: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for drupal-dev.inlanefreight.local (10.129.166.160)
Host is up (0.042s latency).
rDNS record for 10.129.166.160: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for drupal-qa.inlanefreight.local (10.129.166.160)
Host is up (0.043s latency).
rDNS record for 10.129.166.160: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for drupal-acc.inlanefreight.local (10.129.166.160)
Host is up (0.043s latency).
rDNS record for 10.129.166.160: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for drupal.inlanefreight.local (10.129.166.160)
Host is up (0.043s latency).
rDNS record for 10.129.166.160: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for blog.inlanefreight.local (10.129.166.160)
Host is up (0.042s latency).
rDNS record for 10.129.166.160: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for app.inlanefreight.local (10.129.166.160)
Host is up (0.042s latency).
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
```

## eyewitness

```bash
$ eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```

Inside the `inlanefreight_eyewitness` directory, open the `report.html`

---
## Aquatone

```bash
$ wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip

$ unzip aquatone_linux_amd64_1.7.0.zip

$ cat web_discovery.xml | ./aquatone -nmap

# Open aquatone_report.html
```