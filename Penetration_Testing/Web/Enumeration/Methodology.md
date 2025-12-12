### Content

- [Active Reconnaissance](#active-reconnaissance)
- [Passive Reconnaissance](#passive-reconnaissance)

> [!Note]
> Our main goals through this process:
> - Identifying assets (publicly accessible)
> - Discovering hidden assets (Inadvertently exposed)
> - Analyzing the attack surface (identify possible vulnerabilities)
> - OSIT (Further exploitations and social engineering attacks)

---
## Active Reconnaissance

Direct interaction with the web application.

- Port Scanning
- Vulnerability Scanning
- Network Mapping 
- Banner Grabbing
- OS Fingerprint
- Service Enumeration
- Web Spidering

---
## Passive Reconnaissance

Non-direct interaction with the web application.

- Search Engines Queries
- `WHOIS` Lookup
	- Identifying key personnel for further activities
	- Clues about the infrastructure
	- [WhoisFreaks](https://whoisfreaks.com/) has historical `whois` data
- DNS 
  `dnsx`, `dig`, `nslookup`, `host`, `dnsenum`, `fierce`, `dnsrecon`, `theHarvester`, `Online DNS Lookup Services`
- Web Archive Analysis [Internet Archive's Wayback Machine](https://web.archive.org/)
- Social Media Analysis
- Code Review

---
### Automation

- [FinalRecon](https://github.com/thewhiteh4t/FinalRecon)
- [Recon-ng](https://github.com/lanmaster53/recon-ng)
- [theHarvester](https://github.com/laramies/theHarvester)
- [SpiderFoot](https://github.com/smicallef/spiderfoot)
- [OSINT Framework](https://osintframework.com/)

---