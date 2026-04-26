### Content

- [Overview](#overview)
- [Enumeration](#enumeration)
- [Attacks](#attacks)
	- [RCE](#rce)

---
### Overview

- Agentless network monitor software. 
- Used to monitor bandwidth usage, uptime and collect statistics from various hosts, including routers, switches, servers, and more.
- It works with an `autodiscovery` mode to scan areas of a network and create a device list.
	- Once this list is created, it can gather further information from the detected devices using protocols such as ICMP, SNMP, WMI, NetFlow, and more.
- Devices can also communicate with the tool via a REST API.
- The software runs entirely from an AJAX-based website.
- There is a desktop application available for Windows, Linux, and macOS.

---
### Enumeration

```bash
# can typically be found on common web ports such as 80, 443, or 8080.
sudo nmap -sV -p- --open -T4 10.129.201.50
[SNIP]
8080/tcp  open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
[SNIP]

# Getting the version
curl -s http://10.129.201.50:8080/index.htm | grep version
```

---
### Attacks
#### RCE

- To begin, mouse over `Setup` in the top right and then the `Account Settings` menu and finally click on `Notifications`.
- Next, click on `Add new notification`.
- Give the notification a name and scroll down and tick the box next to `EXECUTE PROGRAM`.
- Under `Program File`, select `Demo exe notification - outfile.ps1`
- In the parameter field, enter a command. ex: `file.txt; <COMMAND>`
- After clicking Save, we will be redirected to the Notifications page.
- Click on the notification and click the `Test` button to run our notification and execute the command.




