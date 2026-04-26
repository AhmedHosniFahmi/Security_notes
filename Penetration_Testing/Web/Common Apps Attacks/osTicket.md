### Content

- [Overview](#overview)
- [Enumeration](#enumeration)
- [Attacks](#attacks)

---
### Overview

- [osTicket](https://osticket.com) is an open-source support ticketing system.
- Can be compared to systems such as Jira, OTRS, Request Tracker, and Spiceworks.
- Can integrate user inquiries from email, phone, and web-based forms into a web interface.
- Written in PHP and uses a MySQL backend.
- Can be installed on Windows or Linux.

Here we can break down the main functions into the layers: `User Input`, `Processing`, `Solution`

##### User Input

The core function of `osTicket` is to inform the company's employees about a problem so that a problem can be solved with the service or other components. From the `osTicket` [documentation](https://docs.osticket.com/en/latest/Getting%20Started/Post-Installation.html), we can see that only staff and users with administrator privileges can access the admin panel. So if our target company uses this or a similar application, we can cause a problem and "play dumb" and contact the company's staff. The simulated "lack of" knowledge about the services offered by the company in combination with a technical problem is a widespread social engineering approach to get more information from the company.

##### Processing

As staff or administrators, they try to reproduce significant errors to find the core of the problem. Processing is finally done internally in an isolated environment that will have very similar settings to the systems in production. Suppose staff and administrators suspect that there is an internal bug that may be affecting the business. In that case, they will go into more detail to uncover possible code errors and address more significant issues.

##### Solution

Depending on the depth of the problem, it is very likely that other staff members from the technical departments will be involve d in the email correspondence. This will give us new email addresses to use against the `osTicket` admin panel (in the worst case) and potential usernames with which we can perform OSINT on or try to apply to other company services.

---
### Enumeration

- Cookie named `OSTSESSID` gets set when visiting any page of the application.
- Most osTicket installs will showcase the osTicket logo with the phrase `powered by` in front of it in the page's footer. The footer may also contain the words `Support Ticket System`.
- Nmap scan will just show information about the webserver, such as Apache or IIS, and will not help footprint the application.

---
### Attacks

- Try to brute force the agents endpoint: `http://FQDN/scp/login.php`
- Try to create a ticker in the endpoint `http://FQDN/index.php` which will generate an email, try to abuse it in different ways.

