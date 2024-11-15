### Content
* [[#Overview]]
* [[#Local file inclusion]]
	* Path Traversal
	* Second-Order Attacks
* [[#Bypasses Techniques]]
	* Non-Recursive Path Traversal Filters
	* Encoding
	* Approved Paths
	* Appended Extension
	* Filename Prefix
* [[#PHP Filters]]
	* [[#Scenarios]]
		* Reading PHP files with convert filter
* [[#Examples of Vulnerable Code and FI Functions]]
---
## Overview
- **Types of File Inclusion**:
    - **Local File Inclusion (LFI)**: An attacker includes files from the local file system by manipulating paths.
    - **Remote File Inclusion (RFI)**: An attacker includes files from an external server by supplying a remote URL.
- **Cause**: File inclusion vulnerabilities occur when an application dynamically loads files based on user input without properly validating or sanitizing the file paths. If user input is passed directly to a function that includes files (e.g., `include` in PHP), attackers can control which files are included.
- **Exploitation**:
    - **LFI**: Attackers can manipulate file paths (e.g., using `../../etc/passwd`) to access sensitive system files. If the application is vulnerable to LFI, attackers may also try to execute code by including files that they upload or injecting code into log files that can be loaded.
    - **RFI**: By supplying a URL as the file path, attackers can make the server download and execute files from an external source, allowing remote code execution. RFI is often restricted in modern environments, but it remains a risk if URL-based includes are allowed.
- **Impact**:
    - Sensitive Data Disclosure
    - Remote Code Execution (RCE)
    - Privilege Escalation
- **Prevention**:
    - **Input Validation**: Strictly validate and sanitize file paths. Allow only predefined file paths or filenames, and avoid processing user input directly.
    - **Disable URL Includes**: Ensure that `allow_url_include` (for PHP) or similar settings are disabled to prevent RFI.
    - **Use Absolute Paths**: Instead of allowing user-defined paths, use predefined, absolute paths within the application’s scope.
---
## Local file inclusion
If we were not sure of the directory the web application is in, we can add `../` many times.
- **Common readable files** that are available on most back-end servers:
	- `Windows`: `C:\Windows\boot.ini`
	- `Linux`: `/etc/passwd`
- The main directory of web applications on Linux servers is `/var/www/html/`.
- **Second-Order Attacks**
	- If a web application allow the user to download his avatar through `/profile/$username/avatar.png`, If we crafted a malicious username `../../../etc/passwd`.
	- If the web application didn't sanitize or filter our username, It will be possible to pull another local file from the system rather the user avatar.
---
> [!NOTE]
> Try to combine many techniques together because Some web applications may apply many filters together. 
## Bypasses Techniques
- **Non-Recursive Path Traversal Filters**
	- If the `../` substring is being replaced from user input. payloads:
		- `....//` , `..././` , `....\/` , `....////`
- **Encoding**
	- If the target didn't allow `.` and `/` characters as input
		- It's a must  to URL encode all characters, including the dots. `../etc/passwd`: `%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64`
		- Try to encode the encoded string once again to have a `double encoded` string, which may also bypass other types of filters.
- **Approved Paths**
	- Some web applications may also use Regular Expressions to ensure that the file being included is under a specific path.
		1. Fuzz web directories under the same path until we an approved path.
		2. Start our payload with the approved path, then use `../` to go back to the root.
- **Appended Extension**
	- If the web applications append an extension to our input string (e.g. `.php`).
	- Cannot be bypassed on modern versions of PHP but can be useful to read the source code.
	- Techniques that only works with `PHP versions before 5.3/5.4`:
		1. **Path Truncation**
			- Earlier versions of PHP has a limit of 4096 characters, If a longer string passed, it will be truncated.
			- PHP removes the trailing `/.` : `/etc/passwd/.` -> `/etc/passwd`
			- PHP and Linux disregard multiple `/` : `////etc/passwd` -> `/etc/passwd`
			- Also disregard the current directory shortcut `.` : `/etc/./passwd` -> `/etc/passwd`
			- We have to `start the path with a non-existing directory` for this technique to work.
				``` bash
				echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
				```
		2. **Null Bytes**
			- PHP versions before 5.5 were vulnerable to `null byte injection`
			- Adding a null byte (`%00`) at the end of the string would terminate the string and not consider anything after it.
			- Sending `/etc/passwd%00` would be `/etc/passwd%00.php` but the path used would actually be `/etc/passwd`
- **Filename Prefix**
	- If the web app takes an input `file` and appends `lang_` to it, resulting in `lang_../../../etc/passwd` which will be invalid path.
		- Add `/` at the beginning of the path, `lang_/../../../etc/passwd`, the leading `/` might reset the path to root.
---
## PHP Filters
- [PHP Wrappers](https://www.php.net/manual/en/wrappers.php.php) allow us to access different I/O streams at the application level, like standard input/output, file descriptors, and memory streams.
- There are 4 types of filters: [String Filters](https://www.php.net/manual/en/filters.string.php), [Conversion Filters](https://www.php.net/manual/en/filters.convert.php), [Compression Filters](https://www.php.net/manual/en/filters.compression.php), and [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php).
- To use PHP wrapper streams, we can use the `php://` scheme in our string and access the PHP filter wrapper with `php://filter/`.
- The main parameters for filter wrapper are `resource` and `read`.
	- `resource` With it we can specify the stream we would like to apply our filter on (e.g. local file).
	- `read` With it we can apply different filters on the input resource.
	- The important filter for FI is `convert.base64-encode` filter, under `Conversion Filters`.
###  Scenarios
- **If we have a LFI and the site using appended extension to the user input and we want to read the local PHP files**:
	1. Fuzzing to find PHP files.
	   We are not restricted to pages with HTTP response code `200`, as we have local file inclusion access, so we should be scanning for all codes, including `301`, `302` and `403` pages, and we should be able to read their source code as well.
		``` bash
		ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
		configure               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 69ms]
		```
	2.  We should use the payload `configure`: `www.example.com/index.php?lang=configure`
		1. If the web app uses a that executes the content of the file, it won't show the file content.
		2. Using PHP wrapper with convert filter to encode the content of the file so it doesn't get executed
		   `www.example.com/index.php?lang=php://filter/read=convert.base64-encode/resource=config`
		3. Decode the output
			``` bash
			echo 'PD9waHAK...SNIP...KICB9Ciov' | base64 -d
			```
---
## Examples of Vulnerable Code and FI Functions
The following code snippets show if a site taking a `GET` parameter `?language=en` directly from a user without sanitization or filtration :
- `PHP`, we may use these functions to load a local or a remote file as we load a page:
	* `include()`
	* `inculde_once()`
	* `require()`
	* `require_once()`
	* `file_get_contents()`
		``` PHP
		if (isset($_GET['language'])) { include($_GET['language']); }
		```
- `NodeJS`
	- `readFile()`: `NodeJS`
	- `render()`: `Express.js`
		``` JS
		// NodeJS
		if(req.query.language) {
		    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
		        res.write(data);
		    });
		}
		// Express.js
		app.get("/about/:language", function(req, res) {
		    res.render(`/${req.params.language}/about.html`);
		});
		```
- `Java`: `Java Server Pages (JSP)`
	- `include()`
	- `import()`
		``` java
		// Include local files based on the specified parameter
		<c:if test="${not empty param.language}">
			<jsp:include file="<%= request.getParameter('language') %>" />
		</c:if>
		// The `import` function may also be used to render a local file or a URL
		<c:import url= "<%= request.getParameter('language') %>"/>
		```
- `.NET`
	- `Response.WriteFile()`
	- `@Html.Partial()`
	- `include`
		``` CS
		// Takes a file path for its input and writes its content to the response
		@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
		    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> }
		// Render the specified file as part of the front-end template
		@Html.Partial(HttpContext.Request.Query['language'])
		// Render local files or remote URLs
		<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
		```

The following table shows which functions may execute files and which only read file content:
#read_write_functions

| **Function**                 | **Read Content** | **Execute** | **Remote URL** |
| ---------------------------- | :--------------: | :---------: | :------------: |
| **PHP**                      |                  |             |                |
| `include()`/`include_once()` |        ✅         |      ✅      |       ✅        |
| `require()`/`require_once()` |        ✅         |      ✅      |       ❌        |
| `file_get_contents()`        |        ✅         |      ❌      |       ✅        |
| `fopen()`/`file()`           |        ✅         |      ❌      |       ❌        |
| **NodeJS**                   |                  |             |                |
| `fs.readFile()`              |        ✅         |      ❌      |       ❌        |
| `fs.sendFile()`              |        ✅         |      ❌      |       ❌        |
| `res.render()`               |        ✅         |      ✅      |       ❌        |
| **Java**                     |                  |             |                |
| `include`                    |        ✅         |      ❌      |       ❌        |
| `import`                     |        ✅         |      ✅      |       ✅        |
| **.NET**                     |                  |             |                |
| `@Html.Partial()`            |        ✅         |      ❌      |       ❌        |
| `@Html.RemotePartial()`      |        ✅         |      ❌      |       ✅        |
| `Response.WriteFile()`       |        ✅         |      ❌      |       ❌        |
| `include`                    |        ✅         |      ✅      |       ✅        |

---