### Content

- [Minifying](#minifying)
- [Packing](#packing)
- [Advanced Obfuscation](#advanced-obfuscation)
- [Deobfuscation](#deobfuscation)
- [Decoding](#decoding)
	- [Base64](#base64)
	- [Hex](#hex)
	- [Caesar/Rot13](#caesar/rot13)

> [JSConsole](https://jsconsole.com) JS online console

---
### Minifying 

Code minification means having the entire code in a single line.
The minified JS file often named `file.min.js`  

> [javascript-minifier](https://javascript-minifier.com/)

---
### Packing

A packer obfuscation tool usually attempts to convert all words and symbols of the code into a list or a dictionary and then refer to them using the `(p,a,c,k,e,d)` function to re-build the original code during execution.
The `(p,a,c,k,e,d)` can be different from one packer to another. However, it usually contains a certain order in which the words and symbols of the original code were packed to know how to order them during execution.

> [BeautifyTools](http://beautifytools.com/javascript-obfuscator.php)

---
### Advanced Obfuscation

> [obfuscator](https://obfuscator.io/)
> [JSF](http://www.jsfuck.com)
> [JJ Encode](https://utf-8.jp/public/jjencode.html)
> [AA Encode](https://utf-8.jp/public/aaencode.html)

---
### Deobfuscation

For minified JS code:

> [Prettier](https://prettier.io/playground/)
> [Beautifier](https://beautifier.io/)

For packed JS code:

> [UnPacker](https://matthewfl.com/unPacker.html)

---
### Decoding

Identify encoded strings:

> [Cipher Identifier](https://www.boxentriq.com/code-breaking/cipher-identifier), [Identifier](https://www.dcode.fr/cipher-identifier)
#### Base64

`base64` encoding is usually used to reduce the use of special characters, as any characters encoded in `base64` would be represented in alpha-numeric characters, in addition to `+` and `/` only.

Spot Base64:

- Only alpha-numeric character in addition to `+` and `/`
- Padding in `0`
- The length should be in a multiple of 4

encode:

```bash
$ echo http://website.com | base64
```

decode:

```
$ echo <Encoded> | base64 -d
```
 
#### Hex

find the full ascii table `$ man ascii`

encode:

```bash
$ echo https://website.com | xxd -p
```

decode

```bash
echo <HEX> | xxd -p -r 
```

#### Caesar/Rot13

> [rot13](https://rot13.com/)

Shifting each letter by a fixed number.
The most common of which is `rot13`, which shifts each character 13 times forward.

Spot Caesar cipher:

- each character is mapped to a specific character: `http://www` becomes `uggc://jjj`

Rot13 encode

```bash
$ echo http://website.com | tr 'A-Za-z' 'N-ZA-Mn-za-m'
uggc://jrofvgr.pbz
```

Rot13 decode

```bash
$ echo uggc://jrofvgr.pbz | tr 'A-Za-z' 'N-ZA-Mn-za-m'
http://website.com
```

---