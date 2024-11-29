### Content
* What is XML
* XML DTD
* XML Entities
	* General Entities
	* Parameter Entities
---
## What is XML
 `Extensible Markup Language (XML)` designed for flexible transfer and storage of data and documents in various types of applications.
 Example of an XML:
 ``` XML
 <?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```
key elements of an XML document:

| Key           | Example                                  | Definition                                                                                                    |
| ------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `Tag`         | `<date>`                                 | The keys of an XML document, usually wrapped with (`<`/`>`) characters.                                       |
| `Entity`      | `&lt;`                                   | XML variables, usually wrapped with (`&`/`;`) characters.                                                     |
| `Element`     | `<date>01-01-2022</date>`                | The root element or any of its child elements, and its value is stored in between a start-tag and an end-tag. |
| `Attribute`   | `version="1.0"`/`encoding="UTF-8"`       | Optional specifications for any element that are stored in the tags, which may be used by the XML parser.     |
| `Declaration` | `<?xml version="1.0" encoding="UTF-8"?>` | Usually the first line of an XML document, and defines the XML version and encoding to use when parsing it.   |

- `<`, `>`, `&`, or `"` characters are used as part of an XML document structure, To use them in the XML document, replace them with `&lt;`, `&gt;`, `&amp;`, `&quot;`


---
## XML DTD
* `XML Document Type Definition (DTD)` allows the validation of an XML document against a pre-defined document structure.
* DTD place:
	* Can be defined in the document itself right after the `XML Declaration` in the first line
	* Can be defined in an external file (e.g. `email.dtd`) and then referenced within the XML document with the `SYSTEM` keyword
		``` XML
		<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE email SYSTEM "email.dtd">
		```
	* It is also possible to reference a DTD through a URL
		``` XML
		<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
		```

Example:
``` DTD
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```
---
## XML Entities
### General Entities
* Defining custom entity by using `ENTITY` keyword followed by the entity name and its value
* Defined entity can be referenced in an XML document `&ENTITY_NAME;`
``` XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [<!ENTITY newEntity "k1ng0a21r">] >
<root>
	<name>a</name>
	<tel>1</tel>
	<email>&email;</email>
	<message>123</message>
</root>
```
* `reference External XML Entities` with the `SYSTEM` keyword, which is followed by the external entity's path
``` XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```
`PUBLIC` keyword can be used instead of `SYSTEM` for loading external resources, which is used with publicly declared entities and standards, such as a language code (`lang="en"`).
### Parameter Entities
* Parameter entities are only available in the DTD, not in the XML document’s content.
* A parameter entity is declared with the `<!ENTITY % name "value">` syntax. `%` used to distinguish parameter entities from general entities.