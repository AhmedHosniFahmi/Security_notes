### Content

- [Key Elements](#key-elements)
- [XML DTD](#xml-dtd)
	- [DTD Declaration](#dtd-declaration)
		- [Internal DTD Declaration](#internal-dtd-declaration)
		- [External DTD Declaration](#external-dtd-declaration)
	- [DTD Entities](#dtd-entities)
		- [Internal Entity Declaration](#internal-entity-declaration)
		- [External Entity Declaration](#external-entity-declaration)

---

- **Extensible Markup Language (XML)** designed for flexible transfer and storage of data and documents in various types of applications.
- XML documents are formed of element trees, where each element is essentially denoted by a `tag`, and the first element is called the `root element`, while other elements are `child elements`.

```XML
<?xml version="1.0" encoding="UTF-8"?>
<email>
	<date>01-01-2022</date>
	<time>10:00 am UTC</time>
	<sender>john@corp.com</sender>
	<recipients>
		<to>HR@corp.com</to>
		<cc>
			<to>billing@corp.com</to>
			<to>payslips@corp.com</to>
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

### Key Elements

| Key           | Example                                  | Definition                                                                                                    |
| ------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `Tag`         | `<date>`                                 | The keys of an XML document, usually wrapped with (`<`/`>`) characters.                                       |
| `Entity`      | `&lt;`                                   | XML variables, usually wrapped with (`&`/`;`) characters.                                                     |
| `Element`     | `<date>01-01-2022</date>`                | The root element or any of its child elements, and its value is stored in between a start-tag and an end-tag. |
| `Attribute`   | `version="1.0"`/`encoding="UTF-8"`       | Optional specifications for any element that are stored in the tags, which may be used by the XML parser.     |
| `Declaration` | `<?xml version="1.0" encoding="UTF-8"?>` | Usually the first line of an XML document, and defines the XML version and encoding to use when parsing it.   |

`<`, `>`, `&`, or `"` characters are used as part of an XML document structure, To use them in the XML document, replace them with their HTML encoded version `&lt;`, `&gt;`, `&amp;`, `&quot;`

---
### XML DTD

A **XML Document Type Definition (DTD)** defines the structure and the legal elements and attributes of an XML document.

An XML document with correct syntax is called "Well Formed".
An XML document validated against a DTD is both "Well Formed" and "Valid".

DTD email example:

``` XML
<!DOCTYPE note [
<!ELEMENT note (to,from,heading,body)>
<!ELEMENT to (#PCDATA)>
<!ELEMENT from (#PCDATA)>
<!ELEMENT heading (#PCDATA)>
<!ELEMENT body (#PCDATA)>
]>
```

> [!Important]
> 
> **PCDATA**: (parseable character data)
> 
> - WILL be parsed by a parser. 
> - Tags inside the text will be treated as markup and entities will be expanded.
> - Any &, <, or > characters need to be represented by `&amp;` `&lt;` and `&gt;` entities, respectively.
> 
> **CDATA**: (character data)
> 
> - will NOT be parsed by a parser.
> - Tags inside the text will NOT be treated as markup and entities will not be expanded.

The DTD above is interpreted like this:

- `!DOCTYPE` note -  Defines that the root element of the document is note
- `!ELEMENT` note - Defines that the note element must contain the elements: `to`, `from`, `heading`, `body`
- `!ELEMENT` to - Defines the to element to be of type `#PCDATA`
- `!ELEMENT` from - Defines the from element to be of type `#PCDATA`
- `!ELEMENT` heading  - Defines the heading element to be of type `#PCDATA`
- `!ELEMENT` body - Defines the body element to be of type `#PCDATA`

#### DTD Declaration
##### Internal DTD Declaration

```XML
<?xml version="1.0"?>
<!DOCTYPE note [
	<!ELEMENT note (to,from,heading,body)>
	<!ELEMENT to (#PCDATA)>
	<!ELEMENT from (#PCDATA)>
	<!ELEMENT heading (#PCDATA)>
	<!ELEMENT body (#PCDATA)>
]>
<note>
<to>Tove</to>
<from>Jani</from>
<heading>Reminder</heading>
<body>Don't forget me this weekend</body>
</note> 
```

##### External DTD Declaration

``` XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note SYSTEM "Note.dtd">
<note>
<to>Tove</to>
<from>Jani</from>
<heading>Reminder</heading>
<body>Don't forget me this weekend!</body>
</note> 
```

And here is the file "note.dtd", which contains the DTD:

```XML
<!ELEMENT note (to,from,heading,body)>
<!ELEMENT to (#PCDATA)>
<!ELEMENT from (#PCDATA)>
<!ELEMENT heading (#PCDATA)>
<!ELEMENT body (#PCDATA)> 
```

It is also possible to reference a DTD through a URL

``` XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note SYSTEM "http://corp.com/note.dtd">
<note>
<to>Tove</to>
<from>Jani</from>
<heading>Reminder</heading>
<body>Don't forget me this weekend!</body>
</note> 
```

#### DTD Entities
##### Internal Entity Declaration

```XML
DTD Example:

<!ENTITY writer "Donald Duck.">
<!ENTITY copyright "Copyright W3Schools.">

XML example:

<author>&writer;&copyright;</author>
```

##### External Entity Declaration

```XML
DTD Example:

<!ENTITY writer SYSTEM "https://www.w3schools.com/entities.dtd">
<!ENTITY copyright SYSTEM "https://www.w3schools.com/entities.dtd">

XML example:

<author>&writer;&copyright;</author>
```

> We may also use the `PUBLIC` keyword instead of `SYSTEM` for loading external resources, which is used with publicly declared entities and standards, such as a language code (`lang="en"`).


