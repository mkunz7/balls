<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Codex-native BALLS workflow and evidence rules. -->

# Injection Vulnerability Detection Skill

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

Injection vulnerabilities occur when untrusted data is sent to an interpreter as part of a command or query, allowing an attacker to alter the intended execution. The attacker's hostile data tricks the interpreter into executing unintended commands or accessing data without authorization.

**Why this matters:**
- **OWASP Top 10 #1** (A03:2021 — Injection): The most prevalent and dangerous class of web application vulnerabilities.
- **CWE Top 25**: SQL Injection (CWE-89) and OS Command Injection (CWE-78) consistently rank in the top 5 most dangerous software weaknesses.
- **Impact**: Full database compromise, remote code execution, data exfiltration, privilege escalation, complete system takeover.

**General Principle**: Any time untrusted input is concatenated, interpolated, or formatted into a string that is subsequently interpreted by a parser, query engine, shell, or template engine, an injection vulnerability exists. The defense is to ensure a strict separation between code/commands and data, typically through parameterization or structured APIs.

---

## Vulnerability Patterns

### SQL Injection

**Description**: Occurs when user-supplied data is included in SQL queries via string concatenation, format strings, or interpolation instead of parameterized queries. Allows attackers to manipulate query logic, extract data, modify records, or execute administrative operations.

**Vulnerable Code Examples:**

**Python** — f-string / format / concatenation in `cursor.execute()`:
```python
# VULNERABLE: f-string interpolation
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# VULNERABLE: %-formatting
cursor.execute("SELECT * FROM users WHERE name = '%s'" % username)

# VULNERABLE: .format()
cursor.execute("SELECT * FROM users WHERE email = '{}'".format(email))

# VULNERABLE: string concatenation
cursor.execute("SELECT * FROM accounts WHERE owner = '" + request.args['name'] + "'")
```

**Java** — `Statement.executeQuery()` with concatenation:
```java
// VULNERABLE: string concatenation with Statement
String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);

// VULNERABLE: String.format into query
String query = String.format("SELECT * FROM users WHERE name = '%s'", userInput);
stmt.executeQuery(query);
```

**JavaScript/TypeScript** — template literals in SQL:
```javascript
// VULNERABLE: template literal in raw query
const result = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);

// VULNERABLE: string concatenation
const query = "SELECT * FROM products WHERE name = '" + req.body.name + "'";
connection.query(query);

// VULNERABLE: Sequelize raw query with interpolation
sequelize.query(`SELECT * FROM users WHERE name = '${name}'`);
```

**C#** — `String.Format` / interpolation in SQL:
```csharp
// VULNERABLE: string interpolation
string query = $"SELECT * FROM Users WHERE Id = {userId}";
SqlCommand cmd = new SqlCommand(query, connection);

// VULNERABLE: String.Format
string query = String.Format("SELECT * FROM Users WHERE Name = '{0}'", userName);
cmd.CommandText = query;

// VULNERABLE: concatenation
cmd.CommandText = "SELECT * FROM Users WHERE Email = '" + email + "'";
```

**Go** — `fmt.Sprintf` in SQL:
```go
// VULNERABLE: fmt.Sprintf with user input
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
rows, err := db.Query(query)

// VULNERABLE: string concatenation
query := "SELECT * FROM users WHERE name = '" + name + "'"
db.Exec(query)
```

**PHP** — `mysql_query`, `mysqli_query` with concatenation:
```php
// VULNERABLE: direct concatenation
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
mysql_query($query);

// VULNERABLE: variable interpolation
$query = "SELECT * FROM users WHERE name = '$_POST[name]'";
mysqli_query($conn, $query);
```

**Ruby** — string interpolation in ActiveRecord:
```ruby
# VULNERABLE: string interpolation in where clause
User.where("name = '#{params[:name]}'")

# VULNERABLE: string interpolation in find_by_sql
User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
```

**Dangerous Functions/APIs:**
- Python: `cursor.execute()`, `cursor.executemany()`, `engine.execute()` with string formatting
- Java: `Statement.executeQuery()`, `Statement.execute()`, `Statement.executeUpdate()`
- JavaScript: `connection.query()`, `pool.query()`, `sequelize.query()`, `knex.raw()`
- C#: `SqlCommand()`, `ExecuteReader()`, `ExecuteNonQuery()`, `ExecuteScalar()` with string building
- Go: `db.Query()`, `db.Exec()`, `db.QueryRow()` with `fmt.Sprintf`
- PHP: `mysql_query()`, `mysqli_query()`, `pg_query()`, `PDO::query()` with concatenation
- Ruby: `.where()` with string interpolation, `.find_by_sql()`, `.execute()`, `.select()` with raw strings

---

### NoSQL Injection

**Description**: Occurs when user input is passed directly into NoSQL query objects without sanitization, allowing attackers to inject query operators like `$gt`, `$ne`, `$regex`, `$where` to bypass authentication or extract data.

**Vulnerable Code Examples:**

**JavaScript (MongoDB/Mongoose)**:
```javascript
// VULNERABLE: req.body passed directly as query filter
// Attacker sends: {"username": {"$gt": ""}, "password": {"$gt": ""}}
db.collection('users').find({ username: req.body.username, password: req.body.password });

// VULNERABLE: direct insertion of user object into query
const user = await User.findOne({ email: req.body.email, password: req.body.password });

// VULNERABLE: $where with user-controlled string
db.collection('users').find({ $where: `this.name == '${req.query.name}'` });
```

**Python (PyMongo)**:
```python
# VULNERABLE: unsanitized dict from JSON body
query = json.loads(request.data)
results = db.users.find(query)

# VULNERABLE: operator injection via nested dict
db.users.find({"username": request.json["username"]})
```

**Java (MongoDB Driver)**:
```java
// VULNERABLE: parsing user input as BSON
Document query = Document.parse(request.getParameter("filter"));
collection.find(query);
```

**PHP (MongoDB)**:
```php
// VULNERABLE: direct use of user input in query
$collection->find(['username' => $_POST['username'], 'password' => $_POST['password']]);
```

**Dangerous Operators**: `$gt`, `$gte`, `$lt`, `$lte`, `$ne`, `$in`, `$nin`, `$regex`, `$where`, `$exists`, `$or`, `$and`

---

### OS Command Injection

**Description**: Occurs when user input is incorporated into operating system commands executed by the application. Allows remote code execution with the privileges of the application process.

**Vulnerable Code Examples:**

**Python**:
```python
# VULNERABLE: shell=True with user input
subprocess.call("ping " + user_input, shell=True)
subprocess.Popen("nslookup " + domain, shell=True)

# VULNERABLE: os.system with user input
os.system("ls " + directory)
os.system(f"convert {uploaded_file} output.png")

# VULNERABLE: os.popen
os.popen("cat " + filename)
```

**Java**:
```java
// VULNERABLE: Runtime.exec with user input
Runtime.getRuntime().exec("ping " + userInput);

// VULNERABLE: ProcessBuilder with shell
ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping " + host);
pb.start();
```

**JavaScript/Node.js**:
```javascript
// VULNERABLE: child_process.exec with user input
const { exec } = require('child_process');
exec(`ping ${req.query.host}`);

// VULNERABLE: execSync
child_process.execSync('convert ' + req.body.filename + ' output.png');
```

**C#**:
```csharp
// VULNERABLE: Process.Start with user input
Process.Start("cmd.exe", "/c ping " + hostname);

// VULNERABLE: ProcessStartInfo with shell command
var psi = new ProcessStartInfo("cmd.exe", $"/c nslookup {domain}");
Process.Start(psi);
```

**Go**:
```go
// VULNERABLE: exec.Command with shell
cmd := exec.Command("sh", "-c", "ping " + userInput)
cmd.Run()

// VULNERABLE: string concatenation in command
cmd := exec.Command("bash", "-c", fmt.Sprintf("dig %s", domain))
```

**PHP**:
```php
// VULNERABLE: system(), exec(), passthru(), shell_exec(), backticks
system("ping " . $_GET['host']);
exec("convert " . $_FILES['image']['name'] . " output.png");
$output = `nslookup {$_GET['domain']}`;
shell_exec("whois " . $domain);
passthru("cat " . $file);
```

**Ruby**:
```ruby
# VULNERABLE: system, exec, backticks, %x{}
system("ping #{params[:host]}")
`nslookup #{params[:domain]}`
%x(dig #{user_input})
IO.popen("cat #{filename}")
Kernel.exec("ls #{directory}")
```

**Dangerous Functions/APIs:**
- Python: `os.system()`, `os.popen()`, `subprocess.call(shell=True)`, `subprocess.Popen(shell=True)`, `subprocess.run(shell=True)`, `commands.getoutput()`
- Java: `Runtime.exec()`, `ProcessBuilder` with shell
- JavaScript: `child_process.exec()`, `child_process.execSync()`, `child_process.spawn()` with shell option
- C#: `Process.Start()`, `ProcessStartInfo` with shell commands
- Go: `exec.Command("sh", "-c", ...)`, `exec.Command("bash", "-c", ...)`
- PHP: `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`, `proc_open()`, backtick operator
- Ruby: `system()`, `exec()`, `%x{}`, backtick operator, `IO.popen()`, `Kernel.exec()`, `Open3.capture3()`

---

### LDAP Injection

**Description**: Occurs when user input is incorporated into LDAP queries without proper escaping, allowing attackers to modify query logic to bypass authentication or access unauthorized directory entries.

**Vulnerable Code Examples:**

**Python**:
```python
# VULNERABLE: string concatenation in LDAP filter
search_filter = "(&(uid=" + username + ")(userPassword=" + password + "))"
ldap_conn.search(base_dn, search_filter)
```

**Java**:
```java
// VULNERABLE: concatenation in LDAP search filter
String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
ctx.search(baseDN, filter, searchControls);
```

**C#**:
```csharp
// VULNERABLE: string interpolation in LDAP filter
string filter = $"(&(uid={username})(userPassword={password}))";
searcher.Filter = filter;
```

**PHP**:
```php
// VULNERABLE: concatenation in ldap_search filter
$filter = "(&(uid=" . $_POST['user'] . ")(password=" . $_POST['pass'] . "))";
ldap_search($ds, $base_dn, $filter);
```

**Special Characters**: `*`, `(`, `)`, `\`, `NUL` — attacker payload: `admin)(|(password=*` turns filter into `(&(uid=admin)(|(password=*)(userPassword=anything))`

---

### Template Injection (SSTI)

**Description**: Server-Side Template Injection occurs when user input is embedded into template strings that are then rendered by a template engine, allowing attackers to execute arbitrary code on the server.

**Vulnerable Code Examples:**

**Python (Jinja2)**:
```python
# VULNERABLE: user input used as template source
from jinja2 import Template
template = Template(request.args.get('template'))
template.render()

# VULNERABLE: format string used to build template
template_str = request.form['greeting'] + " {{ user.name }}"
Template(template_str).render(user=user)
```

**Python (Mako)**:
```python
# VULNERABLE: user input in template
from mako.template import Template
Template(user_input).render()
```

**Java (Freemarker)**:
```java
// VULNERABLE: user input as template source
Template template = new Template("template", new StringReader(userInput), cfg);
template.process(dataModel, out);
```

**Java (Thymeleaf)**:
```java
// VULNERABLE: user input in fragment expression
@GetMapping("/page")
public String page(@RequestParam String section) {
    return "welcome :: " + section;  // fragment injection
}
```

**PHP (Twig)**:
```php
// VULNERABLE: user input as template source
$twig->createTemplate($_GET['template'])->render();
```

**Ruby (ERB)**:
```ruby
# VULNERABLE: user input rendered as ERB
ERB.new(params[:template]).result(binding)
```

**JavaScript (Pug/Jade, EJS)**:
```javascript
// VULNERABLE: user input in template compilation
const pug = require('pug');
const fn = pug.compile(req.body.template);

// VULNERABLE: EJS with user template
ejs.render(req.body.template, data);
```

**Test Payloads**: `{{7*7}}` (Jinja2/Twig), `${7*7}` (Freemarker/EL), `<%= 7*7 %>` (ERB/EJS), `#{7*7}` (Pug/Jade)

---

### Expression Language Injection

**Description**: Occurs when user input is evaluated within expression language contexts in Java web frameworks, allowing code execution through EL evaluation.

**Vulnerable Code Examples:**

**Java (Spring EL)**:
```java
// VULNERABLE: user input evaluated as SpEL
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput);
Object result = exp.getValue();

// VULNERABLE: SpEL in annotation
@Value("#{systemProperties['" + userInput + "']}")
```

**Java (JSP EL)**:
```jsp
<!-- VULNERABLE: user input in EL expression -->
${param.name}  <!-- reflected directly -->
<spring:message text="${param.userInput}"/>
```

**Java (OGNL — Struts)**:
```java
// VULNERABLE: OGNL evaluation of user input
OgnlUtil ognlUtil = new OgnlUtil();
ognlUtil.getValue(userInput, context, root);
```

**Dangerous Patterns**: `SpelExpressionParser().parseExpression(userInput)`, `%{...}` in Struts configurations, `#{...}` in JSF expressions where user controls the expression content.

---

### Header Injection / CRLF Injection

**Description**: Occurs when user input containing carriage return (`\r`) and line feed (`\n`) characters is included in HTTP headers, enabling response splitting, header injection, cache poisoning, or XSS.

**Vulnerable Code Examples:**

**Python**:
```python
# VULNERABLE: user input in response header
response.headers['Location'] = request.args.get('redirect_url')
response.headers['X-Custom'] = user_input  # may contain \r\n
```

**Java**:
```java
// VULNERABLE: user input in header
response.setHeader("X-User", request.getParameter("user"));
response.addHeader("Location", redirectUrl);
```

**JavaScript (Express)**:
```javascript
// VULNERABLE: user input in response header
res.setHeader('X-Custom', req.query.value);
res.redirect(req.query.url);  // may contain \r\n
```

**PHP**:
```php
// VULNERABLE: header() with user input
header("Location: " . $_GET['url']);
header("X-Forwarded-User: " . $_COOKIE['user']);
```

**C#**:
```csharp
// VULNERABLE: user input in header
Response.Headers.Add("X-Custom", userInput);
Response.Redirect(Request.QueryString["url"]);
```

**Attack Pattern**: Injecting `\r\nSet-Cookie: admin=true\r\n` or `\r\n\r\n<script>alert(1)</script>` into header values.

---

### HQL/ORM Injection

**Description**: Injection through ORM query languages (HQL, JPQL, DQL) or ORM methods that accept raw SQL fragments. Developers often assume ORM usage is inherently safe, but raw query methods are just as vulnerable.

**Vulnerable Code Examples:**

**Java (Hibernate HQL/JPQL)**:
```java
// VULNERABLE: HQL string concatenation
String hql = "FROM User WHERE username = '" + username + "'";
Query query = session.createQuery(hql);

// VULNERABLE: JPQL concatenation
String jpql = "SELECT u FROM User u WHERE u.email = '" + email + "'";
em.createQuery(jpql);
```

**Python (SQLAlchemy)**:
```python
# VULNERABLE: text() with string concatenation
from sqlalchemy import text
result = db.session.execute(text("SELECT * FROM users WHERE name = '" + name + "'"))

# VULNERABLE: text() with f-string
db.session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))
```

**Python (Django)**:
```python
# VULNERABLE: .extra() with user input
User.objects.extra(where=["name = '%s'" % name])

# VULNERABLE: .raw() with string formatting
User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % username)

# VULNERABLE: RawSQL expression
RawSQL("SELECT * FROM users WHERE id = %s" % user_id)
```

**Ruby (ActiveRecord)**:
```ruby
# VULNERABLE: where with string interpolation
User.where("email = '#{params[:email]}'")

# VULNERABLE: order with user input
User.order(params[:sort])

# VULNERABLE: pluck with raw SQL
User.pluck(Arel.sql(params[:column]))
```

**JavaScript (Prisma)**:
```javascript
// VULNERABLE: $queryRaw with template literal
const result = await prisma.$queryRaw(`SELECT * FROM User WHERE id = ${userId}`);

// VULNERABLE: $executeRaw with concatenation
await prisma.$executeRaw('DELETE FROM User WHERE name = \'' + name + '\'');
```

**JavaScript (TypeORM)**:
```javascript
// VULNERABLE: raw query with interpolation
getRepository(User).query(`SELECT * FROM user WHERE name = '${name}'`);
```

**PHP (Doctrine DQL)**:
```php
// VULNERABLE: DQL concatenation
$dql = "SELECT u FROM User u WHERE u.name = '" . $name . "'";
$query = $em->createQuery($dql);
```

---

## Detection Methodology

### Step 1: Identify All Entry Points

Scan for all locations where external data enters the application:

```bash
# HTTP request parameters and body
grep -rn "request\.\(args\|form\|json\|values\|params\|data\|get\|POST\|GET\|query\)" --include="*.py"
grep -rn "req\.\(body\|params\|query\|headers\|cookies\)" --include="*.js" --include="*.ts"
grep -rn "getParameter\|getHeader\|getCookies\|getQueryString\|getPathInfo" --include="*.java"
grep -rn "Request\.\(Form\|Query\|Headers\|Cookies\|RouteValues\)" --include="*.cs"
grep -rn '\$_\(GET\|POST\|REQUEST\|COOKIE\|SERVER\|FILES\)' --include="*.php"
grep -rn "params\[:\|request\.\(parameters\|headers\|cookies\)" --include="*.rb"
grep -rn "r\.\(FormValue\|URL\.Query\|Header\|PostForm\|Body\)" --include="*.go"
```

### Step 2: Identify Dangerous Sinks

Search for query execution and command execution functions:

```bash
# SQL Injection sinks
grep -rn "execute\|cursor\.\|\.query\|\.raw\|\.extra" --include="*.py"
grep -rn "executeQuery\|executeUpdate\|createStatement\|createQuery\|createNativeQuery" --include="*.java"
grep -rn "\.query\(\|\.raw\(\|sequelize\.\|knex\.\|\.execute(" --include="*.js" --include="*.ts"
grep -rn "SqlCommand\|ExecuteReader\|ExecuteNonQuery\|ExecuteScalar\|FromSqlRaw\|ExecuteSqlRaw" --include="*.cs"
grep -rn "mysql_query\|mysqli_query\|pg_query\|PDO.*query\|->execute" --include="*.php"
grep -rn "\.where\(.*['\"].*#\{.*\}\|find_by_sql\|\.select\(.*#\{" --include="*.rb"
grep -rn "db\.Query\|db\.Exec\|db\.QueryRow\|\.Prepare" --include="*.go"

# OS Command Injection sinks
grep -rn "os\.system\|os\.popen\|subprocess\.\(call\|run\|Popen\).*shell" --include="*.py"
grep -rn "Runtime\..*exec\|ProcessBuilder" --include="*.java"
grep -rn "child_process\.\(exec\|execSync\|spawn\)\|\.exec(" --include="*.js" --include="*.ts"
grep -rn "Process\.Start\|ProcessStartInfo" --include="*.cs"
grep -rn "system\s*(\|exec\s*(\|passthru\|shell_exec\|popen\s*(\|proc_open" --include="*.php"
grep -rn "system\s*(\|%x\|IO\.popen\|Kernel\.exec\|Open3" --include="*.rb"
grep -rn "exec\.Command" --include="*.go"

# NoSQL Injection sinks
grep -rn "\.find\(\|\.findOne\(\|\.aggregate\(\|\.updateOne\(\|\.deleteOne\(" --include="*.js" --include="*.ts"
grep -rn "\.find\(\|\.find_one\(\|\.aggregate\(" --include="*.py"

# Template Injection sinks
grep -rn "Template\(\|\.render\(\|\.compile\(" --include="*.py"
grep -rn "new Template\|createTemplate\|\.render\(" --include="*.java"
grep -rn "ejs\.render\|pug\.compile\|handlebars\.compile\|nunjucks\.\(renderString\|compile\)" --include="*.js" --include="*.ts"
grep -rn "ERB\.new\|Erubi\|render.*inline" --include="*.rb"

# LDAP Injection sinks
grep -rn "ldap_search\|ldap_list\|ldap_read" --include="*.php"
grep -rn "search\(.*filter\|DirContext.*search\|ldap\.search" --include="*.java" --include="*.py"

# Expression Language sinks
grep -rn "SpelExpressionParser\|parseExpression\|OgnlUtil\|ValueExpression" --include="*.java"
```

### Step 3: Trace Data Flow (Source-to-Sink Analysis)

For each identified sink, trace backwards to determine if user-controlled data reaches it:

```bash
# Find variables assigned from request objects then used in queries
# Python: track variable from request to execute
grep -rn "=.*request\.\(args\|form\|json\)" --include="*.py" -l | xargs grep -l "execute\|\.query\|\.raw"

# JavaScript: files with both request params and query execution
grep -rn "req\.\(body\|params\|query\)" --include="*.js" --include="*.ts" -l | xargs grep -l "\.query\|\.exec\|\.find("

# Java: files with both getParameter and executeQuery
grep -rn "getParameter" --include="*.java" -l | xargs grep -l "executeQuery\|createQuery\|exec("
```

### Step 4: Check for Parameterization

Verify whether dangerous sinks use parameterized queries:

```bash
# SAFE patterns — parameterized queries
# Python: cursor.execute("SELECT ... WHERE id = %s", (user_id,))  <-- tuple parameter
# Java: PreparedStatement with ? placeholders
# JavaScript: connection.query("SELECT ... WHERE id = ?", [userId])
# C#: SqlCommand with @param parameters
# Go: db.Query("SELECT ... WHERE id = $1", userId)

# Look for ABSENCE of parameterization in files with query execution
grep -rn "execute.*['\"].*[+%{]" --include="*.py"
grep -rn "executeQuery.*[+]" --include="*.java"
grep -rn "\.query\(.*\`.*\$\{" --include="*.js" --include="*.ts"
grep -rn "SqlCommand\(.*\$\"\|String\.Format.*SELECT" --include="*.cs"
grep -rn "fmt\.Sprintf.*SELECT\|fmt\.Sprintf.*INSERT\|fmt\.Sprintf.*UPDATE\|fmt\.Sprintf.*DELETE" --include="*.go"
```

### Step 5: Check for Raw Query Patterns in ORMs

```bash
# Django raw/extra
grep -rn "\.raw\(\|\.extra\(\|RawSQL\(" --include="*.py"

# SQLAlchemy text() with string operations
grep -rn "text\(.*[+f'\"]" --include="*.py"

# ActiveRecord unsafe patterns
grep -rn "\.where\(\".*#\{" --include="*.rb"
grep -rn "\.order\(.*params\|\.pluck\(.*Arel\.sql" --include="*.rb"

# Prisma raw queries
grep -rn "\$queryRaw\`\|\$executeRaw\`\|\$queryRawUnsafe\|\$executeRawUnsafe" --include="*.js" --include="*.ts"

# Hibernate/JPA string concatenation
grep -rn "createQuery\(.*[+].*get\|createQuery\(.*[+].*param\|createQuery\(.*[+].*request" --include="*.java"

# TypeORM raw queries
grep -rn "\.query\(.*\`\|\.query\(.*[+]" --include="*.js" --include="*.ts"
```

### Step 6: Check for Second-Order Injection

Look for patterns where data is stored and later used in queries:

```bash
# Data read from database then used in another query
grep -rn "row\[.*\]\|result\[.*\]\|fetchone\|fetchall" --include="*.py" -l | xargs grep -l "execute\|\.query"

# Values from one DB query used in another
grep -rn "getString\|getInt\|getObject" --include="*.java" -l | xargs grep -l "executeQuery\|createQuery"
```

### Step 7: Validate Input Sanitization

Check if sanitization exists and whether it is sufficient:

```bash
# Input validation patterns (may be insufficient)
grep -rn "escape\|sanitize\|clean\|strip\|filter\|validate\|whitelist\|allowlist" --include="*.py" --include="*.js" --include="*.java" --include="*.cs" --include="*.rb" --include="*.go" --include="*.php"

# Blocklist patterns (usually insufficient)
grep -rn "replace.*['\"].*[;'\"\\\\]\|blacklist\|blocklist\|deny_list" --include="*.py" --include="*.js" --include="*.java"
```

---

## Common Sinks and Sources

### Sources (Entry Points for Untrusted Data)

| Source Category | Examples |
|---|---|
| HTTP Query Parameters | `request.args`, `req.query`, `getParameter()`, `$_GET`, `params[:id]`, `r.URL.Query()` |
| HTTP Body / Form Data | `request.form`, `req.body`, `$_POST`, `Request.Form`, `r.PostForm` |
| HTTP Headers | `request.headers`, `req.headers`, `getHeader()`, `$_SERVER['HTTP_*']`, `r.Header` |
| Cookies | `request.cookies`, `req.cookies`, `getCookies()`, `$_COOKIE`, `cookies[:name]` |
| URL Path Segments | `request.path`, `req.params`, `getPathInfo()`, `Request.RouteValues` |
| File Uploads | `request.files`, `req.file`, `$_FILES`, `MultipartFile`, `r.FormFile()` |
| WebSocket Messages | `ws.on('message')`, `@OnMessage`, `channel.receive` |
| Database Results (Second-Order) | `cursor.fetchone()`, `resultSet.getString()`, `row[column]` |
| Environment Variables | `os.environ`, `process.env`, `System.getenv()`, `getenv()` |
| External API Responses | `requests.get().json()`, `fetch().json()`, `HttpClient.GetAsync()` |
| CLI Arguments | `sys.argv`, `process.argv`, `args[]`, `os.Args` |
| Message Queues | `channel.basic_consume`, `consumer.poll()`, `@RabbitListener` |

### Sinks by Language

**Python Dangerous Sinks:**
- SQL: `cursor.execute()`, `cursor.executemany()`, `engine.execute()`, `session.execute()`, `text()`, `.raw()`, `.extra()`
- Command: `os.system()`, `os.popen()`, `subprocess.*` with `shell=True`, `commands.getoutput()`
- Template: `Template()`, `render_template_string()`, `Markup()`, `Mako.Template()`
- LDAP: `ldap.search_s()`, `connection.search()`

**Java Dangerous Sinks:**
- SQL: `Statement.execute*()`, `session.createQuery()`, `em.createQuery()`, `em.createNativeQuery()`, `jdbcTemplate.query()` with string concat
- Command: `Runtime.exec()`, `ProcessBuilder`, `commons-exec`
- Template: `new Template()`, `Velocity.evaluate()`, `freemarkerCfg.getTemplate()`
- EL: `SpelExpressionParser.parseExpression()`, `OgnlUtil.getValue()`, `ValueExpression.getValue()`
- LDAP: `DirContext.search()`, `LdapTemplate.search()`

**JavaScript/TypeScript Dangerous Sinks:**
- SQL: `connection.query()`, `pool.query()`, `sequelize.query()`, `knex.raw()`, `prisma.$queryRaw`, `prisma.$queryRawUnsafe`
- Command: `child_process.exec()`, `child_process.execSync()`, `child_process.spawn({shell:true})`
- Template: `ejs.render()`, `pug.compile()`, `nunjucks.renderString()`, `Handlebars.compile()`
- NoSQL: `collection.find()`, `Model.findOne()`, `collection.aggregate()`

**C# Dangerous Sinks:**
- SQL: `SqlCommand()`, `ExecuteReader()`, `ExecuteNonQuery()`, `FromSqlRaw()`, `ExecuteSqlRaw()`, `Database.SqlQuery()`
- Command: `Process.Start()`, `ProcessStartInfo`
- LDAP: `DirectorySearcher.Filter`, `SearchRequest`

**Go Dangerous Sinks:**
- SQL: `db.Query()`, `db.Exec()`, `db.QueryRow()` with `fmt.Sprintf`
- Command: `exec.Command("sh", "-c", ...)`, `exec.Command("bash", "-c", ...)`

**PHP Dangerous Sinks:**
- SQL: `mysql_query()`, `mysqli_query()`, `pg_query()`, `PDO::query()` with string concat, `->execute()` without binding
- Command: `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`, `proc_open()`, backtick operator
- Template: `$twig->createTemplate()`, `Blade::compileString()`
- LDAP: `ldap_search()`, `ldap_list()`, `ldap_read()`

**Ruby Dangerous Sinks:**
- SQL: `.where()` with string interpolation, `.find_by_sql()`, `.order()` with raw input, `.pluck(Arel.sql(...))`, `.select()` with raw strings, `.joins()` with raw strings, `.group()` with raw input
- Command: `system()`, `exec()`, `%x{}`, backticks, `IO.popen()`, `Kernel.exec()`, `Open3.capture3()`
- Template: `ERB.new()`, `Erubi::Engine.new()`, `render inline:`

---

## False Positive Indicators

When reviewing findings, discard or downgrade results matching these patterns:

1. **Parameterized queries that superficially resemble concatenation:**
   ```python
   # SAFE — parameterized (tuple argument)
   cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
   
   # SAFE — SQLAlchemy bound parameter
   db.session.execute(text("SELECT * FROM users WHERE id = :uid"), {"uid": user_id})
   ```

2. **Hardcoded/constant values in concatenation (no user input):**
   ```java
   // SAFE — concatenating constants
   String query = "SELECT * FROM " + TABLE_NAME + " WHERE active = 1";
   // Only if TABLE_NAME is provably a constant, not derived from input
   ```

3. **Values from allow-lists or enum types:**
   ```python
   # SAFE — restricted to allowed values
   ALLOWED_SORT = {"name", "date", "id"}
   sort_col = request.args.get("sort")
   if sort_col in ALLOWED_SORT:
       cursor.execute(f"SELECT * FROM items ORDER BY {sort_col}")
   ```

4. **Strong type casting before use:**
   ```python
   # SAFE — integer cast prevents injection
   user_id = int(request.args.get('id'))
   cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
   ```

5. **ORM query builder methods that auto-parameterize:**
   ```python
   # SAFE — Django ORM auto-parameterizes
   User.objects.filter(name=request.GET['name'])
   
   # SAFE — SQLAlchemy column comparison
   session.query(User).filter(User.name == username)
   ```
   ```javascript
   // SAFE — Prisma parameterized tagged template
   prisma.$queryRaw`SELECT * FROM User WHERE id = ${userId}`
   // Note: tagged template literal (no parentheses) is safe; function call is NOT
   ```

6. **Prepared statements in Java:**
   ```java
   // SAFE — PreparedStatement with placeholders
   PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
   ps.setInt(1, userId);
   ```

7. **Test/migration code:**
   - SQL in test fixtures, seed data scripts, or migration files with hardcoded values are generally not exploitable.

---

## Severity Assessment

### Critical (CVSS 9.0–10.0)
- Direct SQL injection on authentication queries (bypass login)
- OS command injection with unsanitized user input from HTTP requests
- SQL injection on queries with DELETE/UPDATE/DROP capability
- Template injection allowing RCE (e.g., Jinja2 with no sandbox)
- CVSS Vector: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

### High (CVSS 7.0–8.9)
- SQL injection requiring specific conditions (e.g., authenticated user)
- NoSQL injection bypassing authentication
- OS command injection with partial input validation that can be bypassed
- Expression Language injection in Spring/Struts
- Second-order SQL injection with high-value data store
- CVSS Vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

### Medium (CVSS 4.0–6.9)
- Second-order injection requiring specific stored data conditions
- LDAP injection with limited directory access
- Header injection / CRLF with limited impact (e.g., log injection only)
- HQL injection in read-only query paths
- Injection in admin-only or internal-only endpoints
- CVSS Vector: `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N`

### Low (CVSS 0.1–3.9)
- Injection sinks with strong input validation and WAF in front
- Injection in offline/batch processing with no external input path
- Theoretical injection where data flow cannot reach the sink from an external source
- CVSS Vector: `AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N`

---

## Remediation Patterns

### SQL Injection — Secure Patterns

**Python (parameterized):**
```python
# SECURE: parameterized query with tuple
cursor.execute("SELECT * FROM users WHERE id = %s AND name = %s", (user_id, name))

# SECURE: SQLAlchemy with bound parameters
from sqlalchemy import text
db.session.execute(text("SELECT * FROM users WHERE id = :uid"), {"uid": user_id})

# SECURE: Django ORM
User.objects.filter(id=user_id, name=name)
```

**Java (PreparedStatement):**
```java
// SECURE: PreparedStatement
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ? AND name = ?");
ps.setInt(1, userId);
ps.setString(2, name);
ResultSet rs = ps.executeQuery();

// SECURE: JPA named parameters
TypedQuery<User> q = em.createQuery("SELECT u FROM User u WHERE u.name = :name", User.class);
q.setParameter("name", userName);
```

**JavaScript (parameterized):**
```javascript
// SECURE: parameterized query
const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);

// SECURE: Prisma tagged template literal (auto-parameterized)
const user = await prisma.$queryRaw`SELECT * FROM "User" WHERE id = ${userId}`;

// SECURE: Knex query builder
const users = await knex('users').where({ id: userId });
```

**C# (SqlParameter):**
```csharp
// SECURE: parameterized command
var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", connection);
cmd.Parameters.AddWithValue("@id", userId);

// SECURE: EF Core parameterized
var users = context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {userId}");
```

**Go (parameterized):**
```go
// SECURE: parameterized query
rows, err := db.Query("SELECT * FROM users WHERE id = $1", userID)

// SECURE: prepared statement
stmt, err := db.Prepare("SELECT * FROM users WHERE id = $1 AND name = $2")
rows, err := stmt.Query(userID, name)
```

**PHP (PDO prepared):**
```php
// SECURE: PDO prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $userId]);
```

**Ruby (ActiveRecord parameterized):**
```ruby
# SECURE: parameterized where
User.where("name = ?", params[:name])
User.where(name: params[:name])
```

### OS Command Injection — Secure Patterns

```python
# SECURE: avoid shell=True, use argument list
subprocess.run(["ping", "-c", "4", hostname], shell=False)

# SECURE: shlex.quote for unavoidable shell usage
import shlex
subprocess.run(f"ping -c 4 {shlex.quote(hostname)}", shell=True)
```

```java
// SECURE: ProcessBuilder with argument array
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", hostname);
```

```javascript
// SECURE: execFile (no shell by default)
const { execFile } = require('child_process');
execFile('ping', ['-c', '4', hostname]);

// SECURE: spawn without shell option
child_process.spawn('ping', ['-c', '4', hostname]);
```

```go
// SECURE: exec.Command with separate arguments
cmd := exec.Command("ping", "-c", "4", hostname)
```

```php
// SECURE: escapeshellarg for each argument
$safe_host = escapeshellarg($host);
system("ping -c 4 " . $safe_host);
```

### NoSQL Injection — Secure Patterns

```javascript
// SECURE: validate/cast types before query
const username = String(req.body.username);
const password = String(req.body.password);
db.collection('users').find({ username: username, password: password });

// SECURE: use mongo-sanitize or express-mongo-sanitize
const sanitize = require('mongo-sanitize');
const cleanInput = sanitize(req.body);
db.collection('users').find(cleanInput);

// SECURE: explicitly reject operator keys
if (typeof req.body.username !== 'string') throw new Error('Invalid input');
```

### Template Injection — Secure Patterns

```python
# SECURE: never use user input as template source
# Instead, use user input as template DATA
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('templates'))
template = env.get_template('greeting.html')
result = template.render(name=user_input)  # input is data, not template code

# SECURE: Jinja2 sandbox (if dynamic templates unavoidable)
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
```

### LDAP Injection — Secure Patterns

```python
# SECURE: escape special characters
import ldap
from ldap.filter import escape_filter_chars
safe_username = escape_filter_chars(username)
search_filter = f"(&(uid={safe_username})(objectClass=person))"
```

```java
// SECURE: use LdapEncoder or framework escaping
String safeUsername = LdapEncoder.filterEncode(username);
String filter = "(&(uid=" + safeUsername + ")(objectClass=person))";
```

### Header Injection — Secure Patterns

```python
# SECURE: strip \r and \n from header values
safe_value = user_input.replace('\r', '').replace('\n', '')
response.headers['X-Custom'] = safe_value
```

```javascript
// SECURE: validate header values
const safe = value.replace(/[\r\n]/g, '');
res.setHeader('X-Custom', safe);
// Note: modern frameworks (Express 4.x+, etc.) typically reject headers with CRLF
```

---

## CWE References

| CWE | Name | Injection Type |
|---|---|---|
| [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | Improper Neutralization of Special Elements used in an SQL Command | SQL Injection |
| [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | Improper Neutralization of Special Elements used in an OS Command | OS Command Injection |
| [CWE-90](https://cwe.mitre.org/data/definitions/90.html) | Improper Neutralization of Special Elements used in an LDAP Query | LDAP Injection |
| [CWE-943](https://cwe.mitre.org/data/definitions/943.html) | Improper Neutralization of Special Elements in Data Query Logic | NoSQL Injection |
| [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | Improper Neutralization of Special Elements Used in a Template Engine | Template Injection (SSTI) |
| [CWE-917](https://cwe.mitre.org/data/definitions/917.html) | Improper Neutralization of Special Elements used in an Expression Language Statement | Expression Language Injection |
| [CWE-113](https://cwe.mitre.org/data/definitions/113.html) | Improper Neutralization of CRLF Sequences in HTTP Headers | HTTP Response Splitting |
| [CWE-564](https://cwe.mitre.org/data/definitions/564.html) | SQL Injection: Hibernate | HQL/ORM Injection |

### Additional Related CWEs
- **CWE-77**: Improper Neutralization of Special Elements used in a Command (Command Injection — general)
- **CWE-94**: Improper Control of Generation of Code (Code Injection)
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)
- **CWE-116**: Improper Encoding or Escaping of Output
- **CWE-20**: Improper Input Validation
