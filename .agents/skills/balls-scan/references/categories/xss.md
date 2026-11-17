<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Codex-native BALLS workflow and evidence rules. -->

# Cross-Site Scripting (XSS) Detection Skill

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

Cross-Site Scripting (XSS) is a code injection vulnerability that allows an attacker to execute
malicious scripts in the context of a victim's browser session. It remains one of the most
prevalent and dangerous web application vulnerabilities, consistently ranking in the OWASP Top 10
(A03:2021 — Injection).

### Impact

- **Session Hijacking**: Stealing session cookies to impersonate authenticated users.
- **Account Takeover**: Capturing credentials via fake login forms or keyloggers injected into the page.
- **Data Theft**: Exfiltrating sensitive data visible in the DOM (PII, tokens, financial data).
- **Malware Distribution**: Redirecting users to malicious sites or triggering drive-by downloads.
- **Defacement**: Altering page content to spread misinformation or damage reputation.
- **Phishing**: Rendering convincing phishing overlays within a trusted domain origin.
- **Cryptojacking**: Injecting cryptocurrency miners into victim browsers.
- **Worm Propagation**: Self-replicating XSS payloads (e.g., the Samy MySpace worm).

### Three Main Types

| Type | Delivery | Persistence | Server Involvement |
|------|----------|-------------|--------------------|
| **Reflected XSS** | Via URL parameters, form inputs, or HTTP headers | None — payload is in the request | Server reflects unsanitized input in the response |
| **Stored XSS** | Via database, file upload, or persistent storage | Permanent until data is removed | Server retrieves and renders stored malicious content |
| **DOM-based XSS** | Via client-side JavaScript reading from attacker-controlled sources | None — entirely client-side | Server may never see the payload (e.g., fragment identifiers) |

### Server-rendered messages and error paths

Trace request values through validation messages, flash/session messages, redirects, and the later page that renders them. A redirect does not make reflected input safe when the message persists to the next response. Inspect the template engine's autoescape rules for the actual file extension and render call, plus explicit safe/escape filters and custom formatters. Include signin failures, signup errors, search/validation messages, and exception pages among the sinks; don't review only database-backed profile fields. Distinguish text that is HTML-escaped from raw HTML, and distinguish markup injection from script execution.

For BALLS's source-only review, framework/version behavior and the exact template context are evidence. A browser execution test may be listed as an unexecuted reproduction step but is not required when the source-to-render path and escaping behavior are established.

---

## Vulnerability Patterns

### Reflected XSS

Reflected XSS occurs when user-supplied data from the HTTP request is immediately included in the
server's response without proper encoding. The attacker crafts a URL containing a malicious
script, then tricks a victim into clicking it.

**Python (Flask)**:
```python
# VULNERABLE — user input rendered directly into HTML response
@app.route("/search")
def search():
    query = request.args.get("query", "")
    return f"<h1>Results for: {query}</h1>"

# VULNERABLE — Jinja2 autoescape bypassed with |safe filter
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("Hello {{ name|safe }}", name=name)
```

**Java (JSP / Servlet)**:
```jsp
<%-- VULNERABLE — unescaped expression tag --%>
<p>Welcome, <%= request.getParameter("name") %></p>

<%-- VULNERABLE — scriptlet writing directly to response --%>
<%
    String query = request.getParameter("q");
    out.println("<div>Search: " + query + "</div>");
%>
```

```java
// VULNERABLE — servlet writing unescaped parameter to response
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String name = req.getParameter("name");
    resp.getWriter().write("<h1>Hello " + name + "</h1>");
}
```

**PHP**:
```php
<!-- VULNERABLE — direct echo of GET parameter -->
<p>Hello, <?php echo $_GET['name']; ?></p>

<!-- VULNERABLE — short echo tag -->
<p>Search: <?= $_REQUEST['q'] ?></p>

<!-- VULNERABLE — concatenation into HTML -->
<?php
    $username = $_POST['username'];
    echo "<span class='user'>" . $username . "</span>";
?>
```

**Node.js (Express)**:
```javascript
// VULNERABLE — string concatenation into HTML response
app.get("/search", (req, res) => {
    res.send("<h1>Results for: " + req.query.q + "</h1>");
});

// VULNERABLE — template literal with unsanitized input
app.get("/greet", (req, res) => {
    res.send(`<div>Hello ${req.query.name}</div>`);
});
```

**ASP.NET**:
```csharp
// VULNERABLE — writing query string directly to response
Response.Write("<p>Hello " + Request.QueryString["name"] + "</p>");

// VULNERABLE — Razor with Html.Raw()
@Html.Raw(ViewBag.UserInput)
```

**Ruby (ERB / Rails)**:
```erb
<%# VULNERABLE — raw unescaped output in ERB %>
<p>Welcome, <%== params[:name] %></p>

<%# VULNERABLE — .html_safe disables auto-escaping in Rails %>
<p><%= params[:name].html_safe %></p>
```

**Go (net/http)**:
```go
// VULNERABLE — writing user input directly to response
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}
```

---

### Stored XSS

Stored (persistent) XSS occurs when malicious input is saved to a data store (database, file,
cache) and later rendered to other users without sanitization. This is the most dangerous XSS
variant because it does not require social engineering — every user who views the affected page
is a victim.

**Common vulnerable locations**:
- Comment systems and forum posts
- User profile fields (display name, bio, location)
- Chat messages and direct messages
- Product reviews and ratings
- Wiki or CMS content
- Admin dashboards displaying user-submitted data
- Email templates rendered from stored user data
- File names displayed in file managers
- Log viewers rendering stored log entries
- Notification content derived from user actions

**Python (Flask + SQLAlchemy)**:
```python
# VULNERABLE — stored comment rendered without escaping
@app.route("/comment", methods=["POST"])
def add_comment():
    comment = request.form["comment"]
    db.session.add(Comment(body=comment))  # Stored as-is
    db.session.commit()
    return redirect("/comments")

@app.route("/comments")
def show_comments():
    comments = Comment.query.all()
    html = ""
    for c in comments:
        html += f"<div class='comment'>{c.body}</div>"  # XSS on render
    return html
```

**Node.js (Express + MongoDB)**:
```javascript
// VULNERABLE — user message stored and rendered unsanitized
app.post("/messages", async (req, res) => {
    await Message.create({ text: req.body.message, user: req.user.id });
    res.redirect("/chat");
});

app.get("/chat", async (req, res) => {
    const messages = await Message.find();
    let html = messages.map(m => `<p>${m.text}</p>`).join("");  // XSS
    res.send(html);
});
```

**PHP (MySQL)**:
```php
<?php
// VULNERABLE — stored review rendered without htmlspecialchars()
$review = $pdo->query("SELECT body FROM reviews WHERE product_id = $id")->fetchAll();
foreach ($review as $r) {
    echo "<div class='review'>" . $r['body'] . "</div>";  // XSS
}
?>
```

---

### DOM-based XSS

DOM-based XSS occurs entirely in the browser. JavaScript reads from an attacker-controllable
**source** and passes the data to a dangerous **sink** without sanitization. The server may
never see the malicious payload (e.g., when it resides in a URL fragment `#`).

**Dangerous Sinks** (execution points):
| Sink | Risk Level | Notes |
|------|-----------|-------|
| `element.innerHTML = ...` | Critical | Parses and renders HTML including `<script>` and event handlers |
| `element.outerHTML = ...` | Critical | Replaces entire element with parsed HTML |
| `document.write(...)` | Critical | Writes directly to the document stream |
| `document.writeln(...)` | Critical | Same as `document.write` with newline |
| `eval(...)` | Critical | Executes arbitrary JavaScript |
| `setTimeout(string, ...)` | Critical | Evaluates string argument as code |
| `setInterval(string, ...)` | Critical | Evaluates string argument as code |
| `new Function(string)` | Critical | Creates function from string — equivalent to eval |
| `element.insertAdjacentHTML(...)` | High | Parses string as HTML at specified position |
| `location.href = ...` | High | Can trigger `javascript:` protocol navigation |
| `location.assign(...)` | High | Same as setting `location.href` |
| `location.replace(...)` | High | Same as `location.assign` but no history entry |
| `window.open(...)` | High | Can open `javascript:` URLs |
| `jQuery.html(...)` | High | Wrapper around `innerHTML` |
| `jQuery.append(...)` | High | Parses HTML string and appends to DOM |
| `jQuery.prepend(...)` | High | Parses HTML string and prepends |
| `jQuery.after(...)` | High | Inserts parsed HTML after element |
| `jQuery.before(...)` | High | Inserts parsed HTML before element |
| `jQuery(...)` constructor | High | Parses HTML if string starts with `<` |
| `element.setAttribute("on*", ...)` | High | Sets event handler attributes |
| `element.src = ...` | Medium | Script/iframe src can load attacker content |
| `element.href = ...` | Medium | Anchor href can use `javascript:` protocol |
| `Blob + createObjectURL` | Medium | Can create executable script blobs |

**Dangerous Sources** (attacker-controlled input):
| Source | Notes |
|--------|-------|
| `location.hash` | Fragment identifier — never sent to server |
| `location.search` | Query string parameters |
| `location.href` | Full URL including all components |
| `location.pathname` | URL path — may contain injected segments |
| `document.referrer` | Referring page URL — attacker-controlled |
| `document.URL` | Full document URL |
| `document.documentURI` | Same as `document.URL` in modern browsers |
| `document.baseURI` | Base URL of the document |
| `window.name` | Persists across navigations — attacker can set via `window.open` |
| `window.postMessage` data | Cross-origin message data |
| `localStorage` / `sessionStorage` | May contain previously stored attacker input |
| `document.cookie` | Cookies set by attacker via other vulnerabilities |
| `Web Storage events` | `storage` event data from other tabs |
| `IndexedDB` data | May contain attacker-stored content |

**Code examples**:
```javascript
// VULNERABLE — innerHTML from URL hash
document.getElementById("content").innerHTML = decodeURIComponent(location.hash.substring(1));

// VULNERABLE — document.write from query parameter
var search = new URLSearchParams(location.search).get("q");
document.write("<p>You searched for: " + search + "</p>");

// VULNERABLE — eval of URL-sourced data
var code = new URLSearchParams(location.search).get("callback");
eval(code);

// VULNERABLE — jQuery sink with location source
var tab = location.hash.substring(1);
$("#tabs").html(tab);

// VULNERABLE — postMessage handler without origin check
window.addEventListener("message", function(event) {
    // Missing: if (event.origin !== "https://trusted.example.com") return;
    document.getElementById("output").innerHTML = event.data;
});

// VULNERABLE — localStorage as intermediate source
// Attacker stores payload via another vuln, then this page renders it
var username = localStorage.getItem("displayName");
document.getElementById("greeting").innerHTML = "Hello, " + username;

// VULNERABLE — setTimeout with string from user input
var delay = new URLSearchParams(location.search).get("action");
setTimeout("handleAction('" + delay + "')", 1000);
```

---

### Framework-Specific Patterns

**React**:
```jsx
// VULNERABLE — dangerouslySetInnerHTML with user data
function Comment({ body }) {
    return <div dangerouslySetInnerHTML={{ __html: body }} />;
}

// VULNERABLE — ref-based innerHTML bypass
function Display({ content }) {
    const ref = useRef();
    useEffect(() => {
        ref.current.innerHTML = content;  // Bypasses React's escaping
    }, [content]);
    return <div ref={ref} />;
}

// VULNERABLE — href with user-controlled URL (javascript: protocol)
function Link({ url, label }) {
    return <a href={url}>{label}</a>;  // url could be "javascript:alert(1)"
}
```

**Angular**:
```typescript
// VULNERABLE — bypassing Angular's built-in sanitizer
constructor(private sanitizer: DomSanitizer) {}

getContent(userInput: string) {
    return this.sanitizer.bypassSecurityTrustHtml(userInput);        // XSS
    return this.sanitizer.bypassSecurityTrustScript(userInput);      // XSS
    return this.sanitizer.bypassSecurityTrustUrl(userInput);         // XSS
    return this.sanitizer.bypassSecurityTrustResourceUrl(userInput); // XSS
    return this.sanitizer.bypassSecurityTrustStyle(userInput);       // XSS
}

// VULNERABLE — innerHTML binding (Angular sanitizes by default but check bypasses)
// This is safe by default UNLESS combined with bypassSecurityTrust*
@Component({
    template: `<div [innerHTML]="userContent"></div>`
})

// VULNERABLE — ElementRef direct DOM manipulation
constructor(private el: ElementRef) {}
ngOnInit() {
    this.el.nativeElement.innerHTML = this.userInput;  // Bypasses Angular sanitizer
}
```

**Vue.js**:
```vue
<!-- VULNERABLE — v-html directive renders raw HTML -->
<template>
    <div v-html="userComment"></div>
</template>

<!-- VULNERABLE — Vue 1.x unescaped interpolation (deprecated) -->
<template>
    <div>{{{ rawHtml }}}</div>
</template>

<!-- VULNERABLE — dynamic component with user-controlled template -->
<component :is="{ template: userTemplate }"></component>
```

**jQuery**:
```javascript
// VULNERABLE — .html() with user data
$("#output").html(userInput);

// VULNERABLE — .append() with unsanitized string
$(".comments").append("<div>" + comment + "</div>");

// VULNERABLE — jQuery constructor parses HTML
var el = $(userInput);  // If userInput starts with "<", jQuery parses as HTML

// VULNERABLE — .prepend(), .after(), .before() with user data
$(".container").prepend(userContent);
$(".item").after(userContent);
$(".item").before(userContent);

// VULNERABLE — .attr() setting event handlers
$("div").attr("onclick", userInput);

// VULNERABLE — $.globalEval()
$.globalEval(userInput);
```

**Svelte**:
```svelte
<!-- VULNERABLE — @html tag renders unescaped HTML -->
{@html userComment}

<!-- VULNERABLE — action with innerHTML -->
<script>
    function rawHtml(node, content) {
        node.innerHTML = content;
    }
</script>
<div use:rawHtml={userInput}></div>
```

**Template Engines**:
```python
# Jinja2 — VULNERABLE: |safe filter disables auto-escaping
{{ user_input|safe }}

# Jinja2 — VULNERABLE: autoescape block override
{% autoescape false %}
    {{ user_input }}
{% endautoescape %}

# Jinja2 — VULNERABLE: Markup() in Python code
from markupsafe import Markup
return Markup(f"<div>{user_input}</div>")
```

```javascript
// EJS — VULNERABLE: unescaped output tag
<%- userInput %>   // Raw output — no escaping
// Safe: <%= userInput %>  // HTML-escaped output

// Handlebars — VULNERABLE: triple-brace unescaped
{{{ userInput }}}  // Raw output — no escaping
// Safe: {{ userInput }}  // HTML-escaped output

// Pug/Jade — VULNERABLE: unescaped output
p!= userInput      // Raw output — no escaping
// Safe: p= userInput  // Escaped output
```

```ruby
# ERB — VULNERABLE: raw helper
<%= raw user_input %>
<%= user_input.html_safe %>
<%== user_input %>
# Safe: <%= user_input %>  # Auto-escaped in Rails
```

---

### Context-Specific XSS

**HTML Attribute Context**:
```html
<!-- VULNERABLE — unquoted attribute allows breakout -->
<div class=USER_INPUT>       <!-- Payload: x onclick=alert(1) -->

<!-- VULNERABLE — quoted attribute allows breakout with matching quote -->
<div title="USER_INPUT">     <!-- Payload: " onmouseover="alert(1) -->

<!-- VULNERABLE — event handler attribute -->
<button onclick="doSomething('USER_INPUT')">  <!-- Payload: ');alert(1);// -->

<!-- VULNERABLE — href/src with user input (javascript: protocol) -->
<a href="USER_INPUT">Click</a>               <!-- Payload: javascript:alert(1) -->
<iframe src="USER_INPUT"></iframe>            <!-- Payload: javascript:alert(1) -->
```

**JavaScript Context**:
```html
<!-- VULNERABLE — user data embedded in script block -->
<script>
    var username = "USER_INPUT";   // Payload: ";alert(1);//
    var config = USER_INPUT;       // Payload: alert(1)
</script>

<!-- VULNERABLE — JSON-in-HTML without encoding -->
<script>
    var data = {"name": "USER_INPUT"};  // Payload: "</script><script>alert(1)</script>
</script>

<!-- VULNERABLE — inline event handlers -->
<div onload="init('USER_INPUT')">  <!-- Payload: ');alert(1);// -->
```

**URL Context**:
```html
<!-- VULNERABLE — javascript: pseudo-protocol -->
<a href="javascript:USER_INPUT">link</a>
<a href="USER_INPUT">link</a>             <!-- Payload: javascript:alert(1) -->
<form action="USER_INPUT">
<iframe src="USER_INPUT">
<object data="USER_INPUT">
<embed src="USER_INPUT">

<!-- VULNERABLE — data: URI -->
<a href="data:text/html,<script>alert(1)</script>">link</a>
```

**CSS Context**:
```html
<!-- VULNERABLE — CSS expression (IE legacy, but still relevant for compat) -->
<div style="width: expression(alert(1))">
<div style="background: url(javascript:alert(1))">
<div style="behavior: url(malicious.htc)">

<!-- VULNERABLE — CSS injection via user input -->
<style>
    .user-theme { color: USER_INPUT; }   /* Payload: red;} body{background:url(javascript:alert(1)) */
</style>
```

---

### Mutation XSS (mXSS)

Mutation XSS exploits differences between HTML sanitizers and the browser's actual parsing
behavior. A payload that appears safe after sanitization is mutated by the browser's parser
into an executable form.

**DOM Clobbering**:
```html
<!-- Clobbering can override global properties -->
<form id="document"><input name="cookie" value="clobbered"></form>
<script>
    // document.cookie now returns the input element, not actual cookies
    // Can be chained with other gadgets for XSS
</script>

<!-- Clobbering window.name -->
<img name="name" value="javascript:alert(1)">
```

**Parser Differential Exploitation**:
```html
<!-- Sanitizer may see this as safe, but browser parses differently -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
<!-- The <style> tag inside <math> is treated as raw text by sanitizer -->
<!-- but the browser's parser may close it early, exposing the img tag -->

<!-- Nested parsing context switches -->
<svg><foreignObject><div><style><img src=x onerror=alert(1)></style></div></foreignObject></svg>
```

---

## Detection Methodology

Follow this systematic approach when scanning a codebase for XSS vulnerabilities:

### Step 1: Identify the Framework and Default Escaping Behavior

Determine the web framework in use and understand its auto-escaping defaults:
- **Auto-escaping ON by default**: React (JSX), Angular, Vue (`{{ }}`), Jinja2, Django templates, Rails ERB (`<%= %>`), Go `html/template`
- **Auto-escaping OFF by default**: EJS (`<%- %>`), Pug (`!=`), PHP `echo`, Java JSP (`<%= %>`), Go `text/template`

### Step 2: Find Explicit Escape Bypasses

Search for constructs that deliberately disable auto-escaping:

```bash
# React
grep -rn "dangerouslySetInnerHTML" --include="*.jsx" --include="*.tsx"

# Vue
grep -rn "v-html" --include="*.vue"

# Angular
grep -rn "bypassSecurityTrust" --include="*.ts"
grep -rn "ElementRef" --include="*.ts"

# Svelte
grep -rn "{@html" --include="*.svelte"

# jQuery / vanilla JS DOM sinks
grep -rn "\.html\(" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
grep -rn "innerHTML\s*=" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
grep -rn "outerHTML\s*=" --include="*.js" --include="*.ts"
grep -rn "document\.write" --include="*.js" --include="*.ts"
grep -rn "insertAdjacentHTML" --include="*.js" --include="*.ts"

# Template engine escape bypasses
grep -rn "|safe" --include="*.html" --include="*.jinja" --include="*.jinja2"
grep -rn "autoescape false" --include="*.html" --include="*.jinja" --include="*.jinja2"
grep -rn "<%- " --include="*.ejs"
grep -rn "{{{" --include="*.hbs" --include="*.handlebars"
grep -rn "!=\s" --include="*.pug" --include="*.jade"
grep -rn "html_safe\|\.raw" --include="*.erb" --include="*.rb"
grep -rn "Html\.Raw" --include="*.cshtml"

# eval and dynamic code execution
grep -rn "eval\s*(" --include="*.js" --include="*.ts"
grep -rn "new Function\s*(" --include="*.js" --include="*.ts"
grep -rn "setTimeout\s*(" --include="*.js" --include="*.ts"
grep -rn "setInterval\s*(" --include="*.js" --include="*.ts"

# URL-context XSS
grep -rn "href\s*=\s*[\"']?\s*javascript:" --include="*.html" --include="*.jsx" --include="*.tsx"
grep -rn "location\.href\s*=" --include="*.js" --include="*.ts"
grep -rn "window\.open\s*(" --include="*.js" --include="*.ts"

# Server-side direct output
grep -rn "echo\s\+\$_\(GET\|POST\|REQUEST\|COOKIE\)" --include="*.php"
grep -rn "Response\.Write.*Request" --include="*.aspx" --include="*.cs"
grep -rn "out\.println.*getParameter" --include="*.java" --include="*.jsp"
grep -rn "Fprintf.*r\.URL\|Fprintf.*r\.Form\|Fprintf.*r\.Header" --include="*.go"
```

### Step 3: Map All Output Points

Identify every location where data is rendered to users:
- HTML templates and views
- API endpoints returning HTML (or content-type `text/html`)
- Email templates with dynamic content
- PDF generation with HTML input
- Server-Sent Events (SSE) or WebSocket messages rendered in DOM
- Error pages displaying user input (404 pages, search results)
- Admin/back-office interfaces showing user-submitted data

### Step 4: Trace User Input to Output Sinks

For each output point found, trace backward to determine if user-controlled data reaches it:
- HTTP request parameters (query string, POST body, headers, cookies)
- Database records originally sourced from user input
- File content uploaded by users
- Third-party API responses that may relay user data
- URL path segments
- WebSocket message content

### Step 5: Check Content-Security-Policy Headers

Examine CSP configuration for effectiveness against XSS:

```bash
# Search for CSP headers in server configuration
grep -rn "Content-Security-Policy" --include="*.conf" --include="*.config" --include="*.json" --include="*.yaml" --include="*.yml"
grep -rn "content_security_policy\|csp" --include="*.rb" --include="*.py" --include="*.js" --include="*.ts"

# Check for meta tag CSP
grep -rn "http-equiv.*Content-Security-Policy" --include="*.html"
```

Look for weaknesses: `unsafe-inline`, `unsafe-eval`, overly broad `script-src`, missing `default-src`.

### Step 6: Audit JavaScript for DOM Manipulation with User Data

Trace data flow from sources to sinks in client-side JavaScript. Pay special attention to:
- Event handlers receiving `postMessage` data without origin validation
- Code parsing URL fragments or query parameters for DOM updates
- Local/session storage reads rendered into DOM
- Third-party library callbacks inserting data into DOM

### Step 7: Check Cookie Security Flags

```bash
# Search for cookie-setting code
grep -rn "Set-Cookie\|setCookie\|set_cookie\|cookie\s*=" --include="*.js" --include="*.ts" --include="*.py" --include="*.rb" --include="*.java" --include="*.php" --include="*.cs"
grep -rn "httponly\|HttpOnly\|http_only" --include="*.js" --include="*.ts" --include="*.py" --include="*.rb" --include="*.java" --include="*.conf"
grep -rn "secure\s*[=:]\s*true\|Secure" --include="*.js" --include="*.ts" --include="*.py" --include="*.rb"
grep -rn "samesite\|SameSite\|same_site" --include="*.js" --include="*.ts" --include="*.py" --include="*.rb"
```

---

## Common Sinks and Sources by Framework

### React

| Pattern | Type | Risk |
|---------|------|------|
| `dangerouslySetInnerHTML={{__html: data}}` | Sink | Critical |
| `ref.current.innerHTML = data` | Sink | Critical |
| `<a href={userUrl}>` | Sink | High (if `javascript:` not blocked) |
| `window.__INITIAL_STATE__` | Source | Medium (server-rendered state) |
| `useSearchParams()` / `useParams()` | Source | Medium |

### Angular

| Pattern | Type | Risk |
|---------|------|------|
| `bypassSecurityTrustHtml(data)` | Sink | Critical |
| `bypassSecurityTrustScript(data)` | Sink | Critical |
| `bypassSecurityTrustUrl(data)` | Sink | High |
| `bypassSecurityTrustResourceUrl(data)` | Sink | High |
| `ElementRef.nativeElement.innerHTML` | Sink | Critical |
| `[innerHTML]="data"` | Sink | Medium (sanitized by default) |
| `ActivatedRoute.params` | Source | Medium |
| `ActivatedRoute.queryParams` | Source | Medium |

### Vue.js

| Pattern | Type | Risk |
|---------|------|------|
| `v-html="data"` | Sink | Critical |
| `v-bind:href="data"` / `:href="data"` | Sink | High (if `javascript:` not blocked) |
| `$route.query` / `$route.params` | Source | Medium |
| `$refs.el.innerHTML` | Sink | Critical |

### jQuery

| Pattern | Type | Risk |
|---------|------|------|
| `.html(data)` | Sink | Critical |
| `.append(data)` / `.prepend(data)` | Sink | High |
| `.after(data)` / `.before(data)` | Sink | High |
| `$(data)` where data starts with `<` | Sink | Critical |
| `.attr("onclick", data)` | Sink | Critical |
| `$.globalEval(data)` | Sink | Critical |

### Server-Side

| Framework | Vulnerable Pattern | Safe Alternative |
|-----------|--------------------|------------------|
| Flask/Jinja2 | `{{ data\|safe }}` | `{{ data }}` (auto-escaped) |
| Django | `{{ data\|safe }}`, `mark_safe(data)` | `{{ data }}` |
| Rails/ERB | `raw(data)`, `data.html_safe`, `<%== data %>` | `<%= data %>` |
| Express/EJS | `<%- data %>` | `<%= data %>` |
| ASP.NET Razor | `@Html.Raw(data)` | `@data` (auto-encoded) |
| Go html/template | Using `text/template` instead | Use `html/template` |
| PHP | `echo $data` | `echo htmlspecialchars($data, ENT_QUOTES, 'UTF-8')` |
| Java JSP | `<%= data %>` | `<c:out value="${data}"/>` or JSTL fn:escapeXml |

---

## False Positive Indicators

When evaluating potential XSS findings, consider these factors that reduce or eliminate risk:

1. **Content is placed inside `<script type="application/json">`**: Data rendered as JSON within
   a non-executable script type is not directly exploitable, provided `</script>` sequences are
   escaped in the data. Verify that `</` is encoded as `<\/` or `\u003c/`.

2. **Output is HTML-entity encoded before insertion**: If the framework or manual encoding
   properly converts `<`, `>`, `"`, `'`, and `&` to their HTML entity equivalents (`&lt;`,
   `&gt;`, `&quot;`, `&#x27;`, `&amp;`), the output is safe in HTML body and attribute contexts.

3. **Framework auto-escaping is active and not bypassed**: React JSX expressions, Angular
   interpolation `{{ }}`, Vue double-brace `{{ }}`, and Django/Jinja2 default mode all
   auto-escape. Confirm no `|safe`, `dangerouslySetInnerHTML`, `bypassSecurityTrust*`, or
   `v-html` is used on the same data.

4. **Content-Security-Policy with strict nonce or hash**: A CSP with `script-src 'nonce-...'` or
   `script-src 'sha256-...'` and **no** `unsafe-inline` effectively mitigates most XSS even if
   a vulnerability exists. However, CSP should be defense-in-depth, not a replacement for fixing
   the root cause.

5. **Output context does not allow script execution**: Data rendered as the text content of an
   element (not inside attributes, not inside `<script>`, not inside event handlers) with proper
   encoding is generally safe.

6. **Sanitization with DOMPurify or equivalent**: When user HTML is intentionally rendered (e.g.,
   rich text editors), use of a proven sanitizer like DOMPurify with default configuration is
   acceptable. Verify:
   - DOMPurify is up-to-date (check for known bypasses in older versions)
   - Configuration does not whitelist dangerous tags/attributes
   - Sanitization occurs on the **rendering** side, not just on input

7. **Server-side HTML sanitization with allowlist approach**: Libraries like `bleach` (Python),
   `sanitize-html` (Node.js), or `Jsoup` (Java) using strict allowlists are generally safe.

8. **Static content not derived from user input**: HTML that is entirely developer-authored
   (hardcoded strings, static templates) is not vulnerable to XSS, even if it uses `innerHTML`
   or similar sinks.

---

## Severity Assessment

### Critical Severity
- Stored XSS on widely-viewed pages (home page, public feed, comment sections)
- Stored XSS in admin dashboards that could lead to privilege escalation
- No Content-Security-Policy in place
- XSS in authentication flows (login pages, OAuth callbacks)
- Wormable XSS (payload can propagate to other users automatically)

### High Severity
- Reflected XSS in pages with no CSP or weak CSP (`unsafe-inline`)
- Stored XSS with CSP present but bypassable
- DOM-based XSS with no user interaction required (auto-triggered via URL)
- XSS in applications handling sensitive data (banking, healthcare, PII)
- XSS allowing exfiltration of anti-CSRF tokens

### Medium Severity
- DOM-based XSS requiring user interaction beyond clicking a link
- Reflected XSS with partial CSP protection (mitigates some but not all payloads)
- XSS in authenticated-only areas with moderate user base
- XSS that requires specific browser or non-default configuration to exploit
- Stored XSS in low-traffic areas with CSP mitigation

### Low Severity
- Self-XSS (user can only attack themselves — e.g., payload in own profile visible only to self)
- XSS in admin panels with a very small, trusted user base and strong CSP
- XSS in non-production environments (staging, dev) accessible only internally
- XSS mitigated by multiple layers (CSP + HttpOnly cookies + SameSite)
- Theoretical XSS that requires unrealistic payload delivery

---

## Remediation Patterns

### Context-Aware Output Encoding

The correct encoding depends on where the data is inserted:

| Output Context | Encoding Required | Example |
|---------------|-------------------|---------|
| HTML body | HTML entity encoding | `&lt;script&gt;` |
| HTML attribute | HTML attribute encoding | `&quot; onmouseover=` → `&quot; onmouseover=` |
| JavaScript string | JavaScript string encoding | `\x3cscript\x3e` |
| URL parameter | URL/percent encoding | `%3Cscript%3E` |
| CSS value | CSS hex encoding | `\3c script\3e` |

### Framework-Specific Safe Patterns

**React** (safe by default):
```jsx
// SAFE — React auto-escapes JSX expressions
function Comment({ body }) {
    return <div>{body}</div>;  // Automatically escaped
}

// SAFE — if HTML rendering needed, sanitize first
import DOMPurify from "dompurify";
function RichComment({ body }) {
    return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(body) }} />;
}

// SAFE — validate URLs against javascript: protocol
function SafeLink({ url, label }) {
    const safeUrl = url.match(/^https?:\/\//) ? url : "#";
    return <a href={safeUrl}>{label}</a>;
}
```

**Angular** (safe by default):
```typescript
// SAFE — Angular's built-in sanitizer handles interpolation
@Component({
    template: `<div>{{ userContent }}</div>`  // Auto-sanitized
})

// SAFE — use Angular's sanitizer instead of bypassing it
import { DomSanitizer, SafeHtml } from "@angular/platform-browser";
// Only bypass sanitizer when input is already sanitized server-side
// and you fully control the data source
```

**Vue.js**:
```vue
<!-- SAFE — double-brace interpolation auto-escapes -->
<template>
    <div>{{ userComment }}</div>
</template>

<!-- SAFE — if raw HTML needed, sanitize first -->
<template>
    <div v-html="sanitizedComment"></div>
</template>
<script>
import DOMPurify from "dompurify";
export default {
    computed: {
        sanitizedComment() {
            return DOMPurify.sanitize(this.rawComment);
        }
    }
};
</script>
```

**Python (Flask/Jinja2)**:
```python
# SAFE — Jinja2 auto-escaping (default in Flask)
# Template: <div>{{ user_input }}</div>  — auto-escaped

# SAFE — if raw HTML needed, sanitize with bleach
import bleach
clean_html = bleach.clean(
    user_input,
    tags=["b", "i", "u", "a", "p", "br"],
    attributes={"a": ["href", "title"]},
    protocols=["http", "https"]
)
return render_template("page.html", content=Markup(clean_html))
```

**PHP**:
```php
<!-- SAFE — always use htmlspecialchars() with ENT_QUOTES -->
<p>Hello, <?= htmlspecialchars($name, ENT_QUOTES, 'UTF-8') ?></p>

<!-- SAFE — for rich content, use HTML Purifier -->
<?php
require_once 'HTMLPurifier.auto.php';
$config = HTMLPurifier_Config::createDefault();
$purifier = new HTMLPurifier($config);
$clean_html = $purifier->purify($user_input);
echo $clean_html;
?>
```

**Node.js (Express)**:
```javascript
// SAFE — use a template engine with auto-escaping (e.g., Handlebars, Pug default)
app.set("view engine", "pug");
app.get("/search", (req, res) => {
    res.render("search", { query: req.query.q });  // Pug auto-escapes with =
});

// SAFE — for API responses, set correct content type
app.get("/api/data", (req, res) => {
    res.json({ query: req.query.q });  // JSON response, not HTML
});

// SAFE — manual encoding if building HTML strings
const he = require("he");
app.get("/search", (req, res) => {
    res.send(`<p>Results for: ${he.encode(req.query.q)}</p>`);
});
```

**Java**:
```java
// SAFE — use JSTL escapeXml
// JSP: <c:out value="${param.name}" />
// JSP: ${fn:escapeXml(param.name)}

// SAFE — OWASP Java Encoder
import org.owasp.encoder.Encode;
String safe = Encode.forHtml(userInput);          // HTML body context
String safe = Encode.forHtmlAttribute(userInput); // HTML attribute context
String safe = Encode.forJavaScript(userInput);    // JavaScript context
String safe = Encode.forUriComponent(userInput);  // URL parameter context
String safe = Encode.forCssString(userInput);     // CSS context
```

### Content-Security-Policy Implementation

```
# Strict CSP with nonce (recommended)
Content-Security-Policy:
    default-src 'self';
    script-src 'nonce-{random}' 'strict-dynamic';
    style-src 'self' 'nonce-{random}';
    img-src 'self' data: https:;
    font-src 'self';
    connect-src 'self';
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
    object-src 'none';

# Hash-based CSP for static scripts
Content-Security-Policy:
    script-src 'sha256-{hash-of-script-content}';
```

**Express.js CSP with Helmet**:
```javascript
const helmet = require("helmet");
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
        styleSrc: ["'self'", "'unsafe-inline'"],  // Consider nonce for styles too
        imgSrc: ["'self'", "data:", "https:"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"]
    }
}));
```

### DOMPurify Usage

```javascript
import DOMPurify from "dompurify";

// Basic sanitization — removes all dangerous content
const clean = DOMPurify.sanitize(dirtyHtml);

// Allow specific tags and attributes only
const clean = DOMPurify.sanitize(dirtyHtml, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "a", "p", "br", "ul", "ol", "li"],
    ALLOWED_ATTR: ["href", "title", "target"],
    ALLOW_DATA_ATTR: false
});

// Prevent DOM clobbering
const clean = DOMPurify.sanitize(dirtyHtml, {
    SANITIZE_DOM: true       // Default: true — prevents DOM clobbering
});

// Return a DOM node instead of string (avoids double-parsing)
const cleanNode = DOMPurify.sanitize(dirtyHtml, { RETURN_DOM: true });
element.appendChild(cleanNode);

// Add hooks for custom processing
DOMPurify.addHook("afterSanitizeAttributes", (node) => {
    // Force all links to open in new tab safely
    if (node.tagName === "A") {
        node.setAttribute("target", "_blank");
        node.setAttribute("rel", "noopener noreferrer");
    }
});
```

### Cookie Security Flags

```
Set-Cookie: session_id=abc123; HttpOnly; Secure; SameSite=Strict; Path=/

# HttpOnly  — prevents JavaScript access (document.cookie), mitigates cookie theft via XSS
# Secure    — cookie sent only over HTTPS
# SameSite  — Strict: blocks cross-site requests entirely
#              Lax: allows top-level GET navigations (default in modern browsers)
```

**Express.js**:
```javascript
app.use(session({
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 3600000
    }
}));
```

**Django**:
```python
# settings.py
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
```

**Spring Boot**:
```yaml
# application.yml
server:
  servlet:
    session:
      cookie:
        http-only: true
        secure: true
        same-site: strict
```

---

## CWE References

| CWE ID | Name | Description |
|--------|------|-------------|
| [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Improper Neutralization of Input During Web Page Generation | The primary CWE for all XSS variants — covers reflected, stored, and DOM-based XSS. |
| [CWE-80](https://cwe.mitre.org/data/definitions/80.html) | Improper Neutralization of Script-Related HTML Tags | Specific to failure to sanitize HTML tags like `<script>`, `<img>`, `<iframe>` in user input. |
| [CWE-83](https://cwe.mitre.org/data/definitions/83.html) | Improper Neutralization of Script in Attributes | Covers XSS via HTML event handler attributes (e.g., `onmouseover`, `onerror`, `onfocus`). |
| [CWE-84](https://cwe.mitre.org/data/definitions/84.html) | Improper Neutralization of Encoded URI Schemes | Covers XSS via `javascript:`, `data:`, and `vbscript:` URI schemes in href/src attributes. |
| [CWE-87](https://cwe.mitre.org/data/definitions/87.html) | Improper Neutralization of Alternate XSS Syntax | Covers XSS payloads using non-standard syntax, encoding tricks, and parser differentials. |

### Related CWEs

| CWE ID | Name | Relevance |
|--------|------|-----------|
| [CWE-116](https://cwe.mitre.org/data/definitions/116.html) | Improper Encoding or Escaping of Output | Root cause — failure to encode data for the output context. |
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Improper Input Validation | Contributing factor — insufficient validation of user input. |
| [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | Cross-Site Request Forgery (CSRF) | Often chained with XSS — XSS can bypass CSRF protections. |

---

## Additional Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [OWASP Testing Guide — XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [DOMPurify GitHub](https://github.com/cure53/DOMPurify)
- [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/)
