# Security Review: vulnapp

## Scope

Static security review of all Python application modules, configuration, requirements, and Jinja/CSS/README files in the repository.

- Scan mode: repository
- Target kind: directory\_snapshot
- Target ID: target\_sha256\_ef2252f615f432796da4b01da6fb37e646917a021a731eca58e627df5de086a6
- Snapshot digest: codex-security-snapshot/v1:sha256:c5e25b1661b9991c059dd520c57d435e61aa7a87768cbef4a4a9c3fa99847392
- Included paths: .
- Excluded paths: none
- Artifacts reviewed: README.md, app.py, auth.py, config.py, pictures.py, requirements.txt, run.sh, base.jinja2, directory.jinja2, signin.jinja2, signup.jinja2, style.css
- Scan context: User requested a security scan of this repository. Scope is the full workspace.

Limitations and exclusions:
- No independent baseline reviewer was used.
- Deployment topology, filesystem permissions, and internal network reachability were not provided.
- favicon.ico was inventoried but not reviewed as executable or configuration source.
- Excluded favicon.ico: Excluded from review

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 4 |
| Severity mix | high: 1, medium: 3 |
| Confidence mix | high: 4 |
| Validation mode | Static source trace with offline validation. |

Canonical artifacts: `scan-manifest.json` and `findings.json`. This report is a deterministic projection of those files.

## Threat Model

A small Flask web application supports signup, signin, a user directory, and employee lookup and profile-picture HTTP fetches. Flask signed-cookie sessions identify a user; SQLAlchemy stores user data; Jinja templates render the directory and forms. Evidence: app.py:19-21, 53-65, 68-97, 107-148; auth.py:8-34; pictures.py:8-14.

### Assets

- User identities and password hashes in the SQLite database (app.py:27-34).
- User profile information and email addresses exposed by the directory (app.py:55-63; directory.jinja2:17-26).
- Integrity of the Flask session cookie and the authenticated user identity (config.py:11,23,38; auth.py:26-34).
- Local filesystem contents reachable by the catch-all route (app.py:151-159).

### Trust Boundaries

- Unauthenticated HTTP clients submit signup/signin forms and choose picture URLs (app.py:68-97,107-148; signup.jinja2:18-27).
- The app makes server-side HTTP requests to employee lookup and user-selected picture URLs (auth.py:8-15; pictures.py:8-14).
- Authenticated sessions reach the directory; the current user's limited flag controls email display, while all user records are rendered (app.py:53-63; directory.jinja2:17-26).
- The catch-all route accepts paths from HTTP requests and passes them to send\_file without an evident path allowlist (app.py:151-159).

### Attacker Capabilities

- An unauthenticated client can submit arbitrary form values and HTTP paths; signup is available without an invitation (app.py:107-148).
- A signed-up user can submit a picture URL that the server fetches (signup.jinja2:24-25; app.py:131-134; pictures.py:8-14).
- Source readers know the hardcoded Flask SECRET\_KEY values in config.py:6-23.

### Security Objectives

- Only authenticated users should access the directory and session identity should not be forgeable by outsiders (app.py:53-65; config.py:11,23,38; auth.py:26-34).
- User-controlled names, biographies, and messages must be safely encoded when rendered (app.py:73-89,110-120; directory.jinja2:17-26; signin.jinja2:9-16).
- Only intended local assets should be served; request paths must not grant arbitrary local file reads (app.py:151-159).
- User-selected remote URLs should not let callers access protected internal network resources or create unbounded server-side fetches (pictures.py:8-14).

### Assumptions

- Deployment configuration and network reachability are not provided. Production API hosts and internal-service impact are conditional on deployment.
- Templates use the .jinja2 extension; Flask 0.12.2 is pinned in requirements.txt. Flask's default autoescape selection covers .html/.htm/.xml/.xhtml/.svg and not .jinja2.
- No SECURITY.md policy applies to this repository. Review was static and offline; application code was not executed.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [Read arbitrary local files through the catch-all route](#finding-1) | high | high | inline below |
| [Execute stored script from user profile fields in the directory](#finding-2) | medium | high | inline below |
| [Forge Flask sessions with the committed signing key](#finding-3) | medium | high | inline below |
| [Fetch attacker-selected URLs from the application server](#finding-4) | medium | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Read arbitrary local files through the catch-all route

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | The path converter captures arbitrary path segments and the handler passes the captured value directly to send\_file without an allowlist or safe root constraint. |
| Category | Path traversal |
| CWE | CWE-22 |
| Affected lines | app.py:151-159 |

#### Summary

An unauthenticated caller can supply a filesystem path to send\_file and read files available to the application process, including local configuration or other readable data.

#### Root Cause

The catch-all route uses a path converter and forwards its value directly to send\_file. No safe-join, fixed asset root, or extension allowlist prevents traversal into other files readable by the app process.

**Catch-all route accepts caller path** — `app.py:151-158`

The path converter supplies the requested path to this route for arbitrary URL paths, without an authentication check.

```python
@app.route("/<path:path>")
def catch_all(path: str):
    """
    Serve static assets like favicion.ico

    :param path: asset path
    :return: file
    """
```

**Caller path passed to send\_file** — `app.py:159`

The handler uses the request-controlled path as the file to send and does not constrain it to an asset directory.

```python
return send_file(path)
```

#### Validation

The route accepts a URL path and forwards it unchanged to the file response helper; no path validation or authentication is present.

Validation method: Static source trace

**Catch-all route accepts caller path** — `app.py:151-158`

The path converter supplies the requested path to this route for arbitrary URL paths, without an authentication check.

```python
@app.route("/<path:path>")
def catch_all(path: str):
    """
    Serve static assets like favicion.ico

    :param path: asset path
    :return: file
    """
```

**Caller path passed to send\_file** — `app.py:159`

The handler uses the request-controlled path as the file to send and does not constrain it to an asset directory.

```python
return send_file(path)
```

Assertions:
- The route accepts arbitrary path text using \<path:path\>.
- The path is passed directly to send\_file.
- The handler has no authorization or root-directory check.

Limitations:
- The exact operating-system files readable by the deployed process depend on deployment permissions.

#### Dataflow

HTTP URL path -\> catch\_all(path) -\> send\_file(path) -\> local file response

- **Source:** Unauthenticated request path

- **Sink:** Filesystem file opened by send\_file

- **Outcome:** Contents of a readable local file are returned to the caller

**Catch-all route accepts caller path** — `app.py:151-158`

The path converter supplies the requested path to this route for arbitrary URL paths, without an authentication check.

```python
@app.route("/<path:path>")
def catch_all(path: str):
    """
    Serve static assets like favicion.ico

    :param path: asset path
    :return: file
    """
```

**Caller path passed to send\_file** — `app.py:159`

The handler uses the request-controlled path as the file to send and does not constrain it to an asset directory.

```python
return send_file(path)
```

#### Reachability

The route is exposed without a login check; impact is limited by the app process's filesystem permissions.

- **Attacker:** Unauthenticated HTTP client

- **Entry point:** GET /\<path:path\>

- **Outcome:** Read local files accessible to the application process

Preconditions:
- A target file is readable by the application process.

Limitations:
- Deployment-specific filesystem permissions were not supplied.

**Catch-all route accepts caller path** — `app.py:151-158`

The path converter supplies the requested path to this route for arbitrary URL paths, without an authentication check.

```python
@app.route("/<path:path>")
def catch_all(path: str):
    """
    Serve static assets like favicion.ico

    :param path: asset path
    :return: file
    """
```

**Caller path passed to send\_file** — `app.py:159`

The handler uses the request-controlled path as the file to send and does not constrain it to an asset directory.

```python
return send_file(path)
```

#### Severity

**High** — The route is unauthenticated and passes a request-controlled path directly to a file-opening response helper. This grants local file disclosure; exposed files may include credentials or application data.

Additional runtime or deployment evidence could raise or lower this severity.

Impact assessment:
- **Level:** high
- **Why:** Arbitrary local file disclosure can expose application configuration, credentials, or data readable by the process.

Likelihood assessment:
- **Level:** high
- **Why:** The request-controlled route directly invokes the file-serving sink without a path boundary.

#### Remediation

Serve only an explicit allowlist of static assets from a fixed directory, resolving paths with a safe join and rejecting any result outside that directory.

Tests:
- Request traversal paths and verify the server rejects them.
- Verify approved static assets remain available.

Preventive controls:
- Use Flask's static-file serving mechanism for known assets instead of a generic filesystem path route.

<a id="finding-2"></a>

### [2] Execute stored script from user profile fields in the directory

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Signup persists caller-controlled name and bio values, the directory renders them, and Flask's default autoescape extensions do not include .jinja2. |
| Category | Cross-site scripting |
| CWE | CWE-79 |
| Affected lines | app.py:110-120, directory.jinja2:17-26, requirements.txt:2 |

#### Summary

A user can store HTML or JavaScript in the name or bio fields, and directory visitors receive it unescaped because the rendered templates use the unrecognized .jinja2 suffix with Flask 0.12.2's default autoescape selection.

#### Root Cause

Signup stores untrusted name and bio values, then directory.jinja2 interpolates them into HTML. Flask's default autoescape selection does not recognize the .jinja2 suffix used by these templates, so a profile can inject executable markup.

**Signup accepts attacker-controlled profile text** — `app.py:110-120`

An unauthenticated signup request supplies name and bio, which are stored on the newly created user without sanitization.

```python
user = User.create(
    email=request.form.get("email"),
    bio=request.form.get("bio"),
    name=request.form.get("name"),
    password_hash=auth.hash_password(
        request.form.get("password"),
        app.config.get("BCRYPT_SALT"),
    ),
)
```

**Templates use .jinja2 extension** — `app.py:19-20`

Flask uses its default template autoescape selector; the templates are named .jinja2 rather than one of the default HTML extensions.

```python
app = Flask(__name__, template_folder="./")
configure(app)
```

**Pinned Flask version** — `requirements.txt:2`

The repository pins Flask 0.12.2, whose default template autoescape extensions exclude .jinja2.

```text
Flask==0.12.2
```

**Directory renders stored fields** — `directory.jinja2:17-26`

The directory interpolates stored profile fields into HTML. With this template suffix Flask does not enable its default autoescape, so markup from a profile is emitted as active HTML.

```jinja2
{% for user in users %}
    <div class="col-md-4">
        <div class="card mb-4 box-shadow">
            <img class="card-img-top img-responsive" src="{{ user.picture }}" data-holder-rendered="true">
            <div class="card-body">
                <p class="card-text font-weight-bold">{{ user.name }}</p>
                <p class="card-text">{{ user.bio }}</p>
```

#### Validation

Traced signup form values to database fields and the directory template. The template suffix is not covered by Flask 0.12.2's default autoescape extensions, and no explicit escaping is present.

Validation method: Static source trace

**Signup accepts attacker-controlled profile text** — `app.py:110-120`

An unauthenticated signup request supplies name and bio, which are stored on the newly created user without sanitization.

```python
user = User.create(
    email=request.form.get("email"),
    bio=request.form.get("bio"),
    name=request.form.get("name"),
    password_hash=auth.hash_password(
        request.form.get("password"),
        app.config.get("BCRYPT_SALT"),
    ),
)
```

**Templates use .jinja2 extension** — `app.py:19-20`

Flask uses its default template autoescape selector; the templates are named .jinja2 rather than one of the default HTML extensions.

```python
app = Flask(__name__, template_folder="./")
configure(app)
```

**Pinned Flask version** — `requirements.txt:2`

The repository pins Flask 0.12.2, whose default template autoescape extensions exclude .jinja2.

```text
Flask==0.12.2
```

**Directory renders stored fields** — `directory.jinja2:17-26`

The directory interpolates stored profile fields into HTML. With this template suffix Flask does not enable its default autoescape, so markup from a profile is emitted as active HTML.

```jinja2
{% for user in users %}
    <div class="col-md-4">
        <div class="card mb-4 box-shadow">
            <img class="card-img-top img-responsive" src="{{ user.picture }}" data-holder-rendered="true">
            <div class="card-body">
                <p class="card-text font-weight-bold">{{ user.name }}</p>
                <p class="card-text">{{ user.bio }}</p>
```

Assertions:
- Signup stores name and bio directly from request.form.
- The directory renders both values in HTML contexts.
- The templates use .jinja2 and contain no explicit escaping filter.

Limitations:
- The finding is based on Flask 0.12.2's documented/default selector behavior and source; the app was not executed.

#### Dataflow

Signup form name/bio -\> User.create() -\> directory query -\> unescaped Jinja interpolation -\> victim browser

- **Source:** Unauthenticated signup fields name and bio

- **Sink:** HTML response rendered by directory.jinja2

- **Outcome:** Script executes in the origin of the application for directory visitors

**Signup accepts attacker-controlled profile text** — `app.py:110-120`

An unauthenticated signup request supplies name and bio, which are stored on the newly created user without sanitization.

```python
user = User.create(
    email=request.form.get("email"),
    bio=request.form.get("bio"),
    name=request.form.get("name"),
    password_hash=auth.hash_password(
        request.form.get("password"),
        app.config.get("BCRYPT_SALT"),
    ),
)
```

**Directory renders stored fields** — `directory.jinja2:17-26`

The directory interpolates stored profile fields into HTML. With this template suffix Flask does not enable its default autoescape, so markup from a profile is emitted as active HTML.

```jinja2
{% for user in users %}
    <div class="col-md-4">
        <div class="card mb-4 box-shadow">
            <img class="card-img-top img-responsive" src="{{ user.picture }}" data-holder-rendered="true">
            <div class="card-body">
                <p class="card-text font-weight-bold">{{ user.name }}</p>
                <p class="card-text">{{ user.bio }}</p>
```

#### Reachability

Signup is available without an invitation; the stored profile renders whenever an authenticated user views the directory.

- **Attacker:** Unauthenticated prospective user

- **Entry point:** POST /signup

- **Outcome:** Run script in another directory visitor's browser session

Preconditions:
- A victim is authenticated and visits the directory after the malicious profile is stored.

Limitations:
- No privileged application actions were found in the reviewed routes, limiting the demonstrated impact to the app's own data and session.

**Signup accepts attacker-controlled profile text** — `app.py:110-120`

An unauthenticated signup request supplies name and bio, which are stored on the newly created user without sanitization.

```python
user = User.create(
    email=request.form.get("email"),
    bio=request.form.get("bio"),
    name=request.form.get("name"),
    password_hash=auth.hash_password(
        request.form.get("password"),
        app.config.get("BCRYPT_SALT"),
    ),
)
```

**Directory renders stored fields** — `directory.jinja2:17-26`

The directory interpolates stored profile fields into HTML. With this template suffix Flask does not enable its default autoescape, so markup from a profile is emitted as active HTML.

```jinja2
{% for user in users %}
    <div class="col-md-4">
        <div class="card mb-4 box-shadow">
            <img class="card-img-top img-responsive" src="{{ user.picture }}" data-holder-rendered="true">
            <div class="card-body">
                <p class="card-text font-weight-bold">{{ user.name }}</p>
                <p class="card-text">{{ user.bio }}</p>
```

#### Severity

**Medium** — An attacker can create an account and cause script execution in other authenticated users' browsers when they view the directory. This enables actions in victims' sessions, but the reviewed application exposes a narrow directory interface.

Additional runtime or deployment evidence could raise or lower this severity.

Impact assessment:
- **Level:** medium
- **Why:** Same-origin script can act through a victim's session and access directory content; no broader privileged interface was identified.

Likelihood assessment:
- **Level:** high
- **Why:** Profile fields are attacker-controlled and rendered on the directory page without autoescaping.

#### Remediation

Enable autoescaping for .jinja2 templates or rename templates to an autoescaped HTML suffix, and keep contextual escaping enabled for all untrusted profile and flash-message values.

Tests:
- Store HTML and JavaScript payloads in name and bio and verify they render as text.
- Verify flash messages containing submitted values cannot create HTML elements or execute script.

Preventive controls:
- Enable Jinja autoescaping for every template rendered as HTML.
- Avoid interpolating untrusted values into HTML without contextual escaping.

<a id="finding-3"></a>

### [3] Forge Flask sessions with the committed signing key

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | The production config assigns a fixed key, configure() installs it as Flask's session signing key, and authenticated identity is read directly from the signed session. |
| Category | Hard-coded cryptographic key |
| CWE | CWE-321 |
| Affected lines | config.py:20-23, auth.py:26-34, app.py:53-63 |

#### Summary

A source reader can sign a Flask session containing another user's ID and access the authenticated directory as that user. The production and default signing keys are committed in config.py.

#### Root Cause

The production secret used to authenticate Flask's client-side session cookie is a fixed repository value. Because auth.get\_user\_id() trusts the signed session's user\_id, repository readers can create a valid cookie for an existing user.

**Committed production key** — `config.py:20-23`

The production configuration uses a fixed signing key embedded in the source, so anyone who can read this repository can create valid Flask session signatures.

```python
class ProductionConfig(BaseConfig):
    DEBUG = False
    EMPLOYEE_API_URL = "http://directory.nginx.service/lookup/"
    SECRET_KEY = "s337eH1wD9rb42dIb4QsfcTghAWLE5c2DIt3ROpVjv4="
```

**Install key into Flask** — `config.py:34-38`

Application setup installs the selected hardcoded SECRET\_KEY into Flask, where its signed-cookie session implementation uses it.

```python
def configure(app: Flask):
    app.config.from_object(
        config_map.get(os.getenv("FLASK_ENV"), config_map["default"])
    )
    app.secret_key = app.config.get("SECRET_KEY")
```

**Session value controls identity** — `auth.py:26-34`

The application trusts the user\_id stored in the signed session as the authenticated identity; with the known key an attacker can forge that value.

```python
def get_user_id() -> int:
    return session.get("user_id")


def set_user(user_id: Optional[int]):
    if user_id:
        session["user_id"] = user_id
```

**Directory trusts session identity** — `app.py:53-63`

A forged user\_id that matches a database row passes the route's authentication check and renders the directory as that user.

```python
@app.route("/")
def index():
    user = User.query.filter_by(id=auth.get_user_id()).first()
    users = User.query.all()
    if user:
        return render_template(
            "directory.jinja2",
            title="Directory",
            current_user=user,
            users=users,
        )
```

#### Validation

Followed the committed ProductionConfig key through Flask configuration into the signed session identity read and the directory authentication gate.

Validation method: Static source trace

**Committed production key** — `config.py:20-23`

The production configuration uses a fixed signing key embedded in the source, so anyone who can read this repository can create valid Flask session signatures.

```python
class ProductionConfig(BaseConfig):
    DEBUG = False
    EMPLOYEE_API_URL = "http://directory.nginx.service/lookup/"
    SECRET_KEY = "s337eH1wD9rb42dIb4QsfcTghAWLE5c2DIt3ROpVjv4="
```

**Install key into Flask** — `config.py:34-38`

Application setup installs the selected hardcoded SECRET\_KEY into Flask, where its signed-cookie session implementation uses it.

```python
def configure(app: Flask):
    app.config.from_object(
        config_map.get(os.getenv("FLASK_ENV"), config_map["default"])
    )
    app.secret_key = app.config.get("SECRET_KEY")
```

**Session value controls identity** — `auth.py:26-34`

The application trusts the user\_id stored in the signed session as the authenticated identity; with the known key an attacker can forge that value.

```python
def get_user_id() -> int:
    return session.get("user_id")


def set_user(user_id: Optional[int]):
    if user_id:
        session["user_id"] = user_id
```

**Directory trusts session identity** — `app.py:53-63`

A forged user\_id that matches a database row passes the route's authentication check and renders the directory as that user.

```python
@app.route("/")
def index():
    user = User.query.filter_by(id=auth.get_user_id()).first()
    users = User.query.all()
    if user:
        return render_template(
            "directory.jinja2",
            title="Directory",
            current_user=user,
            users=users,
        )
```

Assertions:
- ProductionConfig defines SECRET\_KEY in source.
- configure() installs that value into Flask.
- The directory route grants access when a database user matches the session user\_id.

Counterevidence and remaining uncertainty:
- The review found no administrative mutation routes; impact is limited to the data and capabilities of this application's directory.

Limitations:
- Deployment reachability and the sensitivity of individual directory records were not provided.

#### Dataflow

config.py ProductionConfig.SECRET\_KEY -\> Flask app.secret\_key -\> signed session user\_id -\> auth.get\_user\_id() -\> directory access

- **Source:** Hardcoded production session signing key

- **Sink:** Flask signed-cookie authentication check

- **Outcome:** Access to the directory as the chosen existing user

**Committed production key** — `config.py:20-23`

The production configuration uses a fixed signing key embedded in the source, so anyone who can read this repository can create valid Flask session signatures.

```python
class ProductionConfig(BaseConfig):
    DEBUG = False
    EMPLOYEE_API_URL = "http://directory.nginx.service/lookup/"
    SECRET_KEY = "s337eH1wD9rb42dIb4QsfcTghAWLE5c2DIt3ROpVjv4="
```

**Install key into Flask** — `config.py:34-38`

Application setup installs the selected hardcoded SECRET\_KEY into Flask, where its signed-cookie session implementation uses it.

```python
def configure(app: Flask):
    app.config.from_object(
        config_map.get(os.getenv("FLASK_ENV"), config_map["default"])
    )
    app.secret_key = app.config.get("SECRET_KEY")
```

**Session value controls identity** — `auth.py:26-34`

The application trusts the user\_id stored in the signed session as the authenticated identity; with the known key an attacker can forge that value.

```python
def get_user_id() -> int:
    return session.get("user_id")


def set_user(user_id: Optional[int]):
    if user_id:
        session["user_id"] = user_id
```

**Directory trusts session identity** — `app.py:53-63`

A forged user\_id that matches a database row passes the route's authentication check and renders the directory as that user.

```python
@app.route("/")
def index():
    user = User.query.filter_by(id=auth.get_user_id()).first()
    users = User.query.all()
    if user:
        return render_template(
            "directory.jinja2",
            title="Directory",
            current_user=user,
            users=users,
        )
```

#### Reachability

Any actor who can read the repository and reach the application can forge a session; the target user ID must exist.

- **Attacker:** Repository source reader

- **Entry point:** HTTP GET /

- **Outcome:** Read the directory as another user

Preconditions:
- The application uses the included production configuration.
- A target user row exists.

Limitations:
- No routes with privileged write actions were found in the reviewed source.

**Committed production key** — `config.py:20-23`

The production configuration uses a fixed signing key embedded in the source, so anyone who can read this repository can create valid Flask session signatures.

```python
class ProductionConfig(BaseConfig):
    DEBUG = False
    EMPLOYEE_API_URL = "http://directory.nginx.service/lookup/"
    SECRET_KEY = "s337eH1wD9rb42dIb4QsfcTghAWLE5c2DIt3ROpVjv4="
```

**Directory trusts session identity** — `app.py:53-63`

A forged user\_id that matches a database row passes the route's authentication check and renders the directory as that user.

```python
@app.route("/")
def index():
    user = User.query.filter_by(id=auth.get_user_id()).first()
    users = User.query.all()
    if user:
        return render_template(
            "directory.jinja2",
            title="Directory",
            current_user=user,
            users=users,
        )
```

#### Severity

**Medium** — A lower-trust source reader can bypass session authentication and read the directory as any selected user. The reviewed routes expose profile data and may expose all user email addresses depending on the selected user's limited flag; no more privileged account operations were found, so the impact is bounded to this application's directory.

Additional runtime or deployment evidence could raise or lower this severity.

Impact assessment:
- **Level:** medium
- **Why:** The attacker bypasses authentication and can read directory data, with email visibility depending on the selected account's limited flag.

Likelihood assessment:
- **Level:** high
- **Why:** The key is directly committed in the repository and the cookie identity is accepted without another authentication check.

#### Remediation

Load a unique, high-entropy SECRET\_KEY from a protected runtime secret source, rotate the exposed value, and invalidate existing session cookies.

Tests:
- Verify the production configuration has no source-controlled signing key.
- Verify a cookie signed with the retired key is rejected after rotation.

Preventive controls:
- Keep deployment secrets outside source control and fail startup when a required production secret is missing.

<a id="finding-4"></a>

### [4] Fetch attacker-selected URLs from the application server

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | The signup handler forwards the submitted picture value to requests.get without destination validation; successful response bytes are written to a local file and that path is rendered in the directory. |
| Category | Server-side request forgery |
| CWE | CWE-918 |
| Affected lines | app.py:131-134, pictures.py:8-14, directory.jinja2:17-21 |

#### Summary

During public signup, the server fetches the submitted picture URL without destination restrictions, a timeout, or response size limits. An attacker can make requests from the application network to internal services; fetched response bodies are stored and displayed as profile pictures.

#### Root Cause

Signup lets an unauthenticated requester choose a URL, and download\_picture() passes it to requests.get without restricting destinations. It persists the returned bytes and exposes the resulting path in the user directory.

**Signup forwards caller-selected picture URL** — `app.py:131-134`

The signup handler passes the picture URL directly from the unauthenticated request into the server-side downloader.

```python
picture=download_picture(
    request.form.get("picture"),
    pictures_dir=app.config.get("PICTURES_DIR"),
)
```

**Fetch any submitted URL** — `pictures.py:8-10`

The downloader makes an outbound request to the caller-selected URL without host/IP allowlisting, network blocking, or a timeout.

```python
def download_picture(url: Optional[str], pictures_dir: str):
    Path(pictures_dir).mkdir(exist_ok=True)
    res = requests.get(url)
```

**Persist remote response body** — `pictures.py:11-14`

The response body is stored locally under the user's profile and the returned filename is used as the picture value.

```python
filename = Path(pictures_dir) / f"{uuid4()}.jpg"
with open(filename, "wb") as fp:
    fp.write(res.content)
return str(filename)
```

**Render downloaded file as a picture** — `directory.jinja2:17-21`

The directory publishes the stored filename as an image URL, making fetched response bytes retrievable through the app's file-serving route.

```jinja2
{% for user in users %}
    <div class="col-md-4">
        <div class="card mb-4 box-shadow">
            <img class="card-img-top img-responsive" src="{{ user.picture }}" data-holder-rendered="true">
```

#### Validation

Followed the submitted picture URL from signup to requests.get(), then followed response bytes to the saved profile path and directory image element.

Validation method: Static source trace

**Signup forwards caller-selected picture URL** — `app.py:131-134`

The signup handler passes the picture URL directly from the unauthenticated request into the server-side downloader.

```python
picture=download_picture(
    request.form.get("picture"),
    pictures_dir=app.config.get("PICTURES_DIR"),
)
```

**Fetch any submitted URL** — `pictures.py:8-10`

The downloader makes an outbound request to the caller-selected URL without host/IP allowlisting, network blocking, or a timeout.

```python
def download_picture(url: Optional[str], pictures_dir: str):
    Path(pictures_dir).mkdir(exist_ok=True)
    res = requests.get(url)
```

**Persist remote response body** — `pictures.py:11-14`

The response body is stored locally under the user's profile and the returned filename is used as the picture value.

```python
filename = Path(pictures_dir) / f"{uuid4()}.jpg"
with open(filename, "wb") as fp:
    fp.write(res.content)
return str(filename)
```

**Render downloaded file as a picture** — `directory.jinja2:17-21`

The directory publishes the stored filename as an image URL, making fetched response bytes retrievable through the app's file-serving route.

```jinja2
{% for user in users %}
    <div class="col-md-4">
        <div class="card mb-4 box-shadow">
            <img class="card-img-top img-responsive" src="{{ user.picture }}" data-holder-rendered="true">
```

Assertions:
- The request's picture field is forwarded without validation.
- requests.get() accepts the destination and has no timeout argument.
- Response bytes are persisted and their path is rendered in the directory.

Limitations:
- The app's deployed network egress and internal service reachability are unknown; only source-established request control is claimed.

#### Dataflow

POST /signup picture -\> download\_picture(url) -\> requests.get(url) -\> response body written under pictures\_dir -\> directory image path

- **Source:** Unauthenticated signup picture field

- **Sink:** Server-side requests.get() destination

- **Outcome:** Application network makes a request to the selected destination; response bytes are stored and published as the picture

**Signup forwards caller-selected picture URL** — `app.py:131-134`

The signup handler passes the picture URL directly from the unauthenticated request into the server-side downloader.

```python
picture=download_picture(
    request.form.get("picture"),
    pictures_dir=app.config.get("PICTURES_DIR"),
)
```

**Fetch any submitted URL** — `pictures.py:8-10`

The downloader makes an outbound request to the caller-selected URL without host/IP allowlisting, network blocking, or a timeout.

```python
def download_picture(url: Optional[str], pictures_dir: str):
    Path(pictures_dir).mkdir(exist_ok=True)
    res = requests.get(url)
```

**Persist remote response body** — `pictures.py:11-14`

The response body is stored locally under the user's profile and the returned filename is used as the picture value.

```python
filename = Path(pictures_dir) / f"{uuid4()}.jpg"
with open(filename, "wb") as fp:
    fp.write(res.content)
return str(filename)
```

**Render downloaded file as a picture** — `directory.jinja2:17-21`

The directory publishes the stored filename as an image URL, making fetched response bytes retrievable through the app's file-serving route.

```jinja2
{% for user in users %}
    <div class="col-md-4">
        <div class="card mb-4 box-shadow">
            <img class="card-img-top img-responsive" src="{{ user.picture }}" data-holder-rendered="true">
```

#### Reachability

The signup route invokes the downloader after creating a user, without an invitation or additional authorization.

- **Attacker:** Unauthenticated prospective user

- **Entry point:** POST /signup

- **Outcome:** Cause server-side requests to destinations reachable by the application

Preconditions:
- A destination reachable from the application responds to the request.

Limitations:
- No runtime deployment or network topology was provided.
- The downloader also lacks a timeout and response-size limit, but this report focuses on the unrestricted destination control.

**Signup forwards caller-selected picture URL** — `app.py:131-134`

The signup handler passes the picture URL directly from the unauthenticated request into the server-side downloader.

```python
picture=download_picture(
    request.form.get("picture"),
    pictures_dir=app.config.get("PICTURES_DIR"),
)
```

**Fetch any submitted URL** — `pictures.py:8-10`

The downloader makes an outbound request to the caller-selected URL without host/IP allowlisting, network blocking, or a timeout.

```python
def download_picture(url: Optional[str], pictures_dir: str):
    Path(pictures_dir).mkdir(exist_ok=True)
    res = requests.get(url)
```

#### Severity

**Medium** — An unauthenticated user can trigger server-side HTTP requests to destinations reachable by the app, creating an internal network access path. The exact internal resources reachable and their sensitivity depend on deployment, so the impact is bounded at Medium.

Additional runtime or deployment evidence could raise or lower this severity.

Impact assessment:
- **Level:** medium
- **Why:** The attacker gains an application-network request primitive and may expose returned response bytes through the profile image path; sensitive impact depends on deployment network reachability.

Likelihood assessment:
- **Level:** medium
- **Why:** The picture field is directly caller-controlled, but internal impact depends on the application's network environment.

#### Remediation

Validate and allowlist permitted schemes and destinations, block loopback/link-local/private and metadata addresses after DNS resolution and on redirects, and enforce network egress restrictions. Apply strict timeouts and response-size limits.

Tests:
- Reject loopback, private, link-local, and metadata service destinations, including redirects and DNS rebinding cases.
- Verify permitted public image downloads have bounded time and response size.

Preventive controls:
- Use an egress proxy or firewall policy that blocks application access to internal control-plane and metadata endpoints.
- Validate downloaded content type and size before persisting it.
