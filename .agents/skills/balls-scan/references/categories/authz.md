<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Codex-native BALLS workflow and evidence rules. -->

# Authorization Vulnerability Detection Skill

## Overview

Authorization determines **what an authenticated user is allowed to do**. It is fundamentally
different from authentication (which verifies *who* the user is). Authorization flaws occur when
an application fails to enforce that a user can only access resources and perform actions they
are permitted to. These vulnerabilities are categorized under **OWASP Top 10 A01:2021 — Broken
Access Control**, the #1 most critical web application security risk.

**Impact of authorization vulnerabilities:**

- **Data breach**: Unauthorized access to other users' PII, financial data, or medical records.
- **Privilege escalation**: Regular users gaining admin capabilities, modifying system settings,
  or deleting other users' accounts.
- **Data manipulation**: Unauthorized modification or deletion of resources belonging to other
  users or tenants.
- **Compliance violations**: GDPR, HIPAA, PCI-DSS, SOC 2 all mandate proper access controls.
- **Full system compromise**: Vertical privilege escalation can lead to complete takeover.

Authorization checks must be enforced **server-side, on every request, for every resource**. UI
hiding is not authorization. Client-side role checks are not authorization. Only server-side
enforcement counts.

## Required route and principal matrix

For each route and HTTP method, record the principal states that can reach it (anonymous, ordinary, limited, privileged, and service identity where present), the resource or action it touches, and the server-side authorization predicate. Trace object identifiers from the request through the lookup and mutation; verify ownership/tenant constraints are applied to the object actually loaded, not only to a menu, parent page, or client-supplied role. Include alternate routes, aliases, and methods that reach the same operation. Treat hidden UI as no control, but do not report a missing check until the full route-to-operation path shows the action is reachable by the lower-privilege principal.

When a permission flag is computed from a database, configuration, or service response, trace initialization, type/default handling, persistence, failure paths, and every later consumer. Keep the exact prerequisite and affected data/action explicit; do not generalize a single flag bypass into administrator access without evidence.

---

## Vulnerability Patterns

### 1. IDOR (Insecure Direct Object Reference)

IDOR occurs when an application exposes internal object identifiers (database IDs, filenames,
keys) in URLs or request parameters and fails to verify the requesting user is authorized to
access that specific object.

**Common misconception**: Using UUIDs instead of sequential IDs does NOT prevent IDOR. UUIDs are
harder to guess but are not an authorization mechanism. If a UUID leaks (in logs, URLs, emails,
API responses), the resource is still unprotected.

#### Python (Django) — Vulnerable

```python
# VULNERABLE: No ownership check — any authenticated user can access any profile
@login_required
def user_profile(request, user_id):
    profile = User.objects.get(id=user_id)  # Direct lookup by attacker-controlled ID
    return JsonResponse({"email": profile.email, "ssn": profile.ssn})

# VULNERABLE: UUID doesn't help if there's no ownership check
@login_required
def get_document(request, doc_uuid):
    doc = Document.objects.get(uuid=doc_uuid)  # Still no ownership verification
    return FileResponse(doc.file)
```

#### Python (Flask) — Vulnerable

```python
# VULNERABLE: Fetches any order by ID without checking ownership
@app.route("/api/orders/<int:order_id>")
@jwt_required()
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict())  # Missing: order.user_id == current_user.id
```

#### Python (FastAPI) — Vulnerable

```python
# VULNERABLE: Any authenticated user can fetch any invoice
@router.get("/invoices/{invoice_id}")
async def get_invoice(invoice_id: int, current_user: User = Depends(get_current_user)):
    invoice = await db.execute(select(Invoice).where(Invoice.id == invoice_id))
    return invoice.scalars().first()
    # Missing: .where(Invoice.owner_id == current_user.id)
```

#### Java (Spring) — Vulnerable

```java
// VULNERABLE: No ownership check on the account resource
@GetMapping("/api/accounts/{accountId}")
public ResponseEntity<Account> getAccount(@PathVariable Long accountId) {
    Account account = accountRepository.findById(accountId)
        .orElseThrow(() -> new ResourceNotFoundException("Account not found"));
    return ResponseEntity.ok(account);
    // Missing: verify account.getUserId().equals(currentUser.getId())
}
```

#### JavaScript (Express) — Vulnerable

```javascript
// VULNERABLE: req.params.id is attacker-controlled, no ownership check
router.get("/api/users/:id/profile", authenticate, async (req, res) => {
  const profile = await User.findById(req.params.id);
  res.json(profile); // Any authenticated user can view any profile
});
```

#### C# (ASP.NET) — Vulnerable

```csharp
// VULNERABLE: No ownership verification
[Authorize]
[HttpGet("api/patients/{patientId}")]
public async Task<IActionResult> GetPatient(int patientId)
{
    var patient = await _context.Patients.FindAsync(patientId);
    return Ok(patient); // Missing: patient.DoctorId == User.GetUserId()
}
```

#### Go — Vulnerable

```go
// VULNERABLE: No ownership check on the resource
func GetUserData(w http.ResponseWriter, r *http.Request) {
    userID := chi.URLParam(r, "userID")
    var user User
    db.First(&user, userID) // Fetches any user by attacker-supplied ID
    json.NewEncoder(w).Encode(user)
}
```

#### Ruby (Rails) — Vulnerable

```ruby
# VULNERABLE: Finds any record globally instead of scoping to current user
def show
  @document = Document.find(params[:id])  # No ownership check
end
```

#### PHP (Laravel) — Vulnerable

```php
// VULNERABLE: Direct lookup without authorization check
public function show($id)
{
    $order = Order::findOrFail($id); // Any user can view any order
    return response()->json($order);
}
```

**Detection grep patterns:**

```
# Find direct ID lookups from request parameters (potential IDOR)
findById\(req\.params
objects\.get\(id=request
\.find\(params\[:id\]
FindAsync\(.*[Ii]d\)
query\.get_or_404\(
\.First\(&.*,\s*\w*[Ii][Dd]\)
Model::findOrFail\(\$
```

---

### 2. Missing Function-Level Access Control

Endpoints that perform privileged operations but lack authorization checks. The application
relies on UI hiding (not showing the admin link) instead of server-side enforcement.

#### Python (Django) — Vulnerable

```python
# VULNERABLE: No @permission_required or @user_passes_test decorator
@login_required  # Only checks authentication, NOT authorization
def delete_user(request, user_id):
    User.objects.get(id=user_id).delete()
    return JsonResponse({"status": "deleted"})

# SECURE: Proper function-level access control
@login_required
@permission_required("users.delete_user", raise_exception=True)
def delete_user(request, user_id):
    User.objects.get(id=user_id).delete()
    return JsonResponse({"status": "deleted"})
```

#### Java (Spring) — Vulnerable

```java
// VULNERABLE: No @PreAuthorize or @Secured annotation
@PostMapping("/admin/users/delete")
public ResponseEntity<Void> deleteUser(@RequestBody DeleteUserRequest request) {
    userService.deleteUser(request.getUserId());
    return ResponseEntity.ok().build();
}

// SECURE: Proper role enforcement
@PreAuthorize("hasRole('ADMIN')")
@PostMapping("/admin/users/delete")
public ResponseEntity<Void> deleteUser(@RequestBody DeleteUserRequest request) {
    userService.deleteUser(request.getUserId());
    return ResponseEntity.ok().build();
}
```

#### JavaScript (Express) — Vulnerable

```javascript
// VULNERABLE: No role-checking middleware on admin route
router.post("/admin/config/update", authenticate, async (req, res) => {
  await Config.updateMany({}, req.body);
  res.json({ status: "updated" });
});

// SECURE: Role middleware enforced
router.post("/admin/config/update", authenticate, requireRole("admin"), async (req, res) => {
  await Config.updateMany({}, req.body);
  res.json({ status: "updated" });
});
```

#### JavaScript (NestJS) — Vulnerable

```typescript
// VULNERABLE: Missing @Roles() decorator
@Controller("admin")
@UseGuards(AuthGuard)
export class AdminController {
  @Delete("users/:id")
  async deleteUser(@Param("id") id: string) {
    return this.userService.delete(id);
  }
}

// SECURE: Role guard applied
@Controller("admin")
@UseGuards(AuthGuard, RolesGuard)
@Roles("admin")
export class AdminController {
  @Delete("users/:id")
  async deleteUser(@Param("id") id: string) {
    return this.userService.delete(id);
  }
}
```

#### C# (ASP.NET) — Vulnerable

```csharp
// VULNERABLE: [Authorize] without role specification on admin action
[Authorize]
[HttpPost("admin/system/reset")]
public async Task<IActionResult> ResetSystem()
{
    await _systemService.FullReset();
    return Ok();
}

// SECURE: Policy-based authorization
[Authorize(Policy = "RequireAdminRole")]
[HttpPost("admin/system/reset")]
public async Task<IActionResult> ResetSystem()
{
    await _systemService.FullReset();
    return Ok();
}
```

#### Go — Vulnerable

```go
// VULNERABLE: No role check middleware on admin handler
mux.HandleFunc("/admin/users/delete", authMiddleware(deleteUserHandler))

// SECURE: Admin middleware added
mux.HandleFunc("/admin/users/delete", authMiddleware(adminOnly(deleteUserHandler)))
```

#### Ruby (Rails) — Vulnerable

```ruby
# VULNERABLE: No before_action authorization on admin controller
class AdminController < ApplicationController
  before_action :authenticate_user!  # Auth only, no authz

  def destroy_user
    User.find(params[:id]).destroy
  end
end

# SECURE: Authorization callback present
class AdminController < ApplicationController
  before_action :authenticate_user!
  before_action :require_admin!

  def destroy_user
    User.find(params[:id]).destroy
  end
end
```

#### PHP (Laravel) — Vulnerable

```php
// VULNERABLE: Only 'auth' middleware, no role gate
Route::post('/admin/users/delete', [AdminController::class, 'deleteUser'])
    ->middleware('auth');

// SECURE: Role middleware applied
Route::post('/admin/users/delete', [AdminController::class, 'deleteUser'])
    ->middleware(['auth', 'role:admin']);
```

**Detection grep patterns:**

```
# Find admin routes/endpoints missing authorization decorators
/admin/.*@login_required    (should have @permission_required too)
/admin/.*authenticate       (should have requireRole too)
\.middleware\(['"]auth['"]\) (on admin routes, should include role)
@Authorize\].*admin         (should specify Roles or Policy)
```

---

### 3. Horizontal Privilege Escalation

A user accessing resources belonging to another user at the **same** privilege level. This is
a specific form of IDOR where the impact is cross-user data access.

#### Python (Django) — Vulnerable

```python
# VULNERABLE: User A can view User B's messages by changing the ID
@login_required
def get_messages(request, mailbox_id):
    messages = Message.objects.filter(mailbox_id=mailbox_id)
    return JsonResponse(list(messages.values()), safe=False)
    # Missing: Mailbox.objects.get(id=mailbox_id, owner=request.user)
```

#### Java (Spring) — Vulnerable

```java
// VULNERABLE: No scoping to current user's resources
@GetMapping("/api/projects/{projectId}/files")
public List<ProjectFile> getFiles(@PathVariable Long projectId, Authentication auth) {
    return fileRepository.findByProjectId(projectId);
    // Missing: verify project belongs to auth.getName()
}
```

---

### 4. Vertical Privilege Escalation

A lower-privilege user gaining higher-privilege access through parameter tampering, JWT
manipulation, mass assignment, or missing server-side checks.

#### Mass Assignment — Python (Django)

```python
# VULNERABLE: User can set is_staff=True via request body
@login_required
def update_profile(request):
    form = UserForm(request.POST, instance=request.user)
    form.save()  # If UserForm includes 'is_staff' or 'is_superuser', user can self-promote
```

#### Mass Assignment — Ruby (Rails)

```ruby
# VULNERABLE: No strong parameters — user can set admin: true
def update
  @user = current_user
  @user.update(params[:user])  # Permits all attributes including role/admin
end

# SECURE: Strong parameters
def update
  @user = current_user
  @user.update(user_params)
end

private

def user_params
  params.require(:user).permit(:name, :email)  # Explicitly whitelist safe fields
end
```

#### Hidden Admin Parameters — JavaScript (Express)

```javascript
// VULNERABLE: Trusting role from request body
router.post("/api/register", async (req, res) => {
  const user = await User.create({
    username: req.body.username,
    password: req.body.password,
    role: req.body.role || "user", // Attacker sends {"role": "admin"}
  });
  res.json(user);
});
```

#### JWT Claim Tampering — Go

```go
// VULNERABLE: Role extracted from JWT without server-side verification against DB
func AdminHandler(w http.ResponseWriter, r *http.Request) {
    claims := r.Context().Value("claims").(jwt.MapClaims)
    if claims["role"] == "admin" { // Attacker modifies JWT if secret is weak
        // perform admin action
    }
}
```

#### C# (ASP.NET) — Vulnerable

```csharp
// VULNERABLE: Admin flag from query parameter
[Authorize]
[HttpGet("api/data")]
public IActionResult GetData([FromQuery] bool isAdmin = false)
{
    if (isAdmin)
        return Ok(_dataService.GetAllData());  // Attacker: ?isAdmin=true
    return Ok(_dataService.GetUserData(User.GetUserId()));
}
```

#### PHP (Laravel) — Vulnerable

```php
// VULNERABLE: Mass assignment allows role escalation
public function update(Request $request, User $user)
{
    $user->update($request->all()); // Attacker includes "role": "admin" in body
    return response()->json($user);
}
```

**Detection grep patterns:**

```
# Find mass assignment vectors
\.update\(request\.POST
\.update\(params\[
\.create\(req\.body
update\(\$request->all\(\)
# Find hidden parameter privilege checks
isAdmin.*request
\?admin=true
role.*req\.(body|query|params)
```

---

### 5. GraphQL Authorization Flaws

GraphQL introduces unique authorization challenges due to its flexible query structure.

#### Nested Query Authorization Bypass

```graphql
# User is authorized to query their own 'order' but the resolver for
# 'order.customer' doesn't recheck authorization — leaks other customers' data
query {
  order(id: "my-order-id") {
    id
    customer {           # Resolver fetches customer without auth check
      email
      creditCard {       # Deeply nested — often overlooked in auth checks
        number
      }
    }
  }
}
```

#### JavaScript (NestJS/Apollo) — Vulnerable Resolver

```typescript
// VULNERABLE: Parent resolver checks auth, child resolver does not
@Resolver(() => Order)
export class OrderResolver {
  @UseGuards(AuthGuard)
  @Query(() => Order)
  async order(@Args("id") id: string, @CurrentUser() user: User) {
    return this.orderService.findByIdAndUser(id, user.id); // Auth checked here
  }

  @ResolveField()
  async customer(@Parent() order: Order) {
    return this.customerService.findById(order.customerId); // NO auth check
  }
}
```

#### Introspection Exposure

```python
# VULNERABLE: Introspection enabled in production exposes admin-only types
schema = graphene.Schema(query=Query, mutation=Mutation)
# Attacker can discover: AdminMutation, DeleteAllUsers, SystemConfig types
```

#### Batch Query Abuse

```graphql
# Attacker sends batch to bypass per-query rate limits
[
  { "query": "{ user(id: 1) { email } }" },
  { "query": "{ user(id: 2) { email } }" },
  { "query": "{ user(id: 3) { email } }" }
  # ... hundreds more, each bypassing single-query auth/rate limits
]
```

**Detection grep patterns:**

```
# Find GraphQL resolvers potentially missing auth
@ResolveField\(\)(?!.*Guard)
@Resolver(?!.*@UseGuards)
introspection.*true
enable_introspection
```

---

### 6. BOLA (Broken Object Level Authorization)

BOLA is the API-specific manifestation of IDOR and is **OWASP API Security Top 10 #1** (API1:2023).
The distinction from generic IDOR is that BOLA specifically targets REST/GraphQL API endpoints.

**Key distinction:**
- **Authentication check**: "Is this user logged in?" → `401 Unauthorized` if not
- **Authorization check**: "Does this user own/have access to this specific resource?" → `403 Forbidden` if not

#### Python (FastAPI) — Demonstrates the Difference

```python
# HAS authentication, MISSING authorization
@router.get("/api/v1/accounts/{account_id}")
async def get_account(account_id: int, user: User = Depends(get_current_user)):
    # get_current_user verifies the JWT token (authentication) ✓
    account = await account_repo.get(account_id)
    return account  # But never checks: account.owner_id == user.id ✗

# SECURE: Both authentication AND authorization
@router.get("/api/v1/accounts/{account_id}")
async def get_account(account_id: int, user: User = Depends(get_current_user)):
    account = await account_repo.get(account_id)
    if account.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return account
```

#### Java (Spring) — API Pattern

```java
// VULNERABLE: Authentication present via SecurityContext, but no object-level authz
@GetMapping("/api/v1/documents/{docId}")
public Document getDocument(@PathVariable String docId) {
    return documentRepository.findById(docId)
        .orElseThrow(() -> new NotFoundException("Not found"));
    // Missing: check document.getOwnerId().equals(SecurityContextHolder...getId())
}
```

---

### 7. Forced Browsing

Accessing resources that are not linked in the UI but exist on the server and lack
authorization controls.

**Common targets:**

```
/admin/                      # Admin panel without auth check
/admin/config                # Configuration interface
/backup/db_dump.sql          # Database backup files
/api/v1/debug/users          # Debug endpoints left in production
/.env                        # Environment files with secrets
/swagger-ui.html             # API documentation with try-it-out enabled
/actuator/env                # Spring Boot actuator exposing environment
/graphql/playground          # GraphQL playground in production
/api/internal/               # Internal APIs reachable externally
/wp-admin/                   # CMS admin without IP restriction
```

**Detection grep patterns:**

```
# Find potentially unprotected static/admin paths in route configs
route.*\/admin(?!.*auth)
route.*\/backup
route.*\/debug
route.*\/internal
app\.(get|post).*\/admin(?!.*middleware)
```

---

### 8. Role-Based Access Control (RBAC) Flaws

#### Inconsistent Authorization Across HTTP Methods

```python
# VULNERABLE: GET is checked, but PUT and DELETE are not
class DocumentViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def retrieve(self, request, pk=None):
        doc = self.get_object()
        if doc.owner != request.user:   # Auth check on GET ✓
            return Response(status=403)
        return Response(DocumentSerializer(doc).data)

    def update(self, request, pk=None):
        doc = self.get_object()
        serializer = DocumentSerializer(doc, data=request.data)
        serializer.save()               # NO auth check on PUT ✗
        return Response(serializer.data)

    def destroy(self, request, pk=None):
        doc = self.get_object()
        doc.delete()                     # NO auth check on DELETE ✗
        return Response(status=204)
```

#### Hardcoded Role Checks Missing Edge Cases

```java
// VULNERABLE: Only checks "ADMIN" but misses "SUPER_ADMIN" or "MANAGER" roles
// that should also have access
if (user.getRole().equals("ADMIN")) {
    // allow operation
}
// A "SUPER_ADMIN" is denied because the check is exact string match, not hierarchy
```

#### Frontend-Only Authorization

```javascript
// VULNERABLE: Authorization enforced only in the frontend
// React component hides the button, but the API has no check
{user.role === "admin" && <button onClick={deleteAllUsers}>Delete All</button>}

// The actual API endpoint:
router.delete("/api/users/all", authenticate, async (req, res) => {
  await User.deleteMany({});  // No role check server-side!
  res.json({ status: "deleted" });
});
```

---

### 9. Multi-Tenancy Isolation Failures

In SaaS applications, failing to scope data queries by tenant is catastrophic.

#### Python (Django) — Vulnerable

```python
# VULNERABLE: No tenant scoping — returns data from ALL tenants
@login_required
def list_invoices(request):
    invoices = Invoice.objects.all()  # Missing: .filter(tenant=request.user.tenant)
    return JsonResponse(list(invoices.values()), safe=False)
```

#### Java (Spring) — Vulnerable

```java
// VULNERABLE: Tenant ID comes from request parameter, not session
@GetMapping("/api/reports")
public List<Report> getReports(@RequestParam("tenantId") String tenantId) {
    return reportRepository.findByTenantId(tenantId);
    // Attacker changes tenantId parameter to access other tenants' reports
}

// SECURE: Tenant ID from authenticated session
@GetMapping("/api/reports")
public List<Report> getReports(Authentication auth) {
    String tenantId = ((TenantAwareUser) auth.getPrincipal()).getTenantId();
    return reportRepository.findByTenantId(tenantId);
}
```

#### JavaScript (Express) — Vulnerable

```javascript
// VULNERABLE: Tenant ID from request header (easily spoofed)
router.get("/api/data", authenticate, async (req, res) => {
  const tenantId = req.headers["x-tenant-id"]; // Attacker controls this header
  const data = await Data.find({ tenantId });
  res.json(data);
});
```

#### PHP (Laravel) — Vulnerable

```php
// VULNERABLE: Global scope missing — no tenant isolation
public function index()
{
    return Project::all(); // Returns projects from ALL tenants
}

// SECURE: Tenant scope applied
public function index()
{
    return Project::where('tenant_id', auth()->user()->tenant_id)->get();
}
```

**Detection grep patterns:**

```
# Find queries potentially missing tenant scoping
\.objects\.all\(\)
\.find\(\{\}\)
\.findAll\(\)
SELECT.*FROM.*(?!WHERE.*tenant)
@RequestParam.*tenant
headers\[.*tenant
```

---

## Detection Methodology

Follow this step-by-step process when scanning a codebase for authorization vulnerabilities:

### Step 1: Map All Endpoints and Their Authorization Requirements

```bash
# Find route definitions across frameworks
grep -rn "(@(Get|Post|Put|Delete|Patch)Mapping|@(api_view|action)|router\.(get|post|put|delete|patch)|Route::|app\.(get|post|put|delete))" --include="*.py" --include="*.java" --include="*.js" --include="*.ts" --include="*.cs" --include="*.rb" --include="*.php" --include="*.go"
```

### Step 2: Check for Authorization Middleware/Decorators

```bash
# Find endpoints with authentication but potentially missing authorization
# Python (Django/Flask)
grep -rn "@login_required" --include="*.py"
grep -rn "@permission_required\|@user_passes_test\|@admin_required" --include="*.py"

# Java (Spring)
grep -rn "@PreAuthorize\|@Secured\|@RolesAllowed" --include="*.java"

# JavaScript/TypeScript
grep -rn "authenticate\|isAuthenticated\|authMiddleware" --include="*.js" --include="*.ts"
grep -rn "requireRole\|requirePermission\|@Roles\|RolesGuard" --include="*.js" --include="*.ts"

# C# (ASP.NET)
grep -rn "\[Authorize\]" --include="*.cs"
grep -rn '\[Authorize(Roles\|Policy)' --include="*.cs"

# Ruby (Rails)
grep -rn "before_action :authenticate" --include="*.rb"
grep -rn "before_action :require_admin\|before_action :authorize\|cancancan\|pundit" --include="*.rb"

# PHP (Laravel)
grep -rn "middleware.*auth" --include="*.php"
grep -rn "middleware.*role\|middleware.*can\|Gate::\|@can" --include="*.php"
```

### Step 3: Verify Ownership Checks on Data Access

```bash
# Find database queries using IDs from request parameters without ownership filtering
grep -rn "findById\|find_by_id\|objects\.get(id=\|FindAsync\|\.find(params" --include="*.py" --include="*.java" --include="*.js" --include="*.ts" --include="*.cs" --include="*.rb" --include="*.php"
```

For each match, verify the surrounding code includes an ownership comparison such as:
- `resource.owner_id == current_user.id`
- `.where(user_id: current_user.id)`
- `.filter(owner=request.user)`

### Step 4: Check for Tenant Isolation in Queries

```bash
# Find potentially unscoped queries in multi-tenant applications
grep -rn "\.objects\.all()\|\.find({})\|\.findAll()\|::all()" --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.rb" --include="*.php"
```

Verify each query includes tenant scoping if the application is multi-tenant.

### Step 5: Look for Frontend-Only Authorization

```bash
# Find role checks that may only exist in frontend code
grep -rn "role.*===.*admin\|isAdmin\|user\.role" --include="*.jsx" --include="*.tsx" --include="*.vue" --include="*.svelte"
```

Cross-reference with backend: does the corresponding API endpoint also enforce this check?

### Step 6: Audit GraphQL Resolvers for Field-Level Auth

```bash
# Find GraphQL resolvers and check for auth guards
grep -rn "@ResolveField\|@Resolver\|fieldResolver\|resolve_field" --include="*.ts" --include="*.js" --include="*.py" --include="*.java"
grep -rn "@UseGuards\|@guard\|permission_classes" --include="*.ts" --include="*.js" --include="*.py"
```

### Step 7: Check for Mass Assignment Protections

```bash
# Find potential mass assignment sinks
grep -rn "\.update(request\.\|\.create(req\.body\|update(\$request->all\|\.update(params\[" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.php"
```

### Step 8: Verify Consistent Authorization Across HTTP Methods

For every resource endpoint found in Step 1, verify that ALL HTTP methods (GET, POST, PUT,
PATCH, DELETE) enforce the same authorization checks. A common flaw is checking authorization
on GET but not on PUT/DELETE.

---

## Common Sinks and Sources

### Sources (Attacker-Controlled Input)

| Source                        | Example                                  | Risk              |
|-------------------------------|------------------------------------------|--------------------|
| URL path parameters           | `/api/users/:id`                         | IDOR / BOLA        |
| Query parameters              | `?tenant_id=123`                         | Tenant bypass      |
| Request body fields           | `{"role": "admin"}`                      | Mass assignment    |
| HTTP headers                  | `X-Tenant-Id: 456`                       | Tenant spoofing    |
| JWT claims (weak secret)      | `{"role": "admin"}` in JWT payload       | Priv escalation    |
| GraphQL variables             | `variables: { userId: "other-user" }`    | BOLA               |
| Cookie values                 | `role=admin` in cookie                   | Priv escalation    |

### Sinks (Where Authorization Must Be Enforced)

| Sink                          | Framework Example                        | Required Check          |
|-------------------------------|------------------------------------------|--------------------------|
| ORM query by ID               | `Model.objects.get(id=X)`                | Ownership filter         |
| Repository findById           | `repo.findById(X)`                       | Owner comparison         |
| Direct SQL with user input    | `SELECT * FROM orders WHERE id = ?`      | `AND user_id = ?`        |
| File system access            | `open(f"/uploads/{user_id}/{file}")`     | Path traversal + authz   |
| Admin action handler          | `deleteUser(userId)`                     | Role/permission check    |
| Bulk data retrieval           | `Model.objects.all()`                    | Tenant/scope filter      |
| GraphQL nested resolver       | `@ResolveField() customer()`             | Per-field auth guard     |

---

## False Positive Indicators

When reviewing potential authorization findings, the following patterns indicate the code
may be **correctly authorized** even if the individual handler appears unprotected:

1. **Authorization in middleware or base class**: The handler itself has no visible check,
   but authorization is enforced by a middleware, base controller, or framework interceptor
   applied to the entire route group.
   ```python
   # Base class enforces ownership — subclass handlers are safe
   class OwnedResourceViewSet(viewsets.ModelViewSet):
       def get_queryset(self):
           return self.model.objects.filter(owner=self.request.user)
   ```

2. **Intentionally public resource**: Some endpoints are designed to be publicly accessible
   (e.g., product catalog, public profiles, health checks). Verify the data sensitivity.

3. **ID validated against user's accessible set**: The ID is checked against the user's
   allowed resources before the query executes.
   ```java
   // The service layer validates access before returning data
   public Document getDocument(String docId, String userId) {
       Document doc = repo.findById(docId);
       if (!accessControlService.canAccess(userId, doc)) {
           throw new ForbiddenException();
       }
       return doc;
   }
   ```

4. **Tenant scoping at ORM/repository layer**: Tenant isolation is applied automatically
   via a global query scope, Hibernate filter, or repository base class.
   ```python
   # Django: TenantManager automatically filters by tenant
   class TenantManager(models.Manager):
       def get_queryset(self):
           tenant = get_current_tenant()
           return super().get_queryset().filter(tenant=tenant)
   ```

5. **Authorization in a service/domain layer**: The controller delegates to a service that
   performs the authorization check internally. Inspect the service method before flagging.

6. **Policy-based authorization applied via attribute/annotation at class level**: A single
   `[Authorize(Policy = "...")]` on the controller class covers all actions within it.

---

## Severity Assessment

| Vulnerability                        | Severity    | Justification                                                        |
|--------------------------------------|-------------|----------------------------------------------------------------------|
| IDOR on sensitive data (PII, financial) | **Critical** | Direct access to other users' sensitive data                        |
| IDOR on non-sensitive data           | **High**     | Unauthorized data access, potentially chained with other attacks     |
| Vertical privilege escalation        | **Critical** | User gains admin access, full system compromise possible             |
| Horizontal privilege escalation      | **High**     | Cross-user data access at same privilege level                       |
| Missing function-level access control| **Critical** | Admin functions accessible to unauthenticated or low-privilege users |
| Mass assignment to role field        | **Critical** | Self-promotion to admin role                                         |
| Multi-tenancy isolation failure      | **Critical** | Complete cross-tenant data breach                                    |
| GraphQL nested auth bypass           | **High**     | Data leak through authorized parent, unauthorized child              |
| BOLA on API endpoints                | **Critical** | API1:2023, often exploitable at scale via automation                 |
| Forced browsing to admin pages       | **High**     | Exposure of admin functionality or sensitive files                   |
| Frontend-only authorization          | **High**     | Server enforces no access control; trivially bypassable              |
| Inconsistent method authorization    | **Medium**   | Partial protection; some methods checked, others not                 |
| RBAC role hierarchy flaw             | **Medium**   | Edge cases in role inheritance; limited blast radius                  |

**Escalating factors that increase severity:**
- Sensitive data involved (PII, PHI, financial, credentials)
- No rate limiting (allows mass enumeration)
- Sequential/predictable IDs (easier exploitation)
- Multi-tenant environment (cross-tenant = critical)
- Public-facing API (wider attack surface)

---

## Remediation Patterns

### Django — Object-Level Permissions

```python
# Use django-guardian or custom permission class
from rest_framework.permissions import BasePermission

class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user

class DocumentViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsOwner]
    
    def get_queryset(self):
        return Document.objects.filter(owner=self.request.user)
```

### Spring Security — Method-Level Authorization

```java
@PreAuthorize("hasRole('ADMIN') or @documentSecurity.isOwner(#docId, authentication)")
@GetMapping("/api/documents/{docId}")
public Document getDocument(@PathVariable String docId) {
    return documentRepository.findById(docId).orElseThrow();
}

@Component("documentSecurity")
public class DocumentSecurity {
    public boolean isOwner(String docId, Authentication auth) {
        Document doc = documentRepository.findById(docId).orElse(null);
        return doc != null && doc.getOwnerId().equals(auth.getName());
    }
}
```

### ASP.NET — Policy-Based Authorization

```csharp
// Startup.cs — Define policies
services.AddAuthorization(options =>
{
    options.AddPolicy("DocumentOwner", policy =>
        policy.Requirements.Add(new DocumentOwnerRequirement()));
});

// Handler
public class DocumentOwnerHandler : AuthorizationHandler<DocumentOwnerRequirement, Document>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        DocumentOwnerRequirement requirement,
        Document document)
    {
        if (document.OwnerId == context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value)
            context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
```

### Repository Pattern with Automatic Tenant Scoping

```python
# Python: Base repository that auto-scopes all queries
class TenantScopedRepository:
    def __init__(self, model, tenant_id):
        self._model = model
        self._tenant_id = tenant_id

    def get(self, id):
        return self._model.objects.get(id=id, tenant_id=self._tenant_id)

    def list(self, **filters):
        return self._model.objects.filter(tenant_id=self._tenant_id, **filters)

    def create(self, **data):
        data["tenant_id"] = self._tenant_id
        return self._model.objects.create(**data)
```

```java
// Java: Hibernate filter for automatic tenant scoping
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = "string"))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Entity
public class Project {
    @Column(name = "tenant_id")
    private String tenantId;
}
```

### ABAC (Attribute-Based Access Control) vs RBAC

```python
# RBAC: Role-based — simple but rigid
def check_rbac(user, action):
    role_permissions = {
        "admin": ["read", "write", "delete", "manage_users"],
        "editor": ["read", "write"],
        "viewer": ["read"],
    }
    return action in role_permissions.get(user.role, [])

# ABAC: Attribute-based — flexible, context-aware
def check_abac(user, resource, action, context):
    policies = [
        # Users can read their own documents
        lambda u, r, a, c: a == "read" and r.owner_id == u.id,
        # Managers can read all documents in their department
        lambda u, r, a, c: a == "read" and u.role == "manager" and r.department == u.department,
        # Admins can do anything during business hours
        lambda u, r, a, c: u.role == "admin" and c.get("business_hours", False),
    ]
    return any(policy(user, resource, action, context) for policy in policies)
```

### Express Middleware Pattern

```javascript
// Reusable authorization middleware
function requireOwnership(resourceGetter) {
  return async (req, res, next) => {
    const resource = await resourceGetter(req);
    if (!resource) return res.status(404).json({ error: "Not found" });
    if (resource.userId !== req.user.id) return res.status(403).json({ error: "Forbidden" });
    req.resource = resource;
    next();
  };
}

// Usage
router.get(
  "/api/orders/:id",
  authenticate,
  requireOwnership((req) => Order.findById(req.params.id)),
  (req, res) => res.json(req.resource)
);
```

### Laravel Gate/Policy Pattern

```php
// Define Gate
Gate::define('update-order', function (User $user, Order $order) {
    return $user->id === $order->user_id;
});

// Controller usage
public function update(Request $request, Order $order)
{
    $this->authorize('update-order', $order);
    $order->update($request->validated());
    return response()->json($order);
}
```

---

## CWE References

| CWE ID   | Name                                          | Relevant Patterns                          |
|----------|-----------------------------------------------|--------------------------------------------|
| CWE-862  | Missing Authorization                         | No auth check at all on protected endpoint |
| CWE-863  | Incorrect Authorization                       | Auth check present but bypassable/flawed   |
| CWE-639  | Authorization Bypass Through User-Controlled Key | IDOR, BOLA — ID from user input          |
| CWE-284  | Improper Access Control                       | General broken access control umbrella     |
| CWE-269  | Improper Privilege Management                 | Vertical privilege escalation, mass assign |
| CWE-732  | Incorrect Permission Assignment for Critical Resource | Overly permissive defaults, forced browsing |

**Related CWEs:**
- **CWE-285**: Improper Authorization — generic authorization failure
- **CWE-352**: CSRF — can compound authorization flaws when state-changing actions lack both
  CSRF protection and authorization
- **CWE-566**: Authorization Bypass Through SQL Injection — authz bypass via injection
- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes
  (mass assignment)

---

## References

- [OWASP Top 10 A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP API Security Top 10 — API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP Testing Guide — Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/)
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
