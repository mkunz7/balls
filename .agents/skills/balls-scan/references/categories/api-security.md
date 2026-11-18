<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Antigravity BALLS workflow and evidence rules. -->

## Overview

API security vulnerabilities encompass a broad range of issues specific to how applications expose and consume programmatic interfaces. Modern APIs (REST, GraphQL, gRPC, WebSocket) each have unique attack surfaces. The OWASP API Security Top 10 identifies the most critical risks, including broken authorization at both object and function levels, excessive data exposure, and resource consumption issues. These flaws often result from treating API endpoints like internal functions rather than trust boundaries.

## Vulnerability Patterns

### BOLA — Broken Object Level Authorization

```python
# Python/Django — VULNERABLE: No ownership check
@api_view(['GET'])
@authentication_classes([TokenAuthentication])
def get_order(request, order_id):
    # VULNERABLE: Any authenticated user can access any order
    order = Order.objects.get(id=order_id)
    return Response(OrderSerializer(order).data)
```

```javascript
// Node.js/Express — VULNERABLE: Direct object reference
app.get('/api/users/:userId/profile', authMiddleware, (req, res) => {
    // VULNERABLE: userId from URL, not from authenticated session
    const profile = await db.users.findById(req.params.userId);
    res.json(profile);
});

// VULNERABLE: Predictable/sequential IDs make enumeration trivial
app.get('/api/invoices/:invoiceId', authMiddleware, async (req, res) => {
    // invoiceId is sequential integer: 1001, 1002, 1003...
    const invoice = await Invoice.findById(req.params.invoiceId);
    res.json(invoice);
});
```

```java
// Java/Spring — VULNERABLE: Missing authorization on resource
@GetMapping("/api/documents/{documentId}")
public ResponseEntity<Document> getDocument(
        @PathVariable Long documentId,
        @AuthenticationPrincipal UserDetails user) {
    // VULNERABLE: Fetches document without checking if user owns it
    Document doc = documentRepository.findById(documentId)
        .orElseThrow(() -> new NotFoundException("Document not found"));
    return ResponseEntity.ok(doc);
}
```

```go
// Go — VULNERABLE: BOLA in REST handler
func GetUserAccount(w http.ResponseWriter, r *http.Request) {
    accountID := chi.URLParam(r, "accountId")

    // VULNERABLE: Authenticated user can access any account
    account, err := db.GetAccount(accountID)
    if err != nil {
        http.Error(w, "Not found", 404)
        return
    }
    json.NewEncoder(w).Encode(account)
}
```

### Mass Assignment

```python
# Python/Django — VULNERABLE: All fields accepted
class UserUpdateView(APIView):
    def put(self, request):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        # VULNERABLE: Serializer accepts all model fields including:
        # is_admin, is_staff, role, balance, email_verified
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
```

```javascript
// Node.js — VULNERABLE: Spread operator mass assignment
app.put('/api/users/profile', authMiddleware, async (req, res) => {
    // VULNERABLE: All request body fields merged into user record
    await User.findByIdAndUpdate(req.user.id, { ...req.body });
    // Attacker sends: { "role": "admin", "isVerified": true }
    res.json({ success: true });
});
```

```ruby
# Ruby on Rails — VULNERABLE: Unpermitted params
class UsersController < ApplicationController
  def update
    # VULNERABLE: params not filtered
    @user = User.find(params[:id])
    @user.update(params[:user])
    # Should use: params.require(:user).permit(:name, :email)
  end
end
```

```csharp
// C# — VULNERABLE: Model binding accepts all properties
[HttpPut("users/{id}")]
public IActionResult UpdateUser(int id, [FromBody] User user)
{
    // VULNERABLE: Binds all properties including Role, IsAdmin
    var existingUser = _context.Users.Find(id);
    _context.Entry(existingUser).CurrentValues.SetValues(user);
    _context.SaveChanges();
    return Ok();
}
```

### Excessive Data Exposure

```python
# Python/Django — VULNERABLE: Returning all fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # VULNERABLE: Includes password_hash, ssn, etc.

# API response contains:
# {
#     "id": 1, "email": "user@example.com",
#     "password_hash": "$2b$12$...",
#     "ssn": "123-45-6789",
#     "internal_notes": "VIP customer - bypass limits",
#     "api_key": "sk_live_..."
# }
```

```javascript
// Node.js — VULNERABLE: Unfiltered database response
app.get('/api/users/:id', async (req, res) => {
    // VULNERABLE: Returns entire document including sensitive fields
    const user = await User.findById(req.params.id);
    res.json(user); // Includes passwordHash, resetToken, internalFlags
});

// VULNERABLE: List endpoint returns too many records with sensitive data
app.get('/api/users', adminMiddleware, async (req, res) => {
    const users = await User.find({}); // No field projection
    res.json(users); // All user records with all fields
});
```

```java
// Java — VULNERABLE: Entity directly serialized
@GetMapping("/api/users/{id}")
public ResponseEntity<User> getUser(@PathVariable Long id) {
    // VULNERABLE: JPA entity with @Column fields serialized directly
    // Includes fields like passwordHash, socialSecurityNumber, internalRole
    User user = userRepository.findById(id).orElseThrow();
    return ResponseEntity.ok(user);
}
```

### GraphQL-Specific Vulnerabilities

```graphql
# VULNERABLE: Introspection enabled in production
# Attacker can discover entire schema:
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}

# VULNERABLE: Deeply nested query — DoS via query complexity
{
  users {
    friends {
      friends {
        friends {
          friends {
            friends {
              name
              email
            }
          }
        }
      }
    }
  }
}

# VULNERABLE: Batch query abuse
[
  { "query": "{ user(id: 1) { password } }" },
  { "query": "{ user(id: 2) { password } }" },
  # ... 10,000 more queries
]

# VULNERABLE: Missing field-level authorization
mutation {
  updateUser(id: "other-user-id", input: { role: ADMIN }) {
    id
    role
  }
}
```

```javascript
// Node.js — VULNERABLE: GraphQL resolver without auth
const resolvers = {
    Query: {
        // VULNERABLE: No authorization check
        user: (_, { id }) => db.users.findById(id),
        // VULNERABLE: Returns all users without pagination limit
        users: () => db.users.findAll(),
    },
    Mutation: {
        // VULNERABLE: No check that requesting user can modify target user
        updateUser: (_, { id, input }) => db.users.update(id, input),
        // VULNERABLE: No authorization on admin mutations
        deleteUser: (_, { id }) => db.users.delete(id),
    },
};
```

### WebSocket Vulnerabilities

```javascript
// Node.js — VULNERABLE: No auth on WebSocket
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (ws) => {
    // VULNERABLE: No authentication check
    // VULNERABLE: No origin validation
    ws.on('message', (data) => {
        const msg = JSON.parse(data);
        // VULNERABLE: No authorization on operations
        if (msg.type === 'get_user_data') {
            const userData = db.getUser(msg.userId); // Any userId
            ws.send(JSON.stringify(userData));
        }
    });
});
```

```python
# Python — VULNERABLE: Cross-site WebSocket hijacking
# No Origin header validation
@websocket.route('/ws')
async def ws_handler(ws):
    # VULNERABLE: Accepts connections from any origin
    # Browser sends cookies automatically — attacker's page can connect
    while True:
        data = await ws.receive_json()
        result = await process_command(data)
        await ws.send_json(result)
```

### Rate Limiting Gaps

```python
# Python/Flask — VULNERABLE: No rate limiting on sensitive endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    # VULNERABLE: No rate limit — allows credential stuffing
    username = request.json['username']
    password = request.json['password']
    user = authenticate(username, password)
    if user:
        return jsonify(token=generate_token(user))
    return jsonify(error='Invalid credentials'), 401

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    # VULNERABLE: No rate limit — email bombing
    email = request.json['email']
    send_password_reset(email)
    return jsonify(status='sent')
```

```javascript
// Node.js — VULNERABLE: Bypassable rate limit
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    // VULNERABLE: Uses X-Forwarded-For which can be spoofed
    keyGenerator: (req) => req.headers['x-forwarded-for'] || req.ip,
});
```

### Pagination and Filtering Issues

```javascript
// Node.js — VULNERABLE: No max page size
app.get('/api/records', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    // VULNERABLE: No max limit — attacker requests limit=1000000
    const records = await Record.find().skip((page - 1) * limit).limit(limit);
    res.json(records);
});
```

```python
# Python — VULNERABLE: SQL injection via sort parameter
@app.route('/api/products')
def list_products():
    sort_by = request.args.get('sort', 'name')
    order = request.args.get('order', 'asc')
    # VULNERABLE: Sort field injected into query
    products = db.execute(f"SELECT * FROM products ORDER BY {sort_by} {order}")
    return jsonify(products)
```

## Detection Methodology

1. **Authorization Mapping**: For every endpoint that accesses a resource by ID, verify that ownership or permission checks exist
2. **Mass Assignment Audit**: Check all update/create endpoints for field filtering — identify which model fields are writable
3. **Response Analysis**: Examine serializers, response builders, and database projections for excessive field exposure
4. **GraphQL Schema Review**: Check for introspection access, query depth limits, field-level authorization, and batch query limits
5. **WebSocket Security**: Verify authentication, origin validation, and per-message authorization on WebSocket handlers
6. **Rate Limit Coverage**: Map all sensitive endpoints (auth, password reset, OTP, data export) and verify rate limiting
7. **Pagination Bounds**: Check all list endpoints for maximum page size enforcement
8. **HTTP Method Handling**: Verify that endpoints only accept intended HTTP methods
9. **Content-Type Handling**: Check for content-type confusion (JSON vs form vs XML parsing)
10. **API Versioning**: Check for deprecated API versions that lack security controls

## Common Sinks and Sources

### Controller/Handler Patterns
- Route parameters: `/:id`, `/{id}`, `?id=`
- Request body fields: `req.body`, `request.data`, `@RequestBody`
- Query parameters: `req.query`, `request.args`, `@RequestParam`
- Header values: `req.headers`, `request.META`

### Framework-Specific Patterns
- **Django REST**: `ModelSerializer`, `ModelViewSet`, `fields = '__all__'`
- **Express**: `router.get('/:id')`, `app.use(cors())`, `body-parser`
- **Spring**: `@RequestBody`, `@PathVariable`, `@CrossOrigin`, `@PreAuthorize`
- **Rails**: `params.permit`, `before_action`, `Strong Parameters`
- **FastAPI**: `Depends()`, `Path()`, `Query()`, `Body()`
- **ASP.NET**: `[FromBody]`, `[Authorize]`, `[FromRoute]`

### GraphQL Patterns
- Schema definitions: `type Query`, `type Mutation`
- Resolvers: `Query:`, `Mutation:`
- Directives: `@auth`, `@hasRole`, `@deprecated`
- Middleware: `graphql-shield`, `graphql-middleware`

## False Positive Indicators

- **Public endpoints**: Endpoints intentionally accessible without auth (status pages, public profiles, open APIs)
- **Admin-only tools**: Internal admin panels with separate auth systems
- **DTO/ViewModel patterns**: Separate classes for API responses that already exclude sensitive fields
- **Authorization decorators present**: `@permission_required`, `@PreAuthorize`, `@authorize` — verify they are correct, not just present
- **GraphQL directives**: Custom `@auth` directives that handle authorization in schema layer
- **Rate limiting at infrastructure level**: WAF or API gateway rate limits not visible in application code
- **ID obfuscation**: UUIDs or hashids reduce enumeration risk (but don't prevent BOLA)

## Severity Assessment

| Finding | Severity |
|---------|----------|
| BOLA on sensitive resources (financial, PII) | **Critical** |
| Mass assignment allowing privilege escalation | **Critical** |
| Missing auth on admin/mutation GraphQL operations | **Critical** |
| No authentication on WebSocket connections | **Critical** |
| Excessive data exposure of credentials/tokens | **Critical** |
| BOLA on non-sensitive resources | **High** |
| Mass assignment on non-privilege fields | **High** |
| GraphQL introspection in production | **High** |
| Missing rate limiting on auth endpoints | **High** |
| Excessive data exposure of PII | **High** |
| No pagination limits on list endpoints | **Medium** |
| GraphQL query depth/complexity unlimited | **Medium** |
| Sort/filter injection in API parameters | **Medium** |
| Missing rate limiting on non-auth endpoints | **Medium** |
| HTTP method override allowed | **Low** |
| API version mismatch | **Low** |

## Remediation Patterns

### BOLA Fix — Ownership Verification
```python
# SECURE: Always check resource ownership
@api_view(['GET'])
@authentication_classes([TokenAuthentication])
def get_order(request, order_id):
    order = Order.objects.get(id=order_id, user=request.user)  # Scoped to user
    return Response(OrderSerializer(order).data)
```

### Mass Assignment Fix — Explicit Allowlists
```python
# SECURE: Explicit field allowlist
class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone']
        read_only_fields = ['is_admin', 'role', 'balance', 'email_verified']
```

```javascript
// SECURE: Pick only allowed fields
app.put('/api/users/profile', authMiddleware, async (req, res) => {
    const allowedFields = ['firstName', 'lastName', 'email', 'phone'];
    const updates = _.pick(req.body, allowedFields);
    await User.findByIdAndUpdate(req.user.id, updates);
});
```

### Excessive Data Exposure Fix — Response DTOs
```java
// SECURE: Separate response DTO
public class UserResponse {
    private Long id;
    private String name;
    private String email;
    // No passwordHash, ssn, internalNotes, apiKey
}

@GetMapping("/api/users/{id}")
public ResponseEntity<UserResponse> getUser(@PathVariable Long id) {
    User user = userRepository.findById(id).orElseThrow();
    return ResponseEntity.ok(UserResponse.fromEntity(user));
}
```

### GraphQL Security
```javascript
// SECURE: Disable introspection, add depth limit, field-level auth
const server = new ApolloServer({
    schema,
    introspection: false, // Disable in production
    plugins: [
        ApolloServerPluginLandingPageDisabled(),
    ],
    validationRules: [
        depthLimit(5),
        createComplexityLimitRule(1000),
    ],
});

// Field-level authorization with graphql-shield
const permissions = shield({
    Query: {
        users: isAdmin,
        user: isAuthenticated,
    },
    Mutation: {
        deleteUser: isAdmin,
        updateUser: isOwnerOrAdmin,
    },
});
```

### Rate Limiting
```python
# SECURE: Rate limiting with proper key
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Protected against credential stuffing
    pass

@app.route('/api/auth/forgot-password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    pass
```

### Pagination Bounds
```javascript
// SECURE: Enforce max page size
app.get('/api/records', async (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
    const records = await Record.find()
        .skip((page - 1) * limit)
        .limit(limit)
        .select('name description createdAt'); // Field projection
    res.json(records);
});
```

## CWE References

- **CWE-639**: Authorization Bypass Through User-Controlled Key (BOLA/IDOR)
- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)
- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- **CWE-269**: Improper Privilege Management
- **CWE-770**: Allocation of Resources Without Limits or Throttling
- **CWE-799**: Improper Control of Interaction Frequency
- **CWE-285**: Improper Authorization
- **CWE-862**: Missing Authorization
- **CWE-863**: Incorrect Authorization
- **CWE-284**: Improper Access Control
- **CWE-1275**: Sensitive Cookie with Improper SameSite Attribute (WebSocket CSRF)
