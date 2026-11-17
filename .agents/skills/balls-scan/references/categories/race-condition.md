<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Codex-native BALLS workflow and evidence rules. -->

# Race Condition Vulnerability Detection

## Overview

Race conditions occur when the behavior of a system depends on the relative timing or
interleaving of multiple concurrent operations on shared resources. They are among the
most dangerous and elusive vulnerability classes because they are **non-deterministic** —
exploitation depends on precise timing, making them difficult to reproduce, test, and
detect through static analysis alone.

**Why race conditions are hard to detect:**
- They may never manifest in single-threaded testing environments
- Code review shows "correct" logic — the flaw is in temporal ordering
- Standard functional tests pass because they execute sequentially
- Exploitation requires concurrent requests, often within microsecond windows
- Many static analysis tools cannot model concurrency semantics

**Impact of race condition exploitation:**
- **Privilege escalation**: TOCTOU on permission checks allows unauthorized actions
- **Financial loss**: Double-spend attacks drain accounts, duplicate purchases, free goods
- **Data corruption**: Lost updates, inconsistent state across related records
- **Authentication bypass**: Race past account lockout, MFA, or session invalidation
- **Denial of service**: Resource exhaustion through race-based duplication

**Primary CWE**: CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)

---

## Vulnerability Patterns

### 1. TOCTOU (Time-of-Check to Time-of-Use) — CWE-367

TOCTOU occurs when a program checks a condition, then acts on the assumption that the
condition still holds — but an attacker changes the state between the check and the use.

**Python — File system TOCTOU:**
```python
# VULNERABLE: gap between existence check and open
import os

def read_config(path):
    if os.path.exists(path):          # CHECK — file exists
        # Attacker swaps file with symlink to /etc/shadow here
        with open(path, 'r') as f:    # USE — opens attacker-controlled file
            return f.read()
```

**C — Classic file access TOCTOU:**
```c
// VULNERABLE: access() and open() are not atomic
if (access(filename, W_OK) == 0) {
    // Attacker replaces file with symlink between access() and open()
    int fd = open(filename, O_WRONLY);
    write(fd, data, len);
    close(fd);
}
```

**Java — Permission check then action:**
```java
// VULNERABLE: role could change between check and action
public void deleteUser(User actor, User target) {
    if (actor.isAdmin()) {                    // CHECK — actor is admin
        // Actor's admin role revoked by another thread here
        userRepository.delete(target);         // USE — deletion proceeds
    }
}
```

**C# — File operation TOCTOU:**
```csharp
// VULNERABLE: file state can change between check and use
if (File.Exists(uploadPath))
{
    // Attacker replaces file between check and read
    var content = File.ReadAllText(uploadPath);
    ProcessUpload(content);
}
```

**Go — Directory check then create:**
```go
// VULNERABLE: directory can be created by attacker between check and create
if _, err := os.Stat(dirPath); os.IsNotExist(err) {
    // Attacker creates symlink at dirPath here
    os.MkdirAll(dirPath, 0755)
}
```

**Database TOCTOU — Balance check then deduction:**
```python
# VULNERABLE: balance can change between SELECT and UPDATE
def withdraw(user_id, amount):
    balance = db.execute("SELECT balance FROM accounts WHERE id = %s", user_id).fetchone()
    if balance >= amount:                          # CHECK
        # Another concurrent withdrawal executes here
        db.execute("UPDATE accounts SET balance = %s WHERE id = %s",
                   balance - amount, user_id)      # USE — based on stale balance
```

### 2. Double-Spend / Financial Race Conditions

The attacker sends multiple concurrent requests that each read the same initial state
before any of them write the updated state, causing the operation to succeed multiple times.

**Python/SQL — Non-atomic balance deduction:**
```python
# VULNERABLE: read-modify-write is not atomic
def purchase(user_id, item_price):
    row = db.execute("SELECT balance FROM wallets WHERE user_id = %s", user_id)
    balance = row['balance']        # Thread A reads balance = 100
                                     # Thread B also reads balance = 100
    if balance >= item_price:        # Both threads pass this check (100 >= 80)
        new_balance = balance - item_price
        db.execute("UPDATE wallets SET balance = %s WHERE user_id = %s",
                   new_balance, user_id)
        # Thread A writes balance = 20
        # Thread B also writes balance = 20 (should be -60!)
        create_order(user_id, item_price)
```

**Java/JPA — ORM-level double-spend:**
```java
// VULNERABLE: no optimistic locking, no transaction isolation
@Transactional
public void transferFunds(Long fromId, Long toId, BigDecimal amount) {
    Account from = accountRepository.findById(fromId).get();
    // Concurrent request also loads this entity with same balance
    if (from.getBalance().compareTo(amount) >= 0) {
        from.setBalance(from.getBalance().subtract(amount));
        Account to = accountRepository.findById(toId).get();
        to.setBalance(to.getBalance().add(amount));
        // Both transactions commit — double deduction from 'to', insufficient deduction from 'from'
    }
}
```

**Node.js — Async double-spend:**
```javascript
// VULNERABLE: async gap between read and write
async function redeemCoupon(userId, couponCode) {
  const coupon = await db.query('SELECT * FROM coupons WHERE code = $1', [couponCode]);
  if (coupon.used) throw new Error('Already redeemed');
  // Concurrent request also sees coupon.used = false
  await db.query('UPDATE coupons SET used = true WHERE code = $1', [couponCode]);
  await db.query('UPDATE wallets SET balance = balance + $1 WHERE user_id = $2',
    [coupon.value, userId]);
  // Both requests redeem the same coupon
}
```

**Ruby — ActiveRecord double-spend:**
```ruby
# VULNERABLE: read-modify-write without locking
def withdraw(user_id, amount)
  account = Account.find(user_id)
  if account.balance >= amount
    account.balance -= amount
    account.save!
    # Concurrent request read the old balance, also succeeds
  end
end
```

### 3. Rate Limiting Bypass

Rate limiters that check-then-increment without atomicity allow bursts of concurrent
requests to all pass before the counter reflects the actual count.

**Python/Redis — Non-atomic rate limit:**
```python
# VULNERABLE: get and incr are separate operations
def check_rate_limit(user_id):
    key = f"rate:{user_id}"
    count = redis.get(key)                  # All concurrent requests read count = 0
    if count and int(count) >= MAX_REQUESTS:
        raise RateLimitExceeded()
    redis.incr(key)                         # All increment after passing check
    redis.expire(key, WINDOW_SECONDS)
```

**Node.js — In-memory rate limiter race:**
```javascript
// VULNERABLE: check and update are not atomic in async context
const rateLimits = new Map();

async function rateLimit(ip) {
  const current = rateLimits.get(ip) || 0;
  if (current >= MAX_REQUESTS) {
    throw new Error('Rate limited');
  }
  // Async operation yields control — other requests see old count
  await processRequest();
  rateLimits.set(ip, current + 1);
}
```

**Distributed rate limiting failure:**
```python
# VULNERABLE: each server instance has its own counter
# With 5 app servers, effective rate limit is 5x the intended limit
from functools import lru_cache

request_counts = {}  # In-memory, per-process counter

def check_rate_limit(user_id):
    count = request_counts.get(user_id, 0)
    if count >= MAX_REQUESTS:
        raise RateLimitExceeded()
    request_counts[user_id] = count + 1
```

### 4. Database Race Conditions

**Lost update — read-modify-write without isolation:**
```sql
-- VULNERABLE: Transaction A and B both read quantity = 10
-- Transaction A: UPDATE products SET quantity = 10 - 3 WHERE id = 1;  (sets to 7)
-- Transaction B: UPDATE products SET quantity = 10 - 5 WHERE id = 1;  (sets to 5)
-- Expected: 2, Actual: 5 or 7 (last write wins, first deduction lost)

-- The vulnerable ORM pattern:
-- product = Product.objects.get(id=1)
-- product.quantity -= order_quantity
-- product.save()
```

**Phantom read in booking/inventory systems:**
```python
# VULNERABLE: count can change between SELECT COUNT and INSERT
def book_seat(event_id, user_id):
    count = db.execute(
        "SELECT COUNT(*) FROM bookings WHERE event_id = %s", event_id
    ).scalar()
    max_seats = db.execute(
        "SELECT capacity FROM events WHERE id = %s", event_id
    ).scalar()
    if count < max_seats:
        # Another transaction also passed the check, overbooking occurs
        db.execute(
            "INSERT INTO bookings (event_id, user_id) VALUES (%s, %s)",
            event_id, user_id
        )
```

**Missing optimistic concurrency:**
```java
// VULNERABLE: no @Version field, no optimistic locking
@Entity
public class Inventory {
    @Id private Long id;
    private int quantity;  // Missing: @Version private long version;

    // Two threads load quantity=10, both decrement, both save quantity=9
    // Should be 8
}
```

**Dirty read with wrong isolation level:**
```python
# VULNERABLE: READ UNCOMMITTED allows seeing uncommitted changes
# Transaction A begins a transfer, deducts from account
# Transaction B reads the deducted (uncommitted) balance
# Transaction A rolls back — but Transaction B already acted on the dirty read
connection.execute("SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")
```

### 5. File System Races

**Temp file predictable name — symlink attack:**
```c
// VULNERABLE: predictable temp file name
char *tmpfile = "/tmp/myapp_cache";
// Attacker pre-creates: ln -s /etc/passwd /tmp/myapp_cache
FILE *f = fopen(tmpfile, "w");
fprintf(f, "attacker-controlled data");  // Overwrites /etc/passwd
fclose(f);
```

**Python — Insecure temp file:**
```python
# VULNERABLE: tempfile name is predictable, race between name generation and open
import tempfile
tmpname = tempfile.mktemp()   # Returns name but doesn't create file
# Attacker creates symlink at tmpname
with open(tmpname, 'w') as f: # Follows symlink, writes to attacker target
    f.write(sensitive_data)
```

**Symlink race in privileged process:**
```python
# VULNERABLE: privileged process writes to user-controlled path
def write_log(user_home, message):
    log_path = os.path.join(user_home, '.app', 'debug.log')
    if os.path.isfile(log_path):  # Check: is it a regular file?
        # Attacker replaces debug.log with symlink to /etc/crontab between check and write
        with open(log_path, 'a') as f:
            f.write(message)       # Appends to /etc/crontab as root
```

### 6. Authentication / Session Races

**Account lockout bypass:**
```python
# VULNERABLE: parallel requests can all pass the lockout check
def login(username, password):
    user = get_user(username)
    if user.failed_attempts >= MAX_ATTEMPTS:
        raise AccountLocked()
    # 50 concurrent requests all see failed_attempts < MAX_ATTEMPTS
    if not verify_password(password, user.password_hash):
        user.failed_attempts += 1
        user.save()
        raise InvalidCredentials()
    user.failed_attempts = 0
    user.save()
    return create_session(user)
```

**Duplicate registration race:**
```python
# VULNERABLE: check-then-insert without unique constraint or serialization
def register(username, email, password):
    existing = db.execute(
        "SELECT id FROM users WHERE username = %s", username
    ).fetchone()
    if existing:
        raise UsernameExists()
    # Two concurrent registrations both pass the check
    db.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
        username, email, hash_password(password)
    )
    # Result: two accounts with the same username
```

**Session invalidation race:**
```python
# VULNERABLE: race between password change and session revocation
def change_password(user_id, new_password):
    update_password(user_id, new_password)
    # Attacker's session still valid here — they can make requests
    # before revocation completes
    revoke_all_sessions(user_id)  # Not atomic with password change
```

**Parallel MFA bypass:**
```javascript
// VULNERABLE: MFA attempt counter race
async function verifyMFA(userId, code) {
  const attempts = await db.query(
    'SELECT mfa_attempts FROM users WHERE id = $1', [userId]
  );
  if (attempts >= MAX_MFA_ATTEMPTS) throw new Error('Too many attempts');
  // Concurrent requests all see attempts < MAX
  const isValid = totp.verify(code);
  await db.query(
    'UPDATE users SET mfa_attempts = mfa_attempts + 1 WHERE id = $1', [userId]
  );
  return isValid;
}
```

### 7. Signal Handler Races — CWE-479

**C — Non-reentrant function in signal handler:**
```c
// VULNERABLE: malloc is not async-signal-safe
void signal_handler(int sig) {
    char *buf = malloc(256);            // NOT safe in signal handler
    snprintf(buf, 256, "Signal: %d", sig);
    syslog(LOG_ERR, "%s", buf);         // syslog is also not async-signal-safe
    free(buf);
}
```

**errno corruption in signal handler:**
```c
// VULNERABLE: signal handler can corrupt errno between set and check
void handler(int sig) {
    write(fd, "signal\n", 7);  // write() may change errno
}

int main() {
    signal(SIGUSR1, handler);
    if (read(sock, buf, sizeof(buf)) < 0) {
        // Signal arrives between read() returning -1 and this check
        // handler's write() overwrites errno
        if (errno == EAGAIN) {  // errno may now be wrong
            retry();
        }
    }
}
```

### 8. Thread Safety Issues

**Python — GIL does not prevent I/O races:**
```python
# VULNERABLE: GIL is released during I/O operations
import threading

shared_data = {}

def update_cache(key, value):
    if key not in shared_data:       # GIL may be released between check
        shared_data[key] = value     # and write — another thread can interleave
        log_to_file(f"Added {key}")  # I/O releases GIL — race window
```

**Go — Goroutine data race:**
```go
// VULNERABLE: concurrent map access without sync
var cache = make(map[string]string)

func handler(w http.ResponseWriter, r *http.Request) {
    key := r.URL.Query().Get("key")
    if val, ok := cache[key]; ok {   // Concurrent read
        fmt.Fprint(w, val)
    } else {
        val := fetchFromDB(key)
        cache[key] = val              // Concurrent write — PANIC: concurrent map writes
        fmt.Fprint(w, val)
    }
}
```

**Java — Non-volatile shared field:**
```java
// VULNERABLE: 'initialized' may never be visible to other threads
public class ConfigCache {
    private static boolean initialized = false;  // Missing: volatile
    private static Map<String, String> config;

    public static String get(String key) {
        if (!initialized) {       // Thread may see stale value
            config = loadConfig();
            initialized = true;   // Other threads may not see this write
        }
        return config.get(key);   // May NPE — config appears null
    }
}
```

**Java — Double-checked locking (broken without volatile):**
```java
// VULNERABLE: partially constructed instance visible to other threads
public class Singleton {
    private static Singleton instance;  // Missing: volatile

    public static Singleton getInstance() {
        if (instance == null) {
            synchronized (Singleton.class) {
                if (instance == null) {
                    instance = new Singleton();  // May expose partially constructed object
                }
            }
        }
        return instance;
    }
}
```

**Node.js — Async interleaving race:**
```javascript
// VULNERABLE: await yields control, state can change
async function processPayment(orderId) {
  const order = await Order.findById(orderId);
  if (order.status !== 'pending') return;
  // Another request processes the same order here (between awaits)
  const result = await paymentGateway.charge(order.amount);
  order.status = 'paid';
  await order.save();
  // Double charge: both requests charged the payment gateway
}
```

**C# — Lazy initialization without thread safety:**
```csharp
// VULNERABLE: race on instance creation
public class ServiceLocator
{
    private static ServiceLocator _instance;

    public static ServiceLocator Instance
    {
        get
        {
            if (_instance == null)  // Two threads both see null
            {
                _instance = new ServiceLocator();  // Two instances created
            }
            return _instance;
        }
    }
}
```

### 9. Concurrency Primitives — Audit Points

**Java — Insufficient synchronized scope:**
```java
// VULNERABLE: synchronization scope is too narrow
public class Counter {
    private int count = 0;

    public synchronized int getCount() { return count; }
    public synchronized void increment() { count++; }

    public void incrementIfBelow(int max) {
        if (getCount() < max) {   // Lock released between these two calls
            increment();           // Another thread can also pass the check
        }
    }
}
```

**Go — Mutex not covering full critical section:**
```go
// VULNERABLE: mutex only protects the read, not the full read-modify-write
var mu sync.Mutex
var balance int

func withdraw(amount int) bool {
    mu.Lock()
    current := balance
    mu.Unlock()           // Lock released too early!

    if current >= amount {
        mu.Lock()
        balance = current - amount  // Based on stale 'current'
        mu.Unlock()
    }
    return true
}
```

---

## Detection Methodology

### Step 1: Identify Shared Mutable State

Search for global/shared state that multiple threads or requests can access:

```bash
# Python: module-level mutable state
grep -rn "^[a-zA-Z_].*= \{\}" --include="*.py"
grep -rn "^[a-zA-Z_].*= \[\]" --include="*.py"
grep -rn "threading\.\(Lock\|RLock\|Semaphore\)" --include="*.py"

# Java: shared mutable fields
grep -rn "static.*[^final].*Map\|static.*List\|static.*Set" --include="*.java"
grep -rn "synchronized\|volatile\|AtomicInteger\|ConcurrentHashMap" --include="*.java"

# Go: package-level variables
grep -rn "^var " --include="*.go"
grep -rn "sync\.Mutex\|sync\.RWMutex\|sync\.Map" --include="*.go"

# Node.js: module-level mutable state
grep -rn "^let \|^var " --include="*.js" --include="*.ts"

# C#: static mutable fields
grep -rn "static.*\(List\|Dictionary\|HashSet\)" --include="*.cs"
grep -rn "lock\s*(" --include="*.cs"
```

### Step 2: Find Check-Then-Act Patterns

```bash
# File TOCTOU patterns
grep -rn "os\.path\.exists\|os\.path\.isfile\|os\.path\.isdir" --include="*.py"
grep -rn "File\.Exists\|File\.ReadAllText\|Directory\.Exists" --include="*.cs"
grep -rn "access(.*W_OK\|access(.*R_OK" --include="*.c" --include="*.h"
grep -rn "fs\.existsSync\|fs\.accessSync" --include="*.js" --include="*.ts"

# Database check-then-act (SELECT followed by UPDATE/INSERT)
grep -rn "SELECT.*balance\|SELECT.*quantity\|SELECT.*count" --include="*.py" --include="*.java" --include="*.js"
grep -rn "SELECT.*FROM.*WHERE.*\n.*UPDATE\|SELECT.*FROM.*WHERE.*\n.*INSERT" --include="*.sql"

# Permission check then action
grep -rn "\.is_admin\|\.isAdmin\|\.hasPermission\|\.has_role\|\.HasRole" \
    --include="*.py" --include="*.java" --include="*.js" --include="*.cs" --include="*.go"
```

### Step 3: Audit Read-Modify-Write Sequences

```bash
# ORM patterns: load → modify → save (without locking)
grep -rn "\.find\(.*\).*\.save\(\)\|\.get\(.*\).*\.save\(\)" --include="*.py" --include="*.js"
grep -rn "findById\|findOne\|findByPk" --include="*.java" --include="*.js" --include="*.ts"

# Look for balance/inventory/counter operations without FOR UPDATE
grep -rn "balance\|quantity\|stock\|inventory\|credits\|points\|tokens" \
    --include="*.py" --include="*.java" --include="*.js" --include="*.rb" --include="*.cs"

# Check if FOR UPDATE or locking is used
grep -rn "FOR UPDATE\|for_update\|SERIALIZABLE\|pessimistic_lock\|with_lock" \
    --include="*.py" --include="*.java" --include="*.js" --include="*.rb" --include="*.sql"
```

### Step 4: Audit Financial / Inventory Operations

Look for any operation that reads a value, applies business logic, and writes back:

```bash
# Atomic database operations (SAFE patterns to contrast)
grep -rn "SET balance = balance -\|SET quantity = quantity -\|SET count = count +" \
    --include="*.py" --include="*.java" --include="*.js" --include="*.rb" --include="*.sql"

# Find transaction boundaries
grep -rn "@Transactional\|BEGIN\|COMMIT\|ROLLBACK\|atomic\|transaction" \
    --include="*.py" --include="*.java" --include="*.js" --include="*.rb" --include="*.cs"
```

### Step 5: Check Rate Limiting

```bash
# Redis operations that should be atomic
grep -rn "redis.*get.*redis.*incr\|redis.*get.*redis.*set" --include="*.py" --include="*.js"
grep -rn "rate.limit\|ratelimit\|throttle" --include="*.py" --include="*.js" --include="*.java"
```

### Step 6: Audit File Operations

```bash
# Unsafe temp file creation
grep -rn "mktemp\b\|tmpnam\|tempnam\|tmpfile" --include="*.c" --include="*.cpp" --include="*.h"
grep -rn "tempfile\.mktemp\b" --include="*.py"

# Check for safe alternatives
grep -rn "mkstemp\|mkdtemp\|O_CREAT.*O_EXCL\|NamedTemporaryFile\|tempfile\.mkstemp" \
    --include="*.py" --include="*.c" --include="*.cpp"
```

### Step 7: Check Transaction Isolation

```bash
# Explicit isolation level settings
grep -rn "ISOLATION\|isolation_level\|IsolationLevel" \
    --include="*.py" --include="*.java" --include="*.js" --include="*.cs" --include="*.rb"
grep -rn "READ UNCOMMITTED\|READ COMMITTED\|REPEATABLE READ\|SERIALIZABLE" \
    --include="*.py" --include="*.java" --include="*.sql" --include="*.cs"
```

### Step 8: Audit Locking and Synchronization

```bash
# Find all locking constructs (then verify scope covers full critical section)
grep -rn "synchronized\|ReentrantLock\|\.lock()\|\.tryLock()" --include="*.java"
grep -rn "threading\.Lock\|threading\.RLock\|asyncio\.Lock" --include="*.py"
grep -rn "sync\.Mutex\|sync\.RWMutex\|\.Lock()\|\.RLock()" --include="*.go"
grep -rn "lock\s*(\|Monitor\.\|Interlocked\.\|SemaphoreSlim" --include="*.cs"
grep -rn "Mutex\.new\|\.synchronize\b" --include="*.rb"
```

---

## Common Sinks and Sources

### Sources (where race-prone data originates)
| Source | Languages | Risk |
|--------|-----------|------|
| Database reads (SELECT) | All | Stale data used for decisions |
| File system stat/exists | Python, C, Go, Node | State changes between check and use |
| In-memory shared variables | All | Concurrent modification |
| Cache reads (Redis, Memcached) | All | Stale or inconsistent values |
| Session/cookie state | Web frameworks | Concurrent session mutation |
| Environment variables | C, Python, Go | Modified by concurrent threads |
| HTTP request parameters | All web | Concurrent duplicate submissions |

### Sinks (where race-prone data causes harm)
| Sink | Impact |
|------|--------|
| Database writes (UPDATE, INSERT) | Data corruption, double-spend |
| File writes/deletes | Arbitrary file overwrite, data loss |
| Payment gateway calls | Double charges, refund races |
| Account balance modifications | Financial loss |
| Permission grants/revocations | Privilege escalation |
| Session creation/invalidation | Authentication bypass |
| Resource allocation (seats, inventory) | Overbooking, overselling |
| Counter increments (rate limits) | Rate limiting bypass |

---

## False Positive Indicators

A finding is likely a false positive if ANY of the following apply:

1. **Proper transaction with appropriate isolation**: The entire check-then-act sequence
   is wrapped in a `SERIALIZABLE` or `REPEATABLE READ` transaction with proper locking:
   ```python
   with db.begin(isolation_level="SERIALIZABLE"):
       balance = db.execute("SELECT balance FROM accounts WHERE id = %s FOR UPDATE", uid)
       if balance >= amount:
           db.execute("UPDATE accounts SET balance = balance - %s WHERE id = %s", amount, uid)
   ```

2. **Atomic database operation**: The check and update are a single atomic SQL statement:
   ```sql
   UPDATE accounts SET balance = balance - @amount
   WHERE id = @id AND balance >= @amount;
   -- Check rows affected: if 0, insufficient balance
   ```

3. **Proper locking covers the entire critical section**: The mutex/lock wraps both the
   check and the act, not just one of them:
   ```java
   synchronized(this) {
       if (count < max) { count++; }  // Both check and act are locked
   }
   ```

4. **Single-threaded runtime with no async gaps**: The code runs in a single-threaded
   context (e.g., single-process Python without threads) AND there are no `await`, I/O,
   or yield points between the check and the act.

5. **Optimistic concurrency with retry logic**: A version column or timestamp is used
   and the application retries on conflict:
   ```java
   @Version
   private long version;
   // JPA throws OptimisticLockException if version mismatch — caller retries
   ```

6. **Database UNIQUE constraint prevents duplicates**: Even if the application-level
   check races, the database constraint prevents duplicate insertion:
   ```sql
   CREATE UNIQUE INDEX idx_users_username ON users(username);
   -- INSERT will fail for duplicate, application handles the constraint violation
   ```

7. **Idempotency key prevents duplicate processing**: Requests include a unique
   idempotency key, and the system rejects duplicate keys atomically:
   ```sql
   INSERT INTO processed_requests (idempotency_key) VALUES (@key);
   -- UNIQUE constraint violation = duplicate, skip processing
   ```

8. **Atomic compare-and-swap or conditional update**: The update includes the expected
   current value as a condition:
   ```sql
   UPDATE inventory SET quantity = quantity - 1 WHERE id = @id AND quantity > 0;
   ```

---

## Severity Assessment

### Critical
- **Financial double-spend**: Concurrent requests bypass balance checks, causing monetary loss
- **Authentication bypass via race**: Bypassing MFA, account lockout, or session validation
- **Privilege escalation via TOCTOU**: Race on permission check allows unauthorized admin actions
- **Arbitrary file overwrite**: Symlink race in privileged process writes to system files

### High
- **Data corruption in multi-user system**: Lost updates corrupt critical business data
- **Inventory/booking overbooking**: Race condition allows selling more than available stock
- **Race in user registration**: Duplicate accounts bypass uniqueness requirements
- **Session fixation via race**: Concurrent session manipulation bypasses security controls

### Medium
- **Rate limiting bypass**: Concurrent requests exceed intended rate limits
- **Race in non-critical file operations**: Temp file races without privileged context
- **Non-financial counter races**: Vote manipulation, like count inflation
- **Race in logging/audit**: Audit records may be lost or inconsistent

### Low
- **Cosmetic data inconsistency**: Display glitch from stale read, no security impact
- **Race in single-user context**: Only affects the same user, no privilege boundary crossed
- **Race in test/debug code**: Not present in production configuration
- **Benign TOCTOU**: Check-then-act where the "act" is harmless (e.g., logging)

---

## Remediation Patterns

### Database Remediation

**Use atomic conditional updates (preferred):**
```sql
-- SAFE: atomic check-and-update in one statement
UPDATE accounts SET balance = balance - @amount
WHERE id = @id AND balance >= @amount;
-- If affected_rows == 0: insufficient balance (no race possible)
```

**Use SELECT FOR UPDATE (pessimistic locking):**
```sql
BEGIN;
SELECT balance FROM accounts WHERE id = @id FOR UPDATE;  -- Row locked
-- Other transactions block here until this transaction commits
UPDATE accounts SET balance = balance - @amount WHERE id = @id;
COMMIT;
```

**Use optimistic locking with version column:**
```java
@Entity
public class Account {
    @Version private long version;  // Auto-incremented by JPA on save
    private BigDecimal balance;
}
// On concurrent modification: OptimisticLockException → retry
```

**Use appropriate transaction isolation:**
```python
# For inventory/booking: SERIALIZABLE prevents phantom reads
with db.begin(isolation_level="SERIALIZABLE"):
    count = db.execute("SELECT COUNT(*) FROM bookings WHERE event_id = %s", eid).scalar()
    if count < max_capacity:
        db.execute("INSERT INTO bookings (event_id, user_id) VALUES (%s, %s)", eid, uid)
```

### File System Remediation

**Use atomic file creation:**
```c
// SAFE: O_CREAT | O_EXCL fails if file already exists (atomic)
int fd = open(filepath, O_WRONLY | O_CREAT | O_EXCL, 0600);
if (fd < 0) {
    // File already exists — handle error, no TOCTOU
}
```

**Use mkstemp instead of mktemp:**
```c
// SAFE: mkstemp creates and opens file atomically
char template[] = "/tmp/myapp-XXXXXX";
int fd = mkstemp(template);  // Atomically creates unique file with O_EXCL
```

**Python — Use NamedTemporaryFile:**
```python
import tempfile
# SAFE: creates file atomically with a unique name
with tempfile.NamedTemporaryFile(delete=False, dir='/app/tmp') as f:
    f.write(sensitive_data)
    temp_path = f.name
```

### In-Memory Remediation

**Go — Use sync.Map or proper mutex:**
```go
// SAFE: sync.Map is safe for concurrent use
var cache sync.Map

func handler(w http.ResponseWriter, r *http.Request) {
    key := r.URL.Query().Get("key")
    if val, ok := cache.Load(key); ok {
        fmt.Fprint(w, val)
    } else {
        val := fetchFromDB(key)
        cache.Store(key, val)
        fmt.Fprint(w, val)
    }
}
```

**Java — Use ConcurrentHashMap and atomic operations:**
```java
// SAFE: computeIfAbsent is atomic
private static final ConcurrentHashMap<String, Config> cache = new ConcurrentHashMap<>();

public Config getConfig(String key) {
    return cache.computeIfAbsent(key, k -> loadConfig(k));
}
```

**C# — Use Lazy<T> for thread-safe initialization:**
```csharp
// SAFE: Lazy<T> handles thread-safe initialization
private static readonly Lazy<ServiceLocator> _instance =
    new Lazy<ServiceLocator>(() => new ServiceLocator());

public static ServiceLocator Instance => _instance.Value;
```

### Rate Limiting Remediation

**Redis atomic rate limiting with Lua:**
```python
# SAFE: Lua script executes atomically in Redis
RATE_LIMIT_SCRIPT = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local current = redis.call('INCR', key)
if current == 1 then
    redis.call('EXPIRE', key, window)
end
if current > limit then
    return 0
end
return 1
"""

def check_rate_limit(user_id, limit=100, window=60):
    result = redis.eval(RATE_LIMIT_SCRIPT, 1, f"rate:{user_id}", limit, window)
    if result == 0:
        raise RateLimitExceeded()
```

### Authentication Remediation

**Atomic account lockout:**
```sql
-- SAFE: atomic check-and-increment in one statement
UPDATE users
SET failed_attempts = failed_attempts + 1,
    locked_at = CASE WHEN failed_attempts + 1 >= @max THEN NOW() ELSE locked_at END
WHERE username = @username
  AND (locked_at IS NULL OR locked_at < NOW() - INTERVAL '15 minutes');
```

**Duplicate registration prevention:**
```sql
-- SAFE: UNIQUE constraint + ON CONFLICT
INSERT INTO users (username, email, password_hash)
VALUES (@username, @email, @hash)
ON CONFLICT (username) DO NOTHING;
-- Check affected rows: 0 means username already taken
```

### General Principles

1. **Eliminate shared mutable state** where possible — use immutable data structures,
   message passing, or actor models.
2. **Make operations atomic** — use database atomic updates, compare-and-swap, or
   transactions with proper isolation.
3. **Use idempotency keys** for operations that must not be duplicated (payments,
   order processing).
4. **Use proper locking scope** — ensure the lock covers the ENTIRE check-then-act
   sequence, not just part of it.
5. **Prefer optimistic concurrency** for low-contention scenarios (version columns
   with retry logic).
6. **Prefer pessimistic locking** for high-contention or financial operations.

---

## CWE References

| CWE | Name | Relevance |
|-----|------|-----------|
| CWE-362 | Concurrent Execution Using Shared Resource with Improper Synchronization | Primary — covers all race conditions |
| CWE-367 | Time-of-Check Time-of-Use (TOCTOU) Race Condition | File system and permission check races |
| CWE-421 | Race Condition During Access to Alternate Channel | Multi-channel authentication races |
| CWE-364 | Signal Handler Race Condition | Signal handler concurrency issues |
| CWE-366 | Race Condition within a Thread | Thread-level data races on shared memory |
| CWE-667 | Improper Locking | Insufficient or incorrect use of synchronization primitives |
| CWE-820 | Missing Synchronization | Shared resource access without any synchronization |
| CWE-479 | Signal Handler Use of a Non-Reentrant Function | Unsafe function calls in signal handlers |
