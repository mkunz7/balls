<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Codex-native BALLS workflow and evidence rules. -->

# Memory Corruption Vulnerability Detection

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

Memory corruption vulnerabilities remain among the most severe and exploitable classes of
software defects. They occur when a program accesses memory in an unintended way — writing
beyond allocated boundaries, using memory after it has been freed, or interpreting memory as
the wrong type. These flaws undermine the fundamental assumptions of memory safety that
correct program execution depends upon.

### Impact

Memory corruption vulnerabilities can lead to:

- **Arbitrary Code Execution**: Attackers overwrite return addresses, function pointers, or
  vtable entries to hijack control flow and execute shellcode or ROP chains.
- **Privilege Escalation**: Kernel-level memory corruption (e.g., in drivers or syscall
  handlers) allows unprivileged users to gain root/SYSTEM access.
- **Information Disclosure**: Out-of-bounds reads and uninitialized memory leaks expose
  sensitive data such as cryptographic keys, credentials, or ASLR base addresses.
- **Denial of Service**: Null pointer dereferences, double-frees, and heap corruption cause
  crashes, disrupting service availability.

### Language Scope

- **C/C++**: Primary focus. Manual memory management makes these languages inherently
  susceptible to every category of memory corruption.
- **Rust**: Generally memory-safe, but `unsafe` blocks bypass the borrow checker entirely.
  FFI boundaries with C libraries are a common source of memory corruption.
- **Go**: The `unsafe` package and CGo interop introduce memory corruption risks. Slice
  operations and data races on shared memory are additional concerns.
- **Any language with native bindings**: Python (ctypes, cffi), Java (JNI), Node.js (N-API,
  node-ffi) — wherever native code is called, memory corruption is possible.

---

---

## ⚠️ Severity & Reporting Bar — Primitive-or-Omit

Memory-safety defects are **high-volume, low-signal** in most reviews: the vast majority are
theoretical, crash-only, or on non-attacker-controlled paths. To keep reports actionable, apply a
strict bar:

- **Default: do not report.** A pattern match (unchecked `malloc`, an overflowable add, an `unsafe`
  block, a missing null-check) is **not** a finding on its own.
- **Report Medium+ only with a proven exploit primitive**, traced from attacker-controlled input:
  - **write-what-where** — attacker controls both the target address and the written value;
  - **controlled OOB write** that reaches control data (return address, function pointer, vtable,
    heap metadata) or a security decision;
  - **secret-disclosing OOB read** (keys, credentials, ASLR bases); or
  - a proven **control-flow hijack / type confusion**.
- When you have such a primitive, set the finding field **`proven_primitive: true`** and rate it on
  its merits. Otherwise **omit the finding** — at most it is Info, and the Council and the
  deterministic merge step will suppress non-primitive memory-safety findings regardless.
- **Integer overflow/underflow (CWE-190/191) is not a finding by itself.** Only report it when you
  prove it produces a controllable corruption or drives a security decision (e.g., an undersized
  allocation later written past its bounds). "In theory this wraps" is noise.

The patterns below are **detection aids** — use them to locate candidates, then hold every candidate
to the primitive-or-omit bar above before it becomes a finding.

## Vulnerability Patterns

### 1. Buffer Overflow — Stack (CWE-121, CWE-120)

Stack buffer overflows occur when data is written beyond the bounds of a stack-allocated
buffer, potentially overwriting the return address, saved frame pointer, or other local
variables.

#### Dangerous Functions

```c
// VULNERABLE — no bounds checking
char buf[64];
strcpy(buf, user_input);           // No length limit
strcat(buf, suffix);               // Appends without checking remaining space
sprintf(buf, "Hello %s", name);    // No output size limit
gets(buf);                         // Reads unlimited input from stdin (removed in C11)
scanf("%s", buf);                  // Reads until whitespace, no length limit
```

#### Secure Alternatives

```c
// SECURE — bounded operations
char buf[64];
strncpy(buf, user_input, sizeof(buf) - 1);   // Limit copy length
buf[sizeof(buf) - 1] = '\0';                  // Ensure null termination

snprintf(buf, sizeof(buf), "Hello %s", name); // Output size limited

strlcpy(buf, user_input, sizeof(buf));         // BSD/Linux: copies and null-terminates

// C++ preferred approach
std::string safe_buf = user_input;             // Automatically managed
```

#### Detection Patterns

```
# Grep for banned string functions
grep -rn 'strcpy\s*(' --include='*.c' --include='*.cpp' --include='*.h'
grep -rn 'strcat\s*(' --include='*.c' --include='*.cpp' --include='*.h'
grep -rn 'sprintf\s*(' --include='*.c' --include='*.cpp' --include='*.h'
grep -rn 'gets\s*(' --include='*.c' --include='*.cpp' --include='*.h'
grep -rn 'scanf\s*\(\s*"%s"' --include='*.c' --include='*.cpp'

# Fixed-size stack buffers (potential targets)
grep -rn 'char\s\+\w\+\s*\[\s*[0-9]\+\s*\]' --include='*.c' --include='*.cpp'
```

### 2. Buffer Overflow — Heap (CWE-122)

Heap buffer overflows occur when data is written beyond the bounds of a heap-allocated
buffer. These are often more exploitable than stack overflows because heap metadata can
be corrupted to achieve arbitrary write primitives.

#### Vulnerable Patterns

```c
// VULNERABLE — writing more than allocated
char *buf = malloc(64);
fread(buf, 1, 128, file);          // Reading 128 bytes into 64-byte buffer

// VULNERABLE — realloc not checked
char *new_buf = realloc(buf, new_size);
// If realloc fails, new_buf is NULL but buf is still valid
// If realloc succeeds, buf may be a dangling pointer (buffer moved)
buf[0] = 'A';  // Use-after-free if realloc moved the buffer

// VULNERABLE — off-by-one in heap allocation
char *dup = malloc(strlen(src));    // Missing +1 for null terminator
strcpy(dup, src);                   // Writes one byte past allocation
```

#### Secure Alternatives

```c
// SECURE — check realloc return value
char *new_buf = realloc(buf, new_size);
if (new_buf == NULL) {
    // Handle allocation failure — buf is still valid
    free(buf);
    return ERROR;
}
buf = new_buf;  // Update pointer only on success

// SECURE — correct allocation size
char *dup = malloc(strlen(src) + 1);  // +1 for null terminator
if (dup != NULL) {
    strcpy(dup, src);
}
```

#### Detection Patterns

```
# Grep for malloc followed by unchecked writes
grep -rn 'malloc\s*(' --include='*.c' --include='*.cpp'
grep -rn 'realloc\s*(' --include='*.c' --include='*.cpp'
grep -rn 'calloc\s*(' --include='*.c' --include='*.cpp'

# Look for strlen without +1 in malloc
grep -rn 'malloc\s*(.*strlen' --include='*.c' --include='*.cpp'
```

### 3. Use-After-Free (CWE-416) and Double-Free (CWE-415)

Use-after-free occurs when a program continues to use a pointer after the memory it
references has been freed. Double-free is a specific variant where `free()` is called
twice on the same pointer, corrupting the heap allocator's metadata.

#### Vulnerable Patterns

```c
// VULNERABLE — use-after-free
struct request *req = parse_request(input);
if (req->type == INVALID) {
    free(req);
}
// ... later in the function ...
log_request(req->url);  // UAF if req was freed above

// VULNERABLE — dangling pointer in data structure
void remove_node(struct list *list, struct node *n) {
    list_remove(list, n);
    free(n);
    // n is still referenced by other_list — UAF when other_list is traversed
}

// VULNERABLE — double-free
free(ptr);
if (error_condition) {
    free(ptr);  // Double-free: ptr was already freed
}

// VULNERABLE — C++ unique_ptr misuse
std::unique_ptr<Obj> uptr = std::make_unique<Obj>();
Obj *raw = uptr.get();
uptr.reset();       // Object destroyed
raw->method();      // UAF via dangling raw pointer
```

#### Secure Alternatives

```c
// SECURE — null pointer after free
free(req);
req = NULL;  // Prevents use-after-free (will crash on NULL deref instead)

// SECURE — C++ RAII and smart pointers
auto obj = std::make_shared<Object>();
// shared_ptr reference counting prevents premature deallocation

// SECURE — C++ weak_ptr for non-owning references
std::weak_ptr<Object> weak = shared;
if (auto locked = weak.lock()) {
    locked->method();  // Safe: object is guaranteed alive
}
```

#### Detection Patterns

```
# Grep for free() calls and trace pointer usage afterward
grep -rn 'free\s*(' --include='*.c' --include='*.cpp' --include='*.h'

# Look for patterns: free then use on same variable
grep -rn 'free\s*(\s*\w\+\s*)' --include='*.c' --include='*.cpp'

# C++ raw pointer extraction from smart pointers
grep -rn '\.get\s*()' --include='*.cpp' --include='*.h'
grep -rn '\.release\s*()' --include='*.cpp' --include='*.h'

# Double-free indicators — free in error-handling paths
grep -rn 'goto.*err' --include='*.c' --include='*.cpp'
```

### 4. Integer Overflow and Underflow (CWE-190, CWE-191)

Integer overflow occurs when an arithmetic operation produces a result that exceeds the
maximum value the integer type can represent. When used in memory allocation sizes or
bounds checks, this leads to allocating too-small buffers or bypassing security checks.

#### Vulnerable Patterns

```c
// VULNERABLE — multiplication overflow in allocation
size_t total = count * sizeof(struct element);  // Overflows if count is large
void *buf = malloc(total);                       // Allocates tiny buffer
// Writing count elements overflows the undersized buffer

// VULNERABLE — integer truncation
uint32_t big_len = get_length_from_network();    // e.g., 0x10000
uint16_t len = (uint16_t)big_len;                // Truncated to 0x0000
char *buf = malloc(len + 1);                     // malloc(1)
memcpy(buf, data, big_len);                      // Massive overflow

// VULNERABLE — signed/unsigned comparison
int user_offset = get_user_offset();             // Could be negative
if (user_offset < buffer_size) {                 // Negative passes this check
    buffer[user_offset] = value;                 // Negative index — write before buffer
}

// VULNERABLE — addition wrap-around in bounds check
size_t offset = get_offset();
size_t len = get_len();
if (offset + len > buf_size) {  // If offset + len wraps around to small value
    return ERROR;                // Check is bypassed
}
memcpy(dest + offset, src, len);  // Out-of-bounds write
```

#### Secure Alternatives

```c
// SECURE — checked multiplication
if (count > SIZE_MAX / sizeof(struct element)) {
    return ERROR;  // Would overflow
}
size_t total = count * sizeof(struct element);

// SECURE — compiler built-in overflow checks
size_t total;
if (__builtin_mul_overflow(count, sizeof(struct element), &total)) {
    return ERROR;
}

// SECURE — safe bounds check (no addition)
if (offset > buf_size || len > buf_size - offset) {
    return ERROR;  // Cannot wrap around
}

// SECURE — use calloc for array allocations (checks internally)
struct element *arr = calloc(count, sizeof(struct element));
```

#### Detection Patterns

```
# Grep for arithmetic in malloc/calloc/realloc arguments
grep -rn 'malloc\s*(.*\*' --include='*.c' --include='*.cpp'
grep -rn 'malloc\s*(.*+' --include='*.c' --include='*.cpp'

# Signed/unsigned comparison warnings
grep -rn 'size_t.*int\|int.*size_t' --include='*.c' --include='*.cpp'

# Type truncation in assignments
grep -rn 'uint16_t.*=.*(uint32_t\|size_t\|unsigned long)' --include='*.c' --include='*.cpp'

# Addition in bounds checks
grep -rn 'if\s*(.*+.*>.*size\|if\s*(.*+.*>.*len\|if\s*(.*+.*>.*length' --include='*.c' --include='*.cpp'
```

### 5. Format String Vulnerabilities (CWE-134)

Format string vulnerabilities occur when user-controlled data is passed as the format
string argument to functions like `printf`, `sprintf`, `syslog`, etc. An attacker can
use format specifiers (`%x`, `%n`, `%s`) to read from or write to arbitrary memory.

#### Vulnerable Patterns

```c
// VULNERABLE — user input as format string
printf(user_input);                              // Attacker uses %x%x%x to leak stack
fprintf(stderr, user_input);                     // Same issue
snprintf(buf, sizeof(buf), user_input);          // Same issue
syslog(LOG_ERR, user_input);                     // Same issue — often overlooked

// VULNERABLE — indirect format string
char *msg = get_error_message(error_code);       // If msg comes from untrusted source
printf(msg);                                      // Format string vuln
```

#### Secure Alternatives

```c
// SECURE — always use a literal format string
printf("%s", user_input);
fprintf(stderr, "%s", user_input);
syslog(LOG_ERR, "%s", user_input);

// SECURE — fputs for simple string output
fputs(user_input, stdout);
```

#### Detection Patterns

```
# Grep for printf-family with variable (non-literal) format string
grep -rn 'printf\s*(\s*[a-zA-Z_]' --include='*.c' --include='*.cpp'
grep -rn 'fprintf\s*(\s*\w\+\s*,\s*[a-zA-Z_]' --include='*.c' --include='*.cpp'
grep -rn 'sprintf\s*(\s*\w\+\s*,\s*[a-zA-Z_]' --include='*.c' --include='*.cpp'
grep -rn 'snprintf\s*(\s*\w\+\s*,\s*\w\+\s*,\s*[a-zA-Z_]' --include='*.c' --include='*.cpp'
grep -rn 'syslog\s*(\s*\w\+\s*,\s*[a-zA-Z_]' --include='*.c' --include='*.cpp'

# Broader: any format function where the format arg is not a string literal
grep -rn '\(printf\|fprintf\|syslog\|sprintf\|snprintf\)' --include='*.c' --include='*.cpp'
```

### 6. Out-of-Bounds Read/Write (CWE-125, CWE-787)

Out-of-bounds access occurs when a program reads from or writes to memory locations
outside the allocated boundaries of a buffer or array. This includes both under-reads
(negative indices) and over-reads/writes (past the end).

#### Vulnerable Patterns

```c
// VULNERABLE — off-by-one in loop bounds
int arr[SIZE];
for (int i = 0; i <= SIZE; i++) {     // Should be i < SIZE
    arr[i] = compute(i);              // Writes one element past the array
}

// VULNERABLE — unchecked array index from external input
int index = get_user_index();
return table[index];                   // No bounds check — OOB read

// VULNERABLE — negative index
int offset = user_value - base;        // Could be negative
data[offset] = payload;                // Writes before start of buffer

// VULNERABLE — Heartbleed-style over-read
uint16_t payload_len = ntohs(*(uint16_t*)ptr);  // Attacker-controlled length
memcpy(response, payload, payload_len);          // Reads past actual payload
```

#### Secure Alternatives

```c
// SECURE — strict bounds checking
if (index < 0 || index >= TABLE_SIZE) {
    return ERROR;
}
return table[index];

// SECURE — correct loop bounds
for (int i = 0; i < SIZE; i++) {       // Strict less-than
    arr[i] = compute(i);
}

// SECURE — validate length against actual data
if (payload_len > actual_data_len) {
    return ERROR;
}
memcpy(response, payload, payload_len);
```

#### Detection Patterns

```
# Off-by-one in loops: <= used with array size
grep -rn 'for\s*(.*<=.*SIZE\|for\s*(.*<=.*size\|for\s*(.*<=.*len\|for\s*(.*<=.*count' --include='*.c' --include='*.cpp'

# Array access without prior bounds check
grep -rn '\w\+\s*\[.*\w\+\s*\]' --include='*.c' --include='*.cpp'

# memcpy/memmove with potentially unbounded length
grep -rn 'memcpy\s*(' --include='*.c' --include='*.cpp'
grep -rn 'memmove\s*(' --include='*.c' --include='*.cpp'
```

### 7. Null Pointer Dereference (CWE-476)

Null pointer dereference occurs when a program attempts to access memory through a
pointer that is NULL. While often causing a crash (DoS), in some kernel contexts or
with specific memory layouts, this can lead to code execution.

#### Vulnerable Patterns

```c
// VULNERABLE — unchecked malloc return
char *buf = malloc(size);
memset(buf, 0, size);            // Crash if malloc returned NULL

// VULNERABLE — unchecked fopen return
FILE *f = fopen(path, "r");
fread(data, 1, len, f);          // Crash if fopen returned NULL

// VULNERABLE — dereference before NULL check
void process(struct obj *o) {
    int type = o->type;          // Dereference
    if (o == NULL) return;       // Too late — already dereferenced
}

// VULNERABLE — error path leaves pointer NULL
struct config *cfg = NULL;
if (load_config(&cfg) != SUCCESS) {
    log_error("config load failed");
    // Falls through without returning
}
cfg->setting = value;            // NULL dereference if load failed
```

#### Secure Alternatives

```c
// SECURE — check all allocations
char *buf = malloc(size);
if (buf == NULL) {
    return -ENOMEM;
}

// SECURE — check before dereference
if (o == NULL) {
    return ERROR;
}
int type = o->type;

// SECURE — C++ exceptions or optional
auto buf = std::make_unique<char[]>(size);  // Throws on failure
std::optional<Config> cfg = load_config();
if (!cfg.has_value()) return ERROR;
```

#### Detection Patterns

```
# Grep for malloc/calloc/realloc without NULL check
grep -rn 'malloc\s*(' --include='*.c' --include='*.cpp'
grep -rn 'calloc\s*(' --include='*.c' --include='*.cpp'
grep -rn 'fopen\s*(' --include='*.c' --include='*.cpp'

# Dereference-before-check pattern (pointer used, then checked for NULL)
grep -rn 'if\s*(\s*\w\+\s*==\s*NULL' --include='*.c' --include='*.cpp'
```

### 8. Uninitialized Memory (CWE-908)

Uninitialized memory vulnerabilities occur when a program reads the value of a variable
or memory region before it has been explicitly assigned a value. The memory contains
whatever data was previously stored at that location, which may include sensitive
information from previous operations.

#### Vulnerable Patterns

```c
// VULNERABLE — uninitialized stack variable
int result;
if (condition) {
    result = compute();
}
return result;                   // Uninitialized if condition is false

// VULNERABLE — partially initialized struct
struct response resp;
resp.status = 200;
// resp.padding and other fields contain stack garbage
send(sockfd, &resp, sizeof(resp), 0);  // Leaks stack data via padding

// VULNERABLE — missing memset after malloc
char *buf = malloc(256);
// buf contains heap garbage — may leak info if sent before fully written
send(sockfd, buf, 256, 0);
```

#### Secure Alternatives

```c
// SECURE — always initialize
int result = 0;  // Default value
struct response resp = {0};  // Zero-initialize entire struct

// SECURE — use calloc for zero-initialized heap memory
char *buf = calloc(256, 1);  // All bytes zeroed

// SECURE — explicit memset
struct response resp;
memset(&resp, 0, sizeof(resp));
resp.status = 200;
```

#### Detection Patterns

```
# Grep for struct declarations without initialization
grep -rn 'struct\s\+\w\+\s\+\w\+\s*;' --include='*.c' --include='*.cpp'

# Look for malloc without subsequent memset
grep -rn 'malloc\s*(' --include='*.c' --include='*.cpp'

# Variables declared without initialization
grep -rn '^\s*int\s\+\w\+\s*;' --include='*.c' --include='*.cpp'
grep -rn '^\s*char\s\+\w\+\s*;' --include='*.c' --include='*.cpp'
grep -rn '^\s*size_t\s\+\w\+\s*;' --include='*.c' --include='*.cpp'
```

### 9. Type Confusion (CWE-843)

Type confusion occurs when a program accesses a memory region using a type that differs
from the type it was originally allocated or intended as. This can cause the program to
interpret fields at wrong offsets, leading to memory corruption.

#### Vulnerable Patterns

```c
// VULNERABLE — unsafe cast between unrelated types
struct animal *a = (struct animal *)get_object();
// get_object() may return a struct vehicle — fields at wrong offsets
a->legs = 4;  // Writes to wrong memory offset if not actually an animal

// VULNERABLE — union type punning
union variant {
    int as_int;
    char *as_str;
};
union variant v;
v.as_int = 42;
printf("%s\n", v.as_str);  // Interprets 42 as a pointer — crash or info leak

// VULNERABLE — unchecked dynamic_cast in C++
Base *b = get_object();
Derived *d = dynamic_cast<Derived*>(b);
d->derived_method();  // NULL pointer deref if cast failed (b is not Derived)

// VULNERABLE — void* without type validation
void process(void *data, int type) {
    // Caller passes type=STRING but data points to an int
    struct string_data *s = (struct string_data *)data;
    printf("%s\n", s->value);  // Type confusion
}
```

#### Secure Alternatives

```c
// SECURE — check dynamic_cast result
Derived *d = dynamic_cast<Derived*>(b);
if (d == nullptr) {
    return ERROR;  // Not the expected type
}
d->derived_method();

// SECURE — use std::variant in C++17
std::variant<int, std::string> v = 42;
if (auto *s = std::get_if<std::string>(&v)) {
    // Safely accessed as string only if it is one
}

// SECURE — tagged unions with validation
if (data->type != EXPECTED_TYPE) {
    return ERROR;
}
```

#### Detection Patterns

```
# Grep for void* casts
grep -rn '(void\s*\*)' --include='*.c' --include='*.cpp'

# C-style casts between pointer types
grep -rn '(\s*struct\s\+\w\+\s*\*)' --include='*.c' --include='*.cpp'

# reinterpret_cast in C++
grep -rn 'reinterpret_cast' --include='*.cpp' --include='*.h'

# dynamic_cast without null check
grep -rn 'dynamic_cast' --include='*.cpp' --include='*.h'

# Union definitions (review for type punning)
grep -rn 'union\s\+\w\+' --include='*.c' --include='*.cpp' --include='*.h'
```

### 10. Rust-Specific Memory Corruption

Rust's ownership and borrow checker prevent most memory corruption at compile time.
However, `unsafe` blocks explicitly opt out of these guarantees.

#### Vulnerable Patterns

```rust
// VULNERABLE — raw pointer dereference
unsafe {
    let ptr: *const u8 = get_raw_pointer();
    let value = *ptr;  // No guarantee ptr is valid, aligned, or non-null
}

// VULNERABLE — transmute between incompatible types
unsafe {
    let v: Vec<u8> = vec![0x41; 16];
    let s: String = std::mem::transmute(v);  // v may not be valid UTF-8
}

// VULNERABLE — from_raw_parts with wrong length
unsafe {
    let slice = std::slice::from_raw_parts(ptr, user_controlled_len);
    // OOB read if user_controlled_len > actual allocation
}

// VULNERABLE — ManuallyDrop misuse
let obj = ManuallyDrop::new(MyStruct::new());
let raw = &*obj as *const MyStruct;
drop(ManuallyDrop::into_inner(obj));  // Object dropped
unsafe { (*raw).method(); }           // Use-after-free

// VULNERABLE — FFI boundary
extern "C" {
    fn c_function(buf: *mut u8, len: usize);
}
let mut data = vec![0u8; 64];
unsafe {
    c_function(data.as_mut_ptr(), 128);  // C function writes 128 bytes into 64-byte buf
}
```

#### Detection Patterns

```
# All unsafe blocks
grep -rn 'unsafe\s*{' --include='*.rs'

# Raw pointer operations
grep -rn '\*const\s\|\*mut\s' --include='*.rs'
grep -rn 'as\s\+\*const\|as\s\+\*mut' --include='*.rs'

# Dangerous transmute
grep -rn 'transmute' --include='*.rs'

# from_raw_parts (slice or string construction from raw pointers)
grep -rn 'from_raw_parts' --include='*.rs'

# FFI declarations
grep -rn 'extern\s\+"C"' --include='*.rs'

# ManuallyDrop usage
grep -rn 'ManuallyDrop' --include='*.rs'
```

### 11. Go-Specific Memory Corruption

Go is memory-safe by default, but the `unsafe` package and CGo interop reintroduce
memory corruption risks.

#### Vulnerable Patterns

```go
// VULNERABLE — unsafe.Pointer type conversion
var i int64 = 42
p := unsafe.Pointer(&i)
s := (*string)(p)  // Type confusion: int64 memory interpreted as string header

// VULNERABLE — CGo memory management
/*
#include <stdlib.h>
*/
import "C"

func leaky() {
    cstr := C.CString("hello")  // Allocates C memory
    // Missing: defer C.free(unsafe.Pointer(cstr))
    // Memory leak; or if freed elsewhere, potential double-free
}

// VULNERABLE — slice header manipulation
sh := (*reflect.SliceHeader)(unsafe.Pointer(&mySlice))
sh.Len = sh.Cap * 2  // OOB access when iterating the slice

// VULNERABLE — data race on shared memory
var counter int
go func() { counter++ }()
go func() { counter++ }()
// Race condition — undefined behavior in Go runtime
```

#### Detection Patterns

```
# unsafe package usage
grep -rn 'unsafe\.Pointer' --include='*.go'
grep -rn 'unsafe\.Sizeof\|unsafe\.Offsetof\|unsafe\.Alignof' --include='*.go'

# CGo imports
grep -rn 'import "C"' --include='*.go'
grep -rn 'C\.CString\|C\.GoString\|C\.malloc\|C\.free' --include='*.go'

# reflect.SliceHeader / StringHeader manipulation
grep -rn 'SliceHeader\|StringHeader' --include='*.go'

# Data race indicators (shared state without sync)
grep -rn 'go func' --include='*.go'
```

---

## Detection Methodology

Follow this systematic approach when auditing a codebase for memory corruption:

### Step 1: Enumerate Attack Surface

Identify all source files and categorize by risk:

```
# Find all C/C++ source files
glob pattern: **/*.{c,cpp,cc,cxx,h,hpp,hxx}

# Find Rust files with unsafe blocks
grep -rn 'unsafe' --include='*.rs'

# Find Go files with unsafe or CGo
grep -rn 'unsafe\|import "C"' --include='*.go'
```

### Step 2: Scan for Banned Functions

Search for known-dangerous functions that should never appear in new code:

| Function | Risk | Replacement |
|----------|------|-------------|
| `gets()` | Unbounded read | `fgets()` |
| `strcpy()` | Unbounded copy | `strncpy()`, `strlcpy()` |
| `strcat()` | Unbounded append | `strncat()`, `strlcat()` |
| `sprintf()` | Unbounded format | `snprintf()` |
| `scanf("%s")` | Unbounded scan | `scanf("%63s")` with width |
| `vsprintf()` | Unbounded vformat | `vsnprintf()` |
| `realpath()` | May overflow PATH_MAX | Use with caller-allocated buffer |
| `getwd()` | Deprecated, may overflow | `getcwd()` |

```
# Combined banned function scan
grep -rnE '(gets|strcpy|strcat|sprintf|vsprintf|scanf\s*\(\s*"%s")\s*\(' --include='*.c' --include='*.cpp' --include='*.h'
```

### Step 3: Audit Memory Allocation and Deallocation Pairs

For every `malloc`/`calloc`/`realloc`, verify:
- Return value is checked for NULL
- Allocation size is validated (no integer overflow)
- Every allocation has exactly one matching `free` on all code paths
- Pointer is set to NULL after free

```
# Find all allocation sites
grep -rn 'malloc\|calloc\|realloc\|free\|new\s\|delete\s' --include='*.c' --include='*.cpp' --include='*.h'
```

### Step 4: Audit Integer Arithmetic in Security-Critical Contexts

Check all arithmetic used in:
- Buffer size calculations (`malloc(a * b)`)
- Bounds checks (`if (offset + len > size)`)
- Array index calculations
- Length fields read from external input

### Step 5: Audit Format String Usage

Verify that every call to printf-family functions uses a string literal as the format:

```
# Non-literal format strings (high confidence)
grep -rnE '(printf|fprintf|syslog|sprintf|snprintf)\s*\([^"]*,[^"]*\b[a-z_]\w*\s*\)' --include='*.c' --include='*.cpp'
```

### Step 6: Audit Array and Pointer Access Patterns

Review all array indexing operations:
- Is the index validated against array bounds?
- Are loop termination conditions correct (`<` not `<=`)?
- Are pointer arithmetic results within bounds?

### Step 7: Review Error Handling Paths

Error paths are a common source of memory corruption because they are less tested:
- Are all resources freed exactly once on error?
- Do `goto` cleanup labels handle partial initialization?
- Are early returns leaving dangling pointers in shared structures?

---

## Common Sinks and Sources

### Sources (Attacker-Controlled Data Entry Points)

| Source | Description |
|--------|-------------|
| `read()`, `recv()`, `recvfrom()` | Network/file data |
| `fread()`, `fgets()` | File input |
| `getenv()` | Environment variables |
| `argv[]` | Command-line arguments |
| `scanf()`, `fscanf()` | Formatted input |
| HTTP headers, query params | Web server input |
| Shared memory segments | IPC data |
| `mmap()` of untrusted files | Memory-mapped file data |
| Deserialized data (protobuf, JSON) | Structured input from untrusted sources |

### Sinks (Memory-Sensitive Operations)

| Sink | Risk |
|------|------|
| `memcpy()`, `memmove()` | Buffer overflow if length unchecked |
| `strcpy()`, `strcat()` | Buffer overflow (unbounded) |
| `malloc()`, `realloc()` | Integer overflow in size argument |
| `free()` | Double-free, use-after-free |
| Array indexing `a[i]` | Out-of-bounds read/write |
| Pointer arithmetic `p + offset` | Out-of-bounds access |
| `printf(fmt)` | Format string if fmt is attacker-controlled |
| `ioctl()` | Kernel memory corruption if args unchecked |
| `write()`, `send()` | Information disclosure if buffer has uninit data |

---

## False Positive Indicators

When triaging findings, consider these factors that may indicate a false positive:

### Bounds Already Checked

```c
// NOT VULNERABLE — bounds validated before use
if (index >= 0 && index < ARRAY_SIZE) {
    return array[index];  // Grep may flag this, but it's safe
}
```

### Compiler/Platform Protections

- `__builtin_add_overflow()`, `__builtin_mul_overflow()` — GCC/Clang safe arithmetic
- `_Check_return_` / `_Must_inspect_result_` — SAL annotations in MSVC
- `__attribute__((nonnull))` — Function guarantees non-null arguments
- `_Nonnull`, `_Nullable` — Clang nullability annotations
- Compile-time assertions: `_Static_assert(sizeof(buf) >= MAX_INPUT)`

### Sanitizer Coverage

If the project runs with sanitizers in CI, some issues may already be caught at runtime:
- **AddressSanitizer (ASan)**: Detects buffer overflows, UAF, double-free, stack-use-after-return
- **MemorySanitizer (MSan)**: Detects uninitialized memory reads
- **UndefinedBehaviorSanitizer (UBSan)**: Detects integer overflow, null deref, type issues
- **ThreadSanitizer (TSan)**: Detects data races

Check for sanitizer flags in build configuration:
```
grep -rn 'fsanitize' --include='Makefile' --include='CMakeLists.txt' --include='*.cmake' --include='*.mk'
grep -rn 'fsanitize' --include='*.yml' --include='*.yaml'
```

### Safe Wrappers

Projects may define safe wrapper functions around dangerous operations. Check for:
- Custom `safe_malloc()`, `xmalloc()` that abort on NULL
- Custom `safe_strncpy()` that always null-terminates
- `g_malloc()` (GLib), `apr_palloc()` (APR) — library allocators with different guarantees

### Static Analysis Attributes

```c
// False positive indicator — function contract specifies non-null
void process(__attribute__((nonnull)) struct obj *o) {
    o->field = value;  // Compiler enforces non-null at call sites
}
```

---

## Severity Assessment

### Critical (CVSS 9.0-10.0)

- **Remote** buffer overflow with **no authentication** required
- Use-after-free in **network-facing** code (e.g., HTTP parser, TLS handler)
- Format string vulnerability reachable from **external input**
- Integer overflow leading to **heap overflow** in protocol parsing
- Memory corruption in **kernel drivers** or **privileged services**

### High (CVSS 7.0-8.9)

- Stack buffer overflow reachable from **authenticated** remote input
- Use-after-free in **complex state machines** (requires specific sequence)
- Type confusion in **deserialization** of untrusted data
- Out-of-bounds write via **file format parsing** (e.g., image, PDF)
- Uninitialized memory leak exposing **cryptographic material**

### Medium (CVSS 4.0-6.9)

- Null pointer dereference causing **DoS** (crash but no code execution)
- Out-of-bounds **read** leaking non-sensitive information
- Integer overflow in **non-security-critical** calculation
- Memory corruption requiring **local access** and **specific configuration**
- Uninitialized memory in **logging** (limited information exposure)

### Low (CVSS 0.1-3.9)

- Memory corruption in **test/debug code** not compiled in production
- Theoretical overflow requiring **extremely large input** that is bounded by other limits
- Null pointer dereference in **error handling** that already indicates failure
- Uninitialized read of **non-sensitive** padding bytes

---

## Remediation Patterns

### Immediate Fixes

1. **Replace banned functions** with bounded alternatives:
   - `strcpy` → `strncpy` / `strlcpy` / `std::string`
   - `sprintf` → `snprintf`
   - `gets` → `fgets`
   - `scanf("%s")` → `scanf("%63s")` or `fgets` + `sscanf`

2. **Add NULL checks** after every allocation:
   ```c
   void *p = malloc(size);
   if (p == NULL) { handle_error(); return; }
   ```

3. **Null pointers after free**:
   ```c
   free(ptr);
   ptr = NULL;
   ```

4. **Fix integer overflow in allocations**:
   ```c
   // Before: malloc(count * elem_size)  — may overflow
   // After:
   if (count > SIZE_MAX / elem_size) return ERROR;
   malloc(count * elem_size);
   // Or use calloc(count, elem_size) which checks internally
   ```

### Architectural Improvements

1. **Migrate to smart pointers in C++**:
   - `std::unique_ptr<T>` for exclusive ownership
   - `std::shared_ptr<T>` for shared ownership
   - `std::weak_ptr<T>` for non-owning references
   - Eliminate all `new`/`delete` in favor of `std::make_unique`/`std::make_shared`

2. **Enable compiler and OS protections**:
   - **Stack Canaries**: `-fstack-protector-strong` (GCC/Clang)
   - **ASLR**: Ensure PIE is enabled (`-fPIE -pie`)
   - **DEP/NX**: Mark stack and heap non-executable
   - **RELRO**: `-Wl,-z,relro,-z,now` (full RELRO)
   - **CFI**: `-fsanitize=cfi` (Control Flow Integrity)
   - **SafeStack**: `-fsanitize=safe-stack`

3. **Safe integer arithmetic libraries**:
   - `safe_iop` — Safe integer operation library
   - `<stdckdint.h>` — C23 checked integer arithmetic
   - `__builtin_add_overflow` / `__builtin_mul_overflow` — GCC/Clang builtins
   - `SafeInt<T>` — Microsoft's safe integer class

4. **Integrate sanitizers in CI/CD**:
   ```yaml
   # Example CI configuration
   - name: Build with ASan
     run: |
       export CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g"
       export LDFLAGS="-fsanitize=address"
       make clean && make
       make test
   ```

5. **Use memory-safe languages for new components**:
   - Write new modules in Rust, Go, or other memory-safe languages
   - Expose C-compatible FFI interfaces for integration
   - Gradually replace C/C++ components over time

6. **Adopt secure coding standards**:
   - CERT C Coding Standard (SEI CERT)
   - MISRA C (automotive/embedded)
   - C++ Core Guidelines (Bjarne Stroustrup, Herb Sutter)

---

## CWE References

| CWE ID | Name | Category |
|--------|------|----------|
| [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | Buffer Copy without Checking Size of Input | Buffer Overflow |
| [CWE-121](https://cwe.mitre.org/data/definitions/121.html) | Stack-based Buffer Overflow | Buffer Overflow |
| [CWE-122](https://cwe.mitre.org/data/definitions/122.html) | Heap-based Buffer Overflow | Buffer Overflow |
| [CWE-125](https://cwe.mitre.org/data/definitions/125.html) | Out-of-bounds Read | Out-of-Bounds |
| [CWE-134](https://cwe.mitre.org/data/definitions/134.html) | Use of Externally-Controlled Format String | Format String |
| [CWE-190](https://cwe.mitre.org/data/definitions/190.html) | Integer Overflow or Wraparound | Integer Overflow |
| [CWE-191](https://cwe.mitre.org/data/definitions/191.html) | Integer Underflow | Integer Underflow |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) | Double Free | Use-After-Free |
| [CWE-416](https://cwe.mitre.org/data/definitions/416.html) | Use After Free | Use-After-Free |
| [CWE-476](https://cwe.mitre.org/data/definitions/476.html) | NULL Pointer Dereference | Null Pointer |
| [CWE-787](https://cwe.mitre.org/data/definitions/787.html) | Out-of-bounds Write | Out-of-Bounds |
| [CWE-843](https://cwe.mitre.org/data/definitions/843.html) | Access of Resource Using Incompatible Type | Type Confusion |
| [CWE-908](https://cwe.mitre.org/data/definitions/908.html) | Use of Uninitialized Resource | Uninitialized Memory |

---

## Additional References

- [MITRE CWE Top 25 (2024)](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html)
- [Microsoft SDL Banned Function Calls](https://learn.microsoft.com/en-us/previous-versions/bb288454(v=msdn.10))
- [SEI CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c)
- [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/)
- [Google Project Zero — Memory Safety](https://googleprojectzero.blogspot.com/)
- [Chromium Memory Safety](https://www.chromium.org/Home/chromium-security/memory-safety/)
