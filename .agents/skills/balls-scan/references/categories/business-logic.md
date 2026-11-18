<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Antigravity BALLS workflow and evidence rules. -->

## Overview

Business logic vulnerabilities arise when application workflows, state machines, or validation rules can be subverted through legitimate application functionality. Unlike technical vulnerabilities (XSS, SQLi), these flaws exploit assumptions in how business processes are implemented. They are often invisible to automated scanners because the individual operations are technically valid — it is the sequence, combination, or parameter manipulation that creates the vulnerability.

## Required workflow and invariant trace

For each security-relevant workflow, write down its states, allowed transitions, invariants, and irreversible side effects. Trace the actual order of validation, database commits, external calls, authorization decisions, and session assignment. For every operation that can fail, determine whether rollback/compensation runs and what later requests can observe or use. Check repeated submissions, retries, and alternate orderings when source code makes them reachable.

Report a broken invariant only when source proves a reachable sequence that violates it and a later operation uses the inconsistent state to affect confidentiality, integrity, or availability. State the initial state, triggering action, failure or transition, persisted result, and resulting protected action. Avoid inferring intended business rules that are not represented in code or supplied project documentation.

## Vulnerability Patterns

### Price and Quantity Manipulation

```python
# Python/Django — VULNERABLE: Price from client-side
class OrderView(APIView):
    def post(self, request):
        # VULNERABLE: Trusting client-supplied price
        item_price = request.data['price']
        quantity = request.data['quantity']
        total = item_price * quantity

        Order.objects.create(
            user=request.user,
            total=total,
            item_id=request.data['item_id']
        )
```

```javascript
// Node.js/Express — VULNERABLE: Negative quantity
app.post('/api/cart/update', (req, res) => {
    const { itemId, quantity } = req.body;

    // VULNERABLE: No validation on quantity sign or bounds
    const item = catalog.getItem(itemId);
    const lineTotal = item.price * quantity; // quantity = -5 gives credit

    cart.updateItem(itemId, quantity, lineTotal);
});
```

```java
// Java/Spring — VULNERABLE: Discount manipulation
@PostMapping("/apply-coupon")
public ResponseEntity<?> applyCoupon(@RequestBody CouponRequest request) {
    Cart cart = cartService.getCart(request.getUserId());

    // VULNERABLE: No check for multiple coupon applications
    // VULNERABLE: No validation that discount doesn't exceed total
    double discount = couponService.getDiscount(request.getCouponCode());
    cart.setTotal(cart.getTotal() - discount);

    // VULNERABLE: Total can go negative
    cartService.save(cart);
    return ResponseEntity.ok(cart);
}
```

```csharp
// C# — VULNERABLE: Currency/unit assumption
[HttpPost("transfer")]
public IActionResult Transfer(TransferRequest request)
{
    // VULNERABLE: No validation on currency — user sends USD amount
    // but backend credits in BTC or higher-value currency
    var amount = request.Amount;
    accountService.Debit(request.FromAccount, amount);
    accountService.Credit(request.ToAccount, amount); // Different currency assumed
    return Ok();
}
```

### Payment Flow Bypass

```python
# Python — VULNERABLE: Payment step can be skipped
class CheckoutView(APIView):
    def post(self, request):
        order_id = request.data['order_id']
        order = Order.objects.get(id=order_id)

        # VULNERABLE: Only checks if order exists, not if payment was processed
        # User can call /confirm-order directly without going through /process-payment
        order.status = 'confirmed'
        order.save()
        shipping_service.ship(order)
```

```javascript
// Node.js — VULNERABLE: Client-side payment verification
app.post('/api/checkout/confirm', async (req, res) => {
    const { orderId, paymentConfirmed } = req.body;

    // VULNERABLE: Trusting client-side payment confirmation flag
    if (paymentConfirmed) {
        await orderService.confirmOrder(orderId);
        await shippingService.createShipment(orderId);
        return res.json({ status: 'confirmed' });
    }
});
```

```java
// Java — VULNERABLE: Race condition in payment
@Transactional
public void processPayment(Long orderId) {
    Order order = orderRepository.findById(orderId).get();

    // VULNERABLE: TOCTOU race — two simultaneous requests can both
    // see balance as sufficient and proceed
    if (walletService.getBalance(order.getUserId()) >= order.getTotal()) {
        walletService.debit(order.getUserId(), order.getTotal());
        order.setStatus(OrderStatus.PAID);
        orderRepository.save(order);
    }
}
```

### Workflow Step Bypass

```python
# Python/Django — VULNERABLE: Steps not enforced server-side
class ApplicationWizard(APIView):
    def post(self, request, step):
        application = Application.objects.get(id=request.data['app_id'])

        # VULNERABLE: No validation that previous steps were completed
        # User can POST to /application/5/submit directly
        if step == 'personal_info':
            application.personal_info = request.data
        elif step == 'documents':
            application.documents = request.data
        elif step == 'submit':
            # Missing check: were personal_info and documents completed?
            application.status = 'submitted'
            application.save()
```

```go
// Go — VULNERABLE: State machine allows invalid transitions
func (h *Handler) UpdateOrderStatus(w http.ResponseWriter, r *http.Request) {
    var req StatusUpdateRequest
    json.NewDecoder(r.Body).Decode(&req)

    order, _ := h.orderRepo.Get(req.OrderID)

    // VULNERABLE: No state machine validation
    // Can go from "pending" directly to "delivered", skipping payment/shipping
    order.Status = req.NewStatus
    h.orderRepo.Save(order)
}
```

### State Machine Violations

```python
# SECURE: Proper state machine implementation
VALID_TRANSITIONS = {
    'draft':     ['submitted'],
    'submitted': ['under_review', 'rejected'],
    'under_review': ['approved', 'rejected', 'needs_revision'],
    'needs_revision': ['submitted'],
    'approved':  ['active'],
    'rejected':  [],
    'active':    ['suspended', 'completed'],
    'suspended': ['active', 'completed'],
    'completed': [],
}

def transition_order(order, new_status):
    allowed = VALID_TRANSITIONS.get(order.status, [])
    if new_status not in allowed:
        raise InvalidTransitionError(
            f"Cannot transition from {order.status} to {new_status}"
        )
    order.status = new_status
    order.save()
```

### Feature and Rate Limit Abuse

```javascript
// Node.js — VULNERABLE: Bulk operation without limits
app.post('/api/invitations/send-bulk', async (req, res) => {
    const { emails } = req.body;

    // VULNERABLE: No limit on number of emails
    // Attacker sends 100,000 invitation emails
    for (const email of emails) {
        await emailService.sendInvitation(email, req.user);
    }

    res.json({ sent: emails.length });
});
```

```python
# Python — VULNERABLE: Coupon reuse
class RedeemCouponView(APIView):
    def post(self, request):
        coupon = Coupon.objects.get(code=request.data['code'])

        # VULNERABLE: Race condition allows multiple redemptions
        # Two simultaneous requests both see coupon as valid
        if coupon.is_valid and coupon.uses_remaining > 0:
            apply_discount(request.user.cart, coupon.discount)
            coupon.uses_remaining -= 1
            coupon.save()
```

```java
// Java — VULNERABLE: Referral bonus abuse
@PostMapping("/referral/claim")
public ResponseEntity<?> claimReferral(@RequestBody ReferralRequest req) {
    User referrer = userService.findById(req.getReferrerId());
    User newUser = userService.findById(req.getNewUserId());

    // VULNERABLE: No check if referrer and new user are the same person
    // VULNERABLE: No check on number of referrals from same IP/device
    // VULNERABLE: No minimum activity requirement for new user
    walletService.credit(referrer.getWalletId(), REFERRAL_BONUS);
    return ResponseEntity.ok().build();
}
```

### Time-Based Logic Flaws

```python
# Python — VULNERABLE: Token expiry bypass
def verify_reset_token(token):
    record = PasswordResetToken.objects.get(token=token)

    # VULNERABLE: Comparison uses server time but token was issued
    # with client-provided timezone offset
    if record.expires_at > datetime.now():
        return True

    # VULNERABLE: Token not invalidated after use
    # Can be reused multiple times within validity window
    return False
```

```javascript
// Node.js — VULNERABLE: Time-limited offer bypass
app.post('/api/flash-sale/purchase', (req, res) => {
    const sale = getSale(req.body.saleId);

    // VULNERABLE: Time check uses client-provided timestamp
    const clientTime = new Date(req.body.timestamp);
    if (clientTime < sale.endTime) {
        processDiscountedPurchase(req.body);
    }
});
```

### Assumption-Based Logic Flaws

```go
// Go — VULNERABLE: Currency assumption
func Transfer(from, to string, amount float64) error {
    // VULNERABLE: Assumes both accounts use the same currency
    // Attacker creates account in low-value currency, transfers to high-value
    fromAccount, _ := getAccount(from)
    toAccount, _ := getAccount(to)

    fromAccount.Balance -= amount
    toAccount.Balance += amount // Same numeric amount, different currencies!

    saveAccount(fromAccount)
    saveAccount(toAccount)
    return nil
}
```

```python
# Python — VULNERABLE: Unit assumption
def calculate_shipping(weight, destination):
    # VULNERABLE: Assumes weight is in kg but user can send grams
    # 1000g item submitted as "1000" interpreted as 1000kg
    # or 0.001 kg item getting free shipping threshold
    if weight < 0.5:
        return 0  # Free shipping for light items
    return weight * RATE_PER_KG
```

## Detection Methodology

1. **Payment Flow Analysis**: Trace all checkout/payment flows end-to-end — identify if payment verification is server-side and atomic
2. **Input Trust Boundaries**: Identify where business-critical values (prices, quantities, discounts, status) come from client input vs. server-side lookups
3. **State Machine Audit**: Map all status/state transitions and verify that only valid transitions are enforced server-side
4. **Workflow Step Enforcement**: Check multi-step processes for server-side step completion tracking
5. **Race Condition Points**: Identify TOCTOU (time-of-check-to-time-of-use) windows in financial operations, coupon redemption, and resource allocation
6. **Boundary Validation**: Check for missing validation on numeric ranges (negative, zero, overflow, decimal precision)
7. **Referential Integrity**: Verify that operations reference correct entities (user A can't modify user B's cart)
8. **Time-Based Controls**: Audit all time comparisons for timezone issues, client-provided timestamps, and token reuse
9. **Bulk Operation Limits**: Identify endpoints that process arrays/batches without size limits
10. **Assumption Mapping**: Document implicit assumptions in business logic (currency, units, user roles) and verify they are enforced

## Common Sinks and Sources

### Business-Critical Functions
- Payment processing: `charge()`, `processPayment()`, `checkout()`, `purchase()`
- Account operations: `transfer()`, `withdraw()`, `credit()`, `debit()`
- Discount/coupon: `applyCoupon()`, `applyDiscount()`, `redeem()`
- Status changes: `updateStatus()`, `transition()`, `approve()`, `confirm()`
- Shipping: `calculateShipping()`, `createShipment()`
- User management: `promote()`, `changeRole()`, `inviteUser()`
- Voting/rating: `vote()`, `rate()`, `review()`

### Client-Controlled Inputs to Watch
- Price, quantity, total, subtotal, discount amount
- Status, state, step, phase fields
- User IDs, account IDs, role IDs in request bodies
- Timestamps, timezone offsets, expiration dates
- Currency codes, unit specifications
- Coupon codes and redemption counts
- Bulk operation array sizes

## False Positive Indicators

- **Admin-only endpoints**: Legitimate admin functions that allow price overrides, status changes, etc. — verify access control is enforced
- **Calculated but verified**: Client sends a total, but server recalculates and compares before processing
- **Idempotency keys**: Operations protected by idempotency tokens are resistant to replay
- **Optimistic locking**: Version fields or ETags that prevent concurrent modification
- **Explicit state machines**: Libraries like `django-fsm`, `aasm`, `xstate` that enforce valid transitions
- **Test/sandbox modes**: A bypass is excluded only when repository-defined configuration and the assessed entry point enforce the intended test-only boundary; a comment or hoped-for production override is not evidence
- **Internal service calls**: Service-to-service calls with trusted input may intentionally skip validation

## Severity Assessment

| Finding | Severity |
|---------|----------|
| Payment bypass allowing free purchases | **Critical** |
| Price/total manipulation in checkout | **Critical** |
| Negative quantity resulting in account credit | **Critical** |
| Financial transaction race condition | **Critical** |
| Workflow step bypass skipping security checks | **High** |
| State machine violation allowing invalid transitions | **High** |
| Unlimited coupon/discount redemption | **High** |
| Bulk operation abuse (no size limits) | **High** |
| Referral/reward system abuse | **Medium** |
| Time-based logic bypass (expired offer use) | **Medium** |
| Currency/unit assumption mismatch | **Medium** |
| Feature flag abuse (non-financial) | **Medium** |
| Missing idempotency on non-financial operations | **Low** |

## Remediation Patterns

### Server-Side Price Calculation
```python
# SECURE: Always calculate price server-side
def create_order(user, cart_items):
    total = Decimal('0')
    for item in cart_items:
        product = Product.objects.get(id=item['product_id'])
        quantity = max(1, int(item['quantity']))  # Minimum 1, integer only
        line_total = product.price * quantity
        total += line_total

    if total <= 0:
        raise ValidationError("Order total must be positive")

    return Order.objects.create(user=user, total=total)
```

### Atomic Financial Operations
```python
# SECURE: Use database-level locking
from django.db import transaction
from django.db.models import F

@transaction.atomic
def redeem_coupon(user, coupon_code):
    coupon = Coupon.objects.select_for_update().get(code=coupon_code)

    if coupon.uses_remaining <= 0:
        raise ValidationError("Coupon exhausted")

    # Atomic decrement prevents race condition
    updated = Coupon.objects.filter(
        code=coupon_code, uses_remaining__gt=0
    ).update(uses_remaining=F('uses_remaining') - 1)

    if updated == 0:
        raise ValidationError("Coupon no longer available")

    apply_discount(user.cart, coupon.discount)
```

### State Machine Enforcement
```javascript
// SECURE: Explicit state machine with validated transitions
const stateMachine = {
  draft:      { submit: 'pending_review' },
  pending_review: { approve: 'approved', reject: 'rejected' },
  approved:   { activate: 'active' },
  rejected:   { revise: 'draft' },
  active:     { suspend: 'suspended', complete: 'completed' },
  suspended:  { reactivate: 'active' },
  completed:  {},
};

function transitionOrder(order, action) {
  const transitions = stateMachine[order.status];
  if (!transitions || !transitions[action]) {
    throw new Error(`Invalid action '${action}' for status '${order.status}'`);
  }
  order.status = transitions[action];
  return order.save();
}
```

### Workflow Step Enforcement
```go
// SECURE: Track completed steps server-side
func (h *Handler) SubmitApplication(w http.ResponseWriter, r *http.Request) {
    app, _ := h.appRepo.Get(r.Context(), appID)

    requiredSteps := []string{"personal_info", "documents", "verification"}
    for _, step := range requiredSteps {
        if !app.CompletedSteps[step] {
            http.Error(w, fmt.Sprintf("Step '%s' not completed", step), http.StatusBadRequest)
            return
        }
    }

    app.Status = "submitted"
    h.appRepo.Save(r.Context(), app)
}
```

## CWE References

- **CWE-840**: Business Logic Errors
- **CWE-841**: Improper Enforcement of Behavioral Workflow
- **CWE-799**: Improper Control of Interaction Frequency
- **CWE-770**: Allocation of Resources Without Limits or Throttling
- **CWE-362**: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)
- **CWE-367**: Time-of-check Time-of-use (TOCTOU) Race Condition
- **CWE-20**: Improper Input Validation
- **CWE-345**: Insufficient Verification of Data Authenticity
- **CWE-372**: Incomplete Internal State Distinction
- **CWE-708**: Incorrect Ownership Assignment
