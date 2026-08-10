# API_MAP.md

**Status:** Framework + the one API contract that is **publicly documented** and
therefore analyzable without touching a blocked/authorized asset (the Exchange API
signing scheme). Everything else is a **template** for a human researcher to
populate from authorized traffic (Section 11). No live endpoint was probed from this
environment (`crypto.com`/`exchange-docs.crypto.com` are egress-blocked; the scheme
below is reconstructed from public developer documentation and community SDKs).

---

## 1. Endpoint record schema (fill one per endpoint, Section 11)

```
METHOD:              GET | POST | WS-subscribe | WS-request
PATH / CHANNEL:      /v1/private/...
AUTH:                none | session token | API-key HMAC | OAuth scope
ROLE / KYC TIER:     required principal / tier
KEY SCOPE:           read | trade | withdraw  (which is required)
PARAMETERS:          name → type, constraints, server-recomputed? (Y/N)
OBJECT OWNERSHIP:    which id ties to the caller; where is it checked?
STATE REQUIREMENTS:  required prior state(s); allowed transitions
IDEMPOTENCY:         key field? dedupe window? retry behavior?
SIDE EFFECT:         balance/order/state mutation; async workers triggered
EXPECTED INVARIANT:  the INV-* this endpoint must uphold (see ATTACK_SURFACE.md §1)
DIFFERENTIAL NOTES:  sibling endpoints touching the same object/state
```

---

## 2. Reconstruction methodology (Section 11)
1. Proxy the authorized web + mobile clients (own accounts) through an intercepting
   proxy; capture real requests.
2. Diff mobile vs. web vs. documented public API for the same operation → look for a
   backend that enforces weaker rules (Section 10).
3. Enumerate object-id parameters; for each, record where ownership *should* be
   checked.
4. Reconstruct each money-moving **state machine** and its idempotency key.
5. For every confirmed invariant, list **all** sibling endpoints that touch the same
   object → variant analysis (Section 17).

---

## 3. Publicly-documented contract: Exchange REST/WS v1 request signing

> Source: public `exchange-docs.crypto.com` documentation and community SDKs (read
> via public mirrors/search; the host itself is blocked here). Verify current text
> against the live docs before relying on it.

**Signature construction:**
```
paramString = params_to_str(params)
   # keys sorted ascending; concatenated as  key + value  (NO delimiter, NO spaces);
   # nested objects flattened recursively (documented max nesting level 3);
   # all numbers MUST be strings (double-quoted).

sigPayload  = method + id + api_key + paramString + nonce
signature   = HMAC_SHA256( key = api_secret, msg = sigPayload )  → hex
```
- `id` = request id (int); docs recommend STRING format for order ids "to guarantee
  correctness of the Digital Signature."
- `nonce` = current time in ms; server checks a timestamp window.
- Server recomputes the signature with the stored secret; match ⇒ authentic.

**Security-relevant properties to interrogate (see RESEARCH_PLAN H-3):**
| Property | Question | Why it matters |
|----------|----------|----------------|
| Delimiter-free concat | Can two *different* param sets produce the **same** `paramString`? | Ambiguity ⇒ signature binds to a different logical request than executed (INV-SIGN) |
| `params_to_str` recursion cap (level 3) | What happens to params nested deeper than 3? Dropped? Signed-but-sent? | Signed-vs-executed divergence |
| Number-as-string rule | Does server accept numeric where string expected, changing `paramString`? | Signature/executed mismatch |
| `nonce` window | How wide is the accept window; is `(api_key, nonce)` enforced unique? | Replay within window (INV-SIGN) |
| `id` binding | Is `id` bound to anything the server acts on, or cosmetic? | Cross-request confusion |
| Key scope | Is `withdraw` scope enforced server-side on every withdraw-capable path? | Scope escalation (INV-AUTHZ) |

**Honest caveat on exploitability:** an API client signs with **its own** secret,
so signature *forgery* against another user is not the threat. The realistic threat
class is **signed-vs-executed divergence** — the server executing a request that
differs from the exact bytes the signature covered (via concatenation ambiguity,
recursion cap, or type coercion), or **replay** within a loose nonce window. Both
require live testing with a researcher-owned key to confirm, and their impact may be
limited to the researcher's own account unless combined with another flaw. Treat as
a hypothesis, not a finding.

---

## 4. Template rows to populate under authorized testing (examples, UNVERIFIED)

| METHOD | PATH (candidate) | AUTH | INVARIANT to test | Differential sibling |
|--------|------------------|------|-------------------|----------------------|
| POST | `/v1/private/create-order` | key/HMAC, trade scope | INV-IDEM (`client_oid` reuse), INV-ASSET (precision) | amend / cancel |
| POST | `/v1/private/cancel-order` | key/HMAC, trade scope | INV-STATE (cancel-after-fill) | amend, mass-cancel |
| POST | `/v1/private/create-withdrawal` | key/HMAC, **withdraw** scope | INV-IDEM (retry double), INV-STATE (cancel race), allowlist | cancel-withdrawal |
| GET  | `/v1/private/get-order-detail` | key/HMAC, read | INV-OWN (other account's order id) | get-order-history |
| POST | sub-account transfer | key/HMAC | INV-OWN (foreign sub-account), INV-BAL | — |

> These paths are **illustrative placeholders** to shape testing, not confirmed
> current endpoints. Populate from real authorized captures.
