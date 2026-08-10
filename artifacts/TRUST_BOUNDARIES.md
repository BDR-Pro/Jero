# TRUST_BOUNDARIES.md

**Status:** ⚠️ Model built from public architecture knowledge of custodial
crypto-exchange/wallet platforms (Section 6). Not derived from privileged access.
Use it to locate *where one component trusts a value another was expected to
validate* — that seam is where the best financial-authz bugs live.

**Method:** For each boundary, two questions:
- **(X)** What attacker-controlled value crosses this boundary?
- **(A)** What assumption does the receiving side make about that value?

A finding exists when **(A) is assumed but never enforced on a reachable path.**

---

## 1. Layered model

```
[0] End user (attacker may control their own account fully)
      │  credentials, device, session token, all request bodies
      ▼
[1] Web / Mobile / API client   ── UNTRUSTED. Anything the client "enforces" is advisory.
      │  HTTP(S)/WSS requests, signed API requests, deep links, WebView bridge
      ▼
[2] Edge / API gateway / WAF / CDN
      │  routed request, client IP (spoofable via headers?), rate-limit identity
      ▼
[3] Authentication service (session, OAuth/OIDC, API-key HMAC, MFA)
      │  principal identity, token audience/scope/expiry, MFA/recovery state
      ▼
[4] Authorization / policy (roles, KYC tier, key scope, account/sub-account)
      │  "who may act on which object / which operation"
      ▼
[5] Business logic (orders, transfers, convert, Pay charges, Earn, NFT)
      │  validated operation + parameters
      ▼
[6] Financial ledger / wallet / matching engine (balances, holds, settlement)
      │  balance mutations, holds/locks, idempotency keys, state transitions
      ▼
[7] External integrations (blockchain nodes/RPC, banks, card issuer, payment PSPs)
      value crossing an org boundary — deposits, withdrawals, card auth, settlement
```

---

## 2. Boundary-by-boundary analysis

### B1: Client → Edge (the primary attacker boundary)
- **(X):** Every request field, header, signed payload, WS frame, deep link.
- **(A) commonly (wrongly) assumed:** "the client already validated/enforced this"
  (hidden fields, disabled buttons, min/max, enum values, ownership).
- **Prime bugs:** client-only authz (INV-AUTHZ), server accepts fields the UI hides,
  enum/amount not re-validated server-side. **Cheapest high-yield seam.**

### B2: Edge → Auth
- **(X):** Session token / API-key signature / MFA assertion; forwarded client IP.
- **(A):** Token is authentic, unexpired, correct **audience & scope**; IP allowlist
  reflects true source (not a spoofable `X-Forwarded-For`).
- **Prime bugs:** token audience/scope confusion (a token minted for product P
  accepted by product Q), IP-allowlist bypass via header injection, nonce/timestamp
  replay window on HMAC.

### B3: Auth → Authorization
- **(X):** Authenticated principal id + claimed target object id / operation.
- **(A):** "authentication implies authorization for this object" — the classic
  fallacy. Ownership must be re-checked at the object, not inferred from a valid
  session.
- **Prime bugs:** IDOR (INV-OWN), horizontal/vertical privilege escalation, KYC-tier
  gate enforced in UI but not API, sub-account / merchant / tenant isolation gaps.

### B4: Authorization → Business logic
- **(X):** The *operation intent* (order, transfer, refund, redeem) + parameters.
- **(A):** State is what the client last saw; the transition requested is valid from
  the *current* server state; the operation is fresh (not a replay/retry).
- **Prime bugs:** invalid state transitions (INV-STATE) — cancel-after-fill,
  revive-expired, replay-after-state-change; TOCTOU between check and act.

### B5: Business logic → Ledger / matching / wallet (the money seam)
- **(X):** Balance mutations, holds, idempotency key, asset+amount+precision.
- **(A):** Each logical op applies **once**, **atomically**; failure rolls back
  **completely**; two concurrent ops on the same balance serialize; asset & decimals
  are fixed.
- **Prime bugs:** INV-IDEM (retry/async double-apply), INV-BAL (race creates value;
  partial-failure leaves a hold released but debit not applied, or credit applied
  twice), INV-ASSET (precision truncation/rounding, asset confusion). **Highest
  severity if reachable — "unrestricted balance manipulation" = Integrity:High.**

### B6: Platform → External integrations
- **(X):** Withdrawal address/amount/asset; deposit credit event; card auth; PSP
  webhook; RPC responses.
- **(A):** The external event is authentic (webhook signature valid & non-replayable),
  deposits are final/confirmed before credit, withdrawals debit before broadcast and
  are idempotent against retries, chain/network is the intended one.
- **Prime bugs:** webhook signature bypass/replay (INV-SIGN) crediting funds; deposit
  credited before finality / on reorg; withdrawal double-broadcast on retry;
  testnet↔mainnet / chain confusion (INV-ASSET). **Root-cause caveat:** the *issuer/
  PSP/RPC vendor* may be third-party — eligible only where Crypto.com's own
  verification/idempotency/config is the defect.

---

## 3. Cross-component disagreement map (Section 32: "find disagreement between components")

The richest bugs come from **two components disagreeing about the same fact.** Look
for these disagreements specifically:

| Fact | Component A view | Component B view | Exploit if they disagree |
|------|------------------|------------------|--------------------------|
| Object ownership | Endpoint X checks it | Sibling endpoint Y doesn't | IDOR via Y |
| Order state | Matching engine: filled | Cancel API: still open | Cancel-after-fill / value creation |
| Idempotency key | Sync path dedupes | Async worker re-processes | Double execution |
| Session validity | Auth service: revoked | Product API: cached valid | Action after logout/revoke |
| Token audience | Product P mints | Product Q accepts | Cross-product token reuse |
| Asset/precision | Quote service | Settlement service | Rounding/asset confusion drain |
| Deposit finality | Node: unconfirmed | Ledger: credited | Spend-before-finality |
| What is signed | UI shows tx A | Signer signs tx B | Wallet blind-sign mismatch |

Each row is a concrete two-account (or two-endpoint) differential test — see
RESEARCH_PLAN.md.

---

## 4. Boundaries explicitly outside this engagement
- Node ↔ node P2P / consensus of Cronos/Crypto.org chains → HackenProof.
- Internal service-to-service links not reachable from an in-scope external asset.
- Third-party-owned segments of B6 where Crypto.com controls neither code nor config.
