# ATTACK_SURFACE.md

**Status:** ⚠️ RECONSTRUCTED / UNVERIFIED. Built from public product knowledge and
public developer docs because the live assets and the HackerOne scope table are
egress-blocked from this environment (see SCOPE_SNAPSHOT.md). This is a *planning*
model for a human researcher to validate against the real, authorized scope — **not**
an assertion that any asset here is authorized for testing.

**Method (Section 5):** Understand the application before touching it. For each
candidate asset: purpose, trust/auth/authz boundaries, the security-relevant
lifecycles, likely server-side invariants, and the concurrency-sensitive operations
that tend to break in financial systems.

---

## 1. Cross-cutting security invariants (apply to every money-moving asset)

These are the assumptions that, if violated *server-side*, produce the highest-value
findings. Every hypothesis in RESEARCH_PLAN.md is an instance of one of these.

| Invariant | Statement | Where it usually breaks |
|-----------|-----------|-------------------------|
| INV-OWN | A caller may only read/mutate objects it owns | IDOR on order/wallet/transfer/ticket IDs; ownership checked on one endpoint but not a sibling |
| INV-AUTHZ | Privileged actions require the correct role/scope | Frontend-only gating; API accepts fields the UI hides |
| INV-BAL | Σ credits − Σ debits is conserved; no balance created from nothing | Race on withdrawal/transfer; partial-failure rollback gaps; retry double-credit |
| INV-IDEM | A given logical operation executes **at most once** | Missing/naive idempotency key; retry after client timeout; async worker re-delivery |
| INV-STATE | Only valid state transitions are accepted | Cancel-after-complete; revive expired; replay old request after state change |
| INV-SIGN | A signature/authorization binds to *exactly* the request executed | Delimiter-free signing-string concatenation; identity/operation not bound to signature |
| INV-ASSET | Currency/asset/chain of an operation is fixed and validated | Asset confusion; precision/decimals mismatch; testnet↔mainnet confusion |
| INV-AUTHN | Session/token identity == acting principal, with correct audience/scope/expiry | Token audience confusion; stale session after revoke; MFA/recovery state desync |

---

## 2. Candidate assets and their surfaces

### A. Crypto.com App (retail) — mobile + backend API
- **Purpose:** Buy/sell/convert, custodial balances, transfers, card top-up, Earn.
- **Trust boundary:** Mobile client is **untrusted**; backend must re-validate
  everything. Deep links and any WebView bridge are trust boundaries.
- **Auth boundary:** Login → session/access token; MFA; device binding.
- **Authz boundary:** Per-user object ownership; KYC-tier gating of limits/features.
- **Lifecycles to map:** account, session, device, MFA, recovery, deposit,
  withdrawal, internal transfer, convert/trade, card top-up, Earn subscribe/redeem.
- **Server-side invariants at risk:** INV-OWN (transfers, transaction history),
  INV-BAL/INV-IDEM (convert, transfer, card top-up), INV-STATE (withdrawal cancel),
  INV-AUTHN (recovery/MFA desync), INV-ASSET (convert precision).
- **Concurrency-sensitive ops:** convert, internal transfer, withdrawal request +
  cancel, Earn redeem — all classic double-execute candidates.

### B. Crypto.com Exchange — web + REST/WS trading API
- **Purpose:** Spot, margin, derivatives, OTC, Institutional trading; deposits/
  withdrawals; API-key programmatic access.
- **Public contract:** `exchange-docs.crypto.com` documents REST/WS v1 including a
  **HMAC-SHA256 request-signing scheme** (see API_MAP.md §3). Signing string =
  `method + id + api_key + params_to_str(params) + nonce`, where `params_to_str`
  concatenates sorted `key+value` **with no delimiters**.
- **Trust boundary:** API client untrusted; server recomputes signature with the
  key's secret. WS auth channel is a separate trust surface.
- **Auth boundary:** API key + secret (HMAC); scoped permissions
  (read / trade / withdraw); IP allowlists; nonce/timestamp window.
- **Authz boundary:** Key scope enforcement; account/sub-account isolation; withdraw
  permission gating; withdrawal address allowlisting.
- **Lifecycles to map:** API-key create/scope/revoke; order create/amend/cancel/fill;
  withdrawal request/allowlist/approve/broadcast; deposit credit; sub-account
  transfer; staking/OTC settlement.
- **Server-side invariants at risk:** INV-SIGN (concatenation ambiguity, nonce
  replay window, id/nonce binding), INV-IDEM (order `client_oid` reuse; amend/cancel
  races), INV-STATE (cancel-after-fill; amend-after-fill), INV-OWN (sub-account
  isolation; reading others' orders), INV-BAL (settlement/rollback on partial fills),
  INV-ASSET (instrument/precision/tick-size).
- **Concurrency-sensitive ops:** cancel-replace, amend, withdrawal request vs.
  cancel, sub-account transfer, self-trade prevention edge cases.

### C. DeFi / Onchain Wallet — self-custody (mobile + extension)
- **Purpose:** Non-custodial multi-chain wallet; dApp connect (WalletConnect-style);
  swaps/bridges; token approvals.
- **Trust boundary (critical):** Keys are on-device. The high-value bugs are
  **client-side that reach key/signing** — e.g., malicious dApp deep link causing an
  unintended signature, transaction-request parsing that misrepresents what's being
  signed (blind-signing UI mismatch), WebView↔native bridge exposing signing.
- **Root-cause caveat:** On-chain protocol/contract bugs of *third-party* dApps are
  out of scope; a **Crypto.com-controlled** swap/bridge backend or the wallet's own
  signing/approval UX is the eligible surface.
- **Lifecycles to map:** wallet create/import/backup/recovery; dApp session; sign
  message; sign & send tx; token approval; swap/bridge quote→execute.
- **Invariants at risk:** INV-SIGN (what the UI shows vs. what is signed),
  INV-AUTHN (deep-link/session trust), INV-ASSET (chain/token confusion in swap/bridge
  backend).

### D. Crypto.com Pay — payments/checkout + merchant API
- **Purpose:** Consumer pay + merchant integration (create charge, webhook,
  settlement).
- **Trust boundary:** Merchant server ↔ Pay API; webhook authenticity; the checkout
  page.
- **Auth boundary:** Merchant API key/secret; webhook signature.
- **Authz/invariants at risk:** INV-OWN (read/modify another merchant's charges),
  INV-IDEM (charge/settlement double-processing), INV-SIGN (webhook signature
  verification bypass / replay), INV-STATE (charge status transition: expire→pay→
  refund races), INV-BAL (refund > charge; over-settlement).
- **Concurrency-sensitive ops:** charge capture, refund, webhook re-delivery.

### E. Visa Card program — issuance/rewards backend
- **Root-cause caveat:** Card rails/issuer usually **third-party** → likely out of
  scope. Eligible only for the **Crypto.com-controlled** portions (rewards/cashback
  ledger, top-up flow). Note: cashback *abuse* is commonly policy-excluded — verify.

### F. NFT marketplace — web + API
- **Invariants at risk:** INV-OWN (transfer/list on behalf of another), INV-STATE
  (buy-after-delist; bid/settle races), INV-BAL (royalty/fee arithmetic), INV-IDEM
  (mint/purchase double-execute).

### G. Earn / Supercharger / Staking — financial products backend
- **Invariants at risk:** INV-IDEM (subscribe/redeem double), INV-STATE
  (redeem-after-lock; early-unstake), INV-BAL (interest accrual arithmetic;
  rounding), INV-ASSET (reward-asset conversion precision).

### H. Corporate web / auth / SSO
- **Invariants at risk:** INV-AUTHN (OAuth/OIDC audience/scope confusion, token
  reuse across products, account linking), password-reset/recovery state, MFA
  enrollment/removal races. Note many *cosmetic* web issues here are policy-excluded
  (headers, self-XSS, open redirects) — keep to server-side authz/authn.

### I. Help/Support platform
- Almost certainly **third-party SaaS** → out of scope by root-cause rule unless a
  Crypto.com-controlled SSO/handoff defect leaks a session. Deprioritize.

---

## 3. Highest-leverage surfaces (where to spend time, per Section 31 priority)

1. **Authorization/ownership** across sibling endpoints (INV-OWN, INV-AUTHZ) — App
   transaction/transfer objects; Exchange sub-account isolation; Pay merchant
   isolation; NFT ownership. *Cheap to test with two controlled accounts, high yield.*
2. **Financial state machines & idempotency** (INV-STATE, INV-IDEM, INV-BAL) —
   convert/transfer/withdrawal cancel; order amend/cancel-after-fill; Pay
   charge/refund; Earn redeem. *Requires care; test only own accounts, min values.*
3. **Signing/replay** (INV-SIGN) — Exchange HMAC concatenation ambiguity + nonce
   window; Pay webhook signature verification. *Analyzable partly from public docs;
   confirmation needs live test with own key.*
4. **Auth/recovery/session** (INV-AUTHN) — MFA/recovery desync; token
   audience/scope confusion across products; session revocation completeness.

De-prioritize (mostly policy-excluded): security headers, TLS config, banners,
self-XSS, open redirects, clickjacking-without-theft, KYC-deepfake bypass.

---

## 4. What is explicitly OUT of this surface

- Cronos / Crypto.org chain node & smart-contract code → HackenProof program.
- Third-party issuer/SaaS/cloud/CDN/analytics/email components (root-cause rule).
- The local Monero repo (`BDR-Pro/Jero`) → not a Crypto.com asset.
