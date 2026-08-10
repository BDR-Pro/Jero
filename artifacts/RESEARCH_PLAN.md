# RESEARCH_PLAN.md

**Status:** Prioritized hypothesis plan for a **human researcher with authorized,
live HackerOne access**. From *this* automated, egress-blocked environment none of
these can be executed (see SCOPE_SNAPSHOT.md §7). Each hypothesis is written so a
human can confirm-or-destroy it safely, on researcher-owned accounts, with minimal
values.

**Ranking dimensions** (each 1–5, higher = better research target):
`Impact` · `Likelihood` · `ScopeCertainty` · `TestSafety` · `EvidenceObtainable` ·
`DuplicateRisk` (5 = *low* duplicate risk = better).

---

## Global preconditions & safety rules (Section 2, 9, 14)
- Use **two researcher-controlled accounts** (ATTACKER, VICTIM — both ours).
- Smallest possible amounts; never touch another real user's data/funds.
- Confirm each target asset is in the **current** HackerOne scope table *first*.
- Concurrency tests = atomicity probing only (2–5 parallel requests), never load.
- Reproduce ≥3× from a clean session before writing a report.
- Record UTC, account, request, response, side effect per Section 24.

---

## Ranked hypotheses

### H-1 · IDOR / horizontal authz on object-id endpoints (App/Exchange/NFT/Pay)
- **Invariant:** INV-OWN. A caller reads/mutates only its own objects.
- **Scores:** Impact 5 · Likelihood 3 · ScopeCertainty 3 · TestSafety 5 · Evidence 5 · DupRisk 2
- **Why top:** Highest reward-to-risk. Trivially safe (read your own two accounts).
  Direct Confidentiality/Integrity impact if it lands.
- **Test:** With ATTACKER's session, request VICTIM's object ids (order, transfer,
  ticket, charge, NFT listing, sub-account). Compare body + side effects, not just
  status code. Test **every sibling** endpoint touching the same object (get vs.
  list vs. export vs. cancel) — the forgotten sibling is the bug (Section 17).
- **Destroy-it checks:** ids unguessable AND unusable across accounts? ownership
  enforced on all siblings? is the "leaked" datum actually public (e.g., public
  blockchain address → severity None)?

### H-2 · Withdrawal/transfer state-machine race & idempotency (custodial money seam)
- **Invariant:** INV-IDEM + INV-STATE + INV-BAL. One request → at most one debit;
  no double-spend via cancel/retry race.
- **Scores:** Impact 5 · Likelihood 3 · ScopeCertainty 3 · TestSafety 3 · Evidence 4 · DupRisk 3
- **Why:** "Unrestricted balance manipulation" = Integrity:High. Where exchanges
  most often bleed.
- **Test (own funds, minimal):** (a) fire *withdrawal-request* and *cancel* nearly
  simultaneously → does balance get released **and** the withdrawal still broadcast?
  (b) replay an identical withdrawal/transfer after a simulated client timeout →
  double debit/credit? (c) convert/internal-transfer with 2–5 parallel identical
  requests → net balance conserved?
- **Destroy-it checks:** server idempotency key present? ledger atomic? is the
  "extra" balance a display artifact that reconciles? Reproduce 3×.

### H-3 · Exchange API signed-vs-executed divergence / nonce replay (INV-SIGN)
- **Invariant:** Signature binds to exactly the executed request; `(api_key,nonce)`
  single-use.
- **Scores:** Impact 4 · Likelihood 2 · ScopeCertainty 4 · TestSafety 4 · Evidence 4 · DupRisk 4
- **Why:** Contract is public (API_MAP.md §3); delimiter-free concat + level-3
  recursion cap + number-as-string rule are concrete ambiguity sources.
- **Test (own key):** craft two param sets that collide under `params_to_str`
  (e.g., adjacent `key+value` boundaries), sign one, send with the other's intent →
  does server execute the unsigned intent? Send params nested >3 levels → dropped
  from signature but honored by server? Replay a valid signed request within the
  nonce window → accepted twice?
- **Destroy-it checks:** Remember you sign with **your own** secret — establish a
  *cross-account or privilege* consequence, else impact is self-limited and likely
  **not** eligible. Reproduce deterministically.

### H-4 · Cross-product / audience-confused token (INV-AUTHN)
- **Invariant:** A token minted for product P is rejected by product Q; scope/
  audience enforced.
- **Scores:** Impact 5 · Likelihood 2 · ScopeCertainty 3 · TestSafety 5 · Evidence 4 · DupRisk 4
- **Test:** Capture access/session/OAuth tokens from each product you can log into
  (App, Exchange, NFT, Pay). Replay each against the *other* products' APIs. Check
  `aud`/`scope`/`iss` claims if JWT. A token accepted where it shouldn't be =
  privilege/audience confusion.
- **Destroy-it checks:** is acceptance actually authorized SSO by design? does it
  grant any action beyond what that principal already has?

### H-5 · MFA / recovery / session-revocation desync (INV-AUTHN, INV-STATE)
- **Invariant:** After password reset / device removal / logout / MFA change,
  prior sessions & tokens are invalidated everywhere.
- **Scores:** Impact 4 · Likelihood 3 · ScopeCertainty 3 · TestSafety 5 · Evidence 4 · DupRisk 3
- **Test (own account):** hold an active session on device A; from device B do
  password reset / revoke device A / rotate MFA. Does A's session/token still
  perform sensitive actions? Does an in-flight recovery leave a window where MFA is
  bypassable? Two-device timeline, all own account.
- **Destroy-it checks:** revocation eventually-consistent within seconds (maybe
  acceptable) vs. indefinitely valid (bug). Confirm a *sensitive* action still works.

### H-6 · Web ⇄ Mobile ⇄ legacy backend policy divergence (Section 10)
- **Invariant:** Equivalent operations enforce identical authz/limits across all
  backends & API versions.
- **Scores:** Impact 4 · Likelihood 3 · ScopeCertainty 3 · TestSafety 5 · Evidence 4 · DupRisk 4
- **Test:** For one sensitive op (withdraw, transfer, limit change, KYC-tier-gated
  feature), capture the mobile call and the web call and any `/v1` vs `/v2`. Send the
  *weaker* backend's request shape while authenticated. Does an older/mobile path
  skip a check the current web path enforces (limit, allowlist, ownership)?
- **Destroy-it checks:** is the "weaker" path actually reachable/authenticated? is
  the check enforced deeper (ledger) even if this layer skips it?

### H-7 · Pay merchant isolation + webhook signature/replay (INV-OWN, INV-SIGN)
- **Invariant:** A merchant reads/acts only on its charges; webhooks are
  authenticated and non-replayable before crediting settlement.
- **Scores:** Impact 4 · Likelihood 2 · ScopeCertainty 2 · TestSafety 4 · Evidence 4 · DupRisk 4
- **Test (own merchant sandbox):** enumerate charge ids across two own merchant
  accounts (INV-OWN); replay/forge a settlement webhook without/with a stale
  signature → does the platform mark paid? Charge/refund state races (expire→pay,
  refund>charge).
- **Destroy-it checks:** is a merchant sandbox in scope? webhook verified server-side?

### H-8 · Asset/precision/decimals confusion in convert/swap/settlement (INV-ASSET)
- **Invariant:** Amount precision & asset identity fixed and validated end-to-end.
- **Scores:** Impact 4 · Likelihood 2 · ScopeCertainty 3 · TestSafety 3 · Evidence 3 · DupRisk 4
- **Test (own, tiny):** submit high-precision or boundary amounts to convert/swap;
  check rounding direction and whether truncation ever rounds *in the user's favor*
  repeatedly (money-pump). Asset-id substitution between quote and execute.
- **Destroy-it checks:** does reconciliation claw it back? is the gain > fees and
  repeatable? single rounding = likely None/Low.

### H-9 · Onchain/DeFi Wallet blind-sign / deep-link signing mismatch (INV-SIGN)
- **Invariant:** What the wallet UI displays == what the user actually signs; deep
  links can't trigger unintended signing.
- **Scores:** Impact 4 · Likelihood 2 · ScopeCertainty 2 · TestSafety 4 · Evidence 3 · DupRisk 4
- **Test:** craft a dApp/deep-link tx-request whose displayed summary differs from
  the encoded calldata/tx; confirm signer shows the misleading summary. Focus only
  on **Crypto.com-controlled** wallet UX/backend, not third-party dApp/contract bugs.
- **Destroy-it checks:** root cause in Crypto.com wallet code (eligible) vs. a
  third-party dApp/contract (out of scope)? significant user interaction caps at Low.

### H-10 · Error/rollback partial-commit on dependency failure (INV-BAL, INV-STATE)
- **Invariant:** On downstream failure/timeout, the operation rolls back completely;
  no partial commit; no async side effect from a "failed" request.
- **Scores:** Impact 4 · Likelihood 2 · ScopeCertainty 3 · TestSafety 3 · Evidence 3 · DupRisk 4
- **Test (own account):** induce client-side timeouts/cancels mid-operation on
  convert/transfer/Earn-redeem; verify the request either fully applied or fully
  didn't — never "hold released but debit skipped" or "failed but worker still
  credited." (Section 18.)
- **Destroy-it checks:** eventual reconciliation? is the inconsistency observable &
  exploitable, or transient?

---

## Priority order to execute (Section 31)
1. H-1 (authz/IDOR) → 2. H-4, H-5 (authn/recovery/session) → 3. H-2, H-10 (financial
state machine + rollback) → 4. H-3, H-7 (replay/idempotency/signing) → 5. H-6
(version/backend divergence) → 6. H-8 (asset/precision) → 7. H-9 (wallet signing).

Start with H-1: cheapest, safest, highest expected value; two accounts, read-only
probing first.

---

## Explicitly de-scoped / low-value (don't spend time — Section 3)
Security headers, TLS config, banners/versions/paths, self-XSS, open redirects,
clickjacking-without-theft, KYC deepfake bypass, rate-limit on non-sensitive forms,
vulnerable-dependency identification without a working PoC, DDoS.
