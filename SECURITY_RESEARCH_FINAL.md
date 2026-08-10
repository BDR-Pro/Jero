# SECURITY_RESEARCH_FINAL.md

**Engagement:** Authorized deep security review — Crypto.com HackerOne program
(`https://hackerone.com/crypto?type=team`)
**Date:** 2026-08-10 (UTC)
**Deliverable owner:** Security research session (automated, cloud-sandboxed)
**Companion artifacts:** `artifacts/SCOPE_SNAPSHOT.md`, `POLICY_MATRIX.md`,
`ATTACK_SURFACE.md`, `TRUST_BOUNDARIES.md`, `API_MAP.md`, `RESEARCH_PLAN.md`,
`CANDIDATES.md`.

---

## 1. Scope snapshot (what was actually reviewable)

**Reachable & confirmed:** Crypto.com's public **policy guidelines** repo
`crypto-com/h1-policy-guidelines` (`main`) — README, out-of-scope list, severity
definitions. These are captured verbatim in POLICY_MATRIX.md.

**NOT reachable (decisive):** The **authoritative asset scope** lives on
`hackerone.com/crypto`, which is **blocked by this environment's network egress
proxy**. `crypto.com` and its subdomains are **also egress-blocked**. Verified:

```
hackerone.com  → EGRESS_BLOCKED
crypto.com     → EGRESS_BLOCKED
```

Per the engagement's Section 0, when the current scope cannot be determined with
confidence, the correct action is to **STOP** rather than test ambiguous assets.
The candidate asset landscape (App, Exchange, DeFi/Onchain Wallet, Pay, Card, NFT,
Earn, corporate web) is reconstructed in ATTACK_SURFACE.md and marked **UNVERIFIED**.

---

## 2. Policy interpretation (key eligibility restrictions)

- **Bug Bounty only:** specific, reproducible vuln + manual PoC required;
  scanner-only output → rejected/"Spam".
- **Root cause must be Crypto.com-controlled:** third-party vendor/cloud/SaaS/issuer
  issues are out of scope unless caused by a Crypto.com misconfiguration or missed
  patch. (This is the single most common rejection reason — see POLICY_MATRIX.md §2.)
- **Severity = CVSS CIA matrix;** High needs clear+immediate, directly exploitable,
  critical-function/sensitive-data impact, reliably reproducible. Multiple Lows don't
  sum to High; significant user interaction caps at Low; staging rated lower.
- **Excluded classes** (full list in POLICY_MATRIX.md §3): security headers, TLS
  config, self-XSS, open redirects, clickjacking-without-theft, KYC/deepfake bypass,
  version/IP/path disclosure, vulnerable-lib identification without PoC, properly
  rate-limited brute force, DDoS, fresh (<14d) public 0-days.
- **Important program boundary:** Crypto.com's **open-source chain code (Cronos /
  Crypto.org)** is handled by a **separate HackenProof program** (confirmed via
  `crypto-org-chain/cronos/SECURITY.md`), **not** this HackerOne program.

---

## 3. Attack surface investigated

Modeled (not live-tested) in ATTACK_SURFACE.md / TRUST_BOUNDARIES.md. The
highest-leverage server-side seams for a custodial exchange/wallet were prioritized
per Section 31:
1. Authorization / object-ownership across sibling endpoints (IDOR).
2. Authentication / recovery / session / cross-product token confusion.
3. Financial state machines: withdrawal/transfer/convert idempotency, atomicity,
   rollback, cancel/replay races.
4. Signing/replay of the (publicly documented) Exchange HMAC scheme; Pay webhooks.
5. Web/mobile/API-version policy divergence; asset/precision confusion; wallet
   blind-signing.

Cosmetic/policy-excluded classes were deliberately de-prioritized.

---

## 4. Research methodology

1. Read the reachable policy authority (guidelines repo) → POLICY_MATRIX.md.
2. Attempted to read the authoritative scope → **blocked**; recorded honestly.
3. Confirmed the Cronos→HackenProof program boundary and the Monero-repo
   non-relationship (see §8, §9).
4. Reconstructed attack surface & trust boundaries from public product/dev docs.
5. Extracted the publicly-documented Exchange signing contract for crypto review.
6. Produced a prioritized, safety-bounded, human-executable hypothesis plan and a
   candidate tracker with honest statuses.
No scanners were run against any target; no live Crypto.com asset was probed.

---

## 5. Hypotheses investigated (incl. disproved / blocked)

Ten server-side hypotheses (H-1…H-10) are specified in RESEARCH_PLAN.md with impact/
likelihood/scope-certainty/safety/evidence/duplicate scoring and confirm-or-destroy
steps. **All are `BLOCKED_BY_ENV`** — they cannot be executed without authorized,
live HackerOne access (targets are egress-blocked here).

- **H-3 (Exchange signing ambiguity/replay)** is the only hypothesis with a public
  artifact to study now. On analysis it is **low-confidence**: API requests are
  signed with the *caller's own* secret, so signature forgery against another user
  isn't the threat; only a signed-vs-executed divergence or replay with a
  *cross-account/privilege consequence* would be eligible, and that requires live
  testing to establish. Kept open, not promoted.

Out-of-scope items (Cronos source, local Monero code, support SaaS, card issuer) are
tracked as `OUT_OF_SCOPE` in CANDIDATES.md and are **not** recommended for
submission.

---

## 6. Confirmed vulnerabilities

**None.** No candidate reached CONFIRMED. The confirmation standard (Section 25)
requires a *current in-scope asset, manually reproduced, with concrete impact and a
reliable PoC* — unattainable from an environment where the target and its scope
definition are both network-blocked.

---

## 7. Report-ready findings

**None.** `reports/` contains no finding. Writing a HackerOne report now would
violate the engagement's own bar (Sections 25, 27, 29) and risk a false-positive
submission.

---

## 8. Interesting non-findings / areas reviewed and found sound-or-inapplicable

- **Exchange HMAC signing scheme** — publicly documented; delimiter-free
  concatenation is a legitimate thing to probe, but the self-signed-request property
  makes naive exploitation unlikely; needs live proof of cross-account/privilege
  impact. Not a finding as-is.
- **Cronos `SECURITY.md`** — correctly routes to HackenProof; no HackerOne exposure
  here.

## 9. Out-of-scope observations (recorded, NOT for submission)

- The **local `BDR-Pro/Jero` repository is a Monero-derived C++ codebase**, unrelated
  to any Crypto.com product; it is the artifact workspace only. Any bug there is a
  Monero matter, not a Crypto.com HackerOne matter. **Do not submit.**
- **Cronos / Crypto.org chain** vulnerabilities belong to HackenProof. **Do not
  submit to this HackerOne program.**
- Third-party support/card/cloud components fail the root-cause rule unless a
  Crypto.com-owned config/patch defect is demonstrated.

## 10. Remaining high-value research areas (for authorized, human-run continuation)

In expected-value order (details in RESEARCH_PLAN.md): H-1 IDOR/object-ownership →
H-4/H-5 token-audience & recovery/session desync → H-2/H-10 financial state-machine
idempotency & rollback → H-3/H-7 signing/webhook replay → H-6 backend/version
divergence → H-8 asset/precision → H-9 wallet blind-signing. Begin with H-1 (two
controlled accounts, read-only first — cheapest, safest, highest yield).

---

## 11. Final conclusion

> **Did we identify a CURRENT, REPRODUCIBLE, CRYPTO.COM-CONTROLLED, IN-SCOPE
> vulnerability suitable for HackerOne submission?**
>
> ## NO.

**Justification.** A submittable finding requires all of: (a) an asset confirmed in
the *current* HackerOne scope, (b) a Crypto.com-controlled root cause, (c) manual
reproduction against the live asset, and (d) a reliable PoC with concrete CIA impact.
From this environment, **(a) is impossible** — the authoritative scope page
(`hackerone.com`) is egress-blocked — and **(c)/(d) are impossible** — every
`crypto.com` asset is egress-blocked and, independently, autonomous active
exploitation of a live financial platform is outside safe/authorized bounds for this
automated session (Section 2). The one class of Crypto.com-controlled *public source*
that could be statically audited (Cronos/Crypto.org chain) is governed by a
**different** bug-bounty program (HackenProof), so it cannot yield a *HackerOne*
finding. The checked-out local repository is Monero, not a Crypto.com asset.

This is a **correct negative result**, which the engagement explicitly values over a
false-positive submission (Section 29). The deliverable is therefore a rigorous,
honest scoping/policy/attack-surface package and a prioritized, safety-bounded
research plan that a human researcher with authorized, live HackerOne access can
execute immediately.

**To convert this into live findings, a human operator must:**
1. Open `hackerone.com/crypto` and record the *current* in-scope asset table +
   per-asset bounty eligibility / max severity (fill SCOPE_SNAPSHOT.md §4).
2. Provision two researcher-controlled accounts (and a merchant sandbox for Pay).
3. Execute RESEARCH_PLAN.md H-1…H-10 in priority order, on own accounts, minimal
   values, confirming-or-destroying each and preserving evidence per Section 24.
4. Promote only candidates passing the full Section 25 checklist to `reports/`.

*(An alternative environment with egress access to `hackerone.com` and `crypto.com`,
plus authorized researcher accounts, would remove the blockers in (a)/(c)/(d) and let
this plan be executed with a human in the loop.)*
