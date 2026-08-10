# CANDIDATES.md

Candidate tracking (Section 23). Statuses: `IDEA` · `INVESTIGATING` · `DISPROVED` ·
`OUT_OF_SCOPE` · `DUPLICATE_RISK` · `CONFIRMED` · `REPORT_READY` ·
`BLOCKED_BY_ENV` (this engagement: cannot execute because live target/scope is
egress-blocked).

**No candidate reached CONFIRMED or REPORT_READY.** Reason: no reachable,
confirmed-in-scope, testable asset exists from this environment (SCOPE_SNAPSHOT.md
§7). Failed/blocked hypotheses are kept visible to prevent repeated wasted work.

| ID | Asset (candidate) | Hypothesis | Evidence gathered | Impact if true | Policy status | Confidence | Status |
|----|-------------------|------------|-------------------|----------------|---------------|-----------|--------|
| H-1 | App/Exchange/NFT/Pay | IDOR / horizontal authz on object ids (INV-OWN) | Model only; no live test (assets blocked) | C/I High | Eligible **iff** asset in HackerOne scope; not on OOS list | n/a — untested | BLOCKED_BY_ENV |
| H-2 | App/Exchange | Withdrawal/transfer race + idempotency (INV-IDEM/STATE/BAL) | Model only | Integrity High (balance) | Eligible iff in scope | n/a | BLOCKED_BY_ENV |
| H-3 | Exchange API | Signed-vs-executed divergence / nonce replay (INV-SIGN) | Public signing scheme reviewed (API_MAP §3); no live test | Med; likely self-limited | Eligible iff cross-account impact shown | Low (self-signed caveat) | INVESTIGATING → BLOCKED_BY_ENV |
| H-4 | Multi-product | Cross-product token audience/scope confusion (INV-AUTHN) | Model only | Priv esc | Eligible iff in scope | n/a | BLOCKED_BY_ENV |
| H-5 | App/Exchange | MFA/recovery/session revocation desync (INV-AUTHN) | Model only | Account takeover-adjacent | Eligible iff in scope | n/a | BLOCKED_BY_ENV |
| H-6 | App vs Web vs v1/v2 | Backend/version policy divergence (Section 10) | Model only | Bypass of a control | Eligible iff in scope | n/a | BLOCKED_BY_ENV |
| H-7 | Crypto.com Pay | Merchant isolation + webhook signature/replay | Model only | Fraudulent settlement | Eligible iff Pay+webhook in scope | n/a | BLOCKED_BY_ENV |
| H-8 | Convert/Swap | Asset/precision/decimals confusion (INV-ASSET) | Model only | Money-pump if repeatable | Eligible iff in scope & not reconciled | n/a | BLOCKED_BY_ENV |
| H-9 | Onchain Wallet | Blind-sign / deep-link signing mismatch (INV-SIGN) | Model only | Unintended signing | Eligible iff CC-controlled UX; UI-interaction caps severity | n/a | BLOCKED_BY_ENV |
| H-10 | App/Earn | Partial-commit on dependency failure (INV-BAL/STATE) | Model only | Balance inconsistency | Eligible iff in scope | n/a | BLOCKED_BY_ENV |
| X-1 | Cronos / crypto-org-chain source | Source-code vuln in chain node/contracts | `SECURITY.md` reviewed | (varies) | **OUT_OF_SCOPE for HackerOne** — routes to HackenProof | — | OUT_OF_SCOPE |
| X-2 | `BDR-Pro/Jero` (local Monero code) | Any bug in the checked-out C++ | Repo identified as Monero-derived | (varies) | **OUT_OF_SCOPE** — not a Crypto.com asset | — | OUT_OF_SCOPE |
| X-3 | `help.crypto.com` / support SaaS | Support-platform issue | — | — | Likely OUT_OF_SCOPE — third-party root cause | — | OUT_OF_SCOPE |
| X-4 | Visa card issuer backend | Card-rail issue | — | — | Likely OUT_OF_SCOPE — third-party issuer; cashback abuse often excluded | — | OUT_OF_SCOPE |

## Notes
- Every `BLOCKED_BY_ENV` row is a *ready-to-run* plan for a human with authorized
  HackerOne access (see RESEARCH_PLAN.md), not a claimed vulnerability.
- H-3 is the only hypothesis with a public artifact to study now; its exploitability
  is doubtful because API requests are signed with the caller's own secret — kept
  open but low-confidence.
