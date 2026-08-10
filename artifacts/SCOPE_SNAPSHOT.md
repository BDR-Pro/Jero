# SCOPE_SNAPSHOT.md

**Engagement:** Authorized bug-bounty research — Crypto.com HackerOne program
**Snapshot date/time:** 2026-08-10 (UTC)
**Prepared by:** Security research session (automated, cloud-sandboxed)

---

## 0. Executive scoping conclusion (READ FIRST)

Per the engagement's **Section 0 (non-negotiable rule)**, the authoritative source
for the *current* asset scope is the HackerOne program page
(`https://hackerone.com/crypto?type=team`).

**That page is NOT reachable from this research environment.** The network egress
proxy blocks it:

```
WebFetch https://hackerone.com/crypto?type=team
→ EGRESS_BLOCKED: "Access to hackerone.com is blocked by the network egress proxy."
```

In addition, **`crypto.com` and its subdomains are also egress-blocked**:

```
WebFetch https://crypto.com/.well-known/security.txt
→ EGRESS_BLOCKED: "Access to crypto.com is blocked by the network egress proxy."
```

**Consequence:** The current in-scope asset list **cannot be determined with
confidence from this environment.** Section 0 states: *"If the scope cannot be
determined with confidence: STOP. Do not test the ambiguous asset."*

This snapshot therefore records:
1. What **is** confirmable (the public policy *guidelines* on GitHub — reachable).
2. A **candidate / UNVERIFIED** asset landscape reconstructed from public product
   knowledge, explicitly flagged as requiring re-verification against the live
   HackerOne page before any testing.
3. The environment constraints that bound this engagement.

No asset below should be treated as authorized-for-testing on the basis of this
document. Authorization comes only from the live HackerOne scope table.

---

## 1. Sources actually read (confirmable)

| Source | URL | Reachable? | Notes |
|--------|-----|-----------|-------|
| HackerOne program page (authoritative scope) | https://hackerone.com/crypto?type=team | ❌ BLOCKED | Egress-blocked. Authoritative asset list unavailable. |
| Extended policy — README | https://github.com/crypto-com/h1-policy-guidelines (`main`) | ✅ | Full text captured. See §3. |
| Out-of-scope vulnerabilities | `.../out-of-scope-vulnerabilities.md` | ✅ | Full text captured → see POLICY_MATRIX.md |
| Severity definitions | `.../vulnerability-severity-definitions.md` | ✅ | Full text captured → see POLICY_MATRIX.md |
| crypto.com security.txt | https://crypto.com/.well-known/security.txt | ❌ BLOCKED | Egress-blocked. |
| Cronos chain SECURITY.md | https://github.com/crypto-org-chain/cronos `main` | ✅ | Routes to **HackenProof**, not HackerOne — see §5. |

**Policy revision captured:** `crypto-com/h1-policy-guidelines` default branch `main`,
read 2026-08-10. Exact commit hash was not captured (repo is outside the
session's authorized GitHub tool scope; content was read via public raw URLs). A
human researcher should record the commit hash at test time.

---

## 2. Confirmed program-level rules (from the reachable extended policy)

These are the *rules*, not the *asset list*. They are confirmable and authoritative
as guidelines:

- **Program type:** Bug Bounty (NOT Risk/Threat bounty). Every submission must
  identify a **specific, reproducible** vulnerability, include a **clear PoC**, and
  be **manually verified**. Scanner-only output is rejected and may be marked
  **Spam**.
- **Root-cause ownership:** *"We only accept vulnerability reports where the root
  cause is within our control."* Third-party vendor issues (cloud platforms,
  external assets) are **out of scope** unless caused by Crypto.com's own
  misconfiguration or failure to patch.
- **Reward discretion:** Crypto.com has **sole discretion** over eligibility and
  amount.
- **Program size (context):** Publicly announced as up to **USD $2,000,000** max
  bounty (Dec 2024 upgrade) — the headline figure, not a per-report guarantee.

---

## 3. Extended policy README — captured verbatim summary

> **Program Scope** — We only accept vulnerability reports where the root cause is
> within our control. Issues related to third-party vendors (cloud platforms,
> external assets) are out-of-scope unless specifically caused by our
> misconfigurations or lack of patching.
>
> **Submission Requirements** — This is a Bug Bounty program... All submissions
> must: identify a specific, reproducible vulnerability; include a clear PoC; be
> manually verified (not just scanner output). ... Unverified or non-reproducible
> reports from automated scanners will be marked as "Spam".
>
> **Reward Determination** — Crypto.com maintains sole discretion...

---

## 4. Candidate asset landscape — ⚠️ UNVERIFIED / RECONSTRUCTED

**These are NOT confirmed in-scope assets.** They are Crypto.com's publicly known
products, reconstructed from public marketing/help-center/developer material, to
seed attack-surface planning. Each MUST be re-checked against the live HackerOne
scope table (which distinguishes *in-scope*, *out-of-scope*, bounty-eligible vs.
VDP-only, and per-asset max severity) before any interaction.

| # | Candidate asset (product) | Type | Public identifier(s) (candidate) | Verify-before-touch |
|---|---------------------------|------|----------------------------------|---------------------|
| A | Crypto.com **App** (retail) | Mobile + backend API | iOS/Android app; mobile backend | ⚠️ |
| B | Crypto.com **Exchange** | Web + REST/WS trading API | `exchange-docs.crypto.com` (public docs); trading/derivatives/OTC/Institutional API v1 | ⚠️ |
| C | **DeFi / Onchain Wallet** | Mobile + browser-extension self-custody wallet | Onchain Wallet (36 chains, 700+ tokens) | ⚠️ |
| D | **Crypto.com Pay** | Payments/checkout API + merchant | `pay.crypto.com` (candidate) | ⚠️ |
| E | **Visa Card** program | Card issuance/rewards backend | — | ⚠️ (issuer likely 3rd-party → root-cause boundary) |
| F | **NFT** marketplace | Web + API | `crypto.com/nft` (candidate) | ⚠️ |
| G | **Earn / Supercharger / Staking** | Backend financial products | — | ⚠️ |
| H | Corporate web / auth / SSO | Web, `auth`/`account` endpoints | `crypto.com`, account/login | ⚠️ |
| I | Help/Support platform | 3rd-party (Intercom-style) | `help.crypto.com` | ⚠️ likely 3rd-party → out of scope |

**Explicitly do NOT assume** `*.crypto.com` = authorized. Section 1 forbids treating
every Crypto.com-associated host, IP, bucket, CDN, vendor, analytics, support,
email, RPC, or mobile-backend host as in scope merely because Crypto.com uses it.

---

## 5. Important scope boundary — Cronos / Crypto.org chain source = DIFFERENT PROGRAM

Crypto.com's flagship **open-source blockchain code is not handled by this
HackerOne program.** Confirmed from `crypto-org-chain/cronos/SECURITY.md` (`main`,
read 2026-08-10):

> "If you find a security issue, you can report it on the **Hackenproof Bug Bounty
> Program** (https://hackenproof.com/cronos) or contact our team directly at
> **chain-security@crypto.com**."

**Implication for this engagement:** A vulnerability found by auditing the public
Cronos / `chain-main` / Crypto.org chain repositories would be a **HackenProof**
submission, **not** a HackerOne `crypto` submission. Auditing that source for *this
HackerOne task* would produce an **ineligible** finding. Section 15's warning
applies: do **not** assume every repo under the Crypto.com GitHub org is in this
program's scope.

---

## 6. Local workspace clarification — the `BDR-Pro/Jero` repo is Monero, not a target

The repository this research session is checked out in (`BDR-Pro/Jero`, branch
`claude/crypto-hackerone-security-review-ipfql3`) contains a **Monero-derived C++
codebase** (`contrib/epee`, `levin_base`, `portable_storage`, cryptonote-style
`src/`). Evidence: the `contrib/epee` networking/serialization tree and Monero's
build layout.

**Crypto.com does not run a Monero fork.** Its chains are Cosmos-SDK (Crypto.org /
`chain-main`, Go) and EVM (Cronos, Go). Therefore this local repository is **not a
Crypto.com-controlled asset** and is **not in scope** for this engagement. It is
treated purely as the artifact-storage workspace. Any bug found in this Monero code
would be a **Monero** matter, not a Crypto.com HackerOne matter.

---

## 7. Environment constraints affecting this engagement (must be disclosed)

| Constraint | Effect on methodology |
|-----------|-----------------------|
| `hackerone.com` egress-blocked | Cannot read authoritative scope (Section 0 blocker). |
| `crypto.com` + subdomains egress-blocked | Cannot perform passive recon or active testing against real assets. |
| Automated cloud sandbox, no human-in-loop | Active exploitation of a live exchange is unsafe/unauthorized to perform autonomously (Section 2). |
| Main public source = HackenProof program | Source-review path yields ineligible (wrong-program) findings for *this* task. |

**Net:** There is **no reachable, confirmed-in-scope, testable Crypto.com asset**
available from this environment. This is recorded honestly rather than worked
around. See RESEARCH_PLAN.md for what a human researcher with live HackerOne access
should do, and SECURITY_RESEARCH_FINAL.md for the explicit conclusion.

---

## 8. Ambiguity register (Section 0 requires listing ambiguous items)

| Item | Why ambiguous | Disposition |
|------|---------------|-------------|
| Every asset in §4 | Live scope table unreadable | DO NOT TEST until verified on HackerOne |
| Exchange API host | Public docs exist, but bounty-eligibility/max-severity unknown | Verify per-asset row on HackerOne |
| Visa Card backend | Card issuer is typically a third party → root-cause boundary | Likely out of scope unless Crypto.com-controlled component |
| `help.crypto.com` | Support platforms are usually third-party SaaS | Likely out of scope (third-party) |
| Cronos/chain repos | Routed to HackenProof | Out of scope for HackerOne |
