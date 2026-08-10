# POLICY_MATRIX.md

**Purpose:** Turn Crypto.com's *reachable, confirmable* policy documents (README,
out-of-scope list, severity definitions) into a fast eligibility/triage filter to
apply **before** investing time in any hypothesis (engagement Section 3).

**Source:** `crypto-com/h1-policy-guidelines` `main`, read 2026-08-10. These
documents are the guideline authority; the *asset* authority (HackerOne page) is
blocked (see SCOPE_SNAPSHOT.md).

---

## 1. Gate conditions — a finding must pass ALL of these

| Gate | Requirement | Fail ⇒ |
|------|-------------|--------|
| G1 Root cause | Root cause is **within Crypto.com's control** | Reject (third-party) unless caused by CC misconfig/unpatched |
| G2 Reproducible | Specific, reproducible vulnerability | Reject / "Spam" |
| G3 PoC | Clear, manual PoC (not scanner output) | Reject / "Spam" |
| G4 In-scope asset | Asset appears in the **current** HackerOne scope table | Reject |
| G5 Not excluded | Not on the out-of-scope list (§3 below) | Reject |
| G6 Impact | Demonstrable CIA impact per severity matrix (§4) | Low/None |
| G7 Not internally-known | Not already tracked internally / duplicate | No bounty |
| G8 Not fresh 0-day | Not a public 0-day within its 14-day grace window | Reject |

---

## 2. Root-cause ownership filter (the most common rejection)

Policy: *"We only accept vulnerability reports where the root cause is within our
control. Issues related to third-party vendors (cloud platforms, external assets)
are out-of-scope unless specifically caused by our misconfigurations or lack of
patching."*

Apply this decision tree to every candidate:

```
Is the defective component operated/coded/configured by Crypto.com?
├─ YES → root cause candidate = Crypto.com  → proceed
└─ NO (vendor/SaaS/CDN/issuer/cloud)
     ├─ Did a Crypto.com misconfiguration create the defect? → in scope
     ├─ Did Crypto.com fail to apply an available patch?     → in scope
     └─ Otherwise                                            → OUT OF SCOPE
```

Practical fallout: card-issuer bugs, support-desk SaaS bugs, analytics-vendor bugs,
email-provider bugs, cloud-provider platform bugs → **out of scope** unless you can
pin the defect on a Crypto.com-owned config/patch decision.

---

## 3. Out-of-scope vulnerability classes (auto-deprioritize)

Verbatim-derived from `out-of-scope-vulnerabilities.md`:

**Identity & Verification**
- AI / Deepfake KYC bypass or similar identity-verification circumvention

**Non-critical security gaps**
- Weak password policy (length/complexity/expiry)
- Missing HTTP security headers (CSP, HSTS, X-Frame-Options)
- Absent MFA on **non-critical** endpoints
- SSL/TLS config weaknesses **without practical exploitation**

**Software issues**
- General bugs lacking demonstrable security impact
- Known vulnerable libraries **without working PoC exploitation**

**Information disclosure**
- Server versions, internal IPs, domain names, directory structures
- Technology-stack fingerprinting, server timezone
- Error messages **without sensitive data**

**Third-party & non-technical**
- Broken third-party links/content
- Physical security, social engineering, phishing, physical-access MitM
- Credential exposure **not originating from Crypto.com systems**

**Timing / attack-specific**
- 0-day disclosures within **14 days** of announcement
- Clickjacking **without demonstrated data theft**
- Self-XSS requiring direct user interaction / code input

**Rate limiting & brute force**
- Rate-limit bypass on newsletters/contact forms/non-sensitive endpoints
- **Properly** rate-limited brute force

**Other**
- Open redirects with clearly visible redirects unsuitable for phishing
- CSRF on non-sensitive actions with proper protection
- Purely theoretical vulnerabilities
- DDoS requiring significant traffic / specialized tools

> **Known issues tracked internally receive no bounty.**

---

## 4. Severity matrix (CVSS CIA impact) — for framing, not inflation

Crypto.com uses a CVSS CIA impact matrix (C, I, A each High/Low/None). A **High**
claim requires **all four**: clear & immediate impact; direct exploitability
without complex interaction; effect on a critical function or sensitive data;
reliable reproducibility with PoC.

### Confidentiality
- **High:** Read ALL / all-sensitive data of the component — full DB dump, complete
  TLS decryption, mission-critical file access, comprehensive PII, all-private-key
  access.
- **Low:** Some restricted info but not the most sensitive — limited PII, restricted
  credential exposure with controls, hashed-credential exposure.
- **None:** Blind attacks, clickjacking w/o leak, banner disclosure, phishing-obtained
  data, stack traces, **public blockchain addresses**.

### Integrity
- **High:** Modify ANY/ALL data or code, or execute arbitrary commands **without
  restriction** — unrestricted SQLi, root RCE, admin privesc, **unrestricted balance
  manipulation**.
- **Low:** Constrained modifications — presentation-layer XSS, limited-scope CSRF,
  account-specific modifications.
- **None:** Info disclosure, algorithmic DoS, non-data-altering attacks, self-XSS
  needing manual code insertion.

### Availability
- **High:** Complete/near-complete loss — crash, restart loop, resource exhaustion
  needing manual intervention.
- **Low:** Reduced performance / intermittent; partly available or self-recovers.
- **None:** Info leaks, theoretical-without-PoC, disruption needing unlikely user
  action.

### Severity caps / rules to remember
- Multiple **Low** issues **do not** combine into **High**.
- Significant **user interaction** caps severity at **Low**.
- **Dev/staging** environments rated lower.
- Physical-access / insider-knowledge issues rated **Low or None**.
- Crypto.com has **final authority** on classification.

---

## 5. Quick-reject checklist (paste into each candidate's notes)

```
[ ] Root cause Crypto.com-controlled? (G1)
[ ] Asset in CURRENT HackerOne scope table? (G4)  ← blocked in this env; human must verify
[ ] Not on out-of-scope list? (G3 section)
[ ] Reproducible ≥3x from clean session? (G2)
[ ] Manual PoC, not scanner output? (G3)
[ ] Concrete C/I/A impact, not theoretical? (G6)
[ ] Not a fresh (<14d) public 0-day? (G8)
[ ] Not obviously internally-known/duplicate? (G7)
```
