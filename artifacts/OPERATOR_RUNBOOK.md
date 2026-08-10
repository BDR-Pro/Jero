# OPERATOR_RUNBOOK.md — how to go from this framework to a submitted report

This is the human-in-the-loop procedure. This automated environment cannot do it
(targets are egress-blocked, and authorization is bound to *your* HackerOne account).
Follow these steps on your own machine, with your own authorized accounts.

---

## Step 0 — Decide *where* you run (unblock the environment or go local)
The blockers here are network egress + no human judgment loop. Two ways forward:
- **(Recommended) Run on your own workstation.** Full control, your accounts, your
  proxy. This runbook assumes that.
- **Reconfigure a Claude-on-web environment's network policy** to allow egress to
  `hackerone.com` and the in-scope `crypto.com` hosts, and drive it interactively.
  Even then, *you* must supply authorization and stay in the loop for any action that
  moves money or touches account state.

## Step 1 — Establish authorization & capture the REAL scope (replaces the blocked bits)
1. Log in to `https://hackerone.com/crypto?type=team`, read and **accept** the
   program terms — this is the authorization.
2. Copy the live **structured scope** table into `SCOPE_SNAPSHOT.md §4`, per asset:
   identifier, in/out of scope, **bounty-eligible vs. VDP-only**, **max severity**,
   and any per-asset instructions / rate limits / auth requirements.
3. Note the policy revision date and record the `h1-policy-guidelines` commit hash.
4. **Gate:** if an asset isn't clearly in scope → do not touch it (Section 0).

## Step 2 — Provision researcher-controlled identities (never a real user)
- **ATTACKER** and **VICTIM** accounts — both yours. Fund with the smallest amounts
  needed; prefer a sandbox/testnet where the program offers one.
- For Pay: a test **merchant** account. For Exchange: create a **read-only** API key
  and a separate **trade** key so you can test scope boundaries safely.
- KYC only to the minimum tier a test requires.

## Step 3 — Instrument
- Intercepting proxy (Burp / mitmproxy) for web **and** mobile (install the CA on a
  test device / emulator). Capture the real request contracts into `API_MAP.md`.
- Keep an evidence log per Section 24: UTC, account, request, response, side effect,
  conclusion. Redact tokens/secrets/PII before saving.

## Step 4 — Execute hypotheses in priority order (RESEARCH_PLAN.md)
Order: **H-1** (IDOR) → H-4/H-5 (token audience, recovery/session) → H-2/H-10
(financial state machine + rollback) → H-7 (Pay isolation/webhook) → H-6
(backend/version divergence) → H-8 (asset/precision) → H-9 (wallet signing).
H-3 is **DISPROVED** for the standard model — only revisit if Step 4 reveals a
delegated/oracle signing surface or a read-vs-trade scope split.

For each hypothesis:
1. Read-only first (enumerate, observe). Escalate to a state-changing test only on
   your own objects, smallest values, 2–5 parallel requests max for races.
2. Compare **body + side effects + async events**, not just HTTP status (Section 9).
3. Run the **destroy-it** checklist for that hypothesis before believing it.
4. Reproduce **≥3×** from a clean session.

## Step 5 — Start with H-1 using the provided harness
```
# configure two OWN accounts + their own object ids, then:
python3 artifacts/tools/idor_differential_harness.py --config my_idor_config.json
```
It runs the A/B ownership matrix and flags any case where ATTACKER reads/mutates
VICTIM's object. See the file header for config format and the built-in safety gate.

## Step 6 — Confirmation gate (Section 25) before writing anything
Promote to `reports/` only if ALL hold:
```
[ ] current in-scope asset (verified on HackerOne)
[ ] Crypto.com-controlled root cause
[ ] manually reproduced ≥3x from clean session
[ ] concrete C/I/A impact (not theoretical)
[ ] reliable minimal PoC
[ ] policy-eligible (not on out-of-scope list)
[ ] safe reproduction, own accounts only
[ ] not scanner-only, not best-practice-only, not version-ID-only
[ ] evidence preserved & redacted
```

## Step 7 — Write & submit
Use the report template (engagement Section 27): title → summary → affected asset →
scope evidence → root cause → preconditions → reproduction → expected vs actual →
PoC → impact → why Crypto.com-controlled → policy eligibility → severity rationale
(CVSS CIA) → remediation → sanitized evidence. Submit via HackerOne. One clear,
reproducible bug beats ten maybes.

---

## Guardrails (do not cross — Section 2)
No touching another real person's data/funds; no mass download; no DoS/load tests; no
persistence; no third-party infra; smallest values; own accounts only; stop at the
minimum proof.

---

## Tooling index (all in `artifacts/`)
Each harness has a hard safety gate (won't send until you confirm scope + account
ownership and replace the placeholder host) and a `--dry-run` that sends nothing.

| Hypothesis | Tool | Sample config | Notes |
|-----------|------|---------------|-------|
| H-1 IDOR / object authz | `tools/idor_differential_harness.py` | `tools/idor_config.sample.json` | read-only by default; two-account A/B matrix |
| H-2 idempotency / race | `tools/idempotency_race_harness.py` | `tools/idem_config.sample.json` | `--mode race`/`retry`; moves YOUR OWN funds; amount guard; verify via ledger |
| H-4 token audience/scope | `tools/token_audience_harness.py` | `tools/token_audience_config.sample.json` | JWT claim introspection + cross-product matrix; `--decode-only` is offline |
| H-3 signing ambiguity | `tools/params_to_str_collision.py` | — | already run; DISPROVED (see `tools/H3_signing_ambiguity_analysis.md`) |
| H-5 session/recovery desync | *(manual)* `playbooks/H5_session_recovery_desync_playbook.md` | — | two-session timeline; safest high-value start (no funds) |
| H-7 Pay isolation + state machine | `tools/pay_merchant_ops_harness.py` | `tools/pay_ops_config.sample.json` | two-merchant ordered negative-test runner w/ capture+`{{var}}` substitution |
| H-7 Pay webhook scheme | `tools/pay_webhook_analyzer.py` | `tools/webhook_capture.sample.json` | OFFLINE; recovers Pay's signing scheme, flags replay/tamper; playbook `playbooks/H7_pay_playbook.md` |

Suggested first live session: **H-5 playbook** (no funds, pure authz) → **H-1 harness**
(read-only IDOR) → then H-2/H-4 once you're comfortable and have captured the real
request contracts.
