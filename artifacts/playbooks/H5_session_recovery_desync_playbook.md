# H-5 Playbook — Session / Recovery / MFA revocation desync

**Deep-dive test playbook for a human researcher.** Safe (no funds moved), high value
(account-takeover-adjacent), and hard to automate — it needs a two-session timeline
and human judgment about "how stale is too stale."

---

## 1. The invariant under test (INV-AUTHN + INV-STATE)

> When a credential-invalidating event happens — logout-all, password reset, device
> removal, MFA change, email/phone change — **every previously issued session, access
> token, refresh token, and long-lived credential must stop working**, everywhere,
> promptly.

A break = a stale session survives an event that should have killed it, and can still
perform sensitive actions. That is the tail end of an account-takeover chain: an
attacker who briefly had access (shared device, leaked token, resold phone, malware)
retains control *after* the victim "secures" the account.

**Severity framing (POLICY_MATRIX.md §4):** if a *sensitive* action (withdraw, add
withdrawal address, create API key, change security settings, transfer) still works
after revocation → Integrity/Confidentiality impact, plausibly **High** if immediate
and reliable. Read-only staleness → lower. Multi-second eventual consistency may be
acceptable; **indefinite** survival is the bug.

---

## 2. Preconditions (all your own — Section 2)

- **One** researcher account.
- **Two independent sessions on it:**
  - **Session A ("stale")** — the session you expect to be killed. Use a browser/
    device you fully control; capture its requests through Burp/mitmproxy.
  - **Session B ("actor")** — where you perform the revocation event.
- Prefer A = mobile app, B = web (and repeat swapped) to catch web/mobile desync.
- Have Burp ready to **replay** a captured Session-A request on demand.
- Pick the **sensitive action** you'll replay (see §4). Keep amounts minimal/zero
  (many sensitive actions — e.g. "add withdrawal address", "create API key" — carry
  no funds and are perfect, safe oracles).

---

## 3. The revocation events to test (one pass each)

| # | Event (do from Session B) | Expectation for Session A |
|---|---------------------------|---------------------------|
| E1 | Log out all devices / "sign out everywhere" | A dies immediately |
| E2 | Change password | A dies (all sessions) |
| E3 | Reset password via email/SMS recovery flow | A dies; also test the *window during* reset |
| E4 | Remove/deauthorize Session A's device from device list | A dies |
| E5 | Disable, re-enroll, or rotate MFA (TOTP/passkey) | A dies or at least re-prompts |
| E6 | Change account email / phone | A dies (identity changed) |
| E7 | Revoke the specific access token, then use its **refresh token** | refresh must fail |

---

## 4. Sensitive actions to replay as the oracle (pick 2–3)

Use **non-financial-but-sensitive** ones first (safest, still High-signal):
- Add / list **withdrawal allowlist address** (huge if it survives revoke).
- **Create API key** / view API keys.
- Change **security settings** (2FA, notification email, anti-phishing code).
- View **full account/PII** (profile, KYC docs) — Confidentiality oracle.
- Only if needed: initiate a **minimal self-transfer/withdraw** (Integrity oracle).

---

## 5. Procedure (repeat for each event E1–E7)

```
1. Session A: log in fresh. In Burp, capture a REQUEST for your chosen sensitive
   action (don't necessarily execute it yet) — you want its exact headers/token.
2. Session A: confirm the action works now (baseline) — note status + body.
3. Session B: perform the revocation event (E1..E7). Note the UTC time.
4. IMMEDIATELY (t+~2s): in Burp Repeater, replay Session A's captured request.
   Record status + body + whether the side effect actually happened.
5. Repeat the replay at t+30s, t+5min, t+1h. Record each.
6. Also try Session A's NORMAL app flow (not just replay) — some apps only re-check
   on navigation.
7. If A used a refresh/rotation scheme, force a token refresh from A and see if it
   still succeeds after the event (E7).
```

**Pass (secure):** the replay starts failing (401/403 + no side effect) within a few
seconds and stays failed.
**FAIL (finding):** the replay still succeeds — especially the *side effect* — at
t+30s / t+5min / t+1h. The longer it survives, the stronger the report.

---

## 5b. Automated survival measurement → `tools/session_revocation_probe.py`

The manual timeline in §5 is precise but tedious across credential types. The probe
tool automates the measurement (you still perform the revocation event by hand):

1. Fill `tools/session_probe_config.sample.json`: your `base_url`, and one **probe per
   credential** you want to test (access token, web cookie, refresh token, per-product
   session). Use non-destructive sensitive reads as the oracle (e.g. list withdrawal
   addresses, full profile). Set the confirm flags. Extend `schedule_seconds` to
   `3600` for stronger evidence.
2. Run it:
   ```
   python3 tools/session_revocation_probe.py --config session_probe_config.sample.json --dry-run
   python3 tools/session_revocation_probe.py --config session_probe_config.sample.json
   ```
3. It baselines each credential (must succeed now), then prompts you to perform the
   revocation event in your other session; the moment you press Enter it re-probes
   every credential at t+0,2,5,… and prints a per-credential verdict:
   **DIED at t+Xs** (≤~10s ≈ acceptable eventual consistency) or **SURVIVED ≥ t+Xs**
   (potential finding). This gives you the exact survival window — the core evidence.

It probes all credentials at each time point, so one run **is** the §6 variant matrix.

## 6. Variant analysis (Section 17 — the forgotten sibling)

A single "logout" fixing the web session but not these is the classic partial fix.
Test each credential type and surface separately:

- **Access token vs refresh token** — access dies but refresh still mints new ones?
- **Web cookie vs mobile bearer** — one revoked, the other not?
- **WebSocket session** — REST revoked but an already-open authenticated WS keeps
  streaming/acting?
- **API keys** — do password reset / device removal revoke programmatic keys? (Often
  not — and that may be *intended*; reason about it, don't assume a bug.)
- **Per-product** — App revoked but Exchange/NFT/Pay session on the same identity
  still alive? (Ties into H-4.)
- **OAuth "connected apps"/third-party grants** — still valid after password reset?

Make a small matrix: rows = events E1–E7, columns = credential types; each cell =
survived? (Y/N/seconds). Every "Y" that shouldn't be is a candidate.

---

## 7. Destroy-it checklist (Section 22 — before you believe it)

- [ ] Is the survival just **eventual consistency** (dies within, say, 5–10s)? If so,
      likely acceptable — not a finding. Measure precisely.
- [ ] Did you actually trigger the event server-side (check Session B succeeded), not
      just tap a button?
- [ ] Is the "still works" a **cached client view** rather than a real server side
      effect? Confirm the side effect on a *third* fresh session.
- [ ] Does the surviving action actually do something **sensitive**, or is it a
      harmless read of already-public data?
- [ ] Reproduce **3×** from clean sessions.
- [ ] Is this documented/intended (e.g. API keys deliberately independent of password
      reset)? Check the product's own security docs.

---

## 8. Evidence to capture (Section 24, redacted)

For each confirmed FAIL:
- UTC of the revocation event and of each successful replay (show the time gap).
- The sanitized Session-A request (token redacted to first 6 chars) + response
  showing the side effect succeeded post-revocation.
- Proof from a third session that the side effect really persisted (e.g. the
  withdrawal address now appears on the account).
- The event confirmation from Session B.

---

## 9. Report framing (if confirmed)

- **Root cause:** revocation not propagated to credential type X / surface Y (a
  Crypto.com-controlled session-management defect → passes the root-cause gate).
- **Impact:** attacker with transient access retains it after the victim's remediation;
  name the exact sensitive capability that survives.
- **Severity:** map to CIA; argue immediacy + reliability + sensitivity for High.
- **Remediation:** invalidate the invariant properly — server-side revocation list /
  token version bump on the identity, applied to access **and** refresh **and** WS
  **and** cross-product sessions; not just the one surface.

---

## 10. Why this is a good first non-financial target

It needs no funds, is fully reversible, exercises real server-side authz/authn, and
maps cleanly to a High if a sensitive action survives — exactly the "clear, immediate,
reproducible" profile the severity policy rewards.
