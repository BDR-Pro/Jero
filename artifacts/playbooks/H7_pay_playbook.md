# H-7 Playbook — Crypto.com Pay: merchant isolation, charge/refund state machine, webhook scheme

Three sub-hypotheses under H-7. The **hardest part of H-7 is the root-cause
boundary** — get it right before you spend time, or you'll write up a merchant's bug
that (correctly) gets closed as out of scope.

---

## 0. THE ROOT-CAUSE BOUNDARY (read first — POLICY_MATRIX.md §2)

| Behavior | Root cause | Eligible? |
|----------|-----------|-----------|
| Pay merchant API lets merchant B read/refund merchant A's charge | Crypto.com API authz | ✅ YES |
| Pay API allows refund > charge / double refund / re-pay expired charge | Crypto.com API state machine | ✅ YES |
| Pay's webhook **signing scheme** lacks replay protection or doesn't bind amount/status | Crypto.com scheme design | ✅ YES (scheme-level) |
| Pay's payment-result **redirect/return-URL** signature is forgeable/omittable | Crypto.com signs it | ✅ YES |
| Pay API marks a charge "paid" from attacker-controlled input without real settlement | Crypto.com API | ✅ YES (high impact) |
| **A specific merchant** fails to verify a (sound) webhook signature | The merchant's code | ❌ NO — merchant's bug |
| Merchant's own server has an IDOR/SSRF/etc. | The merchant | ❌ NO |

Rule of thumb: if the defect is in **Crypto.com's API, scheme, or signature**, it's in
scope. If it's in **how one integrator consumes** a correct Crypto.com artifact, it's
not. Frame every H-7 report about Crypto.com's side.

---

## 1. Preconditions (all your own — Sections 1, 2)
- **Two sandbox merchant accounts** you own: **MERCHANT_A**, **MERCHANT_B**.
- A **buyer**/test-payer identity you own (to drive a real charge in sandbox).
- **Your own webhook receiver** (a tiny server / RequestBin you control) registered
  as MERCHANT_A's webhook URL — so you capture *real* webhooks Pay sends, with their
  headers and signatures.
- Your **webhook signing secret** from the MERCHANT_A dashboard (your own secret).
- Confirm Pay + a sandbox is in the **current** HackerOne scope first.

---

## 2. Sub-test A — merchant isolation (INV-OWN)   → `pay_merchant_ops_harness.py`
Goal: MERCHANT_B must not read/act on MERCHANT_A's objects.
1. In `pay_ops_config.sample.json`, fill both merchants' API keys and the real charge/
   refund paths; set the three confirm flags + `allow_state_changing` appropriately.
2. The sample steps already: A creates a charge (captures `charge_id`), A reads it
   (baseline), then **B reads it** and **B refunds it** as `expect.deny` negative
   tests. Run:
   ```
   python3 pay_merchant_ops_harness.py --config pay_ops_config.sample.json --dry-run
   python3 pay_merchant_ops_harness.py --config pay_ops_config.sample.json
   ```
3. Any negative step that **succeeds** (and actually returns A's data / performs the
   refund) is a candidate isolation break. Add more object types: refund objects,
   payout/settlement records, webhook config, API-key listing, customer records.

## 3. Sub-test B — charge/refund state machine (INV-STATE / INV-BAL / INV-IDEM)
Same harness, negative steps on your **own** charge:
- refund **more** than charged; refund a **cancelled/expired** charge; **double**
  refund; **re-pay** a completed charge; **capture** after expiry; cancel after pay.
- Race variant: to test double-capture/refund concurrency, drive the same op with the
  `idempotency_race_harness.py` (H-2 tool) pointed at the Pay endpoint.
- Oracle = the money/state actually changed (check the charge/refund/settlement
  record), not just a 200.

## 4. Sub-test C — webhook scheme soundness (INV-SIGN)   → `pay_webhook_analyzer.py`
This is offline analysis of Crypto.com's own scheme:
1. Trigger a real payment in sandbox so Pay sends a webhook to your receiver.
2. Save the webhook into `webhook_capture.json` (`headers`, `raw_body`,
   `webhook_secret`, optional `signature_header_name`). Run:
   ```
   python3 pay_webhook_analyzer.py --capture webhook_capture.json
   ```
3. It recovers exactly what Pay signs and judges:
   - **Replay:** is a fresh timestamp/nonce *bound into the signature*? If not, a
     captured webhook re-verifies forever → scheme-level replay weakness. Then confirm
     the *server-side* freshness window if a timestamp exists but might be unchecked.
   - **Field binding:** are `amount` / `currency` / `status` / `order_id` inside the
     signed payload? A critical field outside it = tamperable.
4. If weak, build a **safe sandbox PoC** of concrete impact (e.g. replay one real
   payment webhook → your own merchant records two settlements for one payment; or
   tamper `amount` upward while the signature still verifies). Report it about the
   **scheme**, and note it affects *every* integrator, which is what makes it
   Crypto.com's problem, not one merchant's.

## 5. Sub-test D — payment-result redirect / return-URL signature (INV-SIGN)
If checkout redirects back to the merchant with signed result params (e.g.
`?status=paid&sig=...`), test whether that signature is:
- **omittable** (server accepts the redirect without it),
- **forgeable** (weak/guessable, or signs a subset excluding `status`/`amount`),
- **replayable** across orders.
Crypto.com signs these → in scope. Impact: forge a "paid" result → goods released
without payment.

---

## 6. Destroy-it checklist (Section 22) — H-7 specific
- [ ] Is the failing check on **Crypto.com's** side, or did you actually test a
      merchant's own verification? (The #1 H-7 false positive.)
- [ ] Did the negative op actually change money/state, or just return 200 with no
      effect?
- [ ] Is the "isolation break" reading data that's actually meant to be shared (e.g.
      a public charge page), or truly another merchant's private data?
- [ ] For webhook replay: does Crypto.com maybe bind a timestamp you missed? Re-run
      the analyzer with the timestamp header included.
- [ ] Sandbox-only behavior that differs from production? (Severity is lower for
      dev/staging — verify it reproduces on the in-scope environment.)
- [ ] Reproduce 3× from clean state.

## 7. Severity / eligibility framing
- Merchant isolation read → Confidentiality (another merchant's charge/customer data).
- Cross-merchant refund / refund>charge / double refund / forged "paid" → Integrity,
  potentially **High** (unrestricted-ish balance/settlement manipulation), if
  immediate + reliable + real impact.
- Webhook replay/tamper → Integrity; argue it's scheme-level (all integrators),
  Crypto.com-controlled, with a concrete double-credit/tamper PoC. Without concrete
  impact it risks being rated informational — bring the PoC.

## 8. Safety
Own sandbox merchants/buyer only; smallest amounts (amount guard on); never touch a
real merchant's charges; `--dry-run` first; webhook analysis is offline. Stop at the
minimum proof.
