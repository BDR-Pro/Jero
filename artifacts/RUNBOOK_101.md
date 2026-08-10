# RUNBOOK 101 — "How do I actually test this myself?"

A beginner-friendly companion to `OPERATOR_RUNBOOK.md`. It assumes you have nothing
installed yet and walks you to your first real test. Do this on **your own computer**
(not this research sandbox — the sandbox is network-blocked from the targets on
purpose).

---

## 0. The mental model (in one picture)

```
   YOU (logged in)                                    Crypto.com servers
        │                                                     ▲
        ▼                                                     │
   Your browser / app  ──HTTP request──►  [ PROXY you run ]  ─┘
                                          (Burp / mitmproxy)
                                          you SEE + EDIT the
                                          request here, then a
                                          harness REPLAYS edited
                                          versions to check a rule
```

Security testing here = **watch the requests your own client makes, change one thing,
and see if the server still lets you.** The proxy is your microscope; the harnesses
just automate the "change one thing and replay" step.

---

## 1. First, the gate (do NOT skip — it's the authorization)

1. Make a **HackerOne account** → open `https://hackerone.com/crypto`.
2. Read and **accept** the program policy. *That acceptance is what authorizes you.*
3. Read the **Scope** tab. Write the in-scope assets into `SCOPE_SNAPSHOT.md §4`
   (which host, bounty-eligible?, max severity).
4. Rule: **if an asset isn't clearly listed in scope, you don't touch it.** Ever.

Until this is done, the harnesses will physically refuse to run (that's the
`i_confirm_authorized_scope` flag).

---

## 2. Set up your kit (~30–45 min, one time)

| Tool | What for | How |
|------|----------|-----|
| **Python 3** | run the harnesses | `python3 --version` (install from python.org if missing) |
| **Burp Suite Community** (free) | see/edit/replay requests | download from portswigger.net; or use **mitmproxy** / **Caido** |
| **A browser** | drive the web app | any; you'll point it at the proxy |
| **Two accounts** | authorization tests | register **ATTACKER** and **VICTIM** — *both yours* |

**Point your browser at Burp (web testing):**
1. Start Burp → it listens on `127.0.0.1:8080`.
2. Set your browser proxy to `127.0.0.1:8080` (use the FoxyProxy extension, or
   Burp's built-in browser which is pre-configured).
3. Install Burp's CA certificate so HTTPS doesn't error: browse to `http://burp` →
   download the cert → add it to your browser/OS trust store. (One-time.)
4. Now every request your browser makes shows up in Burp → **Proxy → HTTP history**.

*(Mobile testing needs an emulator + the CA on the device — harder. Start with web.)*

---

## 3. The ONE skill to learn: capture a request → turn it into a test

This is 80% of the job. Practice it once:

1. In Burp, log in to the app as **VICTIM** and do something (e.g. open your order/
   transaction history).
2. In **Proxy → HTTP history**, click the request that fetched that data.
3. Read off these four things:
   - **Method** (GET/POST…)
   - **URL** (`https://host/path?query`)
   - **Headers** — especially `Authorization: Bearer …` or `Cookie: …` (this *is*
     your identity)
   - **Body** (for POST)
4. Right-click → **Send to Repeater**. In the **Repeater** tab you can edit any part
   and hit **Send** to replay it. This is manual testing.

**Mapping a captured request into a harness config:**

| From the captured request | Goes into the config as |
|---------------------------|-------------------------|
| `https://host` | `base_url` |
| `/path?query` | the probe/step `path` |
| `Authorization: Bearer abc…` | `headers` → `{"Authorization":"Bearer abc…"}` |
| `Cookie: sid=…` | `headers` → `{"Cookie":"sid=…"}` |
| POST body | `body` |
| the id that identifies the object | the thing you swap between accounts |

---

## 4. Worked example — your first test (H-1 IDOR, read-only, safest)

**Question:** can ATTACKER read VICTIM's private object just by using its ID?

**Manual version (do this first, to understand it):**
1. As **VICTIM**: open an object (say an order). Note its **ID** (in the URL or JSON,
   e.g. `order_id=99123`).
2. As **ATTACKER**: capture *your own* "get order" request; **Send to Repeater**.
3. In Repeater, replace your order id with **VICTIM's** id (`99123`) and **Send**.
4. **Result:**
   - You get VICTIM's order data back → **potential IDOR** (write it down).
   - You get 403/empty → the check works; move on.

**Automated version (same idea, many objects at once):**
1. Open `artifacts/tools/idor_config.sample.json`.
2. Fill in:
   - `base_url` → the real host
   - `accounts.ATTACKER.headers` and `accounts.VICTIM.headers` → each account's token/cookie
   - `objects[].path` → the request path with VICTIM's object id
   - `objects[].owner_marker` → a string that only appears in VICTIM's data (e.g. the id)
3. Set `i_confirm_authorized_scope` and `i_own_all_accounts` to `true` (only if true!).
4. Run:
   ```
   python3 artifacts/tools/idor_differential_harness.py --config idor_config.sample.json --dry-run
   python3 artifacts/tools/idor_differential_harness.py --config idor_config.sample.json
   ```
5. **Read the output:** a line ending `<-- POTENTIAL IDOR` means ATTACKER got data
   that looks like VICTIM's. That's a *lead*, not a confirmed bug — verify by hand.

**Zero-funds alternative first test:** H-5. Log in on two devices, run
`tools/session_revocation_probe.py`, log out / reset password on device B, and watch
whether device A's session keeps working. No money involved. See
`playbooks/H5_session_recovery_desync_playbook.md`.

---

## 5. Running any harness (the pattern)

```
1. cp the sample config → your own config, edit the REPLACE placeholders
2. run with --dry-run first   → confirms the safety gate + shows the plan, sends nothing
3. flip the confirm flags to true (only when genuinely true)
4. run for real
5. read the flagged lines → each is a LEAD to verify by hand
```
Every harness redacts your tokens in its output and refuses to run against the
`REPLACE` placeholder host.

---

## 6. "Did I actually find something?" — the 60-second reality check

Before you believe any flag (this is where beginners go wrong):
- [ ] Reproduce it **3×** from a **fresh login** (not a cached tab).
- [ ] Did a **side effect** really happen (data returned / money moved / state
      changed), or just a `200` with nothing behind it?
- [ ] Is the "leaked" data actually **private**, or is it public (e.g. a public
      blockchain address = not a finding)?
- [ ] Are you sure you're seeing **VICTIM's** data and not ATTACKER's own?
- [ ] Is it maybe **intended** behavior? Check the product docs.

If it survives all five, you have a real candidate → write it up with the report
template in `OPERATOR_RUNBOOK.md` Step 7 and submit on HackerOne.

---

## 7. Safety, in plain words (Section 2)

- Only ever use **your own** accounts and **your own** data.
- Money tests: **smallest possible** amount, to **your own** address.
- Don't run loud automated **scanners** at the site; these harnesses are slow and
  targeted on purpose.
- Test **only** assets you confirmed are in scope.
- Stop at the **minimum proof** — you don't need to drain anything to prove a bug.
- If you're unsure whether something is allowed → **don't**, and ask.

---

## 8. Suggested order for your very first session
1. Do §1 (accept program, capture scope).
2. Do §2 (install Burp + Python, two accounts).
3. Practice §3 (capture one request, Send to Repeater).
4. Run the **H-5** no-funds test *or* the **H-1** read-only IDOR manual test.
5. Only then try the automated harnesses and the money-touching tests (H-2/H-7).
