# H-3 — Exchange signing concatenation ambiguity: local analysis & verdict

**Method:** local-first (Section 21), zero contact with any Crypto.com asset. Ran
`params_to_str_collision.py`, a faithful re-implementation of the *publicly
documented* signing algorithm.

## Result: the ambiguity is REAL (confirmed)

Delimiter-free concatenation makes `params_to_str` non-injective. Different
parameter objects map to the **same** signing payload → the **same** HMAC signature
under one secret. Confirmed examples (run output):

| Case | params A | params B | shared paramString |
|------|----------|----------|--------------------|
| 1 | `{"a":"1","b":"2"}` | `{"a":"1b2"}` | `a1b2` |
| 2 | `{"instrument_name":"BTC_USDT","quantity":"1"}` | `{"instrument_name":"BTC_USDTquantity1"}` | `instrument_nameBTC_USDTquantity1` |
| 3 | `{"price":"10","side":"BUY"}` | `{"price":"10sideBUY"}` | `price10sideBUY` |

So `INV-SIGN` (a signature binds to exactly one request) is *technically* violated:
the signature does not uniquely identify the parameter set.

## Verdict: NOT EXPLOITABLE in the standard single-party API-key model → DISPROVED

Destroy-it reasoning:

1. **The signer already holds the secret.** In the documented model the same party
   computes the signature and sends the request. A collision lets you produce one
   signature valid for two param sets — but you can already sign *any* param set you
   want directly. The ambiguity grants **no capability you don't already have**.
2. **No privilege gap is crossed.** Exploitable signature ambiguity requires a
   *more-privileged* party to sign a *constrained* message that a *less-privileged*
   party can re-interpret. The API-key flow has no such split: one key = one
   principal = one privilege level.
3. **The server acts on the parsed request fields, authenticated by your own key.**
   Making the server "execute a different request than you signed" is meaningless
   when you author both.

Therefore this is **not** a HackerOne-eligible finding on its own. Submitting it
would (correctly) be closed as informative/theoretical (Section 3: theoretical
vulnerabilities lacking practical exploitation are out of scope).

## Residual leads worth a live check (only these could revive H-3)

The ambiguity becomes interesting **only** if a privilege split exists. Under
authorized testing, check whether any of these are present:

- **Delegated / oracle signing:** any endpoint or SDK feature where Crypto.com (or a
  sub-account/broker/OTC/affiliate flow) signs on behalf of a user, or where a
  signature minted for a *restricted* action can be replayed for a broader one.
- **Sub-account or read-only-key escalation:** a signature scoped to `read` that a
  colliding param set turns into a `trade`/`withdraw` interpretation server-side.
- **Nonce replay window:** confirm `(api_key, nonce)` is enforced single-use; a wide
  window is a separate, simpler replay bug (test with your own key).
- **`params_to_str` level-3 recursion cap:** send params nested deeper than 3; if the
  server *executes* fields that the signature *omits*, that IS a signed-vs-executed
  divergence — test on your own account.

If none of these exist, H-3 is dead. Record the outcome either way.

## Reproduce
```
python3 artifacts/tools/params_to_str_collision.py
```
