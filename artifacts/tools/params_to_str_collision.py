#!/usr/bin/env python3
"""
H-3 local analysis: Crypto.com Exchange API request-signing concatenation ambiguity.

SAFE / LOCAL-FIRST (engagement Section 21): this script touches NO Crypto.com asset.
It re-implements the *publicly documented* signing algorithm and asks one question:

    Can two DIFFERENT parameter sets produce the SAME signature under one secret?

If yes, the signature does not uniquely bind to the request that is executed
(INV-SIGN). We then reason honestly about whether that is exploitable in the
standard single-party API-key model.

Documented algorithm (exchange-docs.crypto.com, community SDKs):
  params_to_str: sort keys ascending; concat as  key + value  (no delimiter);
                 recurse nested objects up to level 3; numbers must be strings.
  sig payload:   method + id + api_key + params_to_str(params) + nonce
  signature:     HMAC_SHA256(secret, sig_payload) -> hex
"""
import hmac, hashlib

MAX_LEVEL = 3

def params_to_str(obj, level=0):
    """Faithful re-implementation of the documented params_to_str."""
    if level >= MAX_LEVEL:
        return str(obj)
    if not isinstance(obj, dict):
        return str(obj)
    out = ""
    for key in sorted(obj.keys()):
        out += str(key)
        val = obj[key]
        if val is None:
            out += "null"
        elif isinstance(val, list):
            for sub in val:
                out += params_to_str(sub, level + 1)
        elif isinstance(val, dict):
            out += params_to_str(val, level + 1)
        else:
            out += str(val)
    return out

def sig_payload(method, req_id, api_key, params, nonce):
    return f"{method}{req_id}{api_key}{params_to_str(params)}{nonce}"

def sign(secret, method, req_id, api_key, params, nonce):
    msg = sig_payload(method, req_id, api_key, params, nonce)
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest(), msg

def show(title, cases, secret="RESEARCHER_OWN_SECRET_dummy", method="private/create-order",
         req_id="1", api_key="OWN_KEY", nonce="1700000000000"):
    print("=" * 78)
    print(title)
    print("=" * 78)
    sigs = {}
    for label, params in cases:
        s, msg = sign(secret, method, req_id, api_key, params, nonce)
        print(f"\n[{label}]")
        print(f"  params      = {params}")
        print(f"  paramString = {params_to_str(params)!r}")
        print(f"  sig_payload = {msg!r}")
        print(f"  signature   = {s}")
        sigs.setdefault(s, []).append(label)
    print("\n--- collision result ---")
    collided = {s: ls for s, ls in sigs.items() if len(ls) > 1}
    if collided:
        for s, ls in collided.items():
            print(f"  COLLISION: {ls} share signature {s[:24]}...")
    else:
        print("  no collision among these cases")
    print()

if __name__ == "__main__":
    # 1) Minimal proof: delimiter-free concat is ambiguous at the param level.
    show("1) PARAM-LEVEL COLLISION (different dicts -> identical paramString/sig)", [
        ("two params  a=1,b=2", {"a": "1", "b": "2"}),          # -> "a1b2"
        ("one param   a=1b2",   {"a": "1b2"}),                   # -> "a1b2"
    ])

    # 2) Realistic-looking collision using order-like fields.
    show("2) REALISTIC COLLISION (a benign single field == a two-field order)", [
        ("two fields", {"instrument_name": "BTC_USDT", "quantity": "1"}),
        # single field whose value swallows the next key+value boundary:
        ("one field ", {"instrument_name": "BTC_USDTquantity1"}),
    ])

    # 3) Key-name vs value boundary ambiguity.
    show("3) KEY/VALUE BOUNDARY AMBIGUITY", [
        ("price=10, side=BUY", {"price": "10", "side": "BUY"}),
        ("price=10sideBUY",    {"price": "10sideBUY"}),
    ])
