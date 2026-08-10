#!/usr/bin/env python3
"""
H-7 Crypto.com Pay — webhook signature scheme analyzer (LOCAL, no target contact).

Analyzes a webhook that Crypto.com Pay sent to YOUR OWN sandbox merchant endpoint,
using YOUR OWN webhook signing secret (from your merchant dashboard). It reverse-
engineers exactly WHAT Pay signs, then judges the SCHEME for two Crypto.com-CONTROLLED
weaknesses:

  * REPLAY protection  — is a fresh timestamp/nonce bound into the signature? If not,
    a captured webhook can be re-verified forever (INV-SIGN, replay).
  * FIELD binding      — does the signature cover amount / currency / status /
    order-id? If a critical field is NOT in the signed payload, it can be tampered
    while the signature still verifies (INV-SIGN, tamper).

WHY THIS IS THE CRYPTO.COM-CONTROLLED PART (root-cause boundary — POLICY_MATRIX.md §2)
  * The webhook *signing scheme* (algorithm, what's covered, freshness) is designed by
    Crypto.com → a weakness in it is Crypto.com-controlled → eligible.
  * A specific MERCHANT failing to verify the signature is the MERCHANT's bug → NOT
    eligible. Keep your report about the scheme, and pair it with concrete impact.

100% offline: reads a captured file, computes HMACs locally. Sends nothing.

USAGE
  python3 pay_webhook_analyzer.py --capture webhook_capture.json
"""
import argparse, hashlib, hmac, json, re

CRITICAL_FIELDS = ("amount", "currency", "status", "state", "order_id", "id",
                   "charge_id", "payment_id", "sub_total", "recipient")
HEX = re.compile(r"\b[0-9a-fA-F]{40,128}\b")

def hmac_hex(secret, msg, algo):
    return hmac.new(secret.encode(), msg.encode(), algo).hexdigest()

def parse_sig_header(value):
    """Return (timestamp_or_None, [candidate_hex_signatures])."""
    t = None
    mt = re.search(r"(?:^|[,;\s])t=(\d+)", value)
    if mt:
        t = mt.group(1)
    cands = set(HEX.findall(value))
    # also v1=... style
    for m in re.finditer(r"v\d+=([0-9a-fA-F]{40,128})", value):
        cands.add(m.group(1))
    if HEX.fullmatch(value.strip()):
        cands.add(value.strip())
    return t, [c.lower() for c in cands]

def find_sig_header(headers, explicit):
    if explicit and explicit in headers:
        return explicit, headers[explicit]
    for k, v in headers.items():
        if k.lower() in ("pay-signature", "x-pay-signature", "x-signature",
                          "signature", "x-webhook-signature", "webhook-signature"):
            return k, v
    return None, None

def header_timestamp(headers):
    for k, v in headers.items():
        if k.lower() in ("pay-timestamp", "x-timestamp", "timestamp", "x-pay-timestamp",
                         "x-request-timestamp"):
            return str(v)
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", required=True,
                    help="JSON: {headers:{}, raw_body:'', webhook_secret:'', signature_header_name?:''}")
    args = ap.parse_args()
    cap = json.load(open(args.capture))
    headers = cap["headers"]
    body = cap["raw_body"]
    secret = cap["webhook_secret"]

    sig_name, sig_val = find_sig_header(headers, cap.get("signature_header_name"))
    print("=" * 78 + "\nCRYPTO.COM PAY WEBHOOK SCHEME ANALYSIS (local)\n" + "=" * 78)
    if not sig_val:
        print("No signature header found. Set signature_header_name in the capture file.")
        print("Headers present:", list(headers.keys()))
        return
    t_in_sig, sig_cands = parse_sig_header(sig_val)
    t_in_hdr = header_timestamp(headers)
    ts = t_in_sig or t_in_hdr
    print(f"signature header: {sig_name}")
    print(f"timestamp: in-sig={t_in_sig} in-header={t_in_hdr}")
    print(f"candidate signatures: {[c[:16]+'…' for c in sig_cands]}")

    # 1) recover the signed canonicalization
    algos = {"sha256": hashlib.sha256, "sha1": hashlib.sha1, "sha512": hashlib.sha512}
    payloads = {
        "raw_body": body,
        "t.raw_body (Stripe-style)": f"{ts}.{body}" if ts else None,
        "t+raw_body": f"{ts}{body}" if ts else None,
        "raw_body+t": f"{body}{ts}" if ts else None,
    }
    match = None
    for pname, payload in payloads.items():
        if payload is None:
            continue
        for aname, a in algos.items():
            got = hmac_hex(secret, payload, a)
            if got.lower() in sig_cands:
                match = (pname, aname, payload)
                break
        if match:
            break
    # also test a weak non-HMAC scheme
    if not match:
        for pname, payload in payloads.items():
            if payload is None: continue
            for aname, a in algos.items():
                if a(f"{secret}{payload}".encode()).hexdigest().lower() in sig_cands:
                    match = (pname + " [WEAK: plain hash(secret+payload), not HMAC]", aname, payload)
                    break
            if match: break

    print("\n--- recovered signing scheme ---")
    if not match:
        print("  Could NOT match the signature with tried schemes.")
        print("  Add the correct canonicalization/secret, or the algo may differ.")
        print("  Tried payloads:", [p for p in payloads if payloads[p] is not None],
              "algos:", list(algos))
        return
    pname, aname, payload = match
    print(f"  signed payload = {pname}")
    print(f"  algorithm      = HMAC-{aname}")

    # 2) replay verdict
    print("\n--- REPLAY protection ---")
    has_fresh = (ts is not None) and (str(ts) in payload)
    if has_fresh:
        print(f"  timestamp {ts} IS bound into the signed payload → replay needs a fresh")
        print("  timestamp the attacker can't forge. Now test the SERVER's freshness window:")
        print("  re-deliver the identical webhook after N minutes and see if it's still")
        print("  accepted (a bound-but-never-checked timestamp is still replayable).")
    else:
        print("  NO fresh timestamp/nonce is bound into the signature.")
        print("  => the captured webhook can be re-sent verbatim and will re-verify forever.")
        print("  => SCHEME-LEVEL REPLAY WEAKNESS (Crypto.com-controlled). Pair with impact:")
        print("     e.g. a merchant credited twice for one payment.")

    # 3) field-binding verdict
    print("\n--- FIELD binding (tamper) ---")
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    covered, not_covered = [], []
    for f in CRITICAL_FIELDS:
        present = (f in body)
        if not present:
            continue
        # a field is "covered" iff it appears inside the exact signed payload string
        (covered if f in payload else not_covered).append(f)
    print(f"  critical fields present in body: covered-by-signature={covered}")
    if not_covered:
        print(f"  NOT covered by signature: {not_covered}")
        print("  => those fields can be changed while the signature still verifies (tamper).")
    else:
        print("  all present critical fields fall inside the signed payload (good).")

    print("\n--- verdict ---")
    weak = (not has_fresh) or bool(not_covered)
    if weak:
        print("  POTENTIAL Crypto.com-controlled webhook-scheme weakness. Build a concrete,")
        print("  safe PoC (own sandbox) showing double-credit or amount/status tamper, and")
        print("  frame the report about the SCHEME, not a single merchant's verification.")
    else:
        print("  Scheme binds a fresh timestamp and all present critical fields. Focus H-7")
        print("  effort on merchant-isolation / state-machine tests instead (pay_merchant_ops).")

if __name__ == "__main__":
    main()
