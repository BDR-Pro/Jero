#!/usr/bin/env python3
"""
H-4 cross-product token audience / scope confusion harness (Sections 7, 10).

QUESTION
  Is a token minted for product P accepted by product Q's API? A token should be
  bound to its audience/scope; if Exchange's token acts on the App's API (or a
  read-scoped token performs a trade/withdraw), that's privilege/audience confusion.

WHAT IT DOES
  1. For any token that looks like a JWT, decodes header+payload (NO signature
     verification) and prints aud / iss / scope / sub / exp — to reason about whether
     acceptance is by-design SSO or a real boundary break.
  2. Cross-tests every token against every probe whose product differs from the
     token's product, flagging acceptance (success status + marker) as suspicious.

SAFETY (Sections 1, 2)
  * Own accounts only; assets confirmed in current HackerOne scope.
  * Read-only by default. Set allow_state_changing=true only to test that a foreign
    token can perform an ACTION (higher impact) — use minimal/own objects.
  * Hard gate: i_confirm_authorized_scope=true AND i_own_all_accounts=true AND no
    REPLACE placeholders. Credentials redacted in output.

USAGE
  python3 token_audience_harness.py --config cfg.json [--dry-run] [--decode-only]
"""
import argparse, base64, json, ssl, sys, time, urllib.request, urllib.error

SENSITIVE = ("authorization", "cookie", "x-api-key", "api-key")

def redact(h):
    return {k: (v[:6] + "…[REDACTED]") if k.lower() in SENSITIVE else v for k, v in h.items()}

def b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def decode_jwt(token_value):
    """Best-effort JWT introspection. Returns dict of interesting claims or None."""
    raw = token_value.split()[-1]  # strip 'Bearer '
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    try:
        hdr = json.loads(b64url(parts[0]))
        pl = json.loads(b64url(parts[1]))
    except Exception:
        return None
    keep = {k: pl.get(k) for k in ("aud", "iss", "scope", "scp", "sub", "exp", "iat", "azp", "client_id") if k in pl}
    return {"alg": hdr.get("alg"), "typ": hdr.get("typ"), "claims": keep}

def send(method, url, headers, body, timeout, insecure):
    data = body.encode() if body else None
    req = urllib.request.Request(url, data=data, method=method.upper())
    for k, v in headers.items():
        req.add_header(k, v)
    ctx = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return None, f"__ERROR__ {type(e).__name__}: {e}"

def gate(cfg):
    problems = []
    if not cfg.get("i_confirm_authorized_scope"):
        problems.append("i_confirm_authorized_scope must be true")
    if not cfg.get("i_own_all_accounts"):
        problems.append("i_own_all_accounts must be true")
    if "REPLACE" in cfg.get("base_url", "REPLACE"):
        problems.append("base_url still contains REPLACE placeholder")
    return problems

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--decode-only", action="store_true", help="only introspect tokens, send nothing")
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()

    cfg = json.load(open(args.config))

    # 1) token introspection (always safe, no network)
    print("=" * 78 + "\nTOKEN INTROSPECTION (no verification)\n" + "=" * 78)
    for label, tok in cfg["tokens"].items():
        jwt = decode_jwt(tok["header_value"])
        print(f"\n[{label}] product={tok.get('product')}")
        if jwt:
            print(f"  alg={jwt['alg']} claims={json.dumps(jwt['claims'])}")
            if "exp" in jwt["claims"]:
                exp = jwt["claims"]["exp"]
                print(f"  exp epoch={exp} ({'past' if exp < time.time() else 'future'})")
        else:
            print("  (opaque token — not a JWT; audience must be inferred from behavior)")
    if args.decode_only:
        print("\n--decode-only: sent nothing."); return

    problems = gate(cfg)
    if problems:
        print("\n" + ("[dry-run] safety gate would BLOCK:" if args.dry_run else "REFUSING TO RUN — gate failed:"))
        for p in problems: print("  - " + p)
        if not args.dry_run: sys.exit(2)

    base = cfg["base_url"].rstrip("/")
    delay = float(cfg.get("request_delay_seconds", 1.0))
    timeout = float(cfg.get("timeout_seconds", 20))
    allow_state = bool(cfg.get("allow_state_changing", False))

    print("\n" + "=" * 78 + "\nCROSS-PRODUCT MATRIX (foreign token -> probe)\n" + "=" * 78)
    findings = []
    for tlabel, tok in cfg["tokens"].items():
        for probe in cfg["probes"]:
            if probe["product"] == tok.get("product"):
                continue  # same product = expected; we want cross-product
            method = probe.get("method", "GET")
            if method.upper() not in ("GET", "HEAD") and not allow_state:
                continue
            url = base + probe["path"]
            headers = {probe.get("header_name", "Authorization"): tok["header_value"]}
            if args.dry_run:
                print(f"  [dry-run] {tlabel}({tok.get('product')}) -> {probe['label']}({probe['product']}) {method} {url}")
                continue
            status, bdy = send(method, url, headers, probe.get("body"), timeout, args.insecure)
            marker = probe.get("success_marker")
            accepted = status in probe.get("success_statuses", [200, 201]) and (marker in bdy if marker else True)
            flag = "  <-- FOREIGN TOKEN ACCEPTED (investigate)" if accepted else ""
            print(f"  {tlabel}({tok.get('product')}) -> {probe['label']}({probe['product']}): status={status} accepted={accepted}{flag}")
            if accepted:
                findings.append({"token": tlabel, "token_product": tok.get("product"),
                                 "probe": probe["label"], "probe_product": probe["product"],
                                 "status": status, "url": url, "method": method})
            time.sleep(delay)

    if not args.dry_run:
        print(f"\nSUSPICIOUS ACCEPTANCES: {len(findings)}")
        for f in findings: print("  " + json.dumps(f))
        print("\nNOT every acceptance is a bug — some cross-product access is intended SSO.")
        print("Confirm it grants a capability the principal shouldn't have, then reproduce 3x.")
        json.dump({"findings": findings}, open(cfg.get("output_log", "token_audience_results.json"), "w"), indent=2)

if __name__ == "__main__":
    main()
