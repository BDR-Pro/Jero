#!/usr/bin/env python3
"""
H-1 authorization / IDOR differential harness (Section 9 two-account testing).

WHAT IT DOES
  For each object you list (owned by one of YOUR accounts), it:
    1. baseline-reads it with the OWNER's credentials (should succeed),
    2. re-reads it with every OTHER account's credentials,
  and flags any case where a non-owner receives the owner's data
  (cross-account read = potential broken object-level authorization / IDOR).
  It compares HTTP status, presence of an owner-identifying marker, and body
  similarity — not just status codes (Section 9).

SAFETY (engagement Sections 1, 2, 9)
  * You run this yourself, against assets you have CONFIRMED are in the current
    HackerOne scope, using accounts YOU own. It is not run from the research sandbox.
  * Hard gate: refuses to send unless the config sets
        "i_confirm_authorized_scope": true  AND  "i_own_all_accounts": true
    and base_url is a real host (not the REPLACE placeholder).
  * Read-only by default. State-changing methods are skipped unless
    "allow_state_changing": true (use only on your own objects, minimal values).
  * Self-throttled by request_delay_seconds. This is atomicity/authz testing, not
    load testing — keep it slow.
  * Credentials are redacted in all output.

USAGE
  python3 idor_differential_harness.py --config my_idor_config.json          # run
  python3 idor_differential_harness.py --config my_idor_config.json --dry-run # plan only

CONFIG FORMAT  (see idor_config.sample.json)
"""
import argparse, json, sys, time, ssl, urllib.request, urllib.error
from difflib import SequenceMatcher

SENSITIVE_HEADERS = ("authorization", "cookie", "x-api-key", "api-key")

def redact(headers):
    out = {}
    for k, v in headers.items():
        out[k] = (v[:6] + "…[REDACTED]") if k.lower() in SENSITIVE_HEADERS else v
    return out

def do_request(method, url, headers, body, timeout, insecure):
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

def similarity(a, b):
    if not a or not b or a.startswith("__ERROR__") or b.startswith("__ERROR__"):
        return 0.0
    return round(SequenceMatcher(None, a[:4000], b[:4000]).ratio(), 3)

def gate(cfg):
    problems = []
    if not cfg.get("i_confirm_authorized_scope"):
        problems.append("i_confirm_authorized_scope must be true (verify asset is in current HackerOne scope).")
    if not cfg.get("i_own_all_accounts"):
        problems.append("i_own_all_accounts must be true (all accounts must be researcher-controlled).")
    if "REPLACE" in cfg.get("base_url", "REPLACE"):
        problems.append("base_url still contains the REPLACE placeholder.")
    return problems

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verify (test envs only)")
    args = ap.parse_args()

    cfg = json.load(open(args.config))
    problems = gate(cfg)
    if problems and not args.dry_run:
        print("REFUSING TO RUN — safety gate failed:")
        for p in problems:
            print("  - " + p)
        sys.exit(2)
    if problems and args.dry_run:
        print("[dry-run] safety gate would BLOCK a real run:")
        for p in problems:
            print("  - " + p)
        print()

    base = cfg["base_url"].rstrip("/")
    delay = float(cfg.get("request_delay_seconds", 1.0))
    timeout = float(cfg.get("timeout_seconds", 20))
    allow_state = bool(cfg.get("allow_state_changing", False))
    accounts = cfg["accounts"]
    findings = []

    for obj in cfg["objects"]:
        label = obj["label"]
        owner = obj["owner"]
        method = obj.get("method", "GET")
        url = base + obj["path"]
        marker = obj.get("owner_marker")
        body = obj.get("body")
        state_changing = method.upper() not in ("GET", "HEAD")

        print("=" * 78)
        print(f"OBJECT: {label}   owner={owner}   {method} {url}")
        if marker:
            print(f"owner_marker: {marker!r}")
        if state_changing and not allow_state:
            print("  SKIP: state-changing method and allow_state_changing=false")
            continue
        if args.dry_run:
            print("  [dry-run] would baseline-read as owner, then re-read as each other account")
            continue

        # baseline
        b_status, b_body = do_request(method, url, accounts[owner]["headers"], body, timeout, args.insecure)
        print(f"  [baseline {owner}] status={b_status} marker={'YES' if marker and marker in b_body else 'no'}")
        time.sleep(delay)

        # differential
        for acct, spec in accounts.items():
            if acct == owner:
                continue
            a_status, a_body = do_request(method, url, spec["headers"], body, timeout, args.insecure)
            has_marker = bool(marker and marker in a_body)
            sim = similarity(b_body, a_body)
            leak = has_marker or (a_status == b_status == 200 and sim >= 0.9)
            flag = "  <-- POTENTIAL IDOR" if leak else ""
            print(f"  [attacker {acct}] status={a_status} marker={'YES' if has_marker else 'no'} sim={sim}{flag}")
            if leak:
                findings.append({"object": label, "owner": owner, "attacker": acct,
                                 "attacker_status": a_status, "owner_marker_seen": has_marker,
                                 "body_similarity": sim, "url": url, "method": method})
            time.sleep(delay)

    print("=" * 78)
    if args.dry_run:
        print("dry-run complete — no requests sent.")
        return
    print(f"POTENTIAL FINDINGS: {len(findings)}")
    for f in findings:
        print("  " + json.dumps(f))
    out = cfg.get("output_log", "idor_results.json")
    json.dump({"findings": findings, "config_redacted": {**cfg,
              "accounts": {a: {"headers": redact(s["headers"])} for a, s in accounts.items()}}},
              open(out, "w"), indent=2)
    print(f"\nWrote {out}. Manually verify every flag ≥3x from a clean session before "
          f"believing it (Section 22/25). status/marker heuristics produce false positives.")

if __name__ == "__main__":
    main()
