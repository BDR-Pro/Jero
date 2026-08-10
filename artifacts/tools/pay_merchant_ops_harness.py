#!/usr/bin/env python3
"""
H-7 Crypto.com Pay — merchant isolation + charge/refund state-machine harness.

Covers two Crypto.com-CONTROLLED invariants on the Pay merchant API:
  * INV-OWN  : merchant B must not read/act on merchant A's charges/refunds.
  * INV-STATE/INV-BAL/INV-IDEM : the API must reject invalid money transitions
                (refund > charge, double refund, capture-after-expire, re-pay, etc.)

It runs an ORDERED list of steps as a chosen actor (MERCHANT_A / MERCHANT_B),
capturing values (e.g. charge_id) from responses and substituting them into later
steps via {{var}} — so you can script the isolation matrix AND state-machine
sequences. Steps marked {"expect":{"deny":true}} are NEGATIVE tests: a success there
is a POTENTIAL FINDING.

ROOT-CAUSE NOTE (read POLICY_MATRIX.md §2): the Pay merchant API and its ownership /
state enforcement are Crypto.com-controlled → eligible. A *merchant's own* failure to
verify a webhook is NOT (that's the merchant's bug) — see pay_webhook_analyzer.py and
the H7 playbook for that boundary.

SAFETY (Sections 1,2,14): own merchant sandbox accounts only; assets confirmed in
current HackerOne scope; smallest amounts; amount guard; read-only unless
allow_state_changing=true; --dry-run sends nothing; credentials redacted.

USAGE
  python3 pay_merchant_ops_harness.py --config cfg.json [--dry-run]
"""
import argparse, json, re, ssl, sys, time, urllib.request, urllib.error

SENSITIVE = ("authorization", "cookie", "x-api-key", "api-key", "pay-signature")

def redact(h):
    return {k: (v[:6] + "…[REDACTED]") if k.lower() in SENSITIVE else v for k, v in h.items()}

def gate(cfg):
    problems = []
    if not cfg.get("i_confirm_authorized_scope"):
        problems.append("i_confirm_authorized_scope must be true")
    if not cfg.get("i_own_all_accounts"):
        problems.append("i_own_all_accounts must be true (both merchant accounts yours)")
    if "REPLACE" in cfg.get("base_url", "REPLACE"):
        problems.append("base_url still contains REPLACE placeholder")
    return problems

def subst(s, vars):
    if not s:
        return s
    for k, v in vars.items():
        s = s.replace("{{" + k + "}}", str(v))
    return s

def amount_ok(cfg, body):
    field, cap = cfg.get("amount_field"), cfg.get("max_amount")
    if not field or cap is None or not body:
        return True, None
    m = re.search(re.escape(field) + r'"?\s*[:=]\s*"?([0-9]*\.?[0-9]+)', body)
    if not m:
        return cfg.get("allow_unparsed_amount", False), f"could not parse '{field}'"
    val = float(m.group(1))
    return val <= float(cap), f"amount {val} vs cap {cap}"

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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()
    cfg = json.load(open(args.config))

    problems = gate(cfg)
    if problems:
        print(("[dry-run] safety gate would BLOCK:" if args.dry_run
               else "REFUSING TO RUN — gate failed:"))
        for p in problems: print("  - " + p)
        if not args.dry_run: sys.exit(2)

    base = cfg["base_url"].rstrip("/")
    actors = cfg["actors"]
    delay = float(cfg.get("request_delay_seconds", 1.5))
    timeout = float(cfg.get("timeout_seconds", 20))
    allow_state = bool(cfg.get("allow_state_changing", False))
    vars = dict(cfg.get("initial_vars", {}))
    findings = []

    for i, step in enumerate(cfg["steps"]):
        label = step.get("label", f"step{i}")
        actor = step["actor"]
        method = step.get("method", "GET")
        url = base + subst(step["path"], vars)
        body = subst(step.get("body"), vars)
        expect = step.get("expect", {})
        deny = bool(expect.get("deny"))
        state_changing = method.upper() not in ("GET", "HEAD")

        print("=" * 78)
        print(f"[{i}] {label}  actor={actor}  {method} {url}")
        if body: print(f"     body={body}")

        ok, note = amount_ok(cfg, body)
        if not ok:
            print(f"     amount guard BLOCK ({note}) — skipping this step")
            continue
        if state_changing and not allow_state:
            print("     SKIP: state-changing and allow_state_changing=false")
            continue
        if args.dry_run:
            print(f"     [dry-run] would send as {actor}; expect={'DENY' if deny else expect or 'n/a'}")
            continue

        headers = actors[actor]["headers"]
        status, resp = send(method, url, headers, body, timeout, args.insecure)
        success = status in expect.get("success_statuses", [200, 201])
        marker_ok = (expect["marker"] in resp) if expect.get("marker") else True

        verdict = ""
        if deny:
            if success:
                verdict = "  <-- POTENTIAL FINDING (denied action SUCCEEDED)"
                findings.append({"step": label, "actor": actor, "url": url,
                                 "method": method, "status": status,
                                 "why": "negative test succeeded (isolation/state break)"})
            else:
                verdict = "  (correctly denied)"
        else:
            verdict = "  (baseline ok)" if (success and marker_ok) else "  (unexpected: baseline failed)"
        print(f"     status={status}{verdict}")

        for cap in step.get("capture", []):
            m = re.search(cap["regex"], resp or "")
            if m:
                vars[cap["name"]] = m.group(1)
                print(f"     captured {cap['name']}={m.group(1)}")
            else:
                print(f"     WARN: capture '{cap['name']}' regex did not match")
        time.sleep(delay)

    print("=" * 78)
    if args.dry_run:
        print("dry-run complete — no requests sent."); return
    print(f"POTENTIAL FINDINGS: {len(findings)}")
    for f in findings: print("  " + json.dumps(f))
    print("\nEvery flag is a NEGATIVE test that unexpectedly succeeded — manually confirm "
          "the side effect really happened (money/state changed) and reproduce 3x. A 200 "
          "that did nothing is a false positive.")
    json.dump({"findings": findings, "vars": vars},
              open(cfg.get("output_log", "pay_ops_results.json"), "w"), indent=2)

if __name__ == "__main__":
    main()
