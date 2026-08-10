#!/usr/bin/env python3
"""
H-2 idempotency / concurrency harness (engagement Sections 8, 14).

QUESTION
  Can ONE logical money-moving operation execute more than once?
  Two modes:
    --mode race   : fire N identical requests SIMULTANEOUSLY (TOCTOU / double-spend)
    --mode retry  : send once, then re-send the identical request after a delay
                    (client-timeout / idempotency-key reuse)
  It reports how many requests "succeeded" and how many DISTINCT resource ids were
  created (2+ distinct ids from one intent = broken idempotency / value creation).

SAFETY — READ THIS (Sections 1, 2, 14)
  * This operates on YOUR OWN account and moves YOUR OWN funds. Use a withdrawal to
    your own address, a self-transfer, or a tiny convert. Smallest possible amount.
  * This is ATOMICITY testing, not load testing. N is capped low (default 3, max 8).
  * Hard gate: refuses unless config sets ALL of:
        i_confirm_authorized_scope=true, i_own_all_accounts=true,
        allow_state_changing=true, i_understand_this_moves_my_own_funds=true
    AND base_url is a real host (not REPLACE).
  * Amount guard: if amount_field + max_amount are set, refuses to send any request
    whose parsed amount exceeds max_amount.
  * Check your balance/ledger BEFORE and AFTER by hand — the true oracle is the
    ledger, not the HTTP status. Reproduce 3x before believing anything.

USAGE
  python3 idempotency_race_harness.py --config cfg.json --mode race   [--dry-run]
  python3 idempotency_race_harness.py --config cfg.json --mode retry  [--dry-run]
"""
import argparse, json, re, ssl, sys, threading, time, urllib.request, urllib.error

SENSITIVE = ("authorization", "cookie", "x-api-key", "api-key")
HARD_CAP = 8

def redact(h):
    return {k: (v[:6] + "…[REDACTED]") if k.lower() in SENSITIVE else v for k, v in h.items()}

def gate(cfg, mode):
    flags = ["i_confirm_authorized_scope", "i_own_all_accounts",
             "allow_state_changing", "i_understand_this_moves_my_own_funds"]
    problems = [f"{f} must be true" for f in flags if not cfg.get(f)]
    if "REPLACE" in cfg.get("base_url", "REPLACE"):
        problems.append("base_url still contains REPLACE placeholder.")
    return problems

def amount_ok(cfg, body):
    field = cfg.get("amount_field")
    cap = cfg.get("max_amount")
    if not field or cap is None or not body:
        return True, None
    m = re.search(re.escape(field) + r'"?\s*[:=]\s*"?([0-9]*\.?[0-9]+)', body)
    if not m:
        return (cfg.get("allow_unparsed_amount", False),
                f"could not parse '{field}' from body")
    val = float(m.group(1))
    return (val <= float(cap)), f"amount {val} vs cap {cap}"

def send(method, url, headers, body, timeout, insecure):
    data = body.encode() if body else None
    req = urllib.request.Request(url, data=data, method=method.upper())
    for k, v in headers.items():
        req.add_header(k, v)
    ctx = ssl._create_unverified_context() if insecure else None
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode(errors="replace"), round(time.time()-t0, 3)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), round(time.time()-t0, 3)
    except Exception as e:
        return None, f"__ERROR__ {type(e).__name__}: {e}", round(time.time()-t0, 3)

def succeeded(cfg, status, body):
    ok = status in cfg.get("success_statuses", [200, 201])
    marker = cfg.get("success_marker")
    return ok and (marker in body if marker else True)

def extract_id(cfg, body):
    rgx = cfg.get("id_regex")
    if not rgx:
        return None
    m = re.search(rgx, body or "")
    return m.group(1) if m else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--mode", choices=["race", "retry"], required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()

    cfg = json.load(open(args.config))
    problems = gate(cfg, args.mode)
    if problems:
        print(("[dry-run] safety gate would BLOCK a real run:" if args.dry_run
               else "REFUSING TO RUN — safety gate failed:"))
        for p in problems:
            print("  - " + p)
        if not args.dry_run:
            sys.exit(2)

    url = cfg["base_url"].rstrip("/") + cfg["op"]["path"]
    method = cfg["op"].get("method", "POST")
    headers = cfg["op"]["headers"]
    body = cfg["op"].get("body")
    n = min(int(cfg.get("n", 3)), HARD_CAP)
    timeout = float(cfg.get("timeout_seconds", 20))
    delay = float(cfg.get("retry_delay_seconds", 2.0))

    ok, note = amount_ok(cfg, body)
    print(f"amount guard: {'PASS' if ok else 'BLOCK'} ({note})")
    if not ok and not args.dry_run:
        print("REFUSING — amount exceeds max_amount (or unparseable). Fix the body/cap.")
        sys.exit(2)

    print(f"mode={args.mode}  {method} {url}  n={n}")
    print(f"headers={redact(headers)}")
    print(f"body={body}")
    if args.dry_run:
        print("\n[dry-run] no requests sent. This would move YOUR OWN funds on a real run.")
        return

    results = []
    if args.mode == "race":
        barrier = threading.Barrier(n)
        lock = threading.Lock()
        def worker(i):
            barrier.wait()  # align all threads, then fire together
            s, b, dt = send(method, url, headers, body, timeout, args.insecure)
            with lock:
                results.append((i, s, b, dt))
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads: t.start()
        for t in threads: t.join()
    else:  # retry
        for i in range(n):
            s, b, dt = send(method, url, headers, body, timeout, args.insecure)
            results.append((i, s, b, dt))
            print(f"  attempt {i}: status={s} t={dt}s")
            if i < n - 1:
                time.sleep(delay)

    print("\n--- results ---")
    successes, ids = 0, []
    for i, s, b, dt in sorted(results):
        ok_i = succeeded(cfg, s, b)
        rid = extract_id(cfg, b)
        successes += 1 if ok_i else 0
        if rid: ids.append(rid)
        print(f"  req {i}: status={s} success={ok_i} id={rid} t={dt}s")
    distinct = sorted(set(ids))
    print(f"\nsuccesses={successes}/{n}  distinct_resource_ids={len(distinct)} {distinct}")
    if successes > 1 or len(distinct) > 1:
        print("  <-- POTENTIAL BROKEN IDEMPOTENCY / DOUBLE EXECUTION")
        print("      Verify against the LEDGER (balance before/after) and reproduce 3x.")
    else:
        print("  looks idempotent for this op. Try other ops / cancel-vs-request races too.")
    json.dump({"mode": args.mode, "url": url,
               "results": [{"i": i, "status": s, "t": dt} for i, s, b, dt in results],
               "successes": successes, "distinct_ids": distinct},
              open(cfg.get("output_log", "idem_results.json"), "w"), indent=2)

if __name__ == "__main__":
    main()
