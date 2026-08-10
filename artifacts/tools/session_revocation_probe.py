#!/usr/bin/env python3
"""
H-5 session-revocation survival probe (Sections 7, 17, 24).

Measures HOW LONG a captured session/credential keeps working AFTER you trigger a
revocation event (logout-all / password reset / device removal / MFA change) in your
OTHER session. You perform the event by hand; this tool does the precise, timestamped
replay loop and the credential-type variant matrix.

WHY A TOOL: the finding's strength IS the timing. "Still works at t+1h" is a High;
"dies at t+3s" is acceptable eventual consistency. Doing that measurement by hand
across access-token / refresh-token / cookie / per-product sessions is error-prone.

FLOW
  1. BASELINE: probe every credential once — each must currently SUCCEED (session live).
  2. ARM: you go to your OTHER session and perform the revocation event; press Enter.
  3. SCHEDULE: the tool re-probes every credential at t+0,2,5,… seconds and records
     status + whether the sensitive side effect still works.
  4. VERDICT per credential: "DIED at t+Xs" or "SURVIVED ≥ t+Xs" (potential finding).

SAFETY (Sections 1, 2)
  * ONE account, all sessions/credentials YOUR OWN; asset confirmed in current scope.
  * Prefer a NON-DESTRUCTIVE sensitive oracle (e.g. GET withdrawal-address-list, GET
    api-keys, GET full profile). State-changing oracles need allow_state_changing=true.
  * Hard gate + --dry-run (sends nothing). Credentials redacted in output.

USAGE
  python3 session_revocation_probe.py --config cfg.json            # interactive
  python3 session_revocation_probe.py --config cfg.json --dry-run  # plan only
  python3 session_revocation_probe.py --config cfg.json --no-prompt # arm immediately
"""
import argparse, datetime, json, ssl, sys, time, urllib.request, urllib.error

SENSITIVE = ("authorization", "cookie", "x-api-key", "api-key", "refresh-token")

def redact(h):
    return {k: (str(v)[:6] + "…[REDACTED]") if k.lower() in SENSITIVE else v for k, v in h.items()}

def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def gate(cfg):
    problems = []
    if not cfg.get("i_confirm_authorized_scope"):
        problems.append("i_confirm_authorized_scope must be true")
    if not cfg.get("i_own_all_accounts"):
        problems.append("i_own_all_accounts must be true (all sessions/creds yours)")
    if "REPLACE" in cfg.get("base_url", "REPLACE"):
        problems.append("base_url still contains REPLACE placeholder")
    return problems

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

def probe_once(base, p, timeout, insecure):
    method = p.get("method", "GET")
    url = base + p["path"]
    status, body = send(method, url, p["headers"], p.get("body"), timeout, insecure)
    ok = status in p.get("success_statuses", [200, 201])
    if ok and p.get("success_marker"):
        ok = p["success_marker"] in body
    return ok, status

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-prompt", action="store_true")
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()
    cfg = json.load(open(args.config))

    problems = gate(cfg)
    if problems:
        print(("[dry-run] safety gate would BLOCK:" if args.dry_run else "REFUSING — gate failed:"))
        for p in problems: print("  - " + p)
        if not args.dry_run: sys.exit(2)

    base = cfg["base_url"].rstrip("/")
    timeout = float(cfg.get("timeout_seconds", 20))
    allow_state = bool(cfg.get("allow_state_changing", False))
    schedule = cfg.get("schedule_seconds", [0, 2, 5, 15, 30, 60, 300])
    probes = cfg["probes"]

    # skip state-changing probes unless allowed
    usable = []
    for p in probes:
        if p.get("method", "GET").upper() not in ("GET", "HEAD") and not allow_state:
            print(f"skip probe '{p['label']}' (state-changing, allow_state_changing=false)")
        else:
            usable.append(p)

    print("=" * 78)
    print(f"H-5 survival probe  base={base}  schedule(s)={schedule}")
    for p in usable:
        print(f"  probe [{p['label']}] type={p.get('credential_type','?')} "
              f"{p.get('method','GET')} {base + p['path']} headers={redact(p['headers'])}")
    if args.dry_run:
        print("\n[dry-run] would baseline, prompt you to revoke, then re-probe on schedule. Nothing sent.")
        return

    # BASELINE
    print("\n--- BASELINE (each must SUCCEED now) ---")
    for p in usable:
        ok, status = probe_once(base, p, timeout, args.insecure)
        print(f"  [{p['label']}] success={ok} status={status}  {utc()}")
        if not ok:
            print(f"     WARN: baseline not succeeding — re-capture this credential before arming.")

    # ARM
    if not args.no_prompt:
        print("\n>>> Now switch to your OTHER session and perform the revocation event")
        print("    (logout-all / password reset / device removal / MFA change / email-phone change).")
        try:
            input("    Press Enter the moment you've completed it... ")
        except EOFError:
            pass
    arm_t = time.monotonic()
    arm_utc = utc()
    print(f"ARMED at {arm_utc}. Probing on schedule (Ctrl-C to stop early).")

    # SCHEDULE
    results = {p["label"]: [] for p in usable}
    for offset in schedule:
        wait = arm_t + offset - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        for p in usable:
            ok, status = probe_once(base, p, timeout, args.insecure)
            results[p["label"]].append({"offset": offset, "success": ok, "status": status, "utc": utc()})
            flag = "  <-- STILL ALIVE" if ok else ""
            print(f"  t+{offset:>5}s  [{p['label']}] success={ok} status={status}{flag}")

    # VERDICT
    print("\n" + "=" * 78 + "\nVERDICT (per credential)\n" + "=" * 78)
    findings = []
    for p in usable:
        seq = results[p["label"]]
        alive_offsets = [r["offset"] for r in seq if r["success"]]
        dead = [r["offset"] for r in seq if not r["success"]]
        max_off = max(schedule) if schedule else 0
        if alive_offsets and max(alive_offsets) >= max_off and (not dead or max(alive_offsets) > min(dead)):
            last = max(alive_offsets)
            print(f"  [{p['label']}] SURVIVED ≥ t+{last}s after revocation  <-- POTENTIAL FINDING "
                  f"({p.get('credential_type','?')})")
            findings.append({"probe": p["label"], "credential_type": p.get("credential_type"),
                             "survived_to_offset_s": last, "arm_utc": arm_utc})
        elif dead:
            death = min(dead)
            note = "likely acceptable eventual-consistency" if death <= 10 else "worth reporting — measure precisely"
            print(f"  [{p['label']}] died by t+{death}s ({note})")
        else:
            print(f"  [{p['label']}] inconclusive — extend schedule / re-capture")

    if findings:
        print("\nManually confirm the SIDE EFFECT (not just 200) persisted, from a 3rd fresh "
              "session, and reproduce 3x. Longer survival = stronger report.")
    json.dump({"arm_utc": arm_utc, "schedule": schedule, "results": results, "findings": findings},
              open(cfg.get("output_log", "session_revocation_results.json"), "w"), indent=2)

if __name__ == "__main__":
    main()
