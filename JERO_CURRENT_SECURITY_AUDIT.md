# Jero — Current Security Audit (post-sync)

> Re-audit performed after the maintainer synchronized the fork with upstream Monero.
> This report supersedes the previous audit of snapshot `17891e91`.

## Status header

| Field | Value |
|---|---|
| **CURRENT JERO HEAD** (`origin/master`) | `d8c8cc310cece26250b087659c1bc2e40f86eb75` |
| **CURRENT UPSTREAM HEAD** (`monero-project/master`) | `d8c8cc310cece26250b087659c1bc2e40f86eb75` |
| **MERGE BASE** (fork ↔ upstream) | `d8c8cc31` (identical — they are the same commit) |
| **UPSTREAM COMMITS BEHIND** | **0** |
| **JERO COMMITS AHEAD** | **0** |
| **JERO FILE DELTA vs UPSTREAM** | **0 files, 0 lines** (`git diff origin/master upstream/master` is empty) |
| **PREVIOUS AUDIT SNAPSHOT** | `17891e91` — now **391 commits behind** current HEAD |
| **PREVIOUS FINDINGS STILL APPLICABLE (to current fork)** | **0 of 6** — all fixed by the sync |
| **NEW JERO-SPECIFIC FINDINGS** | **0** — there is no Jero-specific code to introduce any |
| **TESTS RUN (locally)** | None — build deps (Boost, libsodium, unbound) and all git submodules are absent in this environment |
| **TESTS PASSED / FAILED** | N/A locally. This exact commit is upstream Monero's `master` tip and passed upstream CI (unit / functional / core / crypto / fuzz) before merge; the finding-specific regression tests are present in-tree |

---

## The bottom line (blunt, as requested)

**The previous security exposure was caused 100% by the fork being outdated, and 0% by Jero-specific code.**

Jero has **no proprietary modifications whatsoever** — `origin/master` is byte-for-byte identical to `monero-project/master`. Every finding in the prior audit (the six money bugs, plus the additional P2P/DoS/parser bugs the deeper sweep turned up) was a **historical upstream Monero bug that existed only because the fork was pinned 391 commits behind upstream.** The moment you synchronized to `d8c8cc31`, all of them were resolved by upstream's own fixes.

There is not one Jero-specific vulnerability, because there is not one line of Jero-specific code.

A direct consequence worth stating plainly: **"auditing Jero" and "auditing upstream Monero" are now the same activity.** Any *new* vulnerability discovered against the current fork would be a vulnerability in upstream Monero itself — not a Jero issue.

---

## Task 1 — Fork-divergence report

- **Remotes:** `origin → github.com/BDR-Pro/Jero`, `upstream → github.com/monero-project/monero`.
- **`origin/master` is a pristine ancestor-equal of `upstream/master`** — `git merge-base --is-ancestor origin/master upstream/master` = true, and the reverse commit counts are both 0. They are the **same commit** `d8c8cc31`.
- **Commits ahead of upstream:** 0. **Commits behind upstream:** 0.
- **Files changed by Jero relative to upstream:** none. This means there are **no** Jero-specific changes to any category:
  - consensus-critical files — none
  - wallet-critical files — none
  - cryptographic code — none
  - transaction-construction code — none
  - daemon/RPC — none
  - mining/reward — none
  - networking — none
- **The old audited snapshot `17891e91` is a clean ancestor of the new HEAD** — the sync was a straight forward fast-forward that pulled in **391 upstream commits**, not a rebase or a rewrite.

**Conclusion:** Jero is a *pure mirror* of upstream Monero at `d8c8cc31`. There is no divergence to report.

## Task 2 — Is Jero up to date?

1. **Based on which upstream commit/version?** Exactly `d8c8cc31`, the current `monero-project/master` tip (version string `0.18.1.0`, which Monero keeps pinned on `master` between tagged releases — not a staleness signal).
2. **Upstream commits missing:** **0.**
3–8. **Security / consensus / wallet / RingCT-CLSAG-BP+ / tx-construction / RPC-network commits missing:** **none in any category** — the fork is at the upstream tip.
9. **Bug-fix commits missing:** none.
10. **Missing commits that could cause fund loss / privacy degradation / crashes / consensus divergence / incompatibility:** none — nothing is missing.

## Task 3 — Re-evaluation of the previous six findings

All six are now **fixed in the current fork by the upstream sync** (each fix commit is an ancestor of `d8c8cc31`, verified via `git merge-base --is-ancestor`). "Current code identical to upstream" is trivially **YES** for every row because the fork *is* upstream.

| Finding | In old snapshot? | In current Jero? | Fixed by our patch? | Fixed by upstream sync? | Upstream fix | Current == upstream | Regression test |
|---|---|---|---|---|---|---|---|
| FIX-01 key-image misalignment | Yes | **No** | Yes (branch, now redundant) | **Yes** | `5f767c6e` | Yes | Present (`cryptonote_format_utils.cpp` unit test) |
| FIX-02 uninit ephemeral key | Yes | **No** | Yes (redundant) | **Yes** | `13d95824` | Yes | Covered by tx-construction path |
| FIX-03 non-monotonic decoy dist | Yes | **No** | Yes (redundant) | **Yes** | `7578af44` | Yes | Covered |
| FIX-04 gamma divide-by-zero | Yes | **No** | Yes (redundant) | **Yes** | `0b796790` | Yes | Present (`output_selection.cpp`) |
| FIX-05 fee-from-weight overflow | Yes | **No** | Yes (redundant) | **Yes** | `e2a4f68e` | Yes | Covered |
| FIX-06 fee-multiplier OOB | Yes | **No** | Yes (redundant) | **Yes** | `493af986` | Yes | Covered |

Spot-checks against current-fork source confirmed the *fixed* code is present (identity-pad in the key-image helper; `CHECK_AND_ASSERT_MES` on ephemeral-key generation; the "Fee calculation overflow" guard). Regression tests for FIX-01 and FIX-04 are present in the current-fork test tree.

## Task 4 — Historical-upstream vs Jero-specific classification

Every finding — the six above **and** the additional bugs the deeper sweep surfaced (e.g. IPv4-mapped-IPv6 peer ban-evasion / peerlist-poisoning `9268681a`, remote P2P stall DoS `e123147...`, and the rest of the memory-safety/parser/crypto-field set) — is:

> **Category A — Historical upstream Monero bug, inherited solely because Jero was behind upstream.**

- **Category B (Jero-specific regression):** none.
- **Category C (Jero-specific architectural vuln):** none.
- **Category D (upstream bug still present in current Monero):** none identified in scope.
- **Category E (config/deployment):** the outdated-fork condition itself — now resolved.
- **Category F (false positive / no longer applicable):** all six prior findings are now F *relative to the current fork* (fixed by sync), while remaining genuine A findings *relative to the old snapshot*.

**Explicit statement:** the vulnerabilities existed **only because the fork was outdated.** None was introduced by Jero.

## Task 5 — Jero-specific delta audit

`git diff d8c8cc31...HEAD-of-origin` = **empty.** There is no Jero-specific delta to audit. None of the sensitive areas the task enumerates (consensus, key images, RingCT, CLSAG, Bulletproof+, output construction, wallet scan/spend, decoy selection, fees, block/mempool validation, reorg, DB state, mining, emission, difficulty, RPC, serialization, P2P, address handling, crypto primitives, hardware-wallet code) contains a single Jero-authored change.

*(The only non-upstream commits that exist anywhere are the three redundant fix commits on the audit branch `claude/critical-money-loss-bugs-6kxr3j`, which are now superseded by the sync — see Task 6.)*

## Task 6 — Synchronization safety

**No synchronization is needed — it is already done.** The fork's `master` is at the upstream tip. Because Jero carried **zero** proprietary commits, the sync could not, and did not, overwrite any intentional Jero modification (there were none) — which is exactly why it was safe. See `UPSTREAM_SYNC_PLAN.md` for the (now largely retrospective) plan and the one remaining action item: the stale audit branch.

## Task 7 — Testing the current fork

- **Test suites available in-tree:** `unit_tests` (79 files), `core_tests`, `functional_tests`, `crypto`, `hash`, `difficulty`, `block_weight`, `fuzz`, `performance_tests`, `libwallet_api_tests`, `net_load_tests`, `trezor`.
- **Local build/run:** **not performed.** This environment lacks Boost, libsodium, and unbound, and all git submodules (randomx, supercop, rapidjson, miniupnp, trezor-common, unbound) are empty. A real build would require network-fetching submodules and installing dependencies.
- **Strongest available assurance (stated honestly, not as "it compiles"):** the current fork is byte-identical to `monero-project/master @ d8c8cc31`, which passes upstream's full CI matrix on every commit before merge; and the finding-specific regression tests are present in the tree. I did **not** independently execute them here. If you want a real local build + test run, say so and I'll set up deps + submodules and run the relevant suites (expect a lengthy build).

## Task 8 — New vulnerabilities in the current fork

Because the current fork == upstream Monero with zero delta, there is **nothing Jero-specific to find.** A new-vulnerability hunt against `d8c8cc31` is, by definition, a 0-day hunt against current upstream Monero — a research-grade effort, not a fork audit. I can run a bounded consensus/RingCT/wallet pass against `d8c8cc31` if you want, but any result would be an *upstream Monero* finding to report to the Monero project, not a Jero issue.

## Task 9 — Security posture: before vs after

"Old snapshot" = `17891e91`. "Current Jero" = `d8c8cc31` = "Current upstream". Status is relative to the current fork.

| Area | Old snapshot (`17891e91`) | Current Jero (`d8c8cc31`) | Current upstream | Status |
|---|---|---|---|---|
| Consensus | Sound (matched upstream) | Sound | Sound | ✅ In sync |
| Wallet | 4 historical bugs (key-image, ephemeral, decoy×2) | Fixed | Fixed | ✅ Fixed by sync |
| RingCT | Sound | Sound | Sound | ✅ In sync |
| CLSAG | Sound | Sound | Sound | ✅ In sync |
| Bulletproof+ | Sound | Sound | Sound | ✅ In sync |
| Transaction construction | Ephemeral-key bug (FIX-02) | Fixed | Fixed | ✅ Fixed by sync |
| Key images | Alignment bug (FIX-01) | Fixed | Fixed | ✅ Fixed by sync |
| Decoy selection | 2 bugs (FIX-03/04) | Fixed | Fixed | ✅ Fixed by sync |
| Fees | 2 bugs (FIX-05/06) | Fixed | Fixed | ✅ Fixed by sync |
| Mempool | Sound | Sound | Sound | ✅ In sync |
| Reorgs | Sound | Sound | Sound | ✅ In sync |
| RPC | Historical Levin/parse hardening pending | Fixed | Fixed | ✅ Fixed by sync |
| P2P | Historical ban-evasion / stall DoS | Fixed | Fixed | ✅ Fixed by sync |
| Mining / rewards | Sound | Sound | Sound | ✅ In sync |
| Serialization | Historical crypto-field/memcpy hardening pending | Fixed | Fixed | ✅ Fixed by sync |
| Hardware wallets | Ephemeral-key path (FIX-02) + Ledger hardening | Fixed | Fixed | ✅ Fixed by sync |

## Task 10 — Conclusion

**Was the previous exposure primarily Jero-specific code, or primarily an unsynchronized fork?**

**It was an unsynchronized fork. Entirely.** Not one of the findings was Jero-specific — the fork contains no Jero-specific code. It was a Monero snapshot frozen 391 commits in the past, so it inherited every upstream bug that had been fixed since. Syncing to `d8c8cc31` resolved all of them with upstream's own, independently-reviewed fixes.

**Action items:**
1. **Keep the fork synced.** The single root cause was lag; a periodic `git merge upstream/master` (or tracking a tagged release) prevents recurrence.
2. **Retire the audit branch.** `claude/critical-money-loss-bugs-6kxr3j` holds three fix commits that are now **redundant** (the same fixes arrived via the sync) and is 391 commits behind. Do **not** merge or PR it. Discard it, or reset it to `origin/master` if you want to keep the name.
3. **Do not re-apply the old patches.** They would only create conflicts against code that is already correct.
