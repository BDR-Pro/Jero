# Upstream Sync Plan — Jero ↔ Monero

## Current state (verified)

**The fork is already fully synchronized.** No merge is required.

| | Commit |
|---|---|
| `origin/master` (Jero) | `d8c8cc31` |
| `upstream/master` (monero-project) | `d8c8cc31` |
| Divergence | **0 ahead / 0 behind**, identical tree |

`git diff origin/master upstream/master` is empty. Jero carries no proprietary commits, so there was nothing for the sync to conflict with or overwrite — this is why the forward-sync of 391 commits (`17891e91 → d8c8cc31`) was safe and clean.

This document is therefore **retrospective** (why the sync was safe) plus **one open action item** (the stale audit branch).

---

## 1. Divergence point
- Old snapshot the fork was frozen at: `17891e91` (Merge PR #10512).
- The fork was a **pure ancestor** of upstream — a clean fast-forward, not a rebase. `17891e91` is an ancestor of `d8c8cc31`.

## 2. Upstream range integrated
- `17891e91..d8c8cc31` — **391 commits**, now all present on `origin/master`.

## 3. Jero-specific commits at risk during sync
- **None.** The fork had zero proprietary commits on `master`. There was no intentional Jero modification that a sync could clobber.
- The only non-upstream commits that exist anywhere are on the audit branch `claude/critical-money-loss-bugs-6kxr3j` (three security fixes) — and those are now **redundant**, because the identical fixes came in via upstream during the sync.

## 4. Expected merge conflicts
- **None occurred / none possible** on `master`: fast-forwarding a pure-ancestor fork produces no conflicts.
- Consensus-sensitive conflicts: none. Wallet-sensitive: none. Crypto-sensitive: none. (There was no local code to conflict with.)

## 5. Tests before synchronization
Not applicable — the sync is complete. For future syncs, before merging upstream run: `unit_tests`, `crypto`, `hash`, `difficulty`, and a `core_tests` subset, on the *pre-merge* tree to establish a baseline.

## 6. Tests after synchronization
For the current tree (and future syncs), the relevant suites are: `unit_tests` (incl. the finding-specific regression tests in `cryptonote_format_utils` and `output_selection`), `core_tests` (consensus/reorg), `functional_tests` (daemon/RPC/wallet end-to-end), `crypto`/`hash`, and `fuzz` targets for serialization/parsers.

> Note: not run locally in this environment (Boost/libsodium/unbound absent, submodules empty). The current tree is byte-identical to `monero-project/master`, which passes upstream CI per commit.

## 7. Rollback strategy
- The pre-sync state is recoverable at any time: `git checkout -b pre-sync 17891e91`.
- Because the sync was a fast-forward, rolling `master` back is a single `git reset --hard 17891e91` (not recommended — it re-introduces 391 commits' worth of fixed bugs).

---

## Open action item — retire the stale audit branch

`claude/critical-money-loss-bugs-6kxr3j` is now **391 commits behind `origin/master`** and its three fix commits are **redundant** with the synced upstream fixes. Do **not** open a PR from it.

Recommended:
```
# Option A — discard it entirely (fixes already upstream)
git branch -D claude/critical-money-loss-bugs-6kxr3j
git push origin --delete claude/critical-money-loss-bugs-6kxr3j

# Option B — keep the name, reset to current upstream for future work
git fetch origin
git checkout -B claude/critical-money-loss-bugs-6kxr3j origin/master
```

## Prevent recurrence
The entire security exposure was caused by lag behind upstream. To prevent it:
- Track a **tagged release** (e.g. `v0.18.x`) rather than a frozen `master` commit, and bump on each release; or
- Periodically `git fetch upstream && git merge --ff-only upstream/master` while the fork stays proprietary-change-free.
- If Jero ever *does* add proprietary commits, switch to a rebase-or-merge workflow and re-run this plan for real (conflicts become possible at that point).
