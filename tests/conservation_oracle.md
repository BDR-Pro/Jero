# RingCT conservation oracle — consensus minting audit

Audit date: 2026-10-25 — tree: `3fd0f88c2` (v0.18.1.0-3fd0f88c2)

## Purpose

A standalone harness that compiles the **real** consensus verifiers
(`rct::verRctSemanticsSimple`, `rct::verRctNonSemanticsSimple`, bulletproof /
bulletproof+ verification, rctSig serialization, CLSAG/MLSAG, cn_fast_hash)
directly from this repository, and throws every money-creation attack it can
express at them. A tx is generated with known openings; any adversarial
manipulation that passes **both** verifiers is a money-minting candidate.

**Result: no minting path found on this tree.** 300,138 adversarial checks,
zero candidates. The one live consensus-rule finding (ring key-offset wrap,
see F-1) is a maturity-rule bypass, not inflation; its inflation-grade
variant is a separately disclosed, already-fixed issue on the FCMP++
integration branch (see below).

## Files

| File | Role |
|---|---|
| `conservation_oracle.cpp` | The oracle: six adversarial batteries (below) |
| `conservation_oracle_probes.cpp` | Reproduction probes: offset wrap, emission-clamp boundary |
| `conservation_oracle_stubs.cpp` | Stubs for non-consensus utilities (PoW slow hash, DNS, threadpool sizing) so the build needs no libunbound |
| `conservation_oracle_build.sh` | Standalone build (no cmake tree, no libsodium-dev needed) |

## Build and run

```sh
tests/conservation_oracle_build.sh          # -> ./build-oracle/
./build-oracle/conservation_oracle          # full battery (~10 min)
./build-oracle/conservation_oracle_probes offsets
./build-oracle/conservation_oracle_probes emission
```

Requirements: g++, libssl-dev, boost headers, libsodium runtime library.
The script shims the handful of sodium headers normally shipped by
libsodium-dev and reproduces the cmake-generated `crypto/wallet/ops.h`
so the internal wallet crypto is used.

The harness models consensus exactly: `consensus_rebuild_V()` replicates
`cryptonote::expand_transaction_1` (V is always re-derived from outPk with
`scalarmultKey(mask, INV_EIGHT)`, never trusted from the wire), exceptions
from `ge_frombytes_vartime` on non-curve points count as rejection, and
verification runs in consensus order (semantics first, then non-semantics).

## Batteries and results

Run on both mainnet proof families: BulletproofPlus (bp_version 4) and
CLSAG + Bulletproof2 (bp_version 3).

| # | Battery | Attack model | Result |
|---|---|---|---|
| 1-2 | structured mutations | output-commitment inflation ("pay 100 XMR while holding 10"), pseudoOut rebalancing, negative amounts encoded mod l, fee edits, duplicate/extra outputs, per-field bulletproof point/scalar flips, every CLSAG component (c1, I, s, image swap), ecdhInfo, mixRing substitution | all rejected, both families |
| 3 | honest-resigner minting | attacker **owns every key**, re-signs everything from scratch (fresh masks, CLSAGs, range proofs) and only lies about the amount a pseudoOut commits to (10→100 XMR, both inputs, tiny inflation, max-uint64) | all rejected — the CLSAG commitment binding forces pseudoOut = C_in + z·G (pure G-shift), so no H-component (amount) inflation is forgeable; honest re-signed control tx verifies (no false positive) |
| 4 | structural count mismatches | dropped/duplicated pseudoOuts, dropped/duplicated range proofs, extra ecdhInfo, dropped/duplicated CLSAGs, RCT-type swaps, zeroed fee | all rejected by the explicit size cross-checks in `verRctSemanticsSimple` (`rctSigs.cpp`) |
| 5 | block-level batched semantics | drives the real **cross-tx batch** path `verRctSemanticsSimple(std::vector<const rctSig*>)` used by block validation (`ver_mixed_rct_semantics`) with mixed proof sizes (logM 0/1/2); every corrupt-proof field smuggled among honest txs | all detected; all-honest mixed-size control passes; the Gi/Hi weighted multiexp aggregation across proofs is sound |
| 6 | malleability oracle | single-bit flips of the fully serialized tx (base + prunable), 50,000 trials × 3 seeds × 2 families | 298,820 / 300,000 flips parse cleanly and **every one** fails at least one verifier; no parse + both-verifiers-pass combination exists |

```
=== oracle summary ===
checks run:                300138
bitflip trials that parsed cleanly: 298820
unexpected verification passes (candidates): 0
RESULT: all conservation invariants held; no candidate findings.
```

## Finding F-1: ring key-offset wrap defeats the spendable-age rule

**Severity on this tree: consensus-rule bypass (10-block maturity), not minting.**

Chain of facts, all in this tree:

1. `txin_to_key::key_offsets` are attacker-controlled **relative** offsets.
   `relative_output_offsets_to_absolute()` (`cryptonote_format_utils.cpp`)
   accumulates them with plain uint64 addition and no monotonicity check —
   the cumulative sum **wraps**.
2. `check_tx_inputs_ring_members_diff()` (`cryptonote_core.cpp`) only rejects
   **zero** relative offsets (hf >= 6); a wrapped ring passes.
3. `Blockchain::scan_outputkeys_for_indexes()` (`blockchain.cpp`) sets
   `pmax_related_block_height` from **the last ring member's height only**,
   on the assumption that ring members are sorted by absolute offset (true
   for honest wallets, enforced nowhere).
4. `Blockchain::check_tx_inputs()` enforces the hf >= 12 ten-block
   spendable-age rule from that single value.

Reproduction (`conservation_oracle_probes offsets`):

```
relative offsets: 99999999, 18446744073609551622
absolute offsets (iteration order): 99999999 5
last member index = 5  (earlier member = 99999999)
monotonic (last >= all earlier)? NO -> pmax_related_block_height uses the OLD member's height
```

An attacker who owns an output created 1–9 blocks ago places it **first** in
the ring iteration order, ends the ring with an ancient output, and the
maturity check never sees the young member's height. The tx is otherwise
fully valid (all wrapped absolute offsets resolve to real outputs; CLSAG
verifies). Impact today: the hf12 min-age rule can be bypassed, re-enabling
chain-spam/reorg-cascade behavior the rule was created to stop. Key images
still bind every output, so this is **not** double-spend/inflation on
mainline.

### The inflation-grade variant (disclosed and fixed upstream)

Monero Research Lab disclosed on 2026-10-08 that on the FCMP++ integration
branch (seraphis-migration/monero) the same wrap lets a **Carrot output be
spent with the old signature type**, giving the same output a **second key
image** — an inflation risk. The earlier gate (PR #446) was incomplete
precisely because of this overflow. The fix, `check_tx_inputs_ring_members_overflow()`
+ a non-decreasing-height defense in `scan_outputkeys_for_indexes`, is
merged in seraphis-migration/monero **PR #499** (2026-10-03) and gated to
`HF_VERSION_FCMP_PLUS_PLUS` (cannot activate earlier without a net split
since wrapped offsets exist in historical blocks). This master tree contains
no `txout_to_carrot_v1` output type, so the inflation form is unreachable
here; mainnet remains clean (see moneroinflation.com).

## Verified-clean inventory (static audit accompanying the oracle)

| Surface | Verdict |
|---|---|
| Coinbase reward (`validate_miner_transaction`, exact-claim hf >= 12, `check_outs_overflow`, decomposed amounts) | clean |
| Emission (`get_block_reward` saturation clamp on `already_generated_coins` at MONEY_SUPPLY — `blockchain.cpp`, post-`validate_miner_transaction` update) | clean; see `conservation_oracle_probes emission` for the boundary the clamp prevents |
| Key images (`l·I == identity` domain check, intra-tx diff, LMDB `MDB_NODUPDATA` double-spend) | clean |
| Verification-ID cache (`H(tx_hash ‖ mix_ring)`, only set post-verification) | clean |
| rct type gating (borromean/bp1 banned by hard fork; `untested_tx` future-guard) | clean |
| Ring construction from DB (`scan_outputkeys_for_indexes` + `m_scan_table`, partial-result fallbacks) | clean except F-1 |
| `expand_transaction_1` V-rebuild (single proof, L >= 6, max_outputs >= vout) | clean |

## Related out-of-tree findings (crash-grade, not minting)

- **masari**: `validate_uncle_reward` indexes `miner_tx.vout[0]` on uncle
  blocks that never passed `validate_miner_transaction` (OOB read /
  bad_variant_throw); the `vout.size()==2`-guarded uncle-reward check at
  `blockchain.cpp:1493` is unreachable-dead due to unconditional checks, so
  it cannot mint.
- **bittube-core**: reward-share `idx = vout.size() - shares.size()` underflow
  on short coinbases (OOB read); `verRct` dead branch for pre-hf8 types.

## Conclusion

No free-minting path exists on this master tree: the CLSAG commitment
binding is unforgeable even for an attacker who owns every key and re-signs
honestly, batched block verification is sound across mixed proof sizes, and
every structural/manipulation/batch/bitflip vector is rejected. The live
finding (F-1) is a spendable-age bypass; its inflation-grade variant is
already fixed on the integration branch before any fork activation.
