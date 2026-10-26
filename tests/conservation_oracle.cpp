// Conservation-oracle harness for Monero RingCT verification.
//
// Standalone: compiles against the real consensus verifiers (rct::verRctSemanticsSimple,
// rct::verRctNonSemanticsSimple, bulletproof(+) verification, rctSig serialization)
// WITHOUT the rest of the node, and asserts two properties:
//
//   P1 (conservation): a valid tx is generated with known openings; any structured
//      mutation that an attacker could apply (fake output commitments, rebalanced
//      pseudoOuts, fee edits, proof edits, sig edits) must break at least one verifier.
//      A mutation that passes BOTH verifiers is a money-minting candidate.
//
//   P2 (malleability-free): a single random bit flip anywhere in the serialized rctSig
//      (base + prunable) must either fail to parse or fail verification. Parse success
//      + both verifiers passing = finding.
//
// It also replays the exact "pay 100 XMR while holding 10 XMR" attack end to end,
// including the consensus-side V-rebuild step that expand_transaction_1 performs.

#include <cstdio>
#include <cstring>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "misc_log_ex.h"
#include "string_tools.h"

#include "crypto/crypto.h"
#include "crypto/hash.h"

#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"
#include "ringct/bulletproofs.h"
#include "ringct/bulletproofs_plus.h"
#include "serialization/binary_archive.h"
#include "serialization/crypto.h"

#include "device/device.hpp"

static size_t g_checks = 0, g_pass_unexpected = 0, g_parse_ok_verify_ok = 0;

#define CHECK_ORACLE(cond, name)                                              \
  do {                                                                        \
    ++g_checks;                                                               \
    if (!(cond)) {                                                             \
      ++g_pass_unexpected;                                                     \
      std::printf("!! CANDIDATE FINDING (%s): %s line %d\n", name, __FILE__, __LINE__ - 1); \
    }                                                                         \
  } while (0)

static bool verify_full(const rct::rctSig &s)
{
  // Consensus order: semantics (balance + range proofs) first, then non-semantics (ring sigs).
  // A thrown exception (e.g. ge_frombytes_vartime on a non-curve point) is the
  // consensus code rejecting the attacker's bytes, i.e. NOT a finding.
  try
  {
    return rct::verRctSemanticsSimple(s) && rct::verRctNonSemanticsSimple(s);
  }
  catch (...)
  {
    return false;
  }
}

// Consensus-side V rebuild, replicating cryptonote::expand_transaction_1 for the
// bulletproof(+) types: the range proof points are derived from outPk, never trusted.
static bool consensus_rebuild_V(rct::rctSig &s)
{
  // A non-curve point in outPk makes scalarmultKey throw; consensus would
  // treat that as a rejected tx, so surface it as "rebuild failed".
  try
  {
    if (s.type == rct::RCTTypeBulletproofPlus)
    {
      if (s.p.bulletproofs_plus.empty()) return false;
      s.p.bulletproofs_plus[0].V.resize(s.outPk.size());
      for (size_t i = 0; i < s.outPk.size(); ++i)
        s.p.bulletproofs_plus[0].V[i] = rct::scalarmultKey(s.outPk[i].mask, rct::INV_EIGHT);
    }
    else if (s.type == rct::RCTTypeBulletproof || s.type == rct::RCTTypeBulletproof2 || s.type == rct::RCTTypeCLSAG)
    {
      if (s.p.bulletproofs.empty()) return false;
      s.p.bulletproofs[0].V.resize(s.outPk.size());
      for (size_t i = 0; i < s.outPk.size(); ++i)
        s.p.bulletproofs[0].V[i] = rct::scalarmultKey(s.outPk[i].mask, rct::INV_EIGHT);
    }
    return true;
  }
  catch (...)
  {
    return false;
  }
}

struct GeneratedTx
{
  rct::rctSig s;
  rct::ctkeyV in_sk;         // openings of the real inputs
  rct::ctkeyV in_pk;         // public keys of the real inputs
  std::vector<rct::xmr_amount> inamounts;
  std::vector<rct::xmr_amount> outamounts;
  rct::ctkeyV outSk;         // openings of the outputs
  rct::keyV amount_keys;
};

static GeneratedTx generate_valid(rct::RCTConfig config, uint64_t in0, uint64_t in1,
    const std::vector<uint64_t> &outs)
{
  GeneratedTx g;
  const int mixin = 3;
  rct::ctkeyM mixRing(2);
  std::vector<unsigned int> index{1, 1};

  rct::ctkey sk, pk;
  std::tie(sk, pk) = rct::ctskpkGen(in0);
  g.in_sk.push_back(sk);
  g.in_pk.push_back(pk);
  g.inamounts.push_back(in0);

  std::tie(sk, pk) = rct::ctskpkGen(in1);
  g.in_sk.push_back(sk);
  g.in_pk.push_back(pk);
  g.inamounts.push_back(in1);

  for (size_t i = 0; i < 2; ++i)
    for (int j = 0; j <= mixin; ++j)
    {
      if ((int)j == index[i])
        mixRing[i].push_back(g.in_pk[i]); // real key sits exactly at the signed index
      else
        mixRing[i].push_back({rct::scalarmultBase(rct::skGen()), rct::scalarmultBase(rct::skGen())});
    }

  rct::keyV destinations;
  uint64_t total_out = 0;
  for (uint64_t o : outs)
  {
    total_out += o;
    rct::key Sk, Pk;
    rct::skpkGen(Sk, Pk);
    destinations.push_back(Pk);
    g.outamounts.push_back(o);
    g.amount_keys.push_back(rct::hash_to_scalar(rct::zero()));
  }

  const uint64_t fee = in0 + in1 - total_out;
  g.s = rct::genRctSimple(rct::zero(), g.in_sk, destinations, g.inamounts, g.outamounts,
      fee, mixRing, g.amount_keys, index, g.outSk, config, hw::get_device("default"));
  return g;
}

// ---- P1: structured attacker mutations -------------------------------------

// Resolve a named bulletproof(+) point field inside THIS sig copy. Saved pointers
// across rctSig copies are invalid (the proof points live in heap vectors), so
// every mutation re-resolves by name and index.
static rct::key *bp_point_field(rct::rctSig &s, const std::string &name, size_t idx)
{
  if (s.type == rct::RCTTypeBulletproofPlus)
  {
    rct::BulletproofPlus &bp = s.p.bulletproofs_plus[0];
    if (name == "A") return &bp.A;
    if (name == "A1") return &bp.A1;
    if (name == "B") return &bp.B;
    if (name == "L") return idx < bp.L.size() ? &bp.L[idx] : nullptr;
    if (name == "R") return idx < bp.R.size() ? &bp.R[idx] : nullptr;
    if (name == "V") return idx < bp.V.size() ? &bp.V[idx] : nullptr;
  }
  else
  {
    rct::Bulletproof &bp = s.p.bulletproofs[0];
    if (name == "A") return &bp.A;
    if (name == "S") return &bp.S;
    if (name == "T1") return &bp.T1;
    if (name == "T2") return &bp.T2;
    if (name == "L") return idx < bp.L.size() ? &bp.L[idx] : nullptr;
    if (name == "R") return idx < bp.R.size() ? &bp.R[idx] : nullptr;
    if (name == "V") return idx < bp.V.size() ? &bp.V[idx] : nullptr;
  }
  return nullptr;
}

static rct::key *bp_scalar_field(rct::rctSig &s, const std::string &name)
{
  if (s.type == rct::RCTTypeBulletproofPlus)
  {
    rct::BulletproofPlus &bp = s.p.bulletproofs_plus[0];
    if (name == "r1") return &bp.r1;
    if (name == "s1") return &bp.s1;
    if (name == "d1") return &bp.d1;
  }
  else
  {
    rct::Bulletproof &bp = s.p.bulletproofs[0];
    if (name == "taux") return &bp.taux;
    if (name == "mu") return &bp.mu;
    if (name == "a") return &bp.a;
    if (name == "b") return &bp.b;
    if (name == "t") return &bp.t;
  }
  return nullptr;
}

static void battery_structured(rct::RCTConfig config)
{
  const uint64_t XMR = 1000000000000;
  GeneratedTx g = generate_valid(config, 8 * XMR, 3 * XMR, {10 * XMR, 900000000000});

  // sanity gate: the unmolested tx MUST verify, or the generator is broken
  ++g_checks;
  if (!verify_full(g.s))
  {
    std::printf("!! GENERATOR BROKEN: unmolested tx failed verification; aborting battery\n");
    return;
  }

  // 1) "Declare 100 XMR": attacker replaces an output commitment with a commitment
  //    to a much larger amount (using a mask they know), leaving everything else.
  {
    rct::rctSig s = g.s;
    const rct::key big = rct::commit(100 * XMR, g.outSk[0].mask);
    s.outPk[0].mask = big;
    const bool rebuilt = consensus_rebuild_V(s);
    CHECK_ORACLE(!rebuilt || !verify_full(s), "declare_100xmr_output_commitment_swap");
  }

  // 2) "Declare 100 XMR AND rebalance": the attacker also rewrites the pseudoOuts
  //    so the semantics balance equation holds for the inflated output.
  {
    rct::rctSig s = g.s;
    s.outPk[0].mask = rct::commit(100 * XMR, g.outSk[0].mask);
    // rebalance: sum(pseudoOuts) must equal sum(outPk) + H(fee)
    rct::key target = rct::identity();
    for (const auto &o : s.outPk) rct::addKeys(target, target, o.mask);
    rct::key fee_key = rct::scalarmultH(rct::d2h(s.txnFee));
    rct::addKeys(target, target, fee_key);
    // keep all but one pseudoOut; set the last to the remainder minus the others
    rct::key rest = rct::identity();
    for (size_t i = 0; i + 1 < s.p.pseudoOuts.size(); ++i)
      rct::addKeys(rest, rest, s.p.pseudoOuts[i]);
    rct::key last;
    rct::subKeys(last, target, rest);
    s.p.pseudoOuts[s.p.pseudoOuts.size() - 1] = last;
    const bool rebuilt = consensus_rebuild_V(s);
    bool semantics = false, nonsem = false;
    if (rebuilt)
    {
      try { semantics = rct::verRctSemanticsSimple(s); } catch (...) { semantics = false; }
      if (semantics)
      {
        try { nonsem = rct::verRctNonSemanticsSimple(s); } catch (...) { nonsem = false; }
      }
    }
    CHECK_ORACLE(!(semantics && nonsem), "rebalanced_pseudoout_full_bypass");
    // Expected outcome: semantics passes (balance is satisfiable by the attacker),
    // non-semantics FAILS because pseudoOuts are CLSAG-bound to the real input
    // commitments. Passing both = free money.
  }

  // 3) Negative-amount encoding: commitment to (l - 90 XMR) via raw scalars,
  //    plus rebalanced pseudoOuts, original range proof kept. With the consensus
  //    V-rebuild the range proof must fail (amount outside [0, 2^64)).
  {
    rct::rctSig s = g.s;
    rct::key neg_amount;
    static_assert(sizeof(rct::key) == 32, "");
    // scalar = l - 90*XMR
    rct::key xmr_scalar = rct::d2h(90 * XMR);
    sc_sub(neg_amount.bytes, rct::curveOrder().bytes, xmr_scalar.bytes);
    rct::key C;
    rct::addKeys2(C, g.outSk[0].mask, neg_amount, rct::H);
    s.outPk[0].mask = C;
    rct::key target = rct::identity();
    for (const auto &o : s.outPk) rct::addKeys(target, target, o.mask);
    rct::key fee_key = rct::scalarmultH(rct::d2h(s.txnFee));
    rct::addKeys(target, target, fee_key);
    rct::key rest = rct::identity();
    for (size_t i = 0; i + 1 < s.p.pseudoOuts.size(); ++i)
      rct::addKeys(rest, rest, s.p.pseudoOuts[i]);
    rct::key last;
    rct::subKeys(last, target, rest);
    s.p.pseudoOuts[s.p.pseudoOuts.size() - 1] = last;
    const bool rebuilt = consensus_rebuild_V(s);
    CHECK_ORACLE(!rebuilt || !verify_full(s), "negative_amount_mod_l_encoding");
  }

  // 4) Fee theft: raise the declared fee (miner gets more) without touching proofs.
  {
    rct::rctSig s = g.s;
    s.txnFee += 1;
    CHECK_ORACLE(!verify_full(s), "fee_increment");
  }
  {
    rct::rctSig s = g.s;
    s.txnFee -= 1;
    CHECK_ORACLE(!verify_full(s), "fee_decrement");
  }

  // 5) Duplicate output commitment (same commitment paying twice).
  {
    rct::rctSig s = g.s;
    s.outPk[1].mask = s.outPk[0].mask;
    const bool rebuilt = consensus_rebuild_V(s);
    CHECK_ORACLE(!rebuilt || !verify_full(s), "duplicate_output_commitment");
  }

  // 6) Extra hidden output appended (outPk + ecdhInfo) without re-proving.
  {
    rct::rctSig s = g.s;
    rct::ctkey ok;
    ok.mask = rct::scalarmultBase(rct::skGen());
    ok.dest = s.outPk[0].dest;
    s.outPk.push_back(ok);
    rct::ecdhTuple e;
    e.mask = rct::zero();
    e.amount = rct::zero();
    s.ecdhInfo.push_back(e);
    CHECK_ORACLE(!verify_full(s), "extra_output_appended");
  }

  // 7) Every scalar/point of the proof, mutated one field at a time, must break
  //    semantics (with the consensus V-rebuild in place). Field descriptors are
  //    re-resolved inside each fresh copy: the rctSig holds vectors, so raw
  //    pointers taken across a copy are not valid.
  {
    std::vector<std::string> point_names;
    if (g.s.type == rct::RCTTypeBulletproofPlus)
      point_names = {"A", "A1", "B", "L", "R", "V"};
    else
      point_names = {"A", "S", "T1", "T2", "L", "R", "V"};
    for (const std::string &name : point_names)
    {
      size_t count = 1;
      if (name == "L") count = g.s.p.bulletproofs.size() ? g.s.p.bulletproofs[0].L.size() : g.s.p.bulletproofs_plus[0].L.size();
      else if (name == "R") count = g.s.p.bulletproofs.size() ? g.s.p.bulletproofs[0].R.size() : g.s.p.bulletproofs_plus[0].R.size();
      else if (name == "V") count = g.s.outPk.size();
      for (size_t idx = 0; idx < count; ++idx)
      {
        rct::rctSig t = g.s;
        if (!consensus_rebuild_V(t)) continue;
        rct::key *field = bp_point_field(t, name, idx);
        if (!field) continue;
        (*field)[0] ^= 1;
        CHECK_ORACLE(!verify_full(t), "bulletproof_point_mutation");
      }
    }
    std::vector<std::string> scalar_names;
    if (g.s.type == rct::RCTTypeBulletproofPlus)
      scalar_names = {"r1", "s1", "d1"};
    else
      scalar_names = {"taux", "mu", "a", "b", "t"};
    for (const std::string &name : scalar_names)
    {
      rct::rctSig t = g.s;
      if (!consensus_rebuild_V(t)) continue;
      rct::key *field = bp_scalar_field(t, name);
      if (!field) continue;
      (*field)[0] ^= 1;
      CHECK_ORACLE(!verify_full(t), "bulletproof_scalar_mutation");
    }
  }

  // 8) Ring signature fields: CLSAG scalars and images must each be load-bearing.
  {
    rct::rctSig s = g.s;
    for (size_t i = 0; i < s.p.CLSAGs.size(); ++i)
    {
      rct::rctSig t = s;
      rct::clsag &c = t.p.CLSAGs[i];
      c.c1[0] ^= 1;
      CHECK_ORACLE(!verify_full(t), "clsag_c1_mutation");
    }
    for (size_t i = 0; i < s.p.CLSAGs.size(); ++i)
    {
      rct::rctSig t = s;
      rct::clsag &c = t.p.CLSAGs[i];
      c.I[0] ^= 1;
      CHECK_ORACLE(!verify_full(t), "clsag_key_image_mutation");
    }
    for (size_t i = 0; i < s.p.CLSAGs.size(); ++i)
    {
      for (size_t j = 0; j < s.p.CLSAGs[i].s.size(); j += std::max<size_t>(1, s.p.CLSAGs[i].s.size() / 3))
      {
        rct::rctSig t = s;
        t.p.CLSAGs[i].s[j][0] ^= 1;
        CHECK_ORACLE(!verify_full(t), "clsag_s_mutation");
      }
    }
    // key image swap between inputs
    if (s.p.CLSAGs.size() >= 2)
    {
      rct::rctSig t = s;
      std::swap(t.p.CLSAGs[0].I, t.p.CLSAGs[1].I);
      CHECK_ORACLE(!verify_full(t), "clsag_key_image_swap");
    }
  }

  // 9) ecdhInfo is covered by the signature (get_pre_mlsag_hash): mutation must fail.
  {
    rct::rctSig s = g.s;
    s.ecdhInfo[0].amount[0] ^= 1;
    CHECK_ORACLE(!verify_full(s), "ecdhinfo_mutation");
  }

  // 10) mixRing substitution: real ring member's key swapped for another point.
  //     Consensus re-derives the mixring from the chain; a mismatched ring must fail.
  {
    rct::rctSig s = g.s;
    s.mixRing[0][1] = {rct::scalarmultBase(rct::skGen()), rct::scalarmultBase(rct::skGen())};
    CHECK_ORACLE(!verify_full(s), "mixring_member_substitution");
  }
}

// ---- P1b: structural / count-mismatch mutations -----------------------------

static void battery_structural(rct::RCTConfig config)
{
  const uint64_t XMR = 1000000000000;
  GeneratedTx g = generate_valid(config, 4 * XMR, 2 * XMR, {5 * XMR, 800000000000});
  ++g_checks;
  if (!verify_full(g.s))
  {
    std::printf("!! GENERATOR BROKEN: unmolested tx failed verification; aborting battery\n");
    return;
  }

  // a) drop one pseudoOut
  {
    rct::rctSig s = g.s;
    s.p.pseudoOuts.pop_back();
    CHECK_ORACLE(!verify_full(s), "pseudoout_drop");
  }
  // b) duplicate a pseudoOut
  {
    rct::rctSig s = g.s;
    s.p.pseudoOuts.push_back(s.p.pseudoOuts[0]);
    CHECK_ORACLE(!verify_full(s), "pseudoout_duplicate");
  }
  // c) drop the range proof entirely
  {
    rct::rctSig s = g.s;
    if (s.type == rct::RCTTypeBulletproofPlus)
      s.p.bulletproofs_plus.clear();
    else
      s.p.bulletproofs.clear();
    CHECK_ORACLE(!verify_full(s), "proof_drop");
  }
  // d) duplicate the range proof
  {
    rct::rctSig s = g.s;
    if (s.type == rct::RCTTypeBulletproofPlus)
      s.p.bulletproofs_plus.push_back(s.p.bulletproofs_plus[0]);
    else
      s.p.bulletproofs.push_back(s.p.bulletproofs[0]);
    CHECK_ORACLE(!verify_full(s), "proof_duplicate");
  }
  // e) one extra ecdhInfo entry
  {
    rct::rctSig s = g.s;
    rct::ecdhTuple e;
    e.mask = rct::zero();
    e.amount = rct::zero();
    s.ecdhInfo.push_back(e);
    CHECK_ORACLE(!verify_full(s), "ecdhinfo_extra");
  }
  // f) drop a CLSAG
  {
    rct::rctSig s = g.s;
    if (!s.p.CLSAGs.empty())
    {
      s.p.CLSAGs.pop_back();
      CHECK_ORACLE(!verify_full(s), "clsag_drop");
    }
  }
  // g) duplicate a CLSAG
  {
    rct::rctSig s = g.s;
    if (!s.p.CLSAGs.empty())
    {
      s.p.CLSAGs.push_back(s.p.CLSAGs[0]);
      CHECK_ORACLE(!verify_full(s), "clsag_duplicate");
    }
  }
  // h) RCT type confusion: relabel the sig under the other proof family
  {
    rct::rctSig s = g.s;
    s.type = (s.type == rct::RCTTypeBulletproofPlus) ? rct::RCTTypeCLSAG : rct::RCTTypeBulletproofPlus;
    CHECK_ORACLE(!verify_full(s), "type_swap");
  }
  // i) zero fee while proofs untouched (miner gets less; balance breaks)
  {
    rct::rctSig s = g.s;
    s.txnFee = 0;
    CHECK_ORACLE(!verify_full(s), "fee_zeroed");
  }
}

// ---- P1c: honest-resigner minting attempts -----------------------------------
// The strongest attacker: they own every input, know every opening, and can
// re-sign everything from scratch (fresh masks, fresh CLSAGs, fresh range
// proofs). The ONLY lie is the amount a pseudoOut commits to - e.g. declare a
// 100 XMR input while the real input commitment commits 10 XMR. Every such
// honestly-resigned tx must still fail the consensus verifiers; a pass is a
// free-minting bug.
static void battery_resigner(rct::RCTConfig config)
{
  const uint64_t XMR = 1000000000000;
  const int mixin = 3;

  rct::ctkeyV in_sk;
  rct::ctkeyM mixRing(2);
  const std::vector<unsigned int> index{1, 1};

  rct::ctkey sk, pk;
  std::tie(sk, pk) = rct::ctskpkGen(10 * XMR);
  in_sk.push_back(sk);
  mixRing[0].push_back(pk); // placeholder, real key inserted at index 1 below
  std::tie(sk, pk) = rct::ctskpkGen(5 * XMR);
  in_sk.push_back(sk);
  mixRing[1].push_back(pk); // placeholder

  // rebuild rows so the real key sits exactly at the signed index
  for (size_t i = 0; i < 2; ++i)
  {
    rct::ctkey real = mixRing[i][0];
    mixRing[i].clear();
    for (int j = 0; j <= mixin; ++j)
    {
      if ((int)j == index[i])
        mixRing[i].push_back(real);
      else
        mixRing[i].push_back({rct::scalarmultBase(rct::skGen()), rct::scalarmultBase(rct::skGen())});
    }
  }

  rct::key Sk, Pk;
  rct::skpkGen(Sk, Pk);
  rct::keyV destinations{Pk};
  rct::keyV amount_keys{rct::hash_to_scalar(rct::zero())};

  auto resign = [&](const std::vector<uint64_t> &declared_in,
      const std::vector<uint64_t> &outs, uint64_t fee) {
    rct::ctkeyV outSk;
    return rct::genRctSimple(rct::zero(), in_sk, destinations, declared_in, outs,
        fee, mixRing, amount_keys, index, outSk, config, hw::get_device("default"));
  };

  // Control: declaring the TRUE amounts must verify (legitimate re-randomization).
  ++g_checks;
  rct::rctSig honest = resign({10 * XMR, 5 * XMR}, {14 * XMR}, 1 * XMR);
  if (!verify_full(honest))
  {
    std::printf("!! RESIGNER CONTROL BROKEN: honest re-signed tx failed verification\n");
    ++g_pass_unexpected;
    return;
  }

  // Attack 1: declare input 0 as 100 XMR (mints 90 XMR), balanced outputs.
  {
    rct::rctSig s = resign({100 * XMR, 5 * XMR}, {104 * XMR}, 1 * XMR);
    CHECK_ORACLE(!verify_full(s), "inflated_input0_honest_resign");
  }
  // Attack 2: inflate input 1 instead.
  {
    rct::rctSig s = resign({10 * XMR, 50 * XMR}, {59 * XMR}, 1 * XMR);
    CHECK_ORACLE(!verify_full(s), "inflated_input1_honest_resign");
  }
  // Attack 3: inflate both inputs slightly (1 extra XMR total, less conspicuous).
  {
    rct::rctSig s = resign({10 * XMR + 500000000000, 5 * XMR + 500000000000},
        {15 * XMR}, 1 * XMR);
    CHECK_ORACLE(!verify_full(s), "inflated_both_honest_resign");
  }
  // Attack 4: declare the input amount as the max encodable (2^64-1).
  {
    rct::rctSig s = resign({std::numeric_limits<uint64_t>::max(), 5 * XMR},
        {std::numeric_limits<uint64_t>::max() - 5 * XMR}, 1 * XMR);
    CHECK_ORACLE(!verify_full(s), "max_amount_inflated_honest_resign");
  }
}

// ---- P1d: block-level batched semantics verification --------------------------
// Consensus verifies ALL txs of a block with ONE aggregated range-proof check:
// verRctSemanticsSimple(std::vector<const rctSig*>) folds every proof into a
// single weighted multiexp. A cross-proof aggregation bug would let a forged
// proof pass when mixed with honest ones - that is the infinite-money path.
// This battery drives the real batch path directly.
static bool batch_semantics(const std::vector<const rct::rctSig *> &rvv)
{
  try
  {
    return rct::verRctSemanticsSimple(rvv);
  }
  catch (...)
  {
    return false;
  }
}

static void battery_batch(rct::RCTConfig config)
{
  const uint64_t XMR = 1000000000000;

  // Honest txs with DIFFERENT output counts so the batch mixes proof sizes
  // (logM = 0, 1, 2): the Gi/Hi aggregation must span distinct MN correctly.
  std::vector<rct::rctSig> honest;
  {
    GeneratedTx g1 = generate_valid(config, 3 * XMR, 2 * XMR, {4 * XMR, 500000000000});
    honest.push_back(g1.s);
    GeneratedTx g2 = generate_valid(config, 3 * XMR, 2 * XMR, {2 * XMR, 2 * XMR, 500000000000});
    honest.push_back(g2.s);
    GeneratedTx g3 = generate_valid(config, 3 * XMR, 2 * XMR, {1 * XMR, 1 * XMR, 2 * XMR, 500000000000});
    honest.push_back(g3.s);
  }
  for (rct::rctSig &s : honest)
    consensus_rebuild_V(s);

  // Control 1: all-honest batch (mixed sizes) must verify.
  {
    std::vector<const rct::rctSig *> rvv;
    for (const rct::rctSig &s : honest)
      rvv.push_back(&s);
    ++g_checks;
    if (!batch_semantics(rvv))
    {
      std::printf("!! BATCH CONTROL BROKEN: all-honest batch failed\n");
      ++g_pass_unexpected;
      return;
    }
  }

  // Corrupt exactly one member of a mostly-honest batch, in every field family.
  const char *names[] = {"A", "A1", "B", "L", "R", "V", "r1", "s1", "d1"};
  for (const char *nm : names)
  {
    std::vector<rct::rctSig> sigs;
    for (const rct::rctSig &s : honest)
      sigs.push_back(s);

    rct::rctSig &bad = sigs[1]; // corrupt the middle tx's proof
    rct::key *field = bp_point_field(bad, nm, 0);
    if (!field)
      field = bp_scalar_field(bad, nm);
    if (!field)
      continue;
    (*field)[0] ^= 1;

    std::vector<const rct::rctSig *> rvv;
    for (const rct::rctSig &s : sigs)
      rvv.push_back(&s);
    CHECK_ORACLE(!batch_semantics(rvv), "batch_smuggled_corrupt_proof");
  }

  // Empty batch is vacuous truth and never consensus-reachable
  // (ver_mixed_rct_semantics skips the call when the batch is empty);
  // documented, not treated as a finding.
  (void)batch_semantics({});
}

// ---- P2: single-bit malleability oracle over the serialized form ------------

static size_t g_parse_ok = 0;

static void battery_bitflip(rct::RCTConfig config, unsigned seed, size_t trials)
{
  const uint64_t XMR = 1000000000000;
  GeneratedTx g = generate_valid(config, 5 * XMR, 2 * XMR, {6 * XMR, 900000000000});

  const size_t inputs = g.s.mixRing.size();
  const size_t outputs = g.s.outPk.size();
  const size_t mixin = g.s.mixRing[0].size() - 1;

  std::string base_blob, prunable_blob;
  {
    std::stringstream ss;
    binary_archive<true> ar(ss);
    CHECK_AND_ASSERT_MES(g.s.serialize_rctsig_base(ar, inputs, outputs), (void)0, "ser base");
    base_blob = ss.str();
  }
  {
    std::stringstream ss;
    binary_archive<true> ar(ss);
    CHECK_AND_ASSERT_MES(g.s.p.serialize_rctsig_prunable(ar, g.s.type, inputs, outputs, mixin), (void)0, "ser prunable");
    prunable_blob = ss.str();
  }
  const std::string tx_blob = base_blob + prunable_blob;
  const size_t base_len = base_blob.size();

  std::mt19937_64 rng(seed);
  for (size_t n = 0; n < trials; ++n)
  {
    std::string mut = tx_blob;
    const size_t byte = rng() % mut.size();
    const bool is_base = byte < base_len;
    mut[byte] ^= (char)(1u << (rng() % 8));

    rct::rctSig tmp;
    tmp.type = g.s.type;
    try
    {
      binary_archive<false> ar(epee::span<const uint8_t>(
          reinterpret_cast<const uint8_t *>(mut.data()), mut.size()));
      if (tmp.serialize_rctsig_base(ar, inputs, outputs))
      {
        const size_t mixin_ = mixin;
        if (tmp.p.serialize_rctsig_prunable(ar, tmp.type, inputs, outputs, mixin_))
        {
          ++g_parse_ok;
          // restore non-serialized, chain-derived fields
          tmp.mixRing = g.s.mixRing;
          tmp.message = g.s.message;
          if (consensus_rebuild_V(tmp) && verify_full(tmp))
          {
            ++g_parse_ok_verify_ok;
            std::printf("!! CANDIDATE FINDING (bitflip_reverify): %s offset %zu bit %zu\n",
                is_base ? "base" : "prunable", byte, byte * 8);
          }
        }
      }
    }
    catch (...)
    {
      // parse/rebuild rejection: not a finding
    }
    ++g_checks;
  }
}

int main()
{
  // silence easylogging noise
  std::printf("[*] Battery 1: BulletproofPlus (mainnet current, bp_version 4)\n");
  battery_structured({rct::RangeProofPaddedBulletproof, 4});
  std::printf("[*] Battery 2: CLSAG + Bulletproof2 (bp_version 3)\n");
  battery_structured({rct::RangeProofPaddedBulletproof, 3});

  std::printf("[*] Battery 3: honest-resigner minting attempts (owns all keys)\n");
  battery_resigner({rct::RangeProofPaddedBulletproof, 4});
  battery_resigner({rct::RangeProofPaddedBulletproof, 3});

  std::printf("[*] Battery 4: structural count-mismatch mutations\n");
  battery_structural({rct::RangeProofPaddedBulletproof, 4});
  battery_structural({rct::RangeProofPaddedBulletproof, 3});

  std::printf("[*] Battery 5: block-level batched semantics verification\n");
  battery_batch({rct::RangeProofPaddedBulletproof, 4});
  battery_batch({rct::RangeProofPaddedBulletproof, 3});

  std::printf("[*] Battery 6: bitflip malleability oracle (50000 trials per type, 3 seeds)\n");
  for (unsigned seed : {0xC0FFEEu, 0xDEADu, 0xBADF00Du})
  {
    battery_bitflip({rct::RangeProofPaddedBulletproof, 4}, seed, 50000);
    battery_bitflip({rct::RangeProofPaddedBulletproof, 3}, seed ^ 0xBEEF, 50000);
  }

  std::printf("\n=== oracle summary ===\n");
  std::printf("checks run:                %zu\n", g_checks);
  std::printf("bitflip trials that parsed cleanly: %zu\n", g_parse_ok);
  std::printf("unexpected verification passes (candidates): %zu\n", g_pass_unexpected + g_parse_ok_verify_ok);
  if (g_pass_unexpected + g_parse_ok_verify_ok == 0)
    std::printf("RESULT: all conservation invariants held; no candidate findings.\n");
  else
    std::printf("RESULT: CANDIDATES FOUND - triage required.\n");
  return (g_pass_unexpected + g_parse_ok_verify_ok) == 0 ? 0 : 1;
}
