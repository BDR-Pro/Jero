// Reproduction probes for the consensus minting audit (conservation_oracle.md).
//
// Probe "offsets"  : demonstrates that attacker-controlled relative ring
//    key_offsets wrap the uint64 cumulative sum in
//    cryptonote::relative_output_offsets_to_absolute(), so the LAST ring
//    member can be an OLD output while EARLIER members are YOUNG. Since
//    Blockchain::scan_outputkeys_for_indexes() derives
//    pmax_related_block_height from the last member only, the HF >= 12
//    ten-block spendable-age check (Blockchain::check_tx_inputs) never
//    inspects the young members' heights.
//
// Probe "emission" : shows what get_block_reward() would return for wrapped
//    values of already_generated_coins, and why the saturation clamp in
//    Blockchain::handle_block_to_main_chain (already_generated_coins capped
//    at MONEY_SUPPLY instead of wrapping) is what keeps the emission curve
//    from restarting; verify the clamp holds at the boundary.
//
// Build: see tests/conservation_oracle_build.sh (builds conservation_oracle_probes).

#include <cstdio>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "string_tools.h"

static int probe_offsets()
{
  const uint64_t N = 100000000; // ~100M rct outputs on mainnet
  // ring iteration order: [young output (index N-1), old output (index 5)]
  std::vector<uint64_t> rel{N - 1, (uint64_t)(0 - N + 1) + 4 + 1};
  std::printf("relative offsets: %llu, %llu\n",
      (unsigned long long)rel[0], (unsigned long long)rel[1]);
  const std::vector<uint64_t> abs_off = cryptonote::relative_output_offsets_to_absolute(rel);
  std::printf("absolute offsets (iteration order):");
  for (uint64_t o : abs_off) std::printf(" %llu", (unsigned long long)o);
  std::printf("\nlast member index = %llu  (earlier member = %llu)\n",
      (unsigned long long)abs_off.back(), (unsigned long long)abs_off[0]);
  const bool monotonic = abs_off.back() >= abs_off[0];
  std::printf("monotonic (last >= all earlier)? %s\n",
      monotonic ? "YES" : "NO -> pmax_related_block_height uses the OLD member's height");
  return monotonic ? 1 : 0;
}

static int probe_emission()
{
  const uint64_t C = std::numeric_limits<uint64_t>::max(); // MONEY_SUPPLY
  struct Case { uint64_t already; const char *label; };
  const Case cases[] = {
    { C,                        "at cap" },
    { C - 1,                    "cap-1" },
    { 0,                        "wrapped to 0" },
    { 440421,                   "wrapped small (crossing+1)" },
    { 300000000000ULL,          "0.3 XMR wrapped" },
    { 600000000000ULL,          "0.6 XMR wrapped" },
  };
  for (const Case &c : cases)
  {
    uint64_t reward = 0;
    const bool ok = cryptonote::get_block_reward(300000, 300000, c.already, reward, 7);
    std::printf("already=%-22llu (%s) -> ok=%d reward=%llu atomic (%.6f XMR)\n",
        (unsigned long long)c.already, c.label, (int)ok,
        (unsigned long long)reward, (double)reward / 1e12);
  }
  std::printf("note: wrapped values would yield a ~35,184 XMR/block curve restart;\n"
      "consensus never stores a wrapped value because handle_block_to_main_chain\n"
      "clamps already_generated_coins at MONEY_SUPPLY (blockchain.cpp, update after\n"
      "validate_miner_transaction).\n");
  return 0;
}

int main(int argc, char **argv)
{
  const std::string mode = argc > 1 ? argv[1] : "offsets";
  if (mode == "offsets")
    return probe_offsets();
  if (mode == "emission")
    return probe_emission();
  std::printf("usage: %s [offsets|emission]\n", argv[0]);
  return 1;
}
