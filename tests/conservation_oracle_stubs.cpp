// Non-consensus utility stubs for the standalone conservation-oracle build.
//
// Only functions outside the RingCT verification path are stubbed:
//  - RandomX PoW slow hash (block/tx validation never invokes it here)
//  - DNS/OpenAlias address resolution (wallet-level, needs libunbound)
//  - max-concurrency detection (threadpool sizing only)
// The consensus verifiers themselves (rct::verRctSemanticsSimple,
// verRctNonSemanticsSimple, bulletproof(+), cn_fast_hash) are the real
// implementations compiled from this repository.

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

#include "common/dns_utils.h"
#include "common/util.h"
#include "crypto/hash-ops.h"

extern "C"
{
void rx_slow_hash_allocate_state(void) {}
void rx_slow_hash_free_state(void) {}
void rx_slow_hash(const char *seedhash, const void *data, size_t length, char *result_hash)
{
  (void)seedhash; (void)data; (void)length; (void)result_hash;
  std::terminate();
}
}

unsigned tools::get_max_concurrency() { return 0; }

std::string tools::dns_utils::get_account_address_as_str_from_url(
    const std::string &url,
    dnssec_status &dnssec,
    std::function<std::string(const std::string &, const std::vector<std::string> &, dnssec_status)> confirm_dns)
{
  (void)url; (void)dnssec; (void)confirm_dns;
  return {};
}
