/**
 * Differential fuzzer: DOM vs On-Demand numeric range validation.
 *
 * The engine (oracle, locator, both readers, classifier) lives in
 * number_differential.h so the unit tests can reuse it. This file is only the
 * libFuzzer entry point: locate a number in the input, run every getter
 * through both front-ends, and stop on the first finding so the input is
 * reproducible as a corpus file.
 *
 * Without libFuzzer (SIMDJSON_FUZZ_LINKMAIN=On, the default here) the linked
 * main.cpp replays each file named on the command line, which is enough to
 * re-run a saved finding.
 */

#include "number_differential.h"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace number_differential;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Bound the input: the readers and the oracle are O(size); very long numbers
  // (thousands of digits) are covered by the unit tests instead of mutation.
  if (size == 0 || size > (1u << 16)) { return 0; }
  std::string doc(reinterpret_cast<const char *>(data), size);

  Locator locator(doc);
  Location loc = locator.locate();
  const std::string token = locator.token_text(loc);

  static const Getter getters[] = {
      Getter::Int64, Getter::Uint64, Getter::Double,
      Getter::Int32, Getter::Uint32, Getter::Number,
  };
  for (Getter g : getters) {
    Verdict v = check(doc, loc, g);
    if (v.is_finding) {
      std::fprintf(stderr,
                   "=== numeric range differential ===\n"
                   "reason   : %s\n"
                   "getter   : %s\n"
                   "token    : %s\n"
                   "path     : %s (byte %zu)\n"
                   "document : %s\n\n",
                   v.reason, getter_name(g), token.c_str(),
                   loc.description.c_str(), loc.token_offset, doc.c_str());
      std::abort();
    }
  }
  return 0;
}
