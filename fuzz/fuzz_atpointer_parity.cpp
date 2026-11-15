/**
 * Differential fuzzer: DOM vs On-Demand JSON Pointer / JSONPath lookups.
 *
 * The engine (the two observes, the comparison, the documented-divergence
 * classifier) lives in pointer_path_parity.h so the regression tests can reuse
 * it. This file is only the libFuzzer entry point: split the input into a
 * document and a query, look it up through both front-ends, and abort on the
 * first divergence so the input is reproducible as a corpus file.
 *
 * Without libFuzzer (SIMDJSON_FUZZ_LINKMAIN=On, the default here) the linked
 * main.cpp replays each file named on the command line, which is enough to
 * re-run a saved finding:
 *
 *   fuzz_atpointer_parity saved-finding
 *
 * The same document/query pair is used as both a JSON Pointer (at_pointer) and
 * a JSONPath (at_path); the two share the splitting convention with
 * fuzz_atpointer and fuzz_atpath, so corpora are interchangeable.
 */

#include "FuzzUtils.h"
#include "pointer_path_parity.h"
#include "simdjson.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <string_view>

using namespace pointer_path_parity;

namespace {

[[noreturn]] void report(const char *kind, std::string_view document, std::string_view query,
                         const comparison &result) {
  std::fprintf(stderr,
               "=== pointer/path parity differential ===\n"
               "kind     : %s\n"
               "query    : %.*s\n"
               "document : %.*s\n"
               "dom      : %s value=[%.*s]\n"
               "ondemand : %s value=[%.*s]\n\n",
               kind, int(query.size()), query.data(), int(document.size()), document.data(),
               simdjson::error_message(result.dom.error), int(result.dom.value.size()),
               result.dom.value.data(), simdjson::error_message(result.ondemand.error),
               int(result.ondemand.value.size()), result.ondemand.value.data());
  std::abort();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  // Split the input into a query and a document, using the same four byte
  // separator as the other pointer/path fuzzers. Missing the separator gives
  // an empty query, which is a documented divergence for the path form; the
  // comparison classifies that rather than aborting on it.
  FuzzData fd(Data, Size);
  auto strings = fd.splitIntoStrings();
  while (strings.size() < 2) { strings.emplace_back(); }

  const std::string_view document = strings[0];
  const std::string_view query = strings[1];

  // On-Demand needs a padded buffer; build one once and re-iterate it for each
  // lookup (a document is single-pass and consumed by every call).
  const simdjson::padded_string padded{document};

  // Reject documents that do not parse: both front-ends would then report a
  // parse error and there is nothing to compare.
  {
    simdjson::dom::parser parser;
    simdjson::dom::element root;
    if (parser.parse(padded).get(root)) { return 0; }
  }

  const bool scalar_root = document_root_is_scalar(padded);

  for (const bool pointer : {true, false}) {
    const comparison result = compare(padded, query, pointer, scalar_root);
    if (result.divergence) {
      report(pointer ? "pointer" : "path", document, query, result);
    }
  }

  return 0;
}
