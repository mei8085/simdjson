/**
 * Standalone, deterministic driver for the DOM vs On-Demand numeric
 * differential engine in number_differential.h.
 *
 * libFuzzer is not available on every machine that has to run this check
 * (this repository's own tests must run natively, without a sanitizer or a
 * coverage-guided toolchain). This driver supplies a small mutation engine
 * over the structured seed corpus, with a fixed seed by default, so a run is
 * reproducible and can be part of the normal test suite:
 *
 *   number_differential_stress               # default 50000 mutations
 *   number_differential_stress 500000        # more
 *   number_differential_stress 50000 12345   # explicit RNG seed
 *
 * Exit status is 0 when nothing was found, 1 when a finding was printed (with
 * the exact document and the smallest token), so CI fails loudly. A finding is
 * also written as a file in the directory named by $SIMDJSON_DIFF_FINDINGS, if
 * set, for replay:
 *
 *   fuzz_number_differential <saved-file>
 *
 * The mutation operators are chosen to reach the interesting tokens rather
 * than to explore JSON syntax: decimal digits around the 64-bit boundaries,
 * exponent digits, sign flips, and truncation/extension of digit runs.
 */

#include "number_differential.h"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <random>
#include <string>
#include <vector>

using namespace number_differential;

namespace {

// Tokens that are worth mutating around: the whole boundary set from the
// corpus generator, kept here so the driver does not depend on Python.
const char *kSeedTokens[] = {
    "0", "-0", "1", "-1", "127", "128", "-128", "-129",
    "255", "256", "-256", "32767", "32768", "-32768", "-32769",
    "65535", "65536", "-65536", "2147483647", "2147483648",
    "-2147483648", "-2147483649", "4294967295", "4294967296",
    "-4294967296", "9223372036854775807", "9223372036854775808",
    "-9223372036854775808", "-9223372036854775809",
    "18446744073709551615", "18446744073709551616", "18446744073709551617",
    "9999999999999999999", "10000000000000000000",
    "123456789012345678901", "-123456789012345678901234567890",
    "1.0", "-1.5", "0.0", "-0.0", "1e2", "1e-2", "1e0", "1e308",
    "1e309", "-1e309", "1e400", "1e-400", "5e-324",
    "2.2250738585072014e-308", "1.7976931348623157e308",
    "9007199254740992", "9007199254740993", "9007199254740993.0",
    "0.1", "3.4028235e38", "3.4028236e38",
    "0e9999999999999999999999", "1e9999999999999999999999",
    "01", "1.", "1e", "-", "123abc", "1e+", "+1", "1..2",
};

const char *kShapes[] = {
    "%s",                     // root
    "{\"x\":%s}",             // object field
    "{\"pad\":0,\"x\":%s}",   // field after a sibling the readers skip
    "[%s]",                   // array element
    "{\"a\":{\"b\":[%s]}}",   // deep
    "{\"x\":%s,\"x\":2}",     // duplicate key, target first
    "{\"x\":2,\"x\":%s}",     // duplicate key, target second
};

// The exact document the previous run reported, so a failing iteration can be
// printed and saved.
std::string g_last_document;
std::string g_last_token;

bool run_one(const std::string &doc) {
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
      g_last_document = doc;
      g_last_token = token;
      return false;
    }
  }
  return true;
}

// Mutate a numeric token in a way that stays plausibly numeric: change a
// digit (often to 0/9), add or remove a digit, flip a sign, or perturb the
// exponent.
std::string mutate_token(std::mt19937_64 &rng, const std::string &token) {
  std::string t = token;
  if (t.empty()) { t = "0"; }
  const int op = static_cast<int>(rng() % 12);
  switch (op) {
    case 0: { // replace a digit with a boundary digit
      std::vector<size_t> digits;
      for (size_t i = 0; i < t.size(); i++) {
        if (t[i] >= '0' && t[i] <= '9') { digits.push_back(i); }
      }
      if (!digits.empty()) {
        static const char kBoundary[] = {'0', '1', '9'};
        t[digits[rng() % digits.size()]] = kBoundary[rng() % 3];
      }
      break;
    }
    case 1: { // increment the last digit, carrying
      for (size_t i = t.size(); i-- > 0;) {
        if (t[i] >= '0' && t[i] <= '8') { t[i]++; break; }
        if (t[i] == '9') { t[i] = '0'; }
      }
      break;
    }
    case 2: { // insert a digit
      size_t at = rng() % (t.size() + 1);
      t.insert(t.begin() + static_cast<std::ptrdiff_t>(at),
               static_cast<char>('0' + (rng() % 10)));
      break;
    }
    case 3: { // remove a character
      if (t.size() > 1) { t.erase(t.begin() + static_cast<std::ptrdiff_t>(rng() % t.size())); }
      break;
    }
    case 4: { // toggle leading sign
      if (!t.empty() && t[0] == '-') { t.erase(t.begin()); }
      else { t.insert(t.begin(), '-'); }
      break;
    }
    case 5: { // duplicate the digit run (crosses 19/20 digit boundaries)
      std::string digits;
      for (char c : t) { if (c >= '0' && c <= '9') { digits += c; } }
      if (!digits.empty()) { t = digits + digits; if (rng() % 2) { t.insert(t.begin(), '-'); } }
      break;
    }
    case 6: { // append an exponent with a boundary exponent value
      static const char *kExp[] = {"e0", "e1", "e19", "e20", "e308", "e309",
                                   "e-1", "e-308", "e-324", "e-400"};
      t += kExp[rng() % (sizeof(kExp) / sizeof(*kExp))];
      break;
    }
    case 8: { // grow a long digit run (past 19/20 digits, into big-integer land)
      std::string digits;
      for (char c : t) { if (c >= '0' && c <= '9') { digits += c; } }
      if (digits.empty()) { digits = "7"; }
      size_t repeats = 2 + (rng() % 4); // 2x..5x, not unbounded
      std::string grown;
      for (size_t k = 0; k < repeats; k++) { grown += digits; }
      t = grown;
      if (rng() % 2) { t.insert(t.begin(), '-'); }
      break;
    }
    case 9: { // absurd exponent magnitude
      std::string base = t;
      size_t e = base.find_first_of("eE");
      if (e != std::string::npos) { base = base.substr(0, e); }
      size_t zeros = rng() % 24;
      t = base + ((rng() % 2) ? "e" : "e-") + std::string(zeros, '0') +
          std::to_string(rng() % 10);
      break;
    }
    case 10: { // fraction of zeros then a digit
      std::string base = t;
      size_t e = base.find_first_of("eE");
      if (e != std::string::npos) { base = base.substr(0, e); }
      t = base + "." + std::string(rng() % 40, '0') +
          static_cast<char>('1' + (rng() % 9));
      break;
    }
    default: { // append or remove a fraction
      if (t.find('.') == std::string::npos) { t += ".5"; }
      else { t = t.substr(0, t.find('.')); }
      break;
    }
  }
  return t;
}

} // namespace

int main(int argc, char **argv) {
  uint64_t iterations = 50000;
  uint64_t seed = 0xC0FFEEULL;
  if (argc > 1) { iterations = std::strtoull(argv[1], nullptr, 10); }
  if (argc > 2) { seed = std::strtoull(argv[2], nullptr, 10); }

  std::mt19937_64 rng(seed);
  const size_t token_count = sizeof(kSeedTokens) / sizeof(*kSeedTokens);
  const size_t shape_count = sizeof(kShapes) / sizeof(*kShapes);

  for (uint64_t i = 0; i < iterations; i++) {
    std::string token = kSeedTokens[rng() % token_count];
    // Apply one to three mutations so the sweep explores neighbours of the
    // boundary tokens rather than just the boundaries themselves.
    const int mutations = 1 + static_cast<int>(rng() % 3);
    for (int m = 0; m < mutations; m++) { token = mutate_token(rng, token); }

    char buffer[512];
    std::snprintf(buffer, sizeof(buffer), kShapes[rng() % shape_count],
                  token.c_str());
    std::string doc = buffer;

    if (!run_one(doc)) {
      // Persist the exact input so it can be replayed with the libFuzzer
      // entry point, when one is available.
      if (const char *dir = std::getenv("SIMDJSON_DIFF_FINDINGS")) {
        std::string path = std::string(dir) + "/finding-" +
                           std::to_string(seed) + "-" + std::to_string(i);
        std::ofstream out(path, std::ios::binary);
        out.write(doc.data(), static_cast<std::streamsize>(doc.size()));
      }
      return 1;
    }
  }
  std::fprintf(stdout,
               "number_differential_stress: %" PRIu64
               " iterations, seed %" PRIu64 ", no findings\n",
               iterations, seed);
  return 0;
}
