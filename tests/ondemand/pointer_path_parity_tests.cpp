//
// DOM vs On-Demand parity tests for malformed JSON Pointer / JSONPath queries.
//
// Both front-ends expose the same lookup surface for a JSON Pointer
// (dom::element/object/array::at_pointer) and for a JSONPath
// (dom::element/object/array::at_path). A caller may validate a query with one
// front-end and consume it with the other, so the two must classify the same
// malformed query the same way -- same error code, and the same "path
// position" (a query that fails at a given segment must fail at that segment
// whether or not a further suffix is appended).
//
// The tests cover the four malformed-query classes named in the task:
//
//   - illegal escapes       (`~` not followed by 0/1, a dangling `~`)
//   - leading-zero index    (`/a/01`, `$.a[01]`)
//   - oversized index       (`/a/18446744073709551616`, `$.a[...]`)
//   - overlong paths        (tens of thousands of segments)
//
// plus structural garbage (`//`, `$.`, truncated brackets, ...). For each one
// the requirements are:
//
//   1. both front-ends return an error -- never succeed, never crash, never
//      read out of bounds -- and the same error code and path position;
//   2. legal escapes, array indices and object paths return the same value
//      from both front-ends.
//
// When a query diverges, `check_query_with_minimization()` keeps the smallest
// failing query (and writes it under $SIMDJSON_POINTER_PATH_FINDINGS if that
// names a directory), so a regression is a replayable artifact rather than a
// transient fuzz hit.
//
// Documented divergences that are deliberately not asserted equal are pinned in
// documented_divergences() so a change to them is a conscious decision.
//
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "simdjson.h"
#include "test_macros.h"
#include "test_main.h"

// The observe/compare engine, shared with fuzz/fuzz_atpointer_parity.cpp so a
// fuzzer finding replays here and a regression case replays there.
#include "../../fuzz/pointer_path_parity.h"

#if !defined(_WIN32)
#include <sys/mman.h>
#include <unistd.h>
#endif

using namespace simdjson;

namespace pointer_path_parity_tests {

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

// Render a JSON document as canonical JSON, via the shared engine, so a value
// fetched through DOM can be compared with a value fetched through On-Demand.
using pointer_path_parity::canonical_json;

std::string escaped(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\\': out += "\\\\"; break;
      default:
        if (c >= 0x20 && c < 0x7f) {
          out += char(c);
        } else {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\x%02x", c);
          out += buf;
        }
    }
  }
  return out;
}

std::string truncated(std::string_view s, size_t limit = 80) {
  if (s.size() <= limit) { return escaped(s); }
  return escaped(s.substr(0, limit)) + "...<" + std::to_string(s.size()) + " bytes>";
}

// ---------------------------------------------------------------------------
// Guarded query buffer.
//
// On POSIX, copy `query` so its last byte is immediately followed by an
// inaccessible page. A lookup that reads query[size()] -- a missing bounds
// check on a dangling '~' or a truncated bracket, say -- faults, which makes
// the test fail loudly instead of silently reading the adjacent heap byte.
// On other platforms we use a plain std::string_view: still correct, just
// without the out-of-bounds tripwire.
// --------------------------------------------------------------------------
#if !defined(_WIN32)
class guarded_query {
public:
  explicit guarded_query(std::string query) {
    const long page = sysconf(_SC_PAGESIZE);
    const size_t page_size = size_t(page > 0 ? page : 4096);
    data_pages_ = ((query.size() + page_size - 1) / page_size) * page_size;
    mapped_ = data_pages_ + page_size; // one extra page for the guard
    base_ = static_cast<char *>(mmap(nullptr, mapped_, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (base_ == MAP_FAILED) {
      std::fprintf(stderr, "guarded_query: mmap failed\n");
      std::abort();
    }
    if (mprotect(base_ + data_pages_, page_size, PROT_NONE) != 0) {
      std::fprintf(stderr, "guarded_query: mprotect failed\n");
      std::abort();
    }
    char *begin = base_ + (data_pages_ - query.size());
    if (!query.empty()) { std::memcpy(begin, query.data(), query.size()); }
    view_ = std::string_view(begin, query.size());
  }
  guarded_query(const guarded_query &) = delete;
  guarded_query &operator=(const guarded_query &) = delete;
  ~guarded_query() {
    if (base_ != nullptr) { munmap(base_, mapped_); }
  }
  std::string_view view() const { return view_; }

private:
  char *base_ = nullptr;
  size_t mapped_ = 0;
  size_t data_pages_ = 0;
  std::string_view view_{};
};
#else
class guarded_query {
public:
  explicit guarded_query(std::string query) : query_(std::move(query)) {}
  std::string_view view() const { return query_; }
private:
  std::string query_;
};
#endif

// ---------------------------------------------------------------------------
// Observation of one query through both front-ends.
//
// The observe/compare logic is shared with the differential fuzzer through
// fuzz/pointer_path_parity.h, so a finding from the fuzzer is reproduced
// exactly by these tests and vice versa.
// --------------------------------------------------------------------------

using pointer_path_parity::agrees;
using pointer_path_parity::compare;
using pointer_path_parity::observation;
using pointer_path_parity::observe_dom;
using pointer_path_parity::observe_ondemand;

// ---------------------------------------------------------------------------
// Findings: keep the smallest failing query so it can be replayed.
//
// On divergence we try every shorter prefix of the seed (and, above, every
// shorter query generated by the sweep) and report the shortest that still
// diverges, so the artifact is minimal. If SIMDJSON_POINTER_PATH_FINDINGS
// names a directory, each finding is also written there as a replay file.
// --------------------------------------------------------------------------

struct finding {
  std::string document;
  std::string query;
  bool pointer;
  error_code dom_error;
  error_code ondemand_error;
  std::string dom_value;
  std::string ondemand_value;
};

std::vector<finding> &findings() {
  static std::vector<finding> instance;
  return instance;
}

void record_finding(const finding &f) {
  findings().push_back(f);
  if (const char *dir = std::getenv("SIMDJSON_POINTER_PATH_FINDINGS")) {
    const std::string path = std::string(dir) + "/pointer-path-finding-" +
                             std::to_string(findings().size() - 1) + ".txt";
    std::ofstream out(path, std::ios::binary);
    out << "kind: " << (f.pointer ? "pointer" : "path") << "\n"
        << "query: " << f.query << "\n"
        << "document: " << f.document << "\n"
        << "dom_error: " << f.dom_error << "\n"
        << "ondemand_error: " << f.ondemand_error << "\n";
  }
}

// Find the shortest prefix of `seed` for which `diverges` returns true,
// searching prefixes from shortest to longest and skipping the empty JSONPath
// prefix (DOM and On-Demand deliberately differ there; see
// documented_divergences()). If no prefix diverges, returns the seed itself,
// so a caller that already knows `seed` diverges always gets a minimal query.
template <typename Diverges>
std::string minimize_prefix(std::string_view seed, bool pointer, Diverges diverges) {
  for (size_t len = (pointer ? 0 : 1); len < seed.size(); len++) {
    if (diverges(seed.substr(0, len))) { return std::string(seed.substr(0, len)); }
  }
  return std::string(seed);
}

// Check a query and, on divergence, every shorter prefix of it, recording the
// shortest prefix that still diverges.
bool check_query_with_minimization(const std::string &document,
                                   const std::string &seed, bool pointer) {
  const padded_string json(std::string_view{document});
  observation dom = observe_dom(json, seed, pointer);
  observation ondemand = observe_ondemand(json, seed, pointer);
  if (agrees(dom, ondemand)) { return true; }

  auto diverges = [&](std::string_view query) {
    return !agrees(observe_dom(json, query, pointer),
                   observe_ondemand(json, query, pointer));
  };
  const std::string minimal = minimize_prefix(seed, pointer, diverges);
  dom = observe_dom(json, minimal, pointer);
  ondemand = observe_ondemand(json, minimal, pointer);

  record_finding({document, minimal, pointer, dom.error, ondemand.error,
                  dom.value, ondemand.value});
  std::cerr << "FAIL: " << (pointer ? "pointer" : "path") << " parity divergence\n"
            << "  document: " << truncated(document) << "\n"
            << "  minimal query: " << escaped(minimal) << "\n"
            << "  dom: " << dom.error << " value=[" << escaped(dom.value) << "]\n"
            << "  ondemand: " << ondemand.error << " value=["
            << escaped(ondemand.value) << "]\n";
  return false;
}

// ---------------------------------------------------------------------------
// The fixtures.
// ---------------------------------------------------------------------------

// Deliberately mixes keys that look like array indices ("0", "01"), keys that
// need no escape, keys holding the characters an escape encodes ("a/b",
// "m~n"), and nested containers, so a malformed segment can be placed at the
// start, in the middle, or at the end of a query.
const char *const FIXTURE_JSON =
    R"({)"
    R"("a":[10,20,30],)"
    R"("o":{"x":1,"y":[4,5]},)"
    R"("m~n":2,)"
    R"("a/b":3,)"
    R"("01":4,)"
    R"("":5,)"
    R"("arr":[],)"
    R"("deep":{"a":{"a":{"a":[7]}}},)"
    R"("scalar":10,)"
    R"("str":"s",)"
    R"("nul":null,)"
    R"("bo":true)"
    R"(})";

struct query_case {
  const char *class_name;
  const char *query;
  bool pointer;
  error_code expected;
};

// Malformed queries and the error both front-ends must return for each.
//
// A note on "/a/~": when the token is examined by the *array* index parser
// (the receiver is an array) a non-digit is INCORRECT_TYPE before any escape
// is considered, whereas on an object key the same token is
// INVALID_JSON_POINTER. Both front-ends already agree on which, and both cases
// are recorded so the distinction cannot drift.
const std::vector<query_case> &malformed_cases() {
  static const std::vector<query_case> cases = {
      // --- illegal escapes (pointer form) ---------------------------------
      {"illegal-escape", "/m~2n", true, INVALID_JSON_POINTER}, // '2' is not an escape
      {"illegal-escape", "/~", true, INVALID_JSON_POINTER},    // dangling '~'
      {"illegal-escape", "/~2", true, INVALID_JSON_POINTER},
      {"illegal-escape", "/o/~", true, INVALID_JSON_POINTER},
      {"illegal-escape", "/o/~2", true, INVALID_JSON_POINTER},
      {"illegal-escape", "/o/x~", true, INVALID_JSON_POINTER},
      {"illegal-escape", "/a/~", true, INCORRECT_TYPE},   // array index parser first
      {"illegal-escape", "/a/~2", true, INCORRECT_TYPE},
      {"illegal-escape", "/a/~~", true, INCORRECT_TYPE},
      {"illegal-escape", "/a/0~", true, INCORRECT_TYPE},
      {"illegal-escape", "/deep/a/a/a/~", true, INCORRECT_TYPE},

      // --- leading-zero index (pointer form) ------------------------------
      {"leading-zero-index", "/a/01", true, INVALID_JSON_POINTER},
      {"leading-zero-index", "/a/00", true, INVALID_JSON_POINTER},
      {"leading-zero-index", "/a/000", true, INVALID_JSON_POINTER},
      {"leading-zero-index", "/a/0010", true, INVALID_JSON_POINTER},
      {"leading-zero-index", "/a/010", true, INVALID_JSON_POINTER},
      {"leading-zero-index", "/o/y/01", true, INVALID_JSON_POINTER},
      {"leading-zero-index", "/deep/a/a/a/01", true, INVALID_JSON_POINTER},

      // --- oversized index (pointer form) ---------------------------------
      // Above the array length is INDEX_OUT_OF_BOUNDS; a value that does not
      // fit in size_t must not wrap around to a valid index.
      {"oversized-index", "/a/99", true, INDEX_OUT_OF_BOUNDS},
      {"oversized-index", "/a/18446744073709551615", true, INDEX_OUT_OF_BOUNDS}, // size_t max
      {"oversized-index", "/a/18446744073709551616", true, INDEX_OUT_OF_BOUNDS}, // max + 1
      {"oversized-index", "/a/18446744073709551617", true, INDEX_OUT_OF_BOUNDS},
      {"oversized-index", "/a/999999999999999999999999999999", true, INDEX_OUT_OF_BOUNDS},
      {"oversized-index", "/a/100000000000000000000000000000000000000000", true, INDEX_OUT_OF_BOUNDS},
      {"oversized-index", "/o/y/18446744073709551616", true, INDEX_OUT_OF_BOUNDS},
      {"oversized-index", "/deep/a/a/a/18446744073709551616", true, INDEX_OUT_OF_BOUNDS},

      // --- structural garbage (pointer form) ------------------------------
      {"structural", "//", true, NO_SUCH_FIELD},          // two empty keys; only "" exists
      {"structural", "/o/", true, NO_SUCH_FIELD},         // trailing empty key under "o"
      {"structural", "/a/", true, INVALID_JSON_POINTER},  // empty array index
      {"structural", "/a/-", true, INDEX_OUT_OF_BOUNDS},  // append position is never an element
      {"structural", "/a/0x", true, INCORRECT_TYPE},
      {"structural", "/a/+1", true, INCORRECT_TYPE},
      {"structural", "/a/ 1", true, INCORRECT_TYPE},
      {"structural", "a", true, INVALID_JSON_POINTER},    // no leading slash
      {"structural", "a/0", true, INVALID_JSON_POINTER},

      // --- illegal escapes / malformed conversion (path form) -------------
      // In JSONPath a '~' is an ordinary key character, so "m~n" is a legal
      // key (tested below). Paths whose converted pointer is malformed are the
      // path-form analogue: "$.a.~" builds "/a/" and "~" is a key character,
      // so the failure is a type mismatch or a missing key, not a parse error.
      {"illegal-escape-path", "$.a.~", false, INCORRECT_TYPE},
      {"illegal-escape-path", "$.a[~]", false, INCORRECT_TYPE},
      {"illegal-escape-path", "$.o.y[~]", false, INCORRECT_TYPE},
      {"illegal-escape-path", "$.a[~2]", false, INCORRECT_TYPE},
      {"illegal-escape-path", "$.o.y[~2]", false, INCORRECT_TYPE},
      {"illegal-escape-path", "$.a[0].~", false, NO_SUCH_FIELD},
      {"illegal-escape-path", "$.~", false, NO_SUCH_FIELD},
      {"illegal-escape-path", "$['~']", false, NO_SUCH_FIELD},

      // --- leading-zero index (path form) ---------------------------------
      {"leading-zero-index-path", "$.a[01]", false, INVALID_JSON_POINTER},
      {"leading-zero-index-path", "$.a[00]", false, INVALID_JSON_POINTER},
      {"leading-zero-index-path", "$.a[000]", false, INVALID_JSON_POINTER},
      {"leading-zero-index-path", "$.a[0010]", false, INVALID_JSON_POINTER},
      {"leading-zero-index-path", "$.a[010]", false, INVALID_JSON_POINTER},
      {"leading-zero-index-path", "$.o.y[01]", false, INVALID_JSON_POINTER},
      {"leading-zero-index-path", "$.deep.a.a.a[01]", false, INVALID_JSON_POINTER},

      // --- oversized index (path form) ------------------------------------
      {"oversized-index-path", "$.a[99]", false, INDEX_OUT_OF_BOUNDS},
      {"oversized-index-path", "$.a[18446744073709551615]", false, INDEX_OUT_OF_BOUNDS},
      {"oversized-index-path", "$.a[18446744073709551616]", false, INDEX_OUT_OF_BOUNDS},
      {"oversized-index-path", "$.a[999999999999999999999999]", false, INDEX_OUT_OF_BOUNDS},
      {"oversized-index-path", "$.o.y[18446744073709551616]", false, INDEX_OUT_OF_BOUNDS},
      {"oversized-index-path", "$.deep.a.a.a[18446744073709551616]", false, INDEX_OUT_OF_BOUNDS},

      // --- truncated / structural (path form) -----------------------------
      {"structural-path", "$[", false, INVALID_JSON_POINTER},
      {"structural-path", "$.a[", false, INVALID_JSON_POINTER},
      {"structural-path", "$.a[0", false, INVALID_JSON_POINTER},
      {"structural-path", "$['a'", false, INVALID_JSON_POINTER},
      {"structural-path", "$['a'x]", false, INVALID_JSON_POINTER},
      {"structural-path", "$..a", false, NO_SUCH_FIELD},
      {"structural-path", "$.o..x", false, NO_SUCH_FIELD},
      {"structural-path", "not-a-path", false, INVALID_JSON_POINTER},
  };
  return cases;
}

// Legal queries: both front-ends must return the same value, and it must be
// the expected value. This is the "legal escapes, array indices and object
// paths agree" half of the task.
struct value_case {
  const char *pointer;
  const char *path;
  const char *expected;
};

const std::vector<value_case> &legal_cases() {
  static const std::vector<value_case> cases = {
      // legal escapes: "~1" -> '/', "~0" -> '~'
      {"/m~0n", "$.m~n", "2"},
      {"/a~1b", "$.a/b", "3"},
      {"/a~1b", "$['a/b']", "3"},
      // array indices, and the object keys that merely look like them
      {"/a/0", "$.a[0]", "10"},
      {"/a/2", "$.a[2]", "30"},
      {"/o/y/1", "$.o.y[1]", "5"},
      {"/deep/a/a/a/0", "$.deep.a.a.a[0]", "7"},
      {"/01", "$['01']", "4"},   // "01" is a key, never parsed as an index
      {"/", "$['']", "5"},       // empty key
      // nested object / array / whole-container paths
      {"/o/x", "$.o.x", "1"},
      {"/arr", "$.arr", "[]"},
      {"/a", "$.a", "[10,20,30]"},
      {"/o", "$.o", R"({"x":1,"y":[4,5]})"},
  };
  return cases;
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

// Requirement 1: every malformed query returns the recorded error from both
// front-ends. Since a query that diverges is recorded (minimized) and fails,
// this is also the parity assertion for the fixed corpus.
bool malformed_queries_report_parity() {
  TEST_START();
  const padded_string json(std::string_view{FIXTURE_JSON});
  for (const query_case &c : malformed_cases()) {
    guarded_query query(c.query);
    const std::string_view view = query.view();
    observation dom = observe_dom(json, view, c.pointer);
    observation ondemand = observe_ondemand(json, view, c.pointer);
    std::cout << "  " << c.class_name << " [" << escaped(view) << "] -> dom="
              << dom.error << " od=" << ondemand.error << std::endl;
    ASSERT_ERROR(dom.error, c.expected);
    ASSERT_ERROR(ondemand.error, c.expected);
    ASSERT_EQUAL(dom.error, ondemand.error);
    ASSERT_TRUE(agrees(dom, ondemand));

    // Requirement 1, path position: appending a further segment to a query
    // that already failed at an index or escape must not change the error.
    // The append-position token "-" is exempt: the pointer parser documents
    // that "/a/-/x" consults the element at "-", which is not an element, so
    // the class legitimately changes there (and it is the same on both sides).
    const bool append_position =
        std::string_view(c.query).find("/-") != std::string_view::npos ||
        std::string_view(c.query).find("[-]") != std::string_view::npos;
    if (!append_position) {
      const std::string with_suffix = std::string(c.query) + (c.pointer ? "/zzz" : ".zzz");
      observation dom2 = observe_dom(json, with_suffix, c.pointer);
      observation ondemand2 = observe_ondemand(json, with_suffix, c.pointer);
      ASSERT_EQUAL(dom2.error, c.expected);
      ASSERT_EQUAL(ondemand2.error, c.expected);
    }
  }
  TEST_SUCCEED();
}

// Requirement 2: legal escapes, indices and object paths return the same value
// from both front-ends -- cross-checked both ways round (pointer via DOM vs
// path via On-Demand, and path via DOM vs pointer via On-Demand).
bool legal_queries_agree() {
  TEST_START();
  const padded_string json(std::string_view{FIXTURE_JSON});
  for (const value_case &c : legal_cases()) {
    std::cout << "  [" << escaped(c.pointer) << "] [" << escaped(c.path)
              << "] expected " << c.expected << std::endl;
    const std::string expected(c.expected);

    observation dom_pointer = observe_dom(json, c.pointer, true);
    observation dom_path = observe_dom(json, c.path, false);
    observation od_pointer = observe_ondemand(json, c.pointer, true);
    observation od_path = observe_ondemand(json, c.path, false);

    ASSERT_SUCCESS(dom_pointer.error);
    ASSERT_SUCCESS(dom_path.error);
    ASSERT_SUCCESS(od_pointer.error);
    ASSERT_SUCCESS(od_path.error);
    ASSERT_EQUAL(dom_pointer.value, expected);
    ASSERT_EQUAL(dom_path.value, expected);
    ASSERT_EQUAL(od_pointer.value, expected);
    ASSERT_EQUAL(od_path.value, expected);
  }
  TEST_SUCCEED();
}

// The whole document (empty pointer) is the same element from both front-ends
// when the root is a container.
bool empty_pointer_whole_document() {
  TEST_START();
  const padded_string json(std::string_view{FIXTURE_JSON});
  observation dom = observe_dom(json, "", true);
  observation ondemand = observe_ondemand(json, "", true);
  ASSERT_SUCCESS(dom.error);
  ASSERT_SUCCESS(ondemand.error);
  ASSERT_EQUAL(dom.value, ondemand.value);
  ASSERT_EQUAL(dom.value, canonical_json(FIXTURE_JSON));
  TEST_SUCCEED();
}

// Requirement 1, overlong paths: a path of tens of thousands of segments must
// not crash, recurse without bound, or read out of bounds. It simply runs out
// of document or hits a type boundary; either way the two front-ends agree.
bool overlong_paths() {
  TEST_START();
  for (size_t length : {size_t(1024), size_t(4096), size_t(20000)}) {
    std::string pointer;
    std::string path;
    for (size_t i = 0; i < length; i++) {
      pointer += "/a"; // descends through "a" until it becomes an array
      path += ".a";
    }
    std::cout << "  overlong " << length << " segments (" << pointer.size()
              << " bytes)" << std::endl;
    const padded_string json(std::string_view{FIXTURE_JSON});
    observation dom = observe_dom(json, pointer, true);
    observation ondemand = observe_ondemand(json, pointer, true);
    ASSERT_TRUE(dom.error != SUCCESS);
    ASSERT_TRUE(ondemand.error != SUCCESS);
    ASSERT_TRUE(agrees(dom, ondemand));

    observation dom_path = observe_dom(json, path, false);
    observation ondemand_path = observe_ondemand(json, path, false);
    ASSERT_TRUE(dom_path.error != SUCCESS);
    ASSERT_TRUE(ondemand_path.error != SUCCESS);
    ASSERT_TRUE(agrees(dom_path, ondemand_path));
  }

  // An overlong path that also carries an oversized index at the very end must
  // still be classified (as a missing key), not crash.
  {
    std::string pointer;
    for (size_t i = 0; i < 20000; i++) { pointer += "/a"; }
    pointer += "/18446744073709551616";
    const padded_string json(std::string_view{FIXTURE_JSON});
    observation dom = observe_dom(json, pointer, true);
    observation ondemand = observe_ondemand(json, pointer, true);
    ASSERT_TRUE(dom.error != SUCCESS);
    ASSERT_TRUE(agrees(dom, ondemand));
  }
  TEST_SUCCEED();
}

// Guard-page check: make the out-of-bounds tripwire explicit for the shapes
// most likely to over-read -- a query ending on a dangling escape or a
// truncated bracket, where a bounds check on query[size()] matters.
bool query_buffer_is_not_overread() {
  TEST_START();
  const padded_string json(std::string_view{FIXTURE_JSON});
  struct { const char *query; bool pointer; } cases[] = {
      {"/m~", true}, {"/o/~", true}, {"/a/", true}, {"/a/01", true},
      {"~", true}, {"/~", true}, {"$.a[", false}, {"$['a'", false},
      {"$.a.", false}, {"$.a[01]", false},
  };
  for (const auto &c : cases) {
    guarded_query buffer(c.query);
    observation dom = observe_dom(json, buffer.view(), c.pointer);
    observation ondemand = observe_ondemand(json, buffer.view(), c.pointer);
    std::cout << "  guarded [" << escaped(buffer.view()) << "] -> dom="
              << dom.error << " od=" << ondemand.error << std::endl;
    ASSERT_TRUE(dom.error != UNINITIALIZED);
    ASSERT_TRUE(agrees(dom, ondemand));
  }
  TEST_SUCCEED();
}

// Self-test of the minimizer: it must report the shortest prefix of a seed that
// still diverges, so a real finding is replayable at its minimal size. A
// simulated divergence that first appears at a known short prefix exercises the
// same prefix walk without needing the library to actually disagree.
bool minimizer_reports_shortest_prefix() {
  TEST_START();
  // Divergence appears for every prefix that contains '~' and is shorter than
  // 8 bytes; the shortest such prefix of "au~01..." is "au~" (length 3).
  const std::string seed = "au~01...";
  auto diverges = [](std::string_view query) {
    return query.find('~') != std::string_view::npos && query.size() < 8;
  };
  ASSERT_EQUAL(minimize_prefix(seed, true, diverges), std::string("au~"));
  // For a JSONPath the empty prefix is skipped, so a divergence at "" is not
  // reported as the empty query.
  auto always = [](std::string_view) { return true; };
  ASSERT_EQUAL(minimize_prefix("$.a", false, always), std::string("$"));
  // No divergence -> the seed is returned unchanged.
  auto never = [](std::string_view) { return false; };
  ASSERT_EQUAL(minimize_prefix(seed, true, never), seed);
  TEST_SUCCEED();
}

// The randomized sweep: build queries from the vocabulary of each malformed
// class, check parity on every result, and minimize any divergence. It is
// deterministic (fixed seed) so a failure is reproducible.
bool randomized_malformed_sweep() {
  TEST_START();
  static const char *const pieces[] = {
      "/", ".", "[", "]", "~", "~0", "~1", "~2", "0", "1", "01", "00", "9",
      "-", "+", " ", "x", "a", "o", "y", "deep", "m~n", "a/b", "$", "'", "\"",
      "18446744073709551615", "18446744073709551616",
      "999999999999999999999999999999",
  };
  const size_t piece_count = sizeof(pieces) / sizeof(pieces[0]);
  uint64_t state = 0x9E3779B97F4A7C15ULL; // fixed seed
  auto next = [&state]() -> uint64_t {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
  };
  const std::vector<std::string> documents = {
      FIXTURE_JSON,
      R"({"a":[[1,2],[3]],"o":{"p":[{"q":[8,9]}]},"0":[5],"~":{"~":1}})",
      R"([10,{"a":[1,2]},[3,[4]],"s",null])",
  };
  const size_t iterations = 20000;
  size_t checked = 0;
  for (size_t i = 0; i < iterations; i++) {
    std::string query;
    if (next() % 2) { query += '$'; }
    const size_t segments = size_t(next() % 6);
    for (size_t s = 0; s < segments; s++) {
      query += pieces[next() % piece_count];
    }
    if (query.empty()) { continue; } // documented divergence: see below
    const bool pointer = (next() % 2) == 0;
    const std::string &document = documents[next() % documents.size()];
    if (!check_query_with_minimization(document, query, pointer)) {
      TEST_FAIL("parity divergence on a swept query");
    }
    checked++;
  }
  std::cout << "  swept " << checked << " queries" << std::endl;
  TEST_SUCCEED();
}

// ---------------------------------------------------------------------------
// Wildcard JSONPath entry points.
//
// dom::element::at_path_with_wildcard() and
// ondemand::document::for_each_at_path_with_wildcard() are a second JSONPath
// entry point in each front-end. They do not share the at_path() code path:
// each has its own walker, which splits a path into segments and matches them
// itself. The four malformed-query classes that this file is about -- illegal
// escapes, leading-zero indices, oversized indices, overlong paths -- must at
// least behave identically in the two walkers wherever the walker's own
// grammar treats the query as well-formed enough to look at; where the walkers
// apply different grammar rules of their own, documented_divergences() pins
// that fact rather than silently allowing it to drift.
// --------------------------------------------------------------------------

struct wildcard_result {
  error_code error{UNINITIALIZED};
  size_t matches{0};
};

wildcard_result wildcard_dom(const padded_string &json, std::string_view path) {
  dom::parser parser;
  dom::element root;
  if (parser.parse(json).get(root)) { return {UNINITIALIZED, 0}; }
  auto result = root.at_path_with_wildcard(path);
  error_code error = result.error();
  if (error) { return {error, 0}; }
  std::vector<dom::element> values;
  if (std::move(result).get(values)) { return {INVALID_JSON_POINTER, 0}; }
  return {SUCCESS, values.size()};
}

wildcard_result wildcard_ondemand(const padded_string &json, std::string_view path) {
  ondemand::parser parser;
  ondemand::document doc;
  if (parser.iterate(json).get(doc)) { return {UNINITIALIZED, 0}; }
  size_t matches = 0;
  error_code error = doc.for_each_at_path_with_wildcard(
      path, [&matches](ondemand::value) { matches++; });
  return {error, matches};
}

// Robustness for the wildcard entry points: every malformed query in the four
// named classes returns an error (never succeeds silently, never crashes, never
// over-reads) from both walkers.
bool wildcard_malformed_is_robust() {
  TEST_START();
  const padded_string json(std::string_view{FIXTURE_JSON});
  static const char *const malformed[] = {
      // illegal escapes / non-digit bracket contents
      "$.a.~", "$.a[~]", "$.a[~2]", "$.o.y[~]",
      // leading-zero
      "$.a[01]", "$.a[00]", "$.a[0010]", "$.o.y[01]", "$.deep.a.a.a[01]",
      // oversized
      "$.a[18446744073709551616]", "$.a[999999999999999999999999]",
      "$.o.y[18446744073709551616]", "$.deep.a.a.a[18446744073709551616]",
      // truncated
      "$.a[", "$.a[0", "$['a'", "$['a'x]",
  };
  for (const char *path : malformed) {
    guarded_query buffer(path);
    wildcard_result dom = wildcard_dom(json, buffer.view());
    wildcard_result ondemand = wildcard_ondemand(json, buffer.view());
    std::cout << "  wildcard [" << escaped(buffer.view()) << "] -> dom="
              << dom.error << " od=" << ondemand.error << std::endl;
    ASSERT_TRUE(dom.error != SUCCESS);
    ASSERT_TRUE(ondemand.error != SUCCESS);
    ASSERT_TRUE(dom.error != UNINITIALIZED);
    ASSERT_TRUE(ondemand.error != UNINITIALIZED);
  }
  TEST_SUCCEED();
}

// Parity for the classes where the two walkers already agree, plus legal
// queries. This is the part of the wildcard surface the parity contract
// actually covers today; documented_divergences() records the rest.
bool wildcard_classes_agree() {
  TEST_START();
  const padded_string json(std::string_view{FIXTURE_JSON});
  struct { const char *path; error_code expected; size_t matches; } cases[] = {
      // leading-zero index: a parse error in both walkers
      {"$.a[01]", INVALID_JSON_POINTER, 0},
      {"$.a[00]", INVALID_JSON_POINTER, 0},
      {"$.a[0010]", INVALID_JSON_POINTER, 0},
      {"$.o.y[01]", INVALID_JSON_POINTER, 0},
      {"$.deep.a.a.a[01]", INVALID_JSON_POINTER, 0},
      // oversized index: out of bounds in both walkers
      {"$.a[18446744073709551616]", INDEX_OUT_OF_BOUNDS, 0},
      {"$.a[999999999999999999999999]", INDEX_OUT_OF_BOUNDS, 0},
      {"$.o.y[18446744073709551616]", INDEX_OUT_OF_BOUNDS, 0},
      {"$.deep.a.a.a[18446744073709551616]", INDEX_OUT_OF_BOUNDS, 0},
      // legal escapes, indices and object paths: one match each, same value
      {"$.m~n", SUCCESS, 1},
      {"$['a/b']", SUCCESS, 1},
      {"$.a[0]", SUCCESS, 1},
      {"$.o.y[1]", SUCCESS, 1},
      {"$.o.x", SUCCESS, 1},
      // a wildcard query over a legal array
      {"$.a[*]", SUCCESS, 3},
  };
  for (const auto &c : cases) {
    guarded_query buffer(c.path);
    wildcard_result dom = wildcard_dom(json, buffer.view());
    wildcard_result ondemand = wildcard_ondemand(json, buffer.view());
    std::cout << "  wildcard [" << escaped(c.path) << "] -> dom=" << dom.error
              << "/" << dom.matches << " od=" << ondemand.error << "/"
              << ondemand.matches << std::endl;
    ASSERT_ERROR(dom.error, c.expected);
    ASSERT_ERROR(ondemand.error, c.expected);
    ASSERT_EQUAL(dom.matches, c.matches);
    ASSERT_EQUAL(ondemand.matches, c.matches);
  }
  TEST_SUCCEED();
}

// Overlong paths through the wildcard entry points: both walkers must survive a
// query of tens of thousands of segments without crashing. A path of repeated
// numeric indices ends at a type/missing-key boundary; a path of repeated keys
// does too.
bool wildcard_overlong_paths() {
  TEST_START();
  for (size_t length : {size_t(1024), size_t(4096), size_t(20000)}) {
    std::string numeric = "$";
    for (size_t i = 0; i < length; i++) { numeric += "[0]"; }
    std::cout << "  wildcard overlong " << length << " indices ("
              << numeric.size() << " bytes)" << std::endl;
    const padded_string json(std::string_view{FIXTURE_JSON});
    wildcard_result dom = wildcard_dom(json, numeric);
    wildcard_result ondemand = wildcard_ondemand(json, numeric);
    ASSERT_TRUE(dom.error != UNINITIALIZED);
    ASSERT_TRUE(ondemand.error != UNINITIALIZED);
    ASSERT_EQUAL(dom.error, ondemand.error);
  }
  TEST_SUCCEED();
}

// Documented divergences, pinned so a change is a conscious decision. These
// are not defects: each is documented in the headers.
bool documented_divergences() {
  TEST_START();
  // 1. Empty JSONPath: DOM at_path("") is INVALID_JSON_POINTER; On-Demand
  //    at_path("") returns the document (documented in document.h).
  {
    const padded_string json(std::string_view{FIXTURE_JSON});
    observation dom = observe_dom(json, "", false);
    ASSERT_ERROR(dom.error, INVALID_JSON_POINTER);
    observation ondemand = observe_ondemand(json, "", false);
    ASSERT_SUCCESS(ondemand.error);
    ASSERT_EQUAL(ondemand.value, canonical_json(FIXTURE_JSON));
  }
  // 2. Empty JSON Pointer on a scalar root: DOM returns the scalar; On-Demand
  //    reports SCALAR_DOCUMENT_AS_VALUE, because a scalar document cannot be
  //    represented as a value. This is inherent to the On-Demand model.
  {
    const padded_string scalar(std::string_view{"42"});
    observation dom = observe_dom(scalar, "", true);
    ASSERT_SUCCESS(dom.error);
    ASSERT_EQUAL(dom.value, std::string("42"));
    observation ondemand = observe_ondemand(scalar, "", true);
    ASSERT_ERROR(ondemand.error, SCALAR_DOCUMENT_AS_VALUE);
  }
  // 3. The wildcard walkers apply their own segment grammar, independent of
  //    at_path(). Where a query reaches a scalar (or an array with a
  //    non-numeric bracket), DOM's at_path_with_wildcard() classifies it as a
  //    matching failure (INCORRECT_TYPE) while On-Demand's
  //    for_each_at_path_with_wildcard() reports INVALID_JSON_POINTER, and for
  //    an empty segment ("$.") DOM yields the whole object while On-Demand
  //    reports INVALID_JSON_POINTER. These are parser differences in the
  //    wildcard grammar, not in the at_pointer/at_path contract this file
  //    guarantees; they are pinned here so the difference stays intentional.
  {
    const padded_string json(std::string_view{FIXTURE_JSON});
    struct { const char *path; error_code dom_error; error_code od_error; } cases[] = {
        {"$.a[~]", INCORRECT_TYPE, INVALID_JSON_POINTER},
        {"$.a.~", INCORRECT_TYPE, INVALID_JSON_POINTER},
        {"$.a[-]", INDEX_OUT_OF_BOUNDS, INVALID_JSON_POINTER},
        {"$.", SUCCESS, INVALID_JSON_POINTER},
        {"$[]", SUCCESS, INVALID_JSON_POINTER},
    };
    for (const auto &c : cases) {
      wildcard_result dom = wildcard_dom(json, c.path);
      wildcard_result ondemand = wildcard_ondemand(json, c.path);
      std::cout << "  documented wildcard divergence [" << escaped(c.path)
                << "] dom=" << dom.error << " od=" << ondemand.error
                << std::endl;
      ASSERT_ERROR(dom.error, c.dom_error);
      ASSERT_ERROR(ondemand.error, c.od_error);
    }
  }
  TEST_SUCCEED();
}

// A scalar reached inside the document is a receiver like any other: DOM and
// On-Demand must return NO_SUCH_FIELD for a well-formed pointer/path into it.
// (Before the fix, On-Demand value::at_path() returned INVALID_JSON_POINTER
// here while at_pointer() and DOM both returned NO_SUCH_FIELD.)
bool scalar_receiver_parity() {
  TEST_START();
  const padded_string json(std::string_view{FIXTURE_JSON});
  struct { const char *receiver; const char *pointer; const char *path; } cases[] = {
      {"/scalar", "/x", "$.x"},
      {"/str", "/x", "$['x']"},
      {"/nul", "/x", "$.x"},
      {"/bo", "/x", "$.x"},
  };
  for (const auto &c : cases) {
    std::cout << "  scalar receiver " << c.receiver << std::endl;
    dom::parser parser;
    dom::element root;
    ASSERT_SUCCESS(parser.parse(json).get(root));
    dom::element receiver;
    ASSERT_SUCCESS(root.at_pointer(c.receiver).get(receiver));
    dom::element leaf;
    ASSERT_ERROR(receiver.at_pointer(c.pointer).get(leaf), NO_SUCH_FIELD);
    ASSERT_ERROR(receiver.at_path(c.path).get(leaf), NO_SUCH_FIELD);

    // On-Demand consumes on each lookup, so use a fresh document per call.
    ondemand::parser od_pointer_parser;
    ondemand::document od_pointer_doc;
    ASSERT_SUCCESS(od_pointer_parser.iterate(json).get(od_pointer_doc));
    ondemand::value pointer_value;
    ASSERT_SUCCESS(od_pointer_doc.at_pointer(c.receiver).get(pointer_value));
    ASSERT_ERROR(pointer_value.at_pointer(c.pointer).error(), NO_SUCH_FIELD);

    ondemand::parser od_path_parser;
    ondemand::document od_path_doc;
    ASSERT_SUCCESS(od_path_parser.iterate(json).get(od_path_doc));
    ondemand::value path_value;
    ASSERT_SUCCESS(od_path_doc.at_pointer(c.receiver).get(path_value));
    ASSERT_ERROR(path_value.at_path(c.path).error(), NO_SUCH_FIELD);
  }
  TEST_SUCCEED();
}

// The same malformed query must be classified the same whether it is issued on
// the document or on a container inside it (the On-Demand surface has several
// entry points -- document, value, object, array -- and they must not
// disagree with each other).
bool nested_entry_points_agree() {
  TEST_START();
  const padded_string json(std::string_view{FIXTURE_JSON});
  struct { const char *receiver; const char *query; bool pointer; error_code expected; } cases[] = {
      {"/o", "/x/01", true, NO_SUCH_FIELD}, // "x" is a number; further descent fails
      {"/o", "/y/01", true, INVALID_JSON_POINTER},
      {"/o", "/y/18446744073709551616", true, INDEX_OUT_OF_BOUNDS},
      {"/a", "/01", true, INVALID_JSON_POINTER},
      {"/a", "/18446744073709551616", true, INDEX_OUT_OF_BOUNDS},
      {"/deep/a", "/a/18446744073709551616", true, NO_SUCH_FIELD}, // "a" is an object, not the array
      {"/o", "$.y[01]", false, INVALID_JSON_POINTER},
      {"/o", "$.y[18446744073709551616]", false, INDEX_OUT_OF_BOUNDS},
      {"/a", "$.x", false, INCORRECT_TYPE},
  };
  for (const auto &c : cases) {
    std::cout << "  nested " << c.receiver << " [" << escaped(c.query) << "]"
              << std::endl;
    dom::parser parser;
    dom::element root;
    ASSERT_SUCCESS(parser.parse(json).get(root));
    dom::element receiver;
    ASSERT_SUCCESS(root.at_pointer(c.receiver).get(receiver));
    dom::element leaf;
    ASSERT_ERROR(c.pointer ? receiver.at_pointer(c.query).get(leaf)
                           : receiver.at_path(c.query).get(leaf),
                 c.expected);

    ondemand::parser od_parser;
    ondemand::document doc;
    ASSERT_SUCCESS(od_parser.iterate(json).get(doc));
    ondemand::value value;
    ASSERT_SUCCESS(doc.at_pointer(c.receiver).get(value));
    ASSERT_ERROR(c.pointer ? value.at_pointer(c.query).error()
                           : value.at_path(c.query).error(),
                 c.expected);
  }
  TEST_SUCCEED();
}

// The findings the sweep recorded, replayed as permanent regression cases.
// When nothing diverges the list is empty; when a divergence is fixed, moving
// its minimized query into malformed_cases() keeps it covered here for good.
bool replay_findings() {
  TEST_START();
  for (const finding &f : findings()) {
    const padded_string json(std::string_view{f.document});
    observation dom = observe_dom(json, f.query, f.pointer);
    observation ondemand = observe_ondemand(json, f.query, f.pointer);
    std::cerr << "replaying " << (f.pointer ? "pointer" : "path") << " ["
              << escaped(f.query) << "] dom=" << dom.error << " od="
              << ondemand.error << std::endl;
    ASSERT_TRUE(agrees(dom, ondemand));
  }
  TEST_SUCCEED();
}

bool run() {
  return
      malformed_queries_report_parity() &&
      legal_queries_agree() &&
      empty_pointer_whole_document() &&
      overlong_paths() &&
      query_buffer_is_not_overread() &&
      scalar_receiver_parity() &&
      nested_entry_points_agree() &&
      documented_divergences() &&
      wildcard_malformed_is_robust() &&
      wildcard_classes_agree() &&
      wildcard_overlong_paths() &&
      minimizer_reports_shortest_prefix() &&
      randomized_malformed_sweep() &&
      replay_findings() &&
      true;
}

} // namespace pointer_path_parity_tests

int main(int argc, char *argv[]) {
  return test_main(argc, argv, pointer_path_parity_tests::run);
}
