// Regression and boundary tests for DOM vs On-Demand numeric range validation.
//
// These tests pin down the *behaviour* the differential fuzzer
// (fuzz/fuzz_number_differential.cpp, engine in fuzz/number_differential.h)
// relies on, and they run without libFuzzer so they can run on any machine.
//
// Three kinds of test live here:
//
//  1. Oracle tests. fuzz/number_differential.h decides what a token "means"
//     independently of either front-end. If the oracle is wrong, a fuzzer
//     finding is wrong. These tests check it against hand-computed values at
//     the signed/unsigned 64-bit boundaries and for malformed tokens.
//
//  2. Regression tests. Each case records a token, what each path returns, and
//     what that means. They include the documented divergences (the ones the
//     fuzzer must *not* report) and, where a divergence is a real defect, the
//     smallest input that shows it. A regression test that starts failing is
//     either a new bug or a deliberate behaviour change; either way it must be
//     looked at.
//
//  3. Classifier tests. The fuzzer only reports "range escapes". These tests
//     feed the classifier synthetic observation pairs to show that it reports
//     an out-of-range value smuggled through an accepting path, that it does
//     not report documented conversions, and that the legal boundary values
//     pass. Without them a classifier that had become too permissive (and so
//     silent) would look like a clean fuzz run.

#include "simdjson.h"
#include "test_macros.h"

#include "../../fuzz/number_differential.h"

#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

using namespace simdjson;
using namespace number_differential;

namespace number_differential_tests {

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

// Locate the number the harness would read, then check the documented-vs-bug
// classification for one getter.
struct CaseResult {
  bool found{false};
  std::string token{};
  Verdict verdict{};
  CaseResult() = default;
  CaseResult(const CaseResult &o) : found{o.found}, token{o.token}, verdict{o.verdict} {}
  CaseResult &operator=(const CaseResult &o) noexcept {
    found = o.found; token = o.token; verdict = o.verdict; return *this;
  }
  ~CaseResult() = default;
};

static CaseResult run_case(const std::string &doc, Getter g) {
  CaseResult r;
  Locator locator(doc);
  Location loc = locator.locate();
  r.found = loc.found;
  if (!r.found) { return r; }
  r.token = locator.token_text(loc);
  r.verdict = check(doc, loc, g);
  return r;
}

static const char *verdict_kind(const Verdict &v) {
  if (v.is_finding) { return "FINDING"; }
  if (v.documented) { return "DOCUMENTED"; }
  return "AGREE";
}

// Assert that a document is *not* a finding for any getter, and say which
// getters produced a documented difference (so a wholesale change in
// behaviour cannot hide behind "no findings").
static bool expect_no_findings(const std::string &doc, const char *label) {
  static const Getter getters[] = {
      Getter::Int64, Getter::Uint64, Getter::Double,
      Getter::Int32, Getter::Uint32, Getter::Number,
  };
  for (Getter g : getters) {
    CaseResult r = run_case(doc, g);
    if (!r.found) {
      std::cerr << "FAIL: " << label << ": could not locate a number in " << doc
                << std::endl;
      return false;
    }
    if (r.verdict.is_finding) {
      std::cerr << "FAIL: " << label << ": unexpected finding for getter "
                << getter_name(g) << " on token " << r.token << " ("
                << doc << "): " << r.verdict.reason << std::endl;
      return false;
    }
  }
  return true;
}

// Assert that every token in a list is a clean "both paths agree" case, not
// even a documented difference. This is the legal-boundary guard: normal
// parsing must not be mistaken for a vulnerability.
static bool expect_strict_agreement(const std::vector<std::string> &tokens) {
  static const Getter getters[] = {
      Getter::Int64, Getter::Uint64, Getter::Double,
      Getter::Int32, Getter::Uint32, Getter::Number,
  };
  for (const std::string &token : tokens) {
    const std::string doc = "[" + token + "]";
    for (Getter g : getters) {
      CaseResult r = run_case(doc, g);
      if (!r.found) {
        std::cerr << "FAIL: could not locate a number in " << doc << std::endl;
        return false;
      }
      if (r.verdict.is_finding || r.verdict.documented) {
        std::cerr << "FAIL: token " << token << " (getter " << getter_name(g)
                  << ") was classified " << verdict_kind(r.verdict) << ": "
                  << r.verdict.reason << std::endl;
        return false;
      }
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// 1. Oracle.
// ---------------------------------------------------------------------------

bool oracle_signed_boundaries() {
  TEST_START();
  struct Expected {
    const char *token;
    bool valid;
    bool is_integer;
    bool in_int64;
    int64_t value;
  };
  const Expected cases[] = {
      {"0", true, true, true, 0},
#if SIMDJSON_MINUS_ZERO_AS_FLOAT
      // With the flag on, "-0" is a floating-point token in both front-ends.
      {"-0", true, false, false, 0},
#else
      {"-0", true, true, true, 0},
#endif
      {"1", true, true, true, 1},
      {"-1", true, true, true, -1},
      {"9223372036854775807", true, true, true, INT64_MAX},
      {"9223372036854775808", true, true, false, 0},
      {"-9223372036854775808", true, true, true, INT64_MIN},
      {"-9223372036854775809", true, true, false, 0},
      {"18446744073709551615", true, true, false, 0},
      {"18446744073709551616", true, true, false, 0},
  };
  for (const Expected &e : cases) {
    Oracle o = analyze(e.token);
    if (o.valid != e.valid) {
      std::cerr << "FAIL: analyze(" << e.token << ").valid = " << o.valid << std::endl;
      return false;
    }
    if (o.valid && o.syntactically_integer != e.is_integer) {
      std::cerr << "FAIL: analyze(" << e.token << ").syntactically_integer = "
                << o.syntactically_integer << std::endl;
      return false;
    }
    if (o.valid && o.in_int64 != e.in_int64) {
      std::cerr << "FAIL: analyze(" << e.token << ").in_int64 = " << o.in_int64
                << std::endl;
      return false;
    }
    if (o.in_int64 && o.int64_value != e.value) {
      std::cerr << "FAIL: analyze(" << e.token << ").int64_value = "
                << o.int64_value << " (expected " << e.value << ")" << std::endl;
      return false;
    }
  }
  TEST_SUCCEED();
}

bool oracle_unsigned_boundaries() {
  TEST_START();
  struct Expected {
    const char *token;
    bool in_uint64;
    uint64_t value;
  };
  const Expected cases[] = {
      {"0", true, 0},
#if SIMDJSON_MINUS_ZERO_AS_FLOAT
      // With the flag on, "-0" is a floating-point token: no integer getter,
      // including the unsigned one, accepts it.
      {"-0", false, 0},
#else
      {"-0", true, 0}, // negative zero is zero, so the unsigned range holds
#endif
      {"-1", false, 0},
      {"9223372036854775808", true, UINT64_C(9223372036854775808)},
      {"18446744073709551615", true, UINT64_MAX},
      {"18446744073709551616", false, 0},
  };
  for (const Expected &e : cases) {
    Oracle o = analyze(e.token);
    if (o.in_uint64 != e.in_uint64) {
      std::cerr << "FAIL: analyze(" << e.token << ").in_uint64 = " << o.in_uint64
                << std::endl;
      return false;
    }
    if (o.in_uint64 && o.uint64_value != e.value) {
      std::cerr << "FAIL: analyze(" << e.token << ").uint64_value = "
                << o.uint64_value << std::endl;
      return false;
    }
  }
  TEST_SUCCEED();
}

bool oracle_syntax_versus_value() {
  TEST_START();
  // The integer getters key off syntax, not on whether the value happens to
  // be integral. "1.0" and "1e2" are floating-point tokens in both front-ends.
  const char *floating[] = {"1.0", "-1.0", "1e2", "1E2", "1e+2", "1e-2",
                            "0.0", "-0.0", "1.0000000000000001"};
  for (const char *t : floating) {
    Oracle o = analyze(t);
    if (!o.valid) {
      std::cerr << "FAIL: analyze(" << t << ") said invalid" << std::endl;
      return false;
    }
    if (o.syntactically_integer) {
      std::cerr << "FAIL: analyze(" << t << ") claimed integer syntax" << std::endl;
      return false;
    }
  }
  TEST_SUCCEED();
}

bool oracle_rejects_malformed() {
  TEST_START();
  const char *malformed[] = {
      "01", "-01", "1.", ".1", "1e", "1e+", "-", "+1", "--1",
      "1..2", "1e1e1", "0x10", "nan", "inf", "123abc", "0.-1",
  };
  for (const char *t : malformed) {
    Oracle o = analyze(t);
    if (o.valid) {
      std::cerr << "FAIL: analyze(" << t << ") accepted a malformed token"
                << std::endl;
      return false;
    }
  }
  TEST_SUCCEED();
}

bool oracle_double_range() {
  TEST_START();
  // Values that overflow binary64 are not finite; simdjson rejects them.
  Oracle big = analyze("1e309");
  if (!big.valid || big.finite_double) {
    std::cerr << "FAIL: 1e309 should be valid syntax but not a finite double"
              << std::endl;
    return false;
  }
  Oracle small = analyze("1e-400");
  if (!small.valid || !small.finite_double || small.double_value != 0.0) {
    std::cerr << "FAIL: 1e-400 should be a finite zero double" << std::endl;
    return false;
  }
  Oracle maxd = analyze("1.7976931348623157e308");
  if (!maxd.valid || !maxd.finite_double) {
    std::cerr << "FAIL: DBL_MAX token should be finite" << std::endl;
    return false;
  }
  TEST_SUCCEED();
}

// ---------------------------------------------------------------------------
// 2. Regression tests: documented divergences.
//
// These are real differences between the front-ends that the library
// documents. The fuzzer must classify each as DOCUMENTED, not as a finding.
// ---------------------------------------------------------------------------

bool documented_minus_zero_double() {
  TEST_START();
  // doc/basics.md: "By default, the string -0 is parsed as the integer 0 ...
  // If you set the macro SIMDJSON_MINUS_ZERO_AS_FLOAT to 1 ... -0 is mapped
  // to -0.0". Both paths read the token; they simply disagree on the sign of
  // zero when the flag is off in one build and on in another.
  CaseResult r = run_case("[-0]", Getter::Double);
  ASSERT_TRUE(r.found);
#if SIMDJSON_MINUS_ZERO_AS_FLOAT
  // With the flag on, both front-ends produce -0.0 and agree exactly.
  ASSERT_FALSE(r.verdict.is_finding);
  ASSERT_FALSE(r.verdict.documented);
#else
  // With the flag off, DOM yields +0.0 and On-Demand -0.0 (it preserves the
  // sign through get_double()). This is the documented toggle.
  ASSERT_FALSE(r.verdict.is_finding);
  ASSERT_TRUE(r.verdict.documented);
  ASSERT_EQUAL(std::string(r.verdict.detail), std::string("documented-minus-zero"));
#endif
  TEST_SUCCEED();
}

bool documented_big_integer_to_double() {
  TEST_START();
  // doc/dom.md: big integers fail to parse by default (BIGINT_ERROR);
  // doc/basics.md: On-Demand can still produce a double approximation of a big
  // integer via get_double(). The token is outside the 64-bit integer range,
  // so this is neither a range escape nor an integer disagreement.
  const char *tokens[] = {"18446744073709551616", "-9223372036854775809",
                          "123456789012345678901"};
  for (const char *token : tokens) {
    std::string doc = token;
    CaseResult r = run_case(doc, Getter::Double);
    ASSERT_TRUE(r.found);
    ASSERT_FALSE(r.verdict.is_finding);
    ASSERT_TRUE(r.verdict.documented);
    ASSERT_EQUAL(std::string(r.verdict.detail),
                 std::string("documented-big-integer"));
  }
  TEST_SUCCEED();
}

bool documented_type_boundary() {
  TEST_START();
  // The two front-ends document different *errors* at a type boundary even
  // when they agree on the validity verdict. When both reject, they agree that
  // the value is not acceptable, so this is not a security difference and the
  // classifier reports neither a finding nor a documented divergence: only a
  // difference in *validity* is interesting. These cases pin that down.
  {
    // A negative integer is a valid signed integer but not a valid unsigned
    // one. DOM reports NUMBER_OUT_OF_RANGE, On-Demand INCORRECT_TYPE; both
    // reject.
    CaseResult r = run_case("[-1]", Getter::Uint64);
    ASSERT_TRUE(r.found);
    ASSERT_FALSE(r.verdict.is_finding);
    ASSERT_FALSE(r.verdict.documented);
    ASSERT_EQUAL(std::string(verdict_kind(r.verdict)), std::string("AGREE"));
  }
  {
    // 9223372036854775808 is a valid unsigned integer but not a valid signed
    // one. DOM reports NUMBER_OUT_OF_RANGE, On-Demand INCORRECT_TYPE; both
    // reject.
    CaseResult r = run_case("[9223372036854775808]", Getter::Int64);
    ASSERT_TRUE(r.found);
    ASSERT_FALSE(r.verdict.is_finding);
    ASSERT_FALSE(r.verdict.documented);
  }
#if SIMDJSON_MINUS_ZERO_AS_FLOAT
  // With the flag on, "-0" is a floating-point token in both front-ends, so
  // the unsigned getter rejects it identically on both sides.
  {
    CaseResult r = run_case("[-0]", Getter::Uint64);
    ASSERT_TRUE(r.found);
    ASSERT_FALSE(r.verdict.is_finding);
    ASSERT_FALSE(r.verdict.documented);
  }
#else
  // The one asymmetry that *is* reachable in the default build: DOM's
  // get_uint64() of "-0" returns 0 (negative zero is zero, so it fits), while
  // On-Demand's get_uint64() rejects the token because it carries a negative
  // sign. The accepting side's value is in range, so no out-of-range value
  // escapes; the difference is a documented type boundary, not a range escape.
  {
    CaseResult r = run_case("[-0]", Getter::Uint64);
    ASSERT_TRUE(r.found);
    ASSERT_FALSE(r.verdict.is_finding);
    ASSERT_TRUE(r.verdict.documented);
    ASSERT_EQUAL(std::string(r.verdict.detail),
                 std::string("documented-type-boundary"));
  }
#endif
  TEST_SUCCEED();
}

// ---------------------------------------------------------------------------
// 3. Regression tests: legitimate boundaries must pass.
//
// If any of these were reported, ordinary valid JSON would be flagged.
// ---------------------------------------------------------------------------

bool legal_boundaries_agree() {
  TEST_START();
  const std::vector<std::string> tokens = {
      "0", "1", "-1", "42", "-42",
      "127", "128", "-128", "-129",
      "255", "256", "-256",
      "32767", "32768", "-32768", "-32769",
      "65535", "65536", "-65536",
      "2147483647", "2147483648", "-2147483648", "-2147483649",
      "4294967295", "4294967296",
      "9223372036854775807", "-9223372036854775808",
      "18446744073709551615", // fits uint64 exactly
      "9999999999999999999",  // fits uint64, not int64
      "0.0", "1.5", "-1.5", "0.1",
      "1e2", "1e-2", "1e0",
      "1.7976931348623157e308", "4.9406564584124654e-324", "1e-400",
      "9007199254740993", "9007199254740992",
  };
  return expect_strict_agreement(tokens);
}

bool legal_nested_documents_agree() {
  TEST_START();
  const std::vector<std::string> docs = {
      R"({"x":0})",
      R"({"x":18446744073709551615})",
      R"({"x":-9223372036854775808})",
      R"({"x":9223372036854775808})",
      R"({"x":1.5})",
      R"({"x":1e308})",
      R"({"x":1e-400})",
      R"([0,18446744073709551615,-9223372036854775808,1.5])",
      R"({"a":{"b":[{"x":4294967296}]}})",
      R"({"x":7,"x":7})",
      R"({ "x" : 123456789 })",
  };
  for (const std::string &doc : docs) {
    if (!expect_no_findings(doc, "legal nested document")) { return false; }
  }
  TEST_SUCCEED();
}

// DOM's opt-in big-integer mode is the one configuration in which DOM reads an
// out-of-64-bit number instead of failing the whole parse. The documented
// contract is that get_int64()/get_uint64()/get_double() on such an element
// return INCORRECT_TYPE, i.e. no value is handed back. This test asserts that
// contract directly, because it is the check a caller relying on DOM would
// make before consuming the number, and it is the scenario in which an
// out-of-64-bit value could otherwise escape.
bool big_integer_opt_in_hands_back_no_value() {
  TEST_START();
  const char *tokens[] = {
      "18446744073709551616",  // 2^64
      "-9223372036854775809",  // INT64_MIN - 1
      "99999999999999999999",
      "123456789012345678901234567890",
  };
  for (const char *token : tokens) {
    dom::parser parser;
    parser.number_as_string(true);
    dom::element root;
    ASSERT_SUCCESS(parser.parse(padded_string(std::string(token))).get(root));
    // The value is read (not merely parsed) as a distinct BIGINT element.
    ASSERT_EQUAL(root.type(), dom::element_type::BIGINT);
    ASSERT_TRUE(root.is_bigint());
    // Every numeric getter refuses, so no out-of-range value escapes.
    ASSERT_ERROR(root.get_int64(), INCORRECT_TYPE);
    ASSERT_ERROR(root.get_uint64(), INCORRECT_TYPE);
    ASSERT_ERROR(root.get_double(), INCORRECT_TYPE);
    // The digits are still available as text, which is the documented
    // alternative to a numeric read.
    std::string_view digits;
    ASSERT_SUCCESS(root.get_bigint().get(digits));
    ASSERT_EQUAL(digits, std::string_view(token));
  }
  TEST_SUCCEED();
}

// ---------------------------------------------------------------------------
// 4. Regression tests: the two paths actually read the same field.
//
// These read the located token through both front-ends directly (not through
// the classifier) and assert the values are identical, so a harness bug that
// compared a field to itself or to nothing would fail here.
// ---------------------------------------------------------------------------

// The scenario the fuzzer exists for: one front-end *validates* the number's
// range, then the other *consumes* it. If validation says "in range" and
// consumption produces a value outside that range, an attacker gets past the
// check. This test performs that split directly on a range of boundary tokens
// and asserts the consuming value is the one validation approved.
bool validate_then_consume_agrees() {
  TEST_START();
  // The scenario the fuzzer exists for: one front-end validates the number's
  // range, then the other consumes it. If validation says "in range" and
  // consumption produces a value outside that range, an attacker gets past the
  // check. Each case below is a token plus the bounds a caller would apply;
  // both bounds agree with the token, so validation must pass and the
  // consuming front-end must return exactly the value validation approved.
  struct Case {
    const char *doc;
    bool use_int64;     // validator/getter under test
    int64_t lower;      // inclusive, used when use_int64
    int64_t upper;      // inclusive, used when use_int64
    uint64_t unsigned_upper; // inclusive, used when !use_int64
  };
  const Case cases[] = {
      {R"({"x":0})", true, 0, 0, 0},
      {R"({"x":127})", true, 0, 127, 0},
      {R"({"x":-128})", true, -128, 127, 0},
      {R"({"x":32767})", true, INT16_MIN, INT16_MAX, 0},
      {R"({"x":-32768})", true, INT16_MIN, INT16_MAX, 0},
      {R"({"x":2147483647})", true, INT32_MIN, INT32_MAX, 0},
      {R"({"x":-2147483648})", true, INT32_MIN, INT32_MAX, 0},
      {R"({"x":4294967295})", false, 0, 0, UINT32_MAX},
      {R"({"x":9223372036854775807})", true, INT64_MIN, INT64_MAX, 0},
      {R"({"x":18446744073709551615})", false, 0, 0, UINT64_MAX},
  };

  for (const Case &c : cases) {
    // --- Validation path: DOM. ---
    dom::parser parser;
    dom::element root;
    ASSERT_SUCCESS(parser.parse(padded_string(std::string(c.doc))).get(root));
    dom::element field;
    ASSERT_SUCCESS(root["x"].get(field));

    bool accepted = false;
    int64_t accepted_signed = 0;
    uint64_t accepted_unsigned = 0;
    if (c.use_int64) {
      auto r = field.get_int64();
      ASSERT_SUCCESS(r);
      int64_t v = r.value_unsafe();
      if (v >= c.lower && v <= c.upper) {
        accepted = true;
        accepted_signed = v;
      }
    } else {
      auto r = field.get_uint64();
      ASSERT_SUCCESS(r);
      uint64_t v = r.value_unsafe();
      if (v <= c.unsigned_upper) {
        accepted = true;
        accepted_unsigned = v;
      }
    }
    if (!accepted) {
      TEST_FAIL("validation rejected an in-range case: " + std::string(c.doc));
    }

    // --- Consumption path: On-Demand. ---
    ondemand::parser ond_parser;
    padded_string padded{std::string(c.doc)};
    ondemand::document document;
    ASSERT_SUCCESS(ond_parser.iterate(padded).get(document));
    ondemand::value value;
    ASSERT_SUCCESS(document["x"].get(value));
    if (c.use_int64) {
      auto r = value.get_int64();
      ASSERT_SUCCESS(r);
      ASSERT_EQUAL(r.value_unsafe(), accepted_signed);
    } else {
      auto r = value.get_uint64();
      ASSERT_SUCCESS(r);
      ASSERT_EQUAL(r.value_unsafe(), accepted_unsigned);
    }
  }

  // The mirror image: On-Demand validates by classifying the number, DOM
  // consumes it with the getter that classification implies.
  const char *mirror_docs[] = {
      R"({"x":0})", R"({"x":-1})", R"({"x":9223372036854775807})",
      R"({"x":9223372036854775808})", R"({"x":18446744073709551615})",
  };
  for (const char *doc : mirror_docs) {
    ondemand::parser validator;
    padded_string padded{std::string(doc)};
    ondemand::document document;
    ASSERT_SUCCESS(validator.iterate(padded).get(document));
    ondemand::value value;
    ASSERT_SUCCESS(document["x"].get(value));
    auto number = value.get_number();
    ASSERT_SUCCESS(number);
    ondemand::number_type kind = number.value_unsafe().get_number_type();

    dom::parser consumer;
    dom::element root;
    ASSERT_SUCCESS(consumer.parse(padded_string(std::string(doc))).get(root));
    dom::element field;
    ASSERT_SUCCESS(root["x"].get(field));
    switch (kind) {
      case ondemand::number_type::signed_integer: {
        auto r = field.get_int64();
        ASSERT_SUCCESS(r);
        ASSERT_EQUAL(r.value_unsafe(), number.value_unsafe().get_int64());
        break;
      }
      case ondemand::number_type::unsigned_integer: {
        auto r = field.get_uint64();
        ASSERT_SUCCESS(r);
        ASSERT_EQUAL(r.value_unsafe(), number.value_unsafe().get_uint64());
        break;
      }
      default:
        TEST_FAIL("unexpected number kind for a case chosen to be an integer");
    }
  }
  TEST_SUCCEED();
}

bool both_paths_read_the_same_field() {
  TEST_START();
  struct Expected {
    const char *doc;
    Getter getter;
    int64_t signed_value;
    uint64_t unsigned_value;
    double double_value;
  };
  const Expected cases[] = {
      {R"({"x":7})", Getter::Int64, 7, 0, 0},
      {R"({"x":18446744073709551615})", Getter::Uint64, 0, UINT64_MAX, 0},
      {R"({"x":-9223372036854775808})", Getter::Int64, INT64_MIN, 0, 0},
      {R"({"a":{"b":[{"x":4294967296}]}})", Getter::Int64, 4294967296, 0, 0},
  };
  for (const Expected &e : cases) {
    Locator locator(e.doc);
    Location loc = locator.locate();
    ASSERT_TRUE(loc.found);
    Observation dom = observe_dom(e.doc, loc, e.getter);
    Observation ond = observe_ondemand(e.doc, loc, e.getter);
    ASSERT_EQUAL(int(dom.err), int(SUCCESS));
    ASSERT_EQUAL(int(ond.err), int(SUCCESS));
    ASSERT_TRUE(dom.consumed);
    ASSERT_TRUE(ond.consumed);
    switch (e.getter) {
      case Getter::Int64:
        ASSERT_EQUAL(dom.i64, e.signed_value);
        ASSERT_EQUAL(ond.i64, e.signed_value);
        break;
      case Getter::Uint64:
        ASSERT_EQUAL(dom.u64, e.unsigned_value);
        ASSERT_EQUAL(ond.u64, e.unsigned_value);
        break;
      default:
        break;
    }
  }
  TEST_SUCCEED();
}

// The harness must not silently compare a "success" that never read anything.
// A getter that reports SUCCESS without consuming the token is not a read.
bool unread_success_is_not_compared() {
  TEST_START();
  Observation fake;
  fake.reached = true;
  fake.err = SUCCESS;
  fake.consumed = false; // claimed success but never advanced
  fake.tag = Tag::Signed;
  fake.i64 = 12345;

  Observation real;
  real.reached = true;
  real.err = SUCCESS;
  real.consumed = true;
  real.tag = Tag::Signed;
  real.i64 = 0; // different value on purpose

  Oracle o = analyze("0");
  Verdict v = classify(Getter::Int64, fake, real, o);
  ASSERT_FALSE(v.is_finding);

  // A path that never reached the token supplies no verdict either.
  Observation unreached;
  unreached.reached = false;
  unreached.err = BIGINT_ERROR;
  Verdict v2 = classify(Getter::Int64, unreached, real, o);
  ASSERT_FALSE(v2.is_finding);
  TEST_SUCCEED();
}

// ---------------------------------------------------------------------------
// 5. Classifier tests: real defects are reported.
//
// The fuzzer's value comes from catching a path that hands back an
// out-of-range value while calling it acceptable. Feed the classifier such a
// pair directly; it must say FINDING.
// ---------------------------------------------------------------------------

bool out_of_range_value_is_reported() {
  TEST_START();
  // Token 1 denotes 1. A path that returns 18446744073709551615 for get_int64
  // has wrapped or misread: that is the exploit shape.
  Oracle one = analyze("1");
  Observation good;
  good.reached = good.consumed = true;
  good.err = SUCCESS;
  good.tag = Tag::Signed;
  good.i64 = 1;

  Observation wrapped;
  wrapped.reached = wrapped.consumed = true;
  wrapped.err = SUCCESS;
  wrapped.tag = Tag::Signed;
  wrapped.i64 = -1; // wrong signed value for the token

  Verdict v = classify(Getter::Int64, good, wrapped, one);
  ASSERT_TRUE(v.is_finding);
  ASSERT_EQUAL(std::string(v.detail), std::string("wrong-value"));

  // A get_uint64() that returns a value above INT64_MAX for a token that is
  // small is equally wrong. The per-getter observations must match the getter
  // (a signed observation is not a valid get_uint64() result), so build a
  // proper unsigned pair.
  Observation small_unsigned;
  small_unsigned.reached = small_unsigned.consumed = true;
  small_unsigned.err = SUCCESS;
  small_unsigned.tag = Tag::Unsigned;
  small_unsigned.u64 = 1;
  Observation huge;
  huge.reached = huge.consumed = true;
  huge.err = SUCCESS;
  huge.tag = Tag::Unsigned;
  huge.u64 = UINT64_MAX;
  Verdict v2 = classify(Getter::Uint64, small_unsigned, huge, one);
  ASSERT_TRUE(v2.is_finding);
  TEST_SUCCEED();
}

bool range_disagreement_is_reported() {
  TEST_START();
  // One path says a value in range is fine; the other calls it out of range.
  // For token 5 with get_int64 the oracle says in range, so the rejecting
  // path is wrong.
  Oracle five = analyze("5");
  Observation accepting;
  accepting.reached = accepting.consumed = true;
  accepting.err = SUCCESS;
  accepting.tag = Tag::Signed;
  accepting.i64 = 5;

  Observation rejecting;
  rejecting.reached = true;
  rejecting.err = NUMBER_OUT_OF_RANGE;

  Verdict v = classify(Getter::Int64, accepting, rejecting, five);
  ASSERT_TRUE(v.is_finding);
  // The oracle says 5 is in range, so it is the *rejecting* path that is
  // wrong; the classifier names that rather than calling it a neutral
  // disagreement.
  ASSERT_EQUAL(std::string(v.detail), std::string("rejected-in-range"));

#if SIMDJSON_MINUS_ZERO_AS_FLOAT
  // With the flag on, "-0" is a floating-point token and no get_uint64()
  // returns 0 for it, so there is no type boundary to model here.
  TEST_SUCCEED();
#else
  // A documented type boundary: get_uint64() of "-0". The oracle says the
  // value is zero, hence in the unsigned range; one path returns 0 and the
  // other rejects the token on its negative sign with INCORRECT_TYPE. The
  // accepting value is in range, so no value escapes; this is the documented
  // type boundary.
  Oracle minus_zero = analyze("-0");
  Observation returning_zero;
  returning_zero.reached = returning_zero.consumed = true;
  returning_zero.err = SUCCESS;
  returning_zero.tag = Tag::Unsigned;
  returning_zero.u64 = 0;
  Observation rejecting_type;
  rejecting_type.reached = true;
  rejecting_type.err = INCORRECT_TYPE;
  Verdict v2 = classify(Getter::Uint64, rejecting_type, returning_zero, minus_zero);
  ASSERT_FALSE(v2.is_finding);
  ASSERT_TRUE(v2.documented);
  ASSERT_EQUAL(std::string(v2.detail), std::string("documented-type-boundary"));
  TEST_SUCCEED();
#endif
}

bool out_of_range_acceptance_alone_is_reported() {
  TEST_START();
  // Both paths reject, but one of them first *accepts* an out-of-getter-range
  // value. This is the "one path said in range" case even when the other path
  // also refuses: the accepting path's decision is the dangerous one.
  Oracle big = analyze("18446744073709551616"); // beyond uint64
  Observation accepting_beyond;
  accepting_beyond.reached = accepting_beyond.consumed = true;
  accepting_beyond.err = SUCCESS;
  accepting_beyond.tag = Tag::Unsigned;
  // The token is 2^64; a broken reader that truncated would return 0, a
  // reader that saturated would return UINT64_MAX. Either way the value it
  // hands back is not the token's value, which is what makes this a finding.
  accepting_beyond.u64 = UINT64_MAX;

  Observation rejecting;
  rejecting.reached = true;
  rejecting.err = BIGINT_ERROR;

  Verdict v = classify(Getter::Uint64, rejecting, accepting_beyond, big);
  ASSERT_TRUE(v.is_finding);
  ASSERT_EQUAL(std::string(v.detail), std::string("accepted-out-of-range"));
  TEST_SUCCEED();
}

bool validity_disagreement_is_reported() {
  TEST_START();
  // Both paths reject an in-range token, but with different *range* verdicts
  // (NUMBER_OUT_OF_RANGE vs BIGINT_ERROR). The value is in range for this
  // getter according to the oracle, so at least one path's validity call is
  // wrong. Note this is a "both reject" case: the guarded one-accepts/one-
  // rejects branch in classify() does not see it, and the oracle-based check
  // must be the one that fires.
  Oracle five = analyze("5");
  Observation rejected_out_of_range;
  rejected_out_of_range.reached = true;
  rejected_out_of_range.err = NUMBER_OUT_OF_RANGE; // wrong: 5 fits int64
  Observation rejected_bigint;
  rejected_bigint.reached = true;
  rejected_bigint.err = BIGINT_ERROR;               // also wrong, differently

  Verdict v = classify(Getter::Int64, rejected_out_of_range, rejected_bigint, five);
  ASSERT_TRUE(v.is_finding);
  ASSERT_EQUAL(std::string(v.detail), std::string("rejected-in-range"));

  // Conversely, two paths splitting on plain acceptance/rejection of a token
  // that is valid for the getter is a validity disagreement, not something to
  // wave through as "documented".
  Observation accepted;
  accepted.reached = accepted.consumed = true;
  accepted.err = SUCCESS;
  accepted.tag = Tag::Signed;
  accepted.i64 = 5;
  Observation rejected_type;
  rejected_type.reached = true;
  rejected_type.err = INCORRECT_TYPE; // 5 is an integer: this rejection is wrong
  Verdict v2 = classify(Getter::Int64, accepted, rejected_type, five);
  ASSERT_TRUE(v2.is_finding);
  ASSERT_EQUAL(std::string(v2.detail), std::string("validity-disagreement"));
  TEST_SUCCEED();
}

bool get_number_tag_disagreement_is_reported() {
  TEST_START();
  // The two paths classify the same token as a signed and an unsigned
  // integer. That changes what a later narrow read accepts, so it is
  // reported.
  Oracle small = analyze("5");
  Observation signed_obs;
  signed_obs.reached = signed_obs.consumed = true;
  signed_obs.err = SUCCESS;
  signed_obs.tag = Tag::Signed;
  signed_obs.i64 = 5;
  Observation unsigned_obs;
  unsigned_obs.reached = unsigned_obs.consumed = true;
  unsigned_obs.err = SUCCESS;
  unsigned_obs.tag = Tag::Unsigned;
  unsigned_obs.u64 = 5;

  Verdict v = classify(Getter::Number, signed_obs, unsigned_obs, small);
  ASSERT_TRUE(v.is_finding);
  // The oracle classifies "5" as a signed integer, so the path that tagged it
  // unsigned is the one contradicted; the classifier names it.
  ASSERT_EQUAL(std::string(v.detail), std::string("wrong-tag"));
  TEST_SUCCEED();
}

// ---------------------------------------------------------------------------
// 6. Corpus replay: every seed the fuzz corpus generator emits must be clean.
//
// This is the regression half of the "legal boundary samples must pass"
// requirement: it walks the same tokens and shapes the corpus generator uses.
// ---------------------------------------------------------------------------

bool corpus_shapes_are_clean() {
  TEST_START();
  // A representative slice of gen_number_differential_corpus.py TOKENS across
  // the shapes that matter (root, field, array, deep, and the skip-then-read
  // shape), chosen so the test stays fast.
  const char *tokens[] = {
      "0", "-0", "1", "-1", "127", "128", "-129", "255", "256",
      "32767", "32768", "-32769", "65535", "65536",
      "2147483647", "2147483648", "-2147483649",
      "4294967295", "4294967296",
      "9223372036854775807", "9223372036854775808",
      "-9223372036854775808", "-9223372036854775809",
      "18446744073709551615", "18446744073709551616",
      "9999999999999999999", "10000000000000000000",
      "1.0", "-1.5", "1e2", "1e-2", "1e308", "1e-400",
      "9007199254740993", "0.1", "1.7976931348623157e308",
  };
  struct Shape {
    const char *prefix;
    const char *suffix;
  };
  const Shape shapes[] = {
      {"", ""},                       // root
      {"{\"x\":", "}"},               // object field
      {"{\"pad\":0,\"x\":", "}"},     // field after a sibling
      {"[", "]"},                     // array element
      {"{\"a\":{\"b\":[", "]}}"},     // deep
  };
  for (const char *token : tokens) {
    for (const Shape &shape : shapes) {
      std::string doc = std::string(shape.prefix) + token + shape.suffix;
      if (!expect_no_findings(doc, "corpus shape")) { return false; }
    }
  }
  TEST_SUCCEED();
}

// ---------------------------------------------------------------------------

bool run() {
  return oracle_signed_boundaries() &&
         oracle_unsigned_boundaries() &&
         oracle_syntax_versus_value() &&
         oracle_rejects_malformed() &&
         oracle_double_range() &&
         documented_minus_zero_double() &&
         documented_big_integer_to_double() &&
         documented_type_boundary() &&
         big_integer_opt_in_hands_back_no_value() &&
         legal_boundaries_agree() &&
         legal_nested_documents_agree() &&
         validate_then_consume_agrees() &&
         both_paths_read_the_same_field() &&
         unread_success_is_not_compared() &&
         out_of_range_value_is_reported() &&
         range_disagreement_is_reported() &&
         out_of_range_acceptance_alone_is_reported() &&
         validity_disagreement_is_reported() &&
         get_number_tag_disagreement_is_reported() &&
         corpus_shapes_are_clean();
}

} // namespace number_differential_tests

int main() {
  return number_differential_tests::run() ? 0 : 1;
}
