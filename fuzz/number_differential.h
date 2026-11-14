/**
 * Shared engine for the DOM vs On-Demand numeric differential checks.
 *
 * Used by fuzz/fuzz_number_differential.cpp (mutation-driven) and by
 * tests/dom/number_differential_tests.cpp (regression + boundary tests).
 *
 * What is compared
 * ----------------
 * For one JSON number token, two independent reading paths (simdjson DOM and
 * simdjson On-Demand) each perform the same logical getter. An observation is
 * an error code plus, on success, the value and whether the path actually
 * consumed the token. A third, independent reading -- the Oracle below --
 * decides what the token's value really is and whether it lies in each
 * getter's range. Comparing each path against the Oracle is what separates
 * "the two paths disagree" from "one path is wrong", and is what lets the
 * check fire when a path returns an out-of-range value even if the other path
 * also rejects.
 *
 * What is *not* reported
 * ----------------------
 * The library documents several deliberate differences between the two
 * front-ends. They are enumerated in DocumentedDifference and excluded
 * explicitly, with a reason, rather than by accident. See classify().
 */
#ifndef SIMDJSON_FUZZ_NUMBER_DIFFERENTIAL_H
#define SIMDJSON_FUZZ_NUMBER_DIFFERENTIAL_H

#include "simdjson.h"

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace number_differential {

using namespace simdjson;

// ---------------------------------------------------------------------------
// The logical operation both paths are asked to perform.
// ---------------------------------------------------------------------------
enum class Getter { Int64, Uint64, Double, Int32, Uint32, Number };

inline const char *getter_name(Getter g) {
  switch (g) {
    case Getter::Int64:  return "get_int64";
    case Getter::Uint64: return "get_uint64";
    case Getter::Double: return "get_double";
    case Getter::Int32:  return "get_int32";
    case Getter::Uint32: return "get_uint32";
    case Getter::Number: return "get_number";
  }
  return "?";
}

inline const char *error_name(error_code e) {
  switch (e) {
    case SUCCESS:             return "SUCCESS";
    case NUMBER_ERROR:        return "NUMBER_ERROR";
    case BIGINT_ERROR:        return "BIGINT_ERROR";
    case INCORRECT_TYPE:      return "INCORRECT_TYPE";
    case NUMBER_OUT_OF_RANGE: return "NUMBER_OUT_OF_RANGE";
    case TRAILING_CONTENT:    return "TRAILING_CONTENT";
    case NO_SUCH_FIELD:       return "NO_SUCH_FIELD";
    case TAPE_ERROR:          return "TAPE_ERROR";
    case INCOMPLETE_ARRAY_OR_OBJECT: return "INCOMPLETE_ARRAY_OR_OBJECT";
    default:                  return "OTHER";
  }
}

// ---------------------------------------------------------------------------
// Navigation path to the token.
// ---------------------------------------------------------------------------
struct Step {
  bool is_key{false};
  std::string key{};
  size_t index{0};
  Step() = default;
  Step(bool k, std::string s, size_t i) : is_key{k}, key{std::move(s)}, index{i} {}
  Step(const Step &o) : is_key{o.is_key}, key{o.key}, index{o.index} {}
  Step &operator=(const Step &o) noexcept {
    is_key = o.is_key; key = o.key; index = o.index; return *this;
  }
  ~Step() = default;
};

struct Location {
  std::vector<Step> path{};
  size_t token_offset{0};
  bool found{false};   // did the locator find a number token at all?
  std::string description{"<root>"};
  Location() = default;
  Location(const Location &o)
      : path{o.path}, token_offset{o.token_offset}, found{o.found},
        description{o.description} {}
  Location &operator=(const Location &o) noexcept {
    path = o.path; token_offset = o.token_offset; found = o.found;
    description = o.description;
    return *this;
  }
  ~Location() = default;
};

// A forgiving scanner that finds *a* number token and the path reaching it.
// Well-formedness is the libraries' concern; disagreements about it are not
// what this check reports, so the scanner only has to agree with itself.
class Locator {
public:
  // Owns a copy of the document. Holding a reference here is a footgun: a
  // caller passing a temporary std::string (or a std::string built from a
  // string literal) would leave a dangling reference for the whole scan.
  explicit Locator(std::string s) : in_(std::move(s)) {}

  Location locate() {
    Location loc;
    if (scan(0, loc, true)) { loc.found = true; return loc; }
    Location fallback;
    if (scan(0, fallback, false)) { fallback.found = true; return fallback; }
    // Nothing looked like a number. The root-scalar fallback still hands the
    // first bytes to the readers; `found` records that the locator did not
    // actually recognise a token there.
    loc.token_offset = 0;
    loc.description = "<root>";
    loc.found = false;
    return loc;
  }

  // The text of the located token (used by callers that want to report it).
  std::string token_text(const Location &loc) const {
    size_t p = loc.token_offset;
    while (p < in_.size() && (in_[p] == ' ' || in_[p] == '\t' ||
                              in_[p] == '\n' || in_[p] == '\r')) { p++; }
    size_t start = p;
    p = number_end(in_, p);
    return in_.substr(start, p - start);
  }

private:
  std::string in_;

  static void skip_ws(const std::string &s, size_t &p) {
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\n' ||
                            s[p] == '\r')) { p++; }
  }

  static bool parse_string(const std::string &s, size_t &p, std::string &out) {
    if (p >= s.size() || s[p] != '"') { return false; }
    p++;
    while (p < s.size()) {
      char c = s[p++];
      if (c == '"') { return true; }
      if (c == '\\') { if (p >= s.size()) { return false; } p++; }
      else { out += c; }
    }
    return false;
  }

  static bool starts_number(const std::string &s, size_t p) {
    if (p >= s.size()) { return false; }
    if (s[p] == '-') { return p + 1 < s.size() && s[p + 1] >= '0' && s[p + 1] <= '9'; }
    return s[p] >= '0' && s[p] <= '9';
  }

  static size_t number_end(const std::string &s, size_t p) {
    while (p < s.size()) {
      char c = s[p];
      if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' ||
          c == 'e' || c == 'E') { p++; }
      else { break; }
    }
    return p;
  }

  bool scan(size_t p, Location &loc, bool want_x) {
    skip_ws(in_, p);
    if (p >= in_.size()) { return false; }
    char c = in_[p];
    if (c == '[') {
      p++;
      size_t index = 0;
      while (true) {
        skip_ws(in_, p);
        if (p >= in_.size() || in_[p] == ']') { return false; }
        size_t save = loc.path.size();
        loc.path.push_back(Step(false, std::string(), index));
        if (scan(p, loc, want_x)) { return true; }
        loc.path.resize(save);
        if (!skip_value(p)) { return false; }
        skip_ws(in_, p);
        if (p < in_.size() && in_[p] == ',') { p++; index++; continue; }
        return false;
      }
    }
    if (c == '{') {
      p++;
      while (true) {
        skip_ws(in_, p);
        if (p >= in_.size() || in_[p] == '}') { return false; }
        std::string key;
        if (!parse_string(in_, p, key)) { return false; }
        skip_ws(in_, p);
        if (p >= in_.size() || in_[p] != ':') { return false; }
        p++;
        skip_ws(in_, p);
        size_t save = loc.path.size();
        loc.path.push_back(Step(true, key, 0));
        if (starts_number(in_, p)) {
          if (!want_x || key == "x") {
            loc.token_offset = p;
            loc.description = describe(loc.path);
            return true;
          }
        } else if (scan(p, loc, want_x)) {
          return true;
        }
        loc.path.resize(save);
        if (!skip_value(p)) { return false; }
        skip_ws(in_, p);
        if (p < in_.size() && in_[p] == ',') { p++; continue; }
        return false;
      }
    }
    if (starts_number(in_, p)) {
      loc.token_offset = p;
      if (!want_x) { loc.description = describe(loc.path); return true; }
      return false;
    }
    return false;
  }

  bool skip_value(size_t &p) {
    skip_ws(in_, p);
    if (p >= in_.size()) { return false; }
    char c = in_[p];
    if (c == '{' || c == '[') {
      char open = c, close = (c == '{') ? '}' : ']';
      int depth = 0;
      while (p < in_.size()) {
        char d = in_[p];
        if (d == '"') { std::string ignored; if (!parse_string(in_, p, ignored)) { return false; } continue; }
        if (d == open) { depth++; }
        else if (d == close) { depth--; p++; if (depth == 0) { return true; } continue; }
        p++;
      }
      return false;
    }
    if (c == '"') { std::string ignored; return parse_string(in_, p, ignored); }
    p = number_end(in_, p);
    return true;
  }

  static std::string describe(const std::vector<Step> &path) {
    if (path.empty()) { return "<root>"; }
    std::string out;
    for (const Step &s : path) {
      if (s.is_key) {
        out += "/";
        for (char ch : s.key) {
          if (ch == '~') { out += "~0"; }
          else if (ch == '/') { out += "~1"; }
          else { out += ch; }
        }
      } else {
        out += "/" + std::to_string(s.index);
      }
    }
    return out;
  }
};

// ---------------------------------------------------------------------------
// The Oracle: an independent reading of what a JSON number token means.
//
// It is exact. A token is decomposed into sign, digit string D and decimal
// scale, so the integer value is compared as decimal text rather than through
// int64_t arithmetic that could wrap. For doubles it uses strtod, whose
// result is the correctly rounded binary64 on the platforms simdjson targets;
// the callers that need it assert against a known value in the unit tests.
// ---------------------------------------------------------------------------
enum class ValueKind { Invalid, Signed, Unsigned, BigInt, Floating };

struct Oracle {
  bool valid{false};
  bool negative{false};
  bool is_zero{false};
  bool syntactically_integer{false};
  ValueKind kind{ValueKind::Invalid};

  // Exact magnitude for an integer-syntax token (no leading zeros; "0" for
  // zero). Empty when the token is floating-point or invalid. For a magnitude
  // too long to matter it holds a 21-digit sentinel rather than the whole
  // digit run, which also bounds the work an attacker-controlled exponent can
  // cause.
  std::string magnitude{};

  bool in_int64{false}, in_uint64{false};
  int64_t int64_value{0};
  uint64_t uint64_value{0};

  bool in_int32{false}, in_uint32{false};
  int32_t int32_value{0};
  uint32_t uint32_value{0};

  bool finite_double{false};
  double double_value{0};
};

inline int compare_decimal(const std::string &a, const std::string &b) {
  // Both are non-empty magnitudes without leading zeros.
  if (a.size() != b.size()) { return a.size() < b.size() ? -1 : 1; }
  int c = a.compare(b);
  return c < 0 ? -1 : (c > 0 ? 1 : 0);
}

inline Oracle analyze(const std::string &token) {
  Oracle o;
  const size_t n = token.size();
  size_t p = 0;

  if (p < n && token[p] == '-') { o.negative = true; p++; }
  if (p >= n) { return o; }

  // Integer part: "0" or a nonzero digit followed by digits.
  size_t int_start = p;
  if (token[p] == '0') {
    p++;
  } else if (token[p] >= '1' && token[p] <= '9') {
    while (p < n && token[p] >= '0' && token[p] <= '9') { p++; }
  } else {
    return o;
  }
  std::string int_digits = token.substr(int_start, p - int_start);

  // Fraction.
  std::string frac_digits;
  if (p < n && token[p] == '.') {
    p++;
    size_t fs = p;
    while (p < n && token[p] >= '0' && token[p] <= '9') { p++; }
    if (p == fs) { return o; }
    frac_digits = token.substr(fs, p - fs);
  }

  // Exponent.
  bool has_exponent = false;
  long long exponent = 0;
  if (p < n && (token[p] == 'e' || token[p] == 'E')) {
    has_exponent = true;
    p++;
    bool exp_negative = false;
    if (p < n && (token[p] == '+' || token[p] == '-')) {
      exp_negative = (token[p] == '-');
      p++;
    }
    size_t es = p;
    long long magnitude = 0;
    while (p < n && token[p] >= '0' && token[p] <= '9') {
      // Saturate: an exponent this large is either zero or infinite, and the
      // strtod branch below decides which.
      if (magnitude < 1000000000000LL) { magnitude = magnitude * 10 + (token[p] - '0'); }
      p++;
    }
    if (p == es) { return o; }
    exponent = exp_negative ? -magnitude : magnitude;
  }

  // Nothing may follow the token.
  if (p != n) { return o; }

  o.valid = true;
  o.syntactically_integer = (!has_exponent && frac_digits.empty());

  std::string digits = int_digits + frac_digits;
  size_t first_nonzero = digits.find_first_not_of('0');
  o.is_zero = (first_nonzero == std::string::npos);

  // Exact integer value = sign * digits * 10^(exponent - frac_len).
  long long scale = exponent - static_cast<long long>(frac_digits.size());
  std::string magnitude;
  bool exact_integer = false;
  if (o.is_zero) {
    exact_integer = true;
    magnitude = "0";
  } else if (scale >= 0) {
    exact_integer = true;
    if (scale > 64) {
      // Certainly beyond 64 bits. A 21-digit magnitude is enough to compare
      // as larger than any 64-bit limit, and it avoids building a string whose
      // length is proportional to an attacker-controlled exponent.
      magnitude = std::string(21, '9');
    } else {
      magnitude = digits.substr(first_nonzero) + std::string(static_cast<size_t>(scale), '0');
    }
  } else {
    long long drop = -scale;
    if (drop >= static_cast<long long>(digits.size())) {
      exact_integer = false; // every digit is fractional
    } else {
      size_t cut = digits.size() - static_cast<size_t>(drop);
      if (digits.find_first_not_of('0', cut) == std::string::npos) {
        exact_integer = true;
        std::string whole = digits.substr(0, cut);
        size_t nz = whole.find_first_not_of('0');
        magnitude = (nz == std::string::npos) ? "0" : whole.substr(nz);
      }
    }
  }

  // Build option: with SIMDJSON_MINUS_ZERO_AS_FLOAT the token "-0" is a
  // floating-point number (the IEEE -0.0) in both front-ends, so the integer
  // getters reject it. Mirror that here, or every flag build would look like
  // the two paths disagree about "get_number()" for "-0".
#if defined(SIMDJSON_MINUS_ZERO_AS_FLOAT) && SIMDJSON_MINUS_ZERO_AS_FLOAT
  if (o.negative && o.is_zero && o.syntactically_integer) {
    o.syntactically_integer = false;
  }
#endif

  // The integer getters require integer *syntax*, not merely an integer value
  // (get_int64() on "1e2" and on "1.0" is INCORRECT_TYPE in both front-ends).
  if (o.syntactically_integer && exact_integer) {
    o.magnitude = magnitude;
    if (magnitude == "0") {
      o.in_int64 = o.in_uint64 = o.in_int32 = o.in_uint32 = true;
      o.int64_value = 0; o.uint64_value = 0;
      o.int32_value = 0; o.uint32_value = 0;
      o.kind = ValueKind::Signed; // "-0" and "0" are both signed integers
    } else {
      static const std::string kInt64Max = "9223372036854775807";
      static const std::string kUint64Max = "18446744073709551615";
      static const std::string kInt64MinMagnitude = "9223372036854775808";
      if (o.negative) {
        o.in_int64 = compare_decimal(magnitude, kInt64MinMagnitude) <= 0;
        o.in_uint64 = false;
        o.kind = o.in_int64 ? ValueKind::Signed : ValueKind::BigInt;
        if (o.in_int64) {
          o.int64_value = (magnitude == kInt64MinMagnitude)
                              ? INT64_MIN
                              : -static_cast<int64_t>(std::strtoll(magnitude.c_str(), nullptr, 10));
        }
      } else {
        o.in_int64 = compare_decimal(magnitude, kInt64Max) <= 0;
        o.in_uint64 = compare_decimal(magnitude, kUint64Max) <= 0;
        if (o.in_int64) {
          o.kind = ValueKind::Signed;
          o.int64_value = static_cast<int64_t>(std::strtoll(magnitude.c_str(), nullptr, 10));
        } else if (o.in_uint64) {
          o.kind = ValueKind::Unsigned;
          o.uint64_value = static_cast<uint64_t>(std::strtoull(magnitude.c_str(), nullptr, 10));
        } else {
          o.kind = ValueKind::BigInt;
        }
        if (o.in_uint64) {
          o.uint64_value = static_cast<uint64_t>(std::strtoull(magnitude.c_str(), nullptr, 10));
        }
      }
      o.in_int32 = o.in_int64 && o.int64_value >= INT32_MIN && o.int64_value <= INT32_MAX;
      if (o.in_int32) { o.int32_value = static_cast<int32_t>(o.int64_value); }
      o.in_uint32 = o.in_uint64 && o.uint64_value <= UINT32_MAX;
      if (o.in_uint32) { o.uint32_value = static_cast<uint32_t>(o.uint64_value); }
    }
  } else {
    o.kind = ValueKind::Floating;
  }

  // Doubles: strtod is correctly rounded; treat it as the reference. A token
  // whose magnitude overflows binary64 is not representable, and simdjson
  // rejects it (NUMBER_ERROR) rather than returning infinity.
  {
    double d = std::strtod(token.c_str(), nullptr);
    o.finite_double = std::isfinite(d);
    o.double_value = d;
  }
  return o;
}

// ---------------------------------------------------------------------------
// Observations.
// ---------------------------------------------------------------------------
enum class Tag { None, Signed, Unsigned, Double };

struct Observation {
  error_code err{UNINITIALIZED};
  bool consumed{false};
  // Did this path form a verdict about the target token itself? DOM parses
  // eagerly, so a failure elsewhere in a document with a nested target says
  // nothing about that target.
  bool reached{false};
  Tag tag{Tag::None};
  int64_t  i64{0};
  uint64_t u64{0};
  double   dbl{0};
};

template<typename T> struct ValueStore {
  static void store(Observation &o, T v) {
    (void)o; (void)v;
  }
};
template<> struct ValueStore<int64_t> {
  static void store(Observation &o, int64_t v) { o.i64 = v; o.tag = Tag::Signed; }
};
template<> struct ValueStore<uint64_t> {
  static void store(Observation &o, uint64_t v) { o.u64 = v; o.tag = Tag::Unsigned; }
};
template<> struct ValueStore<double> {
  static void store(Observation &o, double v) { o.dbl = v; o.tag = Tag::Double; }
};
template<> struct ValueStore<int32_t> {
  static void store(Observation &o, int32_t v) { o.i64 = v; o.tag = Tag::Signed; }
};
template<> struct ValueStore<uint32_t> {
  static void store(Observation &o, uint32_t v) { o.u64 = v; o.tag = Tag::Unsigned; }
};
template<> struct ValueStore<ondemand::number> {
  static void store(Observation &o, ondemand::number v) {
    switch (v.get_number_type()) {
      case ondemand::number_type::signed_integer:
        o.i64 = v.get_int64(); o.tag = Tag::Signed; break;
      case ondemand::number_type::unsigned_integer:
        o.u64 = v.get_uint64(); o.tag = Tag::Unsigned; break;
      case ondemand::number_type::floating_point_number:
        o.dbl = v.get_double(); o.tag = Tag::Double; break;
      default:
        o.tag = Tag::None; break;
    }
  }
};

// ---------------------------------------------------------------------------
// DOM reading path. DOM is multi-pass, so every getter starts from a fresh
// parse; a reused element would be fine, but a fresh parse keeps the two
// paths' setup symmetric.
// ---------------------------------------------------------------------------
inline bool dom_walk(dom::parser &parser, const std::string &doc,
                     const Location &loc, dom::element &out, error_code &err) {
  dom::element root;
  err = parser.parse(padded_string(doc)).get(root);
  if (err) { return false; }
  dom::element cur = root;
  for (const Step &s : loc.path) {
    if (s.is_key) {
      auto r = cur[s.key];
      err = r.error();
      if (err) { return false; }
      cur = r.value_unsafe();
    } else {
      auto r = cur.at(s.index);
      err = r.error();
      if (err) { return false; }
      cur = r.value_unsafe();
    }
  }
  out = cur;
  return true;
}

inline Observation observe_dom(const std::string &doc, const Location &loc,
                               Getter g) {
  Observation o;
  dom::parser parser;
  dom::element target;
  error_code err = SUCCESS;
  if (!dom_walk(parser, doc, loc, target, err)) {
    o.err = err;
    // A root-scalar document is parsed as one token, so a parse failure is a
    // verdict about that token. A nested target's parse failure may come from
    // any sibling and is not attributable to the target.
    o.reached = loc.path.empty();
    return o;
  }
  o.reached = true;

  switch (g) {
    case Getter::Int64: {
      auto r = target.get_int64();
      o.err = r.error();
      if (!o.err) { o.i64 = r.value_unsafe(); o.tag = Tag::Signed; o.consumed = true; }
      return o;
    }
    case Getter::Uint64: {
      auto r = target.get_uint64();
      o.err = r.error();
      if (!o.err) { o.u64 = r.value_unsafe(); o.tag = Tag::Unsigned; o.consumed = true; }
      return o;
    }
    case Getter::Double: {
      auto r = target.get_double();
      o.err = r.error();
      if (!o.err) { o.dbl = r.value_unsafe(); o.tag = Tag::Double; o.consumed = true; }
      return o;
    }
    case Getter::Int32: {
      // DOM has no get_int32(); mirror the On-Demand operation (get_int64 then
      // a range check) so both sides represent the same thing.
      auto r = target.get_int64();
      o.err = r.error();
      if (!o.err) {
        int64_t v = r.value_unsafe();
        if (v < INT32_MIN || v > INT32_MAX) { o.err = NUMBER_OUT_OF_RANGE; }
        else { o.i64 = v; o.tag = Tag::Signed; o.consumed = true; }
      }
      return o;
    }
    case Getter::Uint32: {
      auto r = target.get_uint64();
      o.err = r.error();
      if (!o.err) {
        uint64_t v = r.value_unsafe();
        if (v > UINT32_MAX) { o.err = NUMBER_OUT_OF_RANGE; }
        else { o.u64 = v; o.tag = Tag::Unsigned; o.consumed = true; }
      }
      return o;
    }
    case Getter::Number: {
      // Use the exact tape type. is_int64()/is_uint64() mean "castable to
      // that type" and are true simultaneously for values below INT64_MAX.
      switch (target.type()) {
        case dom::element_type::INT64: {
          auto r = target.get_int64();
          o.err = r.error();
          if (!o.err) { o.i64 = r.value_unsafe(); o.tag = Tag::Signed; o.consumed = true; }
          return o;
        }
        case dom::element_type::UINT64: {
          auto r = target.get_uint64();
          o.err = r.error();
          if (!o.err) { o.u64 = r.value_unsafe(); o.tag = Tag::Unsigned; o.consumed = true; }
          return o;
        }
        case dom::element_type::DOUBLE: {
          auto r = target.get_double();
          o.err = r.error();
          if (!o.err) { o.dbl = r.value_unsafe(); o.tag = Tag::Double; o.consumed = true; }
          return o;
        }
        default:
          o.err = INCORRECT_TYPE;
          return o;
      }
    }
  }
  o.err = UNINITIALIZED;
  return o;
}

// ---------------------------------------------------------------------------
// On-Demand reading path. On-Demand is single-pass and single-use, so each
// observation gets its own parser+document; a second getter on the same value
// would read an already-consumed token.
// ---------------------------------------------------------------------------
template<typename GetterFn>
inline Observation observe_ondemand_impl(const std::string &doc,
                                         const Location &loc, GetterFn getter) {
  Observation o;
  ondemand::parser parser;
  padded_string padded(doc);
  ondemand::document document;
  error_code err = parser.iterate(padded).get(document);
  if (err) { o.err = err; return o; }

  if (loc.path.empty()) {
    o.reached = true;
    auto r = getter(document);
    o.err = r.error();
    if (!o.err) {
      o.consumed = true;
      ValueStore<std::decay_t<decltype(r.value_unsafe())>>::store(o, r.value_unsafe());
    }
    return o;
  }

  simdjson_result<ondemand::value> result = [&]() -> simdjson_result<ondemand::value> {
    const Step &s = loc.path[0];
    if (s.is_key) { return document[s.key]; }
    return document.at(s.index);
  }();
  for (size_t i = 1; i < loc.path.size(); i++) {
    if (result.error()) { break; }
    ondemand::value v = result.value_unsafe();
    const Step &s = loc.path[i];
    result = s.is_key ? simdjson_result<ondemand::value>(v[s.key])
                      : simdjson_result<ondemand::value>(v.at(s.index));
  }
  if (result.error()) { o.err = result.error(); return o; }
  ondemand::value value = result.value_unsafe();
  o.reached = true;
  auto r = getter(value);
  o.err = r.error();
  if (!o.err) {
    o.consumed = true;
    ValueStore<std::decay_t<decltype(r.value_unsafe())>>::store(o, r.value_unsafe());
  }
  return o;
}

inline Observation observe_ondemand(const std::string &doc, const Location &loc,
                                    Getter g) {
  switch (g) {
    case Getter::Int64:
      return observe_ondemand_impl(doc, loc, [](auto &v) { return v.get_int64(); });
    case Getter::Uint64:
      return observe_ondemand_impl(doc, loc, [](auto &v) { return v.get_uint64(); });
    case Getter::Double:
      return observe_ondemand_impl(doc, loc, [](auto &v) { return v.get_double(); });
    case Getter::Int32:
      return observe_ondemand_impl(doc, loc, [](auto &v) { return v.get_int32(); });
    case Getter::Uint32:
      return observe_ondemand_impl(doc, loc, [](auto &v) { return v.get_uint32(); });
    case Getter::Number:
      return observe_ondemand_impl(doc, loc, [](auto &v) { return v.get_number(); });
  }
  Observation o;
  o.err = UNINITIALIZED;
  return o;
}

// ---------------------------------------------------------------------------
// Classification.
// ---------------------------------------------------------------------------
struct Verdict {
  bool is_finding{false};
  // Set when the pair is a difference the library documents. Kept so tests can
  // assert that a documented difference is classified as documented rather
  // than silently ignored, and so a future change that turns a documented
  // difference into a real one is noticed.
  bool documented{false};
  const char *reason{""};
  const char *detail{""};
};

inline bool same_double_bits(double a, double b) {
  uint64_t ba = 0, bb = 0;
  std::memcpy(&ba, &a, sizeof(a));
  std::memcpy(&bb, &b, sizeof(b));
  return ba == bb;
}

// Does the getter's own documented range contain the oracle's value?
inline bool oracle_in_range(Getter g, const Oracle &o) {
  if (!o.valid) { return false; }
  switch (g) {
    case Getter::Int64:  return o.syntactically_integer && o.in_int64;
    case Getter::Uint64: return o.syntactically_integer && o.in_uint64;
    case Getter::Int32:  return o.syntactically_integer && o.in_int32;
    case Getter::Uint32: return o.syntactically_integer && o.in_uint32;
    case Getter::Double: return o.finite_double;
    case Getter::Number: return o.valid; // a number is always classifiable
  }
  return false;
}

inline bool is_range_verdict(error_code e) {
  return e == NUMBER_OUT_OF_RANGE || e == BIGINT_ERROR;
}

// Verify one path's observation against the oracle. Returns true if the path's
// own conclusion is internally wrong (it is the disagreement source).
//
// `documented` is set when the path's conclusion differs from the oracle only
// because of a behaviour the library documents: today that is DOM's
// parse-time BIGINT_ERROR for an integer outside the 64-bit range (the
// documented default; parser.number_as_string(true) opts out).
inline bool path_contradicts_oracle(Getter g, const Observation &obs,
                                    const Oracle &o, const char *&reason,
                                    const char *&detail, bool &documented) {
  documented = false;
  const bool ok = (obs.err == SUCCESS) && obs.consumed;
  const bool in_range = oracle_in_range(g, o);

#if defined(SIMDJSON_MINUS_ZERO_AS_FLOAT) && SIMDJSON_MINUS_ZERO_AS_FLOAT
  // Build-option edge: under SIMDJSON_MINUS_ZERO_AS_FLOAT the token "-0" is
  // documented as -0.0 ("as in JavaScript"), so DOM's tape records a double
  // and its integer getters reject. On-Demand's integer getters parse the
  // digits directly and still return 0. Both conclusions are "the value is
  // zero", which is in every integer range, so no out-of-range value escapes;
  // treat the difference as documented rather than an escape.
  if (o.negative && o.is_zero && ok &&
      (g == Getter::Int64 || g == Getter::Int32) && obs.i64 == 0) {
    documented = true;
    reason = "documented: -0 is -0.0 under SIMDJSON_MINUS_ZERO_AS_FLOAT";
    detail = "documented-minus-zero-integer";
    return false;
  }
#endif

  if (ok) {
    if (!in_range) {
      // Distinguish the two ways an acceptance can be wrong about the token:
      // the token is not a number at all (malformed), or it is a number the
      // getter's type cannot represent (a fraction, an exponent form, or a
      // magnitude outside the range). Both hand a value to the caller for a
      // token the getter's contract excludes.
      if (!o.valid) {
        reason = "a path accepted a malformed token as a number";
        detail = "accepted-invalid";
      } else {
        reason = "a path accepted a value that is outside this getter's range";
        detail = "accepted-out-of-range";
      }
      return true;
    }
    switch (g) {
      case Getter::Int64:
      case Getter::Int32:
        if (obs.i64 != (g == Getter::Int64 ? o.int64_value : int64_t(o.int32_value))) {
          reason = "a path returned a different signed value than the token denotes";
          detail = "wrong-value";
          return true;
        }
        break;
      case Getter::Uint64:
        if (obs.u64 != o.uint64_value) {
          reason = "a path returned a different unsigned value than the token denotes";
          detail = "wrong-value";
          return true;
        }
        break;
      case Getter::Uint32:
        if (obs.u64 != uint64_t(o.uint32_value)) {
          reason = "a path returned a different unsigned value than the token denotes";
          detail = "wrong-value";
          return true;
        }
        break;
      case Getter::Double:
        if (!same_double_bits(obs.dbl, o.double_value)) {
          // The two representations of zero are a documented toggle; anything
          // else is a real difference.
          if (!(obs.dbl == 0.0 && o.double_value == 0.0)) {
            reason = "a path returned a different double than the token denotes";
            detail = "wrong-value";
            return true;
          }
        }
        break;
      case Getter::Number: {
        // The tag must agree with the oracle's classification. A negative zero
        // is a signed integer in both front-ends' default configuration.
        Tag expected = Tag::None;
        switch (o.kind) {
          case ValueKind::Signed:   expected = Tag::Signed; break;
          case ValueKind::Unsigned: expected = Tag::Unsigned; break;
          case ValueKind::Floating: expected = Tag::Double; break;
          case ValueKind::BigInt:
          case ValueKind::Invalid:  expected = Tag::None; break;
        }
        if (expected != Tag::None && obs.tag != expected) {
          reason = "get_number() classified the token differently than the oracle";
          detail = "wrong-tag";
          return true;
        }
        break;
      }
    }
    return false;
  }

  // The path rejected. That is only wrong if the oracle says the value is in
  // range *and* the path claimed a range failure. A type-boundary rejection
  // (INCORRECT_TYPE) of an out-of-range value is correct behaviour.
  if (in_range && is_range_verdict(obs.err)) {
    // Documented: "By default, integers that exceed the 64-bit range cause
    // parsing to fail with BIGINT_ERROR. You can opt in to big integer
    // support..." (doc/dom.md). A token the oracle classifies as a big
    // integer is therefore legitimately rejected by DOM's default parser,
    // even though the value has a finite binary64 approximation that
    // get_double() would return elsewhere.
    if (obs.err == BIGINT_ERROR && o.kind == ValueKind::BigInt) {
      documented = true;
      reason = "documented: DOM rejects integers outside the 64-bit range at parse time";
      detail = "documented-big-integer";
      return false;
    }
    reason = "a path rejected an in-range value with a range verdict";
    detail = "rejected-in-range";
    return true;
  }
  return false;
}

// Compare the two paths, using the oracle as the tie-breaker.
inline Verdict classify(Getter g, const Observation &dom,
                        const Observation &ond, const Oracle &oracle) {
  Verdict v;

  // Both paths must have reached the token for their conclusions to be about
  // the same thing.
  if (!dom.reached || !ond.reached) { return v; }

  // A path that reported SUCCESS without advancing never actually read the
  // token; that is not an acceptance to compare against. (Both readers below
  // set consumed exactly when they return a value, so this only guards
  // against a malformed observation.)
  if ((dom.err == SUCCESS && !dom.consumed) ||
      (ond.err == SUCCESS && !ond.consumed)) {
    return v;
  }

  const bool dom_ok = (dom.err == SUCCESS) && dom.consumed;
  const bool ond_ok = (ond.err == SUCCESS) && ond.consumed;

  const char *dom_reason = nullptr, *dom_detail = nullptr;
  const char *ond_reason = nullptr, *ond_detail = nullptr;
  bool dom_documented = false, ond_documented = false;
  const bool dom_wrong = path_contradicts_oracle(g, dom, oracle, dom_reason,
                                                 dom_detail, dom_documented);
  const bool ond_wrong = path_contradicts_oracle(g, ond, oracle, ond_reason,
                                                 ond_detail, ond_documented);

  // A path that is internally wrong is the dangerous case: it says "allowed"
  // (or hands back a value) for something the token does not denote.
  if (dom_wrong || ond_wrong) {
    v.is_finding = true;
    v.reason = dom_wrong ? dom_reason : ond_reason;
    v.detail = dom_wrong ? dom_detail : ond_detail;
    return v;
  }
  if (dom_documented || ond_documented) {
    v.documented = true;
    v.reason = dom_documented ? dom_reason : ond_reason;
    v.detail = dom_documented ? dom_detail : ond_detail;
    return v;
  }

  // Neither path is internally wrong. Now look for a disagreement between
  // them that the oracle cannot resolve, i.e. two different conclusions about
  // the same in-range value.
  if (dom_ok && ond_ok) {
    switch (g) {
      case Getter::Int64:
      case Getter::Int32:
        if (dom.i64 != ond.i64) {
          v.is_finding = true;
          v.reason = "both paths accepted, but returned different signed values";
          v.detail = "disagreement";
        }
        return v;
      case Getter::Uint64:
      case Getter::Uint32:
        if (dom.u64 != ond.u64) {
          v.is_finding = true;
          v.reason = "both paths accepted, but returned different unsigned values";
          v.detail = "disagreement";
        }
        return v;
      case Getter::Double:
        if (!same_double_bits(dom.dbl, ond.dbl)) {
          // Documented: SIMDJSON_MINUS_ZERO_AS_FLOAT selects whether the token
          // "-0" is the integer 0 (DOM's default: +0.0) or -0.0 (On-Demand's
          // default). Both are the same numeric zero.
          if (dom.dbl == 0.0 && ond.dbl == 0.0) {
            v.documented = true;
            v.reason = "documented: -0 is an integer 0, or -0.0 under SIMDJSON_MINUS_ZERO_AS_FLOAT";
            v.detail = "documented-minus-zero";
            return v;
          }
          v.is_finding = true;
          v.reason = "both paths accepted, but returned different doubles";
          v.detail = "disagreement";
        }
        return v;
      case Getter::Number:
        if (dom.tag != ond.tag) {
          v.is_finding = true;
          v.reason = "both paths accepted, but get_number() classified the token differently";
          v.detail = "disagreement";
        } else if (dom.tag == Tag::Signed && dom.i64 != ond.i64) {
          v.is_finding = true;
          v.reason = "both paths accepted, but get_number() signed values differ";
          v.detail = "disagreement";
        } else if (dom.tag == Tag::Unsigned && dom.u64 != ond.u64) {
          v.is_finding = true;
          v.reason = "both paths accepted, but get_number() unsigned values differ";
          v.detail = "disagreement";
        } else if (dom.tag == Tag::Double && !same_double_bits(dom.dbl, ond.dbl)) {
          if (dom.dbl == 0.0 && ond.dbl == 0.0) {
            v.documented = true;
            v.reason = "documented: -0 is an integer 0, or -0.0 under SIMDJSON_MINUS_ZERO_AS_FLOAT";
            v.detail = "documented-minus-zero";
          } else {
            v.is_finding = true;
            v.reason = "both paths accepted, but get_number() doubles differ";
            v.detail = "disagreement";
          }
        }
        return v;
    }
    return v;
  }

  if (dom_ok != ond_ok) {
    const Observation &rejecting = dom_ok ? ond : dom;

    // One path accepted an in-range value (the oracle already verified it
    // above), the other rejected. A range verdict against an in-range value is
    // always reportable: the two paths disagree about validity and the
    // rejecting side is demonstrably wrong.
    if (is_range_verdict(rejecting.err)) {
      v.is_finding = true;
      v.reason = "one path accepted an in-range value, the other returned a range verdict";
      v.detail = "disagreement";
      return v;
    }

    // Documented: the token "-0" is the integer 0, and the unsigned getters
    // treat it differently. DOM's get_uint64() converts the stored signed zero
    // and returns 0; On-Demand's get_uint64() rejects the token because it
    // carries a negative sign. The accepting value is the zero the token
    // denotes, so nothing out of range escapes; this is the signed/unsigned
    // type boundary applied to negative zero, not a range escape.
    if (oracle.negative && oracle.is_zero &&
        (g == Getter::Uint64 || g == Getter::Uint32)) {
      v.documented = true;
      v.reason = "documented type boundary: get_uint64() of the integer -0";
      v.detail = "documented-type-boundary";
      return v;
    }

    // Any other acceptance/rejection split is a validity disagreement between
    // two front-ends given the same token and the same getter. That is what a
    // validator-then-consumer split would trip over, so report it rather than
    // assuming it is documented.
    v.is_finding = true;
    v.reason = "one path accepted the token and the other rejected it";
    v.detail = "validity-disagreement";
    return v;
  }

  return v;
}

inline std::string token_text_of(const std::string &doc, const Location &loc) {
  return Locator(doc).token_text(loc);
}

// Run the full check for one getter, returning the verdict. Convenience used by
// both the fuzzer and the tests.
inline Verdict check(const std::string &doc, const Location &loc, Getter g) {
  Oracle oracle = analyze(token_text_of(doc, loc));
  Observation dom = observe_dom(doc, loc, g);
  Observation ond = observe_ondemand(doc, loc, g);
  return classify(g, dom, ond, oracle);
}

} // namespace number_differential

#endif // SIMDJSON_FUZZ_NUMBER_DIFFERENTIAL_H
