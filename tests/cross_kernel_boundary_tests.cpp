//
// Cross-kernel consistency tests for hostile JSON placed at input-block
// boundaries.
//
// A malicious document can position a backslash escape or a UTF-8
// continuation byte exactly where a SIMD input block ends. Every parsing
// kernel (haswell, westmere, fallback, ...) must reach the same verdict on
// the same bytes:
//
//   - complete samples: escapes that straddle a block boundary and legal
//     multi-byte UTF-8 characters must decode to identical string values;
//   - truncated samples: an unclosed escape or an incomplete UTF-8 sequence
//     must be rejected by every kernel, with the same error classification;
//   - illegal samples: invalid escapes and malformed UTF-8 must be rejected
//     by every kernel with the same error code.
//
// Samples are sized so the critical byte (or the document end) lands exactly
// on a 64-byte block boundary and on either side of it. Each document is
// placed in memory so that the byte after len + SIMDJSON_PADDING is an
// inaccessible guard page (on POSIX): any read past the padded region faults
// and fails the test, proving no kernel reads out of bounds. The padding
// itself is filled with 0xAA so a kernel cannot accidentally depend on
// zero-filled padding either.
//
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "simdjson.h"
#include "test_macros.h"

#if !defined(_WIN32)
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace {

// A document buffer whose padding ends exactly at an inaccessible guard
// page. Parsing must never touch the guard page; if it does, the process
// faults and the test run fails loudly.
class guarded_document {
public:
  explicit guarded_document(const std::string &doc) : len_(doc.size()) {
#if defined(_WIN32)
    // No portable guard pages: keep a normally padded copy instead.
    storage_ = simdjson::padded_string(doc);
    ptr_ = storage_.data();
    std::memset(ptr_ + len_, 0xAA, simdjson::SIMDJSON_PADDING);
#else
    const long page_size = sysconf(_SC_PAGESIZE);
    const size_t padded = len_ + simdjson::SIMDJSON_PADDING;
    const size_t usable = ((padded + size_t(page_size) - 1) / size_t(page_size)) * size_t(page_size);
    mapped_len_ = usable + size_t(page_size);
    base_ = static_cast<char *>(
        mmap(nullptr, mapped_len_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (base_ == MAP_FAILED) {
      std::cerr << "mmap failed" << std::endl;
      std::abort();
    }
    if (mprotect(base_ + usable, size_t(page_size), PROT_NONE) != 0) {
      std::cerr << "mprotect failed" << std::endl;
      std::abort();
    }
    // The document ends so that ptr + len + SIMDJSON_PADDING == guard page.
    ptr_ = base_ + (usable - padded);
    std::memcpy(ptr_, doc.data(), len_);
    // Poison the padding: results must not depend on its content.
    std::memset(ptr_ + len_, 0xAA, simdjson::SIMDJSON_PADDING);
#endif
  }
  guarded_document(const guarded_document &) = delete;
  guarded_document &operator=(const guarded_document &) = delete;
  ~guarded_document() {
#if !defined(_WIN32)
    if (base_ != nullptr) { munmap(base_, mapped_len_); }
#endif
  }
  simdjson::padded_string_view view() const {
    return simdjson::padded_string_view(ptr_, len_, len_ + simdjson::SIMDJSON_PADDING);
  }

private:
  char *ptr_ = nullptr;
  size_t len_ = 0;
#if defined(_WIN32)
  simdjson::padded_string storage_{};
#else
  char *base_ = nullptr;
  size_t mapped_len_ = 0;
#endif
};

// Where the "target" offset of a test case is anchored.
enum class anchor_mode {
  payload_start, // the payload (escape / UTF-8 sequence) starts at the target offset
  doc_end,       // the document ends at the target offset
};

struct boundary_sample {
  const char *name;
  std::string payload;                 // raw bytes inside the string literal
  bool truncated_doc;                  // true: input ends right after the payload
  simdjson::error_code expected_error; // SUCCESS for well-formed samples
  std::string expected_value;          // decoded payload when expected_error == SUCCESS
};

const char kSuffix[] = "\",{\"tail\":[1,2,3]}]"; // follows the string in complete docs

// Complete document: ["<filler><payload>",{"tail":[1,2,3]}]
// Truncated document: "<filler><payload>   (end of input)
std::string build_doc(const boundary_sample &sample, size_t filler_len) {
  std::string doc;
  std::string filler(filler_len, 'a');
  if (sample.truncated_doc) {
    doc = "\"" + filler + sample.payload;
  } else {
    doc = "[\"" + filler + sample.payload + kSuffix;
  }
  return doc;
}

// Compute the filler length so that the anchored feature lands exactly at
// `target`. Returns false when the sample cannot reach that offset.
bool filler_length(const boundary_sample &sample, anchor_mode mode, size_t target,
                   size_t &filler_len) {
  // String content starts after the opening quote(s): 1 for a truncated
  // top-level string ("...), 2 for a complete document (["...).
  const size_t content_start = sample.truncated_doc ? 1 : 2;
  size_t needed = 0;
  switch (mode) {
  case anchor_mode::payload_start:
    needed = content_start;
    break;
  case anchor_mode::doc_end:
    needed = content_start + sample.payload.size() +
             (sample.truncated_doc ? 0 : std::strlen(kSuffix));
    break;
  }
  if (target < needed) { return false; }
  filler_len = target - needed;
  return true;
}

struct verdict {
  simdjson::error_code error = simdjson::UNINITIALIZED;
  std::string value{};    // decoded string at [0] (complete, successful docs)
  std::string minified{}; // whole-document serialization (successful docs)
  int64_t tail = -1;    // doc[1]["tail"][2]: document content after the string
};

verdict parse_with_current_kernel(const simdjson::padded_string_view &view, bool complete) {
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  verdict v;
  v.error = parser.parse(view).get(doc);
  if (v.error != simdjson::SUCCESS) { return v; }
  if (complete) {
    std::string_view sv;
    v.error = doc.at(0).get_string().get(sv);
    if (v.error != simdjson::SUCCESS) { return v; }
    v.value.assign(sv.data(), sv.size());
    int64_t tail = -1;
    v.error = doc.at(1)["tail"].at(2).get(tail);
    if (v.error != simdjson::SUCCESS) { return v; }
    v.tail = tail;
  }
  v.minified = simdjson::minify(doc);
  return v;
}

std::string hex_dump(const std::string &s) {
  std::string out;
  char buf[4];
  for (unsigned char c : s) {
    std::snprintf(buf, sizeof buf, "%02x", c);
    out += buf;
    out += ' ';
  }
  return out;
}

bool check_sample(const boundary_sample &sample, anchor_mode mode, size_t target) {
  size_t filler_len = 0;
  if (!filler_length(sample, mode, target, filler_len)) { return true; } // cannot reach: skip
  const std::string doc = build_doc(sample, filler_len);
  guarded_document guarded(doc);
  const simdjson::padded_string_view view = guarded.view();

  const char *mode_name = mode == anchor_mode::payload_start ? "payload@" : "docend@";
  bool ok = true;
  bool have_reference = false;
  verdict reference;
  std::string reference_kernel;

  for (const auto &impl : simdjson::get_available_implementations()) {
    if (!impl->supported_by_runtime_system()) { continue; }
    simdjson::get_active_implementation() = impl;
    // A fresh parser per kernel so no state leaks between implementations.
    const verdict v = parse_with_current_kernel(view, !sample.truncated_doc);

    // 1. The kernel's verdict must match the expected classification.
    if (v.error != sample.expected_error) {
      std::cerr << "FAIL: " << sample.name << " " << mode_name << target
                << " kernel=" << impl->name() << " returned " << v.error
                << " (expected " << sample.expected_error << ")" << std::endl;
      ok = false;
    }
    // 2. Well-formed samples must decode to the expected value, and the
    //    content following the boundary-straddling string must be intact.
    if (sample.expected_error == simdjson::SUCCESS && v.error == simdjson::SUCCESS) {
      const std::string expected_value = std::string(filler_len, 'a') + sample.expected_value;
      if (v.value != expected_value) {
        std::cerr << "FAIL: " << sample.name << " " << mode_name << target
                  << " kernel=" << impl->name() << " decoded [" << hex_dump(v.value)
                  << "] (expected [" << hex_dump(expected_value) << "])" << std::endl;
        ok = false;
      }
      if (v.tail != 3) {
        std::cerr << "FAIL: " << sample.name << " " << mode_name << target
                  << " kernel=" << impl->name() << " tail element is " << v.tail
                  << " (expected 3)" << std::endl;
        ok = false;
      }
    }
    // 3. Every kernel must agree with the first one, byte for byte.
    if (!have_reference) {
      reference = v;
      reference_kernel = impl->name();
      have_reference = true;
    } else {
      if (v.error != reference.error) {
        std::cerr << "FAIL: " << sample.name << " " << mode_name << target
                  << " kernel=" << impl->name() << " returned " << v.error << " but "
                  << reference_kernel << " returned " << reference.error << std::endl;
        ok = false;
      }
      if (v.error == simdjson::SUCCESS &&
          (v.value != reference.value || v.minified != reference.minified)) {
        std::cerr << "FAIL: " << sample.name << " " << mode_name << target
                  << " kernel=" << impl->name() << " disagrees with " << reference_kernel
                  << " on the parsed result" << std::endl;
        ok = false;
      }
    }
  }
  if (!have_reference) {
    std::cerr << "FAIL: no supported kernel available" << std::endl;
    ok = false;
  }
  return ok;
}

bool run_all_samples() {
  TEST_START();
  const std::vector<boundary_sample> samples = {
    // Complete, well-formed samples: escapes and legal multi-byte UTF-8.
    {"escape_quote", "\\\"", false, simdjson::SUCCESS, "\""},
    {"escape_backslash", "\\\\", false, simdjson::SUCCESS, "\\"},
    {"escape_solidus", "\\/", false, simdjson::SUCCESS, "/"},
    {"escape_controls", "\\b\\f\\n\\r\\t", false, simdjson::SUCCESS, "\b\f\n\r\t"},
    {"escape_unicode", "\\u00e9", false, simdjson::SUCCESS, "\xc3\xa9"},
    {"escape_surrogate_pair", "\\ud83d\\ude00", false, simdjson::SUCCESS, "\xf0\x9f\x98\x80"},
    {"utf8_2byte", "\xc3\xa9", false, simdjson::SUCCESS, "\xc3\xa9"},
    {"utf8_3byte", "\xe2\x82\xac", false, simdjson::SUCCESS, "\xe2\x82\xac"},
    {"utf8_4byte", "\xf0\x9f\x98\x80", false, simdjson::SUCCESS, "\xf0\x9f\x98\x80"},
    {"mixed_escape_utf8", "a\\t\xc3\xa9z", false, simdjson::SUCCESS, "a\t\xc3\xa9z"},
    // Complete, illegal samples: bad escapes and malformed UTF-8.
    {"escape_invalid", "\\x", false, simdjson::STRING_ERROR, ""},
    {"escape_short_hex", "\\u12", false, simdjson::STRING_ERROR, ""},
    {"escape_lone_high_surrogate", "\\ud83d", false, simdjson::STRING_ERROR, ""},
    {"escape_lone_low_surrogate", "\\ude00", false, simdjson::STRING_ERROR, ""},
    {"unescaped_control", "a\x01z", false, simdjson::UNESCAPED_CHARS, ""},
    {"utf8_lone_continuation", "\x80", false, simdjson::UTF8_ERROR, ""},
    {"utf8_truncated_2byte", "\xc3", false, simdjson::UTF8_ERROR, ""},
    {"utf8_truncated_3byte", "\xe2\x82", false, simdjson::UTF8_ERROR, ""},
    {"utf8_truncated_4byte", "\xf0\x9f\x98", false, simdjson::UTF8_ERROR, ""},
    {"utf8_overlong", "\xc0\xaf", false, simdjson::UTF8_ERROR, ""},
    {"utf8_surrogate", "\xed\xa0\x80", false, simdjson::UTF8_ERROR, ""},
    {"utf8_invalid_lead", "\xff", false, simdjson::UTF8_ERROR, ""},
    {"utf8_too_large", "\xf4\x90\x80\x80", false, simdjson::UTF8_ERROR, ""},
    // Truncated samples: the input ends inside the string, the escape or the
    // UTF-8 sequence. Every kernel must reject with UNCLOSED_STRING.
    {"unclosed_string", "", true, simdjson::UNCLOSED_STRING, ""},
    {"unclosed_escape", "\\", true, simdjson::UNCLOSED_STRING, ""},
    {"unclosed_unicode_escape", "\\u12", true, simdjson::UNCLOSED_STRING, ""},
    {"unclosed_utf8_2byte_lead", "\xc3", true, simdjson::UNCLOSED_STRING, ""},
    {"unclosed_utf8_3byte_partial", "\xe2\x82", true, simdjson::UNCLOSED_STRING, ""},
    {"unclosed_utf8_4byte_partial", "\xf0\x9f\x98", true, simdjson::UNCLOSED_STRING, ""},
  };

  // Block boundaries of interest: 32/64/128 cover the step sizes used by the
  // SIMD kernels; for each, probe the boundary itself and both sides.
  const size_t targets[] = {31, 32, 33, 63, 64, 65, 127, 128, 129};
  const anchor_mode modes[] = {anchor_mode::payload_start, anchor_mode::doc_end};

  bool ok = true;
  size_t cases = 0;
  for (const boundary_sample &sample : samples) {
    for (anchor_mode mode : modes) {
      for (size_t target : targets) {
        if (!check_sample(sample, mode, target)) { ok = false; }
        cases++;
      }
    }
  }
  std::cout << "checked " << cases << " sample/offset combinations across all supported kernels"
            << std::endl;
  return ok;
}

} // namespace

int main() {
  std::cout << "available kernels:";
  for (const auto &impl : simdjson::get_available_implementations()) {
    if (impl->supported_by_runtime_system()) { std::cout << " " << impl->name(); }
  }
  std::cout << std::endl;
  if (!run_all_samples()) { return EXIT_FAILURE; }
  std::cout << "cross-kernel boundary tests passed." << std::endl;
  return EXIT_SUCCESS;
}
