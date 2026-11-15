#ifndef SIMDJSON_FUZZ_POINTER_PATH_PARITY_H
#define SIMDJSON_FUZZ_POINTER_PATH_PARITY_H

//
// Shared engine for the DOM vs On-Demand JSON Pointer / JSONPath parity checks.
//
// Used by:
//   - fuzz/fuzz_atpointer_parity.cpp (the libFuzzer entry point), and
//   - tests/ondemand/pointer_path_parity_tests.cpp (the regression tests),
//
// so the fuzzer and the tests agree on what "the same answer" means and a
// finding from one is reproducible with the other.
//
// A caller may validate a query with one front-end and consume it with the
// other, so the two must classify the same malformed query the same way. This
// header reduces a lookup to an `observation` (an error code, or the selected
// value rendered as canonical JSON) and compares two observations.
//
// A handful of differences are *documented* behaviour, not defects, and are
// classified as such so neither the fuzzer nor the tests report them:
//
//   - the empty JSONPath: dom::element::at_path("") is INVALID_JSON_POINTER,
//     while ondemand::document::at_path("") returns the document (documented
//     in include/simdjson/generic/ondemand/document.h);
//   - a scalar-root document: dom::element::at_pointer("") returns the scalar,
//     while ondemand::document::at_pointer("") is SCALAR_DOCUMENT_AS_VALUE,
//     because a scalar document cannot be represented as a value.
//
// Everything else -- illegal escapes, leading-zero indices, oversized indices,
// overlong paths and structural garbage -- must agree.
//

#include "simdjson.h"

#include <string>
#include <string_view>

namespace pointer_path_parity {

// The result of one lookup through one front-end.
struct observation {
  simdjson::error_code error{simdjson::UNINITIALIZED};
  std::string value{}; // canonical JSON when error == SUCCESS
};

// Render a JSON element/documents as canonical JSON so a DOM result and an
// On-Demand result can be compared byte for byte.
inline std::string canonical_json(std::string_view raw) {
  simdjson::dom::parser parser;
  simdjson::dom::element element;
  if (parser.parse(simdjson::padded_string(raw)).get(element)) {
    return std::string("<unparseable:") + std::string(raw) + ">";
  }
  return simdjson::minify(element);
}

inline observation observe_dom(const simdjson::padded_string &json,
                               std::string_view query, bool pointer) {
  simdjson::dom::parser parser;
  simdjson::dom::element root;
  if (parser.parse(json).get(root)) { return {simdjson::UNINITIALIZED, ""}; }
  simdjson::dom::element leaf;
  const simdjson::error_code error =
      pointer ? root.at_pointer(query).get(leaf) : root.at_path(query).get(leaf);
  if (error) { return {error, ""}; }
  return {simdjson::SUCCESS, canonical_json(simdjson::minify(leaf))};
}

inline observation observe_ondemand(const simdjson::padded_string &json,
                                    std::string_view query, bool pointer) {
  simdjson::ondemand::parser parser;
  simdjson::ondemand::document doc;
  if (parser.iterate(json).get(doc)) { return {simdjson::UNINITIALIZED, ""}; }
  simdjson::ondemand::value value;
  const simdjson::error_code error = pointer
      ? doc.at_pointer(query).get(value)
      : doc.at_path(query).get(value);
  if (error) { return {error, ""}; }
  std::string_view raw;
  if (simdjson::to_json_string(value).get(raw)) {
    return {simdjson::SUCCESS, "<unserializable>"};
  }
  return {simdjson::SUCCESS, canonical_json(raw)};
}

// True when the two observations agree (same error, or same value).
inline bool agrees(const observation &dom, const observation &ondemand) {
  if (dom.error != ondemand.error) { return false; }
  if (dom.error == simdjson::SUCCESS && dom.value != ondemand.value) { return false; }
  return true;
}

// True when this (query, error pair) is one of the documented differences:
// the empty path, or the empty pointer on a scalar-root document. The document
// root type is needed only to recognise the latter, so the caller passes
// whether the document root is a scalar.
inline bool is_documented_divergence(std::string_view query, bool pointer,
                                     bool scalar_root,
                                     simdjson::error_code dom_error,
                                     simdjson::error_code ondemand_error) {
  // Empty JSONPath. DOM rejects it; On-Demand treats it as "the document
  // itself", which is SUCCESS for a container root and
  // SCALAR_DOCUMENT_AS_VALUE for a scalar root (a scalar document cannot be
  // represented as a value).
  if (!pointer && query.empty()) {
    if (dom_error != simdjson::INVALID_JSON_POINTER) { return false; }
    return ondemand_error == simdjson::SUCCESS ||
           (scalar_root && ondemand_error == simdjson::SCALAR_DOCUMENT_AS_VALUE);
  }
  // Empty pointer on a scalar document: DOM returns the scalar; On-Demand
  // cannot represent it.
  if (pointer && query.empty() && scalar_root) {
    return dom_error == simdjson::SUCCESS &&
           ondemand_error == simdjson::SCALAR_DOCUMENT_AS_VALUE;
  }
  return false;
}

// A complete comparison of one query. `divergence` is false when the two
// front-ends agree or when they differ only in a documented way.
struct comparison {
  observation dom{};
  observation ondemand{};
  bool divergence{false};
};

inline bool document_root_is_scalar(const simdjson::padded_string &json) {
  simdjson::dom::parser parser;
  simdjson::dom::element root;
  if (parser.parse(json).get(root)) { return false; }
  const simdjson::dom::element_type type = root.type();
  return type != simdjson::dom::element_type::ARRAY &&
         type != simdjson::dom::element_type::OBJECT;
}

inline comparison compare(const simdjson::padded_string &json,
                          std::string_view query, bool pointer,
                          bool scalar_root) {
  comparison result;
  result.dom = observe_dom(json, query, pointer);
  result.ondemand = observe_ondemand(json, query, pointer);
  if (!agrees(result.dom, result.ondemand) &&
      !is_documented_divergence(query, pointer, scalar_root,
                                result.dom.error, result.ondemand.error)) {
    result.divergence = true;
  }
  return result;
}

} // namespace pointer_path_parity

#endif // SIMDJSON_FUZZ_POINTER_PATH_PARITY_H
