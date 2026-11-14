#!/usr/bin/env python3
# Structured seed corpus and dictionary generator for fuzz_number_differential.
#
# The numbers that matter here are the ones that sit on a boundary: the edges
# of int8/int16/int32/int64/uint64 and of binary64, integers just outside the
# 64-bit range, exponents that round to zero or to infinity, and malformed
# tokens that the two parsing paths might classify differently. Random byte
# mutation of a whole document almost never lands on such a token, so every
# seed below embeds one of them in the place the harness reads it.
#
# Harness input layout (see fuzz_number_differential.cpp): the input is a
# plain JSON document; the harness locates the numeric field itself. Seeds
# therefore vary both the document *shape* (root scalar, nested object, nested
# array, deep nesting, duplicate keys) and the *token*.
#
# Usage: gen_number_differential_corpus.py <output-basename>
# Writes <output-basename>.zip (seed corpus) and <output-basename>.dict.

import sys
import zipfile

# --- the boundary tokens the two paths must agree on -----------------------

TOKENS = [
    # signed / unsigned 64-bit edges
    "0", "-0", "1", "-1",
    "9223372036854775806", "9223372036854775807", "9223372036854775808",
    "9223372036854775809",
    "-9223372036854775807", "-9223372036854775808", "-9223372036854775809",
    "18446744073709551614", "18446744073709551615", "18446744073709551616",
    "18446744073709551617",
    "9999999999999999999", "10000000000000000000", "99999999999999999999",
    # narrower boundaries
    "127", "128", "-128", "-129", "255", "256", "-256",
    "32767", "32768", "-32768", "-32769",
    "65535", "65536", "-65536",
    "2147483647", "2147483648", "-2147483648", "-2147483649",
    "4294967295", "4294967296", "-4294967296",
    # beyond 64 bits, various lengths
    "123456789012345678901", "-123456789012345678901",
    "123456789012345678901234567890",
    "-123456789012345678901234567890",
    "18446744073709551616" + "0" * 20,
    # doubles, exponents, fractions
    "0.0", "-0.0", "1.0", "-1.0", "1e2", "1E2", "1e+2", "1e-2", "1e0",
    "9007199254740992", "9007199254740993", "9007199254740992.0",
    "9007199254740993.0", "9007199254740994.0",
    "0.1", "0.30000000000000004", "1.7976931348623157e308",
    "1.7976931348623159e308", "2.2250738585072014e-308",
    "4.9406564584124654e-324", "5e-324", "1e-400", "-1e-400",
    "1e308", "1e309", "-1e309", "1e400",
    "3.4028235e38", "3.4028236e38", "1e39", "1e-45", "1e-46",
    "16777216", "16777217", "0e9999999999999999999999",
    "1e9999999999999999999999", "1e-9999999999999999999999",
    "0." + "0" * 340 + "1",
    "0." + "0" * 1074 + "1",
    "1" + "0" * 1080,
    # integer-valued floats and float-valued integers
    "1e19", "1e20", "18446744073709551615.0", "9223372036854775807.0",
    "-9223372036854775808.0", "1.0000000000000000000000001",
    # malformed
    "01", "-01", "1.", ".1", "1e", "1e+", "-", "+1", "--1", "1..2",
    "1e1e1", "0x10", "nan", "inf", "Infinity", "-Infinity",
    "1_000", "123abc", "0.-1", "1e+-2",
]

# --- document shapes -------------------------------------------------------

def shapes(tok):
    """Every way the harness can be made to read `tok`."""
    return {
        "root": tok,
        "obj": '{"x":' + tok + "}",
        "obj-first": '{"x":' + tok + ',"pad":0}',
        "obj-last": '{"pad":0,"x":' + tok + "}",
        "obj-spaced": '{ "x" : ' + tok + ' }',
        "array": "[" + tok + "]",
        "array-mid": '[0,' + tok + ",0]",
        "deep": '{"a":{"b":[' + tok + "]}}",
        # A field whose value the harness does *not* read, followed by the
        # field it does read: exercises the skip path before the read.
        "after-skipped": '{"skipped":' + tok + ',"x":1}',
        # Duplicate keys. Both front-ends return the first occurrence, so in
        # "dup-first" the harness reads exactly the token; in "dup-second" it
        # reads the other value. Either way the two paths must agree with each
        # other and, for "dup-first", with the token.
        "dup-first": '{"x":' + tok + ',"x":2}',
        "dup-second": '{"x":2,"x":' + tok + "}",
    }

# --- a few hand-shaped documents that are not (token, shape) products ------

EXTRA_DOCUMENTS = [
    '{"a":1,"b":18446744073709551615}',
    '{"a":1.5,"b":-9223372036854775808}',
    '{"a":"str","b":9223372036854775808}',
    '{"a":[1,2,3],"b":-1}',
    '{"a":{"k":2},"b":18446744073709551616}',
    '{"a":null,"b":7}',
    '{"a":true,"b":-9223372036854775809}',
    '{"a":1e309,"b":5}',
    '{"a":-0,"b":5}',
    '{"x":1,"x":18446744073709551616}',
    '[18446744073709551615,5,-7,2.5]',
    '[9223372036854775807,9223372036854775808,-9223372036854775809]',
    '[[[[[-9223372036854775809]]]]]',
    '{"x":9223372036854775808,"y":9223372036854775808}',
]


def main(basename):
    # File names must be deterministic across Python runs, so they are a
    # running index rather than a hash of the token.
    seen = {}
    for shape_name in sorted({s for tok in TOKENS for s in shapes(tok)}):
        for tok in TOKENS:
            seen["%s-%03d" % (shape_name, len(seen))] = shapes(tok)[shape_name]
    for i, doc in enumerate(EXTRA_DOCUMENTS):
        seen["extra-%02d" % i] = doc

    with zipfile.ZipFile(basename + ".zip", "w", zipfile.ZIP_DEFLATED) as z:
        for name, doc in seen.items():
            z.writestr(name, doc.encode("utf-8"))

    # A dictionary of the tokens and of the JSON number pieces the mutator
    # should splice in. libFuzzer treats quoted entries as raw bytes.
    with open(basename + ".dict", "w") as f:
        for tok in TOKENS:
            f.write('"%s"\n' % tok.replace("\\", "\\\\").replace('"', '\\"'))
        for piece in ['"x":', '{"x":', "}", "[", "]", ",", "e", "E", ".", "-",
                      '"skipped":', '"pad":0,']:
            f.write("%s\n" % piece)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("usage: %s <output-basename>\n" % sys.argv[0])
        sys.exit(1)
    main(sys.argv[1])
