#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Independent Python implementation. Behavior follows Google's "gutil" hash library
# (Copyright Google Inc., distributed in Apache Kudu, src/kudu/gutil/hash/, see LICENSE),
# which implements Bob Jenkins' lookup2 hash (public domain).
"""Compute the 64-bit docid that Google Search assigns to a URL.

The docid is Google's legacy string fingerprint applied to the exact URL string:

    docid = (Jenkins32(url, seed=0) << 32) | Jenkins32(url, seed=102072)

Jenkins32 is Bob Jenkins' lookup2 hash as implemented in Google's internal "gutil" library,
whose code is published in Apache Kudu (src/kudu/gutil/hash/). That implementation is
backwards compatible with Google's earliest code ("google1"): every full 4-byte word is read
with signed bytes; only the 1 to 3 leftover bytes that do not fill a word are read unsigned.
When the two halves are joined, a result of 0 or 1 is XORed with 0x130f9bef94a0a928, so a
fingerprint is never 0 or 1.

The fingerprint is computed on a specific string. Scheme, "www", trailing slash, query,
fragment, letter case and percent-encoding all change the result. This module never
normalizes a URL silently; the `variants` and `match` commands list labeled variants
explicitly.

Usage:
    python docid.py URL [URL ...]          docid of each exact string
    python docid.py variants URL           docids of common variants of a URL
    python docid.py decode ID              read a docid (decimal, signed, hex) or a
                                           14-character Google page ID
    python docid.py match ID URL [URL ...] find which variant of which URL gives this docid
    add --json to any command for machine-readable output
"""

from __future__ import annotations

import base64
import json
import re
import sys
from urllib.parse import urlsplit

__all__ = [
    "FINGERPRINT_SEED0", "FINGERPRINT_SEED1", "jenkins32", "fingerprint", "docid",
    "to_signed", "to_unsigned", "page_id_prefix", "decode_page_id", "parse_identifier",
    "percent_encode", "url_variants",
]

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

# Seeds used by gutil's Fingerprint() when EXTERNAL_FP is not defined. The "external"
# seeds (0xabc, 0xdef) exist in the same file for code shipped outside Google.
FINGERPRINT_SEED0 = 0
FINGERPRINT_SEED1 = 102072
_ZERO_ONE_MASK = 0x130F9BEF94A0A928
_GOLDEN_RATIO = 0x9E3779B9


def _mix(a: int, b: int, c: int) -> tuple[int, int, int]:
    a = (a - b - c) & M32; a ^= c >> 13
    b = (b - c - a) & M32; b ^= (a << 8) & M32
    c = (c - a - b) & M32; c ^= b >> 13
    a = (a - b - c) & M32; a ^= c >> 12
    b = (b - c - a) & M32; b ^= (a << 16) & M32
    c = (c - a - b) & M32; c ^= b >> 5
    a = (a - b - c) & M32; a ^= c >> 3
    b = (b - c - a) & M32; b ^= (a << 10) & M32
    c = (c - a - b) & M32; c ^= b >> 15
    return a, b, c


def _word(s: bytes, i: int, signed_bytes: bool) -> int:
    """Little-endian 32-bit word; with signed_bytes, each byte is sign-extended (gutil Google1At)."""
    t = s[i] | (s[i + 1] << 8) | (s[i + 2] << 16) | (s[i + 3] << 24)
    if signed_bytes:
        masked = t & 0x80808080
        t = (t - masked - masked) & M32
    return t


def jenkins32(data: bytes, seed: int, *, signed_bytes: bool = True) -> int:
    """gutil Hash32StringWithSeed (Bob Jenkins lookup2, google1-compatible byte reading)."""
    n = len(data)
    a = b = _GOLDEN_RATIO
    c = seed & M32
    i, k = 0, n
    while k >= 12:
        a = (a + _word(data, i, signed_bytes)) & M32
        b = (b + _word(data, i + 4, signed_bytes)) & M32
        c = (c + _word(data, i + 8, signed_bytes)) & M32
        a, b, c = _mix(a, b, c)
        i += 12
        k -= 12
    c = (c + n) & M32
    t = data[i:]
    # Full words of the final block are still read with _word(); leftover bytes are
    # read unsigned (gutil char2unsigned).
    if k >= 8:
        if k >= 11: c = (c + (t[10] << 24)) & M32
        if k >= 10: c = (c + (t[9] << 16)) & M32
        if k >= 9: c = (c + (t[8] << 8)) & M32
        b = (b + _word(t, 4, signed_bytes)) & M32
        a = (a + _word(t, 0, signed_bytes)) & M32
    elif k >= 4:
        if k >= 7: b = (b + (t[6] << 16)) & M32
        if k >= 6: b = (b + (t[5] << 8)) & M32
        if k >= 5: b = (b + t[4]) & M32
        a = (a + _word(t, 0, signed_bytes)) & M32
    else:
        if k >= 3: a = (a + (t[2] << 16)) & M32
        if k >= 2: a = (a + (t[1] << 8)) & M32
        if k >= 1: a = (a + t[0]) & M32
    a, b, c = _mix(a, b, c)
    return c


def fingerprint(data: str | bytes, seed0: int = FINGERPRINT_SEED0, seed1: int = FINGERPRINT_SEED1,
                *, signed_bytes: bool = True) -> int:
    """gutil Fingerprint(): two Jenkins32 halves combined into an unsigned 64-bit integer.

    A str is encoded as UTF-8 bytes, without any other transformation.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    elif not isinstance(data, (bytes, bytearray)):
        raise TypeError("fingerprint() expects str or bytes, got %s" % type(data).__name__)
    data = bytes(data)
    return _combine_halves(jenkins32(data, seed0, signed_bytes=signed_bytes),
                           jenkins32(data, seed1, signed_bytes=signed_bytes))


def _combine_halves(hi: int, lo: int) -> int:
    """gutil CombineFingerprintHalves: 0 and 1 are reserved and never returned."""
    result = (hi << 32) | lo
    if hi == 0 and lo < 2:
        result ^= _ZERO_ONE_MASK
    return result


def docid(url: str) -> int:
    """Google docid of an exact URL string (unsigned 64-bit). The string is not normalized."""
    if not isinstance(url, str):
        raise TypeError("docid() expects a str URL, got %s" % type(url).__name__)
    if url == "":
        raise ValueError("empty URL")
    return fingerprint(url)


def to_signed(value: int) -> int:
    """Unsigned 64-bit -> signed 64-bit (the form some Google systems print, e.g. Java long)."""
    if not 0 <= value <= M64:
        raise ValueError("not an unsigned 64-bit integer: %r" % value)
    return value - (1 << 64) if value >= (1 << 63) else value


def to_unsigned(value: int) -> int:
    """Signed or unsigned 64-bit -> unsigned 64-bit."""
    if not -(1 << 63) <= value <= M64:
        raise ValueError("not a 64-bit integer: %r" % value)
    return value & M64


def page_id_prefix(value: int) -> str:
    """First 10 characters of the 14-character page ID used by Google Images and Discover.

    Those IDs start with the page docid written as 8 little-endian bytes in URL-safe base64.
    Only the first 10 characters depend on the docid alone.
    """
    return base64.urlsafe_b64encode(to_unsigned(value).to_bytes(8, "little")).decode("ascii")[:10]


_PAGE_ID_RE = re.compile(r"[A-Za-z0-9_-]{14}")
_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")


def decode_page_id(page_id: str) -> int:
    """Page docid carried by a 14-character Google page ID (e.g. data-ref-docid in Google Images)."""
    if not _PAGE_ID_RE.fullmatch(page_id or ""):
        raise ValueError("a page ID is 14 URL-safe base64 characters, got %r" % page_id)
    raw = base64.urlsafe_b64decode(page_id[:12])  # 12 characters = 9 bytes
    return int.from_bytes(raw[:8], "little")


def parse_identifier(text: str) -> tuple[int, str]:
    """Read a docid written as unsigned or signed decimal, hex (0x-prefixed, or 16 hex digits
    including a letter), or a 14-character page ID. All-digit input is always read as decimal.

    Returns (unsigned docid, name of the form that was recognized).
    """
    if not isinstance(text, str):
        raise TypeError("parse_identifier() expects a str, got %s" % type(text).__name__)
    s = text.strip()
    if re.fullmatch(r"[0-9]{1,20}", s):
        value = int(s)
        if value > M64:
            raise ValueError("decimal value exceeds 64 bits: %s" % s)
        return value, "unsigned decimal"
    if re.fullmatch(r"-[0-9]{1,19}", s):
        value = int(s)
        if value < -(1 << 63):
            raise ValueError("negative value below the signed 64-bit range: %s" % s)
        return to_unsigned(value), "signed decimal"
    if re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", s):
        return int(s, 16), "hexadecimal"
    if re.fullmatch(r"[0-9a-fA-F]{16}", s):  # contains a letter, otherwise caught as decimal
        return int(s, 16), "hexadecimal"
    if _PAGE_ID_RE.fullmatch(s):
        return decode_page_id(s), "14-character page ID"
    raise ValueError("unrecognized identifier %r (expected decimal, -decimal, 0x-hex or a "
                     "14-character page ID)" % text)


def _has_non_ascii(s: str) -> bool:
    return any(ord(ch) > 0x7F for ch in s)


def percent_encode(url: str) -> str:
    """Percent-encode non-ASCII characters as UTF-8 (%XX, upper case); ASCII is left untouched."""
    return "".join(ch if ord(ch) < 0x80 else "".join("%%%02X" % b for b in ch.encode("utf-8"))
                   for ch in url)


def url_variants(url: str) -> list[tuple[str, str]]:
    """Labeled variants of a URL: scheme, www, trailing slash, query, fragment, encoding.

    The first entry is always the exact input; labels describe the changes from it.
    Variants are deduplicated by string. Structural variants apply to http(s) URLs; a URL
    without a scheme is also tried with https:// and http:// in front.
    """
    if not isinstance(url, str) or url == "":
        raise ValueError("empty URL")
    bases = [("", url)]
    if "&amp;" in url:
        bases.append(("&amp; unescaped", url.replace("&amp;", "&")))
    if _has_non_ascii(url):
        bases += [(_join(label, "percent-encoded"), percent_encode(b)) for label, b in list(bases)]
    if not _SCHEME_RE.match(url):
        bases += [(_join(label, "https:// added"), "https://" + (b[2:] if b.startswith("//") else b))
                  for label, b in list(bases)]

    out: list[tuple[str, str]] = [("as given", url), ("lowercase", url.lower())]
    for base_label, base in bases:
        parts = urlsplit(base)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            out.append((base_label or "as given", base))
            continue
        given_scheme = base.split(":", 1)[0]  # urlsplit lowercases the scheme
        other = "https" if parts.scheme == "http" else "http"
        schemes = [(given_scheme, ""), (other, other)]
        host = parts.netloc
        if host.lower().startswith("www."):
            hosts = [(host, ""), (host[4:], "no www")]
        else:
            hosts = [(host, ""), ("www." + host, "www")]
        path = parts.path
        if path == "":
            paths = [("", ""), ("/", "trailing slash")]
        elif path.endswith("/"):
            paths = [(path, ""), (path[:-1], "no trailing slash")]
        else:
            paths = [(path, ""), (path + "/", "trailing slash")]
        tails = [(parts.query, parts.fragment, "")]
        if parts.fragment:
            tails.append((parts.query, "", "no fragment"))
        if parts.query:
            tails.append(("", parts.fragment, "no query"))
            if parts.fragment:
                tails.append(("", "", "no query, no fragment"))
        for scheme, l1 in schemes:
            for h, l2 in hosts:
                for p, l3 in paths:
                    for q, f, l4 in tails:
                        s = "%s://%s%s%s%s" % (scheme, h, p, "?" + q if q else "", "#" + f if f else "")
                        label = ", ".join(x for x in (base_label, l1, l2, l3, l4) if x)
                        if not label and s != base:
                            label = "empty ? or # removed"
                        out.append((label or "as given", s))
    seen: set[str] = set()
    unique = []
    for label, s in out:
        if s not in seen:
            seen.add(s)
            unique.append((label, s))
    return unique


def _join(*labels: str) -> str:
    return ", ".join(x for x in labels if x)


def _forms(value: int) -> dict:
    return {
        "unsigned": value,
        "signed": to_signed(value),
        "hex": "%016x" % value,
        "page_id_prefix": page_id_prefix(value),
    }


def _warnings(url: str) -> list[str]:
    notes = []
    if url != url.strip():
        notes.append("leading or trailing whitespace is part of the hashed string")
    if _has_non_ascii(url.strip()):
        enc = percent_encode(url)
        notes.append("non-ASCII characters: every Google identifier we resolved for such URLs matched the "
                     "percent-encoded form %s -> %d" % (enc, docid(enc)))
    if not _SCHEME_RE.match(url):
        notes.append("no scheme: the docids we observed were computed on absolute URLs (https://...)")
    return notes


def _print_record(rec: dict) -> None:
    if "label" in rec:
        print("%-30s %20d  %016x  %s" % (rec["label"], rec["unsigned"], rec["unsigned"], rec["url"]))
        return
    print("url             %s" % rec["url"])
    print("docid unsigned  %d" % rec["unsigned"])
    print("docid signed    %d" % rec["signed"])
    print("docid hex       %s" % rec["hex"])
    print("page ID prefix  %s   (first 10 characters of a Google Images / Discover page ID)" % rec["page_id_prefix"])
    for note in rec.get("notes", []):
        print("note            %s" % note)


def _cmd_url(args: list[str], as_json: bool) -> int:
    if not args:
        raise ValueError("no URL given")
    records = []
    for url in args:
        rec = {"url": url, **_forms(docid(url))}
        notes = _warnings(url)
        if notes:
            rec["notes"] = notes
        records.append(rec)
    if as_json:
        print(json.dumps(records, indent=2))
    else:
        for i, rec in enumerate(records):
            if i:
                print()
            _print_record(rec)
    return 0


def _cmd_variants(args: list[str], as_json: bool) -> int:
    if len(args) != 1:
        raise ValueError("variants takes exactly one URL")
    records = [{"label": label, "url": s, **_forms(docid(s))} for label, s in url_variants(args[0])]
    if as_json:
        print(json.dumps(records, indent=2))
    else:
        for rec in records:
            _print_record(rec)
    return 0


def _cmd_decode(args: list[str], as_json: bool) -> int:
    if len(args) != 1:
        raise ValueError("decode takes exactly one identifier")
    value, form = parse_identifier(args[0])
    rec = {"input": args[0], "form": form, **_forms(value)}
    if as_json:
        print(json.dumps(rec, indent=2))
    else:
        print("input           %s  (%s)" % (args[0], form))
        print("docid unsigned  %d" % value)
        print("docid signed    %d" % rec["signed"])
        print("docid hex       %s" % rec["hex"])
        print("page ID prefix  %s" % rec["page_id_prefix"])
    return 0


def _cmd_match(args: list[str], as_json: bool) -> int:
    if len(args) < 2:
        raise ValueError("match takes an identifier and at least one URL")
    target, form = parse_identifier(args[0])
    hits = []
    tested = 0
    for url in args[1:]:
        for label, s in url_variants(url):
            tested += 1
            if docid(s) == target:
                hits.append({"candidate": url, "label": label, "url": s})
    if as_json:
        print(json.dumps({"docid": target, "form": form, "variants_tested": tested, "matches": hits},
                         indent=2))
    else:
        print("docid %d (%s), %d variants tested" % (target, form, tested))
        if not hits:
            print("no match")
        for h in hits:
            print("MATCH  %-28s %s" % (h["label"], h["url"]))
    return 0 if hits else 1


_COMMANDS = {"variants": _cmd_variants, "decode": _cmd_decode, "match": _cmd_match}


_USAGE = (__doc__ or "").partition("Usage:")[2].rstrip() or " python docid.py URL [URL ...]"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage:" + _USAGE, file=sys.stderr)
        return 2
    # "--" ends the options: everything after it is hashed as given (even "decode" or "--json").
    args: list[str] = []
    as_json = literal = forced_url = False
    for a in argv:
        if literal:
            args.append(a)
        elif a == "--":
            literal = True
            forced_url = not args
        elif a in ("-h", "--help"):
            print("usage:" + _USAGE)
            return 0
        elif a == "--json":
            as_json = True
        elif a.startswith("--"):
            print("error: unknown option %s" % a, file=sys.stderr)
            return 2
        else:
            args.append(a)
    command = None if forced_url or not args else _COMMANDS.get(args[0])
    try:
        if command:
            return command(args[1:], as_json)
        return _cmd_url(args, as_json)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    # A console or pipe that cannot encode a character must not abort the output.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    sys.exit(main())
