"""Tests for docid.py. Run with:  python -m unittest -v test_docid

Expected values come from three places:
  1. Published test vectors: Mozc's LegacyFingerprint tests (Google's own port of the same
     lookup2 hash, with Mozc-specific seeds).
  2. Collisions documented in Google's gutil source (hash.h). They reproduce only with the
     internal seeds 0 and 102072, which checks the seeds and the byte handling together.
  3. Page IDs observed on live Google Images result pages (October 2026), whose first
     8 bytes are the docid of the result's source page and whose next 14 bits are a
     checksum of that docid, and a Google Discover card identifier (September 2026).
Other values are regression values computed by this implementation.
"""

import contextlib
import io
import json
import unittest

import docid as d

WIKI = "https://en.wikipedia.org/wiki/ChatGPT"
WIKI_DOCID = 9301487375180519679


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = d.main(list(args))
    return code, out.getvalue(), err.getvalue()


class PublishedVectors(unittest.TestCase):
    """Mozc src/base/hash_test.cc: LegacyFingerprint32 (seed 0xfd12deff), LegacyFingerprint (0x6d6f, 0x7a63)."""

    VECTORS = [
        (b"", 0x0D46D8E3, 0x2DCDBAE1B24D9501),
        (b"google", 0x74290877, 0x56D4AD5EAFA6BEED),
        (b"Hello, world!  Hello, Tokyo!  Good afternoon!  Ladies and gentlemen.",
         0xB0F5A2BA, 0x936CCDDF9D4F0B39),
    ]

    def test_jenkins32(self):
        for data, h32, _ in self.VECTORS:
            self.assertEqual(d.jenkins32(data, 0xFD12DEFF), h32, data)

    def test_fingerprint_with_mozc_seeds(self):
        for data, _, h64 in self.VECTORS:
            self.assertEqual(d.fingerprint(data, 0x6D6F, 0x7A63), h64, data)


class DocumentedCollisions(unittest.TestCase):
    """gutil hash.h: 'Fingerprint() is susceptible to collisions ... Example collisions:
    "01056/02" vs. "11057/02", "LTA 02" vs. "MTA 12"'."""

    PAIRS = [("01056/02", "11057/02"), ("LTA 02", "MTA 12")]

    def test_collide_with_internal_seeds(self):
        for a, b in self.PAIRS:
            self.assertEqual(d.fingerprint(a), d.fingerprint(b), (a, b))
        self.assertEqual(d.fingerprint("01056/02"), 4373384201545180934)
        self.assertEqual(d.fingerprint("LTA 02"), 9154989958582104135)

    def test_each_half_collides_only_with_its_internal_seed(self):
        for a, b in self.PAIRS:
            for seed in (0, 102072):
                self.assertEqual(d.jenkins32(a.encode(), seed), d.jenkins32(b.encode(), seed), (seed, a, b))
            for seed in (0xABC, 0xDEF, 0x6D6F, 0x7A63, 1, 2, 0xFD12DEFF):
                self.assertNotEqual(d.jenkins32(a.encode(), seed), d.jenkins32(b.encode(), seed), (seed, a, b))

    def test_do_not_collide_with_external_or_mozc_seeds(self):
        for seeds in [(0xABC, 0xDEF), (0x6D6F, 0x7A63)]:
            for a, b in self.PAIRS:
                self.assertNotEqual(d.fingerprint(a, *seeds), d.fingerprint(b, *seeds), (seeds, a, b))


class ObservedPageIds(unittest.TestCase):
    """data-lpage / data-ref-docid pairs read on live Google Images result pages (October 2026)."""

    OBSERVED = [
        ("https://en.wikipedia.org/wiki/Lockheed_Martin_F-22_Raptor", "DvLY3kr8C0KWkM"),
        ("https://en.wikipedia.org/wiki/Royal_Australian_Air_Force", "gya2YSzAsyOrpM"),
        ("https://ja.wikipedia.org/wiki/%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB:"
         "Gender_Equality_Center_Yokohama_Minami_2025.jpg", "SPa-AwRoIb_SIM"),
    ]

    def test_page_id_carries_page_docid(self):
        for url, page_id in self.OBSERVED:
            self.assertEqual(d.decode_page_id(page_id), d.docid(url), url)

    def test_page_id_prefix(self):
        for url, page_id in self.OBSERVED:
            self.assertEqual(d.page_id_prefix(d.docid(url)), page_id[:10], url)

    def test_raw_unicode_form_does_not_match(self):
        url, page_id = self.OBSERVED[2]
        raw = "https://ja.wikipedia.org/wiki/ファイル:Gender_Equality_Center_Yokohama_Minami_2025.jpg"
        self.assertEqual(d.percent_encode(raw), url)
        target = d.decode_page_id(page_id)
        self.assertNotEqual(d.fingerprint(raw), target)
        self.assertNotEqual(d.fingerprint(raw, signed_bytes=False), target)
        self.assertEqual(d.docid(d.percent_encode(raw)), target)


class PageIdChecksum(unittest.TestCase):
    """The 14 bits after the docid in a page ID are a checksum of the docid."""

    DISCOVER = ("https://www.20minutes.fr/auto/4247426-20260922-dacia-regle-comptes-europe", "-n9xItu9-16qvM")

    def test_full_page_id_from_url(self):
        for url, observed in ObservedPageIds.OBSERVED + [self.DISCOVER]:
            self.assertEqual(d.page_id(d.docid(url)), observed, url)
            self.assertEqual(d.page_id_status(observed), "valid", observed)

    def test_formula(self):
        self.assertEqual(d.page_id_checksum(WIKI_DOCID), 16247)
        self.assertEqual(d.page_id_checksum(WIKI_DOCID, flip=False), 16247 ^ 64)
        self.assertEqual(d.page_id(WIKI_DOCID), "_1hqgHyFFYH93M")
        self.assertEqual(d.page_id(0), "AAAAAAAAAAABAM")
        self.assertEqual(d.page_id(2**64 - 1), "__________8BAM")
        for value in (0, 1, WIKI_DOCID, 2**64 - 1):
            self.assertEqual(d.decode_page_id(d.page_id(value)), value)

    def test_status(self):
        good = d.page_id(WIKI_DOCID)
        self.assertEqual(d.page_id_status(good), "valid")
        flipped = d._B64URL[d._B64URL.index(good[11]) ^ 1]  # fixed bit = low bit of the 12th character
        variant = good[:11] + flipped + good[12:]
        self.assertEqual(d.decode_page_id(variant), WIKI_DOCID)
        self.assertEqual(d.page_id_status(variant), "variant")
        self.assertEqual(d.page_id_status(good[:12] + "A" + good[13]), "invalid")
        self.assertEqual(d.page_id_status(good[:13] + "Q"), "invalid")
        with self.assertRaises(ValueError):
            d.page_id_status("too short")

    def test_prefix_is_docid_only(self):
        self.assertEqual(d.page_id_prefix(WIKI_DOCID), d.page_id(WIKI_DOCID)[:10])


class ExactStringSemantics(unittest.TestCase):
    """Every written form of an address is a different string, hence a different docid."""

    VARIANTS = {
        "https://en.wikipedia.org/wiki/ChatGPT": 9301487375180519679,
        "https://en.wikipedia.org/wiki/ChatGPT/": 13583687203501448240,
        "http://en.wikipedia.org/wiki/ChatGPT": 7744124899370780516,
        "en.wikipedia.org/wiki/ChatGPT": 15712342959762046648,
        "https://en.m.wikipedia.org/wiki/ChatGPT": 5115253021112119761,
    }

    def test_regression_values(self):
        for url, expected in self.VARIANTS.items():
            self.assertEqual(d.docid(url), expected, url)

    def test_http_vs_https(self):
        self.assertNotEqual(d.docid("http://example.com/"), d.docid("https://example.com/"))

    def test_trailing_slash(self):
        self.assertNotEqual(d.docid("https://example.com/page"), d.docid("https://example.com/page/"))

    def test_case_query_and_fragment(self):
        base = d.docid("https://example.com/page")
        for other in ("https://example.com/Page", "https://example.com/page?a=1",
                      "https://example.com/page#top", "https://EXAMPLE.com/page"):
            self.assertNotEqual(d.docid(other), base, other)

    def test_no_silent_normalization(self):
        url = " https://example.com/ "
        self.assertEqual(d.docid(url), d.fingerprint(url.encode("utf-8")))
        self.assertNotEqual(d.docid(url), d.docid(url.strip()))


class Encoding(unittest.TestCase):

    def test_str_is_utf8(self):
        url = "https://fr.wikipedia.org/wiki/Économie"
        self.assertEqual(d.fingerprint(url), d.fingerprint(url.encode("utf-8")))

    def test_raw_vs_percent_encoded(self):
        raw = "https://fr.wikipedia.org/wiki/Économie"
        enc = "https://fr.wikipedia.org/wiki/%C3%89conomie"
        self.assertEqual(d.percent_encode(raw), enc)
        self.assertNotEqual(d.docid(raw), d.docid(enc))
        self.assertNotEqual(d.docid(enc), d.docid(enc.replace("%C3%89", "%c3%89")))

    def test_signed_bytes_only_matter_for_non_ascii(self):
        ascii_url = "https://example.com/a-long-enough-path-to-fill-several-words"
        self.assertEqual(d.fingerprint(ascii_url), d.fingerprint(ascii_url, signed_bytes=False))
        non_ascii = "https://example.com/été-à-paris"
        self.assertNotEqual(d.fingerprint(non_ascii), d.fingerprint(non_ascii, signed_bytes=False))

    def test_percent_encode_leaves_ascii_alone(self):
        url = "https://example.com/a%20b?q=x&y=%E2%82%AC#f"
        self.assertEqual(d.percent_encode(url), url)


class SixtyFourBitForms(unittest.TestCase):

    def test_signed_unsigned(self):
        self.assertEqual(d.to_signed(WIKI_DOCID), -9145256698529031937)
        self.assertEqual(d.to_unsigned(-9145256698529031937), WIKI_DOCID)
        self.assertEqual(d.to_signed(2**63 - 1), 2**63 - 1)
        self.assertEqual(d.to_signed(2**63), -(2**63))
        self.assertEqual(d.to_signed(2**64 - 1), -1)
        self.assertEqual(d.to_unsigned(-1), 2**64 - 1)
        with self.assertRaises(ValueError):
            d.to_signed(2**64)
        with self.assertRaises(ValueError):
            d.to_signed(-1)
        with self.assertRaises(ValueError):
            d.to_unsigned(-(2**63) - 1)

    def test_parse_identifier(self):
        for text, form in [("9301487375180519679", "unsigned decimal"),
                           ("-9145256698529031937", "signed decimal"),
                           ("0x8115857c806a58ff", "hexadecimal"),
                           ("8115857c806a58ff", "hexadecimal"),
                           ("_1hqgHyFFYH93M", "14-character page ID")]:
            self.assertEqual(d.parse_identifier(text), (WIKI_DOCID, form), text)
        for bad in ("", "abc", "18446744073709551616", "-9223372036854775809", "0x" + "f" * 17,
                    "not a page id!", "DvLY3kr8C0KWk", "٣٤٥"):
            with self.assertRaises(ValueError, msg=bad):
                d.parse_identifier(bad)

    def test_zero_and_one_are_reserved(self):
        self.assertEqual(d._combine_halves(0, 0), 0x130F9BEF94A0A928)
        self.assertEqual(d._combine_halves(0, 1), 0x130F9BEF94A0A929)
        self.assertEqual(d._combine_halves(0, 2), 2)
        self.assertEqual(d._combine_halves(1, 0), 1 << 32)


class Errors(unittest.TestCase):

    def test_bad_types(self):
        with self.assertRaises(TypeError):
            d.docid(b"https://example.com/")
        with self.assertRaises(TypeError):
            d.fingerprint(12345)

    def test_empty(self):
        with self.assertRaises(ValueError):
            d.docid("")
        with self.assertRaises(ValueError):
            d.url_variants("")


class Variants(unittest.TestCase):

    def test_first_is_exact_input_and_unique(self):
        url = "http://www.example.com/a/?utm_source=x&amp;b=1#top"
        variants = d.url_variants(url)
        self.assertEqual(variants[0], ("as given", url))
        strings = [s for _, s in variants]
        self.assertEqual(len(strings), len(set(strings)))
        self.assertIn("https://example.com/a", strings)
        self.assertIn("http://www.example.com/a/?utm_source=x&b=1#top", strings)

    def test_match_finds_the_indexed_form(self):
        code, out, _ = run_cli("match", str(WIKI_DOCID), "http://www.en.wikipedia.org/wiki/ChatGPT/")
        self.assertEqual(code, 0)
        self.assertIn("MATCH", out)
        self.assertIn(WIKI, out)

    def test_labels_are_relative_to_the_input(self):
        variants = d.url_variants("HTTPS://EXAMPLE.COM/A?")
        self.assertEqual([label for label, _ in variants].count("as given"), 1)
        self.assertIn(("lowercase", "https://example.com/a?"), variants)
        self.assertIn(("empty ? or # removed", "HTTPS://EXAMPLE.COM/A"), variants)

    def test_schemeless_input_gets_https(self):
        variants = d.url_variants("en.wikipedia.org/wiki/ChatGPT")
        self.assertIn(("https:// added", WIKI), variants)
        code, out, _ = run_cli("match", str(WIKI_DOCID), "en.wikipedia.org/wiki/ChatGPT")
        self.assertEqual(code, 0)
        self.assertIn("https:// added", out)

    def test_match_reports_no_match(self):
        code, out, _ = run_cli("match", str(WIKI_DOCID), "https://example.com/")
        self.assertEqual(code, 1)
        self.assertIn("no match", out)


class Cli(unittest.TestCase):

    def test_url(self):
        code, out, _ = run_cli(WIKI)
        self.assertEqual(code, 0)
        self.assertIn(str(WIKI_DOCID), out)
        self.assertIn("-9145256698529031937", out)
        self.assertIn("8115857c806a58ff", out)

    def test_json(self):
        code, out, _ = run_cli("--json", WIKI)
        self.assertEqual(code, 0)
        rec = json.loads(out)[0]
        self.assertEqual(rec["unsigned"], WIKI_DOCID)
        self.assertEqual(rec["signed"], -9145256698529031937)

    def test_decode(self):
        code, out, _ = run_cli("decode", "--json", "DvLY3kr8C0KWkM")
        self.assertEqual(code, 0)
        rec = json.loads(out)
        self.assertEqual(rec["unsigned"], d.docid("https://en.wikipedia.org/wiki/Lockheed_Martin_F-22_Raptor"))
        self.assertEqual(rec["checksum"], "valid")
        code, out, _ = run_cli("decode", "DvLY3kr8C0KWAM")
        self.assertEqual(code, 0)
        self.assertIn("does not match", out)

    def test_url_prints_page_id(self):
        code, out, _ = run_cli(WIKI)
        self.assertEqual(code, 0)
        self.assertIn("_1hqgHyFFYH93M", out)

    def test_non_ascii_note(self):
        code, out, _ = run_cli("https://fr.wikipedia.org/wiki/Économie")
        self.assertEqual(code, 0)
        self.assertIn("%C3%89conomie", out)

    def test_double_dash_hashes_literally(self):
        code, out, _ = run_cli("--", "decode")
        self.assertEqual(code, 0)
        self.assertIn(str(d.fingerprint("decode")), out)

    def test_help_anywhere(self):
        self.assertEqual(run_cli("decode", "-h")[0], 0)
        self.assertEqual(run_cli("--help")[0], 0)

    def test_parse_identifier_type(self):
        with self.assertRaises(TypeError):
            d.parse_identifier(9301487375180519679)

    def test_errors(self):
        self.assertEqual(run_cli("")[0], 2)
        self.assertEqual(run_cli("decode", "xyz")[0], 2)
        self.assertEqual(run_cli("--unknown", WIKI)[0], 2)
        self.assertEqual(run_cli()[0], 2)


if __name__ == "__main__":
    unittest.main()
