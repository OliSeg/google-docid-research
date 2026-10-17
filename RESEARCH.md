# Google docids are URL fingerprints: research note

This note documents the evidence behind [README.md](README.md). Each statement carries one of three labels:

- **[Observed]** read directly in Google data or in public source code;
- **[Validated]** computed and checked against Google data, exactly, on all 64 bits;
- **[Interpretation]** our reading of the observations. It may be wrong.

Contents:
[1. Question and findings](#1-research-question-and-findings) ·
[2. The algorithm](#2-the-fingerprint-algorithm) ·
[3. 64-bit arithmetic](#3-signed-and-unsigned-64-bit-arithmetic) ·
[4. Validation](#4-validation-results-and-their-limitations) ·
[5. Across Google products](#5-differences-across-google-products) ·
[6. Gemini](#6-gemini-a-separate-case) ·
[7. Applications](#7-practical-applications) ·
[8. Open questions](#8-open-questions-and-future-work)

## 1. Research question and findings

**Question.** Google Search exposes 64-bit document identifiers (docids) in some of the data it sends to
browsers and apps. Are they arbitrary internal numbers, or can they be computed from public information?

**Findings.**

1. **[Validated]** The docid of a web document is Google's legacy `Fingerprint()` of its URL string,
   with the seeds 0 and 102072 published in Google's `gutil` library. It matched 49,767 of 49,767 results
   in 2023 Google Search data (28,898 distinct URL–docid pairs).
2. **[Validated]** The function is unchanged in 2026: it resolves page IDs in Google Images (1,377 /
   1,380 on live result pages, October 2026), card identifiers in Google Discover (1,482 / 1,545 distinct
   values), Google News article docids and the docids listed in a live Search results page.
3. **[Validated]** The input is the exact URL string. Each written form of an address has its own
   docid; non-ASCII characters are hashed in percent-encoded UTF-8 form.
4. **[Observed]** Several Google identifiers are *not* URL fingerprints: Shopping offer and product IDs,
   Maps place IDs, and the identifiers Gemini attached to its sources.
5. **[Observed]** In Gemini, the identifier of a cited page was issued anew for each response, even for an
   unchanged page and even when the same question was asked again (0 of 582 regenerated responses
   reused an identifier, 72 of them less than an hour apart).

## 2. The fingerprint algorithm

### 2.1 Definition

Google's `gutil` library defines (`hash.cc`, `hash.h`, `jenkins.cc`, `jenkins_lookup2.h` in
[Apache Kudu](https://github.com/apache/kudu/tree/master/src/kudu/gutil/hash)):

```text
Fingerprint(s) = CombineFingerprintHalves(Hash32StringWithSeed(s, 0),
                                          Hash32StringWithSeed(s, 102072))

CombineFingerprintHalves(hi, lo):
    r = hi << 32 | lo
    if hi == 0 and lo < 2: r ^= 0x130f9bef94a0a928
    return r
```

`Hash32StringWithSeed` is Bob Jenkins' lookup2 (1996): three 32-bit registers
`a = b = 0x9e3779b9` (golden ratio) and `c = seed`; the input is consumed in 12-byte blocks added to
`a`, `b`, `c` as little-endian words, each block followed by the `mix` function; the length is added to
`c`, the last 0–11 bytes are added (whole words as words, leftover bytes one by one), and a final `mix`
returns `c`.

```text
mix(a, b, c):                     (all arithmetic modulo 2^32)
  a -= b; a -= c; a ^= c >> 13
  b -= c; b -= a; b ^= a << 8
  c -= a; c -= b; c ^= b >> 13
  a -= b; a -= c; a ^= c >> 12
  b -= c; b -= a; b ^= a << 16
  c -= a; c -= b; c ^= b >> 5
  a -= b; a -= c; a ^= c >> 3
  b -= c; b -= a; b ^= a << 10
  c -= a; c -= b; c ^= b >> 15
```

### 2.2 What makes Google's variant specific

- **[Observed]** Full 4-byte words are read with signed bytes (`Google1At`): the source explains that
  "long ago, the 32-bit version of this operation was implemented using signed characters" and that the
  function "needs to remain backwards compatible" because its values are persisted. `jenkins.cc` calls
  this "the google1 implementation". This applies to every full word, including those of the final
  block; only the 1 to 3 leftover bytes that do not fill a word are read unsigned.
- **[Observed]** The seeds 0 and 102072 apply when `EXTERNAL_FP` is not defined. Code shipped outside
  Google, "notably the Google Search Appliance", uses 0xabc and 0xdef instead, so that "attackers cannot
  mount offline attacks to find collisions with google.com internal fingerprints (most importantly, for
  URL fingerprints)".
- **[Observed]** `hash.h` deprecates the function for new code because of "excess collisions" and gives
  two examples: `"01056/02"` / `"11057/02"` and `"LTA 02"` / `"MTA 12"`.

### 2.3 Checks of the implementation that use no data of ours

| Check | Result |
|---|---|
| Mozc's published `LegacyFingerprint32` / `LegacyFingerprint` test values (Mozc seeds) | 3 / 3 strings, both functions |
| The two collisions listed in `hash.h`, with seeds 0 and 102072 | both reproduced, on each 32-bit half separately |
| The same collisions with the external seeds (0xabc, 0xdef), Mozc's seeds, or seeds 1, 2 | none |

The collisions are specific to the seeds: among the seeds tested, they reproduce only with 0 and 102072.
Reproducing both, on both halves, by chance with a wrong implementation or wrong seeds would have a
probability near 2<sup>-64</sup> per pair.

## 3. Signed and unsigned 64-bit arithmetic

### 3.1 Writing the same 64 bits

| Form | Where we saw it | `https://en.wikipedia.org/wiki/ChatGPT` |
|---|---|---|
| unsigned decimal | Search and Discover data | `9301487375180519679` |
| signed decimal (two's complement int64) | Gemini source identifiers, some Shopping data | `-9145256698529031937` |
| hexadecimal | — | `8115857c806a58ff` |
| 8 bytes little-endian, URL-safe base64, inside a 14-character page ID | Google Images (`data-ref-docid`), Discover | `_1hqgHyFFY…` |

`signed = unsigned − 2^64` when `unsigned ≥ 2^63`. The tool prints all forms and `decode` reads any of
them.

The 14-character page ID holds 13 base64 characters of data (78 bits) and a final character that was `M`
in all 183 IDs we checked. The first 64 bits are the docid, little-endian. **[Observed]** The remaining 14
bits are identical for all images of the same page (7 images of one page, same value), differ between
pages of the same site, and are not reproduced from the docid or the URL by any function we tested.

### 3.2 Signed bytes and non-ASCII URLs

Signed and unsigned byte reading give the same result for ASCII input and different results as soon as a
full word contains a byte ≥ 0x80.

- **[Observed]** All URLs in the 2023 data were ASCII (non-ASCII characters percent-encoded), so that
  data cannot tell the two readings apart.
- **[Validated]** We then looked for every identifier in our data that resolves to a URL
  containing non-ASCII characters, written raw or percent-encoded. 95 identifiers resolved, all to the
  **percent-encoded UTF-8 form** (`%E3%83%95…`, upper-case hex). None matched the raw Unicode bytes, with
  signed or unsigned reading.
- **Consequence.** In practice, URLs are hashed as percent-encoded ASCII and the byte-reading question does
  not arise. The implementation follows `gutil` (signed words) and keeps an unsigned option for
  experiments (`fingerprint(..., signed_bytes=False)`).

## 4. Validation results and their limitations

Validation was performed against an independently assembled research corpus; acquisition details are
outside the scope of this release. No raw data is published.

### 4.1 2023 Google Search results data

- **[Validated]** For each displayed result, the fingerprint of its URL equals a docid present in the
  same Google response: **49,767 of 49,767 results**, no exception, no non-matching URL.
- 28,898 distinct docids ↔ 28,898 distinct URLs. 10,658 docids appear in several responses, always
  with the same URL.
- **[Validated]** An independent re-check on 79 randomly drawn responses confirmed 765 of 765 results.
  (This is a re-check of the same corpus, not additional data.)
- Protocols in the pairs: 28,469 https, 428 http, 1 ftp.

### 4.2 Elimination of other functions

3,000 pairs drawn at random from the 28,898; 152,663 string forms of their URLs; 16.6 million 64-bit values
computed. Each value was compared with the pair's docid as is, byte-reversed, and half by half (32 bits).

| Function | Pairs matched |
|---|---|
| **Google `Fingerprint`, seeds 0 / 102072 (signed or unsigned bytes), exact URL** | **3,000 / 3,000** |
| Same function, external seeds 0xabc / 0xdef | 0 |
| Same function, Mozc seeds; seeds swapped (102072 / 0) | 0 |
| FarmHash Fingerprint64, Hash64, Hash64WithSeed (9 seeds), Fingerprint128 / Hash128 halves, 32-bit variants (two implementations) | 0 |
| CityHash64 / 64WithSeed / 128 / Crc128, versions 1.0.1 to 1.1.1, each checked against its own official test | 0 |
| CityHash64 variant in Google's `gutil` | 0 |
| Fingerprint2011 (port checked against Guava's test values) | 0 |
| MurmurHash64A, MurmurHash3 (x64-128, x86-128 halves, 32-bit) | 0 |
| FNV-1, FNV-1a 64-bit | 0 |
| MD5, SHA-1, SHA-256 truncated to 64 bits (first and last 8 bytes, both byte orders) | 0 |

### 4.3 Which string is hashed

- **[Validated]** Only the exact URL as displayed matches. None of these forms matched, with any
  function: without scheme, `//` only, other scheme, with or without `www`, with or without trailing
  slash, without query or fragment, lowercase, decoded, re-encoded, strictly encoded, reversed host in
  Bigtable row-key style (`com.example.www/path`, with or without `:https`), host only, path only, UTF-16.
- **[Observed]** Different forms of one address are separate identifiers. Among 3,000 sampled addresses,
  41 also had another form (most often without query parameters, sometimes lowercase, without trailing
  slash, with `www` or with `http`) whose fingerprint appeared elsewhere in the same dataset. One example:
  `https://developer.android.com/studio/build/dependencies` and the same URL with `?hl=zh-cn` appeared
  as two documents with two docids.
- **[Observed]** No site structure: docids of two pages of the same site share no more leading bits than
  docids of unrelated sites (0.93 vs 1.00 bit on average). The docid is not a site prefix plus a page
  number.

### 4.4 2026 data

| Surface | Identifier | Result |
|---|---|---|
| Google Images, live result pages (October 2026) | `data-ref-docid` page IDs vs `data-lpage` | 1,377 / 1,380 |
| Other Google Images surfaces, including images in "People also ask" answers and in AI Mode, data from several years | page IDs | 164 / 166 testable |
| Google Discover (September–October 2026) | 14-character card identifiers | 1,482 / 1,545 distinct values (96 %) |
| Google Discover | decimal docids on cards | 140 resolved |
| Google News | article docids | 54 resolved |
| Google's store pages for merchants | video docids | 26 / 26 |
| A live Search results page (September 2026) | ordered docids of its 10 web results | 7 / 10 (3 URLs absent from the captured data) |
| Google app results page with AI Mode (2026) | docid of each web result card | 8 resolved |

Notes:

- "Resolved" means a candidate URL reproduced the identifier on all 64 bits. Unresolved values are values
  for which we had no matching candidate URL, not counter-examples.
- **[Observed]** For images in "People also ask" answers, the page docid is that of the source URL
  *without* its `#:~:text=` fragment when it has one (of 55 resolved, 34 matched the URL as displayed
  and 21 only without the fragment); elsewhere, the URL as displayed.
- **[Observed]** In Discover, in 64 cases a card displayed a URL with tracking parameters while its
  identifier matched the bare URL.
- **[Observed]** The 3 pages we saw both in a Discover card and in Google Images had exactly the same
  14-character page ID, extra bits included.

### 4.5 Limitations

- The validated docids belong to documents that Google displayed. Google's own documentation says the docid
  is "usually fingerprint of URL, but not always"; we did not observe an exception, but exceptions may exist
  for documents we did not see.
- Non-ASCII behavior rests on 95 cases. Internationalized host names (Unicode vs punycode) and lower-case
  percent-encoding were not tested.
- A docid can be traced back to its URL only by testing candidates. The function cannot be inverted.
- The data shows identifiers sent to clients. It does not show how they are used inside Google.

## 5. Differences across Google products

| Product | Identifier | URL fingerprint? | Detail |
|---|---|---|---|
| Search (web results) | docid | **yes** | 2023 and 2026 |
| Google Images | page ID (`data-ref-docid`) | **yes**, first 64 bits | extra 14 bits unexplained |
| Google Images | image ID (`tbnid`, `imgdii`, `data-tbnid`) | no | not the fingerprint of the image URL (0 / 22, 0 / 49); `data-docid` is a page ID on some surfaces and an image ID on others |
| Discover | card identifier, decimal docid | **yes** | `content_numeric_id` is not (0 / 788) |
| Google News | article docid | **yes** | |
| Google Shopping | offer, product, catalog, image IDs | no | 0 / 2,071 explicit offer ↔ merchant URL pairs |
| Google Maps | CID (`ludocid`) | no | 0 / 14,899 candidate URLs; **[Observed]** the CID is the second half of the place ID `0x…:0x…` (2,512 / 2,512) |
| AI Overviews, AI Mode | source cards | no identifier | no 64-bit value next to sources (0 / 4,729 numbers); images shown in AI Mode carry their page ID |
| "People also ask" | 14-bit value per question | no | follows the source page (fragment ignored); no function we tested reproduces it from the docid, and no lookup2 seed reproduces it from the URL (all 2<sup>32</sup> seeds tried) |
| Gemini | source `docid` | no | issued per response, see section 6 |

**[Interpretation]** Search, Images, Discover and News share one document key: the fingerprint of the
document's URL. This is consistent with a common index of web documents behind these surfaces. Shopping
and Maps use their own catalogs of identifiers.

## 6. Gemini: a separate case

Data: more than 16,000 Gemini responses with at least one identified source, April 2025 to May 2026
(94,887 citations of 58,642 distinct URLs).

### 6.1 Observations

- **[Validated]** The `docid` attached to sources is not the URL fingerprint: 0 of 85,485 distinct
  (URL, identifier) pairs, for any URL variant, byte order or 32-bit half. 7 % of URLs carry several
  identifiers, which rules out any function of the URL alone.
- **[Observed]** It is issued per response. Among 90,666 pairs of *different* responses citing the same
  page, 10 share an identifier, and 9 of those are a follow-up turn reusing the previous turn's sources
  within the same conversation.

| Pair of responses citing the same page | Pairs | Same identifier |
|---|---|---|
| duplicate records of one response | 95 | 95 (100 %) |
| same question, regenerated response | 582 | 0 (72 of them less than an hour apart) |
| two responses in one conversation | 3,926 | 9 (0.2 %), all less than an hour apart |
| responses in two different conversations | 86,158 | 1 |

- **[Observed]** Unchanged pages also get new identifiers. For 24 English Wikipedia pages cited in two
  responses a median 28 minutes apart, the public revision history shows no edit between the two responses
  for 23 of them. Example: the article "Macintosh 128K", cited twice 3 minutes apart on 16 July 2025, last
  edited on 25 June 2025, received two different identifiers.
- **[Observed]** Within one response, the citations of a page share one identifier in general (15,929
  cases; 26 responses have two identifiers for the same page).
- **[Observed]** Not a counter or a timestamp: a newer identifier is larger than the older one in 49.9 % of
  cases, and identifiers of the same response share no more leading bits than random ones.
- **[Observed]** The identifier only exists in the older source format that showed a support score for each
  cited sentence: 96.6 % of sources in that format, none in the newer format. It was present in 100 % of
  sources until November 2025 and disappeared in May–June 2026 (a handful of later responses still use
  the older format).

### 6.2 Interpretation

**[Interpretation]** Gemini numbered the documents of a list built for each response; the number linked
sentences to sources (and to their support scores) and was reused only when a follow-up turn reused the
same list. Search identifies a page permanently by its URL; Gemini, in this period, did not. This is
consistent with a separate serving path for grounding Gemini's responses. It does not identify that system,
the index it uses, or whether pages were read live.

## 7. Practical applications

For technical SEO and search research:

- **Which URL form does Google hold?** Where Google exposes a docid (Images page IDs, Discover cards,
  results data), `docid.py match` tells which form of a URL it belongs to: protocol, `www`, trailing slash,
  parameters, fragment.
- **Joining data across products.** Use the docid as a key to follow one document across Search, Images,
  Discover and News, independently of how each surface writes the URL.
- **Recognizing docids in captured data.** Any 64-bit number in a HAR file, an app capture or an export can
  be tested against candidate URLs, in its signed, unsigned, hex or base64 form.
- **Reading documentation.** Fields named docid or URL fingerprint in Google's published or leaked
  documentation can now be related to actual URLs.

Not possible: recovering a URL from a docid without candidates; inferring rank, quality, crawl date or
site from a docid.

## 8. Open questions and future work

1. Which documents have a docid that is *not* the fingerprint of their URL ("usually fingerprint of URL,
   but not always")?
2. What do the extra 14 bits of Images and Discover page IDs encode? They follow the page, not the image.
3. What is the 14-bit per-question value in "People also ask"? It follows the source page, but no function
   we tested reproduces it from the docid.
4. How are internationalized host names hashed (Unicode or punycode)?
5. **[Interpretation, to test]** The Discover and "People also ask" cases suggest that the docid is computed
   on the URL Google retained for the document (without tracking parameters or fragments), not on the
   link as displayed. A systematic test on pages with known canonical URLs would confirm or refute it.
6. Does Gemini still number its sources per response since the identifier left the visible data in
   May–June 2026?

## Responsible use

The algorithm and the seeds have been public in open-source code for years; this release documents where
they apply. We publish no collision-search tool. The fingerprint is not collision resistant and must not be
used as a unique or security identifier. No personal data is included: example URLs are public pages.

## References

- Bob Jenkins, lookup2 and "A Hash Function for Hash Table Lookup":
  [burtleburtle.net/bob/hash/evahash.html](http://burtleburtle.net/bob/hash/evahash.html)
- Apache Kudu, `src/kudu/gutil/hash/`:
  [github.com/apache/kudu](https://github.com/apache/kudu/tree/master/src/kudu/gutil/hash)
- Mozc, `src/base/hash_test.cc`:
  [github.com/google/mozc](https://github.com/google/mozc/blob/master/src/base/hash_test.cc)
- Google Content Warehouse API documentation, `GDocumentBase`:
  [google-api-content-warehouse.hexdocs.pm](https://google-api-content-warehouse.hexdocs.pm/0.4.0/GoogleApi.ContentWarehouse.V1.Model.GDocumentBase.html)
