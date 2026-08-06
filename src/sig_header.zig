const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Operations on a DKIM/ARC signature header field's tag list.
///
/// Shared by `securedkim` (DKIM-Signature) and `securearc` (ARC-Message-Signature,
/// ARC-Seal) because all three carry the same `tag=value; tag=value` list defined
/// by RFC 6376 §3.2, and both daemons need the same operation on it.
/// Return a copy of `header` with the `b=` tag's value removed, leaving `b=`.
///
/// Every signature covers itself with its own `b=` emptied (RFC 6376 §3.7), so a
/// verifier must reproduce this byte for byte or the hash cannot match. Only the
/// value is removed: the tag, the surrounding delimiters, and every other byte --
/// including folding whitespace -- are preserved exactly, because the result is
/// canonicalized and hashed.
///
/// The tag list is walked properly rather than scanned for the text "b=", which
/// is what the two previous copies of this function did. Scanning cannot tell the
/// `b` tag from the same two characters occurring inside another tag's value, and
/// both copies got the surrounding-context test wrong in different ways:
///
///   - `securedkim` required the preceding non-whitespace byte to be `;`, but
///     skipped only spaces and tabs when looking for it. A folded signature puts
///     CRLF before the fold whitespace, so the scan stopped on the LF, concluded
///     it was not looking at the `b` tag, and left the value in place. Since a
///     2048-bit signature is 344 base64 characters and cannot share a line with
///     the other tags inside RFC 5322's limits, essentially every signature sent
///     by a real signer folds -- and none of them could be verified.
///   - `securearc` handled folding but accepted any non-letter before the `b`,
///     so a `:` would do. `z=` (RFC 6376 §3.5) carries copied header fields and
///     legitimately contains colons, so `z=From:x|Subject:b=y` would have matched
///     inside the `z` value and truncated the rest of the signature.
///
/// Neither daemon had a test with a folded signature, because the only signatures
/// either had ever been given came from this suite's own signer, which emits one
/// unfolded line.
pub fn emptyBValue(allocator: Allocator, header: []const u8) ![]u8 {
    const span = findBValue(header) orelse return allocator.dupe(u8, header);

    var result = try allocator.alloc(u8, header.len - (span.end - span.start));
    @memcpy(result[0..span.start], header[0..span.start]);
    @memcpy(result[span.start..], header[span.end..]);
    return result;
}

/// Why a tag list is not a valid RFC 6376 §3.2 tag-list.
pub const TagListError = error{
    /// No tag-spec at all, or only separators.
    EmptyTagList,
    /// A tag-spec with no "=".
    MissingEquals,
    /// A tag-name that is not ALPHA *ALNUMPUNC.
    InvalidTagName,
    /// The same tag-name twice. §3.2 invalidates the whole list, not the tag.
    DuplicateTagName,
    /// More tags than TAG_LIMIT. A bound on the duplicate scan, not a spec rule.
    TooManyTags,
};

/// Upper bound on tag-specs in one list.
///
/// Not an RFC limit — the ABNF permits any number. It exists because duplicate
/// detection compares each tag-name against those already seen, which is
/// quadratic, and a header is only bounded by `MaxHeaderBytes` (1 MB by default).
/// A megabyte of `a;a;a;…` would be roughly 5·10^5 tags and 10^11 comparisons.
/// A legitimate DKIM or ARC signature carries around a dozen tags, so 128 leaves
/// an order of magnitude of headroom while keeping the scan trivial. Same
/// reasoning as the `MaxSignatures` and `MaxHeaders` caps in the lib.
pub const TAG_LIMIT = 128;

/// Validate a tag list against RFC 6376 §3.2, strictly.
///
///     tag-list  =  tag-spec *( ";" tag-spec ) [ ";" ]
///     tag-spec  =  [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]
///     tag-name  =  ALPHA *ALNUMPUNC
///     ALNUMPUNC =  ALPHA / DIGIT / "_"
///
/// plus the prose requirement in the same section: "Tags with duplicate names
/// MUST NOT occur within a single tag-list; if a tag name does occur more than
/// once, the entire tag-list is invalid."
///
/// **Tag names are case sensitive here, unlike DMARC.** §3.2 says "Tags MUST be
/// interpreted in a case-sensitive manner", so `S=` is not `s=` — it is an
/// unrecognised tag, and a signature relying on it is missing its selector. That
/// difference is why this lives beside the DKIM/ARC helpers and is *not* shared
/// with `securedmarc`, whose RFC 9989 §4.7 tag names are case *insensitive*.
///
/// An empty tag-value is accepted: the ABNF makes `tag-value` optional, so `a=;`
/// is syntactically valid. Whether an empty value is *meaningful* belongs to the
/// tag's own semantics — `a=` with no algorithm is rejected where the algorithm
/// is chosen, not here — and conflating the two would make this function the
/// place every tag's rules accumulate.
///
/// A single trailing `;` is allowed because the ABNF's `[ ";" ]` allows it. An
/// interior empty tag-spec (`a=1;;b=2`) is not: that is a `tag-spec` with no
/// `tag-name`.
pub fn validateTagList(tag_list: []const u8) TagListError!void {
    var names: [TAG_LIMIT][]const u8 = undefined;
    var count: usize = 0;

    var rest = tag_list;
    while (true) {
        const semi = mem.indexOfScalar(u8, rest, ';');
        const spec_raw = if (semi) |s| rest[0..s] else rest;
        const spec = mem.trim(u8, spec_raw, &FWS);

        if (spec.len == 0) {
            // Empty spec. Legal only as the optional trailing ";" -- that is,
            // when nothing but whitespace follows it.
            const tail = if (semi) |s| rest[s + 1 ..] else "";
            if (mem.trim(u8, tail, &FWS).len == 0) break;
            return error.InvalidTagName;
        }

        const eq = mem.indexOfScalar(u8, spec, '=') orelse return error.MissingEquals;
        const name = mem.trim(u8, spec[0..eq], &FWS);
        if (name.len == 0) return error.InvalidTagName;
        if (!isAlpha(name[0])) return error.InvalidTagName;
        for (name[1..]) |c| {
            if (!isAlpha(c) and !isDigit(c) and c != '_') return error.InvalidTagName;
        }

        if (count == TAG_LIMIT) return error.TooManyTags;
        for (names[0..count]) |seen| {
            if (mem.eql(u8, seen, name)) return error.DuplicateTagName;
        }
        names[count] = name;
        count += 1;

        if (semi) |s| rest = rest[s + 1 ..] else break;
    }

    if (count == 0) return error.EmptyTagList;
}

/// Value of one tag in a semicolon-separated tag-list, or null if absent.
///
/// `validateTagList` says whether a list is *legal*; this reads one value out of
/// it. Both are here because both are RFC 6376 §3.2, and a caller that wants a
/// selector out of an ARC-Seal or a `p=` out of a DNS key record should not be
/// writing its own scanner to get it.
///
/// **Tag names are matched case sensitively.** §3.2: "Tags MUST be interpreted
/// in a case-sensitive manner." This differs from DMARC, whose RFC 9989 §4.7 tag
/// names are case *insensitive*, so the two must not share a tag scanner.
///
/// The difference is load-bearing rather than pedantic. Matching case
/// insensitively made `S=dummy` satisfy a lookup for `s`, so an ARC-Seal whose
/// selector tag was mis-cased was read as carrying a selector and went on to
/// verify -- where the RFC has no `s=` tag at all and the seal cannot be checked.
/// Applies equally to the `p=` lookup in a DKIM key record, which is the same
/// kind of tag list.
///
/// Lenient where `validateTagList` is strict: it takes the first match and does
/// not reject a duplicate. That division is deliberate. A caller that must refuse
/// a malformed list calls the validator first -- `securearc` does, on every set
/// it parses -- and one that is *reporting* on a record an operator handed it
/// should say what is in there rather than refuse to look.
///
/// It trims `std.ascii.whitespace`, which is a wider set than the `FWS` its
/// neighbour above uses: it also strips VT and FF, which RFC 5234 does not make
/// whitespace. Kept exactly as it arrived from `securearc/src/arc.zig` so this
/// move changes no behaviour. Narrowing it to `FWS` would make a key record
/// carrying `p=<VT>AAAA` stop matching, which is a correctness change and wants
/// its own commit and its own test, not a line inside a deduplication.
pub fn findTag(header_value: []const u8, tag_name: []const u8) ?[]const u8 {
    var rest = header_value;
    while (rest.len > 0) {
        rest = mem.trimLeft(u8, rest, &(.{';'} ++ FWS));
        if (rest.len == 0) break;

        const eq_pos = mem.indexOfScalar(u8, rest, '=') orelse break;
        const name = mem.trim(u8, rest[0..eq_pos], &std.ascii.whitespace);

        const value_start = eq_pos + 1;
        const semi_pos = mem.indexOfScalar(u8, rest[value_start..], ';');
        const value_end = if (semi_pos) |sp| value_start + sp else rest.len;
        const value = mem.trim(u8, rest[value_start..value_end], &std.ascii.whitespace);

        if (mem.eql(u8, name, tag_name)) return value;
        rest = if (semi_pos) |sp| rest[value_start + sp + 1 ..] else "";
    }
    return null;
}

const FWS = [_]u8{ ' ', '\t', '\r', '\n' };

fn isAlpha(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z');
}

fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

/// Byte range of the `b=` tag's value within a signature header field.
pub const ValueSpan = struct {
    /// First byte of the value, immediately after the `=`.
    start: usize,
    /// One past the last byte, at the `;` that ends the tag or at end of input.
    end: usize,
};

/// Locate the `b=` tag's value, or null when the field carries no `b` tag.
///
/// Exposed separately because a caller that needs to know the signature's own
/// bytes -- rather than a copy with them removed -- should not have to find them
/// a second time with different rules.
pub fn findBValue(header: []const u8) ?ValueSpan {
    var i = tagListStart(header);

    while (i < header.len) {
        // A tag runs to the next ';'. RFC 6376 §3.2 excludes ';' from tag values,
        // which is exactly why `z=` uses '|' to separate the fields it copies, so
        // this delimiter is unambiguous.
        var tag_end = i;
        while (tag_end < header.len and header[tag_end] != ';') : (tag_end += 1) {}

        if (mem.indexOfScalar(u8, header[i..tag_end], '=')) |rel_eq| {
            const eq = i + rel_eq;
            // FWS is permitted around the name and the '=' (RFC 6376 §3.2), and a
            // folded field puts CRLF in it, so all four bytes are trimmed.
            const name = mem.trim(u8, header[i..eq], " \t\r\n");
            if (mem.eql(u8, name, "b")) {
                return .{ .start = eq + 1, .end = tag_end };
            }
        }

        i = tag_end + 1;
    }

    return null;
}

/// Index at which the tag list begins.
///
/// Accepts a whole header field (`DKIM-Signature: v=1; ...`) or a bare tag list
/// (`v=1; ...`): callers legitimately have both, and guessing wrong would either
/// treat the field name as a tag or lose a tag to the field name.
fn tagListStart(header: []const u8) usize {
    for (header, 0..) |c, i| {
        switch (c) {
            // A colon reached before any tag punctuation ends the field name.
            ':' => return i + 1,
            // Either of these means the tag list has already started, so there
            // was no field name. Checked because `h=` and `z=` values contain
            // colons of their own.
            '=', ';' => return 0,
            else => {},
        }
    }
    return 0;
}

// =============================================================================
// Tests
// =============================================================================

test "emptyBValue removes a single-line value" {
    const allocator = std.testing.allocator;
    const input = "DKIM-Signature: v=1; a=rsa-sha256; bh=abc; b=LONGSIGNATUREDATA; d=example.com";
    const got = try emptyBValue(allocator, input);
    defer allocator.free(got);
    try std.testing.expectEqualStrings(
        "DKIM-Signature: v=1; a=rsa-sha256; bh=abc; b=; d=example.com",
        got,
    );
}

test "emptyBValue removes a value that ends the field" {
    const allocator = std.testing.allocator;
    const got = try emptyBValue(allocator, "v=1; d=x.com; b=SIGDATA");
    defer allocator.free(got);
    try std.testing.expectEqualStrings("v=1; d=x.com; b=", got);
}

test "emptyBValue removes a folded value, preserving every other byte" {
    // The defect this function was written to fix. Taken from a Gmail signature:
    // the value is folded across lines and the `b` tag itself begins on a
    // continuation line, so the byte before it is LF, not ';'.
    const allocator = std.testing.allocator;
    const input =
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n" ++
        "        d=gmail.com; s=20251104; t=1785286164;\r\n" ++
        "        bh=RB2AQ0D4ARDFvoQp2Bgi8OrVisGN68KqDmvHo/VHKYo=;\r\n" ++
        "        b=iUaeIuhmM0NCOi7FaFQv6x4D+2O9quF9sq3XJGsqEhu3HCr9a+8q0NBPGvKpWw5iXS\r\n" ++
        "         D3yjKETYyqq7dnaskh3oRaBh9G9PLV2ImPslwW+2v3hJW2+82zBb0R5pqEuZJtykHMxM\r\n" ++
        "         Pfhg==";

    const got = try emptyBValue(allocator, input);
    defer allocator.free(got);

    // Folding and indentation ahead of the b tag are untouched; only the value
    // is gone. The trailing CRLF of the previous line stays, so canonicalization
    // sees the same shape it would have seen.
    try std.testing.expectEqualStrings(
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n" ++
            "        d=gmail.com; s=20251104; t=1785286164;\r\n" ++
            "        bh=RB2AQ0D4ARDFvoQp2Bgi8OrVisGN68KqDmvHo/VHKYo=;\r\n" ++
            "        b=",
        got,
    );
}

test "emptyBValue keeps tags that follow a folded value" {
    // Google's ARC-Message-Signature puts darn= after b=, so the value must be
    // cut at its ';' and not to the end of the field.
    const allocator = std.testing.allocator;
    const input =
        "ARC-Message-Signature: i=1; a=rsa-sha256;\r\n" ++
        "        b=SHnvF1ROqEgUVqr9TIeUrXKis1Uw4RB2vmkTWdmr/7kD\r\n" ++
        "         EDuA==;\r\n" ++
        "        darn=morante.net";

    const got = try emptyBValue(allocator, input);
    defer allocator.free(got);
    try std.testing.expectEqualStrings(
        "ARC-Message-Signature: i=1; a=rsa-sha256;\r\n" ++
            "        b=;\r\n" ++
            "        darn=morante.net",
        got,
    );
}

test "emptyBValue does not mistake bh= for b=" {
    const allocator = std.testing.allocator;
    const got = try emptyBValue(allocator, "v=1; bh=BODYHASH; d=x.com");
    defer allocator.free(got);
    // No b tag at all, so nothing changes.
    try std.testing.expectEqualStrings("v=1; bh=BODYHASH; d=x.com", got);
}

test "emptyBValue does not match inside a z= value" {
    // `z=` copies header fields and legitimately contains colons and '=' signs.
    // A scan for the text "b=" preceded by a non-letter matches the ':b=' here
    // and truncates everything after it, destroying the real b tag.
    const allocator = std.testing.allocator;
    const input = "v=1; z=From:x|Subject:b=y; bh=H; b=REALSIG";
    const got = try emptyBValue(allocator, input);
    defer allocator.free(got);
    try std.testing.expectEqualStrings("v=1; z=From:x|Subject:b=y; bh=H; b=", got);
}

test "emptyBValue handles b= as the first tag" {
    const allocator = std.testing.allocator;
    const got = try emptyBValue(allocator, "DKIM-Signature: b=SIG; v=1; d=x.com");
    defer allocator.free(got);
    try std.testing.expectEqualStrings("DKIM-Signature: b=; v=1; d=x.com", got);
}

test "emptyBValue leaves an already-empty value alone" {
    const allocator = std.testing.allocator;
    const got = try emptyBValue(allocator, "v=1; b=; d=x.com");
    defer allocator.free(got);
    try std.testing.expectEqualStrings("v=1; b=; d=x.com", got);
}

test "emptyBValue on a field with no tags returns a copy" {
    const allocator = std.testing.allocator;
    const got = try emptyBValue(allocator, "Subject: hello");
    defer allocator.free(got);
    try std.testing.expectEqualStrings("Subject: hello", got);
}

test "findBValue reports the value's own bytes" {
    const input = "v=1; bh=H; b=SIGDATA; d=x.com";
    const span = findBValue(input).?;
    try std.testing.expectEqualStrings("SIGDATA", input[span.start..span.end]);
    try std.testing.expect(findBValue("v=1; bh=H; d=x.com") == null);
}

test "tagListStart distinguishes a field name from a tag list" {
    // A field name ends at its colon: "DKIM-Signature" is 14 bytes, so the ':'
    // sits at 14 and the list starts at 15, on the space before v=1. Leading FWS
    // is left in place because the tag-name trim removes it.
    try std.testing.expectEqual(@as(usize, 15), tagListStart("DKIM-Signature: v=1; b=x"));
    // A bare tag list has no field name to skip.
    try std.testing.expectEqual(@as(usize, 0), tagListStart("v=1; b=x"));
    // The colons inside an h= value must not be read as a field name.
    try std.testing.expectEqual(@as(usize, 0), tagListStart("h=from:to:subject; b=x"));
}

test "validateTagList accepts what RFC 6376 3.2 allows" {
    // A real ARC-Seal tag list.
    try validateTagList("i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=dummy; t=12345; b=abc");
    // The ABNF's optional trailing ";".
    try validateTagList("a=1; b=2;");
    // FWS around names, "=" and values, including a fold.
    try validateTagList(" a = 1 ;\r\n b\t=\t2 ");
    // An empty tag-value is syntactically fine; whether it MEANS anything is the
    // individual tag's business, not this function's.
    try validateTagList("a=; b=2");
    // Unknown tags are ignored by consumers, not rejected by the syntax.
    try validateTagList("a=1; zz_9=x; b=2");
    // Digits and "_" are legal after the first character.
    try validateTagList("a1=x; b_2=y");
    // A value may contain "=" (base64 padding) and ":" (an h= list).
    try validateTagList("bh=dHN66dCN+jxb8=; h=from:to:subject");
}

test "validateTagList rejects what RFC 6376 3.2 forbids" {
    // tag-name must be ALPHA *ALNUMPUNC -- "_" may not lead.
    try std.testing.expectError(error.InvalidTagName, validateTagList("a=1; _=; b=2"));
    try std.testing.expectError(error.InvalidTagName, validateTagList("1a=x"));
    try std.testing.expectError(error.InvalidTagName, validateTagList("a-b=x"));
    // "Tags with duplicate names MUST NOT occur within a single tag-list; if a
    // tag name does occur more than once, the entire tag-list is invalid."
    try std.testing.expectError(error.DuplicateTagName, validateTagList("s=dummy; s=dummy"));
    try std.testing.expectError(error.DuplicateTagName, validateTagList("a=1; b=2; a=3"));
    // An interior empty tag-spec. Only a single trailing ";" is permitted.
    try std.testing.expectError(error.InvalidTagName, validateTagList("s=dummy;; t=1"));
    try std.testing.expectError(error.InvalidTagName, validateTagList(";a=1"));
    // A spec with no "=".
    try std.testing.expectError(error.MissingEquals, validateTagList("a=1; oops; b=2"));
    // Nothing at all.
    try std.testing.expectError(error.EmptyTagList, validateTagList(""));
    try std.testing.expectError(error.EmptyTagList, validateTagList(";"));
}

test "validateTagList is case sensitive, unlike DMARC" {
    // Both are valid syntax; they are simply different tags. The consequence is
    // in the consumer: a lookup for "s" must not be satisfied by "S".
    try validateTagList("s=dummy; S=other");
}

test "validateTagList bounds the duplicate scan" {
    // TAG_LIMIT exists so the quadratic duplicate check cannot be turned into a
    // denial of service by a header full of tags. Build one tag past the cap.
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(std.testing.allocator);
    var i: usize = 0;
    while (i <= TAG_LIMIT) : (i += 1) {
        try buf.writer(std.testing.allocator).print("a{d}=x;", .{i});
    }
    try std.testing.expectError(error.TooManyTags, validateTagList(buf.items));
}

test "findTag" {
    const val = "i=1; cv=pass; a=rsa-sha256; d=example.com; s=arc2026; b=AAAA==";
    try std.testing.expectEqualStrings("1", findTag(val, "i").?);
    try std.testing.expectEqualStrings("pass", findTag(val, "cv").?);
    try std.testing.expectEqualStrings("rsa-sha256", findTag(val, "a").?);
    try std.testing.expectEqualStrings("example.com", findTag(val, "d").?);
    try std.testing.expectEqualStrings("arc2026", findTag(val, "s").?);
    try std.testing.expectEqualStrings("AAAA==", findTag(val, "b").?);
    try std.testing.expect(findTag(val, "x") == null);
}

test "findTag matches tag names case sensitively (RFC 6376 3.2)" {
    // "Tags MUST be interpreted in a case-sensitive manner." A mis-cased tag is
    // a DIFFERENT tag, not the same one written oddly, so the tag it was meant
    // to be is absent.
    const mis_cased = "i=1; cv=none; a=rsa-sha256; d=example.org; S=dummy; t=12345";
    try std.testing.expect(findTag(mis_cased, "s") == null);
    try std.testing.expectEqualStrings("dummy", findTag(mis_cased, "S").?);

    // While this matched case insensitively, an ARC-Seal carrying `S=` was read
    // as having a selector and went on to verify against a key it named by
    // accident. The suite case is `as_format_tags_key_case`.
    const correct = "i=1; cv=none; a=rsa-sha256; d=example.org; s=dummy";
    try std.testing.expectEqualStrings("dummy", findTag(correct, "s").?);
}

test "findTag reads a DNS key record, which is the same kind of tag list" {
    // The reason this function is shared rather than copied into the key tools:
    // `p=` in a §3.6.1 key record is looked up by exactly the rules `s=` in a
    // signature is, and a second scanner is a second chance to get the case rule
    // wrong. `k=` defaulting to rsa when absent belongs to the caller.
    const rec = "v=DKIM1; k=rsa; p=MIIBIjANBgkq";
    try std.testing.expectEqualStrings("MIIBIjANBgkq", findTag(rec, "p").?);
    try std.testing.expectEqualStrings("rsa", findTag(rec, "k").?);
    try std.testing.expect(findTag(rec, "h") == null);

    // A revoked key is an empty p=, not a missing one -- the tools distinguish
    // them, so the scanner has to.
    try std.testing.expectEqualStrings("", findTag("v=DKIM1; p=", "p").?);
}
