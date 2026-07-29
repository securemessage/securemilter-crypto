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
