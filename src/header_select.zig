const std = @import("std");
const mem = std.mem;

/// Selecting which header instance each `h=` entry refers to (audit D-1/A-6).
///
/// RFC 6376 §5.4.2 lets a signer name the same header field more than once in
/// `h=`. The nth mention of a name refers to the nth instance of that field
/// **counting from the bottom of the header block upward**, and a mention with
/// no instance left to consume contributes *nothing at all* to the hash -- not
/// the name, not the colon, not a CRLF (§3.7).
///
/// That second rule is the whole point of **oversigning**. A signer with one
/// `From:` writes `h=from:from`: the first mention takes the real one, the
/// second takes nothing. If anyone later prepends a second `From:`, a verifier's
/// second mention now finds it, the hash changes, and the signature breaks. It
/// is how a signer nails down a field against later addition, and OpenDKIM's
/// `OverSignHeaders` turns it on for `from` in a great many deployments.
///
/// Every copy of this logic in the suite returned the *last* matching header for
/// every mention. Two consequences, and the interop one is the expensive half:
///
///   * Oversigned mail hashed the same `From:` twice where the signer hashed it
///     once, so **every oversigned message failed verification**. A false
///     `dkim=fail` under `p=reject` is rejected legitimate mail.
///   * On the signing side the same bug made our own oversigned signatures
///     unverifiable by anyone else, latent only because the shipped default
///     names no field twice.
///
/// The walker below pairs `h=` iteration with instance selection so a caller
/// cannot perform one without the other. Callers keep their own canonicalization
/// and allocation, which legitimately differ; what they no longer keep is a
/// private copy of the selection rule.
/// One `h=` entry: a field name, and how many earlier entries named it.
pub const Entry = struct {
    /// Field name, trimmed of the FWS RFC 6376 §3.5 permits around the colons.
    name: []const u8,
    /// Count of earlier entries naming this same field, case-insensitively.
    /// The nth mention (0-based) selects the nth instance up from the bottom.
    skip: usize,
};

/// Iterator over the colon-separated field names of an `h=` tag value.
///
/// `skip` is recomputed by rescanning the consumed prefix rather than kept in a
/// map, so the iterator needs no allocator and no bound on distinct names. An
/// `h=` list is a handful of entries, so the rescan is free.
pub const HTag = struct {
    full: []const u8,
    pos: usize = 0,

    pub fn init(h_tag: []const u8) HTag {
        return .{ .full = h_tag };
    }

    pub fn next(self: *HTag) ?Entry {
        while (self.pos < self.full.len) {
            const start = self.pos;
            const raw = self.take();
            const name = mem.trim(u8, raw, " \t\r\n");
            // An empty entry ("from::to", or a trailing colon) names no field.
            if (name.len == 0) continue;
            return .{ .name = name, .skip = self.countBefore(start, name) };
        }
        return null;
    }

    /// Consume the next colon-delimited chunk, advancing past its delimiter.
    fn take(self: *HTag) []const u8 {
        const rest = self.full[self.pos..];
        if (mem.indexOfScalar(u8, rest, ':')) |colon| {
            self.pos += colon + 1;
            return rest[0..colon];
        }
        self.pos = self.full.len;
        return rest;
    }

    /// How many entries strictly before byte offset `end` name `name`.
    fn countBefore(self: *const HTag, end: usize, name: []const u8) usize {
        var seen: usize = 0;
        var scan = HTag{ .full = self.full[0..end] };
        while (scan.pos < scan.full.len) {
            const raw = scan.take();
            const nm = mem.trim(u8, raw, " \t\r\n");
            if (nm.len != 0 and std.ascii.eqlIgnoreCase(nm, name)) seen += 1;
        }
        return seen;
    }
};

/// Index of the instance of `wanted` that sits `skip` places up from the
/// bottom-most one, or null when the message holds no such instance.
///
/// Null is the oversigning case as well as the missing-header case: RFC 6376
/// §3.7 treats both identically, contributing nothing to the hash.
pub fn selectInstance(
    comptime T: type,
    headers: []const T,
    comptime nameOf: fn (T) []const u8,
    wanted: []const u8,
    skip: usize,
) ?usize {
    var remaining = skip;
    var i = headers.len;
    while (i > 0) {
        i -= 1;
        if (!std.ascii.eqlIgnoreCase(nameOf(headers[i]), wanted)) continue;
        if (remaining == 0) return i;
        remaining -= 1;
    }
    return null;
}

/// Yields the header instances an `h=` tag selects, in `h=` order.
///
/// Entries selecting nothing are skipped internally, so the caller hashes
/// exactly what it is handed and never has to reason about the null case.
pub fn Walker(comptime T: type, comptime nameOf: fn (T) []const u8) type {
    return struct {
        const Self = @This();

        tag: HTag,
        headers: []const T,

        pub fn next(self: *Self) ?T {
            while (self.tag.next()) |entry| {
                const idx = selectInstance(T, self.headers, nameOf, entry.name, entry.skip) orelse
                    continue;
                return self.headers[idx];
            }
            return null;
        }
    };
}

/// Walk `h_tag` against `headers`, yielding each selected instance.
pub fn walker(
    comptime T: type,
    comptime nameOf: fn (T) []const u8,
    h_tag: []const u8,
    headers: []const T,
) Walker(T, nameOf) {
    return .{ .tag = HTag.init(h_tag), .headers = headers };
}

/// Field name of a raw `Name: value` header line.
///
/// A line with no colon is not a header field and can match no `h=` entry, so it
/// yields the empty string -- `h=` entries are non-empty by construction.
pub fn nameOfLine(line: []const u8) []const u8 {
    const colon = mem.indexOfScalar(u8, line, ':') orelse return "";
    return mem.trimRight(u8, line[0..colon], " \t");
}

/// Walk `h_tag` against raw `Name: value` header lines.
pub fn lineWalker(h_tag: []const u8, lines: []const []const u8) Walker([]const u8, nameOfLine) {
    return walker([]const u8, nameOfLine, h_tag, lines);
}

/// Instances of `wanted` present in the message.
fn countInstances(
    comptime T: type,
    comptime nameOf: fn (T) []const u8,
    headers: []const T,
    wanted: []const u8,
) usize {
    var n: usize = 0;
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(nameOf(h), wanted)) n += 1;
    }
    return n;
}

/// Times `wanted` is named in an `h=` list.
fn countMentions(h_tag: []const u8, wanted: []const u8) usize {
    var n: usize = 0;
    var it = HTag.init(h_tag);
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.name, wanted)) n += 1;
    }
    return n;
}

/// Extend an `h=` list so each name in `oversign` is listed one more time than
/// the message actually contains it (audit D-12). Caller owns the result.
///
/// RFC 6376 §5.4: "Signers MAY claim to have signed header fields that do not
/// exist ... the nonexisting header field MUST be treated as the null string",
/// and the rationale given is that "if that header field is added later, the
/// signature will fail". The count comes from the same section's informative
/// note: a name "need only be listed once more than the actual number of that
/// header field in a message at the time of signing in order to prevent any
/// further additions".
///
/// Computed against the actual count rather than hardcoded to two mentions,
/// because two is only correct when the field appears exactly once. A message
/// carrying two `From:` fields and signed with `h=from:from` is *not* protected:
/// both mentions find a real field and a third could still be added. Rare, but
/// the whole value of this feature is that the guarantee holds without the
/// operator having to think about it.
///
/// A name absent from the message gets one mention, which asserts its absence --
/// the RFC's stated purpose above, and useful on its own.
///
/// Appending keeps the operator's own list intact and in their order, so what
/// they configured is still legible in the emitted signature.
pub fn oversignedTag(
    comptime T: type,
    comptime nameOf: fn (T) []const u8,
    allocator: mem.Allocator,
    h_tag: []const u8,
    oversign: []const u8,
    headers: []const T,
) ![]u8 {
    var out: std.ArrayList(u8) = .{};
    errdefer out.deinit(allocator);

    // Trailing separators would compound into empty entries on each append.
    // HTag ignores those, but the emitted `h=` is read by operators too.
    try out.appendSlice(allocator, mem.trim(u8, h_tag, " \t\r\n:"));

    var names = HTag.init(oversign);
    while (names.next()) |entry| {
        // `skip` counts earlier mentions of this same name, so a repeated entry
        // in the operator's oversign list is already handled and must not be
        // applied twice.
        if (entry.skip > 0) continue;

        const want = countInstances(T, nameOf, headers, entry.name) + 1;
        var have = countMentions(out.items, entry.name);
        while (have < want) : (have += 1) {
            if (out.items.len > 0) try out.append(allocator, ':');
            try out.appendSlice(allocator, entry.name);
        }
    }

    return out.toOwnedSlice(allocator);
}

/// `oversignedTag` against raw `Name: value` header lines.
pub fn oversignedLineTag(
    allocator: mem.Allocator,
    h_tag: []const u8,
    oversign: []const u8,
    lines: []const []const u8,
) ![]u8 {
    return oversignedTag([]const u8, nameOfLine, allocator, h_tag, oversign, lines);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

/// Collect the lines an `h=` tag selects, for comparison against an expectation.
fn selected(h_tag: []const u8, lines: []const []const u8, out: [][]const u8) [][]const u8 {
    var w = lineWalker(h_tag, lines);
    var n: usize = 0;
    while (w.next()) |line| : (n += 1) out[n] = line;
    return out[0..n];
}

fn expectSelected(expected: []const []const u8, h_tag: []const u8, lines: []const []const u8) !void {
    var buf: [16][]const u8 = undefined;
    const got = selected(h_tag, lines, &buf);
    try testing.expectEqual(expected.len, got.len);
    for (expected, got) |e, g| try testing.expectEqualStrings(e, g);
}

test "a single mention takes the bottom-most instance" {
    // RFC 6376 §5.4.2: header fields are consumed from the bottom up, so one
    // mention of a duplicated field means the last one in the block.
    const lines = [_][]const u8{
        "From: top@example.com",
        "To: rcpt@example.com",
        "From: bottom@example.com",
    };
    try expectSelected(&.{"From: bottom@example.com"}, "from", &lines);
}

test "repeated mentions walk upward, one instance each" {
    // The defect: every mention used to resolve to the same bottom-most header.
    const lines = [_][]const u8{
        "From: top@example.com",
        "To: rcpt@example.com",
        "From: bottom@example.com",
    };
    try expectSelected(
        &.{ "From: bottom@example.com", "From: top@example.com" },
        "from:from",
        &lines,
    );
}

test "three instances, three mentions, strictly bottom to top" {
    const lines = [_][]const u8{
        "Received: c",
        "Received: b",
        "Received: a",
    };
    try expectSelected(
        &.{ "Received: a", "Received: b", "Received: c" },
        "received:received:received",
        &lines,
    );
}

test "oversigning: a mention with no instance left contributes nothing" {
    // The case that made every oversigned message fail. `h=from:from` over a
    // message with one From must hash it exactly once -- the second mention is
    // the null input of RFC 6376 §3.7, not a repeat of the first.
    const lines = [_][]const u8{
        "From: only@example.com",
        "Subject: hi",
    };
    try expectSelected(&.{"From: only@example.com"}, "from:from", &lines);

    // And the reason a signer does it: once a second From is prepended, the
    // second mention finds it, so the hash changes and the signature breaks.
    const attacked = [_][]const u8{
        "From: injected@evil.example",
        "From: only@example.com",
        "Subject: hi",
    };
    try expectSelected(
        &.{ "From: only@example.com", "From: injected@evil.example" },
        "from:from",
        &attacked,
    );
}

test "a name absent from the message contributes nothing" {
    const lines = [_][]const u8{"From: a@example.com"};
    try expectSelected(&.{}, "subject", &lines);
    try expectSelected(&.{"From: a@example.com"}, "subject:from:date", &lines);
}

test "names match case-insensitively, in the tag and in the message" {
    const lines = [_][]const u8{
        "FROM: a@example.com",
        "from: b@example.com",
    };
    try expectSelected(
        &.{ "from: b@example.com", "FROM: a@example.com" },
        "From:fRoM",
        &lines,
    );
}

test "FWS and empty entries in the h= tag are tolerated" {
    // RFC 6376 §3.5 permits folding whitespace around the colons.
    const lines = [_][]const u8{
        "From: a@example.com",
        "To: b@example.com",
    };
    try expectSelected(
        &.{ "From: a@example.com", "To: b@example.com" },
        " from : to ",
        &lines,
    );
    try expectSelected(
        &.{ "From: a@example.com", "To: b@example.com" },
        "from::to:",
        &lines,
    );
    try expectSelected(&.{}, "", &lines);
    try expectSelected(&.{}, ":::", &lines);
}

test "a header name is what precedes the colon, whitespace trimmed" {
    // RFC 5322 allows no space before the colon, but a lenient MTA may pass one
    // through, and the name must still match.
    const lines = [_][]const u8{
        "From : spaced@example.com",
        "Not a header line",
    };
    try expectSelected(&.{"From : spaced@example.com"}, "from", &lines);
    // The malformed line matches nothing rather than being treated as a field.
    try expectSelected(&.{}, "not a header line", &lines);
}

test "selectInstance walks up one instance at a time" {
    const lines = [_][]const u8{
        "X: 1",
        "X: 2",
        "X: 3",
    };
    try testing.expectEqual(@as(?usize, 2), selectInstance([]const u8, &lines, nameOfLine, "x", 0));
    try testing.expectEqual(@as(?usize, 1), selectInstance([]const u8, &lines, nameOfLine, "x", 1));
    try testing.expectEqual(@as(?usize, 0), selectInstance([]const u8, &lines, nameOfLine, "x", 2));
    try testing.expectEqual(@as(?usize, null), selectInstance([]const u8, &lines, nameOfLine, "x", 3));
}

test "HTag reports the mention index of each entry" {
    var tag = HTag.init("from:to:from:cc:from");
    const expected = [_]Entry{
        .{ .name = "from", .skip = 0 },
        .{ .name = "to", .skip = 0 },
        .{ .name = "from", .skip = 1 },
        .{ .name = "cc", .skip = 0 },
        .{ .name = "from", .skip = 2 },
    };
    for (expected) |e| {
        const got = tag.next().?;
        try testing.expectEqualStrings(e.name, got.name);
        try testing.expectEqual(e.skip, got.skip);
    }
    try testing.expectEqual(@as(?Entry, null), tag.next());
}

test "the walker works over a name/value representation too" {
    // securearc holds headers split into name and value rather than as raw
    // lines; the selection rule must not be re-implemented for it.
    const Header = struct { name: []const u8, value: []const u8 };
    const nameOf = struct {
        fn f(h: Header) []const u8 {
            return h.name;
        }
    }.f;

    const headers = [_]Header{
        .{ .name = "From", .value = "top@example.com" },
        .{ .name = "From", .value = "bottom@example.com" },
    };

    var w = walker(Header, nameOf, "from:from:from", &headers);
    try testing.expectEqualStrings("bottom@example.com", w.next().?.value);
    try testing.expectEqualStrings("top@example.com", w.next().?.value);
    // Third mention: nothing left, so nothing is hashed.
    try testing.expectEqual(@as(?Header, null), w.next());
}

// --- D-12: building the oversigned h= ----------------------------------------

fn expectOversigned(
    expected: []const u8,
    h_tag: []const u8,
    oversign: []const u8,
    lines: []const []const u8,
) !void {
    const got = try oversignedLineTag(testing.allocator, h_tag, oversign, lines);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(expected, got);
}

test "D-12: one From is listed twice" {
    try expectOversigned(
        "from:to:subject:date:message-id:from",
        "from:to:subject:date:message-id",
        "from",
        &.{ "From: a@example.com", "To: b@example.com", "Subject: hi" },
    );
}

test "D-12: two From fields need three mentions, not two" {
    // The case a hardcoded "list it twice" gets wrong. With two real From
    // fields, `h=from:from` leaves both mentions consuming real headers and a
    // third From could still be appended without breaking the signature.
    try expectOversigned(
        "from:to:from:from",
        "from:to",
        "from",
        &.{ "From: a@example.com", "From: b@example.com", "To: c@example.com" },
    );
}

test "D-12: a header absent from the message is named once, asserting absence" {
    try expectOversigned(
        "from:to:from:sender",
        "from:to",
        "from:sender",
        &.{ "From: a@example.com", "To: b@example.com" },
    );
}

test "D-12: an operator who already oversigned is not extended again" {
    // Idempotent against a list that already satisfies the rule, so enabling the
    // default on a config that had been oversigning by hand does not silently
    // add a third mention and change every signature.
    try expectOversigned(
        "from:from:to",
        "from:from:to",
        "from",
        &.{ "From: a@example.com", "To: b@example.com" },
    );
}

test "D-12: a name repeated in the oversign list is applied once" {
    try expectOversigned(
        "from:to:from",
        "from:to",
        "from:from",
        &.{ "From: a@example.com", "To: b@example.com" },
    );
}

test "D-12: a trailing colon does not compound into empty entries" {
    try expectOversigned(
        "from:to:from",
        "from:to:",
        "from",
        &.{ "From: a@example.com", "To: b@example.com" },
    );
}

test "D-12: the oversigned tag still selects exactly the real headers" {
    // The property that makes the whole thing safe: adding the extra mention
    // must not change WHAT gets hashed today, only what would break tomorrow.
    // If this ever selected the same From twice, every oversigned signature we
    // emit would be unverifiable -- which is precisely the D-1 defect.
    const lines = [_][]const u8{ "From: a@example.com", "To: b@example.com" };

    const tag = try oversignedLineTag(testing.allocator, "from:to", "from", &lines);
    defer testing.allocator.free(tag);
    try testing.expectEqualStrings("from:to:from", tag);

    try expectSelected(
        &.{ "From: a@example.com", "To: b@example.com" },
        tag,
        &lines,
    );

    // And once a second From is added, the spare mention finds it, so the hash
    // changes and the signature breaks. That is the entire point.
    const tampered = [_][]const u8{
        "From: attacker@evil.test",
        "From: a@example.com",
        "To: b@example.com",
    };
    try expectSelected(
        &.{ "From: a@example.com", "To: b@example.com", "From: attacker@evil.test" },
        tag,
        &tampered,
    );
}
