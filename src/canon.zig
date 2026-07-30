const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Canonicalization algorithm (RFC 6376 §3.4).
pub const Algorithm = enum {
    simple,
    relaxed,
};

/// Canonicalization pair: header algorithm / body algorithm.
pub const CanonicalizationPair = struct {
    header: Algorithm = .simple,
    body: Algorithm = .simple,
};

/// Parse a "c=" tag value like "relaxed/simple", "relaxed", "simple/relaxed".
/// Default is simple/simple per RFC 6376 §3.4.
pub fn parseCanonicalization(value: []const u8) !CanonicalizationPair {
    if (value.len == 0) return .{};

    if (mem.indexOfScalar(u8, value, '/')) |slash| {
        return .{
            .header = try parseAlgorithm(value[0..slash]),
            .body = try parseAlgorithm(value[slash + 1 ..]),
        };
    }
    // Only header algorithm specified; body defaults to simple
    return .{
        .header = try parseAlgorithm(value),
        .body = .simple,
    };
}

fn parseAlgorithm(s: []const u8) !Algorithm {
    if (mem.eql(u8, s, "simple")) return .simple;
    if (mem.eql(u8, s, "relaxed")) return .relaxed;
    return error.InvalidCanonicalization;
}

// =============================================================================
// Header Canonicalization (RFC 6376 §3.4.1 / §3.4.2)
// =============================================================================

/// Canonicalize a single header field (name: value) for signing/verification.
///
/// Simple (§3.4.1): No change. Headers are used exactly as presented.
///
/// Relaxed (§3.4.2):
///   1. Header field name → lowercase
///   2. Unfold continuation lines (remove CRLF before WSP)
///   3. Collapse sequential WSP to single SP
///   4. Strip trailing WSP before CRLF
///   5. Strip WSP around the colon separator
///
/// The returned slice does NOT include a trailing CRLF — the caller appends it.
pub fn canonicalizeHeader(allocator: Allocator, algorithm: Algorithm, header: []const u8) ![]u8 {
    return switch (algorithm) {
        .simple => allocator.dupe(u8, header),
        .relaxed => canonicalizeHeaderRelaxed(allocator, header),
    };
}

fn canonicalizeHeaderRelaxed(allocator: Allocator, header: []const u8) ![]u8 {
    // Find the colon separating name from value
    const colon_pos = mem.indexOfScalar(u8, header, ':') orelse return error.MalformedHeader;

    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);

    // Step 1: lowercase header name, strip trailing whitespace before colon
    const name_raw = header[0..colon_pos];
    const name = mem.trimRight(u8, name_raw, " \t");
    for (name) |c| {
        try result.append(allocator, std.ascii.toLower(c));
    }
    try result.append(allocator, ':');

    // Step 5: strip leading whitespace after colon
    var value = header[colon_pos + 1 ..];
    value = mem.trimLeft(u8, value, " \t");
    // Strip trailing whitespace
    value = mem.trimRight(u8, value, " \t\r\n");

    // Steps 2-4: unfold + collapse whitespace
    var in_wsp = false;
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        const c = value[i];
        // Unfold: skip CRLF or bare LF if followed by WSP (continuation line)
        // RFC 5322 specifies CRLF+WSP but many MTAs (including Postfix) use bare LF internally.
        if (c == '\r' and i + 1 < value.len and value[i + 1] == '\n') {
            if (i + 2 < value.len and (value[i + 2] == ' ' or value[i + 2] == '\t')) {
                // CRLF followed by WSP = folding, treat as WSP
                i += 1; // skip \n, the \t/space will be handled next iteration
                in_wsp = true;
                continue;
            }
        } else if (c == '\n') {
            if (i + 1 < value.len and (value[i + 1] == ' ' or value[i + 1] == '\t')) {
                // Bare LF followed by WSP = folding, treat as WSP
                in_wsp = true;
                continue;
            }
        }
        if (c == ' ' or c == '\t') {
            in_wsp = true;
        } else {
            if (in_wsp) {
                try result.append(allocator, ' ');
                in_wsp = false;
            }
            try result.append(allocator, c);
        }
    }

    return result.toOwnedSlice(allocator);
}

// =============================================================================
// Body Canonicalization (RFC 6376 §3.4.3 / §3.4.4)
// =============================================================================

/// Streaming body canonicalization state machine.
///
/// Feed body chunks via `update()`, then call `finish()` to get the final
/// canonicalized body (or use the incrementally-hashed result).
///
/// Simple (§3.4.3):
///   - Ignore all empty lines at the end of the body
///   - Ensure body ends with CRLF (if non-empty)
///   - Everything else verbatim
///
/// Relaxed (§3.4.4):
///   - Reduce all sequences of WSP within a line to single SP
///   - Strip all trailing WSP on each line before CRLF
///   - Ignore all empty lines at the end
///   - **An empty result is a null input, NOT a CRLF.** §3.4.4's closing note:
///     "a completely empty or missing body is canonicalized as a null input".
///     Only §3.4.3 (simple) converts "0*CRLF" to a single CRLF. The two
///     algorithms genuinely differ here and the difference is easy to miss,
///     because §3.4.4 states the rule in a note rather than in its numbered
///     steps (D-21).
///
/// A note on CR and LF, since it decides most of the code below: **only the exact
/// sequence CRLF terminates a line.** A lone CR or a lone LF is an ordinary data
/// octet and must survive canonicalization untouched. RFC 5234 defines WSP as SP
/// or HTAB only, so §3.4.4's "reduce WSP" and "ignore whitespace at the end of
/// lines" give relaxed no licence whatsoever to touch a CR. This code previously
/// skipped every CR outright and treated a bare LF as a line terminator (D-22).
pub const BodyCanonicalizer = struct {
    algorithm: Algorithm,
    allocator: Allocator,
    /// Accumulated canonicalized body lines (not including trailing empty lines).
    output: std.ArrayList(u8),
    /// Number of trailing CRLF bytes pending (deferred until we know they aren't
    /// the final empty lines that should be stripped).
    pending_crlf_count: usize,
    /// For relaxed: tracks whether we are in a whitespace run within the current line.
    in_wsp: bool,
    /// For relaxed: current line buffer being built.
    line_buf: std.ArrayList(u8),
    /// A CR has been seen and we do not yet know whether an LF follows.
    ///
    /// Carried in the struct rather than as a local, because `update()` is a
    /// streaming API and a CRLF may be split across two calls. The previous code
    /// looked ahead within the current buffer only (`i + 1 < data.len`), so a
    /// chunk boundary falling between the CR and the LF turned one line terminator
    /// into two data octets, corrupting the hash. No caller streamed the body, so
    /// it never fired -- but the doc comment above invites exactly that, and a
    /// latent bug in a documented API is a live one waiting for its first caller.
    pending_cr: bool,

    pub fn init(allocator: Allocator, algorithm: Algorithm) BodyCanonicalizer {
        return .{
            .algorithm = algorithm,
            .allocator = allocator,
            .output = .{},
            .pending_crlf_count = 0,
            .in_wsp = false,
            .line_buf = .{},
            .pending_cr = false,
        };
    }

    pub fn deinit(self: *BodyCanonicalizer) void {
        self.output.deinit(self.allocator);
        self.line_buf.deinit(self.allocator);
    }

    /// Feed a chunk of body data.
    pub fn update(self: *BodyCanonicalizer, data: []const u8) !void {
        switch (self.algorithm) {
            .simple => try self.updateSimple(data),
            .relaxed => try self.updateRelaxed(data),
        }
    }

    /// Finalize and return the canonicalized body.
    ///
    /// An empty result differs by algorithm, and this is the D-21 defect: simple
    /// yields a single CRLF (§3.4.3, "converts 0*CRLF at the end of the body to a
    /// single CRLF"), while relaxed yields **nothing at all** (§3.4.4, "a
    /// completely empty or missing body is canonicalized as a null input"). The
    /// old code emitted CRLF for both and cited §3.4.4 for a rule §3.4.4 does not
    /// contain.
    pub fn finish(self: *BodyCanonicalizer) ![]u8 {
        // A CR at the very end of the body never became a terminator, so it was
        // data all along.
        if (self.pending_cr) {
            self.pending_cr = false;
            switch (self.algorithm) {
                .simple => {
                    try self.flushPendingCrlf();
                    try self.output.append(self.allocator, '\r');
                },
                .relaxed => try self.appendRelaxedData('\r'),
            }
        }

        // Flush any remaining line content (for relaxed, if body doesn't end with CRLF)
        if (self.algorithm == .relaxed and self.line_buf.items.len > 0) {
            try self.flushRelaxedLine();
        }

        // Trailing empty lines are discarded for both algorithms: they are held in
        // pending_crlf_count and simply never flushed.
        if (self.output.items.len == 0) {
            // The one place the algorithms diverge on an empty result.
            if (self.algorithm == .simple) {
                try self.output.appendSlice(self.allocator, "\r\n");
            }
        } else {
            // Ensure non-empty body ends with exactly one CRLF
            const len = self.output.items.len;
            if (len < 2 or self.output.items[len - 2] != '\r' or self.output.items[len - 1] != '\n') {
                try self.output.appendSlice(self.allocator, "\r\n");
            }
        }

        return self.output.toOwnedSlice(self.allocator);
    }

    // ---- Simple canonicalization ----

    fn updateSimple(self: *BodyCanonicalizer, data: []const u8) !void {
        var i: usize = 0;
        while (i < data.len) {
            const c = data[i];

            if (self.pending_cr) {
                self.pending_cr = false;
                if (c == '\n') {
                    // CRLF: a line terminator, deferred in case it turns out to be
                    // one of the trailing empty lines that get discarded.
                    self.pending_crlf_count += 1;
                    i += 1;
                    continue;
                }
                // The CR stood alone, so it was data. Emit it and then reconsider
                // the current byte from the top without consuming it -- it may
                // itself be the CR of a following CRLF.
                try self.flushPendingCrlf();
                try self.output.append(self.allocator, '\r');
                continue;
            }

            if (c == '\r') {
                self.pending_cr = true;
                i += 1;
                continue;
            }

            // Any other octet, bare LF included, is data and proves the pending
            // CRLFs were not trailing after all.
            try self.flushPendingCrlf();
            try self.output.append(self.allocator, c);
            i += 1;
        }
    }

    // ---- Relaxed canonicalization ----

    fn updateRelaxed(self: *BodyCanonicalizer, data: []const u8) !void {
        var i: usize = 0;
        while (i < data.len) {
            const c = data[i];

            if (self.pending_cr) {
                self.pending_cr = false;
                if (c == '\n') {
                    try self.flushRelaxedLine();
                    i += 1;
                    continue;
                }
                // Lone CR: data, not a terminator. Note this also closes any WSP
                // run, because the run is no longer at the end of the line -- so
                // `a   \rb` reduces to `a \rb` and not to `a\rb`.
                try self.appendRelaxedData('\r');
                continue;
            }

            if (c == '\r') {
                self.pending_cr = true;
                i += 1;
                continue;
            }

            if (c == ' ' or c == '\t') {
                // WSP is only collapsed, never emitted directly: if the line ends
                // here the run is trailing WSP and must vanish, which is what
                // dropping `in_wsp` in flushRelaxedLine achieves.
                self.in_wsp = true;
                i += 1;
                continue;
            }

            // Everything else is data, and a bare LF is data. RFC 5234 WSP is SP
            // and HTAB only, so LF is not whitespace and §3.4.4 does not reach it.
            try self.appendRelaxedData(c);
            i += 1;
        }
    }

    /// Append one data octet to the current line, first collapsing any pending WSP
    /// run to the single SP §3.4.4 calls for.
    fn appendRelaxedData(self: *BodyCanonicalizer, c: u8) !void {
        if (self.in_wsp) {
            try self.line_buf.append(self.allocator, ' ');
            self.in_wsp = false;
        }
        try self.line_buf.append(self.allocator, c);
    }

    fn flushRelaxedLine(self: *BodyCanonicalizer) !void {
        // Strip trailing WSP already handled by not appending trailing WSP
        self.in_wsp = false;

        if (self.line_buf.items.len == 0) {
            // Empty line — defer (might be trailing)
            self.pending_crlf_count += 1;
        } else {
            // Non-empty line: flush pending CRLFs first
            try self.flushPendingCrlf();
            try self.output.appendSlice(self.allocator, self.line_buf.items);
            try self.output.appendSlice(self.allocator, "\r\n");
        }
        self.line_buf.clearRetainingCapacity();
    }

    fn flushPendingCrlf(self: *BodyCanonicalizer) !void {
        while (self.pending_crlf_count > 0) : (self.pending_crlf_count -= 1) {
            try self.output.appendSlice(self.allocator, "\r\n");
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

test "parse canonicalization pair" {
    const pair1 = try parseCanonicalization("relaxed/simple");
    try std.testing.expectEqual(Algorithm.relaxed, pair1.header);
    try std.testing.expectEqual(Algorithm.simple, pair1.body);

    const pair2 = try parseCanonicalization("simple/relaxed");
    try std.testing.expectEqual(Algorithm.simple, pair2.header);
    try std.testing.expectEqual(Algorithm.relaxed, pair2.body);

    const pair3 = try parseCanonicalization("relaxed");
    try std.testing.expectEqual(Algorithm.relaxed, pair3.header);
    try std.testing.expectEqual(Algorithm.simple, pair3.body);

    const pair4 = try parseCanonicalization("");
    try std.testing.expectEqual(Algorithm.simple, pair4.header);
    try std.testing.expectEqual(Algorithm.simple, pair4.body);
}

test "header canonicalization simple" {
    const allocator = std.testing.allocator;
    const input = "Subject: A Simple Test";
    const result = try canonicalizeHeader(allocator, .simple, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Subject: A Simple Test", result);
}

test "header canonicalization relaxed basic" {
    const allocator = std.testing.allocator;
    const input = "Subject:  A   Simple   Test  ";
    const result = try canonicalizeHeader(allocator, .relaxed, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("subject:A Simple Test", result);
}

test "header canonicalization relaxed folded" {
    const allocator = std.testing.allocator;
    const input = "Subject: A\r\n\t Folded Header";
    const result = try canonicalizeHeader(allocator, .relaxed, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("subject:A Folded Header", result);
}

test "header canonicalization relaxed colon whitespace" {
    const allocator = std.testing.allocator;
    const input = "From \t:  user@example.com  ";
    const result = try canonicalizeHeader(allocator, .relaxed, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("from:user@example.com", result);
}

test "header canonicalization relaxed bare LF folding" {
    const allocator = std.testing.allocator;
    // Bare LF + WSP (common in Postfix milter protocol)
    const input = "Authentication-Results: mail.test;\n        spf=fail smtp.mailfrom=example.com";
    const result = try canonicalizeHeader(allocator, .relaxed, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("authentication-results:mail.test; spf=fail smtp.mailfrom=example.com", result);
}

// Body canonicalization conformance, cross-checked against dkimpy.
//
// Every expectation was produced by running dkimpy's own canonicalizer, not
// derived from this module, so the table tests a reading of RFC 6376 §3.4.3 and
// §3.4.4 rather than this module's self-consistency. That distinction is the
// whole lesson of D-18: a test that compares an implementation against itself
// cannot see a mistake the implementation makes twice.
//
// The last five rows are the ones that were failing. D-21 is the empty-result
// divergence; D-22 is CR and LF being treated as structure instead of data.
test "body canonicalization conformance table" {
    const allocator = std.testing.allocator;

    const Case = struct {
        name: []const u8,
        input: []const u8,
        simple: []const u8,
        relaxed: []const u8,
    };

    const cases = [_]Case{
        .{
            .name = "plain text",
            .input = "hi\r\n",
            .simple = "hi\r\n",
            .relaxed = "hi\r\n",
        },
        .{
            .name = "trailing empty lines are dropped by both",
            .input = "hi\r\n\r\n\r\n",
            .simple = "hi\r\n",
            .relaxed = "hi\r\n",
        },
        .{
            .name = "missing final CRLF is added by both",
            .input = "no newline at end",
            .simple = "no newline at end\r\n",
            .relaxed = "no newline at end\r\n",
        },
        .{
            .name = "relaxed strips trailing WSP, simple keeps it",
            .input = "x   \r\n",
            .simple = "x   \r\n",
            .relaxed = "x\r\n",
        },
        .{
            .name = "relaxed collapses WSP runs",
            .input = "a  b\t\tc\r\n",
            .simple = "a  b\t\tc\r\n",
            .relaxed = "a b c\r\n",
        },
        .{
            .name = "WSP-only interior lines become empty under relaxed",
            .input = "a\r\n   \r\n\t\r\n",
            .simple = "a\r\n   \r\n\t\r\n",
            .relaxed = "a\r\n",
        },
        // D-21: §3.4.4's closing note, "a completely empty or missing body is
        // canonicalized as a null input", against §3.4.3's "converts 0*CRLF at the
        // end of the body to a single CRLF". Both were emitting CRLF.
        .{
            .name = "D-21 empty body: null under relaxed, CRLF under simple",
            .input = "",
            .simple = "\r\n",
            .relaxed = "",
        },
        .{
            .name = "D-21 body of one CRLF reduces to the empty case",
            .input = "\r\n",
            .simple = "\r\n",
            .relaxed = "",
        },
        .{
            .name = "D-21 WSP-only body is null under relaxed",
            .input = "   \r\n",
            .simple = "   \r\n",
            .relaxed = "",
        },
        // D-22: CR and LF are not WSP (RFC 5234), so neither algorithm may treat a
        // lone one as a terminator or delete it. Relaxed was doing both.
        .{
            .name = "D-22 bare CR is data, not a terminator",
            .input = "a\rb\r\n",
            .simple = "a\rb\r\n",
            .relaxed = "a\rb\r\n",
        },
        .{
            .name = "D-22 bare LF is data, not a terminator",
            .input = "a\nb\r\n",
            .simple = "a\nb\r\n",
            .relaxed = "a\nb\r\n",
        },
        .{
            .name = "D-22 trailing bare CR is data, then CRLF is appended",
            .input = "abc\r",
            .simple = "abc\r\r\n",
            .relaxed = "abc\r\r\n",
        },
        .{
            // The subtle one: the WSP run is not at end of line, because a data
            // octet follows it, so relaxed collapses it to one SP instead of
            // deleting it.
            .name = "D-22 WSP before a bare CR collapses rather than vanishing",
            .input = "a   \rb\r\n",
            .simple = "a   \rb\r\n",
            .relaxed = "a \rb\r\n",
        },
    };

    for (cases) |case| {
        inline for (.{ .simple, .relaxed }) |alg| {
            var bc = BodyCanonicalizer.init(allocator, alg);
            defer bc.deinit();
            try bc.update(case.input);
            const got = try bc.finish();
            defer allocator.free(got);

            const want = if (alg == .simple) case.simple else case.relaxed;
            std.testing.expectEqualStrings(want, got) catch |err| {
                std.debug.print("\nbody canon {s} failed for {s}\n  input {s}\n", .{ @tagName(alg), case.name, case.input });
                return err;
            };
        }
    }
}

// A CRLF split across two update() calls must still be one line terminator.
//
// This never fired in production because both callers hand the whole body to a
// single update(). It is tested anyway because the type's own documentation
// invites streaming, and the old implementation's lookahead could not see past
// the end of the current chunk -- so the first caller to stream a body would have
// silently corrupted every hash whose chunk boundary landed mid-CRLF.
test "body canonicalization is chunk-boundary safe" {
    const allocator = std.testing.allocator;
    const body = "first line\r\nsecond line\r\n\r\n\r\n";

    inline for (.{ .simple, .relaxed }) |alg| {
        // The whole-body result is the reference.
        var whole = BodyCanonicalizer.init(allocator, alg);
        defer whole.deinit();
        try whole.update(body);
        const want = try whole.finish();
        defer allocator.free(want);

        // Every possible split, so no cut point is left untested -- including the
        // ones that fall between a CR and its LF.
        var split: usize = 0;
        while (split <= body.len) : (split += 1) {
            var bc = BodyCanonicalizer.init(allocator, alg);
            defer bc.deinit();
            try bc.update(body[0..split]);
            try bc.update(body[split..]);
            const got = try bc.finish();
            defer allocator.free(got);

            std.testing.expectEqualStrings(want, got) catch |err| {
                std.debug.print("\n{s} differs when split at {d}\n", .{ @tagName(alg), split });
                return err;
            };
        }
    }
}

// Header canonicalization conformance, cross-checked against dkimpy.
//
// Every expectation below was produced by an independent implementation rather
// than derived from this one, so the table checks the reading of RFC 6376 §3.4.1
// and §3.4.2 and not merely that this module is self-consistent. Added with A-5,
// which made ARC's AMS path honour the c= tag and so depend on `simple` for the
// first time -- a latent defect there would previously have gone unnoticed
// because nothing exercised it.
//
// dkimpy emits a trailing CRLF for relaxed; this module leaves that to the
// caller, so it is absent from the relaxed expectations here.
test "header canonicalization conformance table" {
    const allocator = std.testing.allocator;

    const Case = struct {
        input: []const u8,
        simple: []const u8,
        relaxed: []const u8,
    };

    const cases = [_]Case{
        .{
            .input = "From: user@example.com",
            .simple = "From: user@example.com",
            .relaxed = "from:user@example.com",
        },
        .{
            // Relaxed lowercases the field name but never the value.
            .input = "FroM: User@Example.COM",
            .simple = "FroM: User@Example.COM",
            .relaxed = "from:User@Example.COM",
        },
        .{
            .input = "From:user@example.com",
            .simple = "From:user@example.com",
            .relaxed = "from:user@example.com",
        },
        .{
            .input = "From:   user@example.com   ",
            .simple = "From:   user@example.com   ",
            .relaxed = "from:user@example.com",
        },
        .{
            .input = "Subject:\thello\tthere",
            .simple = "Subject:\thello\tthere",
            .relaxed = "subject:hello there",
        },
        .{
            .input = "Subject: first line\r\n\tsecond line",
            .simple = "Subject: first line\r\n\tsecond line",
            .relaxed = "subject:first line second line",
        },
        .{
            .input = "Subject: a\r\n b\r\n\tc",
            .simple = "Subject: a\r\n b\r\n\tc",
            .relaxed = "subject:a b c",
        },
        .{
            .input = "Subject: a    b\t\tc",
            .simple = "Subject: a    b\t\tc",
            .relaxed = "subject:a b c",
        },
    };

    for (cases) |c| {
        const got_simple = try canonicalizeHeader(allocator, .simple, c.input);
        defer allocator.free(got_simple);
        try std.testing.expectEqualStrings(c.simple, got_simple);

        const got_relaxed = try canonicalizeHeader(allocator, .relaxed, c.input);
        defer allocator.free(got_relaxed);
        try std.testing.expectEqualStrings(c.relaxed, got_relaxed);
    }
}

test "simple header canonicalization is exact identity" {
    // RFC 6376 §3.4.1: simple "does not change the header field in any way".
    // Stated separately from the table so the property is pinned rather than
    // merely sampled -- the AMS path relies on it since A-5.
    const allocator = std.testing.allocator;
    const inputs = [_][]const u8{
        "From: user@example.com",
        "X-Odd:\t \t weird   spacing \t",
        "Folded: a\r\n\tb",
        "NoColonValue:",
        "",
    };
    for (inputs) |in| {
        const got = try canonicalizeHeader(allocator, .simple, in);
        defer allocator.free(got);
        try std.testing.expectEqualStrings(in, got);
    }
}

test "body canonicalization simple strips trailing empty lines" {
    const allocator = std.testing.allocator;
    var bc = BodyCanonicalizer.init(allocator, .simple);
    defer bc.deinit();

    try bc.update("Hello\r\n");
    try bc.update("\r\n");
    try bc.update("\r\n");

    const result = try bc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello\r\n", result);
}

test "body canonicalization simple empty body" {
    const allocator = std.testing.allocator;
    var bc = BodyCanonicalizer.init(allocator, .simple);
    defer bc.deinit();

    const result = try bc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("\r\n", result);
}

test "body canonicalization relaxed whitespace" {
    const allocator = std.testing.allocator;
    var bc = BodyCanonicalizer.init(allocator, .relaxed);
    defer bc.deinit();

    try bc.update("Hello  \t World  \r\n");
    try bc.update("\r\n");

    const result = try bc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello World\r\n", result);
}

test "body canonicalization relaxed multiple lines" {
    const allocator = std.testing.allocator;
    var bc = BodyCanonicalizer.init(allocator, .relaxed);
    defer bc.deinit();

    try bc.update("Line 1\r\n");
    try bc.update("  Line  2  \r\n");
    try bc.update("\r\n");
    try bc.update("Line 3\r\n");
    try bc.update("\r\n");
    try bc.update("\r\n");

    const result = try bc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Line 1\r\n Line 2\r\n\r\nLine 3\r\n", result);
}
