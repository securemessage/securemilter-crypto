const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;
const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/bio.h");
    // d2i_PUBKEY/i2d_PUBKEY live here. They resolved before only because
    // pem.h drags x509.h in; naming it makes that not luck.
    @cInclude("openssl/x509.h");
});

/// Supported DKIM/ARC signing algorithms.
pub const Algorithm = enum {
    rsa_sha256,
    ed25519_sha256,
};

/// RFC 8301 §3.2 puts a hard floor under RSA key sizes for DKIM and everything
/// built on it. Verifiers "MUST NOT consider signatures using RSA keys of less
/// than 1024 bits as valid signatures", and such signatures "have permanently
/// failed evaluation". The same paragraph binds signers: "Signers MUST use RSA
/// keys of at least 1024 bits for all keys."
///
/// The reason it is a MUST NOT and not advice: a 512-bit modulus is factorable
/// for a few hundred dollars of rented compute, so a signature made with one
/// proves nothing about who sent the message. Accepting it is worse than having
/// no signature at all, because it produces a `dkim=pass` that DMARC then
/// treats as an authenticated identity.
pub const RFC8301_MIN_RSA_BITS: u32 = 1024;

/// The configuration key the verifying daemons read the minimum from.
///
/// Shared as a constant so securedkim and securearc cannot drift to two
/// spellings — the failure mode of a typo here is one daemon silently ignoring
/// the operator's setting, which is invisible until someone audits a header.
pub const MIN_KEY_BITS_OPTION = "MinimumKeyBits";

/// Outcome of reconciling a configured minimum with the RFC floor.
pub const MinRsaBits = struct {
    bits: u32,
    /// The configured value was below the RFC floor and has been raised to it.
    raised: bool,
};

/// Reconcile a configured minimum key size with the RFC 8301 floor.
///
/// The floor is raised to, never lowered past. Unlike the `Max*` resource caps,
/// where `0` means "no limit", `0` here does not disable the check: this is a
/// MUST NOT, and one line of configuration should not be able to re-admit
/// signatures the standard says have permanently failed. A value below the
/// floor is reported as `raised` so the caller can say so at startup rather
/// than silently disagreeing with the config file.
pub fn resolveMinRsaBits(configured: u32) MinRsaBits {
    if (configured < RFC8301_MIN_RSA_BITS) {
        return .{ .bits = RFC8301_MIN_RSA_BITS, .raised = true };
    }
    return .{ .bits = configured, .raised = false };
}

/// Modulus size of a loaded key, or 0 if it is not an RSA key.
fn pkeyRsaBits(pkey: *c.EVP_PKEY) u32 {
    if (c.EVP_PKEY_get_base_id(pkey) != c.EVP_PKEY_RSA) return 0;
    const bits = c.EVP_PKEY_get_bits(pkey);
    if (bits <= 0) return 0;
    return @intCast(bits);
}

/// Modulus size of a loaded signing key in bits, or 0 for a non-RSA key.
///
/// Exposed for reporting — the key tools print it, and the daemons log it when
/// a signing key is loaded so an operator can see what is actually in use.
pub fn signingKeyBits(key: *const SigningKey) u32 {
    const pkey = key.rsa_pkey orelse return 0;
    return pkeyRsaBits(pkey);
}

/// An opaque handle to a loaded signing key.
pub const SigningKey = struct {
    algorithm: Algorithm,
    rsa_pkey: ?*c.EVP_PKEY = null,

    /// The **derived keypair**, not the seed (audit C-2): `generateDeterministic`
    /// was being run per signature for a result that cannot change while the key is
    /// loaded.
    ///
    /// One field, not seed *and* pair: two copies of the same secret invites setting
    /// one and reading the other, and `securedkim`'s D-24 tables did build this
    /// struct literally. `secret_key.seed()` recovers the seed when a caller needs it.
    ed25519_key_pair: ?Ed25519.KeyPair = null,

    /// Free the RSA key and **wipe the Ed25519 secret** (audit C-1).
    ///
    /// RSA needs no help -- `EVP_PKEY_free` runs `OPENSSL_cleanse`. The Ed25519 seed
    /// and expanded secret had nobody doing it and simply went out of scope, leaving
    /// a domain's signing key in freed heap or a core dump. A milter is long-lived and
    /// re-reads its key on SIGHUP, so that accumulates copies.
    ///
    /// THE `secureZero` LOOKS REDUNDANT AND IS NOT. This compiler zeroes an optional's
    /// payload on `= null` (verified: 64 bytes of 0x5A become zero), so the secret is
    /// already gone before the wipe runs and no test can separate the two. That is a
    /// lowering artefact, not a guarantee -- and in a release build a store never read
    /// again is the first thing an optimiser drops. The volatile write is the promised
    /// part; the test pins the property, not this line.
    pub fn deinit(self: *SigningKey) void {
        if (self.rsa_pkey) |pkey| {
            c.EVP_PKEY_free(pkey);
            self.rsa_pkey = null;
        }
        if (self.ed25519_key_pair) |*kp| {
            std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key));
            self.ed25519_key_pair = null;
        }
    }

    /// Sign with the cached keypair, per RFC 8463 §3.
    ///
    /// `data` is the canonicalized signing input; the SHA-256 step is here, for the
    /// reasons set out on `ed25519Sha256Sign`.
    pub fn signEd25519Sha256(self: *const SigningKey, data: []const u8) ![64]u8 {
        const kp = self.ed25519_key_pair orelse return error.NotEd25519Key;
        const digest = sha256(data);
        const sig = try kp.sign(&digest, null);
        return sig.toBytes();
    }
};

/// Reject a loaded private key whose modulus is below `min_bits`.
///
/// Signing with an undersized key is not a smaller version of the verify
/// problem, it is a louder one: RFC 8301 §3.2 makes such signatures permanently
/// failed *at every conformant verifier*, so the mail goes out looking signed
/// and arrives failing DKIM everywhere. Refusing the key turns a silent
/// deliverability fault into a startup error.
///
/// `min_bits` of 0 skips the check, for tools that inspect a key in order to
/// report on it rather than to use it.
fn checkPrivateKeyBits(pkey: *c.EVP_PKEY, min_bits: u32) !void {
    if (min_bits == 0) return;
    const bits = pkeyRsaBits(pkey);
    if (bits == 0) return error.NotRsaKey;
    if (bits < min_bits) return error.RsaKeyTooSmall;
}

/// Load a PEM-encoded RSA private key from a file path.
///
/// `min_bits` is a required argument, not a default, so that adding a new
/// caller forces a decision about it. Pass `RFC8301_MIN_RSA_BITS` to sign, or 0
/// to inspect a key without enforcing anything.
pub fn loadRsaKeyFile(path: []const u8, min_bits: u32) !SigningKey {
    var path_buf: [4096]u8 = undefined;
    if (path.len >= path_buf.len) return error.PathTooLong;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    const bio = c.BIO_new_file(&path_buf, "r") orelse return error.FileOpenFailed;
    defer _ = c.BIO_free(bio);

    const pkey = c.PEM_read_bio_PrivateKey(bio, null, null, null) orelse return error.KeyParseFailed;
    errdefer c.EVP_PKEY_free(pkey);
    try checkPrivateKeyBits(pkey, min_bits);

    return .{ .algorithm = .rsa_sha256, .rsa_pkey = pkey };
}

/// Load a PEM-encoded RSA private key from a byte slice. See `loadRsaKeyFile`
/// for the meaning of `min_bits`.
pub fn loadRsaKeyBytes(pem_data: []const u8, min_bits: u32) !SigningKey {
    const bio = c.BIO_new_mem_buf(pem_data.ptr, @intCast(pem_data.len)) orelse return error.BioCreateFailed;
    defer _ = c.BIO_free(bio);

    const pkey = c.PEM_read_bio_PrivateKey(bio, null, null, null) orelse return error.KeyParseFailed;
    errdefer c.EVP_PKEY_free(pkey);
    try checkPrivateKeyBits(pkey, min_bits);

    return .{ .algorithm = .rsa_sha256, .rsa_pkey = pkey };
}

/// Load a raw 32-byte Ed25519 private seed, deriving the keypair once.
///
/// Fallible now: the derivation can reject a seed producing the identity element, and
/// doing it here refuses a bad seed at load rather than on the first message.
pub fn loadEd25519Seed(seed: [32]u8) !SigningKey {
    return .{
        .algorithm = .ed25519_sha256,
        .ed25519_key_pair = try Ed25519.KeyPair.generateDeterministic(seed),
    };
}

/// Sign data with an RSA-SHA256 key.
///
/// Returns the raw signature bytes. Caller owns the returned slice.
pub fn rsaSign(allocator: Allocator, pkey: *c.EVP_PKEY, data: []const u8) ![]u8 {
    const ctx = c.EVP_MD_CTX_new() orelse return error.CtxCreateFailed;
    defer c.EVP_MD_CTX_free(ctx);

    if (c.EVP_DigestSignInit(ctx, null, c.EVP_sha256(), null, pkey) != 1) {
        return error.SignInitFailed;
    }

    if (c.EVP_DigestSignUpdate(ctx, data.ptr, data.len) != 1) {
        return error.SignUpdateFailed;
    }

    var sig_len: usize = 0;
    if (c.EVP_DigestSignFinal(ctx, null, &sig_len) != 1) {
        return error.SignFinalFailed;
    }

    const sig = try allocator.alloc(u8, sig_len);
    errdefer allocator.free(sig);

    if (c.EVP_DigestSignFinal(ctx, sig.ptr, &sig_len) != 1) {
        return error.SignFinalFailed;
    }

    return allocator.realloc(sig, sig_len) catch sig[0..sig_len];
}

/// Verify an RSA-SHA256 signature.
pub fn rsaVerify(pkey: *c.EVP_PKEY, data: []const u8, signature: []const u8) !bool {
    const ctx = c.EVP_MD_CTX_new() orelse return error.CtxCreateFailed;
    defer c.EVP_MD_CTX_free(ctx);

    if (c.EVP_DigestVerifyInit(ctx, null, c.EVP_sha256(), null, pkey) != 1) {
        return error.VerifyInitFailed;
    }

    if (c.EVP_DigestVerifyUpdate(ctx, data.ptr, data.len) != 1) {
        return error.VerifyUpdateFailed;
    }

    const result = c.EVP_DigestVerifyFinal(ctx, signature.ptr, signature.len);
    return result == 1;
}

/// Load a DER-encoded RSA public key (from a DKIM/ARC key record's p= tag) and
/// enforce a minimum modulus size.
///
/// `min_bits` is a required argument with no default on purpose. Every caller of
/// this function is a verifier acting on a key whose size the *signer* chose,
/// and a caller that forgot to check would hand a factorable key to
/// `rsaVerify`, which would then happily report a good signature. Making the
/// argument mandatory turns "remember to check at every call site" into a
/// compile error at every call site.
///
/// `found_bits`, when supplied, receives the modulus size whenever the DER
/// parsed at all — including when the key is then rejected — so a caller can
/// report *how* small the key was instead of just that it was refused.
pub fn loadRsaPublicKeyDer(der_data: []const u8, min_bits: u32, found_bits: ?*u32) !*c.EVP_PKEY {
    var ptr: [*c]const u8 = der_data.ptr;
    const pkey = c.d2i_PUBKEY(null, &ptr, @intCast(der_data.len)) orelse return error.PublicKeyParseFailed;
    errdefer c.EVP_PKEY_free(pkey);

    // A k=rsa record whose p= actually carries an EC or Ed25519 SubjectPublicKeyInfo
    // would otherwise be measured in curve bits, a different unit, and refused
    // with a misleading "too small". Callers check the declared k= tag against
    // the declared a= tag; this checks what the key bytes really are.
    const bits = pkeyRsaBits(pkey);
    if (bits == 0) return error.NotRsaPublicKey;
    if (found_bits) |out| out.* = bits;

    if (bits < min_bits) return error.RsaKeyTooSmall;

    return pkey;
}

/// Free an EVP_PKEY returned by loadRsaPublicKeyDer.
pub fn freePublicKey(pkey: *c.EVP_PKEY) void {
    c.EVP_PKEY_free(pkey);
}

/// The `ed25519-sha256` DKIM signing algorithm, RFC 8463 §3.
///
/// **`data` is the canonicalized signing input, and this function hashes it.**
/// RFC 8463 §3 defines the algorithm as: "computes a message hash as defined in
/// Section 3 of [RFC6376] using SHA-256 as the hash-alg. It signs *the hash*
/// with the PureEdDSA variant Ed25519". So the 32-byte SHA-256 digest is the
/// EdDSA message, not the signing input itself.
///
/// The SHA-256 step is inside these two functions, and the functions are named
/// for the RFC's algorithm rather than for the curve, because the alternative
/// already failed: they were `ed25519Sign`/`ed25519Verify` taking the signing
/// input raw, and both call sites in `securedkim` duly passed the header block
/// straight through. Nothing caught it, because sign and verify were wrong in
/// the same direction and round-tripped perfectly against each other -- the
/// signatures were self-consistent and interoperable with nobody. RFC 8463
/// Appendix A found it in one run.
///
/// Note the asymmetry with RSA that makes this easy to miss: `rsaVerify` is given
/// the same signing input and is correct, because OpenSSL's `EVP_DigestVerify`
/// applies SHA-256 internally. PureEdDSA hashes with SHA-512 as part of EdDSA
/// itself and knows nothing about the DKIM hash-alg, so the caller must supply
/// the digest. Passing the signing input to both *looks* uniform and is only
/// right for one of them.
///
/// ONE-SHOT ONLY -- derives the keypair per call, which is what C-2 was about. Repeat
/// signers hold a `SigningKey` and use `signEd25519Sha256`.
pub fn ed25519Sha256Sign(seed: [32]u8, data: []const u8) ![64]u8 {
    var key = try loadEd25519Seed(seed);
    defer key.deinit();
    return key.signEd25519Sha256(data);
}

/// Verify an `ed25519-sha256` DKIM signature, RFC 8463 §3.
///
/// `data` is the canonicalized signing input; see `ed25519Sha256Sign` for why
/// this function, and not its caller, applies SHA-256.
pub fn ed25519Sha256Verify(public_key: [32]u8, data: []const u8, signature: [64]u8) !bool {
    const pk = Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = Ed25519.Signature.fromBytes(signature);
    const digest = sha256(data);
    sig.verify(&digest, pk) catch return false;
    return true;
}

/// SHA-256 hash.
pub fn sha256(data: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    return hasher.finalResult();
}

/// Incremental SHA-256 hasher for streaming body hash.
pub const Sha256Hasher = struct {
    inner: std.crypto.hash.sha2.Sha256,

    pub fn init() Sha256Hasher {
        return .{ .inner = std.crypto.hash.sha2.Sha256.init(.{}) };
    }

    pub fn update(self: *Sha256Hasher, data: []const u8) void {
        self.inner.update(data);
    }

    pub fn final(self: *Sha256Hasher) [32]u8 {
        return self.inner.finalResult();
    }
};

/// Base64 encode.
pub fn base64Encode(allocator: Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.standard;
    const len = encoder.Encoder.calcSize(data.len);
    const buf = try allocator.alloc(u8, len);
    const result = encoder.Encoder.encode(buf, data);
    _ = result;
    return buf;
}

/// Base64 decode. Strips whitespace (SP, TAB, CR, LF) before decoding,
/// as DKIM/ARC tag values may contain FWS from header line folding.
pub fn base64Decode(allocator: Allocator, encoded: []const u8) ![]u8 {
    // Strip whitespace from input (RFC 6376 §3.5: FWS allowed in tag values)
    var clean_len: usize = 0;
    for (encoded) |ch| {
        if (ch != ' ' and ch != '\t' and ch != '\r' and ch != '\n') clean_len += 1;
    }
    const clean = if (clean_len == encoded.len) encoded else blk: {
        const stripped = try allocator.alloc(u8, clean_len);
        var idx: usize = 0;
        for (encoded) |ch| {
            if (ch != ' ' and ch != '\t' and ch != '\r' and ch != '\n') {
                stripped[idx] = ch;
                idx += 1;
            }
        }
        break :blk stripped;
    };
    defer if (clean.ptr != encoded.ptr) allocator.free(@constCast(clean));

    const decoder = std.base64.standard;
    const max_len = try decoder.Decoder.calcSizeUpperBound(clean.len);
    const buf = try allocator.alloc(u8, max_len);
    const written = decoder.Decoder.calcSizeForSlice(clean) catch |err| {
        allocator.free(buf);
        return @as(anyerror, err);
    };
    decoder.Decoder.decode(buf, clean) catch |err| {
        allocator.free(buf);
        return @as(anyerror, err);
    };
    return allocator.realloc(buf, written) catch @constCast(buf[0..written]);
}

test "sha256 basic" {
    const hash = sha256("hello");
    const expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const hex = std.fmt.bytesToHex(&hash, .lower);
    try std.testing.expectEqualStrings(expected, &hex);
}

test "sha256 incremental matches one-shot" {
    const data = "The quick brown fox jumps over the lazy dog";
    const one_shot = sha256(data);

    var hasher = Sha256Hasher.init();
    hasher.update("The quick brown ");
    hasher.update("fox jumps over ");
    hasher.update("the lazy dog");
    const incremental = hasher.final();

    try std.testing.expectEqualSlices(u8, &one_shot, &incremental);
}

test "base64 round trip" {
    const original = "Hello, DKIM world!";
    const encoded = try base64Encode(std.testing.allocator, original);
    defer std.testing.allocator.free(encoded);

    try std.testing.expectEqualStrings("SGVsbG8sIERLSU0gd29ybGQh", encoded);

    const decoded = try base64Decode(std.testing.allocator, encoded);
    defer std.testing.allocator.free(decoded);

    try std.testing.expectEqualStrings(original, decoded);
}

// C-1. Scans the WHOLE struct for the seed byte, which is what a core dump or a
// scraper reading a reused heap page actually does -- rather than dereferencing the
// one field, which presumes where the secret sits.
//
// WHAT THIS DOES AND DOES NOT PROVE. It pins the property: after `deinit`, no byte of
// the seed remains in the handle. It does NOT isolate the `secureZero` call, because
// this compiler also zeroes an optional's payload on `= null` -- so removing the wipe
// alone keeps this green. Verified, and recorded on `deinit` so the next reader does
// not delete the wipe on the strength of a passing test. Deleting the whole wipe
// block does fail this, which is the regression a reader is actually likely to cause.
test "no seed byte survives deinit" {
    const seed_byte: u8 = 0x5A;
    const seed = [_]u8{seed_byte} ** 32;
    var key = try loadEd25519Seed(seed);

    // Searches for the contiguous 32-byte run, not for occurrences of the byte: the
    // derived PUBLIC key contains 0x5A twice by coincidence, and the public key is
    // not a secret and is not what this is about. A counting assertion here read 34
    // instead of 32 and would have been "fixed" by loosening the number, which is how
    // a test stops meaning anything.
    const whole = mem.asBytes(&key);
    try std.testing.expect(mem.indexOf(u8, whole, &seed) != null);

    key.deinit();

    try std.testing.expect(mem.indexOf(u8, whole, &seed) == null);

    // And the handle no longer claims to hold a key, so a use-after-deinit is an
    // error rather than a signature over wiped material.
    try std.testing.expect(key.ed25519_key_pair == null);
    try std.testing.expectError(error.NotEd25519Key, key.signEd25519Sha256("x"));
}

// C-2. The cached keypair must produce the identical signature to deriving one per
// call -- otherwise this was not a caching change, it was a behaviour change.
test "the cached keypair signs identically to a per-call derivation" {
    const seed = [_]u8{0x11} ** 32;
    const data = "canonicalized signing input";

    var key = try loadEd25519Seed(seed);
    defer key.deinit();

    const cached = try key.signEd25519Sha256(data);
    const one_shot = try ed25519Sha256Sign(seed, data);
    try std.testing.expectEqualSlices(u8, &one_shot, &cached);

    // Ed25519 is deterministic, so repeated signing is byte-identical too. This is
    // what makes the cache safe: there is no per-signature state to lose.
    const again = try key.signEd25519Sha256(data);
    try std.testing.expectEqualSlices(u8, &cached, &again);
}

test "ed25519-sha256 signs the SHA-256 digest, not the signing input (RFC 8463 3)" {
    const seed = [_]u8{0x42} ** 32;
    const data = "test message for signing";
    const sig = try ed25519Sha256Sign(seed, data);

    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const pub_key = kp.public_key.toBytes();

    try std.testing.expect(try ed25519Sha256Verify(pub_key, data, sig));
    try std.testing.expect(!try ed25519Sha256Verify(pub_key, "wrong message", sig));

    // Everything above is a round trip, and a round trip is what let the
    // original bug ship: sign and verify both used the signing input as the
    // EdDSA message, agreed with each other perfectly, and interoperated with
    // nothing. The two checks below are the ones with teeth, because they
    // compare against std.crypto rather than against our other function.
    const digest = sha256(data);
    const parsed = Ed25519.Signature.fromBytes(sig);

    // The EdDSA message MUST be the 32-byte SHA-256 digest.
    try parsed.verify(&digest, kp.public_key);

    // And it MUST NOT be the signing input itself.
    const raw_input_verifies = blk: {
        parsed.verify(data, kp.public_key) catch break :blk false;
        break :blk true;
    };
    try std.testing.expect(!raw_input_verifies);
}

/// Generate an RSA key of a given size for tests.
fn testGenRsa(bits: c_int) !*c.EVP_PKEY {
    const ctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null) orelse return error.CtxFailed;
    defer c.EVP_PKEY_CTX_free(ctx);
    if (c.EVP_PKEY_keygen_init(ctx) != 1) return error.KeygenInitFailed;
    if (c.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) != 1) return error.KeygenBitsFailed;
    var pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_keygen(ctx, &pkey) != 1) return error.KeygenFailed;
    return pkey orelse error.KeygenFailed;
}

/// Serialize a key's SubjectPublicKeyInfo, which is exactly what a DKIM p= tag
/// carries once base64-decoded.
fn testSpkiDer(allocator: Allocator, pkey: *c.EVP_PKEY) ![]u8 {
    const pkey_const: ?*const c.EVP_PKEY = @ptrCast(pkey);
    const len = c.i2d_PUBKEY(pkey_const, null);
    if (len <= 0) return error.PubkeyExportFailed;
    const buf = try allocator.alloc(u8, @intCast(len));
    errdefer allocator.free(buf);
    var out: [*c]u8 = buf.ptr;
    if (c.i2d_PUBKEY(pkey_const, &out) != len) return error.PubkeyExportFailed;
    return buf;
}

test "resolveMinRsaBits raises below the RFC 8301 floor and honours above it" {
    // A configured value under the floor is raised, and says so.
    const low = resolveMinRsaBits(512);
    try std.testing.expectEqual(RFC8301_MIN_RSA_BITS, low.bits);
    try std.testing.expect(low.raised);

    // 0 does not mean "no limit" here, unlike the Max* resource caps: a MUST NOT
    // must not be switchable off from a config file.
    const zero = resolveMinRsaBits(0);
    try std.testing.expectEqual(RFC8301_MIN_RSA_BITS, zero.bits);
    try std.testing.expect(zero.raised);

    // Exactly the floor is not a "raise" and should not be reported as one.
    const at = resolveMinRsaBits(1024);
    try std.testing.expectEqual(@as(u32, 1024), at.bits);
    try std.testing.expect(!at.raised);

    // A site tightening past the RFC keeps its own stricter value.
    const strict = resolveMinRsaBits(2048);
    try std.testing.expectEqual(@as(u32, 2048), strict.bits);
    try std.testing.expect(!strict.raised);
}

test "public key at or above the minimum loads and reports its size" {
    const pkey = try testGenRsa(2048);
    defer c.EVP_PKEY_free(pkey);
    const der = try testSpkiDer(std.testing.allocator, pkey);
    defer std.testing.allocator.free(der);

    var bits: u32 = 0;
    const loaded = try loadRsaPublicKeyDer(der, RFC8301_MIN_RSA_BITS, &bits);
    defer freePublicKey(loaded);
    try std.testing.expectEqual(@as(u32, 2048), bits);
}

test "512-bit public key is refused, and its size is still reported" {
    // The size RFC 8301 exists to exclude, and the one that is genuinely
    // factorable. Without the check in loadRsaPublicKeyDer this call succeeds
    // and rsaVerify goes on to report a good signature.
    const pkey = try testGenRsa(512);
    defer c.EVP_PKEY_free(pkey);
    const der = try testSpkiDer(std.testing.allocator, pkey);
    defer std.testing.allocator.free(der);

    var bits: u32 = 0;
    try std.testing.expectError(
        error.RsaKeyTooSmall,
        loadRsaPublicKeyDer(der, RFC8301_MIN_RSA_BITS, &bits),
    );
    // found_bits is written even on rejection so the caller can say "512".
    try std.testing.expectEqual(@as(u32, 512), bits);
}

test "a stricter configured minimum refuses an RFC-legal key" {
    const pkey = try testGenRsa(1024);
    defer c.EVP_PKEY_free(pkey);
    const der = try testSpkiDer(std.testing.allocator, pkey);
    defer std.testing.allocator.free(der);

    // 1024 satisfies the RFC but not a site that has moved to 2048.
    try std.testing.expectError(error.RsaKeyTooSmall, loadRsaPublicKeyDer(der, 2048, null));
    // Same key, RFC floor: fine.
    const ok = try loadRsaPublicKeyDer(der, RFC8301_MIN_RSA_BITS, null);
    freePublicKey(ok);
}

test "a non-RSA key in a p= tag is refused as such, not as too small" {
    // An Ed25519 SPKI is 256 bits of curve, which would trip a naive bit
    // comparison and produce a misleading "key too small" for what is really a
    // key-type mismatch.
    const raw = [_]u8{0x11} ** 32;
    const ed = c.EVP_PKEY_new_raw_public_key(c.EVP_PKEY_ED25519, null, &raw, raw.len) orelse
        return error.EdKeyFailed;
    defer c.EVP_PKEY_free(ed);
    const der = try testSpkiDer(std.testing.allocator, ed);
    defer std.testing.allocator.free(der);

    try std.testing.expectError(
        error.NotRsaPublicKey,
        loadRsaPublicKeyDer(der, RFC8301_MIN_RSA_BITS, null),
    );
}

test "signing key below the floor is refused at load, and inspectable with 0" {
    const pkey = try testGenRsa(512);
    defer c.EVP_PKEY_free(pkey);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const key_path = try std.fs.path.joinZ(std.testing.allocator, &.{ dir_path, "weak.key" });
    defer std.testing.allocator.free(key_path);

    const bio = c.BIO_new_file(key_path.ptr, "w") orelse return error.BioCreateFailed;
    if (c.PEM_write_bio_PrivateKey(bio, pkey, null, null, 0, null, null) != 1) {
        _ = c.BIO_free(bio);
        return error.PemWriteFailed;
    }
    _ = c.BIO_free(bio);

    // Signing with this key would emit mail that every conformant verifier
    // permanently fails, so loading it for use is an error.
    try std.testing.expectError(
        error.RsaKeyTooSmall,
        loadRsaKeyFile(key_path, RFC8301_MIN_RSA_BITS),
    );

    // 0 is the inspect-only path the key tools use: load it, report on it.
    var key = try loadRsaKeyFile(key_path, 0);
    defer key.deinit();
    try std.testing.expectEqual(@as(u32, 512), signingKeyBits(&key));
}

test "rsa key load from pem bytes" {
    // Minimal test: generate a key in memory via OpenSSL, sign, verify
    const ctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null) orelse return error.CtxFailed;
    defer c.EVP_PKEY_CTX_free(ctx);

    if (c.EVP_PKEY_keygen_init(ctx) != 1) return error.KeygenInitFailed;
    if (c.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) != 1) return error.KeygenBitsFailed;

    var pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_keygen(ctx, &pkey) != 1) return error.KeygenFailed;
    defer c.EVP_PKEY_free(pkey);

    const data = "DKIM test data to sign";
    const sig = try rsaSign(std.testing.allocator, pkey.?, data);
    defer std.testing.allocator.free(sig);

    try std.testing.expect(sig.len > 0);
    try std.testing.expect(try rsaVerify(pkey.?, data, sig));
    try std.testing.expect(!try rsaVerify(pkey.?, "tampered data", sig));
}
