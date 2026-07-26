# securemilter-crypto

Shared cryptographic library for the SecureMilter suite, used by SecureDKIM and SecureARC.

## Modules

- **crypto** — RSA-SHA256 sign/verify (OpenSSL EVP), Ed25519-SHA256 sign/verify (Zig std.crypto), SHA-256 hashing, base64 encode/decode, PEM/DER key loading
- **canon** — DKIM/ARC header and body canonicalization per RFC 6376 §3.4 (simple + relaxed algorithms)

## Why a separate library?

- securespf and securedmarc don't need crypto/canon — smaller trust boundary, no libcrypto linkage
- Focused security review surface — all OpenSSL C interop lives here
- Independent versioning — crypto algorithm updates don't force version bumps on the protocol library

## External C Dependencies

- `libcrypto` (from OpenSSL) — RSA operations only

## License

BSD-2-Clause. Copyright (c) 2026, Daniel Morante.
