# Analysis: Can native-tls / SChannel / WinCrypto Replace ring/aws-lc-rs in russh?

## Executive Summary

**No — native-tls and SChannel cannot replace ring/aws-lc-rs in this codebase.** They operate at the wrong abstraction level (TLS protocol sessions vs. raw AEAD primitives). Windows CNG/BCrypt *could* theoretically provide the raw primitives, but the effort and trade-offs make it impractical. Details below.

---

## 1. What ring/aws-lc-rs Actually Provide in russh

ring and aws-lc-rs are used **exclusively** for AEAD (Authenticated Encryption with Associated Data) cipher operations in three files:

| File | APIs Used | Purpose |
|------|-----------|---------|
| `russh/src/cipher/mod.rs` | `AES_128_GCM`, `AES_256_GCM` (static algorithm constants) | Cipher registry |
| `russh/src/cipher/gcm.rs` | `UnboundKey`, `BoundKey`, `NonceSequence`, `AeadOpeningKey`, `AeadSealingKey`, `Aad`, `Nonce`, `NONCE_LEN` | AES-128/256-GCM encrypt/decrypt |
| `russh/src/cipher/chacha20poly1305.rs` | `chacha20_poly1305_openssh::{OpeningKey, SealingKey, KEY_LEN, TAG_LEN}` | OpenSSH-specific ChaCha20-Poly1305 |

**Specific low-level primitives required:**
- **AES-128-GCM** and **AES-256-GCM**: AEAD seal/open with separate tag, nonce sequence management, AAD support
- **ChaCha20-Poly1305 (OpenSSH variant)**: A non-standard construction with separate packet-length encryption, NOT the RFC 8439 AEAD — uses two ChaCha20 keys (one for header, one for payload), Poly1305 MAC derivation from ChaCha20 keystream, and sequence-number-based nonces

**Everything else** — key exchange (Curve25519, NIST P-curves, DH, ML-KEM), signatures (Ed25519, ECDSA, RSA), hashing (SHA-1/2), HMAC, AES-CTR/CBC — already uses pure-Rust crates (`curve25519-dalek`, `ed25519-dalek`, `p256`/`p384`/`p521`, `aes`, `sha2`, `hmac`, etc.) and does **not** depend on ring or aws-lc-rs.

---

## 2. What native-tls Provides

`native-tls` (v0.2.18) is a **TLS protocol wrapper** — it establishes TLS sessions over byte streams. Its API surface is:

- `TlsConnector` / `TlsAcceptor` — high-level TLS handshake
- `TlsStream<S>` — encrypted read/write stream
- Certificate/identity management

**It does NOT expose:**
- Raw AES-GCM encrypt/decrypt
- Raw ChaCha20-Poly1305 operations
- Any low-level AEAD primitives
- Nonce management
- Key material handling

**Conclusion: native-tls is categorically unusable.** SSH is not TLS — russh implements the SSH protocol directly and needs raw cipher primitives, not a TLS session layer.

---

## 3. What SChannel Provides

The `schannel` crate (v0.1.28) is a Rust wrapper for Windows SChannel, providing **TLS session management** — the same abstraction level as native-tls, just Windows-specific:

- `TlsStream` — encrypted stream
- Certificate context management
- SSPI credential handles

**It does NOT expose:**
- Raw AES-GCM or ChaCha20-Poly1305 primitives
- Any low-level AEAD operations

**Conclusion: The `schannel` crate is equally unusable** for the same reason as native-tls.

---

## 4. What About Windows CNG/BCrypt Directly?

Windows CNG (Cryptography Next Generation) via the BCrypt API **does** expose low-level primitives:

- `BCryptEncrypt` / `BCryptDecrypt` with `BCRYPT_AES_ALGORITHM` + `BCRYPT_CHAIN_MODE_GCM` → AES-GCM ✓
- `BCRYPT_CHACHA20_POLY1305_ALGORITHM` → ChaCha20-Poly1305 (added in Windows 11 / Server 2022) ⚠️

**However, there are critical blockers:**

### 4a. The OpenSSH ChaCha20-Poly1305 Problem

russh uses the **OpenSSH-specific** ChaCha20-Poly1305 construction (`chacha20-poly1305@openssh.com`), which is **not** standard RFC 8439 AEAD. It features:
- Two separate 256-bit keys (K_main for payload, K_header for packet length)
- Per-packet nonces derived from SSH sequence numbers
- Poly1305 key derived from ChaCha20 keystream block 0
- Separate packet-length encryption step

Windows BCrypt provides only the **standard** ChaCha20-Poly1305 AEAD. There is no API for the OpenSSH construction. You would need to:
1. Use raw ChaCha20 stream cipher from BCrypt (not available as a separate primitive)
2. Use raw Poly1305 MAC from BCrypt (not available as a separate primitive)
3. Manually compose the OpenSSH construction from those primitives

**BCrypt does not expose raw ChaCha20 or raw Poly1305 as separate primitives** — it only offers the combined AEAD. This makes it **impossible** to implement the OpenSSH variant using BCrypt alone.

### 4b. Platform Restriction

Windows CNG is Windows-only. russh is a cross-platform library (Linux, macOS, Windows, WASM). A Windows-only crypto backend would:
- Require maintaining a separate code path for Windows
- Still need ring/aws-lc-rs (or another backend) for all other platforms
- Not eliminate the ring/aws-lc-rs dependency from the project

### 4c. Unsafe FFI Overhead

Using Windows CNG directly requires:
- `unsafe` FFI calls to `bcrypt.dll`
- Manual memory management for key handles (`BCRYPT_KEY_HANDLE`)
- Careful error handling for NTSTATUS codes
- No Rust type safety for crypto operations

### 4d. Version Requirements

`BCRYPT_CHACHA20_POLY1305_ALGORITHM` is only available on **Windows 11 / Server 2022+**. Older Windows versions would fall back to AES-GCM only, reducing cipher negotiation options.

**Conclusion: Windows CNG/BCrypt is theoretically possible for AES-GCM only, but cannot support the OpenSSH ChaCha20-Poly1305 construction, is Windows-only, requires unsafe FFI, and adds significant maintenance burden for no cross-platform benefit.**

---

## 5. Summary of Findings

| Replacement Candidate | Can Replace ring/aws-lc-rs? | Reason |
|---|---|---|
| **native-tls** | ❌ No | Provides TLS sessions, not raw AEAD primitives |
| **schannel crate** | ❌ No | Same as native-tls, just Windows-specific |
| **Windows CNG/BCrypt** | ⚠️ Partially (AES-GCM only) | Exposes AES-GCM but **cannot** implement OpenSSH ChaCha20-Poly1305; Windows-only; requires unsafe FFI; would not eliminate ring/aws-lc-rs for other platforms |

---

## 6. Architecture Context

The clean separation in russh's architecture means that ring/aws-lc-rs are **already minimally scoped** — touching only 3 files and providing only 2 cipher families (AES-GCM, ChaCha20-Poly1305). The existing dual-backend pattern (`aws-lc-rs` default, `ring` alternative) via `#[cfg(feature = ...)]` gates works well.

**Affected ciphers if ring/aws-lc-rs were removed entirely:**
- `aes128-gcm@openssh.com` — would lose hardware-accelerated AES-GCM
- `aes256-gcm@openssh.com` — same
- `chacha20-poly1305@openssh.com` — would lose the OpenSSH AEAD cipher

**Unaffected ciphers (pure Rust, no ring/aws-lc-rs dependency):**
- `aes128-ctr`, `aes192-ctr`, `aes256-ctr` — via `aes` + `ctr` crates
- `aes128-cbc`, `aes192-cbc`, `aes256-cbc` — via `aes` + `cbc` crates
- `3des-cbc` — via `des` crate (optional, insecure)

**Unaffected subsystems:**
- All key exchange algorithms (Curve25519, ECDH NIST, DH, ML-KEM hybrid)
- All signature algorithms (Ed25519, ECDSA, RSA)
- All MAC algorithms (HMAC-SHA1, HMAC-SHA2)
- Key parsing, agent communication, SSH protocol state machine
