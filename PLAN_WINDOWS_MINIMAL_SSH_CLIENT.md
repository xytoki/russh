# Windows-Only Minimal SSH Client Plan (russh Subset)

This document describes a staged plan to subset `russh` for a Windows-only, size-sensitive product.

Product requirements:
- Windows-only client integration (no server work).
- Authentication: password only.
- Features needed: `exec`, `sftp`, local port forwarding.
- No local config reading (no `~/.ssh/config`, no `known_hosts` file).
- Host key validation: pinning only (no TOFU cache, no local cache).
- Accept reduced algorithm compatibility; target interoperability with OpenSSH or full `russh` servers.

We are currently working in WSL for fast iteration.
Proposed workflow:
1) In WSL: introduce minimal compile-time features and aggressively trim algorithms/content while keeping the existing crypto backend.
2) On Windows: implement and validate a CNG (BCrypt/NCrypt) crypto backend, then remove third-party crypto dependencies.

---

## Progress (Stage 1)

Status: **Done (WSL stage for algorithm/content trimming + pinning wiring + opt-in interop verification)**.

Implemented in this repo clone:
- Minimal-build features in `russh/Cargo.toml`:
  - `algo-minimal` (algorithm registry + negotiation trimming)
  - `client-minimal` (currently implies `algo-minimal`; module-level trimming is not yet implemented)
  - `pqc-mlkem` (PQC KEX is feature-gated; `libcrux-ml-kem` is now optional)
- Algorithm trimming under `algo-minimal`:
  - KEX: only `ecdh-sha2-nistp256`
  - Ciphers: only `aes128/256-gcm@openssh.com`
  - Host key algorithms: keep **ECDSA P-256** and RSA-SHA2-256
  - Remove/disable under minimal: DH groups/GEX, curve25519, `chacha20-poly1305@openssh.com`, Ed25519, PQ KEX
- Host key pinning hook:
  - `client::Config.host_key_pin_checker: Option<Box<dyn Fn(&[u8; 32]) -> bool + Send + Sync>>`
  - Called during handshake; computed fingerprint is SHA-256 over the raw hostkey blob.
- OpenSSH interop verification file (opt-in): `russh/tests/test_wsl_minimal.rs`
  - All tests are `#[ignore]` and require `RUSSH_SSHD_INTEROP=1`.
  - No hardcoded fingerprints.
  - Optional env var `RUSSH_PINNED_HOSTKEY_FPS` for explicit pin list (comma-separated `SHA256:...`).
  - Without `RUSSH_PINNED_HOSTKEY_FPS`, tests still assert the pin checker ran (records a non-empty fingerprint).

Commands:
- Default unit/integration tests (no sshd required):
  - `cargo test -p russh`
- Interop (requires local OpenSSH on 127.0.0.1:2222):
  - `RUSSH_SSHD_INTEROP=1 cargo test -p russh --test test_wsl_minimal -- --ignored`
  - Optional strict pinning:
    - `RUSSH_PINNED_HOSTKEY_FPS=SHA256:xxxx,SHA256:yyyy RUSSH_SSHD_INTEROP=1 cargo test -p russh --test test_wsl_minimal -- --ignored`

Known Stage-1 limitations (intentional):
- `client-minimal` does not yet fully cfg-gate server/agent/config modules. This is left for a later "size pass".
- Stage 1 keeps the existing crypto backend (ring/aws-lc + RustCrypto). Dependency removal is part of Stage 2.

---

## Progress (Stage 2)

Status: **Windows validation complete — CNG backend passes all interop tests against real OpenSSH**.

### 2a. CNG Backend Implementation (pre-existing)

Scaffolding added:
- `russh/Cargo.toml`:
  - New feature `crypto-cng` (depends on `windows` crate, `Win32_Security_Cryptography`).
  - `windows` crate added as optional `cfg(windows)` dependency (v0.61).
  - Enabling `crypto-cng` on non-Windows triggers a compile error.
- `russh/src/lib.rs`:
  - Backend gate updated: at least one of `ring`, `aws-lc-rs`, or `crypto-cng` required.
- Cipher backend (`russh/src/cipher/`):
  - `gcm_cng.rs`: AES-GCM implemented using BCrypt (CNG). Uses `BCryptOpenAlgorithmProvider` + `BCryptSetProperty(BCRYPT_CHAINING_MODE=GCM)` + `BCryptGenerateSymmetricKey` + `BCryptEncrypt`/`BCryptDecrypt` with `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO`.
  - `cipher/mod.rs`: when `cfg(all(windows, feature="crypto-cng"))`, `_AES_128_GCM` and `_AES_256_GCM` statics use `CngGcmCipher` instead of ring/aws-lc `GcmCipher`.
  - Existing `gcm.rs` (ring/aws-lc) is unchanged and active when `crypto-cng` is not enabled.
  - `mod chacha20poly1305` and `mod gcm` are now cfg-gated behind `cfg(any(feature="ring", feature="aws-lc-rs"))` so they are not compiled when only `crypto-cng` is active.
  - Corresponding statics (`_CHACHA20_POLY1305`, `_AES_*_GCM` for ring/aws-lc) and `ALL_CIPHERS`/`CIPHERS` entries are similarly gated.
- KEX backend (`russh/src/kex/`):
  - `ecdh_nistp_cng.rs`: ECDH P-256 KEX implemented using BCrypt (CNG): keypair generation, SEC1 uncompressed point encoding for SSH payload, peer key import, secret agreement, and `BCRYPT_KDF_RAW_SECRET` derivation.
  - `kex/mod.rs`: `CngEcdhNistP256Kex` variant added to `KexAlgorithm` enum (cfg-gated). When `crypto-cng` is active, `ECDH_SHA2_NISTP256` maps to the CNG implementation in the KEXES registry.
  - Existing `ecdh_nistp.rs` remains active when `crypto-cng` is not enabled.
- Host key verification (`russh/src/keys/`):
  - `verify_cng.rs`: RSA-SHA256 and ECDSA-P256 signature verification implemented using BCrypt:
    - RSA: parses SSH `ssh-rsa` key blob (mpint e, mpint n), builds `BCRYPT_RSAPUBLIC_BLOB`, verifies via `BCryptVerifySignature` with `BCRYPT_PAD_PKCS1` + `BCRYPT_PKCS1_PADDING_INFO` (SHA-256).
    - ECDSA P-256: parses SSH `ecdsa-sha2-nistp256` key blob (SEC1 uncompressed Q), builds `BCRYPT_ECCPUBLIC_BLOB` (ECS1 magic). Parses signature mpints (r, s), zero-pads to 32 bytes each, passes `r||s` to `BCryptVerifySignature` (CNG raw ECDSA format).
    - Both functions hash the message (exchange hash) with SHA-256 internally before passing to `BCryptVerifySignature`, matching the ssh_key crate's signing behavior.
  - `keys/mod.rs`: module declared under `cfg(all(windows, feature="crypto-cng"))`.
- Verification wired into KEX handshake (`russh/src/client/kex.rs`):
  - Under `cfg(all(windows, feature="crypto-cng"))`, the `Verifier::verify` call in `WaitingForDhReply` is replaced with dispatch to `verify_cng::verify_rsa_sha256` or `verify_cng::verify_ecdsa_p256` based on server host key algorithm.
  - RSA dispatch includes a guard: rejects signatures not using SHA-256 (defends against rsa-sha2-512 mismatch).
  - Non-CNG builds continue to use `signature::Verifier` (ssh_key crate) unchanged.
- `helpers.rs`: `map_err!` macro re-export now also available under `crypto-cng` feature.
- SHA-256 via BCrypt (`russh/src/crypto_cng/`):
  - `crypto_cng/sha256.rs`: `pub fn sha256(data: &[u8]) -> Result<[u8; 32], Error>` implemented using `BCryptOpenAlgorithmProvider(BCRYPT_SHA256_ALGORITHM)` + `BCryptGetProperty(BCRYPT_OBJECT_LENGTH/BCRYPT_HASH_LENGTH)` + `BCryptCreateHash` + `BCryptHashData` + `BCryptFinishHash`. RAII wrappers for algorithm provider and hash handle. Internal hash state buffer is zeroized before return.
  - `crypto_cng/mod.rs`: module facade, re-exports `sha256`.
  - `lib_inner.rs`: `pub(crate) mod crypto_cng` declared under `cfg(all(windows, feature="crypto-cng"))`.
  - `client/mod.rs`: `compute_host_key_fingerprint_sha256` has CNG code path using `crate::crypto_cng::sha256` instead of `sha2::Sha256` when `crypto-cng` is enabled. Non-CNG code path unchanged.
  - `kex/ecdh_nistp_cng.rs`: `compute_exchange_hash` now uses `crate::crypto_cng::sha256` instead of `sha2::Sha256::new()` / `Digest` trait methods. `compute_keys` still uses `sha2::Sha256` as generic type parameter (Digest trait-based key derivation unchanged).

All changes are cfg-gated behind `cfg(all(windows, feature="crypto-cng"))`. Existing functionality when `crypto-cng` is not enabled is completely unchanged.

### 2b. Windows Validation Fixes

The following issues were discovered and fixed during Windows compilation and interop testing:

**Critical correctness fixes:**
- `BCRYPT_KDF_RAW_SECRET` byte order: CNG returns little-endian; SSH requires big-endian. Added `.reverse()` after derivation in `ecdh_nistp_cng.rs`. Without this, all interop with real OpenSSH fails (exchange hash mismatch → `WrongServerSig`).
- `verify_cng.rs` SHA-256 pre-hash: Both `verify_rsa_sha256` and `verify_ecdsa_p256` must hash the exchange hash with SHA-256 before passing to `BCryptVerifySignature`, because the server-side `ssh_key` crate hashes the message internally during signing, and CNG's `BCryptVerifySignature` expects the pre-hashed value.

**Windows crate v0.62 API adaptation (5 compile errors):**
- `BCryptExportKey` / `BCryptImportKeyPair`: `hexportkey`/`himportkey` parameters changed from `BCRYPT_KEY_HANDLE` to `Option<BCRYPT_KEY_HANDLE>`. Fixed: `BCRYPT_KEY_HANDLE::default()` → `None` in `ecdh_nistp_cng.rs` (3 sites) and `verify_cng.rs` (2 sites).
- `BCryptGetProperty`: first parameter changed from `BCRYPT_ALG_HANDLE` to `BCRYPT_HANDLE`. Fixed: `alg.0` → `alg.0.into()` in `crypto_cng/sha256.rs`.

**Other compile fixes:**
- `sha256()` returns `Result` but callers didn't propagate: added `?` in `ecdh_nistp_cng.rs` (1 site) and `kex/mod.rs` (2 sites).
- Unix-only dev-dependencies (`termion`, `tokio-fd`, `ratatui`) moved to `[target.'cfg(unix)'.dev-dependencies]` in `Cargo.toml`.
- Unused import warnings for ring/aws-lc `AES_*_GCM` when `crypto-cng` active: added `not(all(windows, feature="crypto-cng"))` to import cfg-gates in `cipher/mod.rs`.

**Security hardening (from Oracle review):**
- RSA signature algorithm guard: CNG RSA verify only supports SHA-256. Added runtime check in `client/kex.rs` that rejects signatures not using `rsa-sha2-256`.
- ECDSA `left_pad` tightened: now returns `Result`; rejects inputs with more than 32 significant (non-zero) bytes instead of silently truncating.
- `encode_mpint` all-zero panic: added early return for all-zero / empty input (previously caused index-out-of-bounds).
- Secret material zeroization: `CngEcdhNistP256Kex` now implements `Drop` that zeroizes `shared_secret` via `zeroize` crate. `sha256()` zeroizes internal `hash_obj` buffer before returning.
- `BCryptGenerateSymmetricKey` with `None` key object buffer: documented as valid on Win8+ (targeting Win10+).

**Test infrastructure fixes:**
- Test server key generation: under `algo-minimal`, tests now generate ECDSA P-256 keys instead of Ed25519 (conditional via `test_key_algorithm()` helper in `tests.rs` and `client/test.rs`).
- Docker-based interop test environment: added `Dockerfile.sshd-test` and `sshd_config_test` in `russh/tests/`. Runs a standalone OpenSSH server on port 2200 with user `russh_test`/`russh_test`, restricted to algo-minimal algorithms only.

### 2c. Test Results

- `cargo test -p russh --features algo-minimal,crypto-cng --lib`: **38/38 passed**
- `cargo test -p russh --features algo-minimal,crypto-cng --test test_wsl_minimal -- --ignored` (against Docker OpenSSH): **5/5 passed**
  - `test_exec_with_pinning` ✓ (full handshake + password auth + exec + output check)
  - `test_sftp_with_pinning` ✓ (SFTP read/write/delete)
  - `test_local_port_forward_with_pinning` ✓ (direct-tcpip port forward)
  - `test_fingerprint_computation` ✓ (SHA-256 fingerprint format)
  - `test_pinning_rejects_wrong_fingerprint` ✓ (pin rejection aborts connection)

Commands:
- Default unit tests (no sshd required):
  - `cargo test -p russh --features algo-minimal,crypto-cng --lib`
- Interop with Docker sshd:
  - Build: `docker build -f russh/tests/Dockerfile.sshd-test -t russh-sshd-test russh/tests/`
  - Run: `docker run --rm -p 2200:2200 russh-sshd-test`
  - Test: `set RUSSH_SSHD_INTEROP=1 && cargo test -p russh --features algo-minimal,crypto-cng --test test_wsl_minimal -- --ignored`
  - With strict pinning: `set RUSSH_PINNED_HOSTKEY_FPS=SHA256:xxxx && set RUSSH_SSHD_INTEROP=1 && cargo test ...`

### 2d. Module-Level cfg-Gating (completed)

Extensive cfg-gating applied so that `--no-default-features --features algo-minimal,crypto-cng` excludes non-CNG code:
- `kex/mod.rs`: `mod curve25519`, `mod dh` gated behind `not(algo-minimal)`; `mod ecdh_nistp` behind `any(ring, aws-lc-rs)`. KexAlgorithm enum variants, KexType consts, generic `compute_keys<D: Digest>` all gated. Stub `DhGroup` under `algo-minimal`.
- `mac/mod.rs`: HMAC statics, crypto/crypto_etm modules gated behind `not(algo-minimal)`. Under algo-minimal only `NONE` MAC.
- `negotiation.rs`: `HMAC_ORDER` split by feature.
- `kex/none.rs`: CNG path for `compute_keys` when ring/aws-lc-rs not present.
- `kex/ecdh_nistp.rs`: P-384/P-521 gated behind `not(algo-minimal)`.
- `client/kex.rs`, `server/kex.rs`, `server/mod.rs`: DH GEX code gated behind `not(algo-minimal)`.

### 2e. CNG Wire Parser (completed)

- `keys/wire.rs`: Minimal SSH wire format parser replacing `ssh-key` for the CNG handshake path. Provides `parse_key_algo()` and `parse_signature()`. Handles only algo-minimal subset: `ssh-rsa`, `rsa-sha2-256`, `ecdsa-sha2-nistp256`.
- `client/kex.rs`: CNG block now uses wire parser instead of `ssh_key::PublicKey::from_bytes()` / `ssh_key::Signature::decode()`. Non-CNG path unchanged.
- `ssh-key` made optional in `Cargo.toml`, pulled in by `aws-lc-rs` and `ring` features.

### 2f. Build verification

All three build configurations compile and pass tests:

- `cargo check -p russh --no-default-features --features client-minimal,crypto-cng`: ✅ compiles (0 errors)
- `cargo check -p russh` (default, aws-lc-rs): ✅ compiles (0 errors)
- `cargo test -p russh --no-default-features --features client-minimal,crypto-cng --lib`: ✅ 1/1 passed (server-dependent tests gated out)
- `cargo test -p russh --lib` (default): ✅ 38/38 passed
- Interop test (Docker OpenSSH): ✅ 5/5 passed

Commands:
- Default unit tests (no sshd required):
  - `cargo test -p russh --no-default-features --features client-minimal,crypto-cng --lib`
- Interop with Docker sshd:
  - Build: `docker build -f russh/tests/Dockerfile.sshd-test -t russh-sshd-test russh/tests/`
  - Run: `docker run --rm -p 2200:2200 russh-sshd-test`
  - Test: `set RUSSH_SSHD_INTEROP=1 && cargo test -p russh --no-default-features --features client-minimal,crypto-cng --test test_wsl_minimal -- --ignored`
  - With strict pinning: `set RUSSH_PINNED_HOSTKEY_FPS=SHA256:xxxx && set RUSSH_SSHD_INTEROP=1 && cargo test ...`

### 2g. client-minimal Module Trimming (completed)

`client-minimal` feature now gates out all modules unnecessary for a password-only SSH client:

**Module-level gating** (`#[cfg(not(feature = "client-minimal"))]`):
- `mod server` — entire server module (combined with existing `not(wasm32)` gate)
- `mod cert` — certificate handling (`PublicKeyOrCertificate`)
- `keys::agent` — SSH agent client/server
- `keys::format` — key format parsing (openssh, pkcs5, pkcs8, pkcs8_legacy)
- `keys::mod.rs` — `load_public_key`, `load_secret_key`, `load_openssh_certificate`, `parse_public_key_base64` file I/O functions
- `mod tests` (lib_inner.rs), `client::test`, `keys::mod.rs` tests — server-dependent test code

**Code path gating** (`#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]`):
- `client/encrypted.rs` — `client_make_to_sign`, `client_send_signature` methods + `PublicKey`/`OpenSshCertificate`/`FuturePublicKey` auth match arms
- `helpers.rs` — `sign_with_hash_alg()` function (uses `signature` crate)
- `lib_inner.rs` — `Signature(#[from] signature::Error)` error variant
- `server/kex.rs`, `server/encrypted.rs`, `keys/agent/server.rs` — `sign_with_hash_alg` and `signature::Verifier` imports

**rand_core replacement** (eliminates `ssh_key::rand_core` dependency under algo-minimal):
- `keys/key.rs` — new `fill_random()` function: under `algo-minimal` uses `BCryptGenRandom` directly via the `windows` crate; under non-algo-minimal uses `rand::rng().fill_bytes()`
- `negotiation.rs`, `cipher/gcm_cng.rs` — callers migrated from `safe_rng().fill_bytes()` to `fill_random()`

**`auth.rs`**:
- `impl Signer for AgentClient<R>` gated under `not(client-minimal)` (references `keys::agent`)

### 2h. Cargo.toml Dependency Optimization (partially completed)

- `ssh-key` changed from `workspace = true` to inline definition with `default-features = false, optional = true`
- New `_crypto-common` internal feature bundles all non-CNG crypto deps (sha2, digest, hmac, signature, rand, rand_core, aes, cbc, ctr, curve25519-dalek, ed25519-dalek, p256, p384, p521, sec1, etc.)
- `aws-lc-rs` and `ring` features pull in `_crypto-common`
- `crypto-cng` feature: `["dep:windows", "ssh-key/alloc", "ssh-key/std"]` — minimal ssh-key features, no RustCrypto crypto
- `client-minimal` feature: `["algo-minimal"]`
- ~30 RustCrypto/crypto deps made optional

Feature dependency graph:
```
default = ["flate2", "aws-lc-rs", "rsa", "pqc-mlkem"]
aws-lc-rs = ["dep:aws-lc-rs", "dep:ssh-key", "_crypto-common"]
ring = ["dep:ring", "dep:ssh-key", "_crypto-common"]
crypto-cng = ["dep:windows", "ssh-key/alloc", "ssh-key/std"]
client-minimal = ["algo-minimal"]
algo-minimal = []
```

### 2i. Remaining Work

- **Deep dep pruning**: Verify `cargo tree` under `client-minimal,crypto-cng` shows minimal dependency set. Identify and eliminate any remaining unnecessary transitive deps.
- **Size measurement**: Compare binary size of `client-minimal,crypto-cng` build vs default build.
- **`algo-minimal,crypto-cng` (without `client-minimal`)**: Currently has 4 compile errors in server signing code. This is by design — server requires `ring`/`aws-lc-rs` for signing. Not a priority to fix.
- **Further auth.rs trimming**: Gate `Method::PublicKey`, `Method::OpenSshCertificate`, `Method::FuturePublicKey` enum variants under `not(client-minimal)` for smaller binary.
- **Minimum Windows version**: Document requirement (Vista SP2+ for all BCrypt APIs used).

---

## 1. Current Repo Facts (As-Is)

Workspace: `russh`, `russh-config`, `russh-util`, `russh-cryptovec`, `pageant`.

Important `russh` design constraints:
- `russh/src/lib.rs` currently enforces: at least one of the crypto backend features `aws-lc-rs` or `ring` must be enabled.
- Algorithms are registered via static tables with invariants:
  - `ALL_CIPHERS` + `CIPHERS` map in `russh/src/cipher/mod.rs` with `assert_eq!(h.len(), ALL_CIPHERS.len())`.
  - `ALL_KEX_ALGORITHMS` + `KEXES` map in `russh/src/kex/mod.rs` with `assert_eq!(ALL_KEX_ALGORITHMS.len(), h.len())`.
  - `ALL_MAC_ALGORITHMS` + `MACS` map in `russh/src/mac/mod.rs` with `assert_eq!(h.len(), ALL_MAC_ALGORITHMS.len())`.
  Any algorithm trimming must keep list+map in sync.

Crypto surface is currently broad:
- AEAD ciphers (`aes*-gcm@openssh.com`, `chacha20-poly1305@openssh.com`) depend on `aws-lc-rs` or `ring`.
- MACs and many other pieces use RustCrypto crates.
- PQ hybrid KEX `mlkem768x25519-sha256` exists and is currently wired into defaults.

---

## 2. Target Algorithm Subset (Minimal, Interop-Oriented)

The goal is to minimize code paths and avoid OpenSSH-specific constructions that are hard to reproduce with Windows CNG.

Recommended minimal subset:

### 2.1 KEX
- Keep: `ecdh-sha2-nistp256` only.
- Drop: curve25519 variants, all finite-field DH groups/GEX, all PQ KEX.

Rationale: ECDH P-256 is a standard, widely supported by OpenSSH and supported in Windows CNG.

### 2.2 Ciphers
- Keep: `aes128-gcm@openssh.com` (optionally also `aes256-gcm@openssh.com`).
- Drop: `chacha20-poly1305@openssh.com`, all CTR/CBC.

Rationale:
- `chacha20-poly1305@openssh.com` is an OpenSSH-specific construction (currently backed by ring/aws-lc `*_openssh`).
  Windows CNG provides RFC8439 ChaCha20-Poly1305, which is not a drop-in replacement.
- Keeping only GCM avoids separate MAC selection and drastically simplifies the transport.

### 2.3 Host Key Algorithms (Verification)
- Keep:
  - `rsa-sha2-256`
  - `ecdsa-sha2-nistp256`
- Drop: `ssh-ed25519`, DSA, security-key variants.

Rationale:
- We need host key verification for pinning.
- Windows CNG can support RSA and ECDSA P-256.
- Ed25519/EdDSA is not part of the standard CNG algorithm identifier set and would likely require non-system crypto.

### 2.4 MACs
- Intention: avoid MAC negotiation by using AEAD-only cipher set.

---

## 3. Host Key Pinning Model (No Cache, No Local Files)

We implement pinning as a pure in-memory policy provided by the embedding product.

### 3.1 Policy API
Inputs from the product:
- A list of allowed server host keys by destination (host:port), expressed as SHA-256 fingerprints.

Suggested representation:
- `Vec<PinEntry>` where each entry contains:
  - destination selector (exact host:port or wildcard group managed by the product)
  - algorithm enum: RSA or ECDSA-P256
  - fingerprint: 32-byte SHA-256 digest of the raw SSH host key blob (or OpenSSH-style base64 string)

### 3.2 Handshake requirements
During KEX:
1) Parse the server host key blob as received in `KEX_REPLY`.
2) Compute SHA-256 over the exact blob bytes.
3) Check fingerprint against the product-provided allowlist.
4) Verify the server's KEX signature using that host public key.
5) If any step fails: abort connection.

Notes:
- Pinning without signature verification is not sufficient.
- No reading/writing local known_hosts files.

---

## 4. Staged Delivery Plan

### Stage 1 (WSL): Feature-gating + Algorithm/Content Trimming

Goal: get a minimal build that supports `exec`, `sftp`, and local port forwarding, using existing crypto backend(s) for now.

Deliverables:
1) New compile features in `russh`:
   - `client-minimal`: only compile client-side code required for exec/sftp/port-forward + transport.
   - `algo-minimal`: only register/advertise the minimal algorithm subset.
   - `pqc-mlkem`: gates PQ KEX implementation and tests.
2) Algorithm trimming implementation (must keep list/map invariants):
   - `russh/src/negotiation.rs`: update `SAFE_KEX_ORDER`, `CIPHER_ORDER`, and `Preferred::DEFAULT.key`.
   - `russh/src/cipher/mod.rs`: keep only AES-GCM ciphers in `ALL_CIPHERS`/`CIPHERS` when `algo-minimal`.
   - `russh/src/kex/mod.rs`: keep only ECDH P-256 KEX in `ALL_KEX_ALGORITHMS`/`KEXES` when `algo-minimal`.
   - `russh/src/keys/key.rs`: keep only RSA/ECDSA-P256 key types when `algo-minimal`.
3) Disable local config reading:
   - Make `russh-config` optional at the product layer; do not link it in minimal client build.
4) Pinning hook:
   - Add a public callback in client config to validate the server host key fingerprint.
5) Testing in WSL:
   - Spin up a local OpenSSH server with explicit algorithms enabled.
   - Test exec, SFTP, and local port forwarding.

Exit criteria:
- Minimal feature build compiles in WSL.
- Negotiation consistently selects only the minimal algorithms.
- exec/sftp/port-forward pass against OpenSSH.

### Stage 2 (Windows): CNG Migration + Verification

Goal: implement crypto using Windows CNG and remove third-party crypto backends.

Deliverables:
1) New feature: `crypto-cng` (Windows-only).
   - Update `russh/src/lib.rs` backend gate to allow `crypto-cng` as a valid backend.
2) Implement minimal primitives via CNG:
   - SHA-256 (fingerprints + exchange hash)
   - ECDH P-256 (KEX)
   - AES-GCM (cipher)
   - RSA-SHA256 verify and ECDSA-P256 verify (host key signature verify)
   - RNG as needed
3) Remove dependencies in the minimal build:
   - `ring`, `aws-lc-rs`.
   - RustCrypto cipher/mac/hash/kex/signature crates, as they become unused.
   - Eliminate `ssh-key` and ASN.1/PKCS parsing stack if host key parsing is implemented directly from SSH wire format.
4) Windows validation:
   - Run the same interop tests against WSL OpenSSH.
   - Verify host key pinning behavior.
   - Measure binary size deltas after dependency removal.

Exit criteria:
- Minimal client build on Windows has no `ring`/`aws-lc-rs` and minimal/no RustCrypto crypto dependencies.
- exec/sftp/port-forward interop passes with pinning.

---

## 5. SFTP Packaging Options

Requirement: SFTP client support.

Option A (fast): depend on an external SFTP client crate.
- Pros: fastest path to feature completeness.
- Cons: adds dependencies and size.

Option B (small): implement minimal SFTP v3 subset in-tree.
- Pros: best size control.
- Cons: more engineering, more interop testing.

Recommendation for staged delivery:
- Stage 1: Option A to validate product integration quickly.
- Stage 2+: evaluate replacing with Option B if size budget requires it.

---

## 6. Reference: Windows CNG Capabilities

Useful Microsoft documentation:
- CNG Algorithm Identifiers: https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
- CNG Named Elliptic Curves (includes curve25519 and NIST curves): https://learn.microsoft.com/en-us/windows/win32/seccng/cng-named-elliptic-curves
- CNG property identifiers (including GCM): https://learn.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers
- AEAD parameters struct: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info
- HMAC via BCryptCreateHash: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
