// Windows CNG host key signature verification (Stage 2).
//
// Provides RSA-SHA256 and ECDSA-P256 signature verification using
// BCryptVerifySignature with BCRYPT_RSA_ALGORITHM / BCRYPT_ECDSA_P256_ALGORITHM.
//
// ## SSH wire formats parsed here
//
// ### RSA public key blob (RFC 4253 §6.6)
//   string  "ssh-rsa"
//   mpint   e   (public exponent)
//   mpint   n   (modulus)
//
// ### ECDSA public key blob (RFC 5656 §3.1)
//   string  "ecdsa-sha2-nistp256"
//   string  "nistp256"
//   string  Q   (SEC1 uncompressed point: 0x04 || x || y)
//
// ### ECDSA signature blob (RFC 5656 §3.1.2)
//   The signature *value* bytes (inside the outer "ssh-sig" wrapper) contain:
//     mpint   r
//     mpint   s
//   CNG expects raw `r || s` with each component zero-padded to 32 bytes.
//
// ### RSA signature
//   The signature value bytes are the raw PKCS#1 v1.5 signature octet string.
//
// All functions receive the raw exchange hash H as `message`.  They hash it
// with SHA-256 internally before calling BCryptVerifySignature, because the
// ssh_key crate's Signer::sign() also hashes the message before signing.

use std::ffi::c_void;

use byteorder::{BigEndian, ByteOrder};
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptImportKeyPair,
    BCryptOpenAlgorithmProvider, BCryptVerifySignature, BCRYPT_ALG_HANDLE, BCRYPT_ECCPUBLIC_BLOB,
    BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_FLAGS, BCRYPT_KEY_HANDLE,
    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_PAD_PKCS1, BCRYPT_PKCS1_PADDING_INFO,
    BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSA_ALGORITHM,
};

use crate::keys::Error;

// ---------------------------------------------------------------------------
// RAII wrappers (same pattern as gcm_cng.rs / ecdh_nistp_cng.rs)
// ---------------------------------------------------------------------------

struct CngAlgHandle(BCRYPT_ALG_HANDLE);
impl Drop for CngAlgHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = BCryptCloseAlgorithmProvider(self.0, 0);
        }
    }
}

struct CngKeyHandle(BCRYPT_KEY_HANDLE);
impl Drop for CngKeyHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = BCryptDestroyKey(self.0);
        }
    }
}

// ---------------------------------------------------------------------------
// SSH wire-format helpers
// ---------------------------------------------------------------------------

/// Read an SSH `string` (u32-be length + bytes) from `data`, advancing the slice.
fn read_ssh_string<'a>(data: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    if data.len() < 4 {
        return Err(Error::CouldNotReadKey);
    }
    #[allow(clippy::indexing_slicing)]
    let len = BigEndian::read_u32(&data[..4]) as usize;
    *data = &data[4..];
    if data.len() < len {
        return Err(Error::CouldNotReadKey);
    }
    #[allow(clippy::indexing_slicing)]
    let value = &data[..len];
    *data = &data[len..];
    Ok(value)
}

/// Read an SSH `mpint` and return its unsigned big-endian bytes (strip leading zero).
fn read_ssh_mpint<'a>(data: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let raw = read_ssh_string(data)?;
    // mpint may have a leading 0x00 for sign; strip it for CNG import
    if raw.first() == Some(&0) && raw.len() > 1 {
        #[allow(clippy::indexing_slicing)]
        return Ok(&raw[1..]);
    }
    Ok(raw)
}

/// Zero-pad `src` on the left to exactly `target_len` bytes.
/// Returns an error if `src` has more than `target_len` significant (non-zero) bytes.
fn left_pad(src: &[u8], target_len: usize) -> Result<Vec<u8>, Error> {
    if src.len() > target_len {
        // Allow excess only if the extra leading bytes are all zeros
        let excess = src.len() - target_len;
        #[allow(clippy::indexing_slicing)]
        if src[..excess].iter().any(|&b| b != 0) {
            return Err(Error::InvalidSignature);
        }
        #[allow(clippy::indexing_slicing)]
        return Ok(src[excess..].to_vec());
    }
    if src.len() == target_len {
        return Ok(src.to_vec());
    }
    let mut out = vec![0u8; target_len];
    #[allow(clippy::indexing_slicing)]
    out[target_len - src.len()..].copy_from_slice(src);
    Ok(out)
}

// ---------------------------------------------------------------------------
// RSA-SHA256 verification
// ---------------------------------------------------------------------------

/// BCRYPT_RSAPUBLIC_BLOB layout:
///   BCRYPT_RSAKEY_BLOB header (24 bytes):
///     Magic        (u32 LE) = BCRYPT_RSAPUBLIC_MAGIC = 0x31415352 ("RSA1")
///     BitLength    (u32 LE)
///     cbPublicExp  (u32 LE)
///     cbModulus    (u32 LE)
///     cbPrime1     (u32 LE) = 0
///     cbPrime2     (u32 LE) = 0
///   Followed by:
///     PublicExponent[cbPublicExp]
///     Modulus[cbModulus]
const RSA_PUBLIC_MAGIC: u32 = 0x3141_5352; // "RSA1"
const RSA_BLOB_HEADER_LEN: usize = 24;

/// SHA-256 algorithm identifier as NUL-terminated UTF-16LE.
/// "SHA256\0" in UTF-16LE.
const SHA256_WIDE: &[u16] = &[0x0053, 0x0048, 0x0041, 0x0032, 0x0035, 0x0036, 0x0000];

/// Verify an RSA-SHA256 signature over the exchange hash.
///
/// - `public_key_blob`: raw SSH public key blob (`string "ssh-rsa"` + `mpint e` + `mpint n`)
/// - `message`: the raw exchange hash bytes (will be SHA-256 hashed before verification)
/// - `signature`: raw PKCS#1 v1.5 signature bytes (the *value* portion from the SSH sig)
pub fn verify_rsa_sha256(
    public_key_blob: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    // --- Parse SSH RSA public key blob ---
    let mut cursor = public_key_blob;
    let key_type = read_ssh_string(&mut cursor)?;
    if key_type != b"ssh-rsa" {
        return Err(Error::CouldNotReadKey);
    }
    let e_bytes = read_ssh_mpint(&mut cursor)?;
    let n_bytes = read_ssh_mpint(&mut cursor)?;

    // --- Build BCRYPT_RSAPUBLIC_BLOB ---
    let bit_length = (n_bytes.len() * 8) as u32;
    let cb_pub_exp = e_bytes.len() as u32;
    let cb_modulus = n_bytes.len() as u32;

    let blob_len = RSA_BLOB_HEADER_LEN + e_bytes.len() + n_bytes.len();
    let mut blob = vec![0u8; blob_len];

    #[allow(clippy::indexing_slicing)]
    {
        blob[0..4].copy_from_slice(&RSA_PUBLIC_MAGIC.to_le_bytes());
        blob[4..8].copy_from_slice(&bit_length.to_le_bytes());
        blob[8..12].copy_from_slice(&cb_pub_exp.to_le_bytes());
        blob[12..16].copy_from_slice(&cb_modulus.to_le_bytes());
        // cbPrime1, cbPrime2 = 0 (already zeroed)
        let exp_start = RSA_BLOB_HEADER_LEN;
        let mod_start = exp_start + e_bytes.len();
        blob[exp_start..mod_start].copy_from_slice(e_bytes);
        blob[mod_start..mod_start + n_bytes.len()].copy_from_slice(n_bytes);
    }

    // --- Import key and verify ---
    unsafe {
        let mut alg = BCRYPT_ALG_HANDLE::default();
        let status = BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_RSA_ALGORITHM,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        );
        if status.is_err() {
            return Err(Error::InvalidSignature);
        }
        let alg_handle = CngAlgHandle(alg);

        let mut key_handle = BCRYPT_KEY_HANDLE::default();
        let status = BCryptImportKeyPair(
            alg_handle.0,
            None,
            BCRYPT_RSAPUBLIC_BLOB,
            &mut key_handle,
            &blob,
            0,
        );
        if status.is_err() {
            return Err(Error::InvalidSignature);
        }
        let key = CngKeyHandle(key_handle);

        // BCryptVerifySignature expects the hash of the message, not the raw message.
        // The ssh_key crate's Signer::sign() internally hashes with SHA-256 before signing,
        // so we must hash the exchange hash H to get SHA-256(H) for CNG.
        let msg_hash =
            crate::crypto_cng::sha256::sha256(message).map_err(|_| Error::InvalidSignature)?;

        let padding_info = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: PCWSTR(SHA256_WIDE.as_ptr()),
        };

        let status = BCryptVerifySignature(
            key.0,
            Some(&padding_info as *const BCRYPT_PKCS1_PADDING_INFO as *const c_void),
            &msg_hash,
            signature,
            BCRYPT_PAD_PKCS1,
        );

        if status.is_ok() {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// ECDSA P-256 verification
// ---------------------------------------------------------------------------

/// BCRYPT_ECDSA_PUBLIC_P256 magic ("ECS1" as LE u32 = 0x31534345).
const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345;
const P256_COORD_LEN: usize = 32;
const ECC_BLOB_HEADER_LEN: usize = 8;

/// Verify an ECDSA-P256 signature over the exchange hash.
///
/// - `public_key_blob`: raw SSH public key blob
///     (`string "ecdsa-sha2-nistp256"` + `string "nistp256"` + `string Q`)
/// - `message`: the raw exchange hash bytes (will be SHA-256 hashed before verification)
/// - `signature`: the SSH signature *value* bytes containing `mpint r` + `mpint s`
pub fn verify_ecdsa_p256(
    public_key_blob: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    // --- Parse SSH ECDSA public key blob ---
    let mut cursor = public_key_blob;
    let key_type = read_ssh_string(&mut cursor)?;
    if key_type != b"ecdsa-sha2-nistp256" {
        return Err(Error::CouldNotReadKey);
    }
    let curve_name = read_ssh_string(&mut cursor)?;
    if curve_name != b"nistp256" {
        return Err(Error::CouldNotReadKey);
    }
    let q_bytes = read_ssh_string(&mut cursor)?;

    // Q must be uncompressed SEC1 point: 0x04 || x(32) || y(32)
    if q_bytes.len() != 1 + 2 * P256_COORD_LEN {
        return Err(Error::CouldNotReadKey);
    }
    #[allow(clippy::indexing_slicing)]
    if q_bytes[0] != 0x04 {
        return Err(Error::CouldNotReadKey);
    }

    // --- Build BCRYPT_ECCPUBLIC_BLOB ---
    // Header: Magic(4 LE) + cbKey(4 LE) then x(32) y(32)
    let mut blob = vec![0u8; ECC_BLOB_HEADER_LEN + 2 * P256_COORD_LEN];
    #[allow(clippy::indexing_slicing)]
    {
        blob[0..4].copy_from_slice(&BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes());
        blob[4..8].copy_from_slice(&(P256_COORD_LEN as u32).to_le_bytes());
        blob[ECC_BLOB_HEADER_LEN..].copy_from_slice(&q_bytes[1..]); // skip 0x04
    }

    // --- Parse ECDSA signature (r, s mpints) ---
    let mut sig_cursor = signature;
    let r_bytes = read_ssh_mpint(&mut sig_cursor)?;
    let s_bytes = read_ssh_mpint(&mut sig_cursor)?;

    // CNG expects r||s each exactly P256_COORD_LEN bytes, big-endian zero-padded
    let r_padded = left_pad(r_bytes, P256_COORD_LEN)?;
    let s_padded = left_pad(s_bytes, P256_COORD_LEN)?;
    let mut cng_sig = Vec::with_capacity(2 * P256_COORD_LEN);
    cng_sig.extend_from_slice(&r_padded);
    cng_sig.extend_from_slice(&s_padded);

    // --- Import key and verify ---
    unsafe {
        let mut alg = BCRYPT_ALG_HANDLE::default();
        let status = BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_ECDSA_P256_ALGORITHM,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        );
        if status.is_err() {
            return Err(Error::InvalidSignature);
        }
        let alg_handle = CngAlgHandle(alg);

        let mut key_handle = BCRYPT_KEY_HANDLE::default();
        let status = BCryptImportKeyPair(
            alg_handle.0,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            &mut key_handle,
            &blob,
            0,
        );
        if status.is_err() {
            return Err(Error::InvalidSignature);
        }
        let key = CngKeyHandle(key_handle);

        // BCryptVerifySignature expects the hash of the message, not the raw message.
        // The ssh_key crate's Signer::sign() internally hashes with SHA-256 before signing,
        // so we must hash the exchange hash H to get SHA-256(H) for CNG.
        let msg_hash =
            crate::crypto_cng::sha256::sha256(message).map_err(|_| Error::InvalidSignature)?;

        // ECDSA: no padding parameter, pass None for pPaddingInfo and flags = 0
        let status = BCryptVerifySignature(key.0, None, &msg_hash, &cng_sig, BCRYPT_FLAGS(0));

        if status.is_ok() {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
