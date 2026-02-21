// Windows CNG ECDH P-256 KEX backend.
//
// Implements ECDH key agreement for `ecdh-sha2-nistp256` using
// BCrypt (CNG) APIs from the `windows` crate:
//
//  - BCryptOpenAlgorithmProvider(BCRYPT_ECDH_P256_ALGORITHM)
//  - BCryptGenerateKeyPair / BCryptFinalizeKeyPair
//  - BCryptExportKey(BCRYPT_ECCPUBLIC_BLOB)  → x||y → 0x04||x||y (SEC1)
//  - BCryptImportKeyPair(BCRYPT_ECCPUBLIC_BLOB)  ← SEC1 → x||y
//  - BCryptSecretAgreement / BCryptDeriveKey(BCRYPT_KDF_RAW_SECRET)
//

use byteorder::{BigEndian, ByteOrder, LittleEndian};

use ssh_encoding::{Encode, Writer};
use windows::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptDeriveKey, BCryptDestroyKey, BCryptDestroySecret,
    BCryptExportKey, BCryptFinalizeKeyPair, BCryptGenerateKeyPair, BCryptImportKeyPair,
    BCryptOpenAlgorithmProvider, BCryptSecretAgreement, BCRYPT_ALG_HANDLE, BCRYPT_ECCPUBLIC_BLOB,
    BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_KDF_RAW_SECRET, BCRYPT_KEY_HANDLE,
    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_SECRET_HANDLE,
};
use zeroize::Zeroize;

use super::{encode_mpint, KexAlgorithm, KexAlgorithmImplementor, KexType, SharedSecret};

use crate::mac;
use crate::session::Exchange;
use crate::{cipher, msg, CryptoVec, Error};

const P256_COORD_LEN: usize = 32;
const P256_SEC1_UNCOMPRESSED_LEN: usize = 1 + 2 * P256_COORD_LEN;
/// BCRYPT_ECCKEY_BLOB header: Magic(4) + cbKey(4).
const ECC_BLOB_HEADER_LEN: usize = 8;
/// BCRYPT_ECDH_PUBLIC_P256 magic ("ECK1" as LE u32 = 0x314B4345).
const BCRYPT_ECDH_PUBLIC_P256_MAGIC: u32 = 0x314B_4345;

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
// Safety: CNG key handles are thread-safe per Microsoft documentation.
unsafe impl Send for CngKeyHandle {}

struct CngSecretHandle(BCRYPT_SECRET_HANDLE);
impl Drop for CngSecretHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = BCryptDestroySecret(self.0);
        }
    }
}
// Safety: CNG secret handles are thread-safe per Microsoft documentation.
unsafe impl Send for CngSecretHandle {}

fn open_ecdh_p256_alg() -> Result<CngAlgHandle, Error> {
    unsafe {
        let mut alg = BCRYPT_ALG_HANDLE::default();
        let status = BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_ECDH_P256_ALGORITHM,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        );
        if status.is_err() {
            return Err(Error::KexInit);
        }
        Ok(CngAlgHandle(alg))
    }
}

fn generate_ecdh_p256_keypair(alg: &CngAlgHandle) -> Result<CngKeyHandle, Error> {
    unsafe {
        let mut key = BCRYPT_KEY_HANDLE::default();
        let status = BCryptGenerateKeyPair(alg.0, &mut key, (P256_COORD_LEN * 8) as u32, 0);
        if status.is_err() {
            return Err(Error::KexInit);
        }
        let status = BCryptFinalizeKeyPair(key, 0);
        if status.is_err() {
            let _ = BCryptDestroyKey(key);
            return Err(Error::KexInit);
        }
        Ok(CngKeyHandle(key))
    }
}

fn export_public_key_sec1(key: &CngKeyHandle) -> Result<Vec<u8>, Error> {
    unsafe {
        let mut blob_len: u32 = 0;
        let status = BCryptExportKey(key.0, None, BCRYPT_ECCPUBLIC_BLOB, None, &mut blob_len, 0);
        if status.is_err() {
            return Err(Error::KexInit);
        }

        let mut blob = vec![0u8; blob_len as usize];
        let mut written: u32 = 0;
        let status = BCryptExportKey(
            key.0,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            Some(&mut blob),
            &mut written,
            0,
        );
        if status.is_err() {
            return Err(Error::KexInit);
        }

        if (written as usize) < ECC_BLOB_HEADER_LEN {
            return Err(Error::KexInit);
        }

        #[allow(clippy::indexing_slicing)] // length checked
        let magic = LittleEndian::read_u32(&blob[0..4]);
        #[allow(clippy::indexing_slicing)] // length checked
        let cb_key = LittleEndian::read_u32(&blob[4..8]) as usize;

        if magic != BCRYPT_ECDH_PUBLIC_P256_MAGIC || cb_key != P256_COORD_LEN {
            return Err(Error::KexInit);
        }

        if (written as usize) < ECC_BLOB_HEADER_LEN + 2 * cb_key {
            return Err(Error::KexInit);
        }

        let mut sec1 = Vec::with_capacity(1 + 2 * cb_key);
        sec1.push(0x04);
        #[allow(clippy::indexing_slicing)] // length checked
        sec1.extend_from_slice(&blob[ECC_BLOB_HEADER_LEN..ECC_BLOB_HEADER_LEN + 2 * cb_key]);
        Ok(sec1)
    }
}

fn import_peer_public_key(alg: &CngAlgHandle, sec1: &[u8]) -> Result<CngKeyHandle, Error> {
    if sec1.len() != P256_SEC1_UNCOMPRESSED_LEN {
        return Err(Error::KexInit);
    }
    #[allow(clippy::indexing_slicing)]
    if sec1[0] != 0x04 {
        return Err(Error::KexInit);
    }

    let mut blob = vec![0u8; ECC_BLOB_HEADER_LEN + 2 * P256_COORD_LEN];
    #[allow(clippy::indexing_slicing)]
    {
        blob[0..4].copy_from_slice(&BCRYPT_ECDH_PUBLIC_P256_MAGIC.to_le_bytes());
        blob[4..8].copy_from_slice(&(P256_COORD_LEN as u32).to_le_bytes());
        blob[ECC_BLOB_HEADER_LEN..].copy_from_slice(&sec1[1..]);
    }

    unsafe {
        let mut key = BCRYPT_KEY_HANDLE::default();
        let status = BCryptImportKeyPair(alg.0, None, BCRYPT_ECCPUBLIC_BLOB, &mut key, &blob, 0);
        if status.is_err() {
            return Err(Error::KexInit);
        }
        Ok(CngKeyHandle(key))
    }
}

// TODO: confirm BCRYPT_KDF_RAW_SECRET byte order on Windows; may need .reverse() for mpint
fn compute_raw_secret(local_key: &CngKeyHandle, peer_key: &CngKeyHandle) -> Result<Vec<u8>, Error> {
    unsafe {
        let mut secret = BCRYPT_SECRET_HANDLE::default();
        let status = BCryptSecretAgreement(local_key.0, peer_key.0, &mut secret, 0);
        if status.is_err() {
            return Err(Error::KexInit);
        }
        let secret_handle = CngSecretHandle(secret);

        let mut derived_len: u32 = 0;
        let status = BCryptDeriveKey(
            secret_handle.0,
            BCRYPT_KDF_RAW_SECRET,
            None,
            None,
            &mut derived_len,
            0,
        );
        if status.is_err() {
            return Err(Error::KexInit);
        }

        let mut derived = vec![0u8; derived_len as usize];
        let mut written: u32 = 0;
        let status = BCryptDeriveKey(
            secret_handle.0,
            BCRYPT_KDF_RAW_SECRET,
            None,
            Some(&mut derived),
            &mut written,
            0,
        );
        if status.is_err() {
            return Err(Error::KexInit);
        }
        derived.truncate(written as usize);

        // BCRYPT_KDF_RAW_SECRET returns the shared secret in little-endian byte order.
        // SSH requires big-endian (network byte order) for the shared secret K.
        derived.reverse();
        Ok(derived)
    }
}

pub struct CngEcdhNistP256KexType;

impl KexType for CngEcdhNistP256KexType {
    fn make(&self) -> KexAlgorithm {
        CngEcdhNistP256Kex {
            local_key: None,
            shared_secret: None,
        }
        .into()
    }
}

pub struct CngEcdhNistP256Kex {
    local_key: Option<CngKeyHandle>,
    shared_secret: Option<Vec<u8>>,
}

impl Drop for CngEcdhNistP256Kex {
    fn drop(&mut self) {
        if let Some(ref mut secret) = self.shared_secret {
            secret.zeroize();
        }
    }
}

impl std::fmt::Debug for CngEcdhNistP256Kex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "CngEcdhNistP256Kex {{ local_key: [hidden], shared_secret: [hidden] }}",
        )
    }
}

impl KexAlgorithmImplementor for CngEcdhNistP256Kex {
    fn skip_exchange(&self) -> bool {
        false
    }

    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), Error> {
        if payload.first() != Some(&msg::KEX_ECDH_INIT) {
            return Err(Error::Inconsistent);
        }

        #[allow(clippy::indexing_slicing)] // length checked
        let client_pubkey_len = {
            if payload.len() < 5 {
                return Err(Error::Inconsistent);
            }
            BigEndian::read_u32(&payload[1..]) as usize
        };

        if payload.len() < 5 + client_pubkey_len {
            return Err(Error::Inconsistent);
        }

        #[allow(clippy::indexing_slicing)] // length checked
        let client_pubkey_bytes = &payload[5..5 + client_pubkey_len];

        let alg = open_ecdh_p256_alg()?;
        let server_key = generate_ecdh_p256_keypair(&alg)?;
        let server_sec1 = export_public_key_sec1(&server_key)?;
        let client_key = import_peer_public_key(&alg, client_pubkey_bytes)?;
        let raw_secret = compute_raw_secret(&server_key, &client_key)?;

        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend(&server_sec1);
        self.shared_secret = Some(raw_secret);
        Ok(())
    }

    fn client_dh(
        &mut self,
        client_ephemeral: &mut CryptoVec,
        writer: &mut impl Writer,
    ) -> Result<(), Error> {
        let alg = open_ecdh_p256_alg()?;
        let client_key = generate_ecdh_p256_keypair(&alg)?;
        let client_sec1 = export_public_key_sec1(&client_key)?;

        client_ephemeral.clear();
        client_ephemeral.extend(&client_sec1);

        msg::KEX_ECDH_INIT.encode(writer)?;
        client_sec1.as_slice().encode(writer)?;

        self.local_key = Some(client_key);
        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey: &[u8]) -> Result<(), Error> {
        let local_key = self.local_key.take().ok_or(Error::KexInit)?;

        let alg = open_ecdh_p256_alg()?;
        let peer_key = import_peer_public_key(&alg, remote_pubkey)?;
        let raw_secret = compute_raw_secret(&local_key, &peer_key)?;

        self.shared_secret = Some(raw_secret);
        Ok(())
    }

    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        self.shared_secret.as_deref()
    }

    fn compute_exchange_hash(
        &self,
        key: &CryptoVec,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<CryptoVec, Error> {
        buffer.clear();
        exchange.client_id.as_ref().encode(buffer)?;
        exchange.server_id.as_ref().encode(buffer)?;
        exchange.client_kex_init.as_ref().encode(buffer)?;
        exchange.server_kex_init.as_ref().encode(buffer)?;

        buffer.extend(key);
        exchange.client_ephemeral.as_ref().encode(buffer)?;
        exchange.server_ephemeral.as_ref().encode(buffer)?;

        if let Some(ref shared) = self.shared_secret {
            encode_mpint(shared, buffer)?;
        }

        let hash = crate::crypto_cng::sha256::sha256(buffer.as_ref())?;

        let mut res = CryptoVec::new();
        res.extend(&hash);
        Ok(res)
    }

    fn compute_keys(
        &self,
        session_id: &CryptoVec,
        exchange_hash: &CryptoVec,
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<cipher::CipherPair, Error> {
        let shared_secret = self
            .shared_secret
            .as_ref()
            .map(|x| SharedSecret::from_mpint(x))
            .transpose()?;

        super::compute_keys_sha256_cng(
            shared_secret.as_ref(),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}
