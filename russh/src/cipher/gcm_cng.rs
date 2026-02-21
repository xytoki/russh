// Windows CNG AES-GCM cipher backend.
//
// Implements AES-128-GCM and AES-256-GCM using Windows BCrypt (CNG) APIs.
// Gated behind `cfg(all(windows, feature = "crypto-cng"))`.

use std::ffi::c_void;
use std::mem;

use windows::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptDecrypt, BCryptDestroyKey, BCryptEncrypt,
    BCryptGenerateSymmetricKey, BCryptOpenAlgorithmProvider, BCryptSetProperty,
    BCRYPT_AES_ALGORITHM, BCRYPT_ALG_HANDLE, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_GCM, BCRYPT_FLAGS, BCRYPT_KEY_HANDLE,
    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
};

use super::super::Error;
use crate::keys::key::fill_random;
use crate::mac::MacAlgorithm;

const BCRYPT_AUTH_MODE_INFO_VERSION: u32 = 1;

pub struct CngGcmCipher {
    key_len: usize,
    nonce_len: usize,
    tag_len: usize,
}

pub static CNG_AES_128_GCM: CngGcmCipher = CngGcmCipher {
    key_len: 16,
    nonce_len: 12,
    tag_len: 16,
};

pub static CNG_AES_256_GCM: CngGcmCipher = CngGcmCipher {
    key_len: 32,
    nonce_len: 12,
    tag_len: 16,
};

struct CngAlgHandle(BCRYPT_ALG_HANDLE);

impl Drop for CngAlgHandle {
    fn drop(&mut self) {
        // Safety: valid handle opened via BCryptOpenAlgorithmProvider.
        unsafe {
            let _ = BCryptCloseAlgorithmProvider(self.0, 0);
        }
    }
}

struct CngKeyHandle(BCRYPT_KEY_HANDLE);

impl Drop for CngKeyHandle {
    fn drop(&mut self) {
        // Safety: valid handle created via BCryptGenerateSymmetricKey.
        unsafe {
            let _ = BCryptDestroyKey(self.0);
        }
    }
}

// Safety: CNG symmetric key handles are thread-safe per Microsoft documentation.
// The windows crate marks them !Send because they wrap raw pointers.
unsafe impl Send for CngKeyHandle {}

fn open_gcm_key(raw_key: &[u8]) -> CngKeyHandle {
    unsafe {
        let mut alg = BCRYPT_ALG_HANDLE::default();
        let status = BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_AES_ALGORITHM,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        );
        #[allow(clippy::panic)]
        if status.is_err() {
            panic!("BCryptOpenAlgorithmProvider failed: {status:?}");
        }
        let alg_handle = CngAlgHandle(alg);

        // BCRYPT_CHAIN_MODE_GCM is a PCWSTR; BCryptSetProperty needs its raw
        // wide-string bytes including the NUL terminator.
        let gcm_mode = BCRYPT_CHAIN_MODE_GCM;
        let gcm_mode_bytes: &[u8] = std::slice::from_raw_parts(
            gcm_mode.as_ptr() as *const u8,
            (wcslen(gcm_mode.as_ptr()) + 1) * 2,
        );
        let status =
            BCryptSetProperty(alg_handle.0.into(), BCRYPT_CHAINING_MODE, gcm_mode_bytes, 0);
        #[allow(clippy::panic)]
        if status.is_err() {
            panic!("BCryptSetProperty(ChainingMode) failed: {status:?}");
        }

        let mut key_handle = BCRYPT_KEY_HANDLE::default();
        // pbKeyObject=None, cbKeyObject=0: BCrypt allocates the key object internally.
        // This is supported since Windows 8 / Server 2012.  We target Win10+.
        let status = BCryptGenerateSymmetricKey(alg_handle.0, &mut key_handle, None, raw_key, 0);
        #[allow(clippy::panic)]
        if status.is_err() {
            panic!("BCryptGenerateSymmetricKey failed: {status:?}");
        }

        CngKeyHandle(key_handle)
    }
}

unsafe fn wcslen(ptr: *const u16) -> usize {
    let mut len = 0;
    #[allow(clippy::indexing_slicing)]
    // Safety: caller guarantees ptr is a valid null-terminated wide string.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    len
}

fn make_auth_info(
    nonce: &mut [u8],
    aad: &mut [u8],
    tag: &mut [u8],
) -> BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cbSize: mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        dwInfoVersion: BCRYPT_AUTH_MODE_INFO_VERSION,
        pbNonce: nonce.as_mut_ptr(),
        cbNonce: nonce.len() as u32,
        pbAuthData: aad.as_mut_ptr(),
        cbAuthData: aad.len() as u32,
        pbTag: tag.as_mut_ptr(),
        cbTag: tag.len() as u32,
        pbMacContext: std::ptr::null_mut(),
        cbMacContext: 0,
        cbAAD: 0,
        cbData: 0,
        dwFlags: 0,
    }
}

impl super::Cipher for CngGcmCipher {
    fn key_len(&self) -> usize {
        self.key_len
    }

    fn nonce_len(&self) -> usize {
        self.nonce_len
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        _mac_key: &[u8],
        _mac: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        let handle = open_gcm_key(k);
        Box::new(CngOpeningKey {
            handle,
            nonce: CngNonce::new(n),
            tag_len: self.tag_len,
        })
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        _mac_key: &[u8],
        _mac: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        let handle = open_gcm_key(k);
        Box::new(CngSealingKey {
            handle,
            nonce: CngNonce::new(n),
            tag_len: self.tag_len,
        })
    }
}

struct CngNonce {
    value: [u8; 12],
}

impl CngNonce {
    fn new(initial: &[u8]) -> Self {
        let mut value = [0u8; 12];
        let len = initial.len().min(12);
        #[allow(clippy::indexing_slicing)]
        value[..len].copy_from_slice(&initial[..len]);
        CngNonce { value }
    }

    fn advance(&mut self) -> [u8; 12] {
        let previous = self.value;
        let mut carry: u16 = 1;
        #[allow(clippy::indexing_slicing)]
        for i in (0..12).rev() {
            let n = self.value[i] as u16 + carry;
            self.value[i] = n as u8;
            carry = n >> 8;
        }
        previous
    }
}

pub struct CngOpeningKey {
    handle: CngKeyHandle,
    nonce: CngNonce,
    tag_len: usize,
}

impl super::OpeningKey for CngOpeningKey {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
        encrypted_packet_length.try_into().unwrap()
    }

    fn tag_len(&self) -> usize {
        self.tag_len
    }

    fn open<'a>(
        &mut self,
        _sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let nonce_bytes = self.nonce.advance();

        // Buffer layout:
        //   [0..4]            packet length (unencrypted AAD)
        //   [4..len-tag_len]  ciphertext
        //   [len-tag_len..]   authentication tag
        let total_len = ciphertext_and_tag.len();
        let tag_len = self.tag_len;

        if total_len < super::PACKET_LENGTH_LEN + tag_len {
            return Err(Error::DecryptionError);
        }

        let mut aad = [0u8; super::PACKET_LENGTH_LEN];
        #[allow(clippy::indexing_slicing)]
        aad.copy_from_slice(&ciphertext_and_tag[..super::PACKET_LENGTH_LEN]);

        let tag_start = total_len - tag_len;
        let mut tag = vec![0u8; tag_len];
        #[allow(clippy::indexing_slicing)]
        tag.copy_from_slice(&ciphertext_and_tag[tag_start..]);

        let ciphertext_start = super::PACKET_LENGTH_LEN;
        let ciphertext_len = tag_start - ciphertext_start;

        let mut ciphertext_buf = vec![0u8; ciphertext_len];
        #[allow(clippy::indexing_slicing)]
        ciphertext_buf.copy_from_slice(&ciphertext_and_tag[ciphertext_start..tag_start]);

        let mut nonce_buf = nonce_bytes;
        let auth_info = make_auth_info(&mut nonce_buf, &mut aad, &mut tag);

        let mut cb_result: u32 = 0;

        // Safety: all pointers/lengths valid; auth_info borrows stack-local
        // arrays that outlive the FFI call.
        let status = unsafe {
            BCryptDecrypt(
                self.handle.0,
                Some(&ciphertext_buf),
                Some(&auth_info as *const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO as *const c_void),
                None,
                #[allow(clippy::indexing_slicing)]
                Some(&mut ciphertext_and_tag[ciphertext_start..tag_start]),
                &mut cb_result,
                BCRYPT_FLAGS(0),
            )
        };

        if status.is_err() {
            return Err(Error::DecryptionError);
        }

        #[allow(clippy::indexing_slicing)]
        Ok(&ciphertext_and_tag[ciphertext_start..tag_start])
    }
}

pub struct CngSealingKey {
    handle: CngKeyHandle,
    nonce: CngNonce,
    tag_len: usize,
}

impl super::SealingKey for CngSealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN
        } else {
            block_size - ((super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        fill_random(padding_out);
    }

    fn tag_len(&self) -> usize {
        self.tag_len
    }

    fn seal(
        &mut self,
        _sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        let nonce_bytes = self.nonce.advance();

        // Buffer layout:
        //   [0..4]  packet length (unencrypted AAD)
        //   [4..]   plaintext to encrypt in-place
        let mut aad = [0u8; super::PACKET_LENGTH_LEN];
        #[allow(clippy::indexing_slicing)]
        aad.copy_from_slice(&plaintext_in_ciphertext_out[..super::PACKET_LENGTH_LEN]);

        let plaintext_start = super::PACKET_LENGTH_LEN;
        let plaintext_len = plaintext_in_ciphertext_out.len() - plaintext_start;

        let mut plaintext_buf = vec![0u8; plaintext_len];
        #[allow(clippy::indexing_slicing)]
        plaintext_buf.copy_from_slice(&plaintext_in_ciphertext_out[plaintext_start..]);

        let mut nonce_buf = nonce_bytes;
        let mut tag_buf = vec![0u8; self.tag_len];
        let auth_info = make_auth_info(&mut nonce_buf, &mut aad, &mut tag_buf);

        let mut cb_result: u32 = 0;

        // Safety: all pointers/lengths valid; auth_info borrows stack-local arrays.
        let status = unsafe {
            BCryptEncrypt(
                self.handle.0,
                Some(&plaintext_buf),
                Some(&auth_info as *const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO as *const c_void),
                None,
                #[allow(clippy::indexing_slicing)]
                Some(&mut plaintext_in_ciphertext_out[plaintext_start..]),
                &mut cb_result,
                BCRYPT_FLAGS(0),
            )
        };

        #[allow(clippy::panic)]
        if status.is_err() {
            panic!("BCryptEncrypt (AES-GCM seal) failed: {status:?}");
        }

        #[allow(clippy::indexing_slicing)]
        tag_out.copy_from_slice(&tag_buf[..self.tag_len]);
    }
}
