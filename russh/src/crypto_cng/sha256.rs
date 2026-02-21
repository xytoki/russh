// Windows CNG SHA-256 implementation.
//
// Uses BCrypt hashing APIs:
//   BCryptOpenAlgorithmProvider(BCRYPT_SHA256_ALGORITHM)
//   BCryptGetProperty(BCRYPT_OBJECT_LENGTH) — allocate hash object buffer
//   BCryptGetProperty(BCRYPT_HASH_LENGTH) — query output length (== 32)
//   BCryptCreateHash / BCryptHashData / BCryptFinishHash
//
// RAII wrappers close the algorithm provider and destroy the hash handle on drop.

use windows::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptGetProperty, BCryptHashData, BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE,
    BCRYPT_HASH_HANDLE, BCRYPT_HASH_LENGTH, BCRYPT_OBJECT_LENGTH,
    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_SHA256_ALGORITHM,
};
use zeroize::Zeroize;

use crate::Error;

/// RAII wrapper for BCRYPT_ALG_HANDLE.
struct AlgHandle(BCRYPT_ALG_HANDLE);

impl Drop for AlgHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = BCryptCloseAlgorithmProvider(self.0, 0);
        }
    }
}

/// RAII wrapper for BCRYPT_HASH_HANDLE.
struct HashHandle(BCRYPT_HASH_HANDLE);

impl Drop for HashHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = BCryptDestroyHash(self.0);
        }
    }
}

/// Read a DWORD property from the algorithm provider.
fn get_property_u32(alg: &AlgHandle, property: &windows::core::PCWSTR) -> Result<u32, Error> {
    unsafe {
        let mut value: u32 = 0;
        let mut cb_result: u32 = 0;
        let status = BCryptGetProperty(
            alg.0.into(),
            *property,
            Some(std::slice::from_raw_parts_mut(
                &mut value as *mut u32 as *mut u8,
                std::mem::size_of::<u32>(),
            )),
            &mut cb_result,
            0,
        );
        if status.is_err() {
            return Err(Error::KexInit);
        }
        Ok(value)
    }
}

/// Compute SHA-256 of `data` using Windows CNG (BCrypt).
///
/// # Errors
///
/// Returns `Error::KexInit` if any BCrypt call fails.
pub fn sha256(data: &[u8]) -> Result<[u8; 32], Error> {
    unsafe {
        // 1. Open algorithm provider for SHA-256.
        let mut alg = BCRYPT_ALG_HANDLE::default();
        let status = BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_SHA256_ALGORITHM,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        );
        if status.is_err() {
            return Err(Error::KexInit);
        }
        let alg = AlgHandle(alg);

        // 2. Query BCRYPT_OBJECT_LENGTH — size of the hash object buffer.
        let obj_len = get_property_u32(&alg, &BCRYPT_OBJECT_LENGTH)? as usize;

        // 3. Query BCRYPT_HASH_LENGTH — expected output size (should be 32).
        let hash_len = get_property_u32(&alg, &BCRYPT_HASH_LENGTH)? as usize;
        if hash_len != 32 {
            return Err(Error::KexInit);
        }

        // 4. Allocate hash object buffer.
        let mut hash_obj = vec![0u8; obj_len];

        // 5. Create hash handle.
        let mut hash_handle = BCRYPT_HASH_HANDLE::default();
        let status = BCryptCreateHash(alg.0, &mut hash_handle, Some(&mut hash_obj), None, 0);
        if status.is_err() {
            return Err(Error::KexInit);
        }
        let hash_handle = HashHandle(hash_handle);

        // 6. Feed data.
        let status = BCryptHashData(hash_handle.0, data, 0);
        if status.is_err() {
            return Err(Error::KexInit);
        }

        // 7. Finalize and retrieve the 32-byte digest.
        let mut output = [0u8; 32];
        let status = BCryptFinishHash(hash_handle.0, &mut output, 0);
        if status.is_err() {
            hash_obj.zeroize();
            return Err(Error::KexInit);
        }

        // Clear internal hash state before dropping.
        hash_obj.zeroize();

        Ok(output)
    }
}
