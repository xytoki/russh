// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//!
//! This module exports kex algorithm names for use with [Preferred].
#[cfg(not(feature = "algo-minimal"))]
mod curve25519;
#[cfg(not(feature = "algo-minimal"))]
pub mod dh;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
mod ecdh_nistp;
#[cfg(all(windows, feature = "crypto-cng"))]
mod ecdh_nistp_cng;
#[cfg(feature = "pqc-mlkem")]
mod hybrid_mlkem;
mod none;

// Stub module so DhGroup type exists even when the full dh module is gated out.
// This allows the KexAlgorithmImplementor trait to compile unconditionally.
#[cfg(feature = "algo-minimal")]
pub mod dh {
    pub mod groups {
        /// Stub for DhGroup when full DH is not compiled.
        #[derive(Debug, Clone)]
        pub struct DhGroup;
    }
}

use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::sync::LazyLock;

#[cfg(not(feature = "algo-minimal"))]
use curve25519::Curve25519KexType;
use delegate::delegate;
use dh::groups::DhGroup;
#[cfg(not(feature = "algo-minimal"))]
use dh::{
    DhGexSha1KexType, DhGexSha256KexType, DhGroup14Sha1KexType, DhGroup14Sha256KexType,
    DhGroup15Sha512KexType, DhGroup16Sha512KexType, DhGroup17Sha512KexType, DhGroup18Sha512KexType,
    DhGroup1Sha1KexType,
};
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
use digest::Digest;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
use ecdh_nistp::EcdhNistP256KexType;
#[cfg(all(
    not(feature = "algo-minimal"),
    any(feature = "ring", feature = "aws-lc-rs")
))]
use ecdh_nistp::{EcdhNistP384KexType, EcdhNistP521KexType};
use enum_dispatch::enum_dispatch;
#[cfg(feature = "pqc-mlkem")]
use hybrid_mlkem::MlKem768X25519KexType;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
use p256::NistP256;
#[cfg(all(
    not(feature = "algo-minimal"),
    any(feature = "ring", feature = "aws-lc-rs")
))]
use p384::NistP384;
#[cfg(all(
    not(feature = "algo-minimal"),
    any(feature = "ring", feature = "aws-lc-rs")
))]
use p521::NistP521;
#[cfg(not(feature = "algo-minimal"))]
use sha1::Sha1;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
use sha2::Sha256;
#[cfg(all(
    not(feature = "algo-minimal"),
    any(feature = "ring", feature = "aws-lc-rs")
))]
use sha2::{Sha384, Sha512};
use ssh_encoding::{Encode, Writer};
use ssh_key::PublicKey;

use crate::cipher::CIPHERS;
use crate::client::GexParams;
use crate::mac::{self, MACS};
use crate::session::{Exchange, NewKeys};
use crate::{cipher, CryptoVec, Error};

#[derive(Debug)]
pub(crate) enum SessionKexState<K> {
    Idle,
    InProgress(K),
    Taken, // some async activity still going on such as host key checks
}

impl<K> PartialEq for SessionKexState<K> {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

impl<K> SessionKexState<K> {
    pub fn active(&self) -> bool {
        match self {
            SessionKexState::Idle => false,
            SessionKexState::InProgress(_) => true,
            SessionKexState::Taken => true,
        }
    }

    pub fn take(&mut self) -> Self {
        // TODO maybe make this take a guarded closure
        std::mem::replace(
            self,
            match self {
                SessionKexState::Idle => SessionKexState::Idle,
                _ => SessionKexState::Taken,
            },
        )
    }
}

#[derive(Debug)]
pub(crate) enum KexCause {
    Initial,
    Rekey { strict: bool, session_id: CryptoVec },
}

impl KexCause {
    pub fn is_strict_rekey(&self) -> bool {
        matches!(self, Self::Rekey { strict: true, .. })
    }

    pub fn is_rekey(&self) -> bool {
        match self {
            Self::Initial => false,
            Self::Rekey { .. } => true,
        }
    }

    pub fn session_id(&self) -> Option<&CryptoVec> {
        match self {
            Self::Initial => None,
            Self::Rekey { session_id, .. } => Some(session_id),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum KexProgress<T> {
    NeedsReply {
        kex: T,
        reset_seqn: bool,
    },
    Done {
        server_host_key: Option<PublicKey>,
        newkeys: NewKeys,
    },
}

#[enum_dispatch(KexAlgorithmImplementor)]
pub(crate) enum KexAlgorithm {
    #[cfg(not(feature = "algo-minimal"))]
    DhGroupKexSha1(dh::DhGroupKex<Sha1>),
    #[cfg(not(feature = "algo-minimal"))]
    DhGroupKexSha256(dh::DhGroupKex<Sha256>),
    #[cfg(not(feature = "algo-minimal"))]
    DhGroupKexSha512(dh::DhGroupKex<Sha512>),
    #[cfg(not(feature = "algo-minimal"))]
    Curve25519Kex(curve25519::Curve25519Kex),
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    EcdhNistP256Kex(ecdh_nistp::EcdhNistPKex<NistP256, Sha256>),
    #[cfg(all(
        not(feature = "algo-minimal"),
        any(feature = "ring", feature = "aws-lc-rs")
    ))]
    EcdhNistP384Kex(ecdh_nistp::EcdhNistPKex<NistP384, Sha384>),
    #[cfg(all(
        not(feature = "algo-minimal"),
        any(feature = "ring", feature = "aws-lc-rs")
    ))]
    EcdhNistP521Kex(ecdh_nistp::EcdhNistPKex<NistP521, Sha512>),
    #[cfg(feature = "pqc-mlkem")]
    MlKem768X25519Kex(hybrid_mlkem::MlKem768X25519Kex),
    #[cfg(all(windows, feature = "crypto-cng"))]
    CngEcdhNistP256Kex(ecdh_nistp_cng::CngEcdhNistP256Kex),
    None(none::NoneKexAlgorithm),
}

pub(crate) trait KexType {
    fn make(&self) -> KexAlgorithm;
}

impl Debug for KexAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KexAlgorithm")
    }
}

#[enum_dispatch]
pub(crate) trait KexAlgorithmImplementor {
    fn skip_exchange(&self) -> bool;
    fn is_dh_gex(&self) -> bool {
        false
    }

    #[cfg_attr(feature = "algo-minimal", allow(dead_code))]
    #[allow(unused_variables)]
    fn client_dh_gex_init(
        &mut self,
        _gex: &GexParams,
        writer: &mut impl Writer,
    ) -> Result<(), Error> {
        Err(Error::KexInit)
    }

    #[cfg_attr(feature = "algo-minimal", allow(dead_code))]
    #[allow(unused_variables)]
    fn dh_gex_set_group(&mut self, group: DhGroup) -> Result<(), Error> {
        Err(Error::KexInit)
    }

    #[cfg_attr(
        any(target_arch = "wasm32", feature = "client-minimal"),
        allow(dead_code)
    )]
    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), Error>;

    fn client_dh(
        &mut self,
        client_ephemeral: &mut CryptoVec,
        writer: &mut impl Writer,
    ) -> Result<(), Error>;

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), Error>;

    /// Get the raw shared secret bytes.
    ///
    /// This is useful for protocols that need to derive additional keys from the
    /// SSH shared secret (e.g., for secondary encrypted channels).
    ///
    /// Returns `None` if the shared secret hasn't been computed yet.
    fn shared_secret_bytes(&self) -> Option<&[u8]>;

    fn compute_exchange_hash(
        &self,
        key: &CryptoVec,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<CryptoVec, Error>;

    fn compute_keys(
        &self,
        session_id: &CryptoVec,
        exchange_hash: &CryptoVec,
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, Error>;
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl Encode for Name {
    delegate! { to self.as_ref() {
        fn encoded_len(&self) -> Result<usize, ssh_encoding::Error>;
        fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> Result<(), ssh_encoding::Error>;
    }}
}

impl TryFrom<&str> for Name {
    type Error = ();
    fn try_from(s: &str) -> Result<Name, ()> {
        KEXES.keys().find(|x| x.0 == s).map(|x| **x).ok_or(())
    }
}

/// `curve25519-sha256`
pub const CURVE25519: Name = Name("curve25519-sha256");
/// `curve25519-sha256@libssh.org`
pub const CURVE25519_PRE_RFC_8731: Name = Name("curve25519-sha256@libssh.org");
/// `mlkem768x25519-sha256`
pub const MLKEM768X25519_SHA256: Name = Name("mlkem768x25519-sha256");
/// `diffie-hellman-group-exchange-sha1`.
pub const DH_GEX_SHA1: Name = Name("diffie-hellman-group-exchange-sha1");
/// `diffie-hellman-group-exchange-sha256`.
pub const DH_GEX_SHA256: Name = Name("diffie-hellman-group-exchange-sha256");
/// `diffie-hellman-group1-sha1`
pub const DH_G1_SHA1: Name = Name("diffie-hellman-group1-sha1");
/// `diffie-hellman-group14-sha1`
pub const DH_G14_SHA1: Name = Name("diffie-hellman-group14-sha1");
/// `diffie-hellman-group14-sha256`
pub const DH_G14_SHA256: Name = Name("diffie-hellman-group14-sha256");
/// `diffie-hellman-group15-sha512`
pub const DH_G15_SHA512: Name = Name("diffie-hellman-group15-sha512");
/// `diffie-hellman-group16-sha512`
pub const DH_G16_SHA512: Name = Name("diffie-hellman-group16-sha512");
/// `diffie-hellman-group17-sha512`
pub const DH_G17_SHA512: Name = Name("diffie-hellman-group17-sha512");
/// `diffie-hellman-group18-sha512`
pub const DH_G18_SHA512: Name = Name("diffie-hellman-group18-sha512");
/// `ecdh-sha2-nistp256`
pub const ECDH_SHA2_NISTP256: Name = Name("ecdh-sha2-nistp256");
/// `ecdh-sha2-nistp384`
pub const ECDH_SHA2_NISTP384: Name = Name("ecdh-sha2-nistp384");
/// `ecdh-sha2-nistp521`
pub const ECDH_SHA2_NISTP521: Name = Name("ecdh-sha2-nistp521");
/// `none`
pub const NONE: Name = Name("none");
/// `ext-info-c`
pub const EXTENSION_SUPPORT_AS_CLIENT: Name = Name("ext-info-c");
/// `ext-info-s`
pub const EXTENSION_SUPPORT_AS_SERVER: Name = Name("ext-info-s");
/// `kex-strict-c-v00@openssh.com`
pub const EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT: Name = Name("kex-strict-c-v00@openssh.com");
/// `kex-strict-s-v00@openssh.com`
pub const EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER: Name = Name("kex-strict-s-v00@openssh.com");

#[cfg(not(feature = "algo-minimal"))]
const _CURVE25519: Curve25519KexType = Curve25519KexType {};
#[cfg(not(feature = "algo-minimal"))]
const _DH_GEX_SHA1: DhGexSha1KexType = DhGexSha1KexType {};
#[cfg(not(feature = "algo-minimal"))]
const _DH_GEX_SHA256: DhGexSha256KexType = DhGexSha256KexType {};
#[cfg(not(feature = "algo-minimal"))]
const _DH_G1_SHA1: DhGroup1Sha1KexType = DhGroup1Sha1KexType {};
#[cfg(not(feature = "algo-minimal"))]
const _DH_G14_SHA1: DhGroup14Sha1KexType = DhGroup14Sha1KexType {};
#[cfg(not(feature = "algo-minimal"))]
const _DH_G14_SHA256: DhGroup14Sha256KexType = DhGroup14Sha256KexType {};
#[cfg(not(feature = "algo-minimal"))]
const _DH_G15_SHA512: DhGroup15Sha512KexType = DhGroup15Sha512KexType {};
#[cfg(not(feature = "algo-minimal"))]
const _DH_G16_SHA512: DhGroup16Sha512KexType = DhGroup16Sha512KexType {};
#[cfg(not(feature = "algo-minimal"))]
const _DH_G17_SHA512: DhGroup17Sha512KexType = DhGroup17Sha512KexType {};
#[cfg(not(feature = "algo-minimal"))]
const _DH_G18_SHA512: DhGroup18Sha512KexType = DhGroup18Sha512KexType {};
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
const _ECDH_SHA2_NISTP256: EcdhNistP256KexType = EcdhNistP256KexType {};
#[cfg(all(
    not(feature = "algo-minimal"),
    any(feature = "ring", feature = "aws-lc-rs")
))]
const _ECDH_SHA2_NISTP384: EcdhNistP384KexType = EcdhNistP384KexType {};
#[cfg(all(
    not(feature = "algo-minimal"),
    any(feature = "ring", feature = "aws-lc-rs")
))]
const _ECDH_SHA2_NISTP521: EcdhNistP521KexType = EcdhNistP521KexType {};
#[cfg(feature = "pqc-mlkem")]
const _MLKEM768X25519_SHA256: MlKem768X25519KexType = MlKem768X25519KexType {};
#[cfg(all(windows, feature = "crypto-cng"))]
const _CNG_ECDH_SHA2_NISTP256: ecdh_nistp_cng::CngEcdhNistP256KexType =
    ecdh_nistp_cng::CngEcdhNistP256KexType;
const _NONE: none::NoneKexType = none::NoneKexType {};

#[cfg(not(feature = "algo-minimal"))]
pub const ALL_KEX_ALGORITHMS: &[&Name] = &[
    #[cfg(feature = "pqc-mlkem")]
    &MLKEM768X25519_SHA256,
    &CURVE25519,
    &CURVE25519_PRE_RFC_8731,
    &DH_GEX_SHA1,
    &DH_GEX_SHA256,
    &DH_G1_SHA1,
    &DH_G14_SHA1,
    &DH_G14_SHA256,
    &DH_G15_SHA512,
    &DH_G16_SHA512,
    &DH_G17_SHA512,
    &DH_G18_SHA512,
    &ECDH_SHA2_NISTP256,
    &ECDH_SHA2_NISTP384,
    &ECDH_SHA2_NISTP521,
    &NONE,
];

#[cfg(feature = "algo-minimal")]
pub const ALL_KEX_ALGORITHMS: &[&Name] = &[&ECDH_SHA2_NISTP256];

pub(crate) static KEXES: LazyLock<HashMap<&'static Name, &(dyn KexType + Send + Sync)>> =
    LazyLock::new(|| {
        let mut h: HashMap<&'static Name, &(dyn KexType + Send + Sync)> = HashMap::new();
        #[cfg(all(not(feature = "algo-minimal"), feature = "pqc-mlkem"))]
        h.insert(&MLKEM768X25519_SHA256, &_MLKEM768X25519_SHA256);
        #[cfg(not(feature = "algo-minimal"))]
        {
            h.insert(&CURVE25519, &_CURVE25519);
            h.insert(&CURVE25519_PRE_RFC_8731, &_CURVE25519);
            h.insert(&DH_GEX_SHA1, &_DH_GEX_SHA1);
            h.insert(&DH_GEX_SHA256, &_DH_GEX_SHA256);
            h.insert(&DH_G18_SHA512, &_DH_G18_SHA512);
            h.insert(&DH_G17_SHA512, &_DH_G17_SHA512);
            h.insert(&DH_G16_SHA512, &_DH_G16_SHA512);
            h.insert(&DH_G15_SHA512, &_DH_G15_SHA512);
            h.insert(&DH_G14_SHA256, &_DH_G14_SHA256);
            h.insert(&DH_G14_SHA1, &_DH_G14_SHA1);
            h.insert(&DH_G1_SHA1, &_DH_G1_SHA1);
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            h.insert(&ECDH_SHA2_NISTP384, &_ECDH_SHA2_NISTP384);
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            h.insert(&ECDH_SHA2_NISTP521, &_ECDH_SHA2_NISTP521);
            h.insert(&NONE, &_NONE);
        }
        #[cfg(all(
            not(all(windows, feature = "crypto-cng")),
            any(feature = "ring", feature = "aws-lc-rs")
        ))]
        h.insert(&ECDH_SHA2_NISTP256, &_ECDH_SHA2_NISTP256);
        #[cfg(all(windows, feature = "crypto-cng"))]
        h.insert(&ECDH_SHA2_NISTP256, &_CNG_ECDH_SHA2_NISTP256);
        assert_eq!(ALL_KEX_ALGORITHMS.len(), h.len());
        h
    });

thread_local! {
    static KEY_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static NONCE_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static MAC_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

pub(crate) enum SharedSecret {
    Mpint(CryptoVec),
    #[cfg(feature = "pqc-mlkem")]
    String(CryptoVec),
}

impl SharedSecret {
    pub fn from_mpint(bytes: &[u8]) -> Result<Self, Error> {
        let mut encoded = CryptoVec::new();
        encode_mpint(bytes, &mut encoded)?;
        Ok(SharedSecret::Mpint(encoded))
    }

    #[cfg(feature = "pqc-mlkem")]
    pub fn from_string(bytes: &[u8]) -> Result<Self, Error> {
        let mut encoded = CryptoVec::new();
        bytes.encode(&mut encoded)?;
        Ok(SharedSecret::String(encoded))
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            SharedSecret::Mpint(v) => v.as_ref(),
            #[cfg(feature = "pqc-mlkem")]
            SharedSecret::String(v) => v.as_ref(),
        }
    }
}

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub(crate) fn compute_keys<D: Digest>(
    shared_secret: Option<&SharedSecret>,
    session_id: &CryptoVec,
    exchange_hash: &CryptoVec,
    cipher: cipher::Name,
    remote_to_local_mac: mac::Name,
    local_to_remote_mac: mac::Name,
    is_server: bool,
) -> Result<super::cipher::CipherPair, Error> {
    let cipher = CIPHERS.get(&cipher).ok_or(Error::UnknownAlgo)?;
    let remote_to_local_mac = MACS.get(&remote_to_local_mac).ok_or(Error::UnknownAlgo)?;
    let local_to_remote_mac = MACS.get(&local_to_remote_mac).ok_or(Error::UnknownAlgo)?;

    // https://tools.ietf.org/html/rfc4253#section-7.2
    BUFFER.with(|buffer| {
        KEY_BUF.with(|key| {
            NONCE_BUF.with(|nonce| {
                MAC_BUF.with(|mac| {
                    let compute_key = |c, key: &mut CryptoVec, len| -> Result<(), Error> {
                        let mut buffer = buffer.borrow_mut();
                        buffer.clear();
                        key.clear();

                        if let Some(shared) = shared_secret {
                            buffer.extend(shared.as_bytes());
                        }

                        buffer.extend(exchange_hash.as_ref());
                        buffer.push(c);
                        buffer.extend(session_id.as_ref());
                        let hash = {
                            let mut hasher = D::new();
                            hasher.update(&buffer[..]);
                            hasher.finalize()
                        };
                        key.extend(hash.as_ref());

                        while key.len() < len {
                            // extend.
                            buffer.clear();
                            if let Some(shared) = shared_secret {
                                buffer.extend(shared.as_bytes());
                            }
                            buffer.extend(exchange_hash.as_ref());
                            buffer.extend(key);
                            let hash = {
                                let mut hasher = D::new();
                                hasher.update(&buffer[..]);
                                hasher.finalize()
                            };
                            key.extend(hash.as_ref());
                        }

                        key.resize(len);
                        Ok(())
                    };

                    let (local_to_remote, remote_to_local) = if is_server {
                        (b'D', b'C')
                    } else {
                        (b'C', b'D')
                    };

                    let (local_to_remote_nonce, remote_to_local_nonce) = if is_server {
                        (b'B', b'A')
                    } else {
                        (b'A', b'B')
                    };

                    let (local_to_remote_mac_key, remote_to_local_mac_key) = if is_server {
                        (b'F', b'E')
                    } else {
                        (b'E', b'F')
                    };

                    let mut key = key.borrow_mut();
                    let mut nonce = nonce.borrow_mut();
                    let mut mac = mac.borrow_mut();

                    compute_key(local_to_remote, &mut key, cipher.key_len())?;
                    compute_key(local_to_remote_nonce, &mut nonce, cipher.nonce_len())?;
                    compute_key(
                        local_to_remote_mac_key,
                        &mut mac,
                        local_to_remote_mac.key_len(),
                    )?;

                    let local_to_remote =
                        cipher.make_sealing_key(&key, &nonce, &mac, *local_to_remote_mac);

                    compute_key(remote_to_local, &mut key, cipher.key_len())?;
                    compute_key(remote_to_local_nonce, &mut nonce, cipher.nonce_len())?;
                    compute_key(
                        remote_to_local_mac_key,
                        &mut mac,
                        remote_to_local_mac.key_len(),
                    )?;
                    let remote_to_local =
                        cipher.make_opening_key(&key, &nonce, &mac, *remote_to_local_mac);

                    Ok(super::cipher::CipherPair {
                        local_to_remote,
                        remote_to_local,
                    })
                })
            })
        })
    })
}

#[cfg(all(windows, feature = "crypto-cng"))]
pub(crate) fn compute_keys_sha256_cng(
    shared_secret: Option<&SharedSecret>,
    session_id: &CryptoVec,
    exchange_hash: &CryptoVec,
    cipher: cipher::Name,
    remote_to_local_mac: mac::Name,
    local_to_remote_mac: mac::Name,
    is_server: bool,
) -> Result<super::cipher::CipherPair, Error> {
    let cipher = CIPHERS.get(&cipher).ok_or(Error::UnknownAlgo)?;
    let remote_to_local_mac = MACS.get(&remote_to_local_mac).ok_or(Error::UnknownAlgo)?;
    let local_to_remote_mac = MACS.get(&local_to_remote_mac).ok_or(Error::UnknownAlgo)?;

    // https://tools.ietf.org/html/rfc4253#section-7.2
    BUFFER.with(|buffer| {
        KEY_BUF.with(|key| {
            NONCE_BUF.with(|nonce| {
                MAC_BUF.with(|mac| {
                    let compute_key = |c, key: &mut CryptoVec, len| -> Result<(), Error> {
                        let mut buffer = buffer.borrow_mut();
                        buffer.clear();
                        key.clear();

                        if let Some(shared) = shared_secret {
                            buffer.extend(shared.as_bytes());
                        }

                        buffer.extend(exchange_hash.as_ref());
                        buffer.push(c);
                        buffer.extend(session_id.as_ref());

                        let hash = crate::crypto_cng::sha256::sha256(&buffer[..])?;
                        key.extend(&hash);

                        while key.len() < len {
                            buffer.clear();
                            if let Some(shared) = shared_secret {
                                buffer.extend(shared.as_bytes());
                            }
                            buffer.extend(exchange_hash.as_ref());
                            buffer.extend(key);
                            let hash = crate::crypto_cng::sha256::sha256(&buffer[..])?;
                            key.extend(&hash);
                        }

                        key.resize(len);
                        Ok(())
                    };

                    let (local_to_remote, remote_to_local) = if is_server {
                        (b'D', b'C')
                    } else {
                        (b'C', b'D')
                    };

                    let (local_to_remote_nonce, remote_to_local_nonce) = if is_server {
                        (b'B', b'A')
                    } else {
                        (b'A', b'B')
                    };

                    let (local_to_remote_mac_key, remote_to_local_mac_key) = if is_server {
                        (b'F', b'E')
                    } else {
                        (b'E', b'F')
                    };

                    let mut key = key.borrow_mut();
                    let mut nonce = nonce.borrow_mut();
                    let mut mac = mac.borrow_mut();

                    compute_key(local_to_remote, &mut key, cipher.key_len())?;
                    compute_key(local_to_remote_nonce, &mut nonce, cipher.nonce_len())?;
                    compute_key(
                        local_to_remote_mac_key,
                        &mut mac,
                        local_to_remote_mac.key_len(),
                    )?;

                    let local_to_remote =
                        cipher.make_sealing_key(&key, &nonce, &mac, *local_to_remote_mac);

                    compute_key(remote_to_local, &mut key, cipher.key_len())?;
                    compute_key(remote_to_local_nonce, &mut nonce, cipher.nonce_len())?;
                    compute_key(
                        remote_to_local_mac_key,
                        &mut mac,
                        remote_to_local_mac.key_len(),
                    )?;

                    let remote_to_local =
                        cipher.make_opening_key(&key, &nonce, &mac, *remote_to_local_mac);

                    Ok(super::cipher::CipherPair {
                        local_to_remote,
                        remote_to_local,
                    })
                })
            })
        })
    })
}

// NOTE: using MpInt::from_bytes().encode() will randomly fail,
// I'm assuming it's due to specific byte values / padding but no time to investigate
#[allow(clippy::indexing_slicing)] // length is known
pub(crate) fn encode_mpint<W: Writer>(s: &[u8], w: &mut W) -> Result<(), Error> {
    // Skip initial 0s.
    let mut i = 0;
    while i < s.len() && s[i] == 0 {
        i += 1
    }
    // All zeros (or empty) → encode as mpint 0 (length = 0).
    if i == s.len() {
        0u32.encode(w)?;
        return Ok(());
    }
    // If the first non-zero is >= 128, write its length (u32, BE), followed by 0.
    if s[i] & 0x80 != 0 {
        ((s.len() - i + 1) as u32).encode(w)?;
        0u8.encode(w)?;
    } else {
        ((s.len() - i) as u32).encode(w)?;
    }
    w.write(&s[i..])?;
    Ok(())
}
