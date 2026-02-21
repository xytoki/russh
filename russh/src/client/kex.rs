use core::fmt;
use std::cell::RefCell;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use bytes::Bytes;
#[cfg(not(feature = "algo-minimal"))]
use log::warn;
use log::{debug, error};
#[cfg(not(all(windows, feature = "crypto-cng")))]
use signature::Verifier;
use ssh_encoding::{Decode, Encode};
#[cfg(not(feature = "algo-minimal"))]
use ssh_key::Mpint;
use ssh_key::PublicKey;
#[cfg(not(all(windows, feature = "crypto-cng")))]
use ssh_key::Signature;

use super::IncomingSshPacket;
use crate::client::{Config, NewKeys};
#[cfg(all(windows, feature = "crypto-cng"))]
use crate::helpers::EncodedExt;
#[cfg(not(feature = "algo-minimal"))]
use crate::kex::dh::groups::DhGroup;
use crate::kex::{KexAlgorithm, KexAlgorithmImplementor, KexCause, KexProgress, KEXES};
use crate::keys::key::parse_public_key;
#[cfg(all(windows, feature = "crypto-cng"))]
use crate::keys::wire::{parse_key_algo, parse_signature};
use crate::negotiation::{Names, Select};
use crate::session::Exchange;
use crate::sshbuffer::PacketWriter;
use crate::{msg, negotiation, strict_kex_violation, CryptoVec, Error, SshId};

thread_local! {
    static HASH_BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ClientKexState {
    Created,
    #[cfg(not(feature = "algo-minimal"))]
    WaitingForGexReply {
        names: Names,
        kex: KexAlgorithm,
    },
    WaitingForDhReply {
        // both KexInit and DH init sent
        names: Names,
        kex: KexAlgorithm,
    },
    WaitingForNewKeys {
        server_host_key: PublicKey,
        newkeys: NewKeys,
    },
}

pub(crate) struct ClientKex {
    exchange: Exchange,
    cause: KexCause,
    state: ClientKexState,
    config: Arc<Config>,
}

impl Debug for ClientKex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("ClientKex");
        s.field("cause", &self.cause);
        match self.state {
            ClientKexState::Created => {
                s.field("state", &"created");
            }
            #[cfg(not(feature = "algo-minimal"))]
            ClientKexState::WaitingForGexReply { .. } => {
                s.field("state", &"waiting for GEX response");
            }
            ClientKexState::WaitingForDhReply { .. } => {
                s.field("state", &"waiting for DH response");
            }
            ClientKexState::WaitingForNewKeys { .. } => {
                s.field("state", &"waiting for NEWKEYS");
            }
        }
        s.finish()
    }
}

impl ClientKex {
    pub fn new(
        config: Arc<Config>,
        client_sshid: &SshId,
        server_sshid: &[u8],
        cause: KexCause,
    ) -> Self {
        let exchange = Exchange::new(client_sshid.as_kex_hash_bytes(), server_sshid);
        Self {
            config,
            exchange,
            cause,
            state: ClientKexState::Created,
        }
    }

    pub fn kexinit(&mut self, output: &mut PacketWriter) -> Result<(), Error> {
        self.exchange.client_kex_init =
            negotiation::write_kex(&self.config.preferred, output, None)?;

        Ok(())
    }

    pub fn step(
        mut self,
        input: Option<&mut IncomingSshPacket>,
        output: &mut PacketWriter,
    ) -> Result<KexProgress<Self>, Error> {
        match self.state {
            ClientKexState::Created => {
                // At this point we expect to read the KEXINIT from the other side

                let Some(input) = input else {
                    return Err(Error::KexInit);
                };
                if input.buffer.first() != Some(&msg::KEXINIT) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit);
                }

                let names = {
                    // read algorithms from packet.
                    self.exchange.server_kex_init.extend(&input.buffer);
                    negotiation::Client::read_kex(
                        &input.buffer,
                        &self.config.preferred,
                        None,
                        &self.cause,
                    )?
                };
                debug!("negotiated algorithms: {names:?}");

                // seqno has already been incremented after read()
                if names.strict_kex() && !self.cause.is_rekey() && input.seqn.0 != 1 {
                    return Err(strict_kex_violation(
                        msg::KEXINIT,
                        input.seqn.0 as usize - 1,
                    ));
                }

                let mut kex = KEXES.get(&names.kex).ok_or(Error::UnknownAlgo)?.make();

                if kex.skip_exchange() {
                    // Non-standard no-kex exchange
                    let newkeys = compute_keys(
                        CryptoVec::new(),
                        kex,
                        names.clone(),
                        self.exchange.clone(),
                        self.cause.session_id(),
                    )?;

                    output.packet(|w| {
                        msg::NEWKEYS.encode(w)?;
                        Ok(())
                    })?;

                    return Ok(KexProgress::Done {
                        newkeys,
                        server_host_key: None,
                    });
                }

                if kex.is_dh_gex() {
                    #[cfg(not(feature = "algo-minimal"))]
                    {
                        output.packet(|w| {
                            kex.client_dh_gex_init(&self.config.gex, w)?;
                            Ok(())
                        })?;

                        self.state = ClientKexState::WaitingForGexReply { names, kex };
                    }
                    #[cfg(feature = "algo-minimal")]
                    {
                        return Err(Error::KexInit);
                    }
                } else {
                    output.packet(|w| {
                        kex.client_dh(&mut self.exchange.client_ephemeral, w)?;
                        Ok(())
                    })?;

                    self.state = ClientKexState::WaitingForDhReply { names, kex };
                }

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            #[cfg(not(feature = "algo-minimal"))]
            ClientKexState::WaitingForGexReply { names, mut kex } => {
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                if input.buffer.first() != Some(&msg::KEX_DH_GEX_GROUP) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit);
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let mut r = &input.buffer[1..];

                let prime = Mpint::decode(&mut r)?;
                let generator = Mpint::decode(&mut r)?;
                debug!("received gex group: prime={prime}, generator={generator}");

                let group = DhGroup {
                    prime: prime.as_bytes().to_vec().into(),
                    generator: generator.as_bytes().to_vec().into(),
                };

                if group.bit_size() < self.config.gex.min_group_size
                    || group.bit_size() > self.config.gex.max_group_size
                {
                    warn!(
                        "DH prime size ({} bits) not within requested range",
                        group.bit_size()
                    );
                    return Err(Error::KexInit);
                }

                let exchange = &mut self.exchange;
                exchange.gex = Some((self.config.gex.clone(), group.clone()));
                kex.dh_gex_set_group(group)?;
                output.packet(|w| {
                    kex.client_dh(&mut exchange.client_ephemeral, w)?;
                    Ok(())
                })?;
                self.state = ClientKexState::WaitingForDhReply { names, kex };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ClientKexState::WaitingForDhReply { mut names, mut kex } => {
                // At this point, we've sent ECDH_INTI and
                // are waiting for the ECDH_REPLY from the server.

                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                if names.ignore_guessed {
                    // Ignore the next packet if (1) it follows and (2) it's not the correct guess.
                    debug!("ignoring guessed kex");
                    names.ignore_guessed = false;
                    self.state = ClientKexState::WaitingForDhReply { names, kex };
                    return Ok(KexProgress::NeedsReply {
                        kex: self,
                        reset_seqn: false,
                    });
                }

                if input.buffer.first()
                    != Some(match kex.is_dh_gex() {
                        true => &msg::KEX_DH_GEX_REPLY,
                        false => &msg::KEX_ECDH_REPLY,
                    })
                {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit);
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let r = &mut &input.buffer[1..];

                let server_host_key = Bytes::decode(r)?; // server public key.
                let server_host_key = parse_public_key(&server_host_key)?;
                debug!(
                    "received server host key: {:?}",
                    server_host_key.to_openssh()
                );

                let server_ephemeral = Bytes::decode(r)?;
                self.exchange.server_ephemeral.extend(&server_ephemeral);
                kex.compute_shared_secret(&self.exchange.server_ephemeral)?;

                let mut pubkey_vec = CryptoVec::new();
                server_host_key.to_bytes()?.encode(&mut pubkey_vec)?;

                let exchange = &self.exchange;
                let hash = HASH_BUFFER.with({
                    |buffer| {
                        let mut buffer = buffer.borrow_mut();
                        buffer.clear();
                        kex.compute_exchange_hash(&pubkey_vec, exchange, &mut buffer)
                    }
                })?;

                let signature = Bytes::decode(r)?;

                #[cfg(all(windows, feature = "crypto-cng"))]
                {
                    let key_blob = server_host_key
                        .key_data()
                        .encoded()
                        .map_err(|_| Error::WrongServerSig)?;
                    let key_algo = parse_key_algo(&key_blob)?;
                    let (sig_algo, sig_bytes) = parse_signature(&signature)?;
                    let hash_ref = hash.as_ref();
                    let verified = match key_algo {
                        "ssh-rsa" => {
                            // CNG only implements SHA-256 for RSA verification.
                            // Reject if signature uses a different hash (e.g. rsa-sha2-512).
                            if sig_algo != "ssh-rsa" && sig_algo != "rsa-sha2-256" {
                                debug!("CNG RSA verify only supports SHA-256, got {sig_algo}");
                                return Err(Error::WrongServerSig);
                            }
                            crate::keys::verify_cng::verify_rsa_sha256(
                                &key_blob, hash_ref, sig_bytes,
                            )
                        }
                        "ecdsa-sha2-nistp256" => crate::keys::verify_cng::verify_ecdsa_p256(
                            &key_blob, hash_ref, sig_bytes,
                        ),
                        _ => {
                            debug!("unsupported host key algorithm for CNG: {key_algo}");
                            Err(crate::keys::Error::InvalidSignature)
                        }
                    };
                    match verified {
                        Ok(true) => {}
                        Ok(false) => {
                            debug!("CNG signature verification returned false");
                            return Err(Error::WrongServerSig);
                        }
                        Err(e) => {
                            debug!("CNG signature verification error: {e:?}");
                            return Err(Error::WrongServerSig);
                        }
                    }
                }

                #[cfg(not(all(windows, feature = "crypto-cng")))]
                {
                    let signature = Signature::decode(&mut &signature[..])?;
                    if let Err(e) = Verifier::verify(&server_host_key, hash.as_ref(), &signature) {
                        debug!("wrong server sig: {e:?}");
                        return Err(Error::WrongServerSig);
                    }
                }

                let newkeys = compute_keys(
                    hash,
                    kex,
                    names.clone(),
                    self.exchange.clone(),
                    self.cause.session_id(),
                )?;

                output.packet(|w| {
                    msg::NEWKEYS.encode(w)?;
                    Ok(())
                })?;

                let reset_seqn = newkeys.names.strict_kex() || self.cause.is_strict_rekey();

                self.state = ClientKexState::WaitingForNewKeys {
                    server_host_key,
                    newkeys,
                };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn,
                })
            }
            ClientKexState::WaitingForNewKeys {
                server_host_key,
                newkeys,
            } => {
                // At this point the exchange is complete
                // and we're waiting for a KEWKEYS packet
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                if input.buffer.first() != Some(&msg::NEWKEYS) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::Kex);
                }

                Ok(KexProgress::Done {
                    newkeys,
                    server_host_key: Some(server_host_key),
                })
            }
        }
    }
}

fn compute_keys(
    hash: CryptoVec,
    kex: KexAlgorithm,
    names: Names,
    exchange: Exchange,
    session_id: Option<&CryptoVec>,
) -> Result<NewKeys, Error> {
    let session_id = if let Some(session_id) = session_id {
        session_id
    } else {
        &hash
    };
    // Now computing keys.
    let c = kex.compute_keys(
        session_id,
        &hash,
        names.cipher,
        names.server_mac,
        names.client_mac,
        false,
    )?;
    Ok(NewKeys {
        exchange,
        names,
        kex,
        key: 0,
        cipher: c,
        session_id: session_id.clone(),
    })
}
