//-----------------------------------------------------------------------------
// Copyright (c) 2026, Oracle and/or its affiliates.
//
// This software is dual-licensed to you under the Universal Permissive License
// (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl and Apache License
// 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose
// either license.
//
// If you elect to accept the software under the Apache License, Version 2.0,
// the following applies:
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// nne.rs
//
// Native Network Encryption and Data Integrity: once negotiated
// (messages/ano.rs), the payload of each data packet carries a keyed checksum
// and is encrypted. AES is implemented for encryption and SHA-2 for integrity,
// in the current version of the algorithms and in the older one of servers
// without it (such as Oracle Database 18c); servers that disallow weak clients
// accept only the current version.
//-----------------------------------------------------------------------------

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use sha2::Digest;

use crate::error::Error;

/// Whether connections use Native Network Encryption and Data Integrity,
/// Oracle's alternative to TLS for encrypting and checksumming the network
/// traffic, set with
/// [Config::set_native_network_encryption()](crate::Config::set_native_network_encryption()).
///
/// The levels are those of the `SQLNET.ENCRYPTION_CLIENT` and
/// `SQLNET.CRYPTO_CHECKSUM_CLIENT` settings of Oracle's client libraries,
/// applied to both. Whether a connection is encrypted depends on the
/// server's levels (`SQLNET.ENCRYPTION_SERVER` and
/// `SQLNET.CRYPTO_CHECKSUM_SERVER`) as well:
///
/// | Client \ Server | Rejected | Accepted | Requested | Required |
/// |-----------------|----------|----------|-----------|----------|
/// | Rejected        | Off      | Off      | Off       | Refused  |
/// | Accepted        | Off      | Off      | On        | On       |
/// | Requested       | Off      | On       | On        | On       |
/// | Required        | Refused  | On       | On        | On       |
///
/// Connections that use TLS (`tcps`) are encrypted already and never use
/// Native Network Encryption. Encryption uses AES (256, 192 or 128 bits) and
/// integrity SHA-2 (512, 384 or 256 bits); the server chooses.
///
/// Accepted, the default of Oracle's client libraries, connects to any
/// database that allows AES and SHA-2, and costs a round trip more when the
/// connection is established than Rejected, the default here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NativeNetworkEncryption {
    /// Not used; databases that require it refuse the connection.
    #[default]
    Rejected,
    /// Used when the database requests or requires it.
    Accepted,
    /// Used unless the database rejects it.
    Requested,
    /// Used, or the connection fails.
    Required,
}

// encryption algorithms, by the ids used in the negotiation
pub(crate) const ENCRYPTION_NONE: u8 = 0;
pub(crate) const ENCRYPTION_AES128: u8 = 15;
pub(crate) const ENCRYPTION_AES192: u8 = 16;
pub(crate) const ENCRYPTION_AES256: u8 = 17;

// data integrity algorithms, by the ids used in the negotiation
pub(crate) const INTEGRITY_NONE: u8 = 0;
pub(crate) const INTEGRITY_SHA512: u8 = 4;
pub(crate) const INTEGRITY_SHA256: u8 = 5;
pub(crate) const INTEGRITY_SHA384: u8 = 6;

const BLOCK_SIZE: usize = 16;

// the bytes of the session key that key the integrity keystreams, in the
// current and the older version of the algorithms
const INTEGRITY_KEY_SIZE: usize = 15;
const OLD_INTEGRITY_KEY_SIZE: usize = 5;

// the IV of the encryption in the older version
const OLD_ENCRYPTION_IV: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

// the last byte of the keystream key for each direction
const INTEGRITY_SEND_KEY_BYTE: u8 = 90;
const INTEGRITY_RECEIVE_KEY_BYTE: u8 = 180;

// the byte ending each packet, after the payload: whether the keys have the
// authentication key folded in
const KEYS_UNFOLDED: u8 = 0;
const KEYS_FOLDED: u8 = 1;

/// AES with a key of any of its sizes.
enum Aes {
    Aes128(aes::Aes128),
    Aes192(aes::Aes192),
    Aes256(aes::Aes256),
}

impl Aes {
    /// Creates the cipher for the key; its length selects the key size.
    fn new(key: &[u8]) -> Self {
        match key.len() {
            16 => Self::Aes128(aes::Aes128::new_from_slice(key).unwrap()),
            24 => Self::Aes192(aes::Aes192::new_from_slice(key).unwrap()),
            _ => Self::Aes256(aes::Aes256::new_from_slice(key).unwrap()),
        }
    }

    fn decrypt_block(&self, block: &mut [u8]) {
        let block = block.try_into().unwrap();
        match self {
            Self::Aes128(c) => c.decrypt_block(block),
            Self::Aes192(c) => c.decrypt_block(block),
            Self::Aes256(c) => c.decrypt_block(block),
        }
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        let block = block.try_into().unwrap();
        match self {
            Self::Aes128(c) => c.encrypt_block(block),
            Self::Aes192(c) => c.encrypt_block(block),
            Self::Aes256(c) => c.encrypt_block(block),
        }
    }
}

/// AES in CBC mode, whose chaining value carries over from one call to the
/// next.
struct CbcEncryptor {
    aes: Aes,
    chain: [u8; BLOCK_SIZE],
}

impl CbcEncryptor {
    fn new(key: &[u8], iv: &[u8]) -> Self {
        Self {
            aes: Aes::new(key),
            chain: iv[..BLOCK_SIZE].try_into().unwrap(),
        }
    }

    /// Encrypts the data in place; its length is a multiple of the block
    /// size.
    fn encrypt(&mut self, data: &mut [u8]) {
        for block in data.chunks_exact_mut(BLOCK_SIZE) {
            for (b, c) in block.iter_mut().zip(self.chain) {
                *b ^= c;
            }
            self.aes.encrypt_block(block);
            self.chain.copy_from_slice(block);
        }
    }
}

/// The encryption of packet payloads: AES in CBC mode, each payload from the
/// same IV, padded with zeros to a whole block and followed by a byte giving
/// the padding's length plus one.
struct PacketCipher {
    aes: Aes,
    iv: [u8; BLOCK_SIZE],
}

impl PacketCipher {
    fn decrypt(&self, data: &mut Vec<u8>) -> Result<(), Error> {
        let pad_len = match data.pop() {
            Some(b) if (1..=BLOCK_SIZE as u8).contains(&b) => b as usize - 1,
            _ => return Err(Error::network_security("invalid padding")),
        };
        if !data.len().is_multiple_of(BLOCK_SIZE) || data.len() < pad_len {
            return Err(Error::network_security("invalid encrypted length"));
        }
        let mut chain = self.iv;
        for block in data.chunks_exact_mut(BLOCK_SIZE) {
            let encrypted: [u8; BLOCK_SIZE] = (&*block).try_into().unwrap();
            self.aes.decrypt_block(block);
            for (b, c) in block.iter_mut().zip(chain) {
                *b ^= c;
            }
            chain = encrypted;
        }
        data.truncate(data.len() - pad_len);
        Ok(())
    }

    fn encrypt(&self, data: &mut Vec<u8>) {
        let pad_len = data.len().next_multiple_of(BLOCK_SIZE) - data.len();
        data.resize(data.len() + pad_len, 0);
        let mut chain = self.iv;
        for block in data.chunks_exact_mut(BLOCK_SIZE) {
            for (b, c) in block.iter_mut().zip(chain) {
                *b ^= c;
            }
            self.aes.encrypt_block(block);
            chain.copy_from_slice(block);
        }
        data.push(pad_len as u8 + 1);
    }
}

/// The SHA-2 variants used for data integrity.
#[derive(Clone, Copy)]
enum Sha {
    Sha256,
    Sha384,
    Sha512,
}

impl Sha {
    fn digest(self, data: &[u8], key_block: &[u8]) -> Vec<u8> {
        fn digest<D: Digest>(data: &[u8], key_block: &[u8]) -> Vec<u8> {
            let mut hasher = D::new();
            hasher.update(data);
            hasher.update(key_block);
            hasher.finalize().to_vec()
        }
        match self {
            Self::Sha256 => digest::<sha2::Sha256>(data, key_block),
            Self::Sha384 => digest::<sha2::Sha384>(data, key_block),
            Self::Sha512 => digest::<sha2::Sha512>(data, key_block),
        }
    }

    fn size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// Data integrity: each payload is followed by the digest of the payload and
/// the next block of a keystream, one keystream per direction. The
/// keystreams' keys are derived from a key generator, which derives new ones
/// whenever the connection is reset.
struct Integrity {
    sha: Sha,
    key_size: usize,
    key_generator: CbcEncryptor,
    generated: [u8; 2 * BLOCK_SIZE],
    send_keystream: CbcEncryptor,
    send_block: Vec<u8>,
    receive_keystream: CbcEncryptor,
    receive_block: Vec<u8>,
}

impl Integrity {
    /// Creates the integrity from the given number of bytes of the session
    /// key, and the IV.
    fn new(sha: Sha, session_key: &[u8], key_size: usize, iv: &[u8]) -> Self {
        let mut key = [0u8; BLOCK_SIZE];
        key[..key_size].copy_from_slice(&session_key[..key_size]);
        key[key_size] = 0xFF;
        let key_generator = CbcEncryptor::new(&key, iv);
        let mut integrity = Self {
            sha,
            key_size,
            key_generator,
            generated: [0; 2 * BLOCK_SIZE],
            send_keystream: CbcEncryptor::new(&key, iv),
            send_block: vec![0; sha.size()],
            receive_keystream: CbcEncryptor::new(&key, iv),
            receive_block: vec![0; sha.size()],
        };
        integrity.generate_keys();
        integrity
    }

    /// Derives the keys of the generator and the keystreams from the next
    /// output of the generator.
    fn generate_keys(&mut self) {
        self.key_generator.encrypt(&mut self.generated);
        let (key, iv) = self.generated.split_at(BLOCK_SIZE);
        let mut key: [u8; BLOCK_SIZE] = key.try_into().unwrap();
        self.key_generator = CbcEncryptor::new(&key, iv);
        key[self.key_size] = INTEGRITY_SEND_KEY_BYTE;
        self.send_keystream = CbcEncryptor::new(&key, iv);
        key[self.key_size] = INTEGRITY_RECEIVE_KEY_BYTE;
        self.receive_keystream = CbcEncryptor::new(&key, iv);
    }

    /// Appends the checksum of the data to it.
    fn append_checksum(&mut self, data: &mut Vec<u8>) {
        self.send_keystream.encrypt(&mut self.send_block);
        let checksum = self.sha.digest(data, &self.send_block);
        data.extend(checksum);
    }

    /// Removes the checksum the data ends with, and verifies it.
    fn verify_checksum(&mut self, data: &mut Vec<u8>) -> Result<(), Error> {
        let size = self.sha.size();
        if data.len() < size {
            return Err(Error::network_security("packet without checksum"));
        }
        let received = data.split_off(data.len() - size);
        self.receive_keystream.encrypt(&mut self.receive_block);
        if self.sha.digest(data, &self.receive_block) != received {
            return Err(Error::network_security(
                "data integrity check failed",
            ));
        }
        Ok(())
    }
}

/// What the negotiation with the server agreed on.
pub(crate) struct Negotiated {
    pub(crate) encryption_algorithm: u8,
    /// Whether the encryption is the current version of the algorithms.
    pub(crate) encryption_current: bool,
    pub(crate) integrity_algorithm: u8,
    /// Whether the integrity is the current version of the algorithms.
    pub(crate) integrity_current: bool,
    /// The key the key exchange agreed on.
    pub(crate) session_key: Vec<u8>,
    /// The IV the server sent with the key exchange, used by the older
    /// version of the algorithms.
    pub(crate) server_iv: Vec<u8>,
}

/// The encryption and data integrity of a connection, transforming the
/// payload of each data packet.
pub(crate) struct NetworkSecurity {
    negotiated: Negotiated,
    /// The IV of the current version, from the session key.
    iv: [u8; 2 * BLOCK_SIZE],
    cipher: Option<PacketCipher>,
    integrity: Option<Integrity>,
    keys_folded: bool,
    reset_pending: bool,
}

impl NetworkSecurity {
    /// Starts encryption and integrity with the algorithms the server chose
    /// and the key agreed with it.
    pub(crate) fn new(negotiated: Negotiated) -> Result<Self, Error> {
        if negotiated.session_key.len() < 4 * BLOCK_SIZE {
            return Err(Error::network_security("session key too short"));
        }
        if !negotiated.integrity_current
            && negotiated.integrity_algorithm != INTEGRITY_NONE
            && negotiated.server_iv.len() < BLOCK_SIZE
        {
            return Err(Error::network_security("IV too short"));
        }
        let iv = negotiated.session_key[2 * BLOCK_SIZE..4 * BLOCK_SIZE]
            .try_into()
            .unwrap();
        let mut security = Self {
            negotiated,
            iv,
            cipher: None,
            integrity: None,
            keys_folded: false,
            reset_pending: false,
        };
        security.start()?;
        Ok(security)
    }

    /// (Re)starts the algorithms from the session key and IV.
    fn start(&mut self) -> Result<(), Error> {
        let negotiated = &self.negotiated;
        let key_len = match negotiated.encryption_algorithm {
            ENCRYPTION_NONE => None,
            ENCRYPTION_AES128 => Some(16),
            ENCRYPTION_AES192 => Some(24),
            ENCRYPTION_AES256 => Some(32),
            other => {
                return Err(Error::network_security(format!(
                    "unsupported encryption algorithm {other}"
                )));
            }
        };
        let iv = if negotiated.encryption_current {
            self.iv[..BLOCK_SIZE].try_into().unwrap()
        } else {
            OLD_ENCRYPTION_IV
        };
        self.cipher = key_len.map(|len| PacketCipher {
            aes: Aes::new(&negotiated.session_key[..len]),
            iv,
        });
        let sha = match negotiated.integrity_algorithm {
            INTEGRITY_NONE => None,
            INTEGRITY_SHA256 => Some(Sha::Sha256),
            INTEGRITY_SHA384 => Some(Sha::Sha384),
            INTEGRITY_SHA512 => Some(Sha::Sha512),
            other => {
                return Err(Error::network_security(format!(
                    "unsupported data integrity algorithm {other}"
                )));
            }
        };
        self.integrity = sha.map(|sha| {
            if negotiated.integrity_current {
                let key = &negotiated.session_key;
                Integrity::new(sha, key, INTEGRITY_KEY_SIZE, &self.iv)
            } else {
                let key = &negotiated.session_key;
                let iv = &negotiated.server_iv;
                Integrity::new(sha, key, OLD_INTEGRITY_KEY_SIZE, iv)
            }
        });
        Ok(())
    }

    /// Folds the key the authentication agreed on into the session key and
    /// IV, which the server does once the authentication has succeeded.
    pub(crate) fn fold_in(&mut self, key: &[u8]) -> Result<(), Error> {
        for (b, k) in self.negotiated.session_key.iter_mut().zip(key) {
            *b ^= k;
        }
        for (b, k) in self.iv.iter_mut().zip(key) {
            *b ^= k;
        }
        self.start()?;
        self.keys_folded = true;
        Ok(())
    }

    /// Returns the largest payload whose transformation still fits in the
    /// given number of bytes.
    pub(crate) fn max_payload_size(&self, available: usize) -> usize {
        let checksum_size =
            self.integrity.as_ref().map_or(0, |i| i.sha.size());
        let mut size = available - 1;
        if self.cipher.is_some() {
            size = (size - 1) / BLOCK_SIZE * BLOCK_SIZE;
        }
        size - checksum_size
    }

    /// Notes that the connection was reset (break and reset markers): the
    /// checksum keys change before the next data packet either way.
    pub(crate) fn reset(&mut self) {
        self.reset_pending = true;
    }

    fn apply_pending_reset(&mut self) {
        if self.reset_pending {
            self.reset_pending = false;
            if let Some(integrity) = self.integrity.as_mut() {
                integrity.generate_keys();
            }
        }
    }

    /// Transforms the payload of a data packet received. A payload of a byte
    /// at most is left as is.
    pub(crate) fn unwrap(&mut self, data: &mut Vec<u8>) -> Result<(), Error> {
        if data.len() <= 1 {
            return Ok(());
        }
        self.apply_pending_reset();
        data.pop();
        if let Some(cipher) = &self.cipher {
            cipher.decrypt(data)?;
        }
        if let Some(integrity) = self.integrity.as_mut() {
            integrity.verify_checksum(data)?;
        }
        Ok(())
    }

    /// Transforms the payload of a data packet to send.
    pub(crate) fn wrap(&mut self, data: &mut Vec<u8>) {
        self.apply_pending_reset();
        if let Some(integrity) = self.integrity.as_mut() {
            integrity.append_checksum(data);
        }
        if let Some(cipher) = &self.cipher {
            cipher.encrypt(data);
        }
        data.push(if self.keys_folded {
            KEYS_FOLDED
        } else {
            KEYS_UNFOLDED
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCRYPTION_ALGORITHMS: [u8; 4] = [
        ENCRYPTION_NONE,
        ENCRYPTION_AES128,
        ENCRYPTION_AES192,
        ENCRYPTION_AES256,
    ];
    const INTEGRITY_ALGORITHMS: [u8; 4] = [
        INTEGRITY_NONE,
        INTEGRITY_SHA256,
        INTEGRITY_SHA384,
        INTEGRITY_SHA512,
    ];

    fn session_key() -> Vec<u8> {
        (0..256).map(|i| (i * 7 + 3) as u8).collect()
    }

    /// Makes this the server's end of the connection: what it sends, the
    /// client receives, so its keystreams are the client's the other way
    /// round.
    fn mirror(server: &mut NetworkSecurity) {
        if let Some(i) = server.integrity.as_mut() {
            std::mem::swap(&mut i.send_keystream, &mut i.receive_keystream);
        }
    }

    /// The client's end of a connection, with the current or the older
    /// version of the algorithms.
    fn client(
        encryption: u8,
        integrity: u8,
        current: bool,
    ) -> NetworkSecurity {
        NetworkSecurity::new(Negotiated {
            encryption_algorithm: encryption,
            encryption_current: current,
            integrity_algorithm: integrity,
            integrity_current: current,
            session_key: session_key(),
            server_iv: (0..16).collect(),
        })
        .unwrap()
    }

    fn server(
        encryption: u8,
        integrity: u8,
        current: bool,
    ) -> NetworkSecurity {
        let mut server = client(encryption, integrity, current);
        mirror(&mut server);
        server
    }

    #[test]
    fn packet_cipher_round_trip() {
        let cipher = PacketCipher {
            aes: Aes::new(&[1; 32]),
            iv: [2; BLOCK_SIZE],
        };
        for len in 0..=3 * BLOCK_SIZE {
            let data: Vec<u8> = (0..len as u8).collect();
            let mut encrypted = data.clone();
            cipher.encrypt(&mut encrypted);
            assert_eq!(encrypted.len() % BLOCK_SIZE, 1);
            if len > 0 {
                assert_ne!(encrypted[..len], data[..]);
            }
            cipher.decrypt(&mut encrypted).unwrap();
            assert_eq!(encrypted, data);
        }
    }

    #[test]
    fn packets_round_trip() {
        for encryption in ENCRYPTION_ALGORITHMS {
            for integrity in INTEGRITY_ALGORITHMS {
                for current in [true, false] {
                    let mut client = client(encryption, integrity, current);
                    let mut server = server(encryption, integrity, current);
                    for round in 0..5 {
                        if round == 2 {
                            client.reset();
                            server.reset();
                            server.apply_pending_reset();
                            mirror(&mut server);
                        }
                        let data: Vec<u8> = (0..100 + round).collect();
                        let mut packet = data.clone();
                        server.wrap(&mut packet);
                        client.unwrap(&mut packet).unwrap();
                        assert_eq!(packet, data);
                    }
                }
            }
        }
    }

    #[test]
    fn folded_keys() {
        let mut client = client(ENCRYPTION_AES256, INTEGRITY_SHA256, true);
        let mut server = server(ENCRYPTION_AES256, INTEGRITY_SHA256, true);
        let mut unfolded = vec![1, 2, 3];
        server.wrap(&mut unfolded);
        assert_eq!(unfolded.last(), Some(&KEYS_UNFOLDED));
        client.fold_in(&[9; 32]).unwrap();
        server.fold_in(&[9; 32]).unwrap();
        mirror(&mut server);
        let mut packet = vec![1, 2, 3];
        server.wrap(&mut packet);
        assert_eq!(packet.last(), Some(&KEYS_FOLDED));
        assert_ne!(packet[..packet.len() - 1], unfolded[..unfolded.len() - 1]);
        client.unwrap(&mut packet).unwrap();
        assert_eq!(packet, [1, 2, 3]);
    }

    #[test]
    fn tampered_packet() {
        let mut client = client(ENCRYPTION_NONE, INTEGRITY_SHA384, true);
        let mut server = server(ENCRYPTION_NONE, INTEGRITY_SHA384, true);
        let mut packet = vec![1, 2, 3];
        server.wrap(&mut packet);
        packet[1] ^= 1;
        assert!(client.unwrap(&mut packet).is_err());
    }

    #[test]
    fn max_payload_size() {
        for encryption in ENCRYPTION_ALGORITHMS {
            for integrity in INTEGRITY_ALGORITHMS {
                let mut security = client(encryption, integrity, true);
                for available in 200..300 {
                    let size = security.max_payload_size(available);
                    let mut packet = vec![0; size];
                    security.wrap(&mut packet);
                    assert!(packet.len() <= available);
                    let mut packet = vec![0; size + 1];
                    security.wrap(&mut packet);
                    assert!(packet.len() > available);
                }
            }
        }
    }
}
