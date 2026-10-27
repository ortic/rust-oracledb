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
// ano.rs
//
// Defines the messages of the advanced negotiation, which follows the accept
// packet when the server wants Native Network Encryption or Data Integrity:
// the client offers the algorithms it supports, the server chooses and sends
// its half of a Diffie-Hellman key exchange, and the client sends its half.
//-----------------------------------------------------------------------------

use std::mem;

use num_bigint::BigUint;
use rand::RngExt;

use crate::client::Client;
use crate::error::Error;
use crate::messages::Message;
use crate::nne;
use crate::nne::NativeNetworkEncryption;
use crate::nne::Negotiated;
use crate::response::Response;
use crate::write_buffer::WriteBuffer;

const MAGIC: u32 = 0xDEADBEEF;

// the version announced: 23 and later get the current version of the
// algorithms (servers without it respond with the older version); servers that
// disallow weak clients refuse older versions with ORA-12269
const VERSION: u32 = 0x17000000;

// services
const SERVICE_AUTHENTICATION: u16 = 1;
const SERVICE_ENCRYPTION: u16 = 2;
const SERVICE_DATA_INTEGRITY: u16 = 3;
const SERVICE_SUPERVISOR: u16 = 4;

// types of the items making up the data of a service
const ITEM_BYTES: u16 = 1;
const ITEM_UB1: u16 = 2;
const ITEM_UB2: u16 = 3;
const ITEM_VERSION: u16 = 5;
const ITEM_STATUS: u16 = 6;

// supervisor service
const SUPERVISOR_CID: [u8; 8] = [0, 0, 16, 28, 102, 236, 40, 234];
const SUPERVISOR_ARRAY_TYPE: u16 = 3;
const SUPERVISOR_STATUS_OK: u16 = 31;

// authentication service
const AUTH_MAGIC: u16 = 0xE0E1;
const AUTH_STATUS_REQUEST: u16 = 0xFCFF;
const AUTH_STATUS_NOT_ACTIVE: u16 = 0xFBFF;

// the algorithms supported, most preferred first
const ENCRYPTION_ALGORITHMS: [u8; 3] = [
    nne::ENCRYPTION_AES256,
    nne::ENCRYPTION_AES192,
    nne::ENCRYPTION_AES128,
];
const INTEGRITY_ALGORITHMS: [u8; 3] = [
    nne::INTEGRITY_SHA512,
    nne::INTEGRITY_SHA384,
    nne::INTEGRITY_SHA256,
];

// not using the service, the same id for both services
const ALGORITHM_NONE: u8 = 0;

// the number of items of a data integrity response with a key exchange
const INTEGRITY_ITEMS_WITH_KEY_EXCHANGE: u16 = 8;

/// Writes the header of an item of service data.
fn write_item_header(buf: &mut WriteBuffer, len: usize, item_type: u16) {
    buf.write_u16be(len as u16);
    buf.write_u16be(item_type);
}

fn write_bytes_item(buf: &mut WriteBuffer, value: &[u8]) {
    write_item_header(buf, value.len(), ITEM_BYTES);
    buf.write_bytes(value);
}

fn write_service_header(buf: &mut WriteBuffer, service: u16, num_items: u16) {
    buf.write_u16be(service);
    buf.write_u16be(num_items);
    buf.write_u32be(0); // error
}

fn write_version_item(buf: &mut WriteBuffer) {
    write_item_header(buf, 4, ITEM_VERSION);
    buf.write_u32be(VERSION);
}

/// Writes the header of a negotiation packet.
fn write_header(buf: &mut WriteBuffer, len: usize, num_services: u16) {
    buf.write_u32be(MAGIC);
    buf.write_u16be(len as u16);
    buf.write_u32be(VERSION);
    buf.write_u16be(num_services);
    buf.write_u8(0); // error flags
}

/// Reads the header of an item of service data, which must be of the given
/// type, and returns the length of its value.
fn read_item_header(
    resp: &mut Response,
    item_type: u16,
) -> Result<usize, Error> {
    let len = resp.read_u16be()? as usize;
    let received_type = resp.read_u16be()?;
    if received_type != item_type {
        return Err(Error::network_security(format!(
            "expected an item of type {item_type}, got {received_type}"
        )));
    }
    Ok(len)
}

fn read_bytes_item(resp: &mut Response) -> Result<Vec<u8>, Error> {
    let len = read_item_header(resp, ITEM_BYTES)?;
    Ok(resp.read_bytes(len)?.to_vec())
}

fn read_status_item(resp: &mut Response) -> Result<u16, Error> {
    read_item_header(resp, ITEM_STATUS)?;
    resp.read_u16be()
}

fn read_ub1_item(resp: &mut Response) -> Result<u8, Error> {
    read_item_header(resp, ITEM_UB1)?;
    resp.read_u8()
}

fn read_ub2_item(resp: &mut Response) -> Result<u16, Error> {
    read_item_header(resp, ITEM_UB2)?;
    resp.read_u16be()
}

fn read_version_item(resp: &mut Response) -> Result<u32, Error> {
    read_item_header(resp, ITEM_VERSION)?;
    resp.read_u32be()
}

/// Returns an error for an error number the server sent instead of a
/// negotiation response.
fn negotiation_refused(error_num: u32) -> Error {
    Error::network_security(format!(
        "the server refused the negotiation (ORA-{error_num:05})"
    ))
}

/// Returns the algorithms to offer for a service: the level is conveyed by
/// whether not using the service is offered too, before the algorithms
/// (accepted) or after them (requested).
fn offered_algorithms(
    algorithms: &[u8],
    level: NativeNetworkEncryption,
) -> Vec<u8> {
    match level {
        NativeNetworkEncryption::Rejected => vec![ALGORITHM_NONE],
        NativeNetworkEncryption::Accepted => {
            [&[ALGORITHM_NONE], algorithms].concat()
        }
        NativeNetworkEncryption::Requested => {
            [algorithms, &[ALGORITHM_NONE]].concat()
        }
        NativeNetworkEncryption::Required => algorithms.to_vec(),
    }
}

/// Whether a service version gets the current algorithms.
fn is_current_version(version: u32) -> bool {
    version >> 24 >= 23 || (version & 0xFF000) >> 12 == 1
}

/// The first message of the negotiation and its response.
pub(crate) struct AnoMessage {
    encryption_offered: Vec<u8>,
    integrity_offered: Vec<u8>,
    pub(crate) encryption_algorithm: u8,
    pub(crate) encryption_version: u32,
    pub(crate) integrity_algorithm: u8,
    pub(crate) integrity_version: u32,
    /// The client's half of the key exchange, sent with AnoKeyMessage.
    pub(crate) public_key: Option<Vec<u8>>,
    /// The key the exchange agreed on.
    pub(crate) session_key: Option<Vec<u8>>,
    /// The IV the server sent with the key exchange.
    pub(crate) server_iv: Vec<u8>,
}

impl AnoMessage {
    pub(crate) fn new(level: NativeNetworkEncryption) -> Self {
        Self {
            encryption_offered: offered_algorithms(
                &ENCRYPTION_ALGORITHMS,
                level,
            ),
            integrity_offered: offered_algorithms(
                &INTEGRITY_ALGORITHMS,
                level,
            ),
            encryption_algorithm: nne::ENCRYPTION_NONE,
            encryption_version: 0,
            integrity_algorithm: nne::INTEGRITY_NONE,
            integrity_version: 0,
            public_key: None,
            session_key: None,
            server_iv: Vec::new(),
        }
    }

    /// Returns what the negotiation agreed on, if the server chose to use
    /// encryption or integrity.
    pub(crate) fn negotiated(&mut self) -> Result<Option<Negotiated>, Error> {
        if self.encryption_algorithm == nne::ENCRYPTION_NONE
            && self.integrity_algorithm == nne::INTEGRITY_NONE
        {
            return Ok(None);
        }
        let session_key = self
            .session_key
            .take()
            .ok_or_else(|| Error::network_security("no key exchange"))?;
        Ok(Some(Negotiated {
            encryption_algorithm: self.encryption_algorithm,
            encryption_current: is_current_version(self.encryption_version),
            integrity_algorithm: self.integrity_algorithm,
            integrity_current: is_current_version(self.integrity_version),
            session_key,
            server_iv: mem::take(&mut self.server_iv),
        }))
    }

    fn read_authentication(
        &mut self,
        resp: &mut Response,
        _num_items: u16,
    ) -> Result<(), Error> {
        read_version_item(resp)?;
        let status = read_status_item(resp)?;
        if status != AUTH_STATUS_NOT_ACTIVE {
            return Err(Error::not_implemented(
                "network authentication services (Kerberos, NTS, RADIUS)"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn read_encryption(
        &mut self,
        resp: &mut Response,
        _num_items: u16,
    ) -> Result<(), Error> {
        self.encryption_version = read_version_item(resp)?;
        self.encryption_algorithm = read_ub1_item(resp)?;
        Ok(())
    }

    /// Reads the data integrity response, which carries the server's half of
    /// the key exchange, and computes the client's half and the key agreed.
    fn read_integrity(
        &mut self,
        resp: &mut Response,
        num_items: u16,
    ) -> Result<(), Error> {
        self.integrity_version = read_version_item(resp)?;
        self.integrity_algorithm = read_ub1_item(resp)?;
        if num_items != INTEGRITY_ITEMS_WITH_KEY_EXCHANGE {
            return Ok(());
        }
        let key_bits = read_ub2_item(resp)? as usize;
        let _prime_bits = read_ub2_item(resp)?;
        let generator = BigUint::from_bytes_be(&read_bytes_item(resp)?);
        let prime_bytes = read_bytes_item(resp)?;
        let server_key_bytes = read_bytes_item(resp)?;
        self.server_iv = read_bytes_item(resp)?;
        let key_len = key_bits.div_ceil(8);
        if key_len == 0
            || prime_bytes.len() != key_len
            || server_key_bytes.len() != key_len
        {
            return Err(Error::network_security(
                "key exchange parameters out of sync",
            ));
        }
        let prime = BigUint::from_bytes_be(&prime_bytes);
        let server_key = BigUint::from_bytes_be(&server_key_bytes);
        let one = BigUint::from(1u8);
        if server_key <= one || server_key >= &prime - &one {
            return Err(Error::network_security("invalid server public key"));
        }
        let mut private_key_bytes = vec![0u8; key_len];
        rand::rng().fill(&mut private_key_bytes[..]);
        let private_key = BigUint::from_bytes_be(&private_key_bytes);
        let to_bytes = |value: BigUint| {
            let bytes = value.to_bytes_be();
            let mut padded = vec![0u8; key_len - bytes.len()];
            padded.extend(bytes);
            padded
        };
        self.public_key =
            Some(to_bytes(generator.modpow(&private_key, &prime)));
        self.session_key =
            Some(to_bytes(server_key.modpow(&private_key, &prime)));
        Ok(())
    }

    fn read_supervisor(
        &mut self,
        resp: &mut Response,
        _num_items: u16,
    ) -> Result<(), Error> {
        read_version_item(resp)?;
        let status = read_status_item(resp)?;
        if status != SUPERVISOR_STATUS_OK {
            return Err(Error::network_security(format!(
                "unexpected supervisor status {status}"
            )));
        }
        read_bytes_item(resp)?; // the services the server knows
        Ok(())
    }
}

impl Message for AnoMessage {
    fn deserialize(
        &mut self,
        _client: &Client,
        resp: &mut Response,
    ) -> Result<(), Error> {
        if resp.read_u32be()? != MAGIC {
            return Err(Error::network_security("invalid negotiation header"));
        }
        resp.read_u16be()?; // length
        resp.read_u32be()?; // version
        let num_services = resp.read_u16be()?;
        let error_flags = resp.read_u8()?;
        if error_flags != 0 {
            return Err(negotiation_refused(error_flags as u32));
        }
        for _ in 0..num_services {
            let service = resp.read_u16be()?;
            let num_items = resp.read_u16be()?;
            let error_num = resp.read_u32be()?;
            if error_num != 0 {
                return Err(negotiation_refused(error_num));
            }
            match service {
                SERVICE_AUTHENTICATION => {
                    self.read_authentication(resp, num_items)?
                }
                SERVICE_ENCRYPTION => self.read_encryption(resp, num_items)?,
                SERVICE_DATA_INTEGRITY => {
                    self.read_integrity(resp, num_items)?
                }
                SERVICE_SUPERVISOR => self.read_supervisor(resp, num_items)?,
                _ => {
                    return Err(Error::network_security(format!(
                        "unknown service {service}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn serialize(&self, _client: &Client, buf: &mut WriteBuffer) {
        let services = [
            SERVICE_SUPERVISOR,
            SERVICE_AUTHENTICATION,
            SERVICE_ENCRYPTION,
            SERVICE_DATA_INTEGRITY,
        ];
        let supervisor_len = 8 + (4 + 8) + (4 + 10 + 2 * services.len());
        let authentication_len = 8 + (4 + 2) + (4 + 2);
        let encryption_len = 8 + (4 + self.encryption_offered.len()) + (4 + 1);
        let integrity_len = 8 + (4 + self.integrity_offered.len());
        let len = 13
            + 4 * 8
            + supervisor_len
            + authentication_len
            + encryption_len
            + integrity_len;
        write_header(buf, len, services.len() as u16);

        write_service_header(buf, SERVICE_SUPERVISOR, 3);
        write_version_item(buf);
        write_bytes_item(buf, &SUPERVISOR_CID);
        write_item_header(buf, 10 + 2 * services.len(), ITEM_BYTES);
        buf.write_u32be(MAGIC);
        buf.write_u16be(SUPERVISOR_ARRAY_TYPE);
        buf.write_u32be(services.len() as u32);
        for service in services {
            buf.write_u16be(service);
        }

        write_service_header(buf, SERVICE_AUTHENTICATION, 3);
        write_version_item(buf);
        write_item_header(buf, 2, ITEM_UB2);
        buf.write_u16be(AUTH_MAGIC);
        write_item_header(buf, 2, ITEM_STATUS);
        buf.write_u16be(AUTH_STATUS_REQUEST);

        write_service_header(buf, SERVICE_ENCRYPTION, 3);
        write_version_item(buf);
        write_bytes_item(buf, &self.encryption_offered);
        write_item_header(buf, 1, ITEM_UB1);
        buf.write_u8(1); // driver

        write_service_header(buf, SERVICE_DATA_INTEGRITY, 2);
        write_version_item(buf);
        write_bytes_item(buf, &self.integrity_offered);
    }
}

/// The last message of the negotiation: the client's half of the key
/// exchange. The server doesn't respond to it.
pub(crate) struct AnoKeyMessage<'a> {
    pub(crate) public_key: &'a [u8],
}

impl Message for AnoKeyMessage<'_> {
    fn serialize(&self, _client: &Client, buf: &mut WriteBuffer) {
        write_header(buf, 13 + 8 + 4 + self.public_key.len(), 1);
        write_service_header(buf, SERVICE_DATA_INTEGRITY, 1);
        write_bytes_item(buf, self.public_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offered_algorithms_by_level() {
        let algorithms = [17, 16, 15];
        let offered = |level| offered_algorithms(&algorithms, level);
        assert_eq!(offered(NativeNetworkEncryption::Rejected), [0]);
        assert_eq!(
            offered(NativeNetworkEncryption::Accepted),
            [0, 17, 16, 15]
        );
        assert_eq!(
            offered(NativeNetworkEncryption::Requested),
            [17, 16, 15, 0]
        );
        assert_eq!(offered(NativeNetworkEncryption::Required), [17, 16, 15]);
    }

    #[test]
    fn current_versions() {
        assert!(is_current_version(0x171A3000)); // 23.26.3
        assert!(is_current_version(0x15001000)); // 21.0.1
        assert!(!is_current_version(0x0B200200)); // 11.2.0.2
    }
}
