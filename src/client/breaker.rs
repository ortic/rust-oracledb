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
// breaker.rs
//
// Interrupts a round trip in progress from another thread
// (Connection::cancel()), while the calling thread holds the client.
//-----------------------------------------------------------------------------

use std::io::Write;
use std::net::TcpStream;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::constants;
use crate::error::Error;

#[derive(Default)]
pub(crate) struct BreakState {
    /// A second handle to the connection's socket, used to write the
    /// interrupt; None for TLS, where writes must go through the session.
    socket: Option<TcpStream>,
    /// Whether packet sizes take four bytes (negotiated at connect).
    full_packet_size: bool,
    /// A request was sent and its response hasn't been received yet.
    in_round_trip: bool,
    /// An interrupt was sent and the server's answer not received yet.
    break_sent: bool,
}

/// Shared between the client and its connection, outside the client lock.
/// The state's lock is also held for every write to the socket, so an
/// interrupt never interleaves with a packet the client is sending.
#[derive(Default)]
pub(crate) struct Breaker {
    state: Mutex<BreakState>,
}

pub(crate) type BreakerRef = Arc<Breaker>;

impl Breaker {
    /// Locks the state while the client writes to the socket.
    pub(crate) fn writing(&self) -> Result<MutexGuard<'_, BreakState>, Error> {
        Ok(self.state.lock()?)
    }

    /// Sets the socket to write interrupts to after connecting (or clears it
    /// when the connection closes).
    pub(crate) fn set_socket(
        &self,
        socket: Option<TcpStream>,
        full_packet_size: bool,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state.socket = socket;
            state.full_packet_size = full_packet_size;
        }
    }

    /// Called once a request has been sent completely.
    pub(crate) fn begin_round_trip(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.in_round_trip = true;
        }
    }

    /// Called when the round trip is over. Returns whether an interrupt was
    /// sent that came too late to stop it: the server keeps such an
    /// interrupt and applies it to the next call, so the client has to
    /// absorb it before that call.
    pub(crate) fn end_round_trip(&self) -> bool {
        match self.state.lock() {
            Ok(mut state) => {
                state.in_round_trip = false;
                std::mem::take(&mut state.break_sent)
            }
            Err(_) => false,
        }
    }

    /// Called after a reset: the server has answered any interrupt.
    pub(crate) fn break_answered(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.break_sent = false;
        }
    }

    /// Sends an interrupt if a round trip is in progress; does nothing
    /// otherwise, or if one was sent already.
    pub(crate) fn send_break(&self) -> Result<(), Error> {
        let mut state = self.state.lock()?;
        if !state.in_round_trip || state.break_sent {
            return Ok(());
        }
        let full_packet_size = state.full_packet_size;
        let Some(socket) = state.socket.as_mut() else {
            return Err(Error::not_implemented(
                "cancelling a call on a TLS connection".to_string(),
            ));
        };
        socket.write_all(&marker_packet(
            constants::MARKER_TYPE_INTERRUPT,
            full_packet_size,
        ))?;
        socket.flush()?;
        state.break_sent = true;
        Ok(())
    }
}

/// A marker packet, as Transport::send_packets() writes MarkerMessage.
fn marker_packet(marker_type: u8, full_packet_size: bool) -> Vec<u8> {
    let data = [1u8, 0, marker_type];
    let size = 8 + data.len();
    let mut packet = Vec::with_capacity(size);
    if full_packet_size {
        packet.extend((size as u32).to_be_bytes());
    } else {
        packet.extend((size as u16).to_be_bytes());
        packet.extend([0, 0]);
    }
    packet.extend([constants::PACKET_TYPE_MARKER, 0, 0, 0]);
    packet.extend(data);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_packets() {
        assert_eq!(
            marker_packet(constants::MARKER_TYPE_INTERRUPT, false),
            [0, 11, 0, 0, constants::PACKET_TYPE_MARKER, 0, 0, 0, 1, 0, 3]
        );
        assert_eq!(
            marker_packet(constants::MARKER_TYPE_INTERRUPT, true),
            [0, 0, 0, 11, constants::PACKET_TYPE_MARKER, 0, 0, 0, 1, 0, 3]
        );
    }

    #[test]
    fn breaks_only_during_round_trips() {
        let breaker = Breaker::default();
        // Idle: nothing to interrupt, not even without a socket.
        assert!(breaker.send_break().is_ok());
        breaker.begin_round_trip();
        // No socket (TLS): says so.
        assert!(breaker.send_break().is_err());
        assert!(!breaker.end_round_trip());
        assert!(breaker.send_break().is_ok());
    }
}
