//! Parse network packets transmitted between the game and the server
//!
//! Packets are built up in following layers depending on the purpose of the packet:
//!
//! - Packets for connection management ([`GamePacket::Connection`])
//!     - **Ethernet/IP/UDP**, handled using [`etherparse`]
//!     - **[`ConnectionPacket`]**, containing events for connection establishment/disconnection
//! - Packets for game commands ([`GamePacket::Commands`])
//!     - **Ethernet/IP/UDP**, handled using [`etherparse`]
//!     - **KCP**, handled using [`kcp`]
//!         - The KCP header contains an extra field that needs to be removed
//!           to be compatible with the regular KCP protocol
//!     - **[`GameCommand`]**, encrypted using XOR
//!     - **Protobuf**, payload, needs to be parsed into using the types generated in [`gen::proto`]
//!
//! [`GameCommand`]s are encrypted using an XOR-key.
//! One of the first packets sent is a request for a new key from a seed.
//! That key is used for the rest of the packets.
//! This means the recording for packets needs to start before the game starts (train hyperdrive).
//!
//! ## Example
//! ```
//! use auto_reliquary::{GamePacket, GameSniffer, ConnectionPacket};
//!
//! let packets: Vec<Vec<u8>> = vec![/**/];
//!
//! let mut sniffer = GameSniffer::new();
//! for packet in packets {
//!     match sniffer.receive_packet(packet) {
//!         Ok(Some(GamePacket::Connection(ConnectionPacket::Disconnected))) => {
//!             println!("Disconnected!");
//!             break;
//!         }
//!         Ok(Some(GamePacket::Commands(commands))) => {
//!             for command in commands {
//!                 println!("{:?}", command);
//!             }
//!         }
//!         Err(error) => {
//!             println!("{error}");
//!             break;
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use tracing::{info, info_span, instrument, trace, warn};

use crate::connection::parse_connection_packet;
use crate::crypto::{decrypt_command, lookup_initial_key, new_key_from_seed, HEAD_MAGIC};
// use crate::gen::protos::PlayerGetTokenScRsp;
use crate::kcp::KcpSniffer;
use crate::unk_utils::{Achievement, matches_get_quest_data_sc_rsp, matches_player_get_token_sc_rsp};

fn bytes_as_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02x}");
        output
    })
}

pub mod gen;

mod connection;
mod crypto;
mod kcp;
mod unk_utils;

const PORTS: [u16; 2] = [23301, 23302];

/// Top-level packet sent by the game
pub enum GamePacket {
    Connection(ConnectionPacket),
    Commands(Vec<GameCommand>),
}

/// Packet for connection management
pub enum ConnectionPacket {
    HandshakeRequested,
    Disconnected,
    HandshakeEstablished,
    SegmentData(PacketDirection, Vec<u8>),
}

/// Game command header.
///
/// Contains the type of the command in `command_id`
/// and the data encoded in protobuf in `proto_data`
///
/// ## Bit Layout
/// | Bit indices     |  Type |  Name |
/// | - | - | - |
/// |   0..4      |  `u32`  |  Header (magic constant) |
/// |   0..6      |  `u16`  |  command_id |
/// |   6..8      |  `u16`  |  header_len (unsure) |
/// |   8..12     |  `u32`  |  data_len |
/// |  12..12+data_len |  variable  |  proto_data |
/// | data_len..data_len+4  |  `u32`  |  Tail (magic constant) |
#[derive(Clone)]
pub struct GameCommand {
    pub command_id: u16,
    #[allow(unused)]
    pub header_len: u16,
    #[allow(unused)]
    pub data_len: u32,
    #[allow(unused)]
    pub proto_header: Vec<u8>,
    pub proto_data: Vec<u8>,
}

impl GameCommand {
    const HEADER_LEN: usize = 12;
    const TAIL_LEN: usize = 4;

    #[instrument(skip(bytes), fields(len = bytes.len()))]
    pub fn try_new(bytes: Vec<u8>) -> Option<Self> {
        let header_overhead = Self::HEADER_LEN + Self::TAIL_LEN;
        if bytes.len() < header_overhead {
            warn!(len = bytes.len(), "game command header incomplete");
            return None;
        }

        // skip header magic const
        let command_id = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let header_len = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
        let data_len = u32::from_be_bytes(bytes[8..12].try_into().unwrap());

        let data_start = 12 + header_len as usize;
        let data_end = data_start + data_len as usize;

        if data_end > bytes.len() {
            warn!(len = bytes.len(), "game command buffer too short");
            return None;
        }

        let proto_header = bytes[12..data_start].to_vec();
        let proto_data = bytes[data_start..data_end].to_vec();
        Some(GameCommand {
            command_id,
            header_len,
            data_len,
            proto_header,
            proto_data,
        })
    }

    pub fn parse_proto<T: protobuf::Message>(&self) -> protobuf::Result<T> {
        T::parse_from_bytes(&self.proto_data)
    }
}

impl fmt::Debug for GameCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GameCommand")
            .field("command_id", &self.command_id)
            .field("header_len", &self.header_len)
            .field("data_len", &self.data_len)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum PacketDirection {
    Sent,
    Received,
}

pub enum Key {
    Dispatch(Vec<u8>),
    Session(Vec<u8>),
}

/// Why the sniffer gave up on a connection.
///
/// The sniffer has reset itself by the time one of these is returned, so whatever
/// follows starts from scratch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffError {
    /// None of the initial keys fit the connection's first packets. Either the
    /// game has a new key, or the capture started after the login.
    InitialKeyMissing {
        /// The version the packets asked for, where the game has such a thing.
        version: Option<u32>,
        /// Whether the connection's handshake was captured. Without it the
        /// capture started late, and any version is just noise.
        saw_handshake: bool,
    },
    /// The initial key stopped fitting, but no session seed was ever seen.
    SessionSeedMissing,
    /// The session key stopped decrypting the traffic.
    SessionKeyLost,
}

impl fmt::Display for SniffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitialKeyMissing { version, saw_handshake } => write!(
                f,
                "no initial key found (version: {version:?}, handshake seen: {saw_handshake})"
            ),
            Self::SessionSeedMissing => write!(f, "no session seed found"),
            Self::SessionKeyLost => write!(f, "the session key stopped working"),
        }
    }
}

impl std::error::Error for SniffError {}

/// Which key the sniffer is decrypting with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    None,
    Dispatch,
    Session,
}

/// How many packets in a row may fail before a key is given up on. Packets the
/// client sent just before the key changed can still be in flight, so one failure
/// proves nothing.
const MAX_KEY_FAILURES: u32 = 5;

#[derive(Default)]
pub struct GameSniffer {
    sent_kcp: Option<KcpSniffer>,
    recv_kcp: Option<KcpSniffer>,
    key: Option<Key>,
    initial_keys: HashMap<u32, Vec<u8>>,
    saw_handshake: bool,
    key_failures: u32,
}

impl GameSniffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_initial_keys(mut self, initial_keys: HashMap<u32, Vec<u8>>) -> Self {
        self.initial_keys = initial_keys;
        self
    }

    /// Forget the current connection, keeping the keys the sniffer was set up with.
    pub fn reset(&mut self) {
        self.recv_kcp = None;
        self.sent_kcp = None;
        self.key = None;
        self.saw_handshake = false;
        self.key_failures = 0;
    }

    /// Which key the sniffer is decrypting with.
    pub fn key_state(&self) -> KeyState {
        match self.key {
            None => KeyState::None,
            Some(Key::Dispatch(_)) => KeyState::Dispatch,
            Some(Key::Session(_)) => KeyState::Session,
        }
    }

    #[instrument(skip_all, fields(len = bytes.len()))]
    pub fn receive_packet(&mut self, bytes: Vec<u8>) -> Result<Option<GamePacket>, SniffError> {
        let result = self.process_packet(bytes);
        if result.is_err() {
            self.reset();
        }
        result
    }

    fn process_packet(&mut self, bytes: Vec<u8>) -> Result<Option<GamePacket>, SniffError> {
        let Some(packet) = parse_connection_packet(&PORTS, bytes) else {
            return Ok(None);
        };
        match packet {
            ConnectionPacket::HandshakeRequested => {
                info!("handshake requested, resetting state");
                self.reset();
                self.saw_handshake = true;
                Ok(Some(GamePacket::Connection(packet)))
            }
            ConnectionPacket::HandshakeEstablished | ConnectionPacket::Disconnected => {
                self.key = None;
                Ok(Some(GamePacket::Connection(packet)))
            }

            ConnectionPacket::SegmentData(direction, kcp_seg) => {
                let commands = self.receive_kcp_segment(direction, &kcp_seg)?;
                Ok(Some(match commands {
                    Some(commands) => GamePacket::Commands(commands),
                    None => GamePacket::Connection(ConnectionPacket::SegmentData(
                        direction, kcp_seg,
                    )),
                }))
            }
        }
    }

    fn receive_kcp_segment(
        &mut self,
        direction: PacketDirection,
        kcp_seg: &[u8],
    ) -> Result<Option<Vec<GameCommand>>, SniffError> {
        let kcp = match direction {
            PacketDirection::Sent => &mut self.sent_kcp,
            PacketDirection::Received => &mut self.recv_kcp,
        };

        if kcp.is_none() {
            let Some(new_kcp) = KcpSniffer::try_new(kcp_seg) else {
                return Ok(None);
            };
            *kcp = Some(new_kcp);
        }

        if let Some(kcp) = kcp {
            let mut commands = Vec::new();
            for data in kcp.receive_segments(kcp_seg) {
                commands.extend(self.receive_command(data)?);
            }

            return Ok(Some(commands));
        }

        Ok(None)
    }

    /// Count a packet the current key can't decrypt, and give up on the connection
    /// once too many have failed in a row.
    fn key_failure<T>(&mut self, error: SniffError) -> Result<Option<T>, SniffError> {
        self.key_failures += 1;
        if self.key_failures >= MAX_KEY_FAILURES {
            return Err(error);
        }
        Ok(None)
    }

    #[instrument(skip_all, fields(len = data.len()))]
    fn receive_command(&mut self, mut data: Vec<u8>) -> Result<Option<GameCommand>, SniffError> {
        let Some(head) = data.first_chunk::<4>().copied() else {
            warn!(len = data.len(), "game command header incomplete");
            return Ok(None);
        };

        if self.key.is_none() {
            match lookup_initial_key(&self.initial_keys, &head) {
                Ok(key) => self.key = Some(Key::Dispatch(key)),
                Err(version) => {
                    return self.key_failure(SniffError::InitialKeyMissing {
                        version: Some(version),
                        saw_handshake: self.saw_handshake,
                    });
                }
            }
        }

        let Some(key) = &self.key else {
            return Ok(None);
        };
        let key_bytes = match key {
            Key::Dispatch(k) | Key::Session(k) => k,
        };

        decrypt_command(key_bytes, &mut data);

        if !data.starts_with(&HEAD_MAGIC.to_be_bytes()) {
            warn!("command did not decrypt");
            let error = match key {
                Key::Dispatch(_) => SniffError::SessionSeedMissing,
                Key::Session(_) => SniffError::SessionKeyLost,
            };
            return self.key_failure(error);
        }
        self.key_failures = 0;

        let Some(command) = GameCommand::try_new(data) else {
            return Ok(None);
        };

        let span = info_span!("command", ?command);
        let _enter = span.enter();

        info!("received");
        trace!(data = BASE64_STANDARD.encode(&command.proto_data), "data");

        // if !matches!(
        //     command.command_id,
        //     command_id::PLAYER_GET_TOKEN_SC_RSP | command_id::GET_QUEST_DATA_SC_RSP
        // ) {
        //     return None;
        // }

        if let Some(Key::Dispatch(_)) = self.key {
            if let Some(seed) = matches_player_get_token_sc_rsp(command.proto_data.clone()) {
                self.key = Some(Key::Session(new_key_from_seed(seed)));
                info!(?seed, "setting new session seed");
            }
        }

        Ok(Some(command))
    }
}

pub fn matches_achievement_packet(game_command: &GameCommand) -> Option<Vec<Achievement>> {
     return matches_get_quest_data_sc_rsp(game_command.proto_data.clone())
}

#[cfg(test)]
mod tests;
