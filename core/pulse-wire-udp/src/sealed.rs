// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Sealed datagrams: ADR-0018's authenticated, encrypted UDP, opt-in.
//!
//! **Review pending.** ADR-0018 item 9 requires that someone who does
//! cryptographic engineering review this module, and the ADR, before sealed
//! mode is recommended for production. That review has not been done.
//! Until it has, sealed mode should not be relied on in production.
//!
//! ## Known limits, for the reviewer
//!
//! - The Noise library (`snow` 0.9.6) does not reject low-order X25519
//!   points. In the IK pattern the session keys stay secret regardless, but
//!   a peer can make a shared secret degenerate on its own side.
//! - A replayed old initiation can displace a responder's unconfirmed
//!   session for about one round trip, delaying that session; it cannot
//!   decrypt or inject traffic.
//! - A responder that restarts is noticed by its initiator only at the
//!   initiator's next rekey, up to [`SealingConfig`]'s rekey period (120 s
//!   by default); datagrams sealed for the old session until then are
//!   dropped and counted.
//! - Backpressure feedback is sealed under the session of the peer whose
//!   data the receiver took last, so a sealed receiver with backpressure on
//!   serves one sending peer, as plaintext backpressure already does
//!   (feedback is one to one); use FEC, not backpressure, one to many.
//! - Outside Unix, a node's receiver half must be running for a handshake
//!   to complete: only there does [`Sealing::connect`] read the shared
//!   socket itself while the receiver is idle.
//!
//! Plaintext stays the default. Nothing here runs until a [`Sealing`] is
//! installed: [`bind_sealed_pair`] binds a socket and returns a sender and
//! a receiver sealed with one, and [`Sender::with_sealing`] and
//! [`Receiver::with_sealing`] install one on endpoints built otherwise.
//! The two halves of a node share one [`Sealing`] and one socket: its key,
//! its allowlist, its sessions and its counts.
//!
//! ## What is sealed
//!
//! Sealing wraps whole datagrams. Whatever the transport puts in a datagram
//! without sealing (a data frame, a fragment, an FEC parity datagram, an
//! ACK or a NACK, a retransmission) becomes, unchanged and with its CRC, the
//! plaintext of one sealed datagram. FEC, backpressure, NACK and
//! fragmentation work as they do in plaintext, one sealed datagram per
//! datagram, and a receiver hands the inner datagram to the decode a
//! plaintext datagram takes
//! ([`receiver::DataIntake::dispatch`](crate::receiver::DataIntake::dispatch)),
//! so nothing reaches that decode, the reassembler behind it included,
//! unsealed from a sealed endpoint but what the plaintext rule below
//! admits; a fragment is authenticated before it is buffered. A retransmission is sealed again under
//! a fresh counter, as any other datagram is, so the replay window does not
//! refuse it.
//!
//! ## Layout
//!
//! Little-endian, no padding. A sealed datagram, kind 3:
//!
//! ```text
//! +--------+---+------+------+----------+---------+------------------+------+
//! | magic  | v | kind | 0  0 | receiver | counter | inner datagram,  | tag  |
//! |        | 2 | 3    |      | index    |         | encrypted        |      |
//! | 4 B    | 1 | 1    | 2 B  | 4 B      | 8 B     | n B              | 16 B |
//! +--------+---+------+------+----------+---------+------------------+------+
//! ```
//!
//! - **`magic`** is [`MAGIC`], the v1 frame's; **`v`** is
//!   [`SEALED_VERSION`], 2; the two reserved bytes are zero.
//! - **`receiver index`** names the session at the receiving node: the
//!   index that node picked for it during the handshake.
//! - **`counter`** is the sender's seal counter for the session, from 0,
//!   one per datagram sealed.
//! - The inner datagram follows as ChaCha20-Poly1305 ciphertext, with bytes
//!   0..20 as associated data and as nonce four zero bytes then the counter,
//!   the nonce Noise's ChaChaPoly cipher uses; then the 16-byte tag.
//!
//! The header and the tag are [`SEALED_OVERHEAD`], 36 bytes. A sealed
//! datagram fits [`MTU_BYTES`] when its inner datagram fits
//! [`SEALED_INNER_BUDGET`], 1,436 bytes, which is what
//! [`Sender::max_inner_datagram`] and [`Receiver::max_inner_datagram`]
//! report while sealing; a sealing sender's frame carries 36 fewer envelope
//! bytes ([`SEALED_MAX_ENVELOPE`], or [`SEALED_FEC_MAX_ENVELOPE`] with FEC
//! on), and its fragments are 36 bytes shorter
//! ([`Sender::max_datagram`]), so that a run is a few fragments longer. The inner CRC stays: the tag authenticates the datagram,
//! and the CRC is the inner frame's, as in plaintext. A sealed datagram with
//! nothing inside is a keepalive: it confirms a session and is not
//! delivered.
//!
//! The handshake messages carry the same first eight bytes, with kind 1 (an
//! initiation) or 2 (a response):
//!
//! ```text
//! initiation: magic | 2 | 1 | 0 0 | initiator's index (4 B) | Noise message 1 (100 B)
//! response:   magic | 2 | 2 | 0 0 | responder's index (4 B) | initiator's index (4 B) | Noise message 2 (56 B)
//! ```
//!
//! ## Handshake
//!
//! Two nodes run `Noise_IK_25519_ChaChaPoly_BLAKE2s` ([`NOISE_PROTOCOL`])
//! through the `snow` crate, with a fixed prologue naming this format. The
//! initiator knows the responder's static public key, from its allowlist;
//! the responder learns the initiator's from message 1 and answers only a
//! key on its own allowlist (and, for a peer listed with an address, only
//! from that address's IP); any other initiation is dropped without an
//! answer and counted ([`SealCounts::handshakes_refused`]). Each side picks
//! a random 32-bit session index, and each message's Noise payload carries
//! the indices its header carries, so the handshake authenticates them.
//!
//! After message 2 both sides take the two transport keys from snow's raw
//! split (`HandshakeState::dangerously_get_raw_split`, the `risky-raw-split`
//! feature): the first seals from initiator to responder, the second from
//! responder to initiator. snow's own transport state keeps an implicit
//! nonce and seals with no associated data; the raw split instead hands the
//! keys to the `chacha20poly1305` crate, the implementation snow's
//! ChaChaPoly cipher wraps, so each datagram can carry its counter as an
//! explicit nonce, arrive out of order, and bind its header as associated
//! data. That is how the Noise specification lets transport messages be
//! used over a lossy, reordering network: each key with a nonce that is
//! never reused, here the per-session counter, which is never reset and
//! never wraps (below). No primitive, construction or handshake is written
//! here: the handshake is snow's and the AEAD is the crate's.
//!
//! The responder does not seal with a new session until a datagram from the
//! initiator has arrived on it, which proves the initiator holds the
//! session's keys; the initiator sends a keepalive right after message 2 so
//! that this happens at once. A repeated initiation (the same Noise
//! ephemeral key) is answered with the same response while its session is
//! unconfirmed, and refused once the session is in use.
//!
//! ## Replay
//!
//! Each session keeps a sliding bitmap over the [`REPLAY_WINDOW`] (2,048)
//! counters up to the highest it has accepted. A counter older than the
//! window, or one already seen inside it, is dropped and counted
//! ([`SealCounts::too_old`], [`SealCounts::replayed`]); the window moves
//! only after the tag has verified, so forged datagrams cannot move it.
//! Within the window, datagrams may arrive in any order.
//!
//! ## Keys and peers
//!
//! A [`NodeKey`] is a node's long-term X25519 key pair: generated, saved to
//! a file created `0o600`, loaded only from a file no group or other user
//! can read or write, and written in configuration as 64 hex digits. Its
//! [`PublicKey`] is the node's identity on the network. An [`Allowlist`] is
//! the set of peer public keys a node admits, each optionally with a fixed
//! address. There is no certificate authority.
//!
//! ## Sessions and rekeying
//!
//! A session is replaced by a fresh handshake every
//! [`SealingConfig::rekey_after`] (two minutes), and before its counter
//! could approach wrap ([`REKEY_AFTER_MESSAGES`]); a counter at
//! [`REJECT_AFTER_MESSAGES`] seals nothing. The node that initiated a
//! session rekeys it, from its send path, its receive paths and its
//! feedback thread, whichever runs first once it is due; the responder
//! rekeys it as well, as a backstop, once the session is a grace period
//! past due. The old session is kept, to open datagrams sealed before the
//! switch, until the new one has carried a datagram each way or for
//! [`SealingConfig::old_session_grace`] (10 seconds), whichever comes
//! first. A peer whose sessions carry nothing for three rekey periods
//! ([`IDLE_REKEY_PERIODS`]) is dropped, sessions and all.
//!
//! The newest session is the one sealed with, on both nodes, because two
//! nodes never finish two handshakes with each other at once. When their
//! initiations cross (each sent one before the other's arrived), the node
//! with the lower public key drops the other's, and the node with the
//! higher key answers the lower's and abandons its own. A node's own
//! initiation counts as crossing only while it is fresh: sent within the
//! last second, the interval at which [`Sealing::connect`] sends a fresh one
//! (or within the handshake retry period, if that is shorter). One older
//! than that has drawn no response in a round trip; it went to an address
//! the peer is not at, or was lost, and the lower key abandons it for the
//! peer's initiation as the higher key always does, so that a peer that
//! moved or restarted is not refused until the stale initiation lapses. And
//! a node that
//! holds the peer's initiation, answered but not yet confirmed, starts no
//! handshake of its own while that one is younger than the handshake retry
//! period (five seconds, or the rekey period if shorter; [`Sealing::connect`]
//! waits up to a second for it), and discards it when it does start one.
//! Both rules are decided under one lock with the handshake messages that
//! arrive. A node that restarts with its key is therefore taken back at
//! once: its new session is the newest.
//!
//! Replacing the allowlist ([`Sealing::set_allowlist`]) drops every session
//! of a peer that is no longer on it.
//!
//! ## Plaintext
//!
//! A sealing node refuses a datagram that is not sealed (a v1 frame,
//! parity, an ACK or a NACK sent in plaintext, anything without the sealed
//! header) from any address that is not loopback, and counts it
//! ([`SealCounts::plaintext_refused`]). From loopback it admits one only
//! when [`SealingConfig::allow_loopback_plaintext`] says so, off by
//! default; an admitted datagram takes the plaintext path unchanged.
//!
//! ## Sockets
//!
//! Every socket write and read of a sealing endpoint goes through this
//! module:
//!
//! - The sender seals each data frame, each fragment, each parity datagram
//!   and each retransmission before it leaves (the scatter-gather send is
//!   not used: the frame is built in one buffer and sealed into another).
//!   The send cache and the FEC encoder keep datagrams unsealed. A batch
//!   send goes frame by frame through the same path instead of
//!   `sendmmsg(2)`.
//! - The receiver opens each datagram it reads, singly and in batches;
//!   `recvmmsg(2)` stays, each datagram opened as the batch is taken. Each
//!   frame it delivers names the public key of the peer whose session
//!   opened it ([`RecvMeta::sealed_by`](crate::RecvMeta::sealed_by)), which
//!   is how a caller knows the sender: a session is found by its index, not
//!   by the source address, which a peer can forge.
//! - The receiver's feedback thread seals its ACKs and NACKs under the
//!   session of the peer whose data it last took; the sender's feedback
//!   thread opens what its feedback socket reads.
//!
//! A responder answers initiations from its receiver: the receiver half
//! must be receiving for other nodes to connect to it. [`Sealing::connect`]
//! sends an initiation from the shared socket and waits for the response,
//! which a receiver half takes when one is receiving; when none has
//! received for 50 ms, `connect` reads the socket itself, without waiting
//! (on Unix), as a sender does before each send while a rekey is in flight.
//! What those reads find that is not a handshake message is kept, up to 256
//! datagrams, for the receiver half's next receive ([`SealCounts::stash_dropped`]
//! counts any beyond). A sealed session is found by its index, not its
//! address, so the feedback sockets, on ports of their own, use the same
//! sessions.
//!
//! What is not protected is ADR-0018's list: a process running as the same
//! user, a compromised host, volumetric denial of service, traffic
//! analysis, and any endpoint with sealing off.
//!
//! [`Sender::with_sealing`]: crate::Sender::with_sealing
//! [`Receiver::with_sealing`]: crate::Receiver::with_sealing
//! [`Sender::max_inner_datagram`]: crate::Sender::max_inner_datagram
//! [`Sender::max_datagram`]: crate::Sender::max_datagram
//! [`Receiver::max_inner_datagram`]: crate::Receiver::max_inner_datagram

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use parking_lot::{Condvar, Mutex, RwLock};
use snow::params::NoiseParams;
use snow::HandshakeState;
use zeroize::{Zeroize, Zeroizing};

use crate::receiver::Receiver;
use crate::retry::{count_error, retry_interrupted};
use crate::sender::Sender;
use crate::wire::{MAGIC, MTU_BYTES};

/// The version byte of a sealed datagram and of the handshake messages.
pub const SEALED_VERSION: u8 = 2;

/// The kind byte of a handshake initiation, Noise message 1.
pub const KIND_INITIATION: u8 = 1;

/// The kind byte of a handshake response, Noise message 2.
pub const KIND_RESPONSE: u8 = 2;

/// The kind byte of a sealed datagram.
pub const KIND_SEALED: u8 = 3;

/// The cleartext header of a sealed datagram: magic, version, kind, two
/// reserved bytes, the receiver's session index and the counter.
pub const SEALED_HEADER_BYTES: usize = 4 + 1 + 1 + 2 + 4 + 8;

/// The ChaCha20-Poly1305 tag that ends a sealed datagram.
pub const TAG_BYTES: usize = 16;

/// What sealing adds to a datagram: the header and the tag, 36 bytes.
pub const SEALED_OVERHEAD: usize = SEALED_HEADER_BYTES + TAG_BYTES;

/// The largest inner datagram whose sealed datagram fits [`MTU_BYTES`]:
/// 1,436 bytes.
pub const SEALED_INNER_BUDGET: usize = MTU_BYTES - SEALED_OVERHEAD;

/// The largest envelope a sealing sender accepts, 1,279 bytes:
/// [`MAX_ENVELOPE`](crate::MAX_ENVELOPE) less [`SEALED_OVERHEAD`].
pub const SEALED_MAX_ENVELOPE: usize = crate::wire::MAX_ENVELOPE - SEALED_OVERHEAD;

/// The largest envelope a sealing sender with FEC on accepts, 1,261 bytes:
/// [`FEC_MAX_ENVELOPE`](crate::FEC_MAX_ENVELOPE) less [`SEALED_OVERHEAD`],
/// so that a sealed parity datagram fits one MTU too.
pub const SEALED_FEC_MAX_ENVELOPE: usize = crate::fec::FEC_MAX_ENVELOPE - SEALED_OVERHEAD;

/// Counters a session's replay window spans.
pub const REPLAY_WINDOW: u64 = 2048;

/// Default [`SealingConfig::rekey_after`]: two minutes.
pub const DEFAULT_REKEY_AFTER: Duration = Duration::from_secs(120);

/// Default [`SealingConfig::old_session_grace`]: ten seconds.
pub const DEFAULT_OLD_SESSION_GRACE: Duration = Duration::from_secs(10);

/// Rekey periods a peer's sessions may carry nothing before they are
/// dropped.
pub const IDLE_REKEY_PERIODS: u32 = 3;

/// A session whose counter reaches this is rekeyed, whatever its age.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// A session whose counter reaches this seals nothing more, so a counter
/// never wraps and a nonce is never reused.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

/// The Noise protocol the handshake runs.
pub const NOISE_PROTOCOL: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// The handshake's prologue, binding it to this format.
const PROLOGUE: &[u8] = b"pulse-wire-udp sealed datagram v2";

/// An initiation's length: the 8-byte header, the initiator's index, then
/// Noise message 1 (an ephemeral key, the encrypted static key and the
/// encrypted 4-byte payload).
pub const INITIATION_BYTES: usize = 8 + 4 + 32 + (32 + 16) + (4 + 16);

/// A response's length: the 8-byte header, both indices, then Noise
/// message 2 (an ephemeral key and the encrypted 8-byte payload).
pub const RESPONSE_BYTES: usize = 8 + 4 + 4 + 32 + (8 + 16);

/// The longest wait for a rekey's response before it is sent afresh.
const HANDSHAKE_RETRY: Duration = Duration::from_secs(5);

/// How often [`Sealing::connect`] sends a fresh initiation while it waits.
const CONNECT_RESEND: Duration = Duration::from_secs(1);

/// How long `connect` waits between looks at the socket, when it reads it.
const CONNECT_POLL: Duration = Duration::from_millis(1);

/// Datagrams kept for the receiver half by reads it did not make.
const STASH_CAPACITY: usize = 256;

/// How long after a receive the receiver half counts as receiving.
const RECEIVER_IDLE: Duration = Duration::from_millis(50);

/// The longest gap between two looks at the sessions' timers.
const MAINTAIN_EVERY: Duration = Duration::from_millis(100);

/// The shortest rekey period taken.
const MIN_REKEY_AFTER: Duration = Duration::from_millis(10);

#[non_exhaustive]
/// Errors of key handling, of the handshake and of sealing.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The socket refused a handshake message.
    #[error("sealing i/o failed: {0}")]
    Io(#[from] std::io::Error),
    /// The key file could not be opened, created, read or written.
    #[error("key file {path}: {source}")]
    KeyFile {
        /// The file.
        path: PathBuf,
        /// The underlying error; `AlreadyExists` when saving over a file.
        #[source]
        source: std::io::Error,
    },
    /// The key file can be read or written by its group or by others, or is
    /// not a regular file; it is not loaded.
    #[error(
        "key file {path} has mode {mode:o}; it must be a regular file of mode 0600 or stricter"
    )]
    KeyFileExposed {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// Text that should name a key is not 64 hex digits.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// The peer's key is not on this node's allowlist.
    #[error("peer key {0} is not on the allowlist")]
    NotAllowed(PublicKey),
    /// No response to the handshake arrived within the timeout.
    #[error("no handshake response from {addr} within {timeout:?}")]
    HandshakeTimeout {
        /// Where the initiations went.
        addr: SocketAddr,
        /// How long [`Sealing::connect`] waited.
        timeout: Duration,
    },
    /// There is no session to the destination: [`Sealing::connect`] first,
    /// or the session was dropped, idle, or spent its counter.
    #[error("no sealed session to {0}")]
    NoSession(SocketAddr),
    /// The Noise library or the system's entropy source refused.
    #[error("crypto: {0}")]
    Crypto(String),
}

fn crypto_error(e: impl fmt::Display) -> SealError {
    SealError::Crypto(e.to_string())
}

/// Parse 64 hex digits, surrounding whitespace aside, as 32 bytes.
fn parse_key_hex(text: &str) -> Result<[u8; 32], SealError> {
    let text = text.trim();
    let mut out = [0u8; 32];
    if text.len() != 64 {
        return Err(SealError::InvalidKey(format!(
            "{} characters, expected 64 hex digits",
            text.len()
        )));
    }
    hex::decode_to_slice(text, &mut out).map_err(|e| SealError::InvalidKey(e.to_string()))?;
    Ok(out)
}

/// A node's identity on the network: its X25519 static public key.
/// Written in configuration as 64 hex digits ([`Self::to_hex`], and
/// `FromStr`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// The key whose bytes are `bytes`.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The key's 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The key as 64 lowercase hex digits.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The key that 64 hex digits name.
    ///
    /// # Errors
    /// [`SealError::InvalidKey`] for anything but 64 hex digits.
    pub fn from_hex(text: &str) -> Result<Self, SealError> {
        parse_key_hex(text).map(Self)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl FromStr for PublicKey {
    type Err = SealError;

    fn from_str(text: &str) -> Result<Self, SealError> {
        Self::from_hex(text)
    }
}

/// The Noise parameters of [`NOISE_PROTOCOL`].
fn noise_params() -> Result<NoiseParams, SealError> {
    NOISE_PROTOCOL.parse().map_err(crypto_error)
}

/// A node's long-term X25519 key pair. The secret half is wiped when the
/// key is dropped, and never printed.
///
/// The key file holds the secret as 64 hex digits and a newline.
/// [`Self::save`] creates it with mode `0o600` and never overwrites one;
/// [`Self::load`] refuses a file its group or others can read or write.
#[derive(Clone)]
pub struct NodeKey {
    secret: Zeroizing<[u8; 32]>,
    public: PublicKey,
}

impl NodeKey {
    /// A fresh key pair, from the system's entropy through snow.
    ///
    /// # Errors
    /// [`SealError::Crypto`] if no entropy can be had.
    pub fn generate() -> Result<Self, SealError> {
        let mut pair = snow::Builder::new(noise_params()?)
            .generate_keypair()
            .map_err(crypto_error)?;
        let result = Self::from_pair(&pair.private, &pair.public);
        pair.private.zeroize();
        result
    }

    fn from_pair(private: &[u8], public: &[u8]) -> Result<Self, SealError> {
        let mut secret = Zeroizing::new([0u8; 32]);
        let mut public_bytes = [0u8; 32];
        if private.len() != 32 || public.len() != 32 {
            return Err(SealError::Crypto("an X25519 key is not 32 bytes".into()));
        }
        secret.copy_from_slice(private);
        public_bytes.copy_from_slice(public);
        Ok(Self {
            secret,
            public: PublicKey(public_bytes),
        })
    }

    /// The key pair whose secret half is `secret`; its public half is
    /// derived with snow's X25519.
    ///
    /// # Errors
    /// [`SealError::Crypto`] if snow has no X25519, which its default
    /// resolver always has.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Result<Self, SealError> {
        use snow::params::DHChoice;
        use snow::resolvers::{CryptoResolver, DefaultResolver};
        let mut dh = DefaultResolver
            .resolve_dh(&DHChoice::Curve25519)
            .ok_or_else(|| SealError::Crypto("no X25519 implementation".into()))?;
        dh.set(secret);
        Self::from_pair(secret, dh.pubkey())
    }

    /// The public half: the node's identity.
    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Write the key to a new file at `path`, created with mode `0o600`
    /// (on Unix; elsewhere with the platform's defaults).
    ///
    /// # Errors
    /// [`SealError::KeyFile`] when the file exists (`AlreadyExists`) or
    /// cannot be created or written.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), SealError> {
        let path = path.as_ref();
        let key_file = |source| SealError::KeyFile {
            path: path.to_path_buf(),
            source,
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(key_file)?;
        let mut text = Zeroizing::new(hex::encode(&self.secret[..]));
        text.push('\n');
        file.write_all(text.as_bytes()).map_err(key_file)?;
        file.sync_all().map_err(key_file)
    }

    /// Read a key [`Self::save`] wrote. The file must be a regular file
    /// that neither its group nor others can read or write (on Unix, mode
    /// `0o600` or stricter), checked on the open file.
    ///
    /// # Errors
    /// [`SealError::KeyFileExposed`] for a file others can reach or that is
    /// not a regular file; [`SealError::KeyFile`] when it cannot be read;
    /// [`SealError::InvalidKey`] when it does not hold 64 hex digits.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, SealError> {
        let path = path.as_ref();
        let key_file = |source| SealError::KeyFile {
            path: path.to_path_buf(),
            source,
        };
        let file = std::fs::File::open(path).map_err(key_file)?;
        let meta = file.metadata().map_err(key_file)?;
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o7777
        };
        #[cfg(not(unix))]
        let mode = 0o600;
        if !meta.is_file() || mode & 0o077 != 0 {
            return Err(SealError::KeyFileExposed {
                path: path.to_path_buf(),
                mode,
            });
        }
        let mut text = Zeroizing::new(String::new());
        (&file)
            .take(256)
            .read_to_string(&mut text)
            .map_err(key_file)?;
        let secret = Zeroizing::new(parse_key_hex(&text)?);
        Self::from_secret_bytes(&secret)
    }

    /// [`Self::load`] the key at `path`, or, when there is no file there,
    /// generate one and [`Self::save`] it: a node's first start.
    ///
    /// # Errors
    /// As [`Self::load`], [`Self::generate`] and [`Self::save`].
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, SealError> {
        let path = path.as_ref();
        match Self::load(path) {
            Err(SealError::KeyFile { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                let key = Self::generate()?;
                match key.save(path) {
                    Ok(()) => Ok(key),
                    // Another process made it first: theirs is the key.
                    Err(SealError::KeyFile { source, .. })
                        if source.kind() == std::io::ErrorKind::AlreadyExists =>
                    {
                        Self::load(path)
                    }
                    Err(e) => Err(e),
                }
            }
            other => other,
        }
    }
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// The peers a node admits: their public keys, each optionally with a fixed
/// address. A peer listed with an address is admitted only from that
/// address's IP (the port is not compared, as the crate's other source
/// filters do not compare it, since a node's feedback comes from a port of
/// its own).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Allowlist {
    peers: BTreeMap<PublicKey, Option<SocketAddr>>,
}

impl Allowlist {
    /// An allowlist that admits nobody.
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit `key` from any address.
    pub fn allow(&mut self, key: PublicKey) {
        self.peers.insert(key, None);
    }

    /// Admit `key` from `addr`'s IP only.
    pub fn allow_at(&mut self, key: PublicKey, addr: SocketAddr) {
        self.peers.insert(key, Some(addr));
    }

    /// Stop admitting `key`; whether it was admitted.
    pub fn remove(&mut self, key: &PublicKey) -> bool {
        self.peers.remove(key).is_some()
    }

    /// Whether `key` is admitted.
    pub fn contains(&self, key: &PublicKey) -> bool {
        self.peers.contains_key(key)
    }

    /// The fixed address `key` is listed with, if any.
    pub fn address_of(&self, key: &PublicKey) -> Option<SocketAddr> {
        self.peers.get(key).copied().flatten()
    }

    /// Peers admitted.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether nobody is admitted.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// The admitted keys, in order.
    pub fn keys(&self) -> impl Iterator<Item = &PublicKey> {
        self.peers.keys()
    }

    /// Whether `key` is admitted from `src`.
    fn admits(&self, key: &PublicKey, src: SocketAddr) -> bool {
        match self.peers.get(key) {
            None => false,
            Some(None) => true,
            Some(Some(fixed)) => fixed.ip().to_canonical() == src.ip().to_canonical(),
        }
    }
}

impl FromIterator<PublicKey> for Allowlist {
    fn from_iter<I: IntoIterator<Item = PublicKey>>(keys: I) -> Self {
        let mut list = Self::new();
        for key in keys {
            list.allow(key);
        }
        list
    }
}

/// How a [`Sealing`] runs its sessions. Build it with [`Self::new`], then
/// set fields or use the builders.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealingConfig {
    /// How old a session gets before the node that initiated it replaces
    /// it with a fresh handshake; a peer's sessions are dropped after
    /// [`IDLE_REKEY_PERIODS`] of these with nothing carried. Taken as at
    /// least 10 ms. Default [`DEFAULT_REKEY_AFTER`].
    pub rekey_after: Duration,
    /// How long a replaced session still opens datagrams, unless the new
    /// one carries a datagram each way first. Default
    /// [`DEFAULT_OLD_SESSION_GRACE`].
    pub old_session_grace: Duration,
    /// Admit plaintext datagrams from loopback sources. Off by default:
    /// a sealing node then refuses every datagram that is not sealed.
    /// Plaintext from any other source is refused either way.
    pub allow_loopback_plaintext: bool,
}

impl Default for SealingConfig {
    fn default() -> Self {
        Self {
            rekey_after: DEFAULT_REKEY_AFTER,
            old_session_grace: DEFAULT_OLD_SESSION_GRACE,
            allow_loopback_plaintext: false,
        }
    }
}

impl SealingConfig {
    /// The defaults: rekey every two minutes, a ten-second grace, no
    /// plaintext admitted.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set [`Self::rekey_after`].
    #[must_use]
    pub fn with_rekey_after(mut self, period: Duration) -> Self {
        self.rekey_after = period;
        self
    }

    /// Set [`Self::old_session_grace`].
    #[must_use]
    pub fn with_old_session_grace(mut self, grace: Duration) -> Self {
        self.old_session_grace = grace;
        self
    }

    /// Set [`Self::allow_loopback_plaintext`].
    #[must_use]
    pub fn with_loopback_plaintext(mut self, allow: bool) -> Self {
        self.allow_loopback_plaintext = allow;
        self
    }

    fn rekey_period(&self) -> Duration {
        self.rekey_after.max(MIN_REKEY_AFTER)
    }

    fn handshake_retry(&self) -> Duration {
        self.rekey_period().min(HANDSHAKE_RETRY)
    }

    /// How long this node's own initiation counts as crossing a peer's
    /// (`on_initiation`): [`CONNECT_RESEND`], after which `connect` would
    /// have sent a fresh one, or the handshake retry period if shorter.
    fn crossing_window(&self) -> Duration {
        self.handshake_retry().min(CONNECT_RESEND)
    }

    fn maintain_every(&self) -> Duration {
        (self.rekey_period() / 4).min(MAINTAIN_EVERY)
    }
}

/// What a [`Sealing`] has done and refused, since it was made; a snapshot
/// from [`Sealing::counts`]. Each refusal is also logged, at the first and
/// each doubling.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SealCounts {
    /// Datagrams sealed, keepalives included.
    pub sealed: u64,
    /// Sealed datagrams opened and accepted, keepalives included.
    pub opened: u64,
    /// Sealed datagrams whose tag did not verify: changed, forged, or
    /// sealed under another key.
    pub unauthentic: u64,
    /// Sealed datagrams whose counter the session had already accepted.
    pub replayed: u64,
    /// Sealed datagrams whose counter was older than the replay window.
    pub too_old: u64,
    /// Sealed datagrams and responses naming no session or handshake of
    /// this node's: forged, or for one dropped.
    pub unknown_session: u64,
    /// Datagrams with the sealed header and a bad kind, length, reserved
    /// byte or counter.
    pub malformed: u64,
    /// Datagrams that are not sealed, refused.
    pub plaintext_refused: u64,
    /// Datagrams that are not sealed, admitted from loopback because
    /// [`SealingConfig::allow_loopback_plaintext`] says so.
    pub plaintext_admitted: u64,
    /// Initiations refused: from a key not on the allowlist, from the wrong
    /// address for one listed with an address, repeating the one that made a
    /// session already in use, or crossing this node's own fresh initiation
    /// to a peer whose key is higher (that peer answers this node's
    /// instead).
    pub handshakes_refused: u64,
    /// Handshake messages that did not decrypt or whose payload did not
    /// match their header.
    pub handshakes_failed: u64,
    /// Sessions that became usable: on the initiator when the response
    /// arrives, on the responder when the first datagram on it does.
    pub sessions_established: u64,
    /// Datagrams not sealed for want of a session: sends refused with
    /// [`SealError::NoSession`], and feedback with no peer to go to yet.
    pub no_session: u64,
    /// Datagrams read for the receiver half that it had no room to keep.
    pub stash_dropped: u64,
}

#[derive(Default)]
struct Counters {
    sealed: AtomicU64,
    opened: AtomicU64,
    unauthentic: AtomicU64,
    replayed: AtomicU64,
    too_old: AtomicU64,
    unknown_session: AtomicU64,
    malformed: AtomicU64,
    plaintext_refused: AtomicU64,
    plaintext_admitted: AtomicU64,
    handshakes_refused: AtomicU64,
    handshakes_failed: AtomicU64,
    sessions_established: AtomicU64,
    no_session: AtomicU64,
    stash_dropped: AtomicU64,
    transmit_errors: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> SealCounts {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        SealCounts {
            sealed: get(&self.sealed),
            opened: get(&self.opened),
            unauthentic: get(&self.unauthentic),
            replayed: get(&self.replayed),
            too_old: get(&self.too_old),
            unknown_session: get(&self.unknown_session),
            malformed: get(&self.malformed),
            plaintext_refused: get(&self.plaintext_refused),
            plaintext_admitted: get(&self.plaintext_admitted),
            handshakes_refused: get(&self.handshakes_refused),
            handshakes_failed: get(&self.handshakes_failed),
            sessions_established: get(&self.sessions_established),
            no_session: get(&self.no_session),
            stash_dropped: get(&self.stash_dropped),
        }
    }
}

/// Count one refusal in `counter` and log the first and each doubling.
fn refuse(counter: &AtomicU64, src: SocketAddr, what: &'static str) {
    if let Some(n) = count_error(counter) {
        tracing::warn!(%src, refused = n, "{what}; dropped");
    }
}

/// The monotonic clock in nanoseconds, the crate's.
fn now() -> u64 {
    crate::monotonic_nanos()
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// The nonce of the datagram sealed under `counter`: four zero bytes, then
/// the counter, little-endian.
fn nonce(counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(bytes)
}

/// The first eight bytes of every sealed-family datagram.
fn put_header(out: &mut Vec<u8>, kind: u8) {
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.push(SEALED_VERSION);
    out.push(kind);
    out.extend_from_slice(&[0, 0]);
}

fn read_u32(d: &[u8], at: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&d[at..at + 4]);
    u32::from_le_bytes(b)
}

fn read_u64(d: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[at..at + 8]);
    u64::from_le_bytes(b)
}

/// A random session index, never zero (zero means none).
fn random_index() -> Result<u32, SealError> {
    loop {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).map_err(crypto_error)?;
        let index = u32::from_le_bytes(b);
        if index != 0 {
            return Ok(index);
        }
    }
}

/// What a datagram claims to be, from its first bytes and its length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// Not of the sealed family: no magic, or another version.
    Plaintext,
    /// The sealed header with a bad kind, length or reserved byte.
    Malformed,
    Initiation,
    Response,
    Sealed,
}

fn classify(d: &[u8]) -> Class {
    if d.len() < 5 || d[0..4] != MAGIC.to_le_bytes() || d[4] != SEALED_VERSION {
        return Class::Plaintext;
    }
    if d.len() < 8 || d[6] != 0 || d[7] != 0 {
        return Class::Malformed;
    }
    match d[5] {
        KIND_INITIATION if d.len() == INITIATION_BYTES => Class::Initiation,
        KIND_RESPONSE if d.len() == RESPONSE_BYTES => Class::Response,
        KIND_SEALED if d.len() >= SEALED_OVERHEAD => Class::Sealed,
        _ => Class::Malformed,
    }
}

/// What [`Sealing::open`] made of a datagram; public only for the fuzz
/// harness and the tests.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opened {
    /// The buffer's first `len` bytes are a datagram for the plaintext
    /// path's decode: the inner datagram of a sealed one, moved to the
    /// front, or a plaintext datagram admitted from loopback, as it came.
    Inner(usize),
    /// Taken here: a handshake message, a keepalive, or a refusal, counted.
    Consumed,
}

/// The verdict of a replay window on a counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Fresh,
    Seen,
    TooOld,
}

const WINDOW_WORDS: usize = (REPLAY_WINDOW / 64) as usize;

/// A session's accepted counters: a ring of [`REPLAY_WINDOW`] bits over
/// the counters from `next - REPLAY_WINDOW` up to `next`, one past the
/// highest accepted.
struct ReplayWindow {
    next: u64,
    bits: [u64; WINDOW_WORDS],
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            next: 0,
            bits: [0; WINDOW_WORDS],
        }
    }

    fn slot(counter: u64) -> (usize, u64) {
        let i = (counter % REPLAY_WINDOW) as usize;
        (i / 64, 1u64 << (i % 64))
    }

    fn check(&self, counter: u64) -> Verdict {
        if counter >= self.next {
            return Verdict::Fresh;
        }
        if self.next - counter > REPLAY_WINDOW {
            return Verdict::TooOld;
        }
        let (word, bit) = Self::slot(counter);
        if self.bits[word] & bit != 0 {
            Verdict::Seen
        } else {
            Verdict::Fresh
        }
    }

    /// Record `counter` if it is fresh; the verdict either way. `counter`
    /// is below [`REJECT_AFTER_MESSAGES`].
    fn accept(&mut self, counter: u64) -> Verdict {
        let verdict = self.check(counter);
        if verdict != Verdict::Fresh {
            return verdict;
        }
        if counter >= self.next {
            // The counters from `next` to `counter` enter the window, over
            // the slots of those that leave it.
            if counter - self.next >= REPLAY_WINDOW {
                self.bits = [0; WINDOW_WORDS];
            } else {
                for c in self.next..=counter {
                    let (word, bit) = Self::slot(c);
                    self.bits[word] &= !bit;
                }
            }
            self.next = counter + 1;
        }
        let (word, bit) = Self::slot(counter);
        self.bits[word] |= bit;
        Verdict::Fresh
    }
}

/// One session: the keys each way, the counter, the replay window.
struct Session {
    /// The index this node picked: the one in datagrams that arrive.
    local_index: u32,
    /// The index the peer picked: the one in datagrams that leave.
    remote_index: u32,
    peer: PublicKey,
    we_initiated: bool,
    /// The initiation's ephemeral key, on the responder, to know a repeat.
    initiation: Option<[u8; 32]>,
    seal: ChaCha20Poly1305,
    open: ChaCha20Poly1305,
    counter: AtomicU64,
    window: Mutex<ReplayWindow>,
    created: u64,
    last_sent: AtomicU64,
    last_received: AtomicU64,
    sent_any: AtomicBool,
    received_any: AtomicBool,
}

impl Session {
    fn new(
        local_index: u32,
        remote_index: u32,
        peer: PublicKey,
        we_initiated: bool,
        initiation: Option<[u8; 32]>,
        keys: &(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>),
        now: u64,
    ) -> Self {
        // Noise's split: the first key seals from initiator to responder.
        let (seal_key, open_key) = if we_initiated {
            (&keys.0, &keys.1)
        } else {
            (&keys.1, &keys.0)
        };
        Self {
            local_index,
            remote_index,
            peer,
            we_initiated,
            initiation,
            seal: ChaCha20Poly1305::new(Key::from_slice(&seal_key[..])),
            open: ChaCha20Poly1305::new(Key::from_slice(&open_key[..])),
            counter: AtomicU64::new(0),
            window: Mutex::new(ReplayWindow::new()),
            created: now,
            last_sent: AtomicU64::new(0),
            last_received: AtomicU64::new(0),
            sent_any: AtomicBool::new(false),
            received_any: AtomicBool::new(false),
        }
    }

    fn last_active(&self) -> u64 {
        self.created
            .max(self.last_sent.load(Ordering::Relaxed))
            .max(self.last_received.load(Ordering::Relaxed))
    }
}

/// The raw split of a finished handshake, wiped when dropped.
fn split(hs: &mut HandshakeState) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let (mut a, mut b) = hs.dangerously_get_raw_split();
    let keys = (Zeroizing::new(a), Zeroizing::new(b));
    a.zeroize();
    b.zeroize();
    keys
}

/// A response this node sent, for a session the initiator has not yet
/// confirmed.
struct Answered {
    index: u32,
    response: Vec<u8>,
    /// When it was answered.
    at: u64,
}

/// An initiation this node sent and awaits the response to.
struct Pending {
    peer: PublicKey,
    hs: HandshakeState,
    addr: SocketAddr,
    sent_at: u64,
}

/// What a node knows of one peer.
#[derive(Default)]
struct PeerState {
    /// The session datagrams to the peer are sealed with.
    current: Option<u32>,
    /// When `current` became current.
    current_since: u64,
    /// The session `current` replaced, still opening.
    previous: Option<u32>,
    /// When `previous` stops opening.
    previous_until: u64,
    /// A session this node answered and the peer has not yet confirmed.
    next: Option<Answered>,
    /// The index of this node's initiation in flight.
    pending: Option<u32>,
    /// Where this node's initiations to the peer go.
    addr: Option<SocketAddr>,
}

#[derive(Default)]
struct Table {
    sessions: HashMap<u32, Arc<Session>>,
    peers: HashMap<PublicKey, PeerState>,
    by_addr: HashMap<SocketAddr, PublicKey>,
    pending: HashMap<u32, Pending>,
    /// Initiation ephemeral keys answered, to the session each made.
    answered: HashMap<[u8; 32], u32>,
}

impl Table {
    fn current_of(&self, peer: &PublicKey) -> Option<Arc<Session>> {
        let index = self.peers.get(peer)?.current?;
        self.sessions.get(&index).cloned()
    }

    fn index_in_use(&self, index: u32) -> bool {
        self.sessions.contains_key(&index) || self.pending.contains_key(&index)
    }

    /// Send to `addr` with `peer`'s sessions. Unless `force`, an address
    /// that already names another peer with a session keeps it.
    fn map_address(&mut self, addr: SocketAddr, peer: PublicKey, force: bool) {
        let keep = !force
            && self
                .by_addr
                .get(&addr)
                .is_some_and(|other| *other != peer && self.current_of(other).is_some());
        if !keep {
            self.by_addr.insert(addr, peer);
        }
    }
}

/// A datagram a non-receiver read took off the socket, for the receiver.
struct Stashed {
    datagram: Vec<u8>,
    src: SocketAddr,
}

/// The shared state: one per node, behind every handle.
struct Inner {
    /// The node's socket, for handshake messages and reads made for an
    /// absent receiver; `None` for a detached sealing (fuzzing, tests).
    socket: Option<UdpSocket>,
    /// What a detached sealing would have sent.
    outbox: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    key: NodeKey,
    params: NoiseParams,
    allowlist: RwLock<Allowlist>,
    config: SealingConfig,
    table: Mutex<Table>,
    /// Signalled when a session is installed.
    changed: Condvar,
    counts: Counters,
    stash: Mutex<VecDeque<Stashed>>,
    stashed: AtomicUsize,
    pending: AtomicUsize,
    /// Receives in progress on the receiver half.
    reading: AtomicUsize,
    /// When the receiver half last started or ended a receive.
    last_read: AtomicU64,
    next_maintain: AtomicU64,
    /// The session the receiver half last took data on: its peer's
    /// sessions carry the receiver's feedback. Zero for none.
    data_session: AtomicU32,
}

/// The slot a feedback thread reads its endpoint's sealing from, so that
/// sealing installed after backpressure reaches it.
pub(crate) type SealSlot = Arc<RwLock<Option<Sealing>>>;

/// A node's sealing: its key, its allowlist, its sessions and its counts,
/// shared by the sender and receiver halves of one socket and by their
/// feedback threads. Cloning it clones the handle.
///
/// Read the module docs ([`crate::sealed`]) before relying on it: the
/// review ADR-0018 requires is pending.
#[derive(Clone)]
pub struct Sealing {
    inner: Arc<Inner>,
}

impl fmt::Debug for Sealing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealing")
            .field("public_key", &self.inner.key.public)
            .field("counts", &self.counts())
            .finish_non_exhaustive()
    }
}

/// Bind a socket at `local_addr` and return a sender and a receiver on it,
/// sealed with one [`Sealing`] of `key` and `allowlist`, with the default
/// [`SealingConfig`]. The sealed counterpart of binding a
/// [`Sender`] and a [`Receiver`].
///
/// # Errors
/// [`SealError::Io`] from the bind or from cloning the socket.
pub fn bind_sealed_pair<A: ToSocketAddrs>(
    local_addr: A,
    key: NodeKey,
    allowlist: Allowlist,
) -> Result<(Sender, Receiver), SealError> {
    bind_sealed_pair_with(local_addr, key, allowlist, SealingConfig::default())
}

/// [`bind_sealed_pair`] with `config`.
///
/// # Errors
/// As [`bind_sealed_pair`].
pub fn bind_sealed_pair_with<A: ToSocketAddrs>(
    local_addr: A,
    key: NodeKey,
    allowlist: Allowlist,
    config: SealingConfig,
) -> Result<(Sender, Receiver), SealError> {
    let socket = UdpSocket::bind(local_addr)?;
    let sealing = Sealing::new(&socket, key, allowlist, config)?;
    let sender = Sender::from_socket(socket.try_clone()?).with_sealing(sealing.clone());
    let receiver = Receiver::from_socket(socket).with_sealing(sealing);
    Ok((sender, receiver))
}

/// The receiver half has a receive in progress while one of these lives.
pub(crate) struct Reading(Arc<Inner>);

impl Drop for Reading {
    fn drop(&mut self) {
        self.0.last_read.store(now(), Ordering::Relaxed);
        self.0.reading.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Sealing {
    /// A sealing for the node whose socket is `socket` (cloned here, for
    /// handshake messages), with key `key`, admitting `allowlist`.
    ///
    /// # Errors
    /// [`SealError::Io`] from cloning the socket.
    pub fn new(
        socket: &UdpSocket,
        key: NodeKey,
        allowlist: Allowlist,
        config: SealingConfig,
    ) -> Result<Self, SealError> {
        Self::build(Some(socket.try_clone()?), key, allowlist, config)
    }

    /// A sealing with no socket: what it would send is kept for
    /// [`Self::take_outgoing`]. For the fuzz harness and the tests.
    ///
    /// # Errors
    /// None in practice: the Noise parameters are a constant.
    #[doc(hidden)]
    pub fn detached(
        key: NodeKey,
        allowlist: Allowlist,
        config: SealingConfig,
    ) -> Result<Self, SealError> {
        Self::build(None, key, allowlist, config)
    }

    fn build(
        socket: Option<UdpSocket>,
        key: NodeKey,
        allowlist: Allowlist,
        config: SealingConfig,
    ) -> Result<Self, SealError> {
        Ok(Self {
            inner: Arc::new(Inner {
                socket,
                outbox: Mutex::new(Vec::new()),
                key,
                params: noise_params()?,
                allowlist: RwLock::new(allowlist),
                config,
                table: Mutex::new(Table::default()),
                changed: Condvar::new(),
                counts: Counters::default(),
                stash: Mutex::new(VecDeque::new()),
                stashed: AtomicUsize::new(0),
                pending: AtomicUsize::new(0),
                reading: AtomicUsize::new(0),
                last_read: AtomicU64::new(0),
                next_maintain: AtomicU64::new(0),
                data_session: AtomicU32::new(0),
            }),
        })
    }

    /// The node's public key.
    pub fn public_key(&self) -> PublicKey {
        self.inner.key.public
    }

    /// The configuration it runs with.
    pub fn config(&self) -> &SealingConfig {
        &self.inner.config
    }

    /// A copy of the allowlist.
    pub fn allowlist(&self) -> Allowlist {
        self.inner.allowlist.read().clone()
    }

    /// Replace the allowlist. Every session and handshake of a peer that is
    /// no longer on it is dropped at once.
    pub fn set_allowlist(&self, allowlist: Allowlist) {
        *self.inner.allowlist.write() = allowlist.clone();
        let mut table = self.inner.table.lock();
        let gone: Vec<PublicKey> = table
            .peers
            .keys()
            .filter(|peer| !allowlist.contains(peer))
            .copied()
            .collect();
        for peer in gone {
            self.drop_peer(&mut table, &peer);
        }
        self.inner
            .pending
            .store(table.pending.len(), Ordering::Relaxed);
    }

    /// What it has sealed, opened and refused so far.
    pub fn counts(&self) -> SealCounts {
        self.inner.counts.snapshot()
    }

    /// Whether a session to `peer` is in use: datagrams to it can be
    /// sealed.
    pub fn has_session(&self, peer: &PublicKey) -> bool {
        self.inner.table.lock().current_of(peer).is_some()
    }

    /// Establish a session to the node whose key is `peer`, at `peer_addr`,
    /// from this node's socket, and send to `peer_addr` with it from then
    /// on. With a session to `peer` already in use, only the address is
    /// recorded. Otherwise an initiation goes out at once and again every
    /// second, each a fresh handshake, until the response arrives or
    /// `timeout` passes; when the peer is connecting to this node at that
    /// moment (this node has answered its initiation and awaits its first
    /// datagram), that handshake is waited for first, for up to a second or
    /// half the timeout, and discarded if this call must start its own. The response is taken by the receiver half when it
    /// is receiving; when it has not received for 50 ms, this call reads the
    /// socket itself, without waiting, keeping for the receiver what is not
    /// a handshake message (Unix only: elsewhere the receiver half must be
    /// receiving).
    ///
    /// # Errors
    /// [`SealError::NotAllowed`] when `peer` is not on the allowlist;
    /// [`SealError::HandshakeTimeout`] when no response arrived in time;
    /// [`SealError::Io`] when the socket refused an initiation;
    /// [`SealError::Crypto`] when snow or the entropy source refused.
    pub fn connect(
        &self,
        peer_addr: SocketAddr,
        peer: &PublicKey,
        timeout: Duration,
    ) -> Result<(), SealError> {
        if !self.inner.allowlist.read().contains(peer) {
            return Err(SealError::NotAllowed(*peer));
        }
        {
            let mut table = self.inner.table.lock();
            table.map_address(peer_addr, *peer, true);
            table.peers.entry(*peer).or_default().addr = Some(peer_addr);
            if table.current_of(peer).is_some() {
                return Ok(());
            }
        }
        let start = Instant::now();
        let deadline = start + timeout;
        let mut resend = start;
        // Whether the peer's own handshake, under way when this call began,
        // has had its turn.
        let mut deferred = false;
        loop {
            let at = Instant::now();
            if at >= resend {
                // The peer connecting to this node at this moment gets one
                // resend interval (or half the timeout) to finish first;
                // after that this node's handshake discards it.
                let sent = (deferred || !self.peer_connecting(peer))
                    && self.initiate_with(peer, peer_addr, deferred)?;
                resend = if sent {
                    at + CONNECT_RESEND
                } else {
                    deferred = true;
                    at + CONNECT_RESEND.min(timeout / 2)
                };
            }
            self.pump();
            let mut table = self.inner.table.lock();
            if table.current_of(peer).is_some() {
                return Ok(());
            }
            let at = Instant::now();
            if at >= deadline {
                return Err(SealError::HandshakeTimeout {
                    addr: peer_addr,
                    timeout,
                });
            }
            let wait = deadline
                .min(resend)
                .saturating_duration_since(at)
                .min(CONNECT_POLL);
            self.inner.changed.wait_for(&mut table, wait);
            if table.current_of(peer).is_some() {
                return Ok(());
            }
        }
    }

    /// Whether this node answered an initiation from `peer` that the peer
    /// has not yet confirmed, within the handshake retry period: the peer is
    /// connecting, and a handshake of this node's would only race it.
    fn peer_connecting(&self, peer: &PublicKey) -> bool {
        let retry = nanos(self.inner.config.handshake_retry());
        let table = self.inner.table.lock();
        let answered = table.peers.get(peer).and_then(|p| p.next.as_ref());
        answered.is_some_and(|n| now().saturating_sub(n.at) < retry)
    }

    /// Send an initiation to `peer` at `addr`, replacing any in flight, and
    /// send to `addr` with `peer`'s sessions. Its response, when it comes,
    /// installs the session. An initiation of the peer's that this node
    /// answered and the peer has not confirmed is discarded first.
    ///
    /// # Errors
    /// As [`Self::connect`], but for the timeout.
    #[doc(hidden)]
    pub fn initiate(&self, peer: &PublicKey, addr: SocketAddr) -> Result<(), SealError> {
        self.initiate_with(peer, addr, true).map(drop)
    }

    /// [`Self::initiate`]; with `discard_answered` false, an unconfirmed
    /// initiation of the peer's that this node answered, younger than the
    /// handshake retry period, makes this one stand down instead (false,
    /// nothing sent), since that handshake is already under way. Decided
    /// under the table lock, against `on_initiation`, so that two nodes never
    /// finish two handshakes with each other at once: a node never installs
    /// both a session it answered and one it initiated while the two were
    /// both in flight.
    fn initiate_with(
        &self,
        peer: &PublicKey,
        addr: SocketAddr,
        discard_answered: bool,
    ) -> Result<bool, SealError> {
        if !self.inner.allowlist.read().contains(peer) {
            return Err(SealError::NotAllowed(*peer));
        }
        let retry = nanos(self.inner.config.handshake_retry());
        loop {
            let index = random_index()?;
            let mut hs = snow::Builder::new(self.inner.params.clone())
                .prologue(PROLOGUE)
                .local_private_key(&self.inner.key.secret[..])
                .remote_public_key(peer.as_bytes())
                .build_initiator()
                .map_err(crypto_error)?;
            let mut message = Vec::with_capacity(INITIATION_BYTES);
            put_header(&mut message, KIND_INITIATION);
            message.extend_from_slice(&index.to_le_bytes());
            let start = message.len();
            message.resize(INITIATION_BYTES, 0);
            let n = hs
                .write_message(&index.to_le_bytes(), &mut message[start..])
                .map_err(crypto_error)?;
            message.truncate(start + n);

            let mut table = self.inner.table.lock();
            let t = &mut *table;
            if t.index_in_use(index) {
                continue;
            }
            let answered = t.peers.get(peer).and_then(|p| p.next.as_ref());
            if let Some(answered) = answered {
                let young = now().saturating_sub(answered.at) < retry;
                if young && !discard_answered {
                    return Ok(false);
                }
                let index = answered.index;
                if let Some(state) = t.peers.get_mut(peer) {
                    state.next = None;
                }
                self.remove_session(t, index);
            }
            t.map_address(addr, *peer, true);
            let state = t.peers.entry(*peer).or_default();
            state.addr = Some(addr);
            if let Some(old) = state.pending.replace(index) {
                t.pending.remove(&old);
            }
            t.pending.insert(
                index,
                Pending {
                    peer: *peer,
                    hs,
                    addr,
                    sent_at: now(),
                },
            );
            self.inner.pending.store(t.pending.len(), Ordering::Relaxed);
            drop(table);
            self.transmit(message, addr).map_err(SealError::Io)?;
            return Ok(true);
        }
    }

    /// What a detached sealing would have sent, oldest first, as
    /// `(datagram, destination)`.
    #[doc(hidden)]
    pub fn take_outgoing(&self) -> Vec<(Vec<u8>, SocketAddr)> {
        std::mem::take(&mut *self.inner.outbox.lock())
    }

    fn transmit(&self, datagram: Vec<u8>, to: SocketAddr) -> std::io::Result<()> {
        match &self.inner.socket {
            Some(socket) => {
                let sent = retry_interrupted(|| socket.send_to(&datagram, to));
                if let Err(e) = &sent {
                    if let Some(n) = count_error(&self.inner.counts.transmit_errors) {
                        tracing::warn!(error = %e, %to, errors = n, "handshake message not sent");
                    }
                }
                sent.map(|_| ())
            }
            None => {
                self.inner.outbox.lock().push((datagram, to));
                Ok(())
            }
        }
    }

    /// Take a datagram the receiver half read from `src`, its first `len`
    /// bytes in `buf`: open a sealed one, answer or complete a handshake,
    /// admit or refuse plaintext. Public only for the fuzz harness and the
    /// tests; the receiver calls it on every datagram.
    #[doc(hidden)]
    pub fn open(&self, buf: &mut [u8], len: usize, src: SocketAddr) -> Opened {
        self.open_sealed_by(buf, len, src).0
    }

    /// [`Self::open`], and the public key of the peer whose session opened
    /// the datagram: `Some` exactly when it was sealed and is
    /// [`Opened::Inner`], `None` for plaintext admitted from loopback and
    /// for what is consumed. The receiver reports it in
    /// [`RecvMeta::sealed_by`](crate::RecvMeta::sealed_by), so that a caller
    /// knows a datagram's sender by its key and not by its source address,
    /// which a peer can forge.
    pub(crate) fn open_sealed_by(
        &self,
        buf: &mut [u8],
        len: usize,
        src: SocketAddr,
    ) -> (Opened, Option<PublicKey>) {
        let mut sealed_by = None;
        let opened = self.open_from(buf, len, src, true, &mut sealed_by);
        (opened, sealed_by)
    }

    /// [`Self::open`] for the sender's feedback thread: the same, without
    /// taking the session as the one the receiver's feedback follows.
    pub(crate) fn open_feedback(&self, buf: &mut [u8], len: usize, src: SocketAddr) -> Opened {
        self.open_from(buf, len, src, false, &mut None)
    }

    /// Open the datagram, setting `sealed_by` to the key of the peer whose
    /// session opened it when it was sealed and has an inner datagram.
    fn open_from(
        &self,
        buf: &mut [u8],
        len: usize,
        src: SocketAddr,
        data: bool,
        sealed_by: &mut Option<PublicKey>,
    ) -> Opened {
        let len = len.min(buf.len());
        self.maintain_if_due();
        let counts = &self.inner.counts;
        match classify(&buf[..len]) {
            Class::Plaintext => {
                if self.admits_plaintext(src) {
                    counts.plaintext_admitted.fetch_add(1, Ordering::Relaxed);
                    Opened::Inner(len)
                } else {
                    refuse(&counts.plaintext_refused, src, "plaintext datagram refused");
                    Opened::Consumed
                }
            }
            Class::Malformed => {
                refuse(&counts.malformed, src, "malformed sealed datagram");
                Opened::Consumed
            }
            Class::Initiation => {
                self.on_initiation(&buf[..len], src);
                Opened::Consumed
            }
            Class::Response => {
                self.on_response(&buf[..len], src);
                Opened::Consumed
            }
            Class::Sealed => self.unseal(buf, len, src, data, sealed_by),
        }
    }

    fn admits_plaintext(&self, src: SocketAddr) -> bool {
        self.inner.config.allow_loopback_plaintext && src.ip().to_canonical().is_loopback()
    }

    fn unseal(
        &self,
        buf: &mut [u8],
        len: usize,
        src: SocketAddr,
        data: bool,
        sealed_by: &mut Option<PublicKey>,
    ) -> Opened {
        let counts = &self.inner.counts;
        let index = read_u32(buf, 8);
        let counter = read_u64(buf, 12);
        let session = self.inner.table.lock().sessions.get(&index).cloned();
        let Some(session) = session else {
            refuse(
                &counts.unknown_session,
                src,
                "sealed datagram for no session",
            );
            return Opened::Consumed;
        };
        if counter >= REJECT_AFTER_MESSAGES {
            refuse(
                &counts.malformed,
                src,
                "sealed datagram with a spent counter",
            );
            return Opened::Consumed;
        }
        match session.window.lock().check(counter) {
            Verdict::Fresh => {}
            Verdict::Seen => {
                refuse(&counts.replayed, src, "replayed sealed datagram");
                return Opened::Consumed;
            }
            Verdict::TooOld => {
                refuse(
                    &counts.too_old,
                    src,
                    "sealed datagram older than the replay window",
                );
                return Opened::Consumed;
            }
        }
        let inner_len = len - SEALED_OVERHEAD;
        let (header, rest) = buf.split_at_mut(SEALED_HEADER_BYTES);
        let (body, tail) = rest.split_at_mut(inner_len);
        let mut tag = [0u8; TAG_BYTES];
        tag.copy_from_slice(&tail[..TAG_BYTES]);
        if session
            .open
            .decrypt_in_place_detached(&nonce(counter), &*header, body, &Tag::from(tag))
            .is_err()
        {
            refuse(
                &counts.unauthentic,
                src,
                "sealed datagram failed authentication",
            );
            return Opened::Consumed;
        }
        // Checked again: another thread may have taken the same counter
        // while this one decrypted.
        if session.window.lock().accept(counter) != Verdict::Fresh {
            refuse(&counts.replayed, src, "replayed sealed datagram");
            return Opened::Consumed;
        }
        buf.copy_within(SEALED_HEADER_BYTES..SEALED_HEADER_BYTES + inner_len, 0);
        counts.opened.fetch_add(1, Ordering::Relaxed);
        session.last_received.store(now(), Ordering::Relaxed);
        if data {
            self.inner.data_session.store(index, Ordering::Relaxed);
        }
        if !session.received_any.swap(true, Ordering::AcqRel) {
            self.first_receipt(&session, src);
        }
        if inner_len == 0 {
            Opened::Consumed
        } else {
            *sealed_by = Some(session.peer);
            Opened::Inner(inner_len)
        }
    }

    /// The first datagram on `session` arrived from `src`: on the responder
    /// it confirms the session, which becomes the one sealed with.
    fn first_receipt(&self, session: &Session, src: SocketAddr) {
        let at = now();
        let mut table = self.inner.table.lock();
        let t = &mut *table;
        let confirms = t.peers.get(&session.peer).is_some_and(|state| {
            state
                .next
                .as_ref()
                .is_some_and(|n| n.index == session.local_index)
        });
        if confirms {
            if let Some(state) = t.peers.get_mut(&session.peer) {
                state.next = None;
                // Where a rekey of the responder's own goes, should one be
                // needed (`maintain`).
                state.addr.get_or_insert(src);
            }
            t.map_address(src, session.peer, false);
            self.install(t, session.peer, session.local_index, at);
            self.inner
                .counts
                .sessions_established
                .fetch_add(1, Ordering::Relaxed);
            self.inner.changed.notify_all();
        }
        self.retire_if_carried(t, session);
    }

    /// Make `index` the session `peer`'s datagrams are sealed with, keeping
    /// the one it replaces as `previous` for the grace. The newest session
    /// wins: the handshake rules (`on_initiation`, `initiate_with`) see to it
    /// that two nodes never finish two handshakes with each other at once,
    /// so both install the same sessions in the same order.
    fn install(&self, t: &mut Table, peer: PublicKey, index: u32, at: u64) {
        let grace = nanos(self.inner.config.old_session_grace);
        let Some(state) = t.peers.get_mut(&peer) else {
            return;
        };
        let retired = match state.current.replace(index) {
            Some(cur) if cur == index => return,
            other => other,
        };
        state.current_since = at;
        let mut dropped = None;
        if let Some(retired) = retired {
            dropped = state.previous.replace(retired);
            state.previous_until = at.saturating_add(grace);
        }
        if let Some(old) = dropped.filter(|&old| old != index) {
            self.remove_session(t, old);
        }
    }

    /// Once the session in use has carried a datagram each way, the one it
    /// replaced goes.
    fn retire_if_carried(&self, t: &mut Table, session: &Session) {
        if !(session.sent_any.load(Ordering::Acquire)
            && session.received_any.load(Ordering::Acquire))
        {
            return;
        }
        let Some(state) = t.peers.get_mut(&session.peer) else {
            return;
        };
        if state.current != Some(session.local_index) {
            return;
        }
        if let Some(previous) = state.previous.take() {
            self.remove_session(t, previous);
        }
    }

    fn remove_session(&self, t: &mut Table, index: u32) {
        let Some(session) = t.sessions.remove(&index) else {
            return;
        };
        if let Some(e) = session.initiation {
            if t.answered.get(&e) == Some(&index) {
                t.answered.remove(&e);
            }
        }
        if self.inner.data_session.load(Ordering::Relaxed) == index {
            let next = t
                .peers
                .get(&session.peer)
                .and_then(|p| p.current)
                .filter(|&c| c != index)
                .unwrap_or(0);
            self.inner.data_session.store(next, Ordering::Relaxed);
        }
    }

    fn drop_peer(&self, t: &mut Table, peer: &PublicKey) {
        let Some(state) = t.peers.remove(peer) else {
            return;
        };
        for index in [state.current, state.previous, state.next.map(|n| n.index)]
            .into_iter()
            .flatten()
        {
            self.remove_session(t, index);
        }
        if let Some(pending) = state.pending {
            t.pending.remove(&pending);
        }
        t.by_addr.retain(|_, p| p != peer);
    }

    /// An initiation from `src`: answer it if its key is admitted.
    fn on_initiation(&self, msg: &[u8], src: SocketAddr) {
        let counts = &self.inner.counts;
        let initiator_index = read_u32(msg, 8);
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&msg[12..44]);
        {
            let table = self.inner.table.lock();
            if let Some(&index) = table.answered.get(&ephemeral) {
                let resend = table.sessions.get(&index).and_then(|s| {
                    table
                        .peers
                        .get(&s.peer)?
                        .next
                        .as_ref()
                        .filter(|n| n.index == index)
                        .map(|n| n.response.clone())
                });
                drop(table);
                match resend {
                    // A duplicate of one answered and not yet confirmed: the
                    // same answer again.
                    Some(response) => {
                        let _ = self.transmit(response, src);
                    }
                    None => refuse(
                        &counts.handshakes_refused,
                        src,
                        "repeat of an initiation whose session is in use",
                    ),
                }
                return;
            }
        }

        // The Diffie-Hellman work happens outside the table lock.
        let built = snow::Builder::new(self.inner.params.clone())
            .prologue(PROLOGUE)
            .local_private_key(&self.inner.key.secret[..])
            .build_responder();
        let Ok(mut hs) = built else {
            refuse(&counts.handshakes_failed, src, "handshake state not built");
            return;
        };
        let mut payload = [0u8; INITIATION_BYTES];
        match hs.read_message(&msg[12..], &mut payload) {
            Ok(4) if payload[..4] == msg[8..12] => {}
            _ => {
                refuse(&counts.handshakes_failed, src, "initiation did not decrypt");
                return;
            }
        }
        let Some(peer) = hs.get_remote_static().and_then(|k| {
            let bytes: [u8; 32] = k.try_into().ok()?;
            Some(PublicKey(bytes))
        }) else {
            refuse(
                &counts.handshakes_failed,
                src,
                "initiation carried no static key",
            );
            return;
        };
        if !self.inner.allowlist.read().admits(&peer, src) {
            refuse(
                &counts.handshakes_refused,
                src,
                "initiation from a key not on the allowlist",
            );
            return;
        }
        let Ok(index) = random_index() else {
            refuse(
                &counts.handshakes_failed,
                src,
                "no entropy for a session index",
            );
            return;
        };
        let mut response = Vec::with_capacity(RESPONSE_BYTES);
        put_header(&mut response, KIND_RESPONSE);
        response.extend_from_slice(&index.to_le_bytes());
        response.extend_from_slice(&initiator_index.to_le_bytes());
        let start = response.len();
        response.resize(RESPONSE_BYTES, 0);
        let mut indices = [0u8; 8];
        indices[..4].copy_from_slice(&index.to_le_bytes());
        indices[4..].copy_from_slice(&initiator_index.to_le_bytes());
        let n = match hs.write_message(&indices, &mut response[start..]) {
            Ok(n) if hs.is_handshake_finished() => n,
            _ => {
                refuse(&counts.handshakes_failed, src, "response not written");
                return;
            }
        };
        response.truncate(start + n);
        let keys = split(&mut hs);
        let at = now();
        let session = Arc::new(Session::new(
            index,
            initiator_index,
            peer,
            false,
            Some(ephemeral),
            &keys,
            at,
        ));

        let mut table = self.inner.table.lock();
        let t = &mut *table;
        if t.answered.contains_key(&ephemeral) {
            // A copy of the same initiation was answered meanwhile, on
            // another thread; that answer stands.
            drop(table);
            refuse(
                &counts.handshakes_refused,
                src,
                "initiation answered twice at once",
            );
            return;
        }
        if t.index_in_use(index) {
            // A collision of random indices: the initiator tries again.
            drop(table);
            refuse(
                &counts.handshakes_failed,
                src,
                "session index already in use",
            );
            return;
        }
        let ours = t.peers.get(&peer).and_then(|p| p.pending);
        if let Some(ours) = ours {
            // The initiation crossed one of this node's own. The lower key's
            // stands: that node drops the other's, and the other answers it
            // and abandons its own, so one handshake finishes, not two. Only
            // a fresh one of this node's stands: an older one drew no
            // response in a round trip (it went where the peer is not, or was
            // lost), and is abandoned for the peer's, as the higher key does.
            let window = nanos(self.inner.config.crossing_window());
            let fresh = t
                .pending
                .get(&ours)
                .is_some_and(|p| now().saturating_sub(p.sent_at) < window);
            if fresh && self.inner.key.public < peer {
                drop(table);
                refuse(
                    &counts.handshakes_refused,
                    src,
                    "initiation crossed this node's own, which stands",
                );
                return;
            }
            t.pending.remove(&ours);
            self.inner.pending.store(t.pending.len(), Ordering::Relaxed);
        }
        t.sessions.insert(index, session);
        t.answered.insert(ephemeral, index);
        let state = t.peers.entry(peer).or_default();
        state.pending = None;
        let replaced = state.next.replace(Answered {
            index,
            response: response.clone(),
            at,
        });
        if let Some(old) = replaced {
            self.remove_session(t, old.index);
        }
        drop(table);
        let _ = self.transmit(response, src);
    }

    /// A response from `src`: complete the handshake it answers.
    fn on_response(&self, msg: &[u8], src: SocketAddr) {
        let counts = &self.inner.counts;
        let responder_index = read_u32(msg, 8);
        let our_index = read_u32(msg, 12);
        let mut table = self.inner.table.lock();
        let t = &mut *table;
        let mut payload = [0u8; RESPONSE_BYTES];
        let verdict = match t.pending.get_mut(&our_index) {
            None => Err(("response to no initiation of ours", &counts.unknown_session)),
            Some(pending) => match pending.hs.read_message(&msg[16..], &mut payload) {
                Ok(8) if payload[..8] == msg[8..16] && pending.hs.is_handshake_finished() => Ok(()),
                // snow restores the handshake when a message fails to
                // decrypt, so the real response can still complete it.
                Err(_) => Err(("response did not decrypt", &counts.handshakes_failed)),
                Ok(_) => {
                    t.pending.remove(&our_index);
                    Err(("response payload does not match", &counts.handshakes_failed))
                }
            },
        };
        let pending = match verdict {
            Ok(()) => t.pending.remove(&our_index),
            Err((what, counter)) => {
                self.inner.pending.store(t.pending.len(), Ordering::Relaxed);
                drop(table);
                refuse(counter, src, what);
                return;
            }
        };
        self.inner.pending.store(t.pending.len(), Ordering::Relaxed);
        let Some(mut pending) = pending else {
            return;
        };
        let keys = split(&mut pending.hs);
        let at = now();
        let session = Arc::new(Session::new(
            our_index,
            responder_index,
            pending.peer,
            true,
            None,
            &keys,
            at,
        ));
        t.sessions.insert(our_index, Arc::clone(&session));
        let state = t.peers.entry(pending.peer).or_default();
        if state.pending == Some(our_index) {
            state.pending = None;
        }
        self.install(t, pending.peer, our_index, at);
        counts.sessions_established.fetch_add(1, Ordering::Relaxed);
        self.inner.changed.notify_all();
        drop(table);
        // Key confirmation: the responder seals with the session once a
        // datagram arrives on it, so one goes now.
        let mut keepalive = Vec::with_capacity(SEALED_OVERHEAD);
        if self.seal_with(&session, &[], &mut keepalive).is_ok() {
            let _ = self.transmit(keepalive, pending.addr);
        }
    }

    /// Seal `inner` for the peer at `dest` into `out`, which is cleared
    /// first. Public only for the tests and the fuzz harness; the sender
    /// calls it on every datagram.
    ///
    /// # Errors
    /// [`SealError::NoSession`] when no session to `dest` is in use, or its
    /// counter is spent.
    #[doc(hidden)]
    pub fn seal_to(
        &self,
        dest: SocketAddr,
        inner: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SealError> {
        self.maintain_if_due();
        let session = {
            let table = self.inner.table.lock();
            table
                .by_addr
                .get(&dest)
                .and_then(|peer| table.current_of(peer))
        };
        let sealed = session.is_some_and(|s| self.seal_with(&s, inner, out).is_ok());
        if sealed {
            Ok(())
        } else {
            refuse(
                &self.inner.counts.no_session,
                dest,
                "datagram with no session to seal under",
            );
            Err(SealError::NoSession(dest))
        }
    }

    /// Whether a datagram to `dest` can be sealed now: a session to the peer
    /// at that address is established and in use. [`Self::has_session`] asks
    /// the same of a peer's key, whatever its address; the two differ while a
    /// peer that moved, or restarted on a new socket, has a new session still
    /// unconfirmed beside the one at its old address. A node that answered a
    /// handshake can seal to the initiator once the initiator's first
    /// datagram, the keepalive [`Self::connect`] sends, has been received.
    pub fn can_seal_to(&self, dest: SocketAddr) -> bool {
        let table = self.inner.table.lock();
        table
            .by_addr
            .get(&dest)
            .is_some_and(|peer| table.current_of(peer).is_some())
    }

    /// Seal a feedback datagram for the peer whose data the receiver half
    /// last took, into `out`; false, counted, when there is none yet.
    pub(crate) fn seal_feedback(&self, inner: &[u8], out: &mut Vec<u8>) -> bool {
        self.maintain_if_due();
        let index = self.inner.data_session.load(Ordering::Relaxed);
        let session = {
            let table = self.inner.table.lock();
            table
                .sessions
                .get(&index)
                .and_then(|s| table.current_of(&s.peer))
        };
        if session.is_some_and(|s| self.seal_with(&s, inner, out).is_ok()) {
            return true;
        }
        self.inner.counts.no_session.fetch_add(1, Ordering::Relaxed);
        false
    }

    fn seal_with(&self, session: &Session, inner: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
        let counter = session.counter.fetch_add(1, Ordering::Relaxed);
        if counter >= REJECT_AFTER_MESSAGES {
            // Spent: the counter stays put, so it can never wrap.
            session
                .counter
                .store(REJECT_AFTER_MESSAGES, Ordering::Relaxed);
            return Err(());
        }
        out.clear();
        out.reserve(inner.len() + SEALED_OVERHEAD);
        put_header(out, KIND_SEALED);
        out.extend_from_slice(&session.remote_index.to_le_bytes());
        out.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(inner);
        let (header, body) = out.split_at_mut(SEALED_HEADER_BYTES);
        let tag = session
            .seal
            .encrypt_in_place_detached(&nonce(counter), &*header, body)
            .map_err(drop)?;
        out.extend_from_slice(&tag);
        self.inner.counts.sealed.fetch_add(1, Ordering::Relaxed);
        session.last_sent.store(now(), Ordering::Relaxed);
        if !session.sent_any.swap(true, Ordering::AcqRel)
            && session.received_any.load(Ordering::Acquire)
        {
            let mut table = self.inner.table.lock();
            self.retire_if_carried(&mut table, session);
        }
        Ok(())
    }

    /// Run the session timers if they are due: at most every 100 ms, or a
    /// quarter of the rekey period if that is shorter.
    fn maintain_if_due(&self) {
        let at = now();
        let due = self.inner.next_maintain.load(Ordering::Relaxed);
        if at < due {
            return;
        }
        let next = at.saturating_add(nanos(self.inner.config.maintain_every()));
        if self
            .inner
            .next_maintain
            .compare_exchange(due, next, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            self.maintain(at);
        }
    }

    /// Retire replaced sessions past their grace, drop idle peers and
    /// unanswered initiations, and start the rekeys that are due.
    fn maintain(&self, at: u64) {
        let config = &self.inner.config;
        let rekey_after = nanos(config.rekey_period());
        let idle = rekey_after.saturating_mul(u64::from(IDLE_REKEY_PERIODS));
        let retry = nanos(config.handshake_retry());
        let grace = nanos(config.old_session_grace);
        let mut rekeys = Vec::new();
        {
            let mut table = self.inner.table.lock();
            let t = &mut *table;
            let peers: Vec<PublicKey> = t.peers.keys().copied().collect();
            for peer in peers {
                let Some(state) = t.peers.get_mut(&peer) else {
                    continue;
                };
                let expired = state.previous.filter(|_| at >= state.previous_until);
                if expired.is_some() {
                    state.previous = None;
                }
                let stale = state.pending.filter(|p| {
                    t.pending
                        .get(p)
                        .is_none_or(|x| at.saturating_sub(x.sent_at) >= retry)
                });
                if stale.is_some() {
                    state.pending = None;
                }
                if let Some(index) = expired {
                    self.remove_session(t, index);
                }
                if let Some(index) = stale {
                    t.pending.remove(&index);
                }
                let Some(state) = t.peers.get(&peer) else {
                    continue;
                };
                let sessions: Vec<Arc<Session>> = [
                    state.current,
                    state.previous,
                    state.next.as_ref().map(|n| n.index),
                ]
                .into_iter()
                .flatten()
                .filter_map(|i| t.sessions.get(&i).cloned())
                .collect();
                let pending_at = state
                    .pending
                    .and_then(|p| t.pending.get(&p))
                    .map(|p| p.sent_at);
                let last = sessions
                    .iter()
                    .map(|s| s.last_active())
                    .chain(pending_at)
                    .max();
                if last.is_none_or(|last| at.saturating_sub(last) >= idle) {
                    self.drop_peer(t, &peer);
                    continue;
                }
                let current = state.current.and_then(|i| t.sessions.get(&i));
                let peer_connecting = state
                    .next
                    .as_ref()
                    .is_some_and(|n| at.saturating_sub(n.at) < retry);
                if let (Some(current), None, Some(addr), false) =
                    (current, state.pending, state.addr, peer_connecting)
                {
                    // The initiator rekeys; the responder only once the
                    // initiator is a grace period late, as a backstop.
                    let period = if current.we_initiated {
                        rekey_after
                    } else {
                        rekey_after.saturating_add(grace)
                    };
                    let due = at.saturating_sub(current.created) >= period
                        || current.counter.load(Ordering::Relaxed) >= REKEY_AFTER_MESSAGES;
                    if due {
                        rekeys.push((peer, addr));
                    }
                }
            }
            self.inner.pending.store(t.pending.len(), Ordering::Relaxed);
        }
        for (peer, addr) in rekeys {
            if let Err(e) = self.initiate_with(&peer, addr, false) {
                tracing::warn!(error = %e, %peer, "rekey initiation not sent");
            }
        }
    }

    /// The receiver half starts a receive; it lasts while the guard lives.
    pub(crate) fn reading(&self) -> Reading {
        self.inner.reading.fetch_add(1, Ordering::AcqRel);
        self.inner.last_read.store(now(), Ordering::Relaxed);
        Reading(Arc::clone(&self.inner))
    }

    fn receiver_active(&self) -> bool {
        if self.inner.reading.load(Ordering::Acquire) > 0 {
            return true;
        }
        let last = self.inner.last_read.load(Ordering::Relaxed);
        last != 0 && now().saturating_sub(last) < nanos(RECEIVER_IDLE)
    }

    /// Before a send: while a handshake of this node's is in flight, read
    /// the socket for its response if the receiver half is not receiving.
    pub(crate) fn pump_if_pending(&self) {
        if self.inner.pending.load(Ordering::Relaxed) > 0 {
            self.pump();
        }
    }

    /// Read what the socket holds, without waiting, when the receiver half
    /// is not receiving: handshake messages are taken here, sealed datagrams
    /// and admitted plaintext kept for the receiver, the rest refused.
    #[cfg(unix)]
    fn pump(&self) {
        let Some(socket) = &self.inner.socket else {
            return;
        };
        if self.receiver_active() {
            return;
        }
        let mut buf = [0u8; MTU_BYTES];
        loop {
            let Ok((n, src)) =
                crate::receiver::recv_with_flags(socket, &mut buf, libc::MSG_DONTWAIT)
            else {
                return;
            };
            let Some(src) = src else {
                continue;
            };
            match classify(&buf[..n]) {
                Class::Sealed => self.stash(&buf[..n], src),
                Class::Plaintext if self.admits_plaintext(src) => self.stash(&buf[..n], src),
                _ => {
                    self.open_from(&mut buf, n, src, true, &mut None);
                }
            }
        }
    }

    /// Without a per-call non-blocking read, nothing but the receiver half
    /// reads the socket.
    #[cfg(not(unix))]
    fn pump(&self) {}

    fn stash(&self, datagram: &[u8], src: SocketAddr) {
        let mut stash = self.inner.stash.lock();
        if stash.len() >= STASH_CAPACITY {
            refuse(
                &self.inner.counts.stash_dropped,
                src,
                "no room to keep a datagram for the receiver",
            );
            return;
        }
        stash.push_back(Stashed {
            datagram: datagram.to_vec(),
            src,
        });
        self.inner.stashed.store(stash.len(), Ordering::Release);
    }

    /// Whether datagrams wait for the receiver half.
    pub(crate) fn has_stashed(&self) -> bool {
        self.inner.stashed.load(Ordering::Acquire) > 0
    }

    /// The oldest datagram kept for the receiver half, copied into `buf`
    /// (one MTU long), with its source.
    pub(crate) fn take_stashed(&self, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
        if !self.has_stashed() {
            return None;
        }
        let mut stash = self.inner.stash.lock();
        let found = stash.pop_front();
        self.inner.stashed.store(stash.len(), Ordering::Release);
        drop(stash);
        let found = found?;
        let n = found.datagram.len().min(buf.len());
        buf[..n].copy_from_slice(&found.datagram[..n]);
        Some((n, found.src))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn the_layout_constants_add_up() {
        assert_eq!(SEALED_HEADER_BYTES, 20);
        assert_eq!(SEALED_OVERHEAD, 36);
        assert_eq!(SEALED_INNER_BUDGET, 1436);
        assert_eq!(SEALED_MAX_ENVELOPE, 1279);
        assert_eq!(SEALED_FEC_MAX_ENVELOPE, 1261);
        assert_eq!(INITIATION_BYTES, 112);
        assert_eq!(RESPONSE_BYTES, 72);
        // A sealed parity datagram of the largest frame fits one MTU.
        let frame = crate::wire::datagram_size(SEALED_FEC_MAX_ENVELOPE);
        assert_eq!(crate::FEC_HEADER_BYTES + frame + SEALED_OVERHEAD, MTU_BYTES);
    }

    #[test]
    fn the_window_takes_each_counter_once_and_slides() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.accept(0), Verdict::Fresh);
        assert_eq!(w.accept(0), Verdict::Seen);
        assert_eq!(w.accept(5), Verdict::Fresh);
        // Within the window, out of order.
        assert_eq!(w.accept(3), Verdict::Fresh);
        assert_eq!(w.accept(3), Verdict::Seen);
        assert_eq!(w.check(4), Verdict::Fresh);
        // Slide: the highest is 5 + 2048, so 5 is the oldest still tracked.
        assert_eq!(w.accept(5 + REPLAY_WINDOW), Verdict::Fresh);
        assert_eq!(w.check(5), Verdict::TooOld);
        assert_eq!(w.check(6), Verdict::Fresh);
        assert_eq!(w.accept(6), Verdict::Fresh);
        assert_eq!(w.accept(6), Verdict::Seen);
        // A jump past the whole window clears it.
        let far = 10 * REPLAY_WINDOW;
        assert_eq!(w.accept(far), Verdict::Fresh);
        // The window is the highest and the 2,047 below it.
        assert_eq!(w.check(far - REPLAY_WINDOW + 1), Verdict::Fresh);
        assert_eq!(w.check(far - REPLAY_WINDOW), Verdict::TooOld);
        assert_eq!(w.accept(far - 1), Verdict::Fresh);
        assert_eq!(w.accept(far), Verdict::Seen);
    }

    #[test]
    fn keys_print_and_parse_as_hex() {
        let key = NodeKey::generate().unwrap();
        let public = key.public_key();
        let text = public.to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<PublicKey>().unwrap(), public);
        assert!("abc".parse::<PublicKey>().is_err());
        assert!("zz".repeat(32).parse::<PublicKey>().is_err());
        // The secret never prints.
        let shown = format!("{key:?}");
        assert!(shown.contains(&text) && !shown.contains(&hex::encode(&key.secret[..])));
        // The public half derives from the secret.
        let again = NodeKey::from_secret_bytes(&key.secret).unwrap();
        assert_eq!(again.public_key(), public);
    }

    #[test]
    fn only_the_sealed_family_is_classified_as_sealed() {
        let mut d = Vec::new();
        put_header(&mut d, KIND_SEALED);
        d.resize(SEALED_OVERHEAD, 0);
        assert_eq!(classify(&d), Class::Sealed);
        d[6] = 1;
        assert_eq!(classify(&d), Class::Malformed);
        d[6] = 0;
        d[5] = 9;
        assert_eq!(classify(&d), Class::Malformed);
        d[5] = KIND_INITIATION;
        assert_eq!(
            classify(&d),
            Class::Malformed,
            "an initiation has one length"
        );
        d[4] = crate::wire::VERSION;
        assert_eq!(classify(&d), Class::Plaintext);
        assert_eq!(classify(&[]), Class::Plaintext);
    }
}
