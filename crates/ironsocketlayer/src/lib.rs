//! IronSocketLayer: agentic-first TLS 1.3 and QUIC-TLS over IronCrypto.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

extern crate alloc;

pub mod client;
pub mod codec;
pub mod config;
pub mod conn;
pub mod crypto;
pub mod ech;
pub mod enums;
pub mod error;
pub mod fixed;
pub mod key_schedule;
pub mod msgs;
pub mod policy;
pub mod quic;
pub mod record;
pub mod report;
pub mod resumption;
pub mod server;
#[cfg(feature = "std")]
pub mod stream;
mod wipe;
pub mod x509;

pub use conn::{Connection, Level};
pub use error::{Error, ErrorKind, Recovery, Result};
