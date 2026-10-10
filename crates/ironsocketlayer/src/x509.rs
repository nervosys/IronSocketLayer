//! X.509 certificates: IronPKI's, under this crate's name.
//!
//! Until 0.4.0 this module held the certificate code itself. That code is
//! now [IronPKI](https://github.com/nervosys/IronPKI), which this module
//! re-exports whole, so `ironsocketlayer::x509::RootStore` is
//! `ironpki::x509::RootStore`. What a handshake adds to it (which
//! algorithms a profile allows on a chain, the bounds a peer's chain is
//! held to, the alert an error becomes) is in [`crate::policy`] and
//! [`crate::error`].

pub use ironpki::sign::VERIFY_ALGORITHMS;
pub use ironpki::x509::*;
pub use ironpki::{Limits, Purpose, TrustAnchor};
