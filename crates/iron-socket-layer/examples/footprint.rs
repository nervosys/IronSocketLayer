//! Report inline storage on this host. Owned buffers and Arc allocations are
//! excluded; these values are not peak heap use or an embedded RAM budget.
use iron_socket_layer::{config, quic::QuicConnection, report::SessionReport, Connection};

fn main() {
    for (name, bytes) in [
        ("Connection", core::mem::size_of::<Connection>()),
        ("QuicConnection", core::mem::size_of::<QuicConnection>()),
        ("ClientConfig", core::mem::size_of::<config::ClientConfig>()),
        ("ServerConfig", core::mem::size_of::<config::ServerConfig>()),
        ("SessionReport", core::mem::size_of::<SessionReport>()),
    ] {
        println!("{name}: {bytes} inline bytes");
    }
}
