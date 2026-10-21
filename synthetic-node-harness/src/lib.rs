//! Disposable wire-level node simulator. Never linked into the API executable.
#![cfg(feature = "synthetic-dev")]

mod grpc;
mod scenario;
mod server;

pub use scenario::{Fault, Scenario, PEER, POINT, TXID};
pub use server::Harness;

#[cfg(test)]
mod tests;
