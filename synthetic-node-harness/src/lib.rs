//! Disposable wire-level node simulator. Never linked into the API executable.
#![cfg(feature = "synthetic-dev")]

#[path = "bitcoin.rs"]
mod bitcoin_rpc;
mod grpc;
pub use bitcoin_rpc::{BitcoinFault, BitcoinHarness, BitcoinScenario};
mod scenario;
mod server;

pub use scenario::{Fault, Scenario, PEER, POINT, TXID};
pub use server::Harness;

#[cfg(test)]
mod tests;
