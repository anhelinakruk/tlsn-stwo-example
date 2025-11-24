#![feature(portable_simd)]
#![feature(array_chunks)]
#![feature(iter_array_chunks)]

pub mod multi_fib;
pub mod prover;
pub mod simple_fib;
pub mod types;
pub mod verifier;
pub mod blake;

pub use prover::prover;
pub use types::{received_commitments, received_secrets, MultiFibZKProofBundle};
pub use verifier::verifier;

// Re-export test server for examples
pub use crate::test_server::start_tls_server as start_test_server;

// Test server module (from bin/test_server.rs)
#[path = "bin/test_server.rs"]
mod test_server;
