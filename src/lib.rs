#![feature(portable_simd)]
#![feature(array_chunks)]
#![feature(iter_array_chunks)]

pub mod multi_fib;
pub mod prover;
pub mod simple_fib;
pub mod types;
pub mod verifier;
pub mod blake;
// pub mod bridge;

pub use prover::prover;
pub use types::{received_commitments, received_secrets, MultiFibZKProofBundle};
pub use verifier::verifier;
// pub use bridge::IndexRelation;
use stwo_constraint_framework::relation;

// Re-export test server for examples
pub use crate::test_server::start_tls_server as start_test_server;

relation!(IndexRelation, 1);

// Test server module (from bin/test_server.rs)
#[path = "bin/test_server.rs"]
mod test_server;
