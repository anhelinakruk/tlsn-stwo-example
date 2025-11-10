use serde::{Deserialize, Serialize};
use tlsn::transcript::{
    hash::{PlaintextHash, PlaintextHashSecret},
    Direction, TranscriptCommitment, TranscriptSecret,
};

/// Bundle containing the Fibonacci ZK proof and public outputs
#[derive(Serialize, Deserialize, Debug)]
pub struct FibonacciZKProofBundle {
    /// Serialized STARK proof
    pub proof: Vec<u8>,
    /// Public output: the computed Fibonacci value
    pub fibonacci_value: u32,
    /// Log size of the proof (determines trace size)
    pub log_size: u32,
    // Note: fibonacci_index is NOT included - it remains private!
}

/// Extract hash commitments for received data from transcript commitments
pub fn received_commitments(
    transcript_commitments: &[TranscriptCommitment],
) -> Vec<&PlaintextHash> {
    transcript_commitments
        .iter()
        .filter_map(|commitment| match commitment {
            TranscriptCommitment::Hash(hash) if hash.direction == Direction::Received => Some(hash),
            _ => None,
        })
        .collect()
}

/// Extract hash secrets (blinders) for received data from transcript secrets
pub fn received_secrets(transcript_secrets: &[TranscriptSecret]) -> Vec<&PlaintextHashSecret> {
    transcript_secrets
        .iter()
        .filter_map(|secret| match secret {
            TranscriptSecret::Hash(secret) if secret.direction == Direction::Received => {
                Some(secret)
            }
            _ => None,
        })
        .collect()
}
