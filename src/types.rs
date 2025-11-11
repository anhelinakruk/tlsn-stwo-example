use serde::{Deserialize, Serialize};
use tlsn::transcript::{
    hash::{PlaintextHash, PlaintextHashSecret},
    Direction, TranscriptCommitment, TranscriptSecret,
};

/// Bundle containing the Multi-Fibonacci ZK proof with scheduler
#[derive(Serialize, Deserialize, Debug)]
pub struct MultiFibZKProofBundle {
    /// Serialized STARK proof
    pub proof: Vec<u8>,
    /// Target element for first computing component
    pub target_element_computing1: usize,
    /// Target element for second computing component
    pub target_element_computing2: usize,
    /// Serialized MultiFibStatement0 (log_size)
    pub statement0: Vec<u8>,
    /// Serialized MultiFibStatement1 (claimed sums)
    pub statement1: Vec<u8>,
    // Note: actual fibonacci indices remain private!
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
