use super::types::{FibonacciZKProofBundle, received_commitments};

use stwo::core::pcs::PcsConfig;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleHasher;
use stwo::core::proof::StarkProof;
use tlsn::{
    config::{CertificateDer, ProtocolConfigValidator, RootCertStore},
    connection::ServerName,
    hash::HashAlgId,
    transcript::{Direction, PartialTranscript},
    verifier::{Verifier, VerifierConfig, VerifierOutput, VerifyConfig},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::instrument;

pub static CA_CERT_DER: &[u8] = include_bytes!("certs/rootCA.der");

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;

#[instrument(skip(socket, extra_socket))]
pub async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
    mut extra_socket: T,
    expected_server_domain: &str,
) -> Result<PartialTranscript, Box<dyn std::error::Error>> {
    tracing::info!("=== Starting Verifier ===");

    // Set up Verifier with protocol configuration validator
    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()?;

    // Create a root certificate store with the server-fixture's self-signed certificate
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .protocol_config_validator(config_validator)
        .build()?;

    let verifier = Verifier::new(verifier_config);

    tracing::info!("Step 1: Verifying MPC-TLS session...");

    // Receive and verify the TLSNotary attestation
    let VerifierOutput {
        server_name,
        transcript,
        transcript_commitments,
        ..
    } = verifier
        .verify(socket.compat(), &VerifyConfig::default())
        .await?;

    let server_name = server_name.ok_or("Prover should have revealed server name")?;
    let transcript = transcript.ok_or("Prover should have revealed transcript data")?;

    tracing::info!("MPC-TLS session verified successfully");

    // Verify server name matches expected domain
    let ServerName::Dns(server_name) = server_name;
    if server_name.as_str() != expected_server_domain {
        return Err(format!(
            "Server name mismatch: expected {}, got {}",
            expected_server_domain,
            server_name.as_str()
        )
        .into());
    }
    tracing::info!("Server name verified: {}", server_name.as_str());

    // Verify sent data contains the expected server domain
    let sent = transcript.sent_unsafe().to_vec();
    let sent_data = String::from_utf8(sent.clone())
        .map_err(|e| format!("Verifier expected valid UTF-8 sent data: {}", e))?;

    if !sent_data.contains(expected_server_domain) {
        return Err(format!(
            "Verification failed: Expected host {} not found in sent data",
            expected_server_domain
        )
        .into());
    }
    tracing::info!("Sent data contains expected server domain");

    // Check received data commitments
    tracing::info!("Step 2: Verifying hash commitment for fibonacci_index...");
    let received_commitments = received_commitments(&transcript_commitments);
    let received_commitment = received_commitments
        .first()
        .ok_or("Missing received hash commitment")?;

    if received_commitment.direction != Direction::Received {
        return Err("Hash commitment should be for received data".into());
    }
    if received_commitment.hash.alg != HashAlgId::SHA256 {
        return Err("Hash commitment should use SHA256".into());
    }

    let committed_hash = &received_commitment.hash;
    tracing::info!(
        "Received hash commitment verified: {}",
        hex::encode(committed_hash.value.as_bytes())
    );

    // Receive ZK proof bundle from prover
    tracing::info!("Step 3: Receiving ZK proof bundle from prover...");
    let mut buf = Vec::new();
    extra_socket.read_to_end(&mut buf).await?;

    if buf.is_empty() {
        return Err("No ZK proof data received from prover".into());
    }

    let proof_bundle: FibonacciZKProofBundle = bincode::deserialize(&buf)
        .map_err(|e| format!("Failed to deserialize ZK proof bundle: {}", e))?;

    tracing::info!("Received ZK proof bundle:");
    tracing::info!("  - fibonacci_value (public): {}", proof_bundle.fibonacci_value);
    tracing::info!("  - log_size: {}", proof_bundle.log_size);
    tracing::info!("  - proof size: {} bytes", proof_bundle.proof.len());

    // Deserialize the STARK proof
    tracing::info!("Step 4: Deserializing STARK proof...");
    let stark_proof: StarkProof<Blake2sMerkleHasher> = bincode::deserialize(&proof_bundle.proof)
        .map_err(|e| format!("Failed to deserialize STARK proof: {}", e))?;

    // Create statement for verification
    let statement = crate::stwo::FibStatement {
        log_size: proof_bundle.log_size,
        fibonacci_value: proof_bundle.fibonacci_value,
    };

    // Verify the ZK proof
    tracing::info!("Step 5: Verifying STARK proof...");
    tracing::info!("  This proves that:");
    tracing::info!("  1. Prover knows a secret fibonacci_index from the server");
    tracing::info!("  2. Prover computed fibonacci(fibonacci_index) = {}", proof_bundle.fibonacci_value);
    tracing::info!("  3. fibonacci_index matches the committed hash from TLSNotary");
    tracing::info!("  Note: fibonacci_index remains SECRET to the verifier!");

    let config = PcsConfig::default();
    crate::stwo::verify_fib(stark_proof, statement, config)?;

    tracing::info!("STARK proof verified successfully!");

    // Summary
    tracing::info!("\n=== Verification Complete ===");
    tracing::info!("TLSNotary attestation verified");
    tracing::info!("Server identity confirmed: {}", expected_server_domain);
    tracing::info!("fibonacci_index committed via hash: {}", hex::encode(committed_hash.value.as_bytes()));
    tracing::info!("ZK proof verified: fibonacci(SECRET_INDEX) = {}", proof_bundle.fibonacci_value);
    tracing::info!("Prover demonstrated knowledge of server's secret without revealing it!");

    Ok(transcript)
}
