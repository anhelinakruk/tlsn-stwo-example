use std::net::SocketAddr;

use super::types::{received_commitments, received_secrets, MultiFibZKProofBundle};

use blake3;
use hex;
use http_body_util::Empty;
use hyper::{body::Bytes, header, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use spansy::{
    http::{BodyContent, Responses},
    Spanned,
};
use stwo::core::channel::Blake2sChannel;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::CommitmentSchemeProver;
use tlsn::{
    config::{CertificateDer, ProtocolConfig, RootCertStore}, connection::ServerName, hash::HashAlgId, prover::{ProveConfig, ProveConfigBuilder, Prover, ProverConfig, TlsConfig}, transcript::{
        TranscriptCommitConfig, TranscriptCommitConfigBuilder, TranscriptCommitmentKind, hash::{PlaintextHash, PlaintextHashSecret}
    }
};
use tokio::{io::AsyncWriteExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

pub static CA_CERT_DER: &[u8] = include_bytes!("certs/rootCA.der");
const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;

#[instrument(skip(verifier_socket, verifier_extra_socket))]
pub async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    mut verifier_extra_socket: T,
    server_addr: &SocketAddr,
    uri: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let uri = uri.parse::<Uri>()?;

    if uri.scheme().map(|s| s.as_str()) != Some("https") {
        return Err("URI must use HTTPS scheme".into());
    }

    let server_domain = uri.authority().ok_or("URI must have authority")?.host();

    // Create a root certificate store with the server-fixture's self-signed certificate
    let mut tls_config_builder = TlsConfig::builder();
    tls_config_builder.root_store(RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    });
    let tls_config = tls_config_builder.build()?;

    // Set up protocol configuration for prover
    let mut prover_config_builder = ProverConfig::builder();
    prover_config_builder
        .server_name(ServerName::Dns(server_domain.try_into()?))
        .tls_config(tls_config)
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        );

    let prover_config = prover_config_builder.build()?;

    // Create prover and connect to verifier
    // Perform the setup phase with the verifier
    let prover = Prover::new(prover_config)
        .setup(verifier_socket.compat())
        .await?;

    // Connect to TLS Server
    let tls_client_socket = tokio::net::TcpStream::connect(server_addr).await?;

    // Pass server connection into the prover
    let (mpc_tls_connection, prover_fut) = prover.connect(tls_client_socket.compat()).await?;

    // Wrap the connection in a TokioIo compatibility layer to use it with hyper
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the Prover to run in the background
    let prover_task = tokio::spawn(prover_fut);

    // MPC-TLS Handshake
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    // Spawn the connection to run in the background
    tokio::spawn(connection);

    // MPC-TLS: Send Request and wait for Response
    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", server_domain)
        .header("Connection", "close")
        .header(header::AUTHORIZATION, "Bearer random_auth_token")
        .method("GET")
        .body(Empty::<Bytes>::new())?;

    let response = request_sender.send_request(request).await?;

    if response.status() != StatusCode::OK {
        return Err(format!("MPC-TLS request failed with status {}", response.status()).into());
    }

    // Create proof for the Verifier
    let mut prover = prover_task.await??;

    let transcript = prover.transcript().clone();
    let mut prove_config_builder = ProveConfig::builder(&transcript);

    // Reveal the DNS name
    prove_config_builder.server_identity();

    let sent: &[u8] = transcript.sent();
    let received: &[u8] = transcript.received();
    let sent_len = sent.len();
    let recv_len = received.len();
    tracing::info!("Sent length: {}, Received length: {}", sent_len, recv_len);

    // Reveal the entire HTTP request except for the authorization bearer token
    reveal_request(sent, &mut prove_config_builder)?;

    // Create hash commitment for the fibonacci_index field from the response
    let mut transcript_commitment_builder = TranscriptCommitConfig::builder(&transcript);
    transcript_commitment_builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::BLAKE3,
    });

    reveal_received(
        received,
        &mut prove_config_builder,
        &mut transcript_commitment_builder,
    )?;

    let transcripts_commitment_config = transcript_commitment_builder.build()?;
    prove_config_builder.transcript_commit(transcripts_commitment_config);

    let prove_config = prove_config_builder.build()?;

    // MPC-TLS prove
    let prover_output = prover.prove(&prove_config).await?;
    prover.close().await?;

    // Generate ZK proof that fibonacci(secret_index) = computed_value
    let received_commitments = received_commitments(&prover_output.transcript_commitments);

    if received_commitments.len() < 2 {
        return Err("Expected at least 2 hash commitments (one for each index)".into());
    }

    let received_commitment1 = received_commitments[0];
    let received_commitment2 = received_commitments[1];

    let received_secrets = received_secrets(&prover_output.transcript_secrets);
    if received_secrets.len() < 2 {
        return Err("Expected at least 2 hash secrets (one for each index)".into());
    }

    let received_secret1 = received_secrets[0];
    let received_secret2 = received_secrets[1];

    let (fibonacci_index1, fibonacci_index2) = extract_fibonacci_indices(received)?;

    // Verify hash commitments (like in interactive_zk)
    verify_fibonacci_index_commitment(
        fibonacci_index1,
        received_commitment1,
        received_secret1,
    )?;
    verify_fibonacci_index_commitment(
        fibonacci_index2,
        received_commitment2,
        received_secret2,
    )?;

    // Extract blinders (16 bytes each)
    let blinder1: [u8; 16] = received_secret1
        .blinder
        .as_bytes()
        .try_into()
        .map_err(|_| "Blinder1 must be exactly 16 bytes")?;
    let blinder2: [u8; 16] = received_secret2
        .blinder
        .as_bytes()
        .try_into()
        .map_err(|_| "Blinder2 must be exactly 16 bytes")?;

    let proof_bundle = generate_multi_fib_zk_proof(
        fibonacci_index1,
        fibonacci_index2,
        received_commitment1,
        received_commitment2,
        &blinder1,
        &blinder2,
    )?;

    // Send zk proof bundle to verifier
    let serialized_proof = bincode::serialize(&proof_bundle)?;
    verifier_extra_socket.write_all(&serialized_proof).await?;
    verifier_extra_socket.shutdown().await?;

    Ok(())
}

// Reveal everything from the request, except for the authorization token
fn reveal_request(
    request: &[u8],
    builder: &mut ProveConfigBuilder<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    use spansy::http::Requests;

    let reqs = Requests::new_from_slice(request).collect::<Result<Vec<_>, _>>()?;

    let req = reqs.first().ok_or("No requests found")?;

    if req.request.method.as_str() != "GET" {
        return Err(format!("Expected GET method, found {}", req.request.method.as_str()).into());
    }

    let authorization_header = req
        .headers_with_name(header::AUTHORIZATION.as_str())
        .next()
        .ok_or("Authorization header not found")?;

    let start_pos = authorization_header
        .span()
        .indices()
        .min()
        .ok_or("Could not find authorization header start position")?
        + header::AUTHORIZATION.as_str().len()
        + 2;
    let end_pos =
        start_pos + authorization_header.span().len() - header::AUTHORIZATION.as_str().len() - 2;

    builder.reveal_sent(&(0..start_pos))?;
    builder.reveal_sent(&(end_pos..request.len()))?;

    Ok(())
}

fn reveal_received(
    received: &[u8],
    builder: &mut ProveConfigBuilder<'_>,
    transcript_commitment_builder: &mut TranscriptCommitConfigBuilder,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = Responses::new_from_slice(received).collect::<Result<Vec<_>, _>>()?;

    let response = resp.first().ok_or("No responses found")?;
    let body = response.body.as_ref().ok_or("Response body not found")?;

    let BodyContent::Json(json) = &body.content else {
        return Err("Expected JSON body content".into());
    };

    // Commit to hash of both fibonacci indices (these are SECRET values from server)
    let challenge_index1 = json
        .get("challenge_index1")
        .ok_or("challenge_index1 field not found in JSON")?;
    let challenge_index2 = json
        .get("challenge_index2")
        .ok_or("challenge_index2 field not found in JSON")?;

    let start_pos1 = challenge_index1
        .span()
        .indices()
        .min()
        .ok_or("Could not find challenge_index1 start position")?;
    let end_pos1 = challenge_index1
        .span()
        .indices()
        .max()
        .ok_or("Could not find challenge_index1 end position")?
        + 1;

    let start_pos2 = challenge_index2
        .span()
        .indices()
        .min()
        .ok_or("Could not find challenge_index2 start position")?;
    let end_pos2 = challenge_index2
        .span()
        .indices()
        .max()
        .ok_or("Could not find challenge_index2 end position")?
        + 1;

    // Debug: show what we're committing to
    tracing::info!("Committing to index1 bytes: {:?} (range {}..{})",
        &received[start_pos1..end_pos1],
        start_pos1, end_pos1);
    tracing::info!("Committing to index2 bytes: {:?} (range {}..{})",
        &received[start_pos2..end_pos2],
        start_pos2, end_pos2);
    tracing::info!("Index1 as string: {:?}", String::from_utf8_lossy(&received[start_pos1..end_pos1]));
    tracing::info!("Index2 as string: {:?}", String::from_utf8_lossy(&received[start_pos2..end_pos2]));

    // Commit to both indices
    transcript_commitment_builder.commit_recv(&(start_pos1..end_pos1))?;
    transcript_commitment_builder.commit_recv(&(start_pos2..end_pos2))?;

    // Reveal the rest of the response (everything except the two indices)
    let min_start = start_pos1.min(start_pos2);
    let max_end = end_pos1.max(end_pos2);

    if min_start > 0 {
        builder.reveal_recv(&(0..min_start))?;
    }

    // Reveal between the two indices if they're not adjacent
    if start_pos1 < start_pos2 && end_pos1 < start_pos2 {
        builder.reveal_recv(&(end_pos1..start_pos2))?;
    } else if start_pos2 < start_pos1 && end_pos2 < start_pos1 {
        builder.reveal_recv(&(end_pos2..start_pos1))?;
    }

    if max_end < received.len() {
        builder.reveal_recv(&(max_end..received.len()))?;
    }

    Ok(())
}

fn extract_fibonacci_indices(
    received: &[u8],
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let resp = Responses::new_from_slice(received).collect::<Result<Vec<_>, _>>()?;
    let response = resp.first().ok_or("No responses found")?;
    let body = response.body.as_ref().ok_or("Response body not found")?;

    let BodyContent::Json(_json) = &body.content else {
        return Err("Expected JSON body content".into());
    };

    // Find where the JSON body starts in the original bytes
    let body_start = body
        .span()
        .indices()
        .min()
        .ok_or("Could not find body start")?;
    let body_end = body
        .span()
        .indices()
        .max()
        .ok_or("Could not find body end")?
        + 1;
    let body_bytes = &received[body_start..body_end];

    // Parse the body bytes directly with serde_json
    let json_value: serde_json::Value = serde_json::from_slice(body_bytes)?;

    let index1 = json_value
        .get("challenge_index1")
        .and_then(|v| v.as_u64())
        .ok_or("challenge_index1 not found or not a valid u64")? as usize;

    let index2 = json_value
        .get("challenge_index2")
        .and_then(|v| v.as_u64())
        .ok_or("challenge_index2 not found or not a valid u64")? as usize;

    Ok((index1, index2))
}

/// Verify that the blinded hash commitment is correct (like in interactive_zk)
/// This ensures: hash(fibonacci_index_bytes + blinder) == committed_hash
fn verify_fibonacci_index_commitment(
    fibonacci_index: usize,
    received_commitment: &PlaintextHash,
    received_secret: &PlaintextHashSecret,
) -> Result<(), Box<dyn std::error::Error>> {
    use tlsn::transcript::Direction;

    // Verify commitment and secret are for received data
    assert_eq!(received_commitment.direction, Direction::Received);
    assert_eq!(received_commitment.hash.alg, HashAlgId::BLAKE3);
    assert_eq!(received_secret.direction, Direction::Received);
    assert_eq!(received_secret.alg, HashAlgId::BLAKE3);

    let committed_hash = received_commitment.hash.value.as_bytes();
    let blinder = received_secret.blinder.as_bytes();

    // Convert fibonacci_index to bytes (as it appears in JSON: "5" -> b"5")
    let index_string = fibonacci_index.to_string();
    let index_bytes = index_string.as_bytes();

    tracing::info!("Verifying hash for index: {}", fibonacci_index);
    tracing::info!("  Index bytes: {:?}", index_bytes);
    tracing::info!("  Blinder: {}", hex::encode(blinder));

    // Compute hash(index_bytes + blinder) using BLAKE3
    let mut hasher = blake3::Hasher::new();
    hasher.update(index_bytes);
    hasher.update(blinder);
    let computed_hash = hasher.finalize();

    tracing::info!("  Computed hash: {}", hex::encode(computed_hash.as_bytes()));

    // Verify computed hash matches committed hash
    if committed_hash != computed_hash.as_bytes() {
        tracing::error!(
            "Hash verification failed for fibonacci_index {}",
            fibonacci_index
        );
        tracing::error!("  Expected (committed): {}", hex::encode(committed_hash));
        tracing::error!("  Computed:             {}", hex::encode(computed_hash.as_bytes()));
        return Err("Computed hash does not match committed hash".into());
    }

    tracing::info!(
        "✓ Hash commitment verified for fibonacci_index {}: {}",
        fibonacci_index,
        hex::encode(committed_hash)
    );

    Ok(())
}

/// Przygotowuje BLAKE3 input z fibonacci_index + blinder
/// Format zgodny z TLSNotary: hash(index_bytes + blinder)
/// Zwraca (v, m) jako arrays gotowe do konwersji na u32x16
pub fn prepare_blake3_input(
    fibonacci_index: usize,
    blinder: &[u8; 16],
) -> ([u32; 16], [u32; 16]) {

    // Konwertuj fibonacci_index na bytes jak w JSON: "5" -> b"5"
    let index_string = fibonacci_index.to_string();
    let index_bytes = index_string.as_bytes();

    // Przygotuj wiadomość: index_bytes + blinder (max 64 bytes)
    let mut message = [0u8; 64];
    let index_len = index_bytes.len();
    message[..index_len].copy_from_slice(index_bytes);
    message[index_len..index_len + 16].copy_from_slice(blinder);

    let total_len = index_len + 16;

    // Konwertuj do u32 array (little-endian) dla BLAKE3
    let m: [u32; 16] = std::array::from_fn(|i| {
        u32::from_le_bytes([
            message[i * 4],
            message[i * 4 + 1],
            message[i * 4 + 2],
            message[i * 4 + 3],
        ])
    });

    // Initialize BLAKE3 state (IV)
    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    let mut v = [0u32; 16];
    // First 8 words: chaining value (IV for first chunk)
    v[0..8].copy_from_slice(&IV);
    // Next 4 words: IV[0..4]
    v[8..12].copy_from_slice(&IV[0..4]);
    // Last 4 words: counter_low, counter_high, block_len, flags
    v[12] = 0; // counter_low
    v[13] = 0; // counter_high
    v[14] = total_len as u32; // block_len in bytes
    v[15] = 0b1011; // flags: CHUNK_START | CHUNK_END | ROOT

    (v, m)
}

fn generate_multi_fib_zk_proof(
    fibonacci_index1: usize,
    fibonacci_index2: usize,
    committed_hash1: &PlaintextHash,
    committed_hash2: &PlaintextHash,
    blinder1: &[u8; 16],
    blinder2: &[u8; 16],
) -> Result<MultiFibZKProofBundle, Box<dyn std::error::Error>> {
    tracing::info!("Generating Multi-Fib ZK proof with Stwo...");

    // Use both indices from server
    let target_element_computing1 = fibonacci_index1;
    let target_element_computing2 = fibonacci_index2;

    tracing::info!(
        "Private inputs: index1 = {}, index2 = {} (from server)",
        target_element_computing1,
        target_element_computing2
    );

    // Setup Stwo proof system
    let config = PcsConfig::default();
    let max_target = target_element_computing1.max(target_element_computing2);
    let min_log_size: u32 = if max_target + 1 <= 1 {
        0
    } else {
        (max_target as u32).ilog2() + 1
    };
    let fib_log_size = min_log_size.max(4);

    // BLAKE3 log_size: 2 instances
    let num_instances: usize = 2;
    let blake3_log_size = crate::multi_fib::compute_blake3_log_size(num_instances);

    // Max log_size considering all circuit components
    let max_log_size = crate::multi_fib::compute_max_log_size(fib_log_size, blake3_log_size);

    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(max_log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    tracing::info!("Proof parameters: fib_log_size={}, blake3_log_size={}, max_log_size={}",
        fib_log_size, blake3_log_size, max_log_size);

    // Prepare BLAKE3 inputs
    let (v1, m1) = prepare_blake3_input(fibonacci_index1, blinder1);
    let (v2, m2) = prepare_blake3_input(fibonacci_index2, blinder2);
    let blake3_inputs = vec![(v1, m1), (v2, m2)];

    // Expected hashes (committed_hash from TLSNotary)
    let hash1: [u8; 32] = committed_hash1
        .hash
        .value
        .as_bytes()
        .try_into()
        .map_err(|_| "committed_hash1 must be 32 bytes")?;
    let hash2: [u8; 32] = committed_hash2
        .hash
        .value
        .as_bytes()
        .try_into()
        .map_err(|_| "committed_hash2 must be 32 bytes")?;
    let blake3_expected_hashes = vec![hash1, hash2];

    tracing::info!("BLAKE3 verification enabled: 2 hash instances");
    tracing::info!("  Hash1 (committed): {}", hex::encode(hash1));
    tracing::info!("  Hash2 (committed): {}", hex::encode(hash2));

    let channel = &mut Blake2sChannel::default();
    let commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    let (proof, _computing_components, _scheduler_component, statement0, statement1) =
        crate::multi_fib::prove_multi_fib(
            target_element_computing1,
            target_element_computing2,
            Some(blake3_inputs),
            Some(blake3_expected_hashes),
            channel,
            commitment_scheme,
        )?;

    tracing::info!("Multi-Fib STARK proof generated successfully!");
    tracing::info!("Scheduler computed sum of two Fibonacci values in ZK");

    let proof_bytes = bincode::serialize(&proof)?;
    let statement0_bytes = bincode::serialize(&statement0)?;
    let statement1_bytes = bincode::serialize(&statement1)?;

    let proof_bundle = MultiFibZKProofBundle {
        proof: proof_bytes,
        target_element_computing1,
        target_element_computing2,
        statement0: statement0_bytes,
        statement1: statement1_bytes,
    };

    Ok(proof_bundle)
}
