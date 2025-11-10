use std::net::SocketAddr;

use super::types::{FibonacciZKProofBundle, received_commitments, received_secrets};

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
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::CommitmentSchemeProver;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;
use tlsn::{
    config::{CertificateDer, ProtocolConfig, RootCertStore},
    connection::ServerName,
    hash::HashAlgId,
    prover::{ProveConfig, ProveConfigBuilder, Prover, ProverConfig, TlsConfig},
    transcript::{
        hash::{PlaintextHash, PlaintextHashSecret},
        TranscriptCommitConfig, TranscriptCommitConfigBuilder, TranscriptCommitmentKind,
    },
};
use tokio::io::AsyncWriteExt;
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
        alg: HashAlgId::SHA256,
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
    let received_commitment = received_commitments
        .first()
        .ok_or("No received commitments found")?; // committed hash (of fibonacci_index)
    let received_secrets = received_secrets(&prover_output.transcript_secrets);
    let received_secret = received_secrets
        .first()
        .ok_or("No received secrets found")?; // hash blinder

    let fibonacci_index = extract_fibonacci_index(received)?;
    let proof_bundle = generate_zk_proof(fibonacci_index, received_commitment, received_secret)?;

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

    // Commit to hash of fibonacci_index (this is the SECRET value from server)
    let challenge_index = json
        .get("challenge_index")
        .ok_or("challenge_index field not found in JSON")?;

    let start_pos = challenge_index
        .span()
        .indices()
        .min()
        .ok_or("Could not find challenge_index start position")?;
    let end_pos = challenge_index
        .span()
        .indices()
        .max()
        .ok_or("Could not find challenge_index end position")?
        + 1;

    transcript_commitment_builder.commit_recv(&(start_pos..end_pos))?;

    // Reveal the rest of the response (headers, status, etc.)
    if start_pos > 0 {
        builder.reveal_recv(&(0..start_pos))?;
    }
    if end_pos < received.len() {
        builder.reveal_recv(&(end_pos..received.len()))?;
    }

    Ok(())
}

fn extract_fibonacci_index(received: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    let resp = Responses::new_from_slice(received).collect::<Result<Vec<_>, _>>()?;
    let response = resp.first().ok_or("No responses found")?;
    let body = response.body.as_ref().ok_or("Response body not found")?;

    let BodyContent::Json(_json) = &body.content else {
        return Err("Expected JSON body content".into());
    };

    // Find where the JSON body starts in the original bytes
    let body_start = body.span().indices().min().ok_or("Could not find body start")?;
    let body_end = body.span().indices().max().ok_or("Could not find body end")? + 1;
    let body_bytes = &received[body_start..body_end];

    // Parse the body bytes directly with serde_json
    let json_value: serde_json::Value = serde_json::from_slice(body_bytes)?;

    let index = json_value
        .get("challenge_index")
        .and_then(|v| v.as_u64())
        .ok_or("challenge_index not found or not a valid u64")?
        as usize;

    Ok(index)
}

fn generate_zk_proof(
    fibonacci_index: usize,
    _committed_hash: &PlaintextHash,
    _blinder_secret: &PlaintextHashSecret,
) -> Result<FibonacciZKProofBundle, Box<dyn std::error::Error>> {
    tracing::info!("Generating ZK proof with Stwo...");
    tracing::info!("Private input: fibonacci_index = {} (from server)", fibonacci_index);

    // Setup Stwo proof system
    let config = PcsConfig::default();
    let min_log_size: u32 = if fibonacci_index + 1 <= 1 {
        0
    } else {
        (fibonacci_index as u32).ilog2() + 1
    };
    let log_size = min_log_size.max(4); 

    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let channel = &mut Blake2sChannel::default();
    let commitment_scheme = CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(
        config,
        &twiddles,
    );

    let (proof, _component, statement) =
        crate::stwo::prove_simple_fib(fibonacci_index, channel, commitment_scheme)?;

    let fibonacci_value = statement.fibonacci_value;

    tracing::info!(
        "Public output: fibonacci_value = {} (COMPUTED by prover)",
        fibonacci_value
    );
    tracing::info!("STARK proof generated successfully!");

    let proof_bytes = bincode::serialize(&proof)?;

    let proof_bundle = FibonacciZKProofBundle {
        proof: proof_bytes,
        fibonacci_value,
        log_size: statement.log_size,
    };

    Ok(proof_bundle)
}
