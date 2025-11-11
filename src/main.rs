pub mod multi_fib;
mod prover;
pub mod prover_test;
pub mod simple_fib;
mod types;
mod verifier;

use prover::prover;
use std::{
    env,
    net::{IpAddr, SocketAddr},
};
use verifier::verifier;

const TEST_SERVER_DOMAIN: &str = "localhost";
const TEST_SERVER_PORT: u16 = 3000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // Get server config from environment or use defaults
    let server_host: String = env::var("SERVER_HOST").unwrap_or("127.0.0.1".into());
    let server_port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(TEST_SERVER_PORT);

    let server_domain = env::var("SERVER_DOMAIN").unwrap_or(TEST_SERVER_DOMAIN.to_string());

    // Build URI
    let uri = format!("https://{}:{}/fibonacci", server_domain, server_port);
    let server_ip: IpAddr = server_host
        .parse()
        .map_err(|e| format!("Invalid IP address '{}': {}", server_host, e))?;
    let server_addr = SocketAddr::from((server_ip, server_port));

    tracing::info!("=== Fibonacci ZK + TLSNotary Demo ===");
    tracing::info!("Server: {}", uri);
    tracing::info!("Address: {}", server_addr);

    // Connect prover and verifier with duplex channels
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);
    let (prover_extra_socket, verifier_extra_socket) = tokio::io::duplex(1 << 23);

    // Run prover and verifier concurrently
    let (_prover_result, transcript) = tokio::try_join!(
        prover(prover_socket, prover_extra_socket, &server_addr, &uri),
        verifier(verifier_socket, verifier_extra_socket, &server_domain)
    )?;

    println!("\n=== SUCCESS ===");
    println!("✅ Successfully verified {}", &uri);
    println!("✅ Fibonacci computation verified in ZK!");
    println!("✅ fibonacci_index remains SECRET (zero-knowledge!)\n");

    println!(
        "Verified sent data:\n{}",
        bytes_to_redacted_string(transcript.sent_unsafe())
    );
    println!(
        "Verified received data:\n{}",
        bytes_to_redacted_string(transcript.received_unsafe())
    );

    Ok(())
}

/// Render redacted bytes as `🙈`.
pub fn bytes_to_redacted_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace('\0', "🙈")
}
