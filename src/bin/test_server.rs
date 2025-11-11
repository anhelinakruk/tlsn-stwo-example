use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

/// Handler HTTP
async fn handle_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<String>, Infallible> {
    let path = req.uri().path();
    match path {
        "/fibonacci" => {
            let challenge_index1 = 5;
            let challenge_index2 = 7;
            let response_json = json!({
                "challenge_index1": challenge_index1,
                "challenge_index2": challenge_index2,
                "status": "ok"
            });

            info!(
                "Serving fibonacci challenge: index1 = {}, index2 = {}",
                challenge_index1, challenge_index2
            );

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(response_json.to_string())
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body("Not Found".to_string())
            .unwrap()),
    }
}

/// Start HTTPS server (TLS)
pub async fn start_tls_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting HTTPS test server on {}", addr);

    // ---- 🔐 Wczytaj certyfikaty i klucz (DER) ----
    let cert_bytes = include_bytes!("../certs/server_cert.der").to_vec();
    let key_bytes = include_bytes!("../certs/server_key.der").to_vec();

    let certs = vec![CertificateDer::from(cert_bytes)];
    let pkcs8_key = PrivatePkcs8KeyDer::from(key_bytes);

    // 👇 To jest kluczowa zmiana:
    let key = PrivateKeyDer::Pkcs8(pkcs8_key);

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config error: {}", e))?;

    let acceptor = TlsAcceptor::from(Arc::new(config));

    // ---- 🔌 Listener ----
    let listener = TcpListener::bind(addr).await?;
    info!("Server listening on https://{}", addr);

    loop {
        let (tcp_stream, remote_addr) = listener.accept().await?;
        info!("New connection from {}", remote_addr);

        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    let service = service_fn(handle_request);

                    if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                        error!("Error serving connection: {:?}", err);
                    }
                }
                Err(err) => {
                    error!("TLS handshake failed: {:?}", err);
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let port = if args.len() > 2 && args[1] == "--port" {
        args[2].parse().unwrap_or(3443)
    } else {
        3000
    };

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║   Fibonacci ZK + TLSNotary Test Server (HTTPS)          ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  🚀 Starting TLS server on https://{}", addr);
    println!();
    println!("  📡 Endpoint:");
    println!("     GET /fibonacci - Returns challenge_index");
    println!();
    println!("  💡 Test with curl (ignore cert validation):");
    println!("     curl -k https://{}/fibonacci", addr);
    println!();

    start_tls_server(addr).await?;
    Ok(())
}
