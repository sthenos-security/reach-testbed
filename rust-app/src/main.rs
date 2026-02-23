// Rust Test App — REACHABLE testbed
//
// PURPOSE: Validate Cargo dependency scanning and SBOM generation.
// Rust does not have reachability (call-graph) analysis — all findings
// are DEP_REACHABLE (dependency is in the build graph).
//
// CVEs exercised:
//   RUSTSEC-2023-0034 / CVE-2023-44487  — hyper HTTP/2 rapid reset
//   RUSTSEC-2023-0065                   — h2 HTTP/2 rapid reset
//   RUSTSEC-2023-0044                   — openssl use-after-free
//   RUSTSEC-2023-0052                   — rustls bad cert rejection
//
// HARDCODED SECRETS (SECRET signal):
//   AWS and Stripe keys below

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::net::SocketAddr;

// ===========================================================================
// HARDCODED SECRETS (SECRET signal — should be flagged by TruffleHog/Semgrep)
// ===========================================================================
const AWS_ACCESS_KEY_ID: &str = "AKIAIOSFODNN7RUSTTEST";
const AWS_SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYRUSTKEY123";
const STRIPE_SECRET_KEY: &str = "sk_live_rust_test_51FakeKeyForTestingPurpose";

// ===========================================================================
// HTTP handler — uses hyper 0.14.18 (CVE-2023-44487 HTTP/2 rapid reset)
// This is the application entry point — all routes are REACHABLE
// ===========================================================================
async fn handle(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_owned();
    
    match path.as_str() {
        "/health" => {
            let body = r#"{"status":"ok"}"#;
            Ok(Response::new(Body::from(body)))
        }
        "/api/data" => {
            // Uses serde_json — no CVE but exercises SBOM coverage
            let data = serde_json::json!({
                "message": "hello",
                "key": AWS_ACCESS_KEY_ID  // SECRET leak via response — CWE
            });
            Ok(Response::new(Body::from(data.to_string())))
        }
        _ => {
            let body = r#"{"error":"not found"}"#;
            let resp = Response::builder()
                .status(404)
                .body(Body::from(body))
                .unwrap();
            Ok(resp)
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    
    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handle))
    });

    // hyper Server — any HTTP/2 connection triggers CVE-2023-44487
    let server = Server::bind(&addr).serve(make_svc);
    
    println!("Listening on http://{}", addr);
    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }
}

// ===========================================================================
// Dead code — these functions use openssl/rustls but are never called from main
// They represent NOT_REACHABLE deps in the call graph (if we had one)
// ===========================================================================
#[allow(dead_code)]
fn dead_code_openssl_parse(cert_pem: &[u8]) {
    // RUSTSEC-2023-0044: use-after-free in openssl X.509 parsing
    // Never called — NOT_REACHABLE in a call-graph sense
    use openssl::x509::X509;
    let _ = X509::from_pem(cert_pem);
}

#[allow(dead_code)]  
fn dead_code_stripe_payment() -> String {
    // Never called — secret here would be unreachable
    format!("using key: {}", STRIPE_SECRET_KEY)
}
