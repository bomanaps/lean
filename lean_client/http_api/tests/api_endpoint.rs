/// Integration tests for api_endpoint test vectors.
///
/// Discovers all JSON files under `test_vectors/api_endpoint/` and for each:
///   1. Deserialises the test-vector fields.
///   2. Spins up an axum HTTP server on a random port with the aggregator
///      controller seeded from `initialIsAggregator`.
///   3. Issues the specified HTTP request (GET or POST).
///   4. Asserts status code, Content-Type, and response body match the
///      expected values recorded in the test vector.
use std::{collections::HashMap, fs, path::Path, sync::Arc};

use fork_choice::store::Store;
use http_api::{AggregatorController, HttpServerConfig, SharedStore, routing::normal_routes};
use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::Value;
use test_generator::test_resources;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Deserialization types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ApiEndpointTestVectorFile {
    #[serde(flatten)]
    tests: HashMap<String, ApiEndpointTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiEndpointTestCase {
    #[allow(dead_code)]
    network: String,
    #[allow(dead_code)]
    lean_env: String,
    endpoint: String,
    #[serde(default = "default_get")]
    method: String,
    #[serde(default)]
    initial_is_aggregator: Option<bool>,
    #[serde(default)]
    request_body: Option<Value>,
    #[allow(dead_code)]
    genesis_params: GenesisParams,
    expected_status_code: u16,
    expected_content_type: String,
    #[serde(default)]
    expected_body: Option<Value>,
    #[serde(rename = "_info")]
    info: Info,
}

fn default_get() -> String {
    "GET".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenesisParams {
    #[allow(dead_code)]
    num_validators: u64,
    #[allow(dead_code)]
    genesis_time: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Info {
    #[allow(dead_code)]
    comment: String,
    #[allow(dead_code)]
    test_id: String,
    description: String,
    #[allow(dead_code)]
    fixture_format: String,
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

fn run_api_endpoint_test(path: impl AsRef<Path>) {
    let json_content = fs::read_to_string(path.as_ref())
        .unwrap_or_else(|e| panic!("read test vector {}: {}", path.as_ref().display(), e));

    let file: ApiEndpointTestVectorFile = serde_json::from_str(&json_content)
        .unwrap_or_else(|e| panic!("parse test vector {}: {}", path.as_ref().display(), e));

    let (test_name, case) = file
        .tests
        .into_iter()
        .next()
        .expect("at least one test case per file");

    println!("\n{}", test_name);
    println!("  {}", case.info.description);

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        // Build a minimal store — aggregator handlers only read/write
        // `store.is_aggregator`; no chain state is needed.
        let initial_is_aggregator = case.initial_is_aggregator.unwrap_or(false);
        let store: SharedStore = Arc::new(RwLock::new(Store {
            is_aggregator: initial_is_aggregator,
            ..Default::default()
        }));

        let controller = Arc::new(AggregatorController::new(store.clone(), None));
        let shared_controller = Some(controller);

        let config = HttpServerConfig::default();
        let router = normal_routes(&config, store, shared_controller);

        // Bind to a random OS-assigned port so tests never collide.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let server = axum::serve(listener, router.into_make_service());
        let server_handle = tokio::spawn(async move {
            let _ = server.await;
        });

        // Issue the request.
        let url = format!("http://{}{}", addr, case.endpoint);
        let client = reqwest::Client::new();

        let response = match case.method.as_str() {
            "POST" => {
                match case.request_body {
                    Some(body) => {
                        // JSON body — sets Content-Type: application/json automatically.
                        client.post(&url).json(&body).send().await
                    }
                    None => {
                        // Null body — send POST with no body to trigger parse error.
                        client.post(&url).body("").send().await
                    }
                }
            }
            _ => client.get(&url).send().await,
        }
        .expect("HTTP request");

        // --- Assertions ---

        let actual_status = response.status().as_u16();
        let actual_content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();

        // Collect body before consuming response.
        let body_bytes = response.bytes().await.expect("response body");

        assert_eq!(
            actual_status, case.expected_status_code,
            "status code mismatch in {}",
            test_name,
        );

        assert!(
            actual_content_type.contains(&case.expected_content_type),
            "content-type mismatch in {}: got '{}', expected '{}'",
            test_name,
            actual_content_type,
            case.expected_content_type,
        );

        if let Some(expected_body) = case.expected_body {
            let actual_body: Value =
                serde_json::from_slice(&body_bytes).expect("parse response body as JSON");
            assert_eq!(actual_body, expected_body, "body mismatch in {}", test_name,);
        }

        server_handle.abort();
        println!("  \x1b[32m✓ PASS\x1b[0m");
    });
}

// ---------------------------------------------------------------------------
// Test discovery
// ---------------------------------------------------------------------------

#[test_resources("test_vectors/api_endpoint/**/*.json")]
fn api_endpoint(spec_file: &str) {
    let test_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(spec_file);
    run_api_endpoint_test(test_path);
}
