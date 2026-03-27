use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use http::Request;
use hyper::body::to_bytes;
use hyper::{Body, Client};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::tempdir;
use trusttunnel::settings::{
    Http1Settings, ListenProtocolSettings, ManagementApiSettings, Settings, TlsHostInfo,
    TlsHostsSettings,
};

#[allow(dead_code)]
mod common;

#[derive(Deserialize)]
struct CreateUserResponse {
    username: String,
    client_config: Option<ClientConfigResponse>,
}

#[derive(Deserialize)]
struct ClientConfigResponse {
    format: String,
    content: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

#[tokio::test]
async fn create_user_api_activates_user_immediately() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();
    let management_address = common::make_endpoint_address();
    let temp_dir = tempdir().unwrap();
    let users_db_path = temp_dir.path().join("users.sqlite");

    let test_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let response = create_user(
            management_address,
            Some("test-token"),
            json!({
                "username": "alice",
                "password": "secret",
                "client_config": {
                    "addresses": [endpoint_address.to_string()],
                    "format": "deeplink"
                }
            }),
        )
        .await;

        assert_eq!(response.status(), http::StatusCode::CREATED);
        let body: CreateUserResponse =
            serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
        assert_eq!(body.username, "alice");
        let client_config = body.client_config.expect("client config must be returned");
        assert_eq!(client_config.format, "deeplink");
        assert!(client_config.content.starts_with("tt://"));

        let status = do_connect_request(&endpoint_address, Some("alice:secret".into())).await;
        assert_ne!(status, http::StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    };

    tokio::select! {
        _ = run_endpoint_with_sqlite(&endpoint_address, &management_address, &users_db_path, "test-token") => unreachable!(),
        _ = test_task => (),
        _ = tokio::time::sleep(Duration::from_secs(15)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn create_user_api_requires_bearer_token() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();
    let management_address = common::make_endpoint_address();
    let temp_dir = tempdir().unwrap();
    let users_db_path = temp_dir.path().join("users.sqlite");

    let test_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let response = create_user(
            management_address,
            None,
            json!({
                "username": "alice",
                "password": "secret"
            }),
        )
        .await;

        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
        let body: ErrorResponse =
            serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
        assert_eq!(body.error, "Unauthorized");
    };

    tokio::select! {
        _ = run_endpoint_with_sqlite(&endpoint_address, &management_address, &users_db_path, "test-token") => unreachable!(),
        _ = test_task => (),
        _ = tokio::time::sleep(Duration::from_secs(15)) => panic!("Timed out"),
    }
}

async fn run_endpoint_with_sqlite(
    endpoint_address: &SocketAddr,
    management_address: &SocketAddr,
    users_db_path: &std::path::Path,
    auth_token: &str,
) {
    let settings = Settings::builder()
        .listen_address(endpoint_address)
        .unwrap()
        .listen_protocols(ListenProtocolSettings {
            http1: Some(Http1Settings::builder().build()),
            ..Default::default()
        })
        .allow_private_network_connections(true)
        .users_db_file(users_db_path.to_string_lossy().to_string())
        .management_api(
            ManagementApiSettings::builder()
                .listen_address(management_address)
                .unwrap()
                .auth_token(auth_token)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let cert_key_file = common::make_cert_key_file();
    let cert_key_path = cert_key_file.path.to_str().unwrap();
    let hosts_settings = TlsHostsSettings::builder()
        .main_hosts(vec![TlsHostInfo {
            hostname: common::MAIN_DOMAIN_NAME.to_string(),
            cert_chain_path: cert_key_path.to_string(),
            private_key_path: cert_key_path.to_string(),
            allowed_sni: vec![],
        }])
        .build()
        .unwrap();

    common::run_endpoint_with_settings(settings, hosts_settings).await;
}

async fn create_user(
    management_address: SocketAddr,
    bearer_token: Option<&str>,
    body: serde_json::Value,
) -> hyper::Response<Body> {
    let client = Client::new();
    let mut request = Request::post(format!("http://{management_address}/users"))
        .header(http::header::CONTENT_TYPE, "application/json");
    if let Some(token) = bearer_token {
        request = request.header(http::header::AUTHORIZATION, format!("Bearer {token}"));
    }

    client
        .request(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

async fn do_connect_request(
    endpoint_address: &SocketAddr,
    proxy_auth: Option<String>,
) -> http::StatusCode {
    let stream =
        common::establish_tls_connection(common::MAIN_DOMAIN_NAME, endpoint_address, None).await;

    let (mut request, conn_driver) = hyper::client::conn::Builder::new()
        .handshake(stream)
        .await
        .unwrap();

    let exchange = async move {
        let mut rr = Request::builder()
            .version(http::Version::HTTP_11)
            .method(http::Method::CONNECT)
            .uri("https://httpbin.agrd.dev:443/");

        if let Some(proxy_auth) = proxy_auth {
            rr = rr.header(
                http::header::PROXY_AUTHORIZATION,
                format!("Basic {}", BASE64_ENGINE.encode(proxy_auth)),
            );
        }

        let response = request
            .send_request(rr.body(Body::empty()).unwrap())
            .await
            .unwrap();
        response.status()
    };

    futures::pin_mut!(conn_driver);
    futures::pin_mut!(exchange);
    match futures::future::select(conn_driver, exchange).await {
        futures::future::Either::Left((_, exchange)) => exchange.await,
        futures::future::Either::Right((response, _)) => response,
    }
}
