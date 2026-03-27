use crate::client_config;
use crate::core;
use crate::http1_codec::Http1Codec;
use crate::http_codec::{self, HttpCodec};
use crate::pipe;
use crate::user_store::{CreateUserError, NewUser};
use crate::{log_id, log_utils};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::io;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

const LOG_FMT: &str = "MGMT={}";
const USERS_PATH: &str = "/users";
const MAX_BODY_SIZE: usize = 64 * 1024;

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    #[serde(default)]
    max_http2_conns: Option<u32>,
    #[serde(default)]
    max_http3_conns: Option<u32>,
    #[serde(default)]
    client_config: Option<CreateUserClientConfigRequest>,
}

#[derive(Deserialize)]
struct CreateUserClientConfigRequest {
    addresses: Vec<String>,
    #[serde(default)]
    custom_sni: Option<String>,
    #[serde(default)]
    client_random_prefix: Option<String>,
    #[serde(default)]
    format: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: &'a str,
}

#[derive(Serialize)]
struct CreateUserResponse {
    username: String,
    client_config: Option<ClientConfigResponse>,
}

#[derive(Serialize)]
struct ClientConfigResponse {
    format: String,
    content: String,
}

pub(crate) async fn listen(
    context: Arc<core::Context>,
    log_chain: log_utils::IdChain<u64>,
) -> io::Result<()> {
    let (mut shutdown_notification, _shutdown_completion) = {
        let shutdown = context.shutdown.lock().unwrap();
        (shutdown.notification_handler(), shutdown.completion_guard())
    };

    tokio::select! {
        x = shutdown_notification.wait() => {
            match x {
                Ok(_) => Ok(()),
                Err(e) => Err(io::Error::new(ErrorKind::Other, format!("{}", e))),
            }
        }
        x = listen_inner(context, log_chain) => x,
    }
}

async fn listen_inner(
    context: Arc<core::Context>,
    log_chain: log_utils::IdChain<u64>,
) -> io::Result<()> {
    let settings = match context.settings.management_api.as_ref() {
        Some(settings) => settings,
        None => return Ok(()),
    };

    let next_id = AtomicU64::default();
    let listener = TcpListener::bind(settings.address).await?;

    loop {
        let (stream, peer) = listener.accept().await?;
        let log_id = log_chain.extended(log_utils::IdItem::new(
            LOG_FMT,
            next_id.fetch_add(1, Ordering::Relaxed),
        ));
        log_id!(trace, log_id, "New connection from {}", peer);
        let context = context.clone();
        tokio::spawn(async move { handle_request(context, stream, log_id).await });
    }
}

async fn handle_request(
    context: Arc<core::Context>,
    io: TcpStream,
    log_id: log_utils::IdChain<u64>,
) {
    let mut codec = Http1Codec::new(context.settings.clone(), io, log_id.clone());
    let timeout = context
        .settings
        .management_api
        .as_ref()
        .unwrap()
        .request_timeout;
    let stream = match tokio::time::timeout(timeout, codec.listen()).await {
        Ok(Ok(Some(stream))) => stream,
        Ok(Ok(None)) => return,
        Ok(Err(e)) => {
            log_id!(debug, log_id, "Listen failed: {}", e);
            return;
        }
        Err(_) => {
            log_id!(
                debug,
                log_id,
                "Didn't receive any request during configured period"
            );
            return;
        }
    };

    let dispatch = async {
        match codec.listen().await {
            Ok(Some(stream)) => log_id!(
                debug,
                log_id,
                "Got unexpected request while processing previous: {:?}",
                stream.request().request(),
            ),
            Ok(None) => (),
            Err(e) => log_id!(debug, log_id, "IO error during processing: {}", e),
        }
    };

    let handle = async {
        let request = stream.request().clone_request();
        let result = match (request.method.clone(), request.uri.path()) {
            (http::Method::POST, USERS_PATH) => {
                handle_create_user(context.clone(), stream, request).await
            }
            (_, path) => {
                log_id!(debug, log_id, "Unexpected path: {}", path);
                send_json(
                    stream.split().1,
                    request.version,
                    http::StatusCode::NOT_FOUND,
                    &ErrorResponse { error: "Not found" },
                )
                .await
            }
        };

        if let Err(e) = result {
            log_id!(debug, log_id, "Failed to handle request: {}", e);
        }
    };

    tokio::select! {
        _ = dispatch => (),
        _ = handle => (),
    }

    if let Err(e) = codec.graceful_shutdown().await {
        log_id!(debug, log_id, "Failed to shutdown HTTP session: {}", e);
    }
}

async fn handle_create_user(
    context: Arc<core::Context>,
    stream: Box<dyn http_codec::Stream>,
    request_headers: http::request::Parts,
) -> io::Result<()> {
    if !authorize_request(
        &request_headers,
        context.settings.management_api.as_ref().unwrap(),
    ) {
        return send_json(
            stream.split().1,
            request_headers.version,
            http::StatusCode::UNAUTHORIZED,
            &ErrorResponse {
                error: "Unauthorized",
            },
        )
        .await;
    }

    let (pending_request, respond) = stream.split();
    let content_length = request_headers
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
    let body = match read_request_body(pending_request.finalize(), content_length).await {
        Ok(body) => body,
        Err(error) if error.kind() == ErrorKind::InvalidData => {
            return send_json(
                respond,
                request_headers.version,
                http::StatusCode::PAYLOAD_TOO_LARGE,
                &ErrorResponse {
                    error: "Request body is too large",
                },
            )
            .await;
        }
        Err(error) => return Err(error),
    };
    let request: CreateUserRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return send_json(
                respond,
                request_headers.version,
                http::StatusCode::BAD_REQUEST,
                &ErrorResponse {
                    error: "Invalid JSON body",
                },
            )
            .await;
        }
    };

    let registry = context.user_registry.as_ref().ok_or_else(|| {
        io::Error::new(
            ErrorKind::Other,
            "Management API requires an initialized user registry",
        )
    })?;

    let request_version = request_headers.version;
    let new_user = NewUser {
        username: request.username,
        password: request.password,
        max_http2_conns: request.max_http2_conns,
        max_http3_conns: request.max_http3_conns,
    };

    match registry.create_user(new_user.clone()) {
        Ok(()) => {
            let client_config = match request.client_config {
                Some(config_request) => match build_client_config_response(
                    &context,
                    &new_user.username,
                    &new_user.password,
                    config_request,
                ) {
                    Ok(client_config) => Some(client_config),
                    Err(error) if error.kind() == ErrorKind::InvalidInput => {
                        let error_message = error.to_string();
                        return send_json(
                            respond,
                            request_version,
                            http::StatusCode::BAD_REQUEST,
                            &ErrorResponse {
                                error: &error_message,
                            },
                        )
                        .await;
                    }
                    Err(error) => return Err(error),
                },
                None => None,
            };

            send_json(
                respond,
                request_version,
                http::StatusCode::CREATED,
                &CreateUserResponse {
                    username: new_user.username,
                    client_config,
                },
            )
            .await
        }
        Err(CreateUserError::InvalidInput(error)) => {
            send_json(
                respond,
                request_version,
                http::StatusCode::BAD_REQUEST,
                &ErrorResponse { error: &error },
            )
            .await
        }
        Err(CreateUserError::UserExists(error)) => {
            send_json(
                respond,
                request_version,
                http::StatusCode::CONFLICT,
                &ErrorResponse { error: &error },
            )
            .await
        }
        Err(CreateUserError::Unsupported(error)) => {
            send_json(
                respond,
                request_version,
                http::StatusCode::BAD_REQUEST,
                &ErrorResponse { error: &error },
            )
            .await
        }
        Err(CreateUserError::Io(error)) => Err(error),
    }
}

fn build_client_config_response(
    context: &Arc<core::Context>,
    username: &str,
    password: &str,
    request: CreateUserClientConfigRequest,
) -> io::Result<ClientConfigResponse> {
    if request.addresses.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "client_config.addresses must not be empty",
        ));
    }

    let config = client_config::build_with_credentials(
        username,
        password,
        request.addresses,
        &context.tls_hosts_settings.read().unwrap(),
        request.custom_sni,
        request.client_random_prefix,
    )?;

    let format = request.format.unwrap_or_else(|| "deeplink".to_string());
    let content = match format.as_str() {
        "deeplink" => config.compose_deeplink()?,
        "toml" => config.compose_toml(),
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "client_config.format must be 'deeplink' or 'toml'",
            ))
        }
    };

    Ok(ClientConfigResponse { format, content })
}

async fn send_json<T: Serialize>(
    respond: Box<dyn http_codec::PendingRespond>,
    version: http::Version,
    status: http::StatusCode,
    payload: &T,
) -> io::Result<()> {
    let body = serde_json::to_vec(payload).map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    let response = http::Response::builder()
        .version(version)
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(())
        .unwrap()
        .into_parts()
        .0;

    let mut sink = respond.send_response(response, false)?.into_pipe_sink();
    sink.write_all(Bytes::from(body)).await?;
    sink.eof()
}

async fn read_request_body(
    mut source: Box<dyn pipe::Source>,
    content_length: Option<usize>,
) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        match source.read().await? {
            pipe::Data::Chunk(chunk) => {
                let chunk_len = chunk.len();
                if body.len() + chunk_len > MAX_BODY_SIZE {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "Request body is too large",
                    ));
                }
                body.extend_from_slice(&chunk);
                source.consume(chunk_len)?;
                if let Some(content_length) = content_length {
                    match body.len().cmp(&content_length) {
                        std::cmp::Ordering::Less => (),
                        std::cmp::Ordering::Equal => return Ok(body),
                        std::cmp::Ordering::Greater => {
                            return Err(io::Error::new(
                                ErrorKind::InvalidData,
                                "Request body exceeded Content-Length",
                            ))
                        }
                    }
                }
            }
            pipe::Data::Eof => {
                if let Some(content_length) = content_length {
                    if body.len() != content_length {
                        return Err(io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "Request body ended before Content-Length was satisfied",
                        ));
                    }
                }
                return Ok(body);
            }
        }
    }
}

fn authorize_request(
    request: &http::request::Parts,
    settings: &crate::settings::ManagementApiSettings,
) -> bool {
    request
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| token == settings.auth_token)
}
