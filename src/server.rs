use crate::certificates::encryption::{kdf_danger_static, EncAlg};
use crate::certificates::x509::end_entity::nioca_server_cert;
use crate::config::{Config, ConfigSealed, Db, EncKeys};
use crate::constants::{AUTO_UNSEAL, DEV_MODE, INSTANCE_UUID, XSRF_HEADER};
use crate::models::api::openapi::ApiDoc;
use crate::models::db::enc_key::EncKeyEntity;
use crate::routes::{ca, groups, unsealed};
use crate::routes::{clients_ssh, sealed};
use crate::routes::{clients_x509, oidc};
use crate::schedulers::scheduler_main;
use crate::service::password_hasher;
use crate::VERSION;
use axum::body::Bytes;
use axum::handler::HandlerWithoutStateExt;
use axum::headers::HeaderValue;
use axum::http::{header, HeaderName, StatusCode, Uri};
use axum::response::Redirect;
use axum::routing::{delete, get, post, put};
use axum::{extract, BoxError, Router};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use base64::{engine::general_purpose, Engine as _};
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tower::ServiceBuilder;
use tower_http::services::ServeDir;
use tower_http::trace::DefaultOnResponse;
use tower_http::{trace::TraceLayer, LatencyUnit, ServiceBuilderExt};
use tracing::{debug, info, warn};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;
use x509_parser::nom::AsBytes;

#[derive(Debug, Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
    https_pub: u16,
}

impl Ports {
    fn build() -> Self {
        let http = env::var("PORT_HTTP")
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .expect("Error parsing PORT_HTTP to u16");
        let https = env::var("PORT_HTTPS")
            .unwrap_or_else(|_| "443".to_string())
            .parse::<u16>()
            .expect("Error parsing PORT_HTTPS to u16");
        let https_pub = env::var("PORT_HTTPS_PUB")
            .unwrap_or_else(|_| "443".to_string())
            .parse::<u16>()
            .expect("Error parsing PORT_HTTPS_PUB to u16");
        Self {
            http,
            https,
            https_pub,
        }
    }
}

pub async fn run_server(level: &str) -> Result<(), anyhow::Error> {
    info!("Nioca v{}", VERSION);
    info!("Log Level set to {}", level);

    info!("Nioca instance uuid: {}", *INSTANCE_UUID);

    Db::init().await?;

    // build middleware
    let sensitive_headers: Arc<[_]> = vec![
        header::AUTHORIZATION,
        header::COOKIE,
        HeaderName::from_str(XSRF_HEADER).unwrap(),
    ]
    .into();
    let middleware = ServiceBuilder::new()
        // Mark the `Authorization` and `Cookie` headers as sensitive so it doesn't show in logs
        .sensitive_request_headers(sensitive_headers.clone())
        // Add high level tracing / logging to all requests
        .layer(
            TraceLayer::new_for_http()
                .on_body_chunk(|chunk: &Bytes, latency: Duration, _: &tracing::Span| {
                    tracing::trace!(size_bytes = chunk.len(), latency = ?latency, "sending body chunk")
                })
                // .make_span_with(DefaultMakeSpan::new().include_headers(true))
                // .on_response(DefaultOnResponse::new().latency_unit(LatencyUnit::Micros)),
                .on_response(DefaultOnResponse::new().include_headers(true).latency_unit(LatencyUnit::Micros)),
        )
        .sensitive_response_headers(sensitive_headers)
        .compression()
        .append_response_header(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("SAMEORIGIN")
        )
        .append_response_header(
            header::X_XSS_PROTECTION,
            HeaderValue::from_static("1;mode=block")
        )
        .append_response_header(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff")
        )
        .append_response_header(
            header::STRICT_TRANSPORT_SECURITY,
            // HeaderValue::from_static("max-age=31536000; includeSubDomains")
            HeaderValue::from_static("max-age=31536000;includeSubDomains;preload")
        )
        .append_response_header(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer")
        )
        .append_response_header(
            header::CONTENT_SECURITY_POLICY,
            // TODO add nonce's to inline scripts
            HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; object-src 'none';")
        )
        .append_response_header(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store")
        )
        .append_response_header(
            header::PRAGMA,
            HeaderValue::from_static("no-cache")
        );

    // redirect http -> https
    let ports = Ports::build();
    debug!("{ports:?}");
    if !*DEV_MODE {
        tokio::spawn(redirect_http_to_https(ports));
    }

    // run the password hasher
    tokio::spawn(password_hasher::run());

    // TLS config unseal
    let tls_config_unseal = {
        let cert = env::var("UNSEAL_CERT_B64").expect("UNSEAL_CERT_B64 is missing");
        let cert_bytes = general_purpose::STANDARD
            .decode(&cert)
            .expect("Error decoding UNSEAL_CERT_B64 from b64 to bytes");
        let key = env::var("UNSEAL_KEY_B64").expect("UNSEAL_KEY_B64 is missing");
        let key_bytes = general_purpose::STANDARD
            .decode(&key)
            .expect("Error decoding UNSEAL_KEY_B64 from b64 to bytes");
        RustlsConfig::from_pem(
            cert_bytes.as_bytes().to_vec(),
            key_bytes.as_bytes().to_vec(),
        )
        .await?
    };
    debug!("\n\n{:?}", tls_config_unseal);

    // after startup, everything is sealed -> start up special routes first
    let (tx_enc_key, rx_enc_keys) = flume::unbounded();
    let (tx_exit, rx_exit) = flume::unbounded();

    // to have a better quality of life in dev mode, we can auto-unseal
    if *AUTO_UNSEAL {
        tokio::spawn(auto_unseal(tx_enc_key.clone(), tx_exit.clone()));
    }

    let config_sealed = ConfigSealed::new(tx_enc_key, tx_exit).await?;
    let routes_sealed = Router::new()
        .route("/api/status", get(sealed::get_status))
        .nest(
            "/unseal",
            Router::new()
                .route("/execute", post(sealed::post_unseal))
                .route("/init", post(sealed::post_init))
                .route("/init/check", post(sealed::post_init_check))
                .route("/key", post(sealed::post_master_shard))
                .route("/status", get(sealed::get_status))
                .route("/xsrf", get(sealed::get_xsrf)),
        )
        .nest_service("/", ServeDir::new("static"))
        .layer(middleware.clone().into_inner())
        .with_state(config_sealed);
    debug!("Router created");

    let shutdown_handle = Handle::new();
    let handle_clone = shutdown_handle.clone();
    tokio::spawn(async move {
        let _ = rx_exit.recv_async().await;

        // shut down the sealed server
        time::sleep(Duration::from_secs(1)).await;
        handle_clone.shutdown();
        debug!("Shutdown signal for sealed server sent");
    });

    if *DEV_MODE {
        let addr = SocketAddr::from(([0, 0, 0, 0], ports.http));
        info!("Server listening on {}", addr);
        axum_server::bind(addr)
            .handle(shutdown_handle)
            .serve(routes_sealed.into_make_service())
            .await
            .expect("Starting the axum sealed server");
    } else {
        let addr = SocketAddr::from(([0, 0, 0, 0], ports.https));
        info!("Server listening on {}", addr);
        axum_server::bind_rustls(addr, tls_config_unseal)
            .handle(shutdown_handle)
            .serve(routes_sealed.into_make_service())
            .await
            .expect("Starting the axum sealed server");
    }

    let enc_keys = rx_enc_keys.recv_async().await?;

    // The sealed server has shut down, port is free again
    let app_state = Config::new(enc_keys)
        .await
        .expect("Building AppState Config - Is Nioca initialized?");

    // start OIDC SSO cache handler
    // TODO

    // start schedulers
    tokio::spawn(scheduler_main(app_state.clone()));

    // TLS config main -> With the intermediate certificates from the DB we now generate our own
    let tls_config = {
        let ca_cert = &app_state.read().await.nioca_signing_cert;
        let ca_chain = &app_state.read().await.ca_chain_pem;
        let (cert, key) = nioca_server_cert(ca_cert, ca_chain).await?;
        RustlsConfig::from_pem(cert.as_bytes().to_vec(), key.as_bytes().to_vec()).await?
    };

    // main routes
    let routes = Router::new()
        .nest(
            "/api",
            Router::new()
                .route("/ca/ssh", get(ca::get_ca_ssh))
                .route("/ca/ssh/external", post(ca::post_external_ca_ssh))
                .route("/ca/ssh/generate", post(ca::post_generate_ca_ssh))
                .route("/ca/ssh/:id", delete(ca::delete_ca_ssh))
                .route("/ca/x509", get(ca::get_ca_x509).post(ca::post_ca_x509))
                .route("/ca/x509/inspect", get(ca::get_ca_x509_inspect))
                .route("/ca/x509/:id", delete(ca::delete_ca_x509))
                .route(
                    "/clients/ssh",
                    get(clients_ssh::get_clients).post(clients_ssh::post_client),
                )
                .route(
                    "/clients/ssh/:id",
                    get(clients_ssh::get_client)
                        .put(clients_ssh::put_client)
                        .delete(clients_ssh::delete_client),
                )
                .route(
                    "/clients/ssh/:id/cert",
                    post(clients_ssh::post_build_client_cert),
                )
                .route(
                    "/clients/ssh/:id/secret",
                    get(clients_ssh::get_client_secret).put(clients_ssh::put_client_secret),
                )
                .route(
                    "/clients/x509",
                    get(clients_x509::get_clients).post(clients_x509::post_client),
                )
                .route(
                    "/clients/x509/:id",
                    get(clients_x509::get_client)
                        .put(clients_x509::put_client)
                        .delete(clients_x509::delete_client),
                )
                .route(
                    "/clients/x509/:id/cert",
                    post(clients_x509::post_build_client_cert),
                )
                .route(
                    "/clients/x509/:id/cert/p12",
                    post(clients_x509::post_build_client_cert_p12),
                )
                .route(
                    "/clients/x509/:id/secret",
                    get(clients_x509::get_client_secret).put(clients_x509::put_client_secret),
                )
                .route("/groups", get(groups::get_groups).post(groups::post_group))
                .route(
                    "/groups/:id",
                    put(groups::put_group).delete(groups::delete_group),
                )
                .route("/login", post(unsealed::post_login))
                .route("/login/check", get(unsealed::get_login_check))
                .route("/logout", post(unsealed::post_logout))
                .route("/password_change", put(unsealed::put_password_change))
                .route("/sessions", post(unsealed::post_session))
                .route("/oidc/auth", get(oidc::get_oidc_auth))
                .route("/oidc/auth/redirect", get(oidc::get_oidc_auth_redirect))
                .route("/oidc/callback", get(oidc::get_oidc_callback))
                .route(
                    "/oidc/config",
                    get(oidc::get_config_oidc).put(oidc::put_config_oidc),
                )
                .route("/oidc/exists", get(oidc::get_oidc_exists))
                .route("/status", get(unsealed::get_status)),
        )
        .route("/unseal/status", get(unsealed::get_status))
        .route("/root.fingerprint", get(unsealed::get_root_fingerprint))
        .route("/root.pem", get(unsealed::get_root_pem))
        .merge(SwaggerUi::new("/docs/swagger-ui").url("/docs/openapi.json", ApiDoc::build()))
        .nest_service("/", ServeDir::new("static"))
        .layer(middleware.into_inner())
        .with_state(app_state);

    if *DEV_MODE {
        let addr = SocketAddr::from(([0, 0, 0, 0], ports.http));
        info!("Server listening on {}", addr);
        axum_server::bind(addr)
            .serve(routes.into_make_service())
            .await
            .expect("Starting the axum server");
    } else {
        let addr = SocketAddr::from(([0, 0, 0, 0], ports.https));
        info!("Server listening on {}", addr);
        axum_server::bind_rustls(addr, tls_config)
            .serve(routes.into_make_service())
            .await
            .expect("Starting the axum server");
    }

    Ok(())
}

async fn redirect_http_to_https(ports: Ports) {
    fn make_https(host: String, uri: Uri, ports: Ports) -> Result<Uri, BoxError> {
        let mut parts = uri.into_parts();

        parts.scheme = Some(axum::http::uri::Scheme::HTTPS);

        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".parse().unwrap());
        }

        let https_host = host.replace(&ports.http.to_string(), &ports.https_pub.to_string());
        parts.authority = Some(https_host.parse()?);

        Ok(Uri::from_parts(parts)?)
    }

    let redirect = move |extract::Host(host): extract::Host, uri: Uri| async move {
        match make_https(host, uri, ports) {
            Ok(uri) => Ok(Redirect::permanent(&uri.to_string())),
            Err(error) => {
                tracing::warn!(%error, "failed to convert URI to HTTPS");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    };

    let addr = SocketAddr::from(([0, 0, 0, 0], ports.http));
    debug!("Https redirect listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(redirect.into_make_service())
        .await
        .expect("Binding HTTP redirect service to configure HTTP_PORT");
}

async fn auto_unseal(tx: flume::Sender<EncKeys>, tx_exit: flume::Sender<()>) {
    warn!(
        r#"

        !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        !!! Auto-Unsealing is activated - DO NOT USE IN PRODUCTION !!!
        !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        "#
    );

    let master_shard_1 = env::var("AUTO_UNSEAL_SHARD_1").expect("AUTO_UNSEAL_SHARD_1");
    let master_shard_2 = env::var("AUTO_UNSEAL_SHARD_2").expect("AUTO_UNSEAL_SHARD_2");
    let master_full = format!("{}{}", master_shard_1, master_shard_2);
    // let master_key_digest = digest::digest(&digest::SHA256, master_full.as_bytes());
    let master_key = kdf_danger_static(master_full.as_bytes())
        .await
        .expect("Bad DEV AUTO_UNSEAL setup");
    // this is our master key for decryption end enc keys
    // let master_key = master_key_hash.as_ref().to_vec();

    let enc_id = env::var("AUTO_UNSEAL_ENC_UUID").expect("AUTO_UNSEAL_ENC_UUID");
    let enc_hex = env::var("AUTO_UNSEAL_ENC_VALUE").expect("AUTO_UNSEAL_ENC_VALUE");
    let enc_bytes = hex::decode(enc_hex).expect("AUTO_UNSEAL_ENC_VALUE decoding");

    let enc_keys = EncKeys {
        master_shard_1: None,
        master_shard_2: None,
        master_key,
        pepper: master_full,
        enc_key: EncKeyEntity {
            id: Uuid::from_str(&enc_id).expect("AUTO_UNSEAL_ENC_UUID to uuid"),
            alg: EncAlg::ChaCha20Poly1305.to_string(),
            value: enc_bytes,
        },
    };

    tx.send_async(enc_keys).await.unwrap();
    time::sleep(Duration::from_millis(100)).await;
    tx_exit.send_async(()).await.unwrap();
}
