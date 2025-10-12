use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpStream, time::timeout};
use tokio_native_tls::native_tls::{Error as NativeTlsError, TlsConnector};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::protocol::Message as WsMessage,
};
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::Role;

pub type ResultType<F, E = anyhow::Error> = anyhow::Result<F, E>;

use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TLSError, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use rustls_pki_types::{ServerName, UnixTime};
use tokio_rustls::rustls;

#[derive(Debug)]
pub(crate) struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer,
        _intermediates: &[rustls_pki_types::CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

pub struct WsFramedStream {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    addr: SocketAddr,
    send_timeout: u64,
}

impl WsFramedStream {
    fn new_connector_native_tls(
        danger_accept_invalid_certs: bool,
    ) -> Result<TlsConnector, NativeTlsError> {
        TlsConnector::builder()
            .danger_accept_invalid_certs(danger_accept_invalid_certs)
            .build()
    }

    fn new_connector_rustls(
        danger_accept_invalid_certs: bool,
    ) -> Result<Arc<rustls::ClientConfig>, TLSError> {
        #[allow(unused_mut)]
        let mut root_store = RootCertStore::empty();
        {
            let rustls_native_certs::CertificateResult { certs, errors, .. } =
                rustls_native_certs::load_native_certs();

            if !errors.is_empty() {
                log::warn!("native root CA certificate loading errors: {errors:?}");
            }
            let total_number = certs.len();
            let (number_added, number_ignored) = root_store.add_parsable_certificates(certs);
            log::debug!(
                "Added {number_added}/{total_number} native root certificates (ignored {number_ignored})"
            );
        }
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = if !danger_accept_invalid_certs {
            ClientConfig::builder().with_root_certificates(root_store)
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
        }
        .with_no_client_auth();
        Ok(Arc::new(config))
    }

    pub async fn new<T: AsRef<str>>(
        url: T,
        danger_accept_invalid_certs: bool,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        let url_str = url.as_ref();
        let request = url_str
            .into_client_request()
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        let ws_config = None;
        let disable_nagle = false;
        let (stream, _) = {
            if !url_str.starts_with("wss://") {
                log::info!("Connecting to WebSocket URL without TLS");
                timeout(
                    Duration::from_millis(ms_timeout),
                    connect_async_tls_with_config(
                        request,
                        ws_config,
                        disable_nagle,
                        Some(Connector::Plain),
                    ),
                )
                .await??
            } else {
                log::info!("Connecting to WebSocket URL, trying native-tls first");
                let connector = Self::new_connector_native_tls(danger_accept_invalid_certs)?;
                match timeout(
                    Duration::from_millis(ms_timeout),
                    connect_async_tls_with_config(
                        request,
                        ws_config,
                        disable_nagle,
                        Some(Connector::NativeTls(connector)),
                    ),
                )
                .await
                {
                    Ok(Ok(res)) => res,
                    Ok(Err(..)) => {
                        log::info!("Falling back to rustls TLS connector");
                        let connector = Self::new_connector_rustls(danger_accept_invalid_certs)?;
                        timeout(
                            Duration::from_millis(ms_timeout),
                            connect_async_tls_with_config(
                                url_str,
                                ws_config,
                                disable_nagle,
                                Some(Connector::Rustls(connector)),
                            ),
                        )
                        .await??
                    }
                    Err(_) => {
                        return Err(Error::new(ErrorKind::TimedOut, "Connection timed out").into());
                    }
                }
            }
        };

        let addr = match stream.get_ref() {
            MaybeTlsStream::Plain(tcp) => tcp.peer_addr()?,
            MaybeTlsStream::NativeTls(tls) => tls.get_ref().get_ref().get_ref().peer_addr()?,
            MaybeTlsStream::Rustls(tls) => tls.get_ref().0.peer_addr()?,
            _ => return Err(Error::new(ErrorKind::Other, "Unsupported stream type").into()),
        };

        let ws = Self {
            stream,
            addr,
            send_timeout: ms_timeout,
        };

        Ok(ws)
    }

    #[inline]
    pub async fn from_tcp_stream(stream: TcpStream, addr: SocketAddr) -> ResultType<Self> {
        let ws_stream =
            WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(stream), Role::Client, None)
                .await;

        Ok(Self {
            stream: ws_stream,
            addr,
            send_timeout: 0,
        })
    }

    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    #[inline]
    pub fn set_send_timeout(&mut self, ms: u64) {
        self.send_timeout = ms;
    }

    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        let msg = WsMessage::Binary(bytes);
        if self.send_timeout > 0 {
            timeout(
                Duration::from_millis(self.send_timeout),
                self.stream.send(msg),
            )
            .await??
        } else {
            self.stream.send(msg).await?
        };
        Ok(())
    }

    #[inline]
    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        while let Some(msg) = self.stream.next().await {
            let msg = match msg {
                Ok(msg) => msg,
                Err(e) => {
                    log::error!("{}", e);
                    return Some(Err(Error::new(
                        ErrorKind::Other,
                        format!("WebSocket protocol error: {}", e),
                    )));
                }
            };

            match msg {
                WsMessage::Binary(data) => {
                    let bytes = BytesMut::from(&data[..]);
                    return Some(Ok(bytes));
                }
                WsMessage::Text(text) => {
                    let bytes = BytesMut::from(text.as_bytes());
                    return Some(Ok(bytes));
                }
                WsMessage::Close(_) => {
                    return None;
                }
                _ => {
                    continue;
                }
            }
        }

        None
    }

    #[inline]
    pub async fn next_timeout(&mut self, ms: u64) -> Option<Result<BytesMut, Error>> {
        match timeout(Duration::from_millis(ms), self.next()).await {
            Ok(res) => res,
            Err(_) => None,
        }
    }
}

pub fn is_ws_endpoint(endpoint: &str) -> bool {
    endpoint.starts_with("ws://") || endpoint.starts_with("wss://")
}

#[tokio::main]
async fn main() -> ResultType<()> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    // let url = "ws://192.168.1.8/ws/";
    let url = "wss://192.168.1.8/ws/";
    // let url = "wss://echo.websocket.org";
    let mut ws = WsFramedStream::new(url, true, 5000).await?;
    log::info!("Connected to: {}", ws.local_addr());
    ws.send_bytes(Bytes::from("Hello WebSocket")).await?;
    if let Some(Ok(msg)) = ws.next_timeout(5000).await {
        log::info!("Received: {:?}", msg);
    } else {
        log::info!("No message received within timeout");
    }
    Ok(())
}
