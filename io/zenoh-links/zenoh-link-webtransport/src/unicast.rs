//
// Copyright (c) 2026 Adamo Technology Ltd.
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//

use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wtransport::{
    endpoint::{endpoint_side, ConnectOptions, IncomingSession},
    tls::{Identity, Sha256Digest},
    ClientConfig, Connection, Endpoint, ServerConfig, VarInt,
};
use zenoh_core::{zasynclock, zasyncread, zasyncwrite};
use zenoh_link_commons::{
    get_ip_interface_names,
    tls::config::{TLS_LISTEN_CERTIFICATE_FILE, TLS_LISTEN_PRIVATE_KEY_FILE},
    LinkAuthId, LinkManagerUnicastTrait, LinkUnicast, LinkUnicastTrait, NewLinkChannelSender,
};
use zenoh_protocol::{
    core::{EndPoint, Locator, Priority},
    transport::BatchSize,
};
use zenoh_result::{bail, zerror, ZResult};

use super::{
    WEBTRANSPORT_ALLOWED_ORIGINS, WEBTRANSPORT_CLIENT_ORIGIN, WEBTRANSPORT_DEFAULT_MTU, WEBTRANSPORT_DEFAULT_PATH,
    WEBTRANSPORT_LOCATOR_PREFIX, WEBTRANSPORT_PATH, WEBTRANSPORT_SERVER_CERTIFICATE_HASH,
    WEBTRANSPORT_TICKET, WEBTRANSPORT_TICKET_AUDIENCE, WEBTRANSPORT_TICKET_ISSUER,
    WEBTRANSPORT_TICKET_PUBLIC_KEY_FILE,
};

#[derive(Debug, Deserialize)]
struct TicketClaims {
    sub: String,
    org: String,
    origin: String,
    jti: String,
    iat: usize,
    exp: usize,
}

struct TicketVerifier {
    key: DecodingKey,
    validation: Validation,
    allowed_origins: Vec<String>,
    used: Mutex<HashMap<String, usize>>,
}

impl TicketVerifier {
    async fn from_endpoint(endpoint: &EndPoint) -> ZResult<Self> {
        let config = endpoint.config();
        let required = |name: &'static str| {
            config.get(name).filter(|value| !value.trim().is_empty()).ok_or_else(|| {
                zerror!("WebTransport listener requires non-empty '{name}'")
            })
        };
        let key_file = required(WEBTRANSPORT_TICKET_PUBLIC_KEY_FILE)?;
        let issuer = required(WEBTRANSPORT_TICKET_ISSUER)?;
        let audience = required(WEBTRANSPORT_TICKET_AUDIENCE)?;
        let origins = required(WEBTRANSPORT_ALLOWED_ORIGINS)?;
        let allowed_origins = origins
            .split(',')
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if allowed_origins.is_empty() {
            bail!("WebTransport listener requires at least one allowed origin");
        }
        for origin in &allowed_origins {
            let parsed = url::Url::parse(origin)
                .map_err(|error| zerror!("Invalid WebTransport allowed origin '{origin}': {error}"))?;
            if parsed.origin().ascii_serialization() != *origin || parsed.path() != "/" {
                bail!("WebTransport allowed origin must contain only scheme and authority: '{origin}'");
            }
        }
        let pem = tokio::fs::read(key_file)
            .await
            .map_err(|error| zerror!("Cannot read WebTransport ticket key '{key_file}': {error}"))?;
        let key = DecodingKey::from_ec_pem(&pem)
            .map_err(|error| zerror!("Cannot parse WebTransport ES256 ticket key: {error}"))?;
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["aud", "exp", "iat", "iss", "jti", "sub"]);
        validation.leeway = 5;
        Ok(Self {
            key,
            validation,
            allowed_origins,
            used: Mutex::new(HashMap::new()),
        })
    }

    fn authorize(&self, request_path: &str, request_origin: Option<&str>) -> ZResult<String> {
        let origin = request_origin
            .ok_or_else(|| zerror!("WebTransport request has no browser Origin"))?;
        if !self.allowed_origins.iter().any(|allowed| allowed == origin) {
            bail!("WebTransport request Origin is not allowed");
        }
        let token = request_path
            .split_once('?')
            .map(|(_, query)| query)
            .and_then(|query| {
                url::form_urlencoded::parse(query.as_bytes())
                    .find_map(|(name, value)| (name == "ticket").then(|| value.into_owned()))
            })
            .ok_or_else(|| zerror!("WebTransport request has no ticket"))?;
        let claims = jsonwebtoken::decode::<TicketClaims>(&token, &self.key, &self.validation)
            .map_err(|_| zerror!("WebTransport ticket is invalid"))?
            .claims;
        if claims.sub.is_empty() || claims.jti.is_empty() || claims.iat > claims.exp {
            bail!("WebTransport ticket has invalid session claims");
        }
        if claims.origin != origin {
            bail!("WebTransport ticket is bound to a different Origin");
        }
        if !valid_org_slug(&claims.org) {
            bail!("WebTransport ticket has an invalid organization identity");
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| zerror!("System clock precedes Unix epoch"))?
            .as_secs() as usize;
        let mut used = self
            .used
            .lock()
            .map_err(|_| zerror!("WebTransport ticket replay cache is unavailable"))?;
        used.retain(|_, expiry| *expiry + self.validation.leeway as usize >= now);
        if used.insert(claims.jti, claims.exp).is_some() {
            bail!("WebTransport ticket has already been used");
        }
        Ok(claims.org)
    }
}

fn valid_org_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub struct LinkUnicastWebTransport {
    _client_endpoint: Option<Endpoint<endpoint_side::Client>>,
    connection: Connection,
    send: AsyncMutex<wtransport::stream::SendStream>,
    recv: AsyncMutex<wtransport::stream::RecvStream>,
    src_addr: SocketAddr,
    src_locator: Locator,
    dst_addr: SocketAddr,
    dst_locator: Locator,
    auth_id: LinkAuthId,
}

impl LinkUnicastWebTransport {
    fn new(
        client_endpoint: Option<Endpoint<endpoint_side::Client>>,
        connection: Connection,
        send: wtransport::stream::SendStream,
        recv: wtransport::stream::RecvStream,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        auth_id: LinkAuthId,
    ) -> Self {
        Self {
            _client_endpoint: client_endpoint,
            connection,
            send: AsyncMutex::new(send),
            recv: AsyncMutex::new(recv),
            src_addr,
            src_locator: Locator::new(WEBTRANSPORT_LOCATOR_PREFIX, src_addr.to_string(), "").unwrap(),
            dst_addr,
            dst_locator: Locator::new(WEBTRANSPORT_LOCATOR_PREFIX, dst_addr.to_string(), "").unwrap(),
            auth_id,
        }
    }
}

#[async_trait]
impl LinkUnicastTrait for LinkUnicastWebTransport {
    async fn close(&self) -> ZResult<()> {
        self.connection.close(VarInt::from_u32(0), b"zenoh link closed");
        Ok(())
    }

    async fn write(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<usize> {
        zasynclock!(self.send)
            .write(buffer)
            .await
            .map_err(|error| zerror!("WebTransport write failed on {}: {error}", self).into())
    }

    async fn write_all(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<()> {
        zasynclock!(self.send)
            .write_all(buffer)
            .await
            .map_err(|error| zerror!("WebTransport write failed on {}: {error}", self).into())
    }

    async fn read(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<usize> {
        zasynclock!(self.recv)
            .read(buffer)
            .await
            .map_err(|error| zerror!("WebTransport read failed on {}: {error}", self))?
            .ok_or_else(|| zerror!("WebTransport stream closed on {}", self).into())
    }

    async fn read_exact(&self, buffer: &mut [u8], priority: Option<Priority>) -> ZResult<()> {
        let mut offset = 0;
        while offset < buffer.len() {
            offset += self.read(&mut buffer[offset..], priority).await?;
        }
        Ok(())
    }

    fn get_src(&self) -> &Locator { &self.src_locator }
    fn get_dst(&self) -> &Locator { &self.dst_locator }
    fn get_mtu(&self) -> BatchSize { *WEBTRANSPORT_DEFAULT_MTU }
    fn get_interface_names(&self) -> Vec<String> { get_ip_interface_names(&self.src_addr) }
    fn is_reliable(&self) -> bool { true }
    fn is_streamed(&self) -> bool { true }
    fn get_auth_id(&self) -> &LinkAuthId { &self.auth_id }
}

impl Drop for LinkUnicastWebTransport {
    fn drop(&mut self) {
        self.connection.close(VarInt::from_u32(0), b"zenoh link dropped");
    }
}

impl fmt::Display for LinkUnicastWebTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} => {}", self.src_addr, self.dst_addr)
    }
}

impl fmt::Debug for LinkUnicastWebTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("WebTransport")
            .field("src", &self.src_addr)
            .field("dst", &self.dst_addr)
            .finish()
    }
}

struct Listener {
    endpoint: EndPoint,
    token: CancellationToken,
    handle: JoinHandle<ZResult<()>>,
}

pub struct LinkManagerUnicastWebTransport {
    manager: NewLinkChannelSender,
    listeners: Arc<RwLock<HashMap<SocketAddr, Listener>>>,
}

impl LinkManagerUnicastWebTransport {
    pub fn new(manager: NewLinkChannelSender) -> Self {
        Self { manager, listeners: Arc::new(RwLock::new(HashMap::new())) }
    }
}

#[async_trait]
impl LinkManagerUnicastTrait for LinkManagerUnicastWebTransport {
    async fn new_link(&self, endpoint: EndPoint) -> ZResult<LinkUnicast> {
        let path = endpoint_path(&endpoint)?;
        let ticket = required_config(&endpoint, WEBTRANSPORT_TICKET)?;
        let url = format!(
            "https://{}{}?ticket={}",
            endpoint.address(),
            path,
            url::form_urlencoded::byte_serialize(ticket.as_bytes()).collect::<String>()
        );
        let builder = ClientConfig::builder().with_bind_default();
        let config = match endpoint.config().get(WEBTRANSPORT_SERVER_CERTIFICATE_HASH) {
            Some(hash) => {
                let digest = Sha256Digest::from_str(hash)
                    .map_err(|error| zerror!("Invalid WebTransport certificate hash: {error}"))?;
                builder.with_server_certificate_hashes([digest]).build()
            }
            None => builder.with_native_certs().build(),
        };
        let client = Endpoint::client(config)
            .map_err(|error| zerror!("Cannot create WebTransport client: {error}"))?;
        let src_addr = client.local_addr()?;
        let mut connect = ConnectOptions::builder(&url);
        if let Some(origin) = endpoint.config().get(WEBTRANSPORT_CLIENT_ORIGIN) {
            connect = connect.add_header("origin", origin);
        }
        let connection = client.connect(connect).await
            .map_err(|error| zerror!("Cannot connect WebTransport endpoint: {error}"))?;
        let dst_addr = connection.remote_address();
        let (send, recv) = connection.open_bi().await?.await?;
        Ok(LinkUnicast::from(Arc::new(LinkUnicastWebTransport::new(
            Some(client), connection, send, recv, src_addr, dst_addr,
            LinkAuthId::WebTransport(None),
        )) as Arc<dyn LinkUnicastTrait>))
    }

    async fn new_listener(&self, mut endpoint: EndPoint) -> ZResult<Locator> {
        let addr = resolve_addr(&endpoint).await?;
        let cert = required_config(&endpoint, TLS_LISTEN_CERTIFICATE_FILE)?;
        let key = required_config(&endpoint, TLS_LISTEN_PRIVATE_KEY_FILE)?;
        let path = endpoint_path(&endpoint)?.to_owned();
        let verifier = Arc::new(TicketVerifier::from_endpoint(&endpoint).await?);
        let identity = Identity::load_pemfiles(cert, key).await
            .map_err(|error| zerror!("Cannot load WebTransport TLS identity: {error}"))?;
        let server = Endpoint::server(
            ServerConfig::builder()
                .with_bind_address(addr)
                .with_identity(identity)
                .keep_alive_interval(Some(Duration::from_secs(3)))
                .build(),
        )?;
        let local_addr = server.local_addr()?;
        endpoint = EndPoint::new(endpoint.protocol(), local_addr.to_string(), endpoint.metadata(), endpoint.config())?;
        let token = CancellationToken::new();
        let task = {
            let token = token.clone();
            let manager = self.manager.clone();
            let listeners = self.listeners.clone();
            zenoh_runtime::ZRuntime::Acceptor.spawn(async move {
                let result = accept_task(server, local_addr, path, verifier, token, manager).await;
                zasyncwrite!(listeners).remove(&local_addr);
                result
            })
        };
        let locator = endpoint.to_locator();
        zasyncwrite!(self.listeners).insert(local_addr, Listener { endpoint, token, handle: task });
        Ok(locator)
    }

    async fn del_listener(&self, endpoint: &EndPoint) -> ZResult<()> {
        let addr = resolve_addr(endpoint).await?;
        let listener = zasyncwrite!(self.listeners).remove(&addr)
            .ok_or_else(|| zerror!("WebTransport listener not found: {addr}"))?;
        listener.token.cancel();
        listener.handle.await?
    }

    async fn get_listeners(&self) -> Vec<EndPoint> {
        zasyncread!(self.listeners).values().map(|listener| listener.endpoint.clone()).collect()
    }

    async fn get_locators(&self) -> Vec<Locator> {
        zasyncread!(self.listeners).values().map(|listener| listener.endpoint.to_locator()).collect()
    }
}

async fn accept_task(
    server: Endpoint<endpoint_side::Server>,
    local_addr: SocketAddr,
    path: String,
    verifier: Arc<TicketVerifier>,
    token: CancellationToken,
    manager: NewLinkChannelSender,
) -> ZResult<()> {
    loop {
        let incoming = tokio::select! {
            incoming = server.accept() => incoming,
            _ = token.cancelled() => break,
        };
        let manager = manager.clone();
        let verifier = verifier.clone();
        let path = path.clone();
        zenoh_runtime::ZRuntime::Acceptor.spawn(async move {
            if let Err(error) = accept_one(incoming, local_addr, &path, &verifier, manager).await {
                tracing::debug!("WebTransport request rejected: {error}");
            }
        });
    }
    Ok(())
}

async fn accept_one(
    incoming: IncomingSession,
    local_addr: SocketAddr,
    expected_path: &str,
    verifier: &TicketVerifier,
    manager: NewLinkChannelSender,
) -> ZResult<()> {
    let request = incoming.await
        .map_err(|error| zerror!("WebTransport CONNECT failed: {error}"))?;
    let request_path = request.path().split('?').next().unwrap_or_default();
    if request_path != expected_path {
        request.not_found().await;
        bail!("WebTransport request path is not available");
    }
    let organization = match verifier.authorize(request.path(), request.origin()) {
        Ok(organization) => organization,
        Err(error) => {
            request.forbidden().await;
            return Err(error);
        }
    };
    let remote_addr = request.remote_address();
    let connection = request.accept().await?;
    let (send, recv) = tokio::time::timeout(Duration::from_secs(10), connection.accept_bi())
        .await
        .map_err(|_| zerror!("WebTransport peer did not open a Zenoh stream in time"))??;
    let link = Arc::new(LinkUnicastWebTransport::new(
        None, connection, send, recv, local_addr, remote_addr,
        LinkAuthId::WebTransport(Some(organization)),
    )) as Arc<dyn LinkUnicastTrait>;
    manager.send_async(LinkUnicast::from(link)).await
        .map_err(|error| zerror!("Cannot deliver authenticated WebTransport link: {error}"))?;
    Ok(())
}

fn endpoint_path(endpoint: &EndPoint) -> ZResult<&str> {
    let path = endpoint.config().get(WEBTRANSPORT_PATH).unwrap_or(WEBTRANSPORT_DEFAULT_PATH);
    if !path.starts_with('/') || path.contains('?') || path.contains('#') {
        bail!("WebTransport path must be absolute and contain no query or fragment");
    }
    Ok(path)
}

fn required_config<'a>(endpoint: &'a EndPoint, name: &str) -> ZResult<&'a str> {
    endpoint.config().get(name).filter(|value| !value.trim().is_empty())
        .ok_or_else(|| zerror!("WebTransport endpoint requires non-empty '{name}'").into())
}

async fn resolve_addr(endpoint: &EndPoint) -> ZResult<SocketAddr> {
    tokio::net::lookup_host(endpoint.address().as_str()).await?.next()
        .ok_or_else(|| zerror!("Cannot resolve WebTransport address {}", endpoint.address()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rcgen::KeyPair;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestClaims<'a> {
        sub: &'a str,
        org: &'a str,
        origin: &'a str,
        jti: &'a str,
        iss: &'a str,
        aud: &'a str,
        iat: usize,
        exp: usize,
    }

    fn verifier(pair: &KeyPair) -> TicketVerifier {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&["https://api-dev.example"]);
        validation.set_audience(&["zenoh-webtransport"]);
        validation.set_required_spec_claims(&["aud", "exp", "iat", "iss", "jti", "sub"]);
        TicketVerifier {
            key: DecodingKey::from_ec_pem(pair.public_key_pem().as_bytes()).unwrap(),
            validation,
            allowed_origins: vec!["https://app-dev.example".into()],
            used: Mutex::new(HashMap::new()),
        }
    }

    fn token(pair: &KeyPair, claims: &TestClaims<'_>) -> String {
        encode(
            &Header::new(Algorithm::ES256),
            claims,
            &EncodingKey::from_ec_pem(pair.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn claims<'a>(jti: &'a str) -> TestClaims<'a> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
        TestClaims {
            sub: "user-1",
            org: "adamo-culif",
            origin: "https://app-dev.example",
            jti,
            iss: "https://api-dev.example",
            aud: "zenoh-webtransport",
            iat: now,
            exp: now + 60,
        }
    }

    #[test]
    fn organization_identity_is_a_bounded_dns_label() {
        assert!(valid_org_slug("adamo-culif"));
        assert!(valid_org_slug("a1"));
        assert!(!valid_org_slug(""));
        assert!(!valid_org_slug("-tenant"));
        assert!(!valid_org_slug("tenant-"));
        assert!(!valid_org_slug("Tenant"));
        assert!(!valid_org_slug("tenant/other"));
        assert!(!valid_org_slug(&"a".repeat(64)));
    }

    #[test]
    fn valid_ticket_yields_only_the_server_acl_identity() {
        let pair = KeyPair::generate().unwrap();
        let verifier = verifier(&pair);
        let ticket = token(&pair, &claims("ticket-1"));
        let identity = verifier
            .authorize(
                &format!("/zenoh?ticket={ticket}"),
                Some("https://app-dev.example"),
            )
            .unwrap();
        assert_eq!(identity, "adamo-culif");
    }

    #[test]
    fn ticket_is_single_use() {
        let pair = KeyPair::generate().unwrap();
        let verifier = verifier(&pair);
        let ticket = token(&pair, &claims("ticket-2"));
        let path = format!("/zenoh?ticket={ticket}");
        verifier.authorize(&path, Some("https://app-dev.example")).unwrap();
        assert!(verifier.authorize(&path, Some("https://app-dev.example")).is_err());
    }

    #[test]
    fn origin_must_be_present_allowed_and_ticket_bound() {
        let pair = KeyPair::generate().unwrap();
        let verifier = verifier(&pair);
        let ticket = token(&pair, &claims("ticket-3"));
        let path = format!("/zenoh?ticket={ticket}");
        assert!(verifier.authorize(&path, None).is_err());
        assert!(verifier.authorize(&path, Some("https://evil.example")).is_err());

        let mut wrong_claim = claims("ticket-4");
        wrong_claim.origin = "https://other.example";
        let wrong_ticket = token(&pair, &wrong_claim);
        assert!(verifier
            .authorize(
                &format!("/zenoh?ticket={wrong_ticket}"),
                Some("https://app-dev.example"),
            )
            .is_err());
    }

    #[test]
    fn signature_issuer_audience_expiry_and_org_are_fail_closed() {
        let pair = KeyPair::generate().unwrap();
        let other_pair = KeyPair::generate().unwrap();
        let verifier = verifier(&pair);

        let wrong_signature = token(&other_pair, &claims("bad-signature"));
        assert!(verifier
            .authorize(
                &format!("/zenoh?ticket={wrong_signature}"),
                Some("https://app-dev.example"),
            )
            .is_err());

        for (jti, mutate) in [
            ("bad-issuer", 0_u8),
            ("bad-audience", 1_u8),
            ("bad-expiry", 2_u8),
            ("bad-org", 3_u8),
        ] {
            let mut value = claims(jti);
            match mutate {
                0 => value.iss = "https://other.example",
                1 => value.aud = "other-service",
                2 => {
                    value.iat = 1;
                    value.exp = 2;
                }
                3 => value.org = "adamo/other",
                _ => unreachable!(),
            }
            let rejected = token(&pair, &value);
            assert!(verifier
                .authorize(
                    &format!("/zenoh?ticket={rejected}"),
                    Some("https://app-dev.example"),
                )
                .is_err());
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authenticated_listener_delivers_a_native_zenoh_byte_stream() {
        use wtransport::tls::Identity;

        let directory = std::env::temp_dir().join(format!(
            "zenoh-webtransport-clean-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let cert_file = directory.join("server-cert.pem");
        let key_file = directory.join("server-key.pem");
        let ticket_key_file = directory.join("ticket-public.pem");

        let identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
        let certificate_hash = identity.certificate_chain().as_slice()[0].hash().to_string();
        identity.certificate_chain().store_pemfile(&cert_file).await.unwrap();
        identity.private_key().store_secret_pemfile(&key_file).await.unwrap();
        let ticket_pair = KeyPair::generate().unwrap();
        std::fs::write(&ticket_key_file, ticket_pair.public_key_pem()).unwrap();
        let ticket = token(&ticket_pair, &claims("e2e-ticket"));

        let (accepted_tx, accepted_rx) = flume::bounded(1);
        let listener = LinkManagerUnicastWebTransport::new(accepted_tx);
        let listen_config = format!(
            "{TLS_LISTEN_CERTIFICATE_FILE}={};{TLS_LISTEN_PRIVATE_KEY_FILE}={};\
             {WEBTRANSPORT_TICKET_PUBLIC_KEY_FILE}={};{WEBTRANSPORT_TICKET_ISSUER}=https://api-dev.example;\
             {WEBTRANSPORT_TICKET_AUDIENCE}=zenoh-webtransport;{WEBTRANSPORT_ALLOWED_ORIGINS}=https://app-dev.example",
            cert_file.display(),
            key_file.display(),
            ticket_key_file.display(),
        );
        let listen_endpoint = EndPoint::new(
            WEBTRANSPORT_LOCATOR_PREFIX,
            "127.0.0.1:0",
            "",
            listen_config,
        )
        .unwrap();
        let locator = listener.new_listener(listen_endpoint).await.unwrap();

        let (unused_tx, _unused_rx) = flume::bounded(1);
        let client = LinkManagerUnicastWebTransport::new(unused_tx);
        let client_config = format!(
            "{WEBTRANSPORT_TICKET}={ticket};{WEBTRANSPORT_SERVER_CERTIFICATE_HASH}={certificate_hash};\
             {WEBTRANSPORT_CLIENT_ORIGIN}=https://app-dev.example"
        );
        let client_endpoint = EndPoint::new(
            WEBTRANSPORT_LOCATOR_PREFIX,
            locator.address().as_str(),
            "",
            client_config,
        )
        .unwrap();
        let client_link = client.new_link(client_endpoint).await.unwrap();
        let server_link = tokio::time::timeout(Duration::from_secs(3), accepted_rx.recv_async())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            server_link.get_auth_id(),
            &LinkAuthId::WebTransport(Some("adamo-culif".into()))
        );

        client_link.write_all(b"native zenoh", None).await.unwrap();
        let mut received = [0_u8; 12];
        server_link.read_exact(&mut received, None).await.unwrap();
        assert_eq!(&received, b"native zenoh");

        client_link.close().await.unwrap();
        listener
            .del_listener(&EndPoint::new(
                WEBTRANSPORT_LOCATOR_PREFIX,
                locator.address().as_str(),
                "",
                "",
            ).unwrap())
            .await
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}
