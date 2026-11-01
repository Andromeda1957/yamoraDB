//! Bounded standalone and replica-set YamoraDB HTTP/TLS. No third-party Rust crates.
//! See the crate README for raw JSON contracts, limits and unimplemented stages.
#![deny(unsafe_op_in_unsafe_fn)]
mod binary;
mod binary_operations;
mod binary_reply;
mod binary_wire;
pub use binary::{
    BinaryClient, BinaryConfig, BinaryEnvelope, BinaryError, BinaryIdentity, BinaryMethod,
    BinaryOptions, BinaryResponse, BinaryTlsConfig,
};
pub use binary_operations::{
    BinaryChangePage, BinaryFeedResult, BinaryOperationEnvelope, BinaryOperationError,
    BinaryOperationMetadata, BinaryOperationMethod, BinaryOperationResponse,
};
mod cluster;
mod json;
mod semantic;
mod socket;
pub use cluster::{
    CancellationToken, ClusterClient, ClusterConfig, ClusterError, ClusterSeed, PreparedMutation,
    UncertainWriteError,
};
mod tls;
mod transport;

#[cfg(test)]
#[path = "tests/json.rs"]
mod tests;

use std::{
    fmt,
    net::{SocketAddr, SocketAddrV4},
    path::PathBuf,
    time::Duration,
};
pub type Result<T> = std::result::Result<T, Error>;
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const SMALL_REQUEST: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Invalid(&'static str),
    Http(u16),
    Timeout,
    Cancelled,
    #[doc(hidden)]
    ClusterUncertain(Box<UncertainWriteError>),
    Tls,
    Io(std::io::ErrorKind),
    SchemaPolicyReplicationUnsupported,
}
/// Errors never include remote bodies, credentials, or OpenSSL's error queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub may_have_committed: bool,
}
impl Error {
    fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            may_have_committed: false,
        }
    }
    fn invalid(message: &'static str) -> Self {
        Self::new(ErrorKind::Invalid(message))
    }
    fn tls() -> Self {
        Self::new(ErrorKind::Tls)
    }
    fn after_send(mut self, write: bool) -> Self {
        self.may_have_committed =
            write && !matches!(self.kind, ErrorKind::Http(400..=407 | 409..=499));
        self
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "yamora: {:?}{}",
            self.kind,
            if self.may_have_committed {
                "; mutation outcome uncertain"
            } else {
                ""
            }
        )
    }
}
impl std::error::Error for Error {}

#[derive(Clone)]
pub struct ClientIdentity {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}
/// Explicit PEM trust bundle, optional PEM client identity and DNS SAN/SNI name.
/// Without server_name the numeric endpoint's IP SAN is verified. No bypass.
#[derive(Clone)]
pub struct TlsOptions {
    pub ca_file: PathBuf,
    pub identity: Option<ClientIdentity>,
    pub server_name: Option<String>,
}
/// Not Debug: credentials must never appear in diagnostic formatting.
#[derive(Clone)]
pub struct Config {
    pub endpoint: String,
    pub read_token: Option<String>,
    pub write_token: Option<String>,
    pub timeout: Duration,
    pub max_response_bytes: usize,
    pub tls: Option<TlsOptions>,
}
impl Config {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            read_token: None,
            write_token: None,
            timeout: Duration::from_secs(5),
            max_response_bytes: MAX_RESPONSE_BYTES,
            tls: None,
        }
    }
}
/// Immutable configuration; safe to share between threads. Each call opens and
/// closes its own connection and TLS context; there is no request replay.
pub struct Client {
    config: Config,
    address: SocketAddrV4,
    cluster: Option<std::sync::Arc<cluster::Routing>>,
    cancellation: Option<CancellationToken>,
}
#[derive(Clone, Copy, Default)]
pub enum Condition<'a> {
    #[default]
    Any,
    IfMatch(&'a str),
    CreateOnly,
}
#[derive(Clone, Copy, Default)]
pub struct WriteOptions<'a> {
    pub condition: Condition<'a>,
    pub request_id: Option<&'a str>,
}
/// Raw body and validated HTTP metadata. No JSON numeric conversion or YAML parsing.
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub revision: String,
    pub etag: Option<String>,
    pub content_type: String,
}
impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .field("revision", &self.revision)
            .finish()
    }
}
pub struct Document {
    pub source: Vec<u8>,
    pub etag: String,
    pub revision: String,
}
impl fmt::Debug for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Document")
            .field("source_bytes", &self.source.len())
            .field("etag", &self.etag)
            .field("revision", &self.revision)
            .finish()
    }
}
#[derive(Clone, Copy)]
pub enum ReplicationPhase {
    Begin,
    Apply,
    Commit,
    Abort,
}
impl ReplicationPhase {
    fn path(self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::Apply => "apply",
            Self::Commit => "commit",
            Self::Abort => "abort",
        }
    }
}
fn id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Error::invalid("invalid collection or document identifier"));
    }
    Ok(())
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn revision(value: &str) -> Result<()> {
    if !hex(value, 16) {
        return Err(Error::invalid("invalid revision or ETag"));
    }
    Ok(())
}
fn document_path(collection: &str, document: &str) -> Result<String> {
    id(collection)?;
    id(document)?;
    Ok(format!("/v1/collections/{collection}/documents/{document}"))
}
impl Client {
    pub fn new(config: Config) -> Result<Self> {
        let address = config
            .endpoint
            .parse::<SocketAddrV4>()
            .map_err(|_| Error::invalid("numeric IPv4 endpoint required"))?;
        if address.port() == 0
            || !(address.ip().is_loopback() || address.ip().is_private())
            || address.to_string() != config.endpoint
        {
            return Err(Error::invalid("loopback or RFC1918 IPv4 endpoint required"));
        }
        for token in [&config.read_token, &config.write_token]
            .into_iter()
            .flatten()
        {
            if !(32..=512).contains(&token.len()) || !token.bytes().all(|b| (33..=126).contains(&b))
            {
                return Err(Error::invalid("invalid credential"));
            }
        }
        if config.timeout.is_zero() || config.timeout > Duration::from_secs(30) {
            return Err(Error::invalid(
                "timeout must be greater than zero and at most 30 seconds",
            ));
        }
        if config.max_response_bytes == 0 || config.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(Error::invalid("invalid response limit"));
        }
        if let Some(options) = &config.tls {
            tls::validate(options)?;
        }
        Ok(Self {
            config,
            address,
            cluster: None,
            cancellation: None,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        media: &str,
        write: bool,
        options: WriteOptions<'_>,
        maximum: usize,
        statuses: &[u16],
        json_response: bool,
    ) -> Result<Response> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(Error::invalid("request exceeds limit"));
        }
        // Prepare once, before the first connection. Rust borrows prevent concurrent
        // caller mutation; cluster retries additionally own the complete byte snapshot.
        let generated = if write && self.cluster.is_some() && options.request_id.is_none() {
            Some(cluster::request_id()?)
        } else {
            None
        };
        let options = WriteOptions {
            request_id: options.request_id.or(generated.as_deref()),
            ..options
        };
        let mut headers = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json, application/yaml, text/plain\r\n",
            self.address
        );
        let token = if write {
            &self.config.write_token
        } else {
            &self.config.read_token
        };
        if write && token.is_none() {
            return Err(Error::invalid("write credential required"));
        }
        if let Some(token) = token {
            headers.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        match options.condition {
            Condition::Any => (),
            Condition::CreateOnly => headers.push_str("If-None-Match: *\r\n"),
            Condition::IfMatch(value) => {
                revision(value)?;
                headers.push_str(&format!("If-Match: \"{value}\"\r\n"));
            }
        }
        if let Some(request_id) = options.request_id {
            if !write || !hex(request_id, 32) || request_id.bytes().all(|b| b == b'0') {
                return Err(Error::invalid("invalid mutation request ID"));
            }
            headers.push_str(&format!("X-Yamora-Request-Id: {request_id}\r\n"));
        }
        if !media.is_empty() {
            headers.push_str(&format!(
                "Content-Type: {media}\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        headers.push_str("\r\n");
        if let Some(routing) = &self.cluster {
            return routing.request(
                self,
                cluster::Operation {
                    method,
                    path,
                    body,
                    headers: &headers,
                    write,
                    options,
                    maximum: maximum.min(self.config.max_response_bytes),
                    statuses,
                    json_response,
                },
            );
        }
        let mut connection = transport::Connection::connect(
            SocketAddr::V4(self.address),
            self.config.timeout,
            self.config.tls.as_ref(),
        )?;
        let execute = || -> Result<Response> {
            connection.write(headers.as_bytes())?;
            connection.write(body)?;
            let response =
                connection.response(maximum.min(self.config.max_response_bytes), statuses)?;
            let actual_revision = response
                .headers
                .get("x-yamldb-revision")
                .ok_or_else(|| Error::invalid("missing snapshot revision"))?;
            revision(actual_revision)?;
            let content_type = response
                .headers
                .get("content-type")
                .cloned()
                .unwrap_or_default();
            if json_response {
                if content_type.split(';').next().map(str::trim) != Some("application/json") {
                    return Err(Error::invalid("expected JSON response"));
                }
                json::object(&response.body, false)?;
            }
            Ok(Response {
                status: response.status,
                body: response.body,
                revision: actual_revision.clone(),
                etag: response.headers.get("etag").cloned(),
                content_type,
            })
        };
        let mut execute = execute;
        execute().map_err(|error| error.after_send(write))
    }
    fn read_json(&self, path: &str) -> Result<Response> {
        self.request(
            "GET",
            path,
            &[],
            "",
            false,
            WriteOptions::default(),
            MAX_RESPONSE_BYTES,
            &[200],
            true,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn send_json(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        write: bool,
        options: WriteOptions<'_>,
        limit: usize,
        statuses: &[u16],
    ) -> Result<Response> {
        if body.len() > limit {
            return Err(Error::invalid("JSON request exceeds operation limit"));
        }
        json::object(body, true)?;
        self.request(
            method,
            path,
            body,
            "application/json",
            write,
            options,
            MAX_RESPONSE_BYTES,
            statuses,
            true,
        )
    }
    pub fn health(&self) -> Result<Response> {
        self.read_json("/healthz")
    }
    pub fn ready(&self) -> Result<Response> {
        self.read_json("/readyz")
    }
    /// Advisory source preflight before application-owned stages. Native transfer
    /// admission remains authoritative; old policy-free servers may omit the field.
    pub fn require_replication_source(&self) -> Result<Response> {
        let reply = self.ready()?;
        let value = semantic::decode(&reply.body, false)?;
        if let Some(allowed) = value.optional("replication_policy_free")? {
            if !allowed.boolean()? {
                return Err(Error::new(ErrorKind::SchemaPolicyReplicationUnsupported));
            }
        }
        Ok(reply)
    }
    pub fn stats(&self) -> Result<Response> {
        self.read_json("/v1/stats")
    }
    pub fn metrics(&self) -> Result<Response> {
        let r = self.request(
            "GET",
            "/metrics",
            &[],
            "",
            false,
            WriteOptions::default(),
            MAX_DOCUMENT_BYTES,
            &[200],
            false,
        )?;
        if r.content_type.split(';').next().map(str::trim) != Some("text/plain")
            || std::str::from_utf8(&r.body).is_err()
        {
            return Err(Error::invalid("invalid metrics response"));
        }
        Ok(r)
    }
    pub fn collections(&self) -> Result<Response> {
        self.read_json("/v1/collections")
    }
    pub fn documents_page(
        &self,
        collection: &str,
        limit: u16,
        after: Option<&str>,
        expected_revision: Option<&str>,
    ) -> Result<Response> {
        id(collection)?;
        if !(1..=1000).contains(&limit) {
            return Err(Error::invalid("invalid page limit"));
        }
        if let Some(r) = expected_revision {
            revision(r)?;
        }
        let mut path = format!("/v1/collections/{collection}/documents?limit={limit}");
        if let Some(cursor) = after {
            id(cursor)?;
            if expected_revision.is_none() {
                return Err(Error::invalid("continuation requires revision"));
            }
            path.push_str(&format!("&after={cursor}"));
        }
        let response = self.read_json(&path)?;
        if expected_revision.is_some_and(|r| r != response.revision) {
            return Err(Error::invalid("snapshot revision changed"));
        }
        Ok(response)
    }
    pub fn get(
        &self,
        collection: &str,
        document: &str,
        expected_revision: Option<&str>,
    ) -> Result<Document> {
        if let Some(r) = expected_revision {
            revision(r)?;
        }
        let response = self.request(
            "GET",
            &document_path(collection, document)?,
            &[],
            "",
            false,
            WriteOptions::default(),
            MAX_DOCUMENT_BYTES,
            &[200],
            false,
        )?;
        let media = response.content_type.split(';').next().map(str::trim);
        if !matches!(media, Some("application/yaml" | "text/yaml")) {
            return Err(Error::invalid("expected YAML response"));
        }
        let etag = response
            .etag
            .as_deref()
            .filter(|v| {
                v.len() == 18 && v.starts_with('"') && v.ends_with('"') && hex(&v[1..17], 16)
            })
            .ok_or_else(|| Error::invalid("invalid document ETag"))?;
        if expected_revision.is_some_and(|r| r != response.revision) {
            return Err(Error::invalid("snapshot revision changed"));
        }
        Ok(Document {
            source: response.body,
            etag: etag[1..17].to_string(),
            revision: response.revision,
        })
    }
    pub fn put(
        &self,
        collection: &str,
        document: &str,
        source: &[u8],
        options: WriteOptions<'_>,
    ) -> Result<Response> {
        let path = document_path(collection, document)?;
        if source.is_empty()
            || source.len() > MAX_DOCUMENT_BYTES
            || std::str::from_utf8(source).is_err()
        {
            return Err(Error::invalid("nonempty UTF-8 YAML up to 16 MiB required"));
        }
        self.request(
            "PUT",
            &path,
            source,
            "application/yaml",
            true,
            options,
            MAX_DOCUMENT_BYTES,
            &[200, 201],
            true,
        )
    }
    pub fn patch(
        &self,
        collection: &str,
        document: &str,
        operations: &[u8],
        options: WriteOptions<'_>,
    ) -> Result<Response> {
        if matches!(options.condition, Condition::CreateOnly) {
            return Err(Error::invalid("PATCH does not support create-only"));
        }
        self.send_json(
            "PATCH",
            &document_path(collection, document)?,
            operations,
            true,
            options,
            MAX_REQUEST_BYTES,
            &[200],
        )
    }
    pub fn delete(
        &self,
        collection: &str,
        document: &str,
        options: WriteOptions<'_>,
    ) -> Result<Response> {
        if matches!(options.condition, Condition::CreateOnly) {
            return Err(Error::invalid("DELETE does not support create-only"));
        }
        self.request(
            "DELETE",
            &document_path(collection, document)?,
            &[],
            "",
            true,
            options,
            0,
            &[204],
            false,
        )
    }
    fn collection_operation(
        &self,
        operation: &str,
        collection: &str,
        spec: &[u8],
    ) -> Result<Response> {
        id(collection)?;
        self.send_json(
            "POST",
            &format!("/v1/{operation}/{collection}"),
            spec,
            false,
            WriteOptions::default(),
            SMALL_REQUEST,
            &[200],
        )
    }
    pub fn query(&self, collection: &str, spec: &[u8]) -> Result<Response> {
        self.collection_operation("query", collection, spec)
    }
    pub fn aggregate(&self, collection: &str, spec: &[u8]) -> Result<Response> {
        self.collection_operation("aggregate", collection, spec)
    }
    pub fn search(&self, collection: &str, spec: &[u8]) -> Result<Response> {
        self.collection_operation("search", collection, spec)
    }
    pub fn transaction(&self, spec: &[u8], request_id: Option<&str>) -> Result<Response> {
        self.send_json(
            "POST",
            "/v1/transactions",
            spec,
            true,
            WriteOptions {
                request_id,
                ..WriteOptions::default()
            },
            MAX_REQUEST_BYTES,
            &[200],
        )
    }
    pub fn indexes(&self) -> Result<Response> {
        self.read_json("/v1/indexes")
    }
    pub fn set_indexes(
        &self,
        catalog: &[u8],
        expected_revision: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<Response> {
        self.send_json(
            "PUT",
            "/v1/indexes",
            catalog,
            true,
            WriteOptions {
                condition: expected_revision.map_or(Condition::Any, Condition::IfMatch),
                request_id,
            },
            SMALL_REQUEST,
            &[200],
        )
    }
    pub fn start_index_build(
        &self,
        catalog: &[u8],
        expected_revision: Option<&str>,
    ) -> Result<Response> {
        self.send_json(
            "POST",
            "/v1/index-builds",
            catalog,
            true,
            WriteOptions {
                condition: expected_revision.map_or(Condition::Any, Condition::IfMatch),
                request_id: None,
            },
            SMALL_REQUEST,
            &[202],
        )
    }
    pub fn index_builds(&self) -> Result<Response> {
        self.read_json("/v1/index-builds")
    }
    pub fn index_build(&self, job: &str) -> Result<Response> {
        job_id(job)?;
        self.read_json(&format!("/v1/index-builds/{job}"))
    }
    pub fn cancel_index_build(&self, job: &str) -> Result<Response> {
        job_id(job)?;
        self.request(
            "DELETE",
            &format!("/v1/index-builds/{job}"),
            &[],
            "",
            true,
            WriteOptions::default(),
            MAX_DOCUMENT_BYTES,
            &[200, 202],
            true,
        )
    }
    pub fn changes(&self, after: Option<&str>, limit: u8) -> Result<Response> {
        if !(1..=100).contains(&limit) {
            return Err(Error::invalid("invalid change limit"));
        }
        let Some(token) = after else {
            return self.read_json("/v1/changes");
        };
        if token.len() != 52
            || !token.starts_with("v1.")
            || token.as_bytes()[35] != b'.'
            || !hex(&token[3..35], 32)
            || !hex(&token[36..], 16)
        {
            return Err(Error::invalid("invalid change token"));
        }
        self.read_json(&format!("/v1/changes?after={token}&limit={limit}"))
    }
    pub fn replication_status(&self) -> Result<Response> {
        self.read_json("/v1/replication/status")
    }
    pub fn replication(&self, phase: ReplicationPhase, spec: &[u8]) -> Result<Response> {
        self.send_json(
            "POST",
            &format!("/v1/replication/{}", phase.path()),
            spec,
            true,
            WriteOptions::default(),
            if matches!(phase, ReplicationPhase::Apply) {
                MAX_REQUEST_BYTES
            } else {
                SMALL_REQUEST
            },
            &[200],
        )
    }
    pub fn follow_replication(&self, phase: ReplicationPhase, spec: &[u8]) -> Result<Response> {
        self.send_json(
            "POST",
            &format!("/v1/replication/follow/{}", phase.path()),
            spec,
            true,
            WriteOptions::default(),
            if matches!(phase, ReplicationPhase::Apply) {
                MAX_REQUEST_BYTES
            } else {
                SMALL_REQUEST
            },
            &[200],
        )
    }
    /// Advisory only; this method never changes the configured endpoint.
    pub fn cluster_leader(&self) -> Result<Response> {
        self.read_json("/v1/cluster/leader")
    }
    pub fn cluster_status(&self) -> Result<Response> {
        self.read_json("/v1/cluster/status")
    }
}
fn job_id(value: &str) -> Result<()> {
    if !hex(value, 32) {
        return Err(Error::invalid("invalid index job ID"));
    }
    Ok(())
}
