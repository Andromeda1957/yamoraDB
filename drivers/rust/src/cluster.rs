//! Synchronous replica-set routing; configured TLS seeds are the entire trust set.
use crate::{
    Client, Condition, Config, Document, Error, ErrorKind, MAX_DOCUMENT_BYTES, MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES, Response, Result, SMALL_REQUEST, TlsOptions, WriteOptions, document_path,
    hex, id, revision,
    semantic::{self, Value},
    transport::{Connection, Control, WireResponse},
};
use std::{
    collections::BTreeSet,
    fmt,
    fs::File,
    io::Read,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

/// One-way cancellation. Cancelling affects only operations using this token.
/// Calls synchronously release sockets/TLS state before returning; no detached work.
#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);
impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
/// A configured HTTPS seed and its expected node ID. TLS has no bypass; a
/// dedicated CA/SAN policy supplied by the caller binds seeds to the cluster.
#[derive(Clone)]
pub struct ClusterSeed {
    pub endpoint: String,
    pub node: u8,
    pub tls: TlsOptions,
}
impl ClusterSeed {
    pub fn new(endpoint: impl Into<String>, node: u8, tls: TlsOptions) -> Self {
        Self {
            endpoint: endpoint.into(),
            node,
            tls,
        }
    }
}
#[derive(Clone)]
pub struct ClusterConfig {
    pub seeds: Vec<ClusterSeed>,
    pub voters: u8,
    pub read_token: Option<String>,
    pub write_token: Option<String>,
    pub timeout: Duration,
    pub attempt_timeout: Duration,
    pub max_response_bytes: usize,
}
impl ClusterConfig {
    pub fn new(seeds: Vec<ClusterSeed>, voters: u8) -> Self {
        Self {
            seeds,
            voters,
            read_token: None,
            write_token: None,
            timeout: Duration::from_secs(30),
            attempt_timeout: Duration::from_secs(3),
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}
/// An immutable recovery envelope. Reuse this object after uncertainty; never
/// construct a different mutation with its ID. No credential is stored here.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedMutation {
    method: String,
    path: String,
    body: Vec<u8>,
    media: String,
    condition: FrozenCondition,
    request_id: String,
    maximum: usize,
    statuses: Vec<u16>,
    json_response: bool,
}
#[derive(Clone, PartialEq, Eq)]
enum FrozenCondition {
    Any,
    Match(String),
    Create,
}
impl PreparedMutation {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn method(&self) -> &str {
        &self.method
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn condition(&self) -> Condition<'_> {
        match &self.condition {
            FrozenCondition::Any => Condition::Any,
            FrozenCondition::Match(v) => Condition::IfMatch(v),
            FrozenCondition::Create => Condition::CreateOnly,
        }
    }
    fn from_operation(op: &Operation<'_>) -> Self {
        Self {
            method: op.method.into(),
            path: op.path.into(),
            body: op.body.to_vec(),
            media: if op.body.is_empty() {
                ""
            } else if op.method == "PUT" && op.path.starts_with("/v1/collections/") {
                "application/yaml"
            } else {
                "application/json"
            }
            .into(),
            condition: match op.options.condition {
                Condition::Any => FrozenCondition::Any,
                Condition::IfMatch(v) => FrozenCondition::Match(v.into()),
                Condition::CreateOnly => FrozenCondition::Create,
            },
            request_id: op.options.request_id.unwrap_or_default().into(),
            maximum: op.maximum,
            statuses: op.statuses.to_vec(),
            json_response: op.json_response,
        }
    }
}
impl fmt::Debug for PreparedMutation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedMutation")
            .field("request_id", &self.request_id)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncertainWriteError {
    pub mutation: PreparedMutation,
    pub cause: Error,
}
impl UncertainWriteError {
    pub fn request_id(&self) -> &str {
        self.mutation.request_id()
    }
}
#[derive(Debug)]
pub enum ClusterError {
    Failure(Error),
    Uncertain(Box<UncertainWriteError>),
}
impl fmt::Display for ClusterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::Failure(e) => e.fmt(f), Self::Uncertain(_) => f.write_str("yamora: mutation outcome uncertain; recover original prepared bytes and request ID") }
    }
}
impl std::error::Error for ClusterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Failure(e) => e,
            Self::Uncertain(e) => &e.cause,
        })
    }
}
impl From<Error> for ClusterError {
    fn from(error: Error) -> Self {
        match error.kind {
            ErrorKind::ClusterUncertain(value) => Self::Uncertain(value),
            _ => Self::Failure(error),
        }
    }
}
type ClusterResult<T> = std::result::Result<T, ClusterError>;

/// Thread-safe client; per-call bodies, deadlines and cancellation never share
/// mutable state. Only a short-held generation-checked route cache is shared.
pub struct ClusterClient {
    inner: Client,
}
impl ClusterClient {
    pub fn new(config: ClusterConfig) -> Result<Self> {
        if config.seeds.is_empty()
            || config.seeds.len() > 9
            || !(3..=9).contains(&config.voters)
            || config.voters % 2 == 0
        {
            return Err(Error::invalid(
                "1..9 distinct TLS seeds and 3/5/7/9 voters required",
            ));
        }
        for timeout in [config.timeout, config.attempt_timeout] {
            if timeout < Duration::from_millis(1) || timeout > Duration::from_secs(30) {
                return Err(Error::invalid("cluster timeout must be 1ms..30s"));
            }
        }
        let mut addresses = BTreeSet::new();
        let mut nodes = BTreeSet::new();
        let mut endpoints = Vec::new();
        for seed in &config.seeds {
            if seed.node == 0
                || seed.node > config.voters
                || !addresses.insert(seed.endpoint.clone())
                || !nodes.insert(seed.node)
            {
                return Err(Error::invalid(
                    "duplicate or invalid configured seed binding",
                ));
            }
            let mut single = Config::new(&seed.endpoint);
            single.read_token = config.read_token.clone();
            single.write_token = config.write_token.clone();
            single.timeout = config.timeout;
            single.max_response_bytes = config.max_response_bytes;
            single.tls = Some(seed.tls.clone());
            endpoints.push(Client::new(single)?);
        }
        let first = &endpoints[0];
        Ok(Self {
            inner: Client {
                config: first.config.clone(),
                address: first.address,
                cluster: Some(Arc::new(Routing {
                    endpoints,
                    nodes: config.seeds.iter().map(|s| s.node).collect(),
                    voters: config.voters,
                    timeout: config.timeout,
                    attempt_timeout: config.attempt_timeout,
                    route: Mutex::new(Route {
                        leader: None,
                        cursor: 0,
                        generation: 0,
                    }),
                })),
                cancellation: None,
            },
        })
    }
    /// A handle sharing the route cache, with cancellation scoped to this token.
    pub fn cancellable(&self, token: &CancellationToken) -> Self {
        Self {
            inner: Client {
                config: self.inner.config.clone(),
                address: self.inner.address,
                cluster: self.inner.cluster.clone(),
                cancellation: Some(token.clone()),
            },
        }
    }
    pub fn execute(&self, mutation: &PreparedMutation) -> ClusterResult<Response> {
        self.inner
            .request(
                &mutation.method,
                &mutation.path,
                &mutation.body,
                &mutation.media,
                true,
                WriteOptions {
                    condition: mutation.condition(),
                    request_id: Some(mutation.request_id()),
                },
                mutation.maximum,
                &mutation.statuses,
                mutation.json_response,
            )
            .map_err(Into::into)
    }
    pub fn prepare_put(
        &self,
        collection: &str,
        document: &str,
        source: &[u8],
        options: WriteOptions<'_>,
    ) -> Result<PreparedMutation> {
        let path = document_path(collection, document)?;
        if source.is_empty()
            || source.len() > MAX_DOCUMENT_BYTES
            || std::str::from_utf8(source).is_err()
        {
            return Err(Error::invalid("nonempty UTF-8 YAML up to 16 MiB required"));
        }
        self.prepare(
            "PUT",
            &path,
            source,
            options,
            MAX_DOCUMENT_BYTES,
            &[200, 201],
            true,
        )
    }
    pub fn prepare_patch(
        &self,
        collection: &str,
        document: &str,
        spec: &[u8],
        options: WriteOptions<'_>,
    ) -> Result<PreparedMutation> {
        self.prepare(
            "PATCH",
            &document_path(collection, document)?,
            spec,
            options,
            MAX_RESPONSE_BYTES,
            &[200],
            true,
        )
    }
    pub fn prepare_delete(
        &self,
        collection: &str,
        document: &str,
        options: WriteOptions<'_>,
    ) -> Result<PreparedMutation> {
        self.prepare(
            "DELETE",
            &document_path(collection, document)?,
            &[],
            options,
            0,
            &[204],
            false,
        )
    }
    pub fn prepare_transaction(
        &self,
        spec: &[u8],
        request_id: Option<&str>,
    ) -> Result<PreparedMutation> {
        self.prepare(
            "POST",
            "/v1/transactions",
            spec,
            WriteOptions {
                request_id,
                ..WriteOptions::default()
            },
            MAX_RESPONSE_BYTES,
            &[200],
            true,
        )
    }
    pub fn prepare_set_indexes(
        &self,
        catalog: &[u8],
        expected_revision: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<PreparedMutation> {
        self.prepare(
            "PUT",
            "/v1/indexes",
            catalog,
            WriteOptions {
                condition: expected_revision.map_or(Condition::Any, Condition::IfMatch),
                request_id,
            },
            MAX_RESPONSE_BYTES,
            &[200],
            true,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        options: WriteOptions<'_>,
        maximum: usize,
        statuses: &[u16],
        json_response: bool,
    ) -> Result<PreparedMutation> {
        if body.len() > MAX_REQUEST_BYTES || (path == "/v1/indexes" && body.len() > SMALL_REQUEST) {
            return Err(Error::invalid("request exceeds operation limit"));
        }
        if let Condition::IfMatch(v) = options.condition {
            revision(v)?;
        }
        let generated = if options.request_id.is_none() {
            Some(request_id()?)
        } else {
            None
        };
        let options = WriteOptions {
            request_id: options.request_id.or(generated.as_deref()),
            ..options
        };
        validate_id(options.request_id.unwrap_or_default())?;
        let op = Operation {
            method,
            path,
            body,
            headers: "",
            write: true,
            options,
            maximum,
            statuses,
            json_response,
        };
        contract(&op)?;
        Ok(PreparedMutation::from_operation(&op))
    }
}
macro_rules! methods {
    ($(fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => { impl ClusterClient { $(pub fn $name(&self, $($arg:$ty),*) -> ClusterResult<$ret> { self.inner.$name($($arg),*).map_err(Into::into) })* } };
}
methods! {
    fn health() -> Response; fn ready() -> Response; fn stats() -> Response; fn metrics() -> Response;
    fn collections() -> Response;
    fn documents_page(collection: &str, limit: u16, after: Option<&str>, expected_revision: Option<&str>) -> Response;
    fn get(collection: &str, document: &str, expected_revision: Option<&str>) -> Document;
    fn put(collection: &str, document: &str, source: &[u8], options: WriteOptions<'_>) -> Response;
    fn patch(collection: &str, document: &str, spec: &[u8], options: WriteOptions<'_>) -> Response;
    fn delete(collection: &str, document: &str, options: WriteOptions<'_>) -> Response;
    fn transaction(spec: &[u8], request_id: Option<&str>) -> Response;
    fn indexes() -> Response;
    fn set_indexes(catalog: &[u8], expected_revision: Option<&str>, request_id: Option<&str>) -> Response;
    fn query(collection: &str, spec: &[u8]) -> Response;
    fn aggregate(collection: &str, spec: &[u8]) -> Response;
    fn search(collection: &str, spec: &[u8]) -> Response;
    fn changes(after: Option<&str>, limit: u8) -> Response;
    fn cluster_status() -> Response; fn cluster_leader() -> Response;
    fn index_builds() -> Response; fn index_build(job: &str) -> Response;
    fn start_index_build(catalog: &[u8], expected_revision: Option<&str>) -> Response;
    fn cancel_index_build(job: &str) -> Response;
    fn replication_status() -> Response;
    fn replication(phase: crate::ReplicationPhase, spec: &[u8]) -> Response;
    fn follow_replication(phase: crate::ReplicationPhase, spec: &[u8]) -> Response;
}
pub(crate) fn request_id() -> Result<String> {
    let mut random = [0; 16];
    // OS CSPRNG, no custom cryptography and no new runtime dependency.
    let mut source = File::open("/dev/urandom").map_err(|e| Error::new(ErrorKind::Io(e.kind())))?;
    loop {
        source
            .read_exact(&mut random)
            .map_err(|e| Error::new(ErrorKind::Io(e.kind())))?;
        if random.iter().any(|&v| v != 0) {
            return Ok(random.iter().map(|b| format!("{b:02x}")).collect());
        }
    }
}
fn validate_id(value: &str) -> Result<()> {
    if !hex(value, 32) || value.bytes().all(|b| b == b'0') {
        return Err(Error::invalid("invalid mutation request ID"));
    }
    Ok(())
}
pub(crate) struct Operation<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
    pub headers: &'a str,
    pub write: bool,
    pub options: WriteOptions<'a>,
    pub maximum: usize,
    pub statuses: &'a [u16],
    pub json_response: bool,
}
#[derive(Clone, Copy)]
struct Route {
    leader: Option<usize>,
    cursor: usize,
    generation: u64,
}
pub(crate) struct Routing {
    endpoints: Vec<Client>,
    nodes: Vec<u8>,
    voters: u8,
    timeout: Duration,
    attempt_timeout: Duration,
    route: Mutex<Route>,
}
impl Routing {
    fn route(&self) -> std::sync::MutexGuard<'_, Route> {
        self.route
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn budget(&self, control: &Control, shares: u32) -> Result<Control> {
        Ok(Control {
            deadline: (Instant::now()
                + self
                    .attempt_timeout
                    .min(control.remaining()? / shares)
                    .max(Duration::from_nanos(1)))
            .min(control.deadline),
            cancellation: control.cancellation.clone(),
        })
    }
    fn discover(&self, control: &Control, attempts: &mut u8) -> Result<Option<Route>> {
        let observed = *self.route();
        if observed.leader.is_some() {
            return Ok(Some(observed));
        }
        for offset in 0..self.endpoints.len() {
            control.remaining()?;
            if *attempts >= 32 {
                break;
            }
            *attempts += 1;
            let index = (observed.cursor + offset) % self.endpoints.len();
            let endpoint = &self.endpoints[index];
            let mut headers = format!(
                "GET /v1/cluster/status HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                endpoint.address
            );
            if let Some(token) = &endpoint.config.read_token {
                headers = headers.replace(
                    "Connection: close",
                    &format!("Authorization: Bearer {token}\r\nConnection: close"),
                );
            }
            let result = self.exchange(
                index,
                self.budget(control, (self.endpoints.len() - offset + 1) as u32)?,
                &headers,
                &[],
                endpoint.config.max_response_bytes.min(4096),
                &[200],
                false,
            );
            match result {
                Ok(response) if leader(&response, self.nodes[index], self.voters).is_ok() => {
                    control.remaining()?;
                    let mut current = self.route();
                    if current.generation == observed.generation {
                        current.leader = Some(index);
                        current.generation = current.generation.wrapping_add(1);
                        return Ok(Some(*current));
                    }
                    // Stale discovery never overwrites a newer route. Its own
                    // validated result remains usable without publishing it.
                    return Ok(Some(Route {
                        leader: Some(index),
                        ..observed
                    }));
                }
                Err(e) if matches!(e.kind, ErrorKind::Http(401 | 403)) => return Err(e),
                _ => (),
            }
        }
        let mut current = self.route();
        if current.generation == observed.generation {
            current.cursor = (observed.cursor + 1) % self.endpoints.len();
            current.generation = current.generation.wrapping_add(1);
        }
        Ok(None)
    }
    #[allow(clippy::too_many_arguments)]
    fn exchange(
        &self,
        index: usize,
        control: Control,
        headers: &str,
        body: &[u8],
        maximum: usize,
        statuses: &[u16],
        write: bool,
    ) -> Result<Response> {
        let endpoint = &self.endpoints[index];
        let mut connection = Connection::connect_control(
            SocketAddr::V4(endpoint.address),
            control.clone(),
            endpoint.config.tls.as_ref(),
        )?;
        let result = (|| {
            // Once any mutation bytes may leave the process all subsequent
            // protocol, HTTP, cancellation and lifetime errors stay recoverable.
            connection.write(headers.as_bytes())?;
            connection.write(body)?;
            let wire = connection.response(maximum, statuses)?;
            control.remaining()?;
            response(wire)
        })();
        result.map_err(|e: Error| e.after_send(write))
    }
    pub(crate) fn request(&self, client: &Client, op: Operation<'_>) -> Result<Response> {
        let control = Control {
            deadline: Instant::now() + self.timeout,
            cancellation: client.cancellation.clone(),
        };
        control.remaining()?;
        let receipt = if op.write { Some(contract(&op)?) } else { None };
        let frozen = op
            .write
            .then(|| Box::new(PreparedMutation::from_operation(&op)));
        let body = op.body.to_vec();
        let headers = op.headers.to_owned();
        let mut uncertain = false;
        let result = (|| {
            let mut attempts = 0;
            let mut delay = Duration::from_millis(25);
            let mut last = Error::new(ErrorKind::Http(503));
            loop {
                control.remaining()?;
                if attempts >= 32 {
                    return Err(last);
                }
                if let Some(route) = self.discover(&control, &mut attempts)? {
                    if attempts >= 32 {
                        return Err(last);
                    }
                    let index = route
                        .leader
                        .ok_or_else(|| Error::invalid("missing route"))?;
                    attempts += 1;
                    // Host and credentials always belong to a configured seed.
                    let target_headers = headers.replacen(
                        &format!("Host: {}\r\n", client.address),
                        &format!("Host: {}\r\n", self.endpoints[index].address),
                        1,
                    );
                    let result = self
                        .exchange(
                            index,
                            self.budget(&control, if self.endpoints.len() > 1 { 2 } else { 1 })?,
                            &target_headers,
                            &body,
                            op.maximum,
                            op.statuses,
                            op.write,
                        )
                        .and_then(|r| {
                            (|| {
                                if op.json_response {
                                    json_response(&r)?;
                                }
                                if let Some(contract) = &receipt {
                                    validate_receipt(&r, contract)?;
                                }
                                control.remaining()?;
                                Ok(r)
                            })()
                            .map_err(|e: Error| e.after_send(op.write))
                        });
                    match result {
                        Ok(r) => return Ok(r),
                        Err(e) => {
                            // A connection/TLS failure before dispatch is certain.
                            // Receipt validation fails after dispatch, even though
                            // its local Error has no transport after_send marker.
                            uncertain |= op.write && e.may_have_committed;
                            let retry = matches!(
                                e.kind,
                                ErrorKind::Io(_)
                                    | ErrorKind::Tls
                                    | ErrorKind::Timeout
                                    | ErrorKind::Http(503)
                            );
                            if !retry {
                                return Err(e);
                            }
                            let mut current = self.route();
                            if current.generation == route.generation
                                && current.leader == route.leader
                            {
                                current.leader = None;
                                current.cursor = (index + 1) % self.endpoints.len();
                                current.generation = current.generation.wrapping_add(1);
                            }
                            last = e;
                        }
                    }
                }
                let end = Instant::now() + delay.min(control.remaining()?);
                while Instant::now() < end {
                    control.remaining()?;
                    thread::sleep(
                        Duration::from_millis(10)
                            .min(end.saturating_duration_since(Instant::now())),
                    );
                }
                delay = (delay * 2).min(Duration::from_millis(500));
            }
        })();
        result.map_err(|error| {
            if uncertain {
                Error {
                    kind: ErrorKind::ClusterUncertain(Box::new(UncertainWriteError {
                        mutation: *frozen.expect("mutation uncertainty requires frozen write"),
                        cause: error,
                    })),
                    may_have_committed: true,
                }
            } else {
                error
            }
        })
    }
}
fn response(wire: WireResponse) -> Result<Response> {
    let actual = wire
        .headers
        .get("x-yamldb-revision")
        .ok_or_else(|| Error::invalid("missing snapshot revision"))?;
    revision(actual)?;
    if let Some(tag) = wire.headers.get("etag") {
        let bytes = tag.as_bytes();
        if bytes.len() != 18 || bytes[0] != b'"' || bytes[17] != b'"' || !hex(&tag[1..17], 16) {
            return Err(Error::invalid("invalid response ETag"));
        }
    }

    Ok(Response {
        status: wire.status,
        body: wire.body,
        revision: actual.clone(),
        etag: wire.headers.get("etag").cloned(),
        content_type: wire
            .headers
            .get("content-type")
            .cloned()
            .unwrap_or_default(),
    })
}
fn json_response(response: &Response) -> Result<Value> {
    if response.content_type.split(';').next().map(str::trim) != Some("application/json") {
        return Err(Error::invalid("expected JSON response"));
    }
    let value = semantic::decode(&response.body, false)?;
    if let Some(actual) = value.optional("revision")? {
        if actual.text()? != response.revision {
            return Err(Error::invalid("body/header revision disagreement"));
        }
    }
    Ok(value)
}
fn leader(response: &Response, node: u8, voters: u8) -> Result<()> {
    let value = json_response(response)?;
    value.keys(&[
        "node",
        "leader",
        "term",
        "role",
        "voters",
        "last",
        "committed",
        "applied",
        "failed",
        "checkpoints",
        "compaction",
        "application_compaction",
    ])?;
    // Current native daemon advisory; never a route, electorate or identity.
    if let Some(advisory) = value.optional("application_compaction")? {
        advisory.map()?;
    }
    if value.get("node")?.uint()? != u64::from(node)
        || value.get("leader")?.uint()? != u64::from(node)
        || value.get("voters")?.uint()? != u64::from(voters)
        || value.get("term")?.uint()? == 0
        || value.get("role")?.text()? != "leader"
        || value.get("failed")?.boolean()?
        || value.get("applied")?.uint()? > value.get("committed")?.uint()?
        || value.get("committed")?.uint()? > value.get("last")?.uint()?
    {
        return Err(Error::invalid("unbound or invalid cluster leader"));
    }
    Ok(())
}
enum Receipt {
    Document {
        collection: String,
        document: String,
        statuses: &'static [u16],
    },
    Delete,
    Commit(usize),
}
fn contract(op: &Operation<'_>) -> Result<Receipt> {
    validate_id(op.options.request_id.unwrap_or_default())?;
    if let Condition::IfMatch(v) = op.options.condition {
        revision(v)?;
    }
    if op.method == "POST" && op.path == "/v1/transactions" {
        let value = semantic::decode(op.body, true)?;
        value.keys(&["operations", "revision"])?;
        if let Some(r) = value.optional("revision")? {
            revision(r.text()?)?;
        }
        let operations = value.get("operations")?.array()?;
        if operations.is_empty() || operations.len() > 128 {
            return Err(Error::invalid("transaction requires 1..128 operations"));
        }
        let mut identities = BTreeSet::new();
        for operation in operations {
            operation.keys(&[
                "collection",
                "document",
                "put",
                "patch",
                "delete",
                "etag",
                "create_only",
            ])?;
            let collection = operation.get("collection")?.text()?;
            let document = operation.get("document")?.text()?;
            write_identity(collection, document)?;
            if !identities.insert((collection, document)) {
                return Err(Error::invalid("duplicate transaction identity"));
            }
            let put = operation.optional("put")?;
            let patch = operation.optional("patch")?;
            let delete = operation.optional("delete")?;
            if usize::from(put.is_some())
                + usize::from(patch.is_some())
                + usize::from(delete.is_some())
                != 1
            {
                return Err(Error::invalid("exactly one mutation mode required"));
            }
            if let Some(v) = put {
                let text = v.text()?;
                if text.is_empty() || text.len() > MAX_DOCUMENT_BYTES {
                    return Err(Error::invalid("invalid transaction source"));
                }
            }
            if let Some(v) = patch {
                if v.map()?.is_empty() {
                    return Err(Error::invalid("empty transaction patch"));
                }
            }
            if let Some(v) = delete {
                if !v.boolean()? {
                    return Err(Error::invalid("invalid delete mode"));
                }
            }
            if let Some(v) = operation.optional("etag")? {
                revision(v.text()?)?;
            }
            if let Some(v) = operation.optional("create_only")? {
                if v.boolean()? && (put.is_none() || operation.optional("etag")?.is_some()) {
                    return Err(Error::invalid("invalid create-only precondition"));
                }
            }
        }
        return Ok(Receipt::Commit(operations.len()));
    }
    if op.method == "PUT" && op.path == "/v1/indexes" {
        let value = semantic::decode(op.body, true)?;
        value.keys(&["indexes"])?;
        value.get("indexes")?.array()?;
        return Ok(Receipt::Commit(1));
    }
    let parts: Vec<_> = op.path.split('/').collect();
    if parts.len() != 6
        || parts[1] != "v1"
        || parts[2] != "collections"
        || parts[4] != "documents"
        || !["PUT", "PATCH", "DELETE"].contains(&op.method)
    {
        return Err(Error::new(ErrorKind::Http(405)));
    }
    write_identity(parts[3], parts[5])?;
    if op.method != "PUT" && matches!(op.options.condition, Condition::CreateOnly) {
        return Err(Error::invalid("create-only only supported by PUT"));
    }
    if op.method == "PATCH" && semantic::decode(op.body, true)?.map()?.is_empty() {
        return Err(Error::invalid("empty patch"));
    }
    if op.method == "DELETE" {
        return Ok(Receipt::Delete);
    }
    Ok(Receipt::Document {
        collection: parts[3].into(),
        document: parts[5].into(),
        statuses: match (op.method, op.options.condition) {
            ("PUT", Condition::Any) => &[200, 201],
            ("PUT", Condition::CreateOnly) => &[201],
            _ => &[200],
        },
    })
}
fn write_identity(collection: &str, document: &str) -> Result<()> {
    id(collection)?;
    id(document)?;
    if collection == "yamldb-system" {
        return Err(Error::invalid("reserved collection"));
    }
    Ok(())
}
fn validate_receipt(response: &Response, contract: &Receipt) -> Result<()> {
    revision(&response.revision)?;
    if matches!(contract, Receipt::Delete) {
        if response.status != 204 || !response.body.is_empty() {
            return Err(Error::invalid("invalid delete receipt"));
        }
        return Ok(());
    }
    let value = json_response(response)?;
    if value.get("revision")?.text()? != response.revision {
        return Err(Error::invalid("receipt revision mismatch"));
    }
    match contract {
        Receipt::Document {
            collection,
            document,
            statuses,
        } => {
            if !statuses.contains(&response.status) {
                return Err(Error::invalid(
                    "receipt status contradicts mutation preconditions",
                ));
            }
            value.keys(&["status", "collection", "document", "etag", "revision"])?;
            let tag = value.get("etag")?.text()?;
            revision(tag)?;
            if value.get("status")?.text()? != "stored"
                || value.get("collection")?.text()? != collection
                || value.get("document")?.text()? != document
                || response.etag.as_deref() != Some(format!("\"{tag}\"").as_str())
            {
                return Err(Error::invalid("invalid document mutation receipt"));
            }
        }
        Receipt::Commit(count) => {
            value.keys(&["status", "operations", "revision"])?;
            if response.status != 200
                || value.get("status")?.text()? != "committed"
                || value.get("operations")?.uint()? != *count as u64
            {
                return Err(Error::invalid("invalid commit receipt"));
            }
        }
        Receipt::Delete => (),
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/cluster.rs"]
mod tests;
