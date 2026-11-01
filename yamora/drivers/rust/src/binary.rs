//! One verified TLS connection per operation, with no routing or automatic replay.
use crate::{
    CancellationToken, Error, ErrorKind, MAX_DOCUMENT_BYTES, binary_wire::Wire, transport::Control,
};
use std::{
    fmt,
    net::SocketAddrV4,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

/// Only static PEM bytes are accepted; no opaque contexts, callbacks or paths.
/// Ownership transfers to the client. No certificate/key material is formatted.
#[derive(Clone)]
pub struct BinaryIdentity {
    pub certificate_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
}
#[derive(Clone)]
pub struct BinaryTlsConfig {
    pub root_pem: Vec<u8>,
    /// Expected DNS SAN (also SNI), or canonical IPv4 SAN. Never used for routing.
    pub server_name: String,
    pub identity: Option<BinaryIdentity>,
}
pub struct BinaryConfig {
    pub endpoint: String,
    pub tls: BinaryTlsConfig,
    pub timeout: Duration,
    pub max_frame_bytes: usize,
    pub max_concurrent_calls: usize,
}
impl BinaryConfig {
    pub fn new(endpoint: String, tls: BinaryTlsConfig) -> Self {
        Self {
            endpoint,
            tls,
            timeout: Duration::from_secs(5),
            max_frame_bytes: 65536,
            max_concurrent_calls: 4,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BinaryMethod {
    Get = 1,
    Head = 2,
    Put = 3,
    Delete = 4,
}
impl BinaryMethod {
    pub fn is_mutation(self) -> bool {
        matches!(self, Self::Put | Self::Delete)
    }
}
/// Borrowed primitive input. Waiting callers retain only these references. No
/// conversion hooks run; source is copied only after admission. Rust borrowing
/// prevents safe concurrent mutation of borrowed input during the call.
#[derive(Default)]
pub struct BinaryOptions<'a> {
    pub bearer: Option<&'a str>,
    pub if_match: Option<&'a str>,
    pub if_none_match: Option<&'a str>,
    pub request_id: Option<[u8; 16]>,
    pub cancellation: Option<&'a CancellationToken>,
}
struct Operation {
    method: BinaryMethod,
    collection: String,
    document: String,
    source: Box<[u8]>,
    if_match: Option<String>,
    if_none_match: Option<String>,
    request_id: Option<[u8; 16]>,
}
/// Immutable original operation, deliberately without bearer credentials. Clones
/// share immutable storage; accessors never expose mutable backing buffers.
#[derive(Clone)]
pub struct BinaryEnvelope(Arc<Operation>);
impl BinaryEnvelope {
    pub fn method(&self) -> BinaryMethod {
        self.0.method
    }
    pub fn collection(&self) -> &str {
        &self.0.collection
    }
    pub fn document(&self) -> &str {
        &self.0.document
    }
    pub fn source(&self) -> &[u8] {
        &self.0.source
    }
    pub fn if_match(&self) -> Option<&str> {
        self.0.if_match.as_deref()
    }
    pub fn if_none_match(&self) -> Option<&str> {
        self.0.if_none_match.as_deref()
    }
    pub fn request_id(&self) -> Option<[u8; 16]> {
        self.0.request_id
    }
}
impl fmt::Debug for BinaryEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("yamora binary envelope (source redacted)")
    }
}
#[derive(Debug)]
pub struct BinaryError {
    pub kind: ErrorKind,
    envelope: Option<BinaryEnvelope>,
}
impl BinaryError {
    pub fn envelope(&self) -> Option<&BinaryEnvelope> {
        self.envelope.as_ref()
    }
    pub fn may_have_committed(&self) -> bool {
        self.envelope.is_some()
    }
}
impl From<Error> for BinaryError {
    fn from(e: Error) -> Self {
        Self {
            kind: e.kind,
            envelope: None,
        }
    }
}
impl fmt::Display for BinaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "yamora binary: {:?}{}",
            self.kind,
            if self.may_have_committed() {
                "; write outcome uncertain; retain original envelope"
            } else {
                ""
            }
        )
    }
}
impl std::error::Error for BinaryError {}
/// Validated metadata and immutable body. HEAD retains representation_length.
pub struct BinaryResponse {
    pub status: u16,
    pub revision: String,
    pub etag: Option<String>,
    pub representation_length: usize,
    body: Box<[u8]>,
}
impl BinaryResponse {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub(crate) fn new(
        status: u16,
        revision: String,
        etag: Option<String>,
        representation_length: usize,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            revision,
            etag,
            representation_length,
            body: body.into_boxed_slice(),
        }
    }
}
impl fmt::Debug for BinaryResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BinaryResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}
pub struct BinaryClient {
    pub(crate) config: BinaryConfig,
    pub(crate) address: SocketAddrV4,
    slots: Mutex<usize>,
    available: Condvar,
}
pub(crate) struct Admission<'a>(&'a BinaryClient);
impl Drop for Admission<'_> {
    fn drop(&mut self) {
        let mut slots = self.0.slots.lock().unwrap_or_else(|e| e.into_inner());
        *slots -= 1;
        self.0.available.notify_one();
    }
}
impl BinaryClient {
    pub fn new(config: BinaryConfig) -> Result<Self, BinaryError> {
        let address = config
            .endpoint
            .parse::<SocketAddrV4>()
            .map_err(|_| invalid())?;
        if address.port() == 0
            || address.port() == 8000
            || address.to_string() != config.endpoint
            || !(address.ip().is_loopback() || address.ip().is_private())
            || config.timeout.is_zero()
            || config.timeout > Duration::from_secs(30)
            || !(4096..=65536).contains(&config.max_frame_bytes)
            || !(1..=4).contains(&config.max_concurrent_calls)
        {
            return Err(invalid().into());
        }
        let name = &config.tls.server_name;
        let valid_name = if let Ok(ip) = name.parse::<std::net::Ipv4Addr>() {
            ip.to_string() == *name
        } else {
            !name.is_empty()
                && name.len() <= 253
                && !name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                && name.split('.').all(|part| {
                    !part.is_empty()
                        && part.len() <= 63
                        && !part.starts_with('-')
                        && !part.ends_with('-')
                        && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        };
        if !valid_name {
            return Err(invalid().into());
        }
        crate::tls::validate_binary(&config.tls)?;
        Ok(Self {
            config,
            address,
            slots: Mutex::new(0),
            available: Condvar::new(),
        })
    }
    pub(crate) fn admit(&self, control: &Control) -> crate::Result<Admission<'_>> {
        let mut slots = self.slots.lock().map_err(|_| invalid())?;
        loop {
            let wait = control.remaining()?.min(Duration::from_millis(10));
            if *slots < self.config.max_concurrent_calls {
                *slots += 1;
                return Ok(Admission(self));
            }
            slots = self
                .available
                .wait_timeout(slots, wait)
                .map_err(|_| invalid())?
                .0;
        }
    }
    pub fn get(
        &self,
        c: &str,
        d: &str,
        options: BinaryOptions<'_>,
    ) -> Result<BinaryResponse, BinaryError> {
        self.call(BinaryMethod::Get, c, d, &[], options)
    }
    pub fn head(
        &self,
        c: &str,
        d: &str,
        options: BinaryOptions<'_>,
    ) -> Result<BinaryResponse, BinaryError> {
        self.call(BinaryMethod::Head, c, d, &[], options)
    }
    pub fn put(
        &self,
        c: &str,
        d: &str,
        source: &[u8],
        options: BinaryOptions<'_>,
    ) -> Result<BinaryResponse, BinaryError> {
        self.call(BinaryMethod::Put, c, d, source, options)
    }
    pub fn delete(
        &self,
        c: &str,
        d: &str,
        options: BinaryOptions<'_>,
    ) -> Result<BinaryResponse, BinaryError> {
        self.call(BinaryMethod::Delete, c, d, &[], options)
    }
    pub fn call(
        &self,
        method: BinaryMethod,
        c: &str,
        d: &str,
        source: &[u8],
        options: BinaryOptions<'_>,
    ) -> Result<BinaryResponse, BinaryError> {
        let control = Control {
            deadline: Instant::now() + self.config.timeout,
            cancellation: options.cancellation.cloned(),
        };
        let _admission = self.admit(&control)?;
        crate::document_path(c, d)?;
        for condition in [options.if_match, options.if_none_match]
            .into_iter()
            .flatten()
        {
            if condition.len() > 31 || !condition.bytes().all(|b| (32..=126).contains(&b)) {
                return Err(invalid().into());
            }
        }
        if options.request_id == Some([0; 16])
            || (method != BinaryMethod::Put && !source.is_empty())
            || source.len() > MAX_DOCUMENT_BYTES
            || (method == BinaryMethod::Put && source.is_empty())
        {
            return Err(invalid().into());
        }
        let request_id = if method.is_mutation() && options.request_id.is_none() {
            Some(crate::tls::binary_random()?)
        } else {
            options.request_id
        };
        let mut frozen = Vec::new();
        frozen
            .try_reserve_exact(source.len())
            .map_err(|_| invalid())?;
        for part in source.chunks(4096) {
            control.remaining()?;
            frozen.extend_from_slice(part);
        }
        utf8(&frozen, &control)?;
        let envelope = BinaryEnvelope(Arc::new(Operation {
            method,
            collection: c.to_owned(),
            document: d.to_owned(),
            source: frozen.into_boxed_slice(),
            if_match: options.if_match.map(str::to_owned),
            if_none_match: options.if_none_match.map(str::to_owned),
            request_id,
        }));
        self.execute(&envelope, options.bearer, &control)
    }
    /// Explicit repetition of precisely the original operation. This is a new
    /// call and deadline with a newly supplied credential. Standalone storage
    /// has no deduplication guarantee; inspect stored source before repeating.
    pub fn replay(
        &self,
        envelope: &BinaryEnvelope,
        bearer: Option<&str>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<BinaryResponse, BinaryError> {
        let control = Control {
            deadline: Instant::now() + self.config.timeout,
            cancellation: cancellation.cloned(),
        };
        let _admission = self.admit(&control)?;
        self.execute(envelope, bearer, &control)
    }
    fn execute(
        &self,
        envelope: &BinaryEnvelope,
        bearer: Option<&str>,
        control: &Control,
    ) -> Result<BinaryResponse, BinaryError> {
        if bearer.is_some_and(|token| {
            token.is_empty() || token.len() > 512 || !token.bytes().all(|b| (33..=126).contains(&b))
        }) {
            return Err(invalid().into());
        }
        control.remaining()?;
        let socket = crate::socket::connect(self.address.into(), control)?;
        socket.set_nodelay(true).map_err(crate::transport::io)?;
        let stream = crate::tls::Stream::connect_binary(socket, control.clone(), &self.config.tls)?;
        let mut wire = Wire::new(stream, self.config.max_frame_bytes, control.clone());
        wire.hello()?;
        let metadata = crate::binary_wire::request(envelope, bearer, control)?;
        control.remaining()?;
        // From the first attempted REQUEST write, every ambiguous error keeps
        // the original immutable operation. No reconnect or implicit retry.
        let result = (|| {
            wire.send(2, 1, &metadata)?;
            for part in envelope.source().chunks(wire.cap) {
                wire.send(4, 1, part)?;
            }
            wire.send(5, 1, &[])?;
            let response = crate::binary_reply::receive(&mut wire, envelope, control)?;
            control.remaining()?;
            Ok(response)
        })();
        // Guard failed typed receipts too: a cancellation/deadline race after
        // validation must retain a dispatched mutation's original envelope.
        let result = match control.remaining() {
            Ok(_) => result,
            Err(error) => Err(error),
        };
        result.map_err(|error: Error| {
            let uncertain = envelope.method().is_mutation()
                && !matches!(error.kind, ErrorKind::Http(400..=407 | 409..=499));
            BinaryError {
                kind: error.kind,
                envelope: uncertain.then(|| envelope.clone()),
            }
        })
    }
}
pub(crate) fn invalid() -> Error {
    Error::invalid("invalid binary input or response")
}
pub(crate) fn utf8(source: &[u8], control: &Control) -> crate::Result<()> {
    let mut offset = 0;
    while offset < source.len() {
        control.remaining()?;
        let end = (offset + 4096).min(source.len());
        match std::str::from_utf8(&source[offset..end]) {
            Ok(_) => offset = end,
            Err(error)
                if error.error_len().is_none() && end < source.len() && error.valid_up_to() > 0 =>
            {
                offset += error.valid_up_to()
            }
            Err(_) => return Err(invalid()),
        }
    }
    control.remaining()?;
    Ok(())
}
pub(crate) fn source_etag(source: &[u8], control: &Control) -> crate::Result<String> {
    utf8(source, control)?;
    let mut hash = 1469598103934665603u64;
    for part in source.chunks(4096) {
        control.remaining()?;
        for byte in part {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(1099511628211);
        }
    }
    control.remaining()?;
    Ok(format!("\"{hash:016x}\""))
}
