//! Additive schema-2 raw operations and complete-page callback feeds.
use crate::{
    BinaryClient, BinaryOptions, Error, ErrorKind, MAX_DOCUMENT_BYTES, Result,
    binary::{invalid, utf8},
    binary_reply::{Metadata, metadata_schema},
    binary_wire::Wire,
    semantic::{self, Value},
    transport::Control,
};
use std::{fmt, sync::Arc, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BinaryOperationMethod {
    Get = 1,
    Post = 5,
    Patch = 6,
}
struct Operation {
    method: BinaryOperationMethod,
    target: String,
    content_type: String,
    source: Box<[u8]>,
    if_match: Option<String>,
    if_none_match: Option<String>,
    request_id: Option<[u8; 16]>,
}
/// Original immutable bytes and conditions; no credential or connection state.
#[derive(Clone)]
pub struct BinaryOperationEnvelope(Arc<Operation>);
impl BinaryOperationEnvelope {
    pub fn method(&self) -> BinaryOperationMethod {
        self.0.method
    }
    pub fn target(&self) -> &str {
        &self.0.target
    }
    pub fn content_type(&self) -> &str {
        &self.0.content_type
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
    pub fn is_mutation(&self) -> bool {
        self.method() == BinaryOperationMethod::Patch || self.target() == "/v1/transactions"
    }
}
impl fmt::Debug for BinaryOperationEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("yamora operation envelope (source redacted)")
    }
}
#[derive(Clone, Debug)]
pub struct BinaryOperationMetadata {
    pub status: u16,
    pub revision: String,
    pub etag: Option<String>,
    pub representation_length: usize,
    pub request_id: Option<[u8; 16]>,
    pub streaming: bool,
}
pub struct BinaryOperationResponse {
    pub metadata: BinaryOperationMetadata,
    body: Box<[u8]>,
}
impl BinaryOperationResponse {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}
impl fmt::Debug for BinaryOperationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BinaryOperationResponse")
            .field("metadata", &self.metadata)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}
#[derive(Debug)]
pub struct BinaryOperationError {
    pub kind: ErrorKind,
    pub metadata: Option<Box<BinaryOperationMetadata>>,
    pub last_after: Option<String>,
    pub response: Option<Box<BinaryOperationResponse>>,
    envelope: Option<BinaryOperationEnvelope>,
}
impl BinaryOperationError {
    pub fn envelope(&self) -> Option<&BinaryOperationEnvelope> {
        self.envelope.as_ref()
    }
    pub fn may_have_committed(&self) -> bool {
        self.envelope.is_some()
    }
}
impl From<Error> for BinaryOperationError {
    fn from(e: Error) -> Self {
        Self {
            kind: e.kind,
            metadata: None,
            last_after: None,
            response: None,
            envelope: None,
        }
    }
}
impl fmt::Display for BinaryOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "yamora operation: {:?}{}",
            self.kind,
            if self.may_have_committed() {
                "; mutation outcome uncertain"
            } else {
                ""
            }
        )
    }
}
impl std::error::Error for BinaryOperationError {}
/// Borrowed only during the callback. Bytes include the original complete LF.
pub struct BinaryChangePage {
    bytes: Box<[u8]>,
    pub after: String,
    pub terminal_status: Option<u16>,
}
impl BinaryChangePage {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl fmt::Debug for BinaryChangePage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BinaryChangePage")
            .field("bytes", &self.bytes.len())
            .field("terminal_status", &self.terminal_status)
            .finish()
    }
}
#[derive(Debug)]
pub struct BinaryFeedResult {
    pub metadata: BinaryOperationMetadata,
    pub last_after: Option<String>,
    pub terminal_status: Option<u16>,
}

fn prepare(
    method: BinaryOperationMethod,
    target: &str,
    content_type: &str,
    source: &[u8],
    options: &BinaryOptions<'_>,
    control: &Control,
) -> Result<BinaryOperationEnvelope> {
    let valid = match method {
        BinaryOperationMethod::Get => {
            source.is_empty()
                && content_type.is_empty()
                && (target == "/v1/changes"
                    || target.starts_with("/v1/changes?")
                    || target.starts_with("/v1/changes/stream?"))
        }
        BinaryOperationMethod::Post => {
            target == "/v1/transactions"
                || ["/v1/query/", "/v1/aggregate/", "/v1/search/"]
                    .iter()
                    .any(|p| target.strip_prefix(p).is_some_and(|n| crate::id(n).is_ok()))
        }
        BinaryOperationMethod::Patch => document_names(target).is_ok(),
    };
    let base = content_type.split(';').next().unwrap_or("");
    if !valid
        || target.len() > 1024
        || !target.bytes().all(|b| (33..=126).contains(&b) && b != b'#')
        || source.len() > MAX_DOCUMENT_BYTES
        || content_type.len() > 95
        || !content_type.bytes().all(|b| (32..=126).contains(&b))
        || (method != BinaryOperationMethod::Get
            && !["application/json", "application/yaml", "text/yaml"]
                .iter()
                .any(|v| base.eq_ignore_ascii_case(v)))
        || options.request_id == Some([0; 16])
        || [options.if_match, options.if_none_match]
            .into_iter()
            .flatten()
            .any(|v| v.len() > 31 || !v.bytes().all(|b| (32..=126).contains(&b)))
    {
        return Err(invalid());
    }
    let mutation = method == BinaryOperationMethod::Patch || target == "/v1/transactions";
    let id = if mutation && options.request_id.is_none() {
        Some(crate::tls::binary_random()?)
    } else {
        options.request_id
    };
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(source.len())
        .map_err(|_| invalid())?;
    for part in source.chunks(4096) {
        control.remaining()?;
        bytes.extend_from_slice(part);
    }
    utf8(&bytes, control)?;
    Ok(BinaryOperationEnvelope(Arc::new(Operation {
        method,
        target: target.into(),
        content_type: content_type.into(),
        source: bytes.into_boxed_slice(),
        if_match: options.if_match.map(str::to_owned),
        if_none_match: options.if_none_match.map(str::to_owned),
        request_id: id,
    })))
}
fn document_names(target: &str) -> Result<(&str, &str)> {
    let (collection, document) = target
        .strip_prefix("/v1/collections/")
        .and_then(|s| s.split_once("/documents/"))
        .ok_or_else(invalid)?;
    crate::id(collection)?;
    crate::id(document)?;
    Ok((collection, document))
}
fn request(
    e: &BinaryOperationEnvelope,
    bearer: Option<&str>,
    control: &Control,
) -> Result<Vec<u8>> {
    let mut fields: Vec<(u16, Vec<u8>)> = vec![
        (1, vec![e.method() as u8]),
        (2, e.target().as_bytes().to_vec()),
        (3, e.content_type().as_bytes().to_vec()),
        (4, (e.source().len() as u64).to_be_bytes().to_vec()),
    ];
    if let Some(b) = bearer {
        fields.push((5, format!("Bearer {b}").into_bytes()));
    }
    if let Some(v) = e.if_match() {
        fields.push((6, v.as_bytes().to_vec()));
    }
    if let Some(v) = e.if_none_match() {
        fields.push((7, v.as_bytes().to_vec()));
    }
    if let Some(v) = e.request_id() {
        fields.push((8, v.to_vec()));
    }
    fields.push((
        9,
        (control.remaining()?.as_millis().clamp(1, 30000) as u32)
            .to_be_bytes()
            .to_vec(),
    ));
    let mut out = vec![0, 2];
    out.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for (id, bytes) in fields {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&bytes);
    }
    if out.len() > 2048 {
        return Err(invalid());
    }
    Ok(out)
}
fn metadata(m: &Metadata) -> BinaryOperationMetadata {
    BinaryOperationMetadata {
        status: m.status,
        revision: m.revision.clone(),
        etag: m.etag.clone(),
        representation_length: m.representation,
        request_id: m.id,
        streaming: m.streaming,
    }
}
fn correlate(m: &Metadata, e: &BinaryOperationEnvelope, feed: bool) -> Result<()> {
    if m.id != e.request_id()
        || m.length != m.representation
        || (m.status == 401 && !m.authenticate)
        || (m.status == 405 && !m.allow)
    {
        return Err(invalid());
    }
    if e.method() == BinaryOperationMethod::Patch {
        let (c, d) = document_names(e.target())?;
        if m.collection.as_deref().is_some_and(|v| v != c)
            || m.document.as_deref().is_some_and(|v| v != d)
        {
            return Err(invalid());
        }
    } else if m.collection.is_some() || m.document.is_some() || m.etag.is_some() {
        return Err(invalid());
    }
    let base = m.media.split(';').next().unwrap_or("");
    if m.streaming {
        if !feed
            || m.status != 200
            || m.length != 0
            || !base.eq_ignore_ascii_case("application/x-ndjson")
            || m.etag.is_some()
        {
            return Err(invalid());
        }
    } else if !base.eq_ignore_ascii_case("application/json")
        || (feed && m.status < 400)
        || (m.status < 400 && m.status != 200)
        || ((e.is_mutation() || m.status >= 400) && !(1..=4096).contains(&m.length))
    {
        return Err(invalid());
    }
    Ok(())
}
fn exact(v: &Value, keys: &[&str]) -> Result<()> {
    v.keys(keys)?;
    if v.map()?.len() != keys.len() {
        return Err(invalid());
    }
    Ok(())
}
fn finite_body(
    m: &Metadata,
    e: &BinaryOperationEnvelope,
    body: &[u8],
    control: &Control,
) -> Result<()> {
    control.remaining()?;
    let v = semantic::decode_controlled(body, control)?;
    if m.status >= 400 {
        exact(&v, &["error"])?;
        let error = v.get("error")?.text()?;
        if error.is_empty()
            || error.len() > 128
            || !error
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(invalid());
        }
    } else if e.method() == BinaryOperationMethod::Patch {
        exact(
            &v,
            &["status", "collection", "document", "etag", "revision"],
        )?;
        let (c, d) = document_names(e.target())?;
        let tag = v.get("etag")?.text()?;
        if v.get("status")?.text()? != "stored"
            || v.get("collection")?.text()? != c
            || v.get("document")?.text()? != d
            || v.get("revision")?.text()? != m.revision
            || !crate::hex(tag, 16)
            || m.etag.as_deref() != Some(format!("\"{tag}\"").as_str())
        {
            return Err(invalid());
        }
    } else if e.target() == "/v1/transactions" {
        exact(&v, &["status", "operations", "revision"])?;
        if v.get("status")?.text()? != "committed"
            || v.get("revision")?.text()? != m.revision
            || !(1..=128).contains(&v.get("operations")?.uint()?)
        {
            return Err(invalid());
        }
    } else if e.target().starts_with("/v1/changes") {
        change(&v, None)?;
        if v.get("revision")?.text()? != m.revision {
            return Err(invalid());
        }
    } else if v.get("revision")?.text()? != m.revision {
        return Err(invalid());
    }
    control.remaining()?;
    Ok(())
}
fn token(t: &str) -> bool {
    t.len() == 52
        && t.starts_with("v1.")
        && t.as_bytes()[35] == b'.'
        && t.bytes()
            .enumerate()
            .all(|(i, b)| i < 3 || i == 35 || b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn change(v: &Value, last: Option<&str>) -> Result<(String, Option<u16>)> {
    if v.optional("terminal")?.is_some() {
        exact(v, &["terminal", "status", "after", "detail"])?;
        let after = v.get("after")?.text()?;
        let status = v.get("status")?.uint()?;
        v.get("detail")?.map()?;
        if !v.get("terminal")?.boolean()?
            || !(400..=599).contains(&status)
            || !token(after)
            || last.is_some_and(|t| t != after)
        {
            return Err(invalid());
        }
        return Ok((after.into(), Some(status as u16)));
    }
    exact(
        v,
        &[
            "transactions",
            "next_after",
            "oldest_after",
            "checkpoint",
            "revision",
            "has_more",
        ],
    )?;
    let next = v.get("next_after")?.text()?;
    let oldest = v.get("oldest_after")?.text()?;
    let checkpoint = v.get("checkpoint")?.text()?;
    if !token(next)
        || !token(oldest)
        || !token(checkpoint)
        || !crate::hex(v.get("revision")?.text()?, 16)
        || [Some(oldest), Some(checkpoint), last]
            .into_iter()
            .flatten()
            .any(|t| !token(t) || t[..36] != next[..36])
        || oldest[36..] > next[36..]
        || next[36..] > checkpoint[36..]
        || last.is_some_and(|t| next[36..] < t[36..])
    {
        return Err(invalid());
    }
    let transactions = v.get("transactions")?.array()?;
    let more = v.get("has_more")?.boolean()?;
    if transactions.len() > 100 || (more && transactions.is_empty()) {
        return Err(invalid());
    }
    let mut previous = last;
    for txn in transactions {
        exact(
            txn,
            &[
                "token",
                "previous_revision",
                "revision",
                "resnapshot_required",
                "operations",
            ],
        )?;
        let t = txn.get("token")?.text()?;
        let ops = txn.get("operations")?.array()?;
        if !token(t)
            || t[..36] != next[..36]
            || previous.is_some_and(|p| t[36..] <= p[36..])
            || !crate::hex(txn.get("revision")?.text()?, 16)
            || !crate::hex(txn.get("previous_revision")?.text()?, 16)
            || ops.len() > 256
            || (txn.get("resnapshot_required")?.boolean()? && !ops.is_empty())
        {
            return Err(invalid());
        }
        for op in ops {
            crate::id(op.get("collection")?.text()?)?;
            if op.optional("create_collection")?.is_some() {
                exact(op, &["collection", "create_collection"])?;
                if !op.get("create_collection")?.boolean()? {
                    return Err(invalid());
                }
            } else {
                crate::id(op.get("document")?.text()?)?;
                if op.optional("put")?.is_some() {
                    exact(op, &["collection", "document", "put"])?;
                    op.get("put")?.text()?;
                } else {
                    exact(op, &["collection", "document", "delete"])?;
                    if !op.get("delete")?.boolean()? {
                        return Err(invalid());
                    }
                }
            }
        }
        previous = Some(t);
    }
    if previous.is_some_and(|t| t != next) {
        return Err(invalid());
    }
    Ok((next.into(), None))
}
fn page(bytes: Vec<u8>, last: &str, control: &Control) -> Result<BinaryChangePage> {
    if bytes.last() != Some(&b'\n')
        || bytes[..bytes.len() - 1].contains(&b'\n')
        || bytes.contains(&b'\r')
    {
        return Err(invalid());
    }
    control.remaining()?;
    let (after, terminal_status) = change(
        &semantic::decode_controlled(&bytes[..bytes.len() - 1], control)?,
        Some(last),
    )?;
    control.remaining()?;
    Ok(BinaryChangePage {
        bytes: bytes.into_boxed_slice(),
        after,
        terminal_status,
    })
}

enum Output {
    Finite(BinaryOperationResponse),
    Feed(BinaryFeedResult),
}
impl BinaryClient {
    pub fn operation(
        &self,
        method: BinaryOperationMethod,
        target: &str,
        content_type: &str,
        source: &[u8],
        options: BinaryOptions<'_>,
    ) -> std::result::Result<BinaryOperationResponse, BinaryOperationError> {
        match self.operation_run(method, target, content_type, source, options, None)? {
            Output::Finite(v) => Ok(v),
            Output::Feed(_) => Err(invalid().into()),
        }
    }
    /// Returning false cancels after that complete page. No next page is read
    /// until the callback returns; the caller controls any retained copies.
    pub fn feed<F: FnMut(&BinaryChangePage) -> bool>(
        &self,
        target: &str,
        options: BinaryOptions<'_>,
        mut callback: F,
    ) -> std::result::Result<BinaryFeedResult, BinaryOperationError> {
        match self.operation_run(
            BinaryOperationMethod::Get,
            target,
            "",
            &[],
            options,
            Some(&mut callback),
        )? {
            Output::Feed(v) => Ok(v),
            Output::Finite(_) => Err(invalid().into()),
        }
    }
    fn operation_run(
        &self,
        method: BinaryOperationMethod,
        target: &str,
        content_type: &str,
        source: &[u8],
        options: BinaryOptions<'_>,
        mut callback: Option<&mut dyn FnMut(&BinaryChangePage) -> bool>,
    ) -> std::result::Result<Output, BinaryOperationError> {
        let control = Control {
            deadline: Instant::now() + self.config.timeout,
            cancellation: options.cancellation.cloned(),
        };
        let _admission = self.admit(&control)?;
        let e = prepare(method, target, content_type, source, &options, &control)?;
        let feed = callback.is_some();
        if feed != e.target().starts_with("/v1/changes/stream?")
            || options.bearer.is_some_and(|b| {
                b.is_empty() || b.len() > 512 || !b.bytes().all(|b| (33..=126).contains(&b))
            })
        {
            return Err(invalid().into());
        }
        let socket = crate::socket::connect(self.address.into(), &control)?;
        socket.set_nodelay(true).map_err(crate::transport::io)?;
        let stream = crate::tls::Stream::connect_binary(socket, control.clone(), &self.config.tls)?;
        let mut wire = Wire::new(stream, self.config.max_frame_bytes, control.clone());
        wire.hello_protocol(2)?;
        let metadata_bytes = request(&e, options.bearer, &control)?;
        control.remaining()?;
        let mut observed = None;
        let mut last: Option<String> = None;
        let mut response = None;
        let result = (|| -> Result<Output> {
            wire.send(2, 1, &metadata_bytes)?;
            for part in e.source().chunks(wire.cap) {
                wire.send(4, 1, part)?;
            }
            wire.send(5, 1, &[])?;
            let mut m: Option<Metadata> = None;
            let mut body = Vec::new();
            let mut total = 0usize;
            let mut terminal = None;
            let mut goaway = false;
            let resume = target
                .split_once('?')
                .into_iter()
                .flat_map(|(_, q)| q.split('&'))
                .filter_map(|p| p.strip_prefix("after="))
                .find(|p| token(p));
            loop {
                control.remaining()?;
                let next = wire.receive()?;
                if next.kind == 10 {
                    if goaway {
                        return Err(invalid());
                    }
                    goaway = true;
                    continue;
                }
                if next.kind == 7 {
                    if next.body == [0; 4] {
                        return Err(invalid());
                    }
                    return Err(Error::new(ErrorKind::Io(
                        std::io::ErrorKind::ConnectionAborted,
                    )));
                }
                if next.kind == 3 {
                    if m.is_some() {
                        return Err(invalid());
                    }
                    let decoded = metadata_schema(&next.body, 2)?;
                    correlate(&decoded, &e, feed)?;
                    observed = Some(metadata(&decoded));
                    m = Some(decoded);
                    continue;
                }
                let m = m.as_ref().ok_or_else(invalid)?;
                match next.kind {
                    4 => {
                        total = total.checked_add(next.body.len()).ok_or_else(invalid)?;
                        if total > MAX_DOCUMENT_BYTES || terminal.is_some() {
                            return Err(invalid());
                        }
                        if !m.streaming {
                            if next.body.len() > m.length - body.len() {
                                return Err(invalid());
                            }
                            body.extend_from_slice(&next.body);
                            continue;
                        }
                        let mut offset = 0;
                        while offset < next.body.len() {
                            if terminal.is_some() {
                                return Err(invalid());
                            }
                            let lf = next.body[offset..]
                                .iter()
                                .position(|b| *b == b'\n')
                                .map(|p| offset + p);
                            let end = lf.map_or(next.body.len(), |p| p + 1);
                            body.extend_from_slice(&next.body[offset..end]);
                            offset = end;
                            if lf.is_none() {
                                break;
                            }
                            let delivered = page(
                                std::mem::take(&mut body),
                                last.as_deref().or(resume).ok_or_else(invalid)?,
                                &control,
                            )?;
                            control.remaining()?;
                            let accepted = callback.as_mut().ok_or_else(invalid)?(&delivered);
                            last = Some(delivered.after.clone());
                            terminal = delivered.terminal_status;
                            if !accepted {
                                return Err(Error::new(ErrorKind::Cancelled));
                            }
                            control.remaining()?;
                        }
                    }
                    5 => {
                        control.remaining()?;
                        if m.streaming {
                            if !body.is_empty() || last.is_none() {
                                return Err(invalid());
                            }
                            return Ok(Output::Feed(BinaryFeedResult {
                                metadata: metadata(m),
                                last_after: last.clone(),
                                terminal_status: terminal,
                            }));
                        }
                        if body.len() != m.length {
                            return Err(invalid());
                        }
                        finite_body(m, &e, &body, &control)?;
                        let value = BinaryOperationResponse {
                            metadata: metadata(m),
                            body: body.into_boxed_slice(),
                        };
                        if m.status >= 400 {
                            response = Some(value);
                            return Err(Error::new(ErrorKind::Http(m.status)));
                        }
                        return Ok(Output::Finite(value));
                    }
                    _ => return Err(invalid()),
                }
            }
        })();
        let result = match control.remaining() {
            Ok(_) => result,
            Err(e) => Err(e),
        };
        result.map_err(|error| BinaryOperationError {
            envelope: (e.is_mutation()
                && !matches!(error.kind, ErrorKind::Http(400..=407 | 409..=499)))
            .then(|| e.clone()),
            kind: error.kind,
            metadata: observed.map(Box::new),
            last_after: last,
            response: response.map(Box::new),
        })
    }
}

#[cfg(test)]
#[path = "tests/binary_operations.rs"]
mod tests;
