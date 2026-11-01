//! Persistent HTTP v2 observations through the public SDK only.
//! The parent owns fault injection, the outside watchdog and native qualification.
use std::{
    ffi::CString,
    fs::File,
    io::{self, BufRead, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
use yamora::{
    ClientIdentity, ClusterClient, ClusterConfig, ClusterError, ClusterSeed, Condition, ErrorKind,
    PreparedMutation, Response, TlsOptions, UncertainWriteError, WriteOptions,
};

type Result<T> = std::result::Result<T, ()>;
const LINE: usize = 16384;
const FILE: usize = 131072;
const COMMAND_SCHEMA: &str = "yamora-http-replica-command/2";

// Linux descriptor-relative opens pin the runner-owned root and reject every
// symlink component. NONBLOCK also prevents an input FIFO from hanging parsing.
unsafe extern "C" {
    fn openat(fd: i32, path: *const std::ffi::c_char, flags: i32, mode: u32) -> i32;
    fn getuid() -> u32;
}
const CLOEXEC: i32 = 0x80000;
const NOFOLLOW: i32 = 0x20000;
const DIRECTORY: i32 = 0x10000;
fn at(dir: &File, name: &str, flags: i32) -> Result<File> {
    let name = CString::new(name).map_err(|_| ())?;
    // SAFETY: name is NUL-terminated, dir stays open and a successful new fd
    // transfers exactly once to File. The mode is used only for output creation.
    let fd = unsafe {
        openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | CLOEXEC | NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn root(path: &Path) -> Result<File> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(());
    }
    if path
        .to_str()
        .ok_or(())?
        .split('/')
        .any(|p| p == "." || p == "..")
    {
        return Err(());
    }
    let mut dir = File::open("/").map_err(|_| ())?;
    let mut count = 0;
    for part in path.components() {
        match part {
            Component::RootDir => (),
            Component::Normal(name) => {
                dir = at(&dir, name.to_str().ok_or(())?, DIRECTORY)?;
                count += 1;
            }
            _ => return Err(()),
        }
    }
    let meta = dir.metadata().map_err(|_| ())?;
    if count == 0 || meta.uid() != unsafe { getuid() } {
        return Err(());
    }
    Ok(dir)
}
fn owned_file(dir: &File, name: &str) -> Result<File> {
    let file = at(dir, name, 0x800)?;
    let meta = file.metadata().map_err(|_| ())?;
    if !meta.is_file() || meta.uid() != unsafe { getuid() } || meta.len() > FILE as u64 {
        return Err(());
    }
    Ok(file)
}
fn read_file(file: &mut File, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(limit + 1).map_err(|_| ())?;
    bytes.resize(limit + 1, 0);
    let mut n = 0;
    while n < bytes.len() {
        let got = file.read(&mut bytes[n..]).map_err(|_| ())?;
        if got == 0 {
            break;
        }
        n += got;
    }
    if n > limit {
        return Err(());
    }
    bytes.truncate(n);
    Ok(bytes)
}
fn write_file(dir: &File, name: &str, bytes: &[u8]) -> Result<()> {
    if bytes.len() > FILE {
        return Err(());
    }
    // O_WRONLY | O_CREAT | O_EXCL: never overwrite runner or unknown files.
    let mut file = at(dir, name, 1 | 0x40 | 0x80)?;
    file.write_all(bytes).map_err(|_| ())
}

// The SDK's JSON modules are private. This small boundary parser accepts only
// the frozen profile's types, with decoded-key uniqueness and bounded depth.
#[derive(Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(u64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}
impl Json {
    fn text(&self) -> Result<&str> {
        if let Self::Str(v) = self {
            Ok(v)
        } else {
            Err(())
        }
    }
    fn num(&self) -> Result<u64> {
        if let Self::Num(v) = self {
            Ok(*v)
        } else {
            Err(())
        }
    }
    fn field(&self, key: &str) -> Result<&Json> {
        if let Self::Obj(v) = self {
            v.iter().find(|(k, _)| k == key).map(|(_, v)| v).ok_or(())
        } else {
            Err(())
        }
    }
    fn keys(&self, keys: &[&str]) -> Result<()> {
        if let Self::Obj(v) = self {
            if v.len() == keys.len() && v.iter().all(|(k, _)| keys.contains(&k.as_str())) {
                return Ok(());
            }
        }
        Err(())
    }
    fn optional(&self, key: &str) -> Result<Option<&str>> {
        match self.field(key)? {
            Self::Null => Ok(None),
            v => Ok(Some(v.text()?)),
        }
    }
}
struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    pos: usize,
    nodes: usize,
}
fn parse(bytes: &[u8]) -> Result<Json> {
    if bytes.len() > FILE {
        return Err(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut p = Parser {
        bytes,
        text,
        pos: 0,
        nodes: 0,
    };
    let value = p.value(0)?;
    p.space();
    if p.pos != bytes.len() {
        return Err(());
    }
    Ok(value)
}
impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\r' | b'\n' | b'\t')) {
            self.pos += 1;
        }
    }
    fn take(&mut self, byte: u8) -> Result<()> {
        if self.peek() != Some(byte) {
            return Err(());
        }
        self.pos += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<String> {
        self.take(b'"')?;
        let mut out = String::new();
        loop {
            let byte = self.peek().ok_or(())?;
            if byte == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            let ch = if byte == b'\\' {
                self.pos += 1;
                let escaped = self.peek().ok_or(())?;
                self.pos += 1;
                match escaped {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{8}',
                    b'f' => '\u{c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    b'u' => {
                        let high = self.hex()?;
                        let code = if (0xd800..=0xdbff).contains(&high) {
                            self.take(b'\\')?;
                            self.take(b'u')?;
                            let low = self.hex()?;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return Err(());
                            }
                            0x10000 + ((high - 0xd800) << 10) + low - 0xdc00
                        } else {
                            high
                        };
                        char::from_u32(code).ok_or(())?
                    }
                    _ => return Err(()),
                }
            } else {
                if byte < 32 {
                    return Err(());
                }
                let text = self.text.get(self.pos..).ok_or(())?;
                let ch = text.chars().next().ok_or(())?;
                self.pos += ch.len_utf8();
                ch
            };
            out.try_reserve(ch.len_utf8()).map_err(|_| ())?;
            out.push(ch);
        }
    }
    fn hex(&mut self) -> Result<u32> {
        let mut n = 0;
        for _ in 0..4 {
            n = n * 16 + char::from(self.peek().ok_or(())?).to_digit(16).ok_or(())?;
            self.pos += 1;
        }
        Ok(n)
    }
    fn value(&mut self, depth: usize) -> Result<Json> {
        self.nodes += 1;
        if depth > 12 || self.nodes > 4096 {
            return Err(());
        }
        self.space();
        match self.peek().ok_or(())? {
            b'"' => Ok(Json::Str(self.string()?)),
            b'{' => {
                if depth >= 12 {
                    return Err(());
                }
                self.pos += 1;
                self.space();
                let mut fields = Vec::new();
                if self.peek() != Some(b'}') {
                    loop {
                        let key = self.string()?;
                        if fields.iter().any(|(k, _)| k == &key) {
                            return Err(());
                        }
                        self.space();
                        self.take(b':')?;
                        let value = self.value(depth + 1)?;
                        fields.try_reserve(1).map_err(|_| ())?;
                        fields.push((key, value));
                        self.space();
                        if self.peek() == Some(b'}') {
                            break;
                        }
                        self.take(b',')?;
                        self.space();
                    }
                }
                self.take(b'}')?;
                Ok(Json::Obj(fields))
            }
            b'[' => {
                if depth >= 12 {
                    return Err(());
                }
                self.pos += 1;
                self.space();
                let mut values = Vec::new();
                if self.peek() != Some(b']') {
                    loop {
                        values.try_reserve(1).map_err(|_| ())?;
                        values.push(self.value(depth + 1)?);
                        self.space();
                        if self.peek() == Some(b']') {
                            break;
                        }
                        self.take(b',')?;
                        self.space();
                    }
                }
                self.take(b']')?;
                Ok(Json::Arr(values))
            }
            b'0'..=b'9' => {
                let start = self.pos;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
                let s = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| ())?;
                if s.len() > 1 && s.starts_with('0') {
                    return Err(());
                }
                Ok(Json::Num(s.parse().map_err(|_| ())?))
            }
            b'n' | b't' | b'f' => {
                let (word, value): (&[u8], Json) = match self.peek() {
                    Some(b'n') => (b"null", Json::Null),
                    Some(b't') => (b"true", Json::Bool(true)),
                    _ => (b"false", Json::Bool(false)),
                };
                if self.bytes.get(self.pos..self.pos + word.len()) != Some(word) {
                    return Err(());
                }
                self.pos += word.len();
                Ok(value)
            }
            _ => Err(()),
        }
    }
}
fn hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn token(dir: &File, name: &str) -> Result<String> {
    let bytes = read_file(&mut owned_file(dir, name)?, 512)?;
    let value = String::from_utf8(bytes).map_err(|_| ())?;
    if !(32..=512).contains(&value.len()) || !value.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(());
    }
    Ok(value)
}
struct Session {
    client: ClusterClient,
    root: File,
    // OpenSSL receives fixed /proc/self/fd paths for bounded, validated PEM
    // files. Keep descriptors alive so replacement of a runner path cannot
    // redirect later SDK retries to an unchecked file.
    _pem: Vec<File>,
    recovery: Vec<UncertainWriteError>,
}
impl Session {
    fn new(root: File) -> Result<Self> {
        let config = parse(&read_file(&mut owned_file(&root, "config.json")?, LINE)?)?;
        config.keys(&[
            "schema",
            "cluster_id",
            "voters",
            "seeds",
            "tls",
            "tokens",
            "timeout_ms",
            "attempt_timeout_ms",
        ])?;
        let cluster = config.field("cluster_id")?.text()?;
        if config.field("schema")?.text()? != "yamora-http-replica-config/2"
            || !hex(cluster, 32)
            || cluster.bytes().all(|b| b == b'0')
            || config.field("voters")?.num()? != 3
            || config.field("timeout_ms")?.num()? != 15000
            || config.field("attempt_timeout_ms")?.num()? != 3000
        {
            return Err(());
        }
        // This public SDK has no cluster-ID configuration field. Node bindings,
        // voter count and the fixture CA/SAN are the available trust controls.
        let tls = config.field("tls")?;
        tls.keys(&["ca_file", "cert_file", "key_file"])?;
        let mut pem = Vec::new();
        for (key, name) in [
            ("ca_file", "ca.pem"),
            ("cert_file", "client.pem"),
            ("key_file", "client.key"),
        ] {
            if tls.field(key)?.text()? != name {
                return Err(());
            }
            let mut file = owned_file(&root, name)?;
            if read_file(&mut file, LINE)?.is_empty() {
                return Err(());
            }
            pem.push(file);
        }
        let fd_path = |i: usize| PathBuf::from(format!("/proc/self/fd/{}", pem[i].as_raw_fd()));
        let tls = TlsOptions {
            ca_file: fd_path(0),
            identity: Some(ClientIdentity {
                certificate: fd_path(1),
                private_key: fd_path(2),
            }),
            server_name: None,
        };
        let tokens = config.field("tokens")?;
        tokens.keys(&["read_file", "write_file"])?;
        if tokens.field("read_file")?.text()? != "read.token"
            || tokens.field("write_file")?.text()? != "write.token"
        {
            return Err(());
        }
        let read_token = token(&root, "read.token")?;
        let write_token = token(&root, "write.token")?;
        let Json::Arr(seeds) = config.field("seeds")? else {
            return Err(());
        };
        if seeds.len() != 3 {
            return Err(());
        }
        let mut ports = Vec::new();
        let mut nodes = Vec::new();
        let mut configured = Vec::new();
        for seed in seeds {
            seed.keys(&["host", "port", "node"])?;
            let port = seed.field("port")?.num()?;
            let node = seed.field("node")?.num()?;
            if seed.field("host")?.text()? != "127.0.0.1"
                || port == 0
                || port > 65535
                || port == 8000
                || !(1..=3).contains(&node)
                || ports.contains(&port)
                || nodes.contains(&node)
            {
                return Err(());
            }
            ports.push(port);
            nodes.push(node);
            configured.push(ClusterSeed::new(
                format!("127.0.0.1:{port}"),
                node as u8,
                tls.clone(),
            ));
        }
        let mut config = ClusterConfig::new(configured, 3);
        config.timeout = Duration::from_millis(15000);
        config.attempt_timeout = Duration::from_millis(3000);
        config.max_response_bytes = FILE;
        config.read_token = Some(read_token);
        config.write_token = Some(write_token);
        Ok(Self {
            client: ClusterClient::new(config).map_err(|_| ())?,
            root,
            _pem: pem,
            recovery: Vec::new(),
        })
    }
}

struct Call<'a> {
    method: &'a str,
    collection: &'a str,
    document: &'a str,
    source: Vec<u8>,
    request_id: Option<&'a str>,
    condition: Condition<'a>,
}
impl<'a> Call<'a> {
    fn parse(value: &'a Json, root: &File) -> Result<Self> {
        value.keys(&[
            "schema",
            "seq",
            "action",
            "method",
            "collection",
            "document",
            "source_file",
            "request_id",
            "if_match",
            "if_none_match",
        ])?;
        let method = value.field("method")?.text()?;
        let collection = value.field("collection")?.text()?;
        let document = value.field("document")?.text()?;
        let request_id = value.optional("request_id")?;
        let matching = value.optional("if_match")?;
        let create = value.optional("if_none_match")?;
        let file = value.optional("source_file")?;
        if !["GET", "PUT", "PATCH", "DELETE"].contains(&method)
            || !identifier(collection, 128)
            || !identifier(document, 128)
            || (method != "GET" && collection == "yamldb-system")
            || request_id.is_some_and(|s| !hex(s, 32) || s.bytes().all(|b| b == b'0'))
        {
            return Err(());
        }
        if matching.is_some_and(|s| {
            s.len() != 18 || !s.starts_with('"') || !s.ends_with('"') || !hex(&s[1..17], 16)
        }) || create.is_some_and(|s| s != "*" || method != "PUT")
            || (matching.is_some() && create.is_some())
            || (method == "GET" && (request_id.is_some() || matching.is_some() || create.is_some()))
        {
            return Err(());
        }
        let source = if ["PUT", "PATCH"].contains(&method) {
            let file = file.ok_or(())?;
            let name = file.strip_prefix("input/").ok_or(())?;
            if !identifier(name.strip_suffix(".bin").ok_or(())?, 64) {
                return Err(());
            }
            let input = at(root, "input", DIRECTORY)?;
            let source = read_file(&mut owned_file(&input, name)?, FILE)?;
            if source.is_empty() || std::str::from_utf8(&source).is_err() {
                return Err(());
            }
            if method == "PATCH" {
                let patch = parse(&source)?;
                patch.keys(&["$inc"])?;
                let inc = patch.field("$inc")?;
                inc.keys(&["n"])?;
                if inc.field("n")?.num()? != 1 {
                    return Err(());
                }
            }
            source
        } else {
            if file.is_some() {
                return Err(());
            }
            Vec::new()
        };
        let condition = match (matching, create) {
            (Some(tag), _) => Condition::IfMatch(&tag[1..17]),
            (_, Some(_)) => Condition::CreateOnly,
            _ => Condition::Any,
        };
        Ok(Self {
            method,
            collection,
            document,
            source,
            request_id,
            condition,
        })
    }
    fn prepare(&self, client: &ClusterClient) -> yamora::Result<PreparedMutation> {
        let options = WriteOptions {
            condition: self.condition,
            request_id: self.request_id,
        };
        match self.method {
            "PUT" => client.prepare_put(self.collection, self.document, &self.source, options),
            "PATCH" => client.prepare_patch(self.collection, self.document, &self.source, options),
            "DELETE" => client.prepare_delete(self.collection, self.document, options),
            _ => unreachable!("validated mutation"),
        }
    }
}

// One bounded writer for the complete observation: API values cannot expand
// into an unbounded diagnostic or JSON line. Files carry raw bytes separately.
struct Output(String);
impl Output {
    fn new() -> Result<Self> {
        let mut s = String::new();
        s.try_reserve_exact(LINE).map_err(|_| ())?;
        Ok(Self(s))
    }
    fn raw(&mut self, s: &str) -> Result<()> {
        if self.0.len() + s.len() >= LINE {
            return Err(());
        }
        self.0.push_str(s);
        Ok(())
    }
    fn string(&mut self, s: &str) -> Result<()> {
        self.raw("\"")?;
        for ch in s.chars() {
            match ch {
                '"' => self.raw("\\\"")?,
                '\\' => self.raw("\\\\")?,
                '\u{0}'..='\u{1f}' => self.raw(&format!("\\u{:04x}", ch as u32))?,
                _ => self.raw(ch.encode_utf8(&mut [0; 4]))?,
            }
        }
        self.raw("\"")
    }
    fn optional(&mut self, s: Option<&str>) -> Result<()> {
        match s {
            Some(s) => self.string(s),
            None => self.raw("null"),
        }
    }
}
#[derive(Default)]
struct Observation<'a> {
    outcome: &'a str,
    kind: Option<&'a str>,
    elapsed: u128,
    status: Option<u16>,
    body: Option<&'a [u8]>,
    etag: Option<&'a str>,
    revision: Option<&'a str>,
    uncertainty: Option<&'a UncertainWriteError>,
    handle: Option<usize>,
}
fn category(kind: &ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Http(_) | ErrorKind::SchemaPolicyReplicationUnsupported => "status",
        ErrorKind::Timeout => "deadline",
        ErrorKind::Cancelled => "cancelled",
        ErrorKind::Invalid(_) => "protocol",
        ErrorKind::Io(_) | ErrorKind::Tls => "transport",
        ErrorKind::ClusterUncertain(v) => category(&v.cause.kind),
    }
}
fn from_error(error: &ClusterError, elapsed: u128, handle: Option<usize>) -> Observation<'_> {
    let (cause, uncertainty) = match error {
        ClusterError::Failure(e) => (e, None),
        ClusterError::Uncertain(e) => (&e.cause, Some(e.as_ref())),
    };
    let kind = category(&cause.kind);
    Observation {
        outcome: if uncertainty.is_some() {
            "uncertain"
        } else {
            kind
        },
        kind: Some(kind),
        elapsed,
        status: match cause.kind {
            ErrorKind::Http(s) => Some(s),
            ErrorKind::SchemaPolicyReplicationUnsupported => Some(409),
            _ => None,
        },
        uncertainty,
        handle,
        ..Observation::default()
    }
}
fn from_response(response: &Response, elapsed: u128, handle: Option<usize>) -> Observation<'_> {
    Observation {
        outcome: "success",
        elapsed,
        status: Some(response.status),
        body: Some(&response.body),
        etag: response.etag.as_deref(),
        revision: Some(&response.revision),
        handle,
        ..Observation::default()
    }
}
impl Observation<'_> {
    fn emit(&self, dir: &File, seq: usize, action: &str, stdout: &mut impl Write) -> Result<()> {
        let dir_name = format!("call-{seq:06}");
        let body_path = if let Some(body) = self.body {
            write_file(dir, "body.bin", body)?;
            Some(format!("{dir_name}/body.bin"))
        } else {
            None
        };
        let mut out = Output::new()?;
        out.raw("{\"schema\":\"yamora-http-replica-observation/2\",\"seq\":")?;
        out.raw(&seq.to_string())?;
        out.raw(",\"action\":")?;
        out.string(action)?;
        out.raw(",\"outcome\":")?;
        out.string(self.outcome)?;
        out.raw(",\"error_kind\":")?;
        out.optional(self.kind)?;
        out.raw(",\"elapsed_ns\":")?;
        out.raw(&self.elapsed.to_string())?;
        out.raw(",\"api\":{\"status\":")?;
        out.raw(&self.status.map_or_else(|| "null".into(), |v| v.to_string()))?;
        out.raw(",\"body_file\":")?;
        out.optional(body_path.as_deref())?;
        out.raw(",\"etag\":")?;
        out.optional(self.etag)?;
        out.raw(",\"revision\":")?;
        out.optional(self.revision)?;
        out.raw(",\"receipt\":null},\"sdk_request_id\":")?;
        out.optional(self.uncertainty.map(UncertainWriteError::request_id))?;
        out.raw(",\"envelope\":")?;
        if let Some(error) = self.uncertainty {
            let mutation = &error.mutation;
            write_file(dir, "envelope.bin", mutation.body())?;
            out.raw("{\"method\":")?;
            out.string(mutation.method())?;
            out.raw(",\"path\":")?;
            out.string(mutation.path())?;
            out.raw(",\"if_match\":")?;
            let matching = if let Condition::IfMatch(tag) = mutation.condition() {
                Some(format!("\"{tag}\""))
            } else {
                None
            };
            out.optional(matching.as_deref())?;
            out.raw(",\"if_none_match\":")?;
            out.optional(matches!(mutation.condition(), Condition::CreateOnly).then_some("*"))?;
            out.raw(",\"request_id\":")?;
            out.string(mutation.request_id())?;
            out.raw(",\"body_file\":")?;
            out.string(&format!("{dir_name}/envelope.bin"))?;
            out.raw("}")?;
        } else {
            out.raw("null")?;
        }
        out.raw(",\"recovery_mode\":")?;
        out.optional(self.handle.map(|_| "sdk-envelope"))?;
        out.raw(",\"recovery_handle\":")?;
        out.optional(self.handle.map(|h| format!("h{h}")).as_deref())?;
        out.raw("}")?;
        stdout.write_all(out.0.as_bytes()).map_err(|_| ())?;
        stdout.write_all(b"\n").map_err(|_| ())?;
        stdout.flush().map_err(|_| ())
    }
}
fn command_line(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(LINE).map_err(|_| ())?;
    loop {
        let next = reader.fill_buf().map_err(|_| ())?;
        if next.is_empty() {
            return Err(());
        } // EOF is incomplete, including between commands.
        let n = next
            .iter()
            .position(|b| *b == b'\n')
            .map_or(next.len(), |i| i + 1);
        if bytes.len() + n > LINE || next[..n].contains(&b'\r') {
            return Err(());
        }
        let complete = next[n - 1] == b'\n';
        bytes.extend_from_slice(&next[..n]);
        reader.consume(n);
        if complete {
            bytes.pop();
            return Ok(bytes);
        }
    }
}
impl Session {
    fn run(mut self, reader: &mut impl BufRead, stdout: &mut impl Write) -> Result<()> {
        for seq in 1..=64 {
            let value = parse(&command_line(reader)?)?;
            if value.field("schema")?.text()? != COMMAND_SCHEMA
                || value.field("seq")?.num()? != seq as u64
            {
                return Err(());
            }
            let dir = at(&self.root, &format!("call-{seq:06}"), DIRECTORY)?;
            match value.field("action")?.text()? {
                "close" => {
                    value.keys(&["schema", "seq", "action"])?;
                    self.recovery.clear();
                    drop(self.client);
                    drop(self._pem);
                    Observation {
                        outcome: "closed",
                        ..Observation::default()
                    }
                    .emit(&dir, seq, "close", stdout)?;
                    return Ok(());
                }
                "recover" => {
                    value.keys(&["schema", "seq", "action", "handle"])?;
                    let handle = value.field("handle")?.text()?;
                    let h: usize = handle
                        .strip_prefix('h')
                        .ok_or(())?
                        .parse()
                        .map_err(|_| ())?;
                    if h == 0 || h > self.recovery.len() || handle != format!("h{h}") {
                        return Err(());
                    }
                    let start = Instant::now();
                    let result = self.client.execute(&self.recovery[h - 1].mutation);
                    let elapsed = start.elapsed().as_nanos();
                    let observation = match &result {
                        Ok(r) => from_response(r, elapsed, Some(h)),
                        Err(e) => from_error(e, elapsed, Some(h)),
                    };
                    observation.emit(&dir, seq, "recover", stdout)?;
                }
                "call" => {
                    let call = Call::parse(&value, &self.root)?;
                    // Reject before dispatch when another uncertain result could
                    // no longer be retained. Recovery and reads remain available.
                    if call.method != "GET" && self.recovery.len() == 16 {
                        return Err(());
                    }
                    if call.method == "GET" {
                        let start = Instant::now();
                        let result = self.client.get(call.collection, call.document, None);
                        let elapsed = start.elapsed().as_nanos();
                        let observation = match &result {
                            Ok(d) => Observation {
                                outcome: "success",
                                elapsed,
                                body: Some(&d.source),
                                etag: Some(&d.etag),
                                revision: Some(&d.revision),
                                ..Observation::default()
                            },
                            Err(e) => from_error(e, elapsed, None),
                        };
                        observation.emit(&dir, seq, "call", stdout)?;
                    } else {
                        let start = Instant::now();
                        let result = call
                            .prepare(&self.client)
                            .map_err(ClusterError::from)
                            .and_then(|m| self.client.execute(&m));
                        let elapsed = start.elapsed().as_nanos();
                        let handle = matches!(result, Err(ClusterError::Uncertain(_)))
                            .then_some(self.recovery.len() + 1);
                        let observation = match &result {
                            Ok(r) => from_response(r, elapsed, None),
                            Err(e) => from_error(e, elapsed, handle),
                        };
                        observation.emit(&dir, seq, "call", stdout)?;
                        if let Err(ClusterError::Uncertain(error)) = result {
                            self.recovery.push(*error);
                        }
                    }
                }
                _ => return Err(()),
            }
        }
        Err(())
    }
}
fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let mut config = None;
    let mut root_path = None;
    while let Some(flag) = args.next() {
        let value = args.next().ok_or(())?;
        if value.len() > 4096 {
            return Err(());
        }
        match flag.to_str() {
            Some("--config") if config.is_none() => config = Some(PathBuf::from(value)),
            Some("--root") if root_path.is_none() => root_path = Some(PathBuf::from(value)),
            _ => return Err(()),
        }
    }
    let root_path = root_path.ok_or(())?;
    if config.as_deref() != Some(root_path.join("config.json").as_path()) {
        return Err(());
    }
    let session = Session::new(root(&root_path)?)?;
    session.run(&mut io::stdin().lock(), &mut io::stdout().lock())
}
fn main() {
    if run().is_err() {
        // Fixed diagnostic: never format SDK errors, peer text, paths or input.
        let _ = io::stderr()
            .write_all(b"http replica adapter: invalid input or infrastructure failure\n");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[path = "tests/http_replica.rs"]
mod tests;
