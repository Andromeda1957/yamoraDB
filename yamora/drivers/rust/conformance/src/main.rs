//! Public SDK observations only. The parent runner owns scenarios and assertions.
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use yamora::{
    BinaryClient, BinaryConfig, BinaryIdentity, BinaryMethod, BinaryOptions, BinaryTlsConfig,
    CancellationToken, ErrorKind,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const REQUIRED: [&str; 15] = [
    "host",
    "port",
    "server-name",
    "ca-file",
    "cert-file",
    "key-file",
    "method",
    "collection",
    "document",
    "source-file",
    "request-id",
    "timeout-ms",
    "max-frame-bytes",
    "cancel-mode",
    "output-dir",
];

fn args() -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    let mut input = std::env::args().skip(1);
    while let Some(flag) = input.next() {
        let key = flag.strip_prefix("--").ok_or("argument")?;
        if !REQUIRED.contains(&key) && !["token-file", "if-match", "if-none-match"].contains(&key) {
            return Err("argument".into());
        }
        let value = input.next().ok_or("argument")?;
        if value.len() > 4096 || values.insert(key.to_owned(), value).is_some() {
            return Err("argument".into());
        }
    }
    if REQUIRED.iter().any(|key| !values.contains_key(*key)) {
        return Err("argument".into());
    }
    Ok(values)
}
fn read(path: &str, cap: usize) -> Result<Vec<u8>> {
    if !Path::new(path).is_absolute() {
        return Err("path".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err("file bound".into());
    }
    Ok(bytes)
}
fn write(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))?;
    file.write_all(bytes)?;
    Ok(())
}
fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0}'..='\u{1f}' => out.push_str(&format!("\\u{:04x}", ch as u32)),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}
fn optional(value: Option<&str>) -> String {
    value.map(quote).unwrap_or_else(|| "null".into())
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn method(value: &str) -> Result<BinaryMethod> {
    Ok(match value {
        "GET" => BinaryMethod::Get,
        "HEAD" => BinaryMethod::Head,
        "PUT" => BinaryMethod::Put,
        "DELETE" => BinaryMethod::Delete,
        _ => return Err("method".into()),
    })
}
fn method_name(value: BinaryMethod) -> &'static str {
    match value {
        BinaryMethod::Get => "GET",
        BinaryMethod::Head => "HEAD",
        BinaryMethod::Put => "PUT",
        BinaryMethod::Delete => "DELETE",
    }
}

// Linux pipe control is deliberately polled: dropping a blocking stdin reader
// would leave an orphan when the SDK returns before the parent sends a command.
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}
unsafe extern "C" {
    fn poll(fds: *mut PollFd, count: usize, timeout: i32) -> i32;
    #[link_name = "read"]
    fn read_fd(fd: i32, bytes: *mut u8, count: usize) -> isize;
}
struct Control {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<bool>>,
}
impl Control {
    fn start(enabled: bool, token: CancellationToken) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut control = Self {
            stop: stop.clone(),
            worker: None,
        };
        if enabled {
            let (ready, started) = mpsc::sync_channel(0);
            control.worker = Some(thread::spawn(move || {
                if ready.send(()).is_err() {
                    return false;
                }
                let mut state = 0;
                while !stop.load(Ordering::Acquire) {
                    let mut fd = PollFd {
                        fd: 0,
                        events: 1,
                        revents: 0,
                    };
                    // SAFETY: one initialized pollfd, bounded Linux poll timeout.
                    let result = unsafe { poll(&mut fd, 1, 20) };
                    if result < 0 {
                        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                        {
                            continue;
                        }
                        token.cancel();
                        return false;
                    }
                    if result == 0 {
                        continue;
                    }
                    if fd.revents & (8 | 32) != 0 {
                        token.cancel();
                        return false;
                    }
                    let mut bytes = [0u8; 3];
                    // SAFETY: stdin is a runner-owned pipe and has one reader;
                    // poll reported readable data or EOF. One extra byte detects
                    // malformed C-newline-plus-garbage before cancellation.
                    let count = unsafe { read_fd(0, bytes.as_mut_ptr(), bytes.len()) };
                    if count < 0 {
                        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                        {
                            continue;
                        }
                        token.cancel();
                        return false;
                    }
                    if count == 0 {
                        if state == 1 {
                            token.cancel();
                        }
                        return state != 1;
                    }
                    for byte in &bytes[..count as usize] {
                        if state == 2 || *byte != if state == 1 { b'\n' } else { b'C' } {
                            token.cancel();
                            return false;
                        }
                        state += 1;
                    }
                    if state == 2 {
                        token.cancel();
                    }
                }
                if state == 1 {
                    token.cancel();
                }
                state != 1
            }));
            started.recv_timeout(Duration::from_secs(1))?;
        }
        Ok(control)
    }
    fn finish(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if !worker.join().map_err(|_| "control thread")? {
                return Err("control".into());
            }
        }
        Ok(())
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

fn run() -> Result<String> {
    let args = args()?;
    let port: u16 = args["port"].parse()?;
    let timeout: u64 = args["timeout-ms"].parse()?;
    if args["host"] != "127.0.0.1"
        || args["server-name"] != "localhost"
        || port == 0
        || port == 8000
        || !(1..=30000).contains(&timeout)
        || args["max-frame-bytes"] != "4096"
        || !["none", "pre", "external"].contains(&args["cancel-mode"].as_str())
    {
        return Err("configuration".into());
    }
    let root = PathBuf::from(&args["output-dir"]);
    if !root.is_absolute() || root.canonicalize()? != root || !root.is_dir() {
        return Err("output".into());
    }
    let source = read(&args["source-file"], yamora::MAX_DOCUMENT_BYTES)?;
    let method = method(&args["method"])?;
    // Reject local SDK source errors before they can become protocol observations.
    if (method == BinaryMethod::Put && source.is_empty())
        || (method != BinaryMethod::Put && !source.is_empty())
    {
        return Err("source".into());
    }
    std::str::from_utf8(&source)?;
    for key in ["collection", "document"] {
        let value = &args[key];
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("name".into());
        }
    }
    for key in ["if-match", "if-none-match"] {
        if args
            .get(key)
            .is_some_and(|v| v.len() > 31 || !v.bytes().all(|b| (32..=126).contains(&b)))
        {
            return Err("condition".into());
        }
    }
    let id = args["request-id"].as_bytes();
    if id.len() != 32
        || !id
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        || id.iter().all(|b| *b == b'0')
    {
        return Err("request id".into());
    }
    let mut request_id = [0u8; 16];
    for (i, byte) in request_id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&args["request-id"][i * 2..i * 2 + 2], 16)?;
    }
    let token_bytes = args.get("token-file").map(|p| read(p, 512)).transpose()?;
    let bearer = token_bytes
        .as_deref()
        .map(std::str::from_utf8)
        .transpose()?;
    if bearer.is_some_and(|v| v.is_empty() || !v.bytes().all(|b| (33..=126).contains(&b))) {
        return Err("bearer file".into());
    }
    let client = BinaryClient::new(BinaryConfig {
        endpoint: format!("127.0.0.1:{port}"),
        timeout: Duration::from_millis(timeout),
        max_frame_bytes: 4096,
        max_concurrent_calls: 1,
        tls: BinaryTlsConfig {
            root_pem: read(&args["ca-file"], 65536)?,
            server_name: args["server-name"].clone(),
            identity: Some(BinaryIdentity {
                certificate_pem: read(&args["cert-file"], 65536)?,
                private_key_pem: read(&args["key-file"], 65536)?,
            }),
        },
    })
    .map_err(|_| "client construction")?;
    let token = CancellationToken::new();
    if args["cancel-mode"] == "pre" {
        token.cancel();
    }
    let options = BinaryOptions {
        bearer,
        if_match: args.get("if-match").map(String::as_str),
        if_none_match: args.get("if-none-match").map(String::as_str),
        request_id: Some(request_id),
        cancellation: Some(&token),
    };
    let mut control = Control::start(args["cancel-mode"] == "external", token.clone())?;
    let start = Instant::now();
    let result = client.call(
        method,
        &args["collection"],
        &args["document"],
        &source,
        options,
    );
    let elapsed = start.elapsed().as_nanos();
    control.finish()?;
    let mut outcome = "success";
    let mut kind = "null".to_owned();
    let mut api = "{\"status\":null,\"body_file\":null,\"etag\":null,\"revision\":null,\"representation_length\":null,\"request_id\":null,\"receipt\":null}".to_owned();
    let mut envelope = "null".to_owned();
    match result {
        Ok(response) => {
            write(&root, "body.bin", response.body())?;
            api = format!(
                "{{\"status\":{},\"body_file\":\"body.bin\",\"etag\":{},\"revision\":{},\"representation_length\":{},\"request_id\":null,\"receipt\":null}}",
                response.status,
                optional(response.etag.as_deref()),
                quote(&response.revision),
                response.representation_length
            );
        }
        Err(error) => {
            let mapped = match error.kind {
                ErrorKind::Http(_) | ErrorKind::SchemaPolicyReplicationUnsupported => "status",
                ErrorKind::Timeout => "deadline",
                ErrorKind::Cancelled => "cancelled",
                // Public Rust API groups invalid binary responses in Invalid.
                // All adapter-controlled primitive inputs were validated above.
                ErrorKind::Invalid(_) => "protocol",
                ErrorKind::Tls | ErrorKind::Io(_) => "transport",
                ErrorKind::ClusterUncertain(_) => return Err("unexpected error type".into()),
            };
            outcome = mapped;
            kind = quote(mapped);
            if let ErrorKind::Http(status) = error.kind {
                api = api.replacen("\"status\":null", &format!("\"status\":{status}"), 1);
            } else if matches!(error.kind, ErrorKind::SchemaPolicyReplicationUnsupported) {
                api = api.replacen("\"status\":null", "\"status\":409", 1);
            }
            if error.may_have_committed() {
                let original = error.envelope().ok_or("missing envelope")?;
                write(&root, "envelope.bin", original.source())?;
                let original_id = original.request_id().map(|id| hex(&id));
                envelope = format!(
                    "{{\"method\":{},\"collection\":{},\"document\":{},\"if_match\":{},\"if_none_match\":{},\"request_id\":{},\"source_file\":\"envelope.bin\"}}",
                    quote(method_name(original.method())),
                    quote(original.collection()),
                    quote(original.document()),
                    optional(original.if_match()),
                    optional(original.if_none_match()),
                    optional(original_id.as_deref())
                );
                outcome = "uncertain";
            }
        }
    }
    let json = format!(
        "{{\"schema\":\"yamora-observation/1\",\"outcome\":{},\"error_kind\":{kind},\"elapsed_ns\":{elapsed},\"api\":{api},\"envelope\":{envelope}}}",
        quote(outcome)
    );
    if json.len() + 1 > 16384 {
        return Err("observation bound".into());
    }
    Ok(json)
}
fn main() {
    match run() {
        Ok(json) => {
            if writeln!(std::io::stdout().lock(), "{json}").is_err() {
                std::process::exit(2);
            }
        }
        Err(_) => {
            eprintln!("Rust conformance adapter failed");
            std::process::exit(2);
        }
    }
}
