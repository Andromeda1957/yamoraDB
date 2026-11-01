use super::*;
use std::{
    fs,
    os::unix::fs::symlink,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let base = std::env::var_os("TMPDIR").expect("owned task TMPDIR required");
        let base = scratch_parent(Path::new(&base)).expect("owned private TMPDIR required");
        let path = Path::new(&base).join(format!(
            "unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
fn scratch_parent(base: &Path) -> Result<PathBuf> {
    let work = std::env::var_os("ANDROMEDA_SCRATCH_DIRECTORY").ok_or(())?;
    let work = Path::new(&work);
    root(work)?;
    if !base.starts_with(work) || base == work {
        return Err(());
    }
    let directory = root(base)?;
    let metadata = directory.metadata().map_err(|_| ())?;
    if metadata.mode() & 0o022 != 0 {
        return Err(());
    }
    Ok(base.to_path_buf())
}
#[test]
fn scratch_accepts_owned_runner_allocations_and_rejects_unsafe_roots() {
    use std::os::unix::fs::PermissionsExt;
    let temp = Scratch::new();
    assert_eq!(scratch_parent(&temp.0).unwrap(), temp.0);
    let managed = std::env::var_os("ANDROMEDA_SCRATCH_DIRECTORY").unwrap();
    for path in [
        Path::new("relative"),
        Path::new(&managed),
        Path::new("/var/tmp/andromeda-work"),
        Path::new("/tmp"),
    ] {
        assert!(scratch_parent(path).is_err());
    }
    let link = temp.0.join("link");
    symlink(&temp.0, &link).unwrap();
    assert!(scratch_parent(&link).is_err());
    let plain = temp.0.join("file");
    fs::write(&plain, b"fixture").unwrap();
    assert!(scratch_parent(&plain).is_err());
    let original = fs::metadata(&temp.0).unwrap().permissions();
    fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(scratch_parent(&temp.0).is_err());
    fs::set_permissions(&temp.0, original).unwrap();
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn command(method: &str) -> Json {
    parse(format!(r#"{{"schema":"{COMMAND_SCHEMA}","seq":1,"action":"call","method":"{method}","collection":"manifests","document":"counter","source_file":null,"request_id":null,"if_match":null,"if_none_match":null}}"#).as_bytes()).unwrap()
}
fn set(value: &mut Json, key: &str, new: Json) {
    let Json::Obj(fields) = value else {
        panic!("object");
    };
    fields.iter_mut().find(|(k, _)| k == key).unwrap().1 = new;
}
#[test]
fn json_rejects_duplicates_malformed_types_and_excess_nesting() {
    for bad in [
        r#"{"a":1,"\u0061":2}"#,
        r#"{"x":NaN}"#,
        r#"{"x":1.0}"#,
        r#"{"x":01}"#,
        r#"{"x":-1}"#,
        r#"{"x":18446744073709551616}"#,
        r#"{"x":"\ud800"}"#,
        r#"{"x":"\udc00"}"#,
        r#"{"x":1,}"#,
        "{} trailing",
        "\u{feff}{}",
    ] {
        assert!(parse(bad.as_bytes()).is_err(), "accepted {bad}");
    }
    assert!(parse(&[0xff]).is_err());
    assert!(parse(format!("{}0{}", "[".repeat(12), "]".repeat(12)).as_bytes()).is_ok());
    assert!(parse(format!("{}0{}", "[".repeat(13), "]".repeat(13)).as_bytes()).is_err());
    assert_eq!(parse(br#""\ud83d\ude00""#).unwrap().text().unwrap(), "😀");
}
#[test]
fn line_limit_includes_lf_and_eof_is_incomplete() {
    let mut exact = vec![b' '; LINE - 1];
    exact.push(b'\n');
    assert_eq!(
        command_line(&mut io::Cursor::new(exact)).unwrap().len(),
        LINE - 1
    );
    let mut over = vec![b' '; LINE];
    over.push(b'\n');
    assert!(command_line(&mut io::Cursor::new(over)).is_err());
    assert!(command_line(&mut io::Cursor::new(b"{}".as_slice())).is_err());
    assert!(command_line(&mut io::Cursor::new(b"".as_slice())).is_err());
    assert!(command_line(&mut io::Cursor::new(b"{}\r\n".as_slice())).is_err());
    let mut lines = io::Cursor::new(b"{}\n[]\n");
    assert_eq!(command_line(&mut lines).unwrap(), b"{}");
    assert_eq!(command_line(&mut lines).unwrap(), b"[]");
}
#[test]
fn path_escapes_symlinks_special_files_and_oversize_are_rejected() {
    let temp = Scratch::new();
    let dir = root(&temp.0).unwrap();
    fs::create_dir(temp.0.join("input")).unwrap();
    fs::write(
        temp.0.join("input/value.bin"),
        b"# receipt\r\nn: 0 # keep\r\n",
    )
    .unwrap();
    let mut call = command("PUT");
    for path in [
        "../value.bin",
        "/value.bin",
        "input/../value.bin",
        "input/a/b.bin",
        "input/.bin",
        "input/a.BIN",
    ] {
        set(&mut call, "source_file", Json::Str(path.into()));
        assert!(Call::parse(&call, &dir).is_err(), "accepted {path}");
    }
    set(
        &mut call,
        "source_file",
        Json::Str("input/value.bin".into()),
    );
    assert_eq!(
        Call::parse(&call, &dir).unwrap().source,
        b"# receipt\r\nn: 0 # keep\r\n"
    );
    symlink(
        temp.0.join("input/value.bin"),
        temp.0.join("input/link.bin"),
    )
    .unwrap();
    set(&mut call, "source_file", Json::Str("input/link.bin".into()));
    assert!(Call::parse(&call, &dir).is_err());
    symlink(temp.0.join("input"), temp.0.join("alias")).unwrap();
    assert!(at(&dir, "alias", DIRECTORY).is_err());
    assert!(root(&temp.0.join("alias")).is_err());
    assert!(root(&temp.0.join("input/../input")).is_err());
    fs::write(temp.0.join("input/large.bin"), vec![b'a'; FILE + 1]).unwrap();
    set(
        &mut call,
        "source_file",
        Json::Str("input/large.bin".into()),
    );
    assert!(Call::parse(&call, &dir).is_err());
    assert!(owned_file(&dir, "input").is_err());
    fs::write(temp.0.join("exact.bin"), vec![b'x'; FILE]).unwrap();
    assert_eq!(
        read_file(&mut owned_file(&dir, "exact.bin").unwrap(), FILE)
            .unwrap()
            .len(),
        FILE
    );
    assert!(read_file(&mut owned_file(&dir, "exact.bin").unwrap(), FILE - 1).is_err());
}
#[test]
fn conditions_ids_patch_and_unknown_fields_are_validated_before_sdk() {
    let temp = Scratch::new();
    let dir = root(&temp.0).unwrap();
    fs::create_dir(temp.0.join("input")).unwrap();
    let mut value = command("GET");
    assert!(Call::parse(&value, &dir).is_ok());
    set(&mut value, "request_id", Json::Str("1".repeat(32)));
    assert!(Call::parse(&value, &dir).is_err());
    let mut value = command("DELETE");
    for id in [
        "",
        "00000000000000000000000000000000",
        "ABCDEF0123456789abcdef0123456789",
    ] {
        set(&mut value, "request_id", Json::Str(id.into()));
        assert!(Call::parse(&value, &dir).is_err());
    }
    set(&mut value, "request_id", Json::Null);
    for tag in [
        "",
        "0123456789abcdef",
        "*",
        "\"0123456789ABCDEF\"",
        "\"0123456789abcdef\",\"0123456789abcdef\"",
    ] {
        set(&mut value, "if_match", Json::Str(tag.into()));
        assert!(Call::parse(&value, &dir).is_err());
    }
    set(
        &mut value,
        "if_match",
        Json::Str("\"0123456789abcdef\"".into()),
    );
    assert!(matches!(
        Call::parse(&value, &dir).unwrap().condition,
        Condition::IfMatch("0123456789abcdef")
    ));
    set(&mut value, "if_none_match", Json::Str("*".into()));
    assert!(Call::parse(&value, &dir).is_err());
    let mut value = command("PATCH");
    set(
        &mut value,
        "source_file",
        Json::Str("input/patch.bin".into()),
    );
    for patch in [
        r#"{"$inc":{"n":2}}"#,
        r#"{"$inc":{"n":1,"n":1}}"#,
        r#"{"$inc":{"n":1},"x":0}"#,
        r#"{"$inc":{"n":true}}"#,
    ] {
        fs::write(temp.0.join("input/patch.bin"), patch).unwrap();
        assert!(Call::parse(&value, &dir).is_err());
    }
    fs::write(
        temp.0.join("input/patch.bin"),
        b" { \"$inc\" : {\"n\" : 1} }\n",
    )
    .unwrap();
    assert!(Call::parse(&value, &dir).is_ok());
    set(&mut value, "collection", Json::Str("yamldb-system".into()));
    assert!(Call::parse(&value, &dir).is_err());
    let Json::Obj(mut fields) = command("GET") else {
        panic!();
    };
    fields.push(("extra".into(), Json::Null));
    assert!(Call::parse(&Json::Obj(fields), &dir).is_err());
}
#[test]
fn output_preserves_raw_bytes_nulls_and_never_overwrites() {
    let temp = Scratch::new();
    let dir = root(&temp.0).unwrap();
    let raw = b"# receipt\r\nn: 0 # keep\r\n";
    let mut output = Vec::new();
    Observation {
        outcome: "success",
        body: Some(raw),
        etag: Some("0123456789abcdef"),
        revision: Some("0123456789abcdef"),
        ..Observation::default()
    }
    .emit(&dir, 1, "call", &mut output)
    .unwrap();
    let value = parse(&output).unwrap();
    assert_eq!(
        value.field("api").unwrap().field("status").unwrap(),
        &Json::Null
    );
    assert_eq!(value.field("sdk_request_id").unwrap(), &Json::Null);
    assert_eq!(value.field("envelope").unwrap(), &Json::Null);
    assert_eq!(value.field("recovery_mode").unwrap(), &Json::Null);
    assert_eq!(
        value
            .field("api")
            .unwrap()
            .field("etag")
            .unwrap()
            .text()
            .unwrap(),
        "0123456789abcdef"
    );
    assert_eq!(fs::read(temp.0.join("body.bin")).unwrap(), raw);
    assert!(write_file(&dir, "body.bin", b"changed").is_err());
    assert_eq!(fs::read(temp.0.join("body.bin")).unwrap(), raw);
    assert!(write_file(&dir, "large.bin", &vec![b'x'; FILE + 1]).is_err());
    assert!(output.len() <= LINE);
    let mut writer = Output::new().unwrap();
    assert!(writer.string(&"\u{0}".repeat(LINE)).is_err());
}

// Existing committed fake-peer fixture, never a native qualification. It
// deliberately returns a malformed receipt to obtain a real SDK exception.
struct Peer {
    child: std::process::Child,
    scratch: Scratch,
    port: u16,
}
impl Peer {
    fn new() -> Self {
        use std::os::unix::process::CommandExt;
        let scratch = Scratch::new();
        let child = std::process::Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/support/fixture.py"))
            .arg("--root")
            .arg(&scratch.0)
            .args(["--mode", "good"])
            .process_group(0)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut peer = Self {
            child,
            scratch,
            port: 0,
        };
        let until = Instant::now() + Duration::from_secs(25);
        loop {
            assert!(
                peer.child.try_wait().unwrap().is_none(),
                "fake peer setup failed (infrastructure)"
            );
            if let Ok(ready) = fs::read_to_string(peer.scratch.0.join("ready")) {
                peer.port = ready.lines().next().unwrap().parse().unwrap();
                break;
            }
            assert!(
                Instant::now() < until,
                "fake peer setup watchdog (infrastructure)"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        peer
    }
    fn session(&self) -> Session {
        // Only seed 1 is used by these negative controls; no three-node
        // topology, election or native-recovery assertion is made here.
        let b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let config = format!(
            r#"{{"schema":"yamora-http-replica-config/2","cluster_id":"01020304000000000000000000000000","voters":3,"seeds":[{{"host":"127.0.0.1","port":{},"node":1}},{{"host":"127.0.0.1","port":{},"node":2}},{{"host":"127.0.0.1","port":{},"node":3}}],"tls":{{"ca_file":"ca.pem","cert_file":"client.pem","key_file":"client.key"}},"tokens":{{"read_file":"read.token","write_file":"write.token"}},"timeout_ms":15000,"attempt_timeout_ms":3000}}"#,
            self.port,
            b.local_addr().unwrap().port(),
            c.local_addr().unwrap().port()
        );
        assert_ne!(b.local_addr().unwrap().port(), 8000);
        assert_ne!(c.local_addr().unwrap().port(), 8000);
        fs::write(self.scratch.0.join("config.json"), config).unwrap();
        fs::create_dir(self.scratch.0.join("input")).unwrap();
        for seq in 1..=8 {
            fs::create_dir(self.scratch.0.join(format!("call-{seq:06}"))).unwrap();
        }
        Session::new(root(&self.scratch.0).unwrap()).unwrap()
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        // This exact process group was created above; no foreign process is
        // inspected or controlled. Kill the group and reap on every path.
        let group = format!("-{}", self.child.id());
        let _ = std::process::Command::new("kill")
            .args(["-TERM", "--", &group])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            if self.child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= until {
                let _ = std::process::Command::new("kill")
                    .args(["-KILL", "--", &group])
                    .status();
                self.child.wait().unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
fn receive(reader: &mut impl BufRead) -> Json {
    // SO_RCVTIMEO on the local socket is only an infrastructure watchdog.
    parse(&command_line(reader).expect("adapter observation/watchdog infrastructure")).unwrap()
}
#[test]
fn actual_sdk_uncertainty_retains_envelopes_generated_ids_and_handles() {
    use std::os::unix::net::UnixStream;
    let peer = Peer::new();
    for (i, method) in ["PUT", "PATCH", "DELETE"].iter().enumerate() {
        // Each independent session gets fresh runner-created output slots.
        if i > 0 {
            for seq in 1..=8 {
                let dir = peer.scratch.0.join(format!("call-{seq:06}"));
                fs::remove_dir_all(&dir).unwrap();
            }
            fs::remove_dir_all(peer.scratch.0.join("input")).unwrap();
        }
        let session = peer.session();
        let source: &[u8] = match *method {
            "PUT" => b"# receipt\r\nn: 0 # keep\r\n",
            "PATCH" => b" { \"$inc\" : { \"n\" : 1 } }\n",
            _ => b"",
        };
        fs::write(peer.scratch.0.join("input/value.bin"), source).unwrap();
        fs::write(peer.scratch.0.join("wire.reply"), b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nX-YamlDB-Revision: 0123456789abcdef\r\n\r\n{}").unwrap();
        let (mut input, runner_input) = UnixStream::pair().unwrap();
        let (runner_output, output) = UnixStream::pair().unwrap();
        output
            .set_read_timeout(Some(Duration::from_secs(25)))
            .unwrap();
        let mut output = io::BufReader::new(output);
        let worker = std::thread::spawn(move || {
            session.run(&mut io::BufReader::new(runner_input), &mut {
                runner_output
            })
        });
        let id = if *method == "PATCH" {
            "null"
        } else {
            "\"1234567890abcdef1234567890abcdef\""
        };
        let condition = if *method == "PUT" {
            r#""if_match":null,"if_none_match":"*""#
        } else {
            r#""if_match":"\"0123456789abcdef\"","if_none_match":null"#
        };
        let file = if *method == "DELETE" {
            "null"
        } else {
            "\"input/value.bin\""
        };
        writeln!(input, r#"{{"schema":"{COMMAND_SCHEMA}","seq":1,"action":"call","method":"{method}","collection":"manifests","document":"counter","source_file":{file},"request_id":{id},{condition}}}"#).unwrap();
        let uncertain = receive(&mut output);
        assert_eq!(
            uncertain.field("outcome").unwrap().text().unwrap(),
            "uncertain"
        );
        let actual_id = uncertain
            .field("sdk_request_id")
            .unwrap()
            .text()
            .unwrap()
            .to_owned();
        assert!(hex(&actual_id, 32));
        assert_ne!(actual_id, "0".repeat(32));
        if *method != "PATCH" {
            assert_eq!(actual_id, "1234567890abcdef1234567890abcdef");
        }
        assert_eq!(
            uncertain.field("recovery_handle").unwrap().text().unwrap(),
            "h1"
        );
        assert_eq!(
            uncertain.field("recovery_mode").unwrap().text().unwrap(),
            "sdk-envelope"
        );
        let envelope = uncertain.field("envelope").unwrap();
        assert_eq!(
            envelope.field("request_id").unwrap().text().unwrap(),
            actual_id
        );
        assert_eq!(envelope.field("method").unwrap().text().unwrap(), *method);
        assert_eq!(
            envelope.field("path").unwrap().text().unwrap(),
            "/v1/collections/manifests/documents/counter"
        );
        assert_eq!(
            fs::read(peer.scratch.0.join("call-000001/envelope.bin")).unwrap(),
            source
        );
        fs::remove_file(peer.scratch.0.join("wire.reply")).unwrap();
        if *method == "PUT" {
            let receipt = r#"{"status":"stored","collection":"manifests","document":"counter","etag":"fedcba9876543210","revision":"0123456789abcdef"}"#;
            fs::write(peer.scratch.0.join("wire.reply"), format!("HTTP/1.1 201 Created\r\nContent-Length: {}\r\nContent-Type: application/json\r\nX-YamlDB-Revision: 0123456789abcdef\r\nETag: \"fedcba9876543210\"\r\n\r\n{receipt}", receipt.len())).unwrap();
        }
        // Replacing then removing the source proves recovery never rereads
        // input and never prepares a fresh mutation/request ID.
        fs::write(peer.scratch.0.join("input/value.bin"), b"changed\n").unwrap();
        fs::remove_file(peer.scratch.0.join("input/value.bin")).unwrap();
        for seq in 2..=3 {
            writeln!(
                input,
                r#"{{"schema":"{COMMAND_SCHEMA}","seq":{seq},"action":"recover","handle":"h1"}}"#
            )
            .unwrap();
            let recovered = receive(&mut output);
            assert_eq!(
                recovered.field("outcome").unwrap().text().unwrap(),
                "success"
            );
            assert_eq!(
                recovered.field("recovery_handle").unwrap().text().unwrap(),
                "h1"
            );
            assert_eq!(recovered.field("sdk_request_id").unwrap(), &Json::Null);
            assert_eq!(recovered.field("envelope").unwrap(), &Json::Null);
            assert_eq!(
                recovered
                    .field("api")
                    .unwrap()
                    .field("status")
                    .unwrap()
                    .num()
                    .unwrap(),
                match *method {
                    "DELETE" => 204,
                    "PUT" => 201,
                    _ => 200,
                }
            );
            if *method == "DELETE" {
                assert!(
                    fs::read(peer.scratch.0.join(format!("call-{seq:06}/body.bin")))
                        .unwrap()
                        .is_empty()
                );
            }
        }
        writeln!(
            input,
            r#"{{"schema":"{COMMAND_SCHEMA}","seq":4,"action":"close"}}"#
        )
        .unwrap();
        assert_eq!(
            receive(&mut output)
                .field("outcome")
                .unwrap()
                .text()
                .unwrap(),
            "closed"
        );
        assert!(worker.join().unwrap().is_ok());
        let count: usize = fs::read_to_string(peer.scratch.0.join("count-write"))
            .unwrap()
            .parse()
            .unwrap();
        for n in count - 2..=count {
            assert_eq!(
                fs::read_to_string(peer.scratch.0.join(format!("write-{n}.id"))).unwrap(),
                actual_id
            );
            assert_eq!(
                fs::read(peer.scratch.0.join(format!("write-{n}.body"))).unwrap(),
                source
            );
            let headers =
                fs::read_to_string(peer.scratch.0.join(format!("write-{n}.headers"))).unwrap();
            assert!(headers.contains(if *method == "PUT" {
                "If-None-Match: *"
            } else {
                "If-Match: \"0123456789abcdef\""
            }));
        }
    }
}

#[test]
fn session_rejects_invalid_commands_eof_and_output_symlinks_before_dispatch() {
    let peer = Peer::new();
    drop(peer.session());
    let fresh = || Session::new(root(&peer.scratch.0).unwrap()).unwrap();
    for text in [
        String::new(),
        format!(r#"{{"schema":"{COMMAND_SCHEMA}","seq":1,"action":"close"}}"#),
        format!("{{\"schema\":\"{COMMAND_SCHEMA}\",\"seq\":2,\"action\":\"close\"}}\n"),
        format!("{{\"schema\":\"{COMMAND_SCHEMA}\",\"seq\":true,\"action\":\"close\"}}\n"),
        format!(
            "{{\"schema\":\"{COMMAND_SCHEMA}\",\"seq\":1,\"action\":\"close\",\"secret\":\"redact-me\"}}\n"
        ),
        format!(
            "{{\"schema\":\"{COMMAND_SCHEMA}\",\"seq\":1,\"action\":\"recover\",\"handle\":\"h1\"}}\n"
        ),
        "{\"schema\":\"wrong\",\"seq\":1,\"action\":\"close\"}\n".into(),
    ] {
        let mut output = Vec::new();
        assert!(
            fresh()
                .run(&mut io::Cursor::new(text), &mut output)
                .is_err()
        );
        assert!(output.is_empty());
    }
    let mut output = Vec::new();
    let close = format!("{{\"schema\":\"{COMMAND_SCHEMA}\",\"seq\":1,\"action\":\"close\"}}\n");
    fresh()
        .run(&mut io::Cursor::new(close), &mut output)
        .unwrap();
    let value = parse(&output).unwrap();
    assert_eq!(value.field("outcome").unwrap().text().unwrap(), "closed");
    assert_eq!(value.field("elapsed_ns").unwrap().num().unwrap(), 0);
    for key in [
        "sdk_request_id",
        "envelope",
        "recovery_handle",
        "recovery_mode",
        "error_kind",
    ] {
        assert_eq!(value.field(key).unwrap(), &Json::Null);
    }
    fs::remove_dir(peer.scratch.0.join("call-000001")).unwrap();
    symlink(
        peer.scratch.0.join("call-000002"),
        peer.scratch.0.join("call-000001"),
    )
    .unwrap();
    let get = format!(
        "{{\"schema\":\"{COMMAND_SCHEMA}\",\"seq\":1,\"action\":\"call\",\"method\":\"GET\",\"collection\":\"manifests\",\"document\":\"counter\",\"source_file\":null,\"request_id\":null,\"if_match\":null,\"if_none_match\":null}}\n"
    );
    assert!(
        fresh()
            .run(&mut io::Cursor::new(get), &mut Vec::new())
            .is_err()
    );
    assert!(!peer.scratch.0.join("count-read").exists());
    assert!(!peer.scratch.0.join("count-discovery").exists());
}
#[test]
fn get_reports_only_exposed_fields_and_sixty_four_command_cap() {
    let peer = Peer::new();
    let session = peer.session();
    let raw = "# receipt\r\nn: 0 # keep\r\n";
    fs::write(peer.scratch.0.join("wire.reply"), format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/yaml\r\nX-YamlDB-Revision: 0123456789abcdef\r\nETag: \"fedcba9876543210\"\r\n\r\n{raw}", raw.len())).unwrap();
    let mut commands = String::new();
    for seq in 1..=64 {
        if seq > 8 {
            fs::create_dir(peer.scratch.0.join(format!("call-{seq:06}"))).unwrap();
        }
        commands.push_str(&format!("{{\"schema\":\"{COMMAND_SCHEMA}\",\"seq\":{seq},\"action\":\"call\",\"method\":\"GET\",\"collection\":\"manifests\",\"document\":\"counter\",\"source_file\":null,\"request_id\":null,\"if_match\":null,\"if_none_match\":null}}\n"));
    }
    commands.push_str(&format!(
        "{{\"schema\":\"{COMMAND_SCHEMA}\",\"seq\":65,\"action\":\"close\"}}\n"
    ));
    let mut output = Vec::new();
    assert!(
        session
            .run(&mut io::Cursor::new(commands), &mut output)
            .is_err()
    );
    let lines = output
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 64);
    for (i, line) in lines.iter().enumerate() {
        assert!(line.len() < LINE);
        let observation = parse(line).unwrap();
        assert_eq!(
            observation.field("outcome").unwrap().text().unwrap(),
            "success"
        );
        let api = observation.field("api").unwrap();
        assert_eq!(api.field("status").unwrap(), &Json::Null);
        assert_eq!(api.field("receipt").unwrap(), &Json::Null);
        assert_eq!(
            api.field("etag").unwrap().text().unwrap(),
            "fedcba9876543210"
        );
        assert_eq!(
            fs::read(peer.scratch.0.join(format!("call-{:06}/body.bin", i + 1))).unwrap(),
            raw.as_bytes()
        );
    }
    assert_eq!(
        fs::read_to_string(peer.scratch.0.join("count-read")).unwrap(),
        "64"
    );
}
#[test]
fn sixteen_real_uncertainties_bound_handles_before_seventeenth_dispatch() {
    let peer = Peer::new();
    let session = peer.session();
    fs::write(
        peer.scratch.0.join("input/patch.bin"),
        br#"{"$inc":{"n":1}}"#,
    )
    .unwrap();
    fs::write(peer.scratch.0.join("wire.reply"), b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nX-YamlDB-Revision: 0123456789abcdef\r\n\r\n{}").unwrap();
    let mut commands = String::new();
    for seq in 1..=17 {
        if seq > 8 {
            fs::create_dir(peer.scratch.0.join(format!("call-{seq:06}"))).unwrap();
        }
        commands.push_str(&format!("{{\"schema\":\"{COMMAND_SCHEMA}\",\"seq\":{seq},\"action\":\"call\",\"method\":\"PATCH\",\"collection\":\"manifests\",\"document\":\"counter\",\"source_file\":\"input/patch.bin\",\"request_id\":null,\"if_match\":null,\"if_none_match\":null}}\n"));
    }
    let mut output = Vec::new();
    assert!(
        session
            .run(&mut io::Cursor::new(commands), &mut output)
            .is_err()
    );
    let lines = output
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 16);
    let mut ids = std::collections::BTreeSet::new();
    for (i, line) in lines.iter().enumerate() {
        let value = parse(line).unwrap();
        assert_eq!(value.field("outcome").unwrap().text().unwrap(), "uncertain");
        assert_eq!(
            value.field("recovery_handle").unwrap().text().unwrap(),
            format!("h{}", i + 1)
        );
        ids.insert(
            value
                .field("sdk_request_id")
                .unwrap()
                .text()
                .unwrap()
                .to_owned(),
        );
    }
    assert_eq!(ids.len(), 16);
    assert_eq!(
        fs::read_to_string(peer.scratch.0.join("count-write")).unwrap(),
        "16"
    );
}
