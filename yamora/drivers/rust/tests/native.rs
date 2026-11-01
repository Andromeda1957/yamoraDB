//! Run explicitly with YAMORA_TEST_BINARY and a task-owned TMPDIR; never builds a daemon.
use std::{
    fs::{self, File},
    net::TcpListener,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};
use yamora::{
    Client, ClientIdentity, Condition, Config, ErrorKind, ReplicationPhase, TlsOptions,
    WriteOptions,
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let validation = Command::new("python3")
            .args([
                "-c",
                "import os, sys; from tools.ci.yamora_driver_ci.runner import scratch_parent; sys.stdout.buffer.write(os.fsencode(scratch_parent(os.environ['TMPDIR'])))",
            ])
            .output()
            .expect("scratch validation requires the selected Python helper");
        assert!(
            validation.status.success(),
            "TMPDIR must name an existing owned disk-backed managed directory: {}",
            String::from_utf8_lossy(&validation.stderr)
        );
        let root = PathBuf::from(std::ffi::OsString::from_vec(validation.stdout));
        let path = root.join(format!(
            "rust-native-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("clean owned native test scratch");
    }
}

fn run(command: &mut Command) {
    // Fixed test commands, no shell; bounded even if a native helper stalls.
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "native fixture command failed: {status}");
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("native fixture command timed out");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            let _ = Command::new("kill")
                .args(["-TERM", &self.0.id().to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let deadline = Instant::now() + Duration::from_secs(3);
            while self.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if self.0.try_wait().unwrap().is_none() {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }
}
struct Daemon {
    process: Option<Process>,
    config: Config,
    scratch: Scratch,
}
impl Daemon {
    fn new(tls: Option<&Certificates>, server: &str, replica: bool) -> Self {
        let binary = std::env::var_os("YAMORA_TEST_BINARY")
            .expect("set YAMORA_TEST_BINARY to an existing TLS-capable native daemon");
        assert!(Path::new(&binary).is_absolute());
        let scratch = Scratch::new();
        fs::create_dir(scratch.path("db")).unwrap();
        for (file, token) in [
            ("read.token", "r".repeat(32)),
            ("write.token", "w".repeat(32)),
        ] {
            fs::write(scratch.path(file), token).unwrap();
            fs::set_permissions(scratch.path(file), fs::Permissions::from_mode(0o600)).unwrap();
        }
        run(Command::new(&binary)
            .arg("--data-dir")
            .arg(scratch.path("db"))
            .args(["--init-disk", "--validate-only"]));
        let mut command = Command::new(binary);
        command
            .arg("--data-dir")
            .arg(scratch.path("db"))
            .args(["--port", "0", "--workers", "4"])
            .arg("--auth-token-file")
            .arg(scratch.path("read.token"))
            .arg("--write-auth-token-file")
            .arg(scratch.path("write.token"));
        if replica {
            command.arg("--replica");
        }
        if let Some(certs) = tls {
            command
                .arg("--tls-cert-file")
                .arg(certs.path(&format!("{server}.pem")))
                .arg("--tls-key-file")
                .arg(certs.path(&format!("{server}.key")))
                .arg("--tls-client-ca-file")
                .arg(certs.path("ca.pem"));
        }
        let process = Process(
            command
                .stdout(File::create(scratch.path("stdout")).unwrap())
                .stderr(File::create(scratch.path("stderr")).unwrap())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        let address = loop {
            let text = fs::read_to_string(scratch.path("stdout")).unwrap();
            if let Some(address) = text
                .strip_prefix("yamora listening on ")
                .and_then(|s| s.split(' ').next())
            {
                break address.to_owned();
            }
            assert!(
                Instant::now() < deadline,
                "daemon startup failed: {}",
                fs::read_to_string(scratch.path("stderr")).unwrap()
            );
            thread::sleep(Duration::from_millis(10));
        };
        assert_ne!(
            address.parse::<std::net::SocketAddr>().unwrap().port(),
            8000
        );
        let mut config = Config::new(address);
        config.timeout = Duration::from_secs(10);
        config.read_token = Some("r".repeat(32));
        config.write_token = Some("w".repeat(32));
        if let Some(certs) = tls {
            config.tls = Some(certs.options());
        }
        Self {
            process: Some(process),
            config,
            scratch,
        }
    }
    fn client(&self) -> Client {
        Client::new(self.config.clone()).unwrap()
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        drop(self.process.take());
        let log = fs::read_to_string(self.scratch.path("stderr")).unwrap();
        assert!(
            !log.contains("ERROR: AddressSanitizer")
                && !log.contains("runtime error:")
                && !log.contains("LeakSanitizer"),
            "daemon sanitizer failure: {log}"
        );
    }
}
struct Certificates(Scratch);
impl Certificates {
    fn new() -> Self {
        let result = Self(Scratch::new());
        for name in ["ca", "other-ca"] {
            run(Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=Rust driver test CA",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                    "-keyout",
                ])
                .arg(result.path(&format!("{name}.key")))
                .arg("-out")
                .arg(result.path(&format!("{name}.pem"))));
        }
        for (name, extension) in [
            (
                "server",
                "subjectAltName=IP:127.0.0.1,DNS:yamora.test\nextendedKeyUsage=serverAuth\n",
            ),
            (
                "wrong-ip",
                "subjectAltName=IP:127.0.0.2\nextendedKeyUsage=serverAuth\n",
            ),
            ("client", "extendedKeyUsage=clientAuth\n"),
        ] {
            fs::write(result.path(&format!("{name}.ext")), format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n{extension}")).unwrap();
            run(Command::new("openssl")
                .args([
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-subj",
                    &format!("/CN={name}"),
                    "-keyout",
                ])
                .arg(result.path(&format!("{name}.key")))
                .arg("-out")
                .arg(result.path(&format!("{name}.csr"))));
            run(Command::new("openssl")
                .args(["x509", "-req", "-days", "1", "-in"])
                .arg(result.path(&format!("{name}.csr")))
                .arg("-CA")
                .arg(result.path("ca.pem"))
                .arg("-CAkey")
                .arg(result.path("ca.key"))
                .arg("-CAcreateserial")
                .arg("-extfile")
                .arg(result.path(&format!("{name}.ext")))
                .arg("-out")
                .arg(result.path(&format!("{name}.pem"))));
        }
        result
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.path(name)
    }
    fn options(&self) -> TlsOptions {
        TlsOptions {
            ca_file: self.path("ca.pem"),
            identity: Some(ClientIdentity {
                certificate: self.path("client.pem"),
                private_key: self.path("client.key"),
            }),
            server_name: None,
        }
    }
}
fn field(response: &[u8], name: &str) -> String {
    let text = std::str::from_utf8(response).unwrap();
    let needle = format!("\"{name}\":\"");
    text.split_once(&needle)
        .unwrap_or_else(|| panic!("no test field {name} in {text}"))
        .1
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}
fn status(error: yamora::Error, expected: u16) {
    assert_eq!(error.kind, ErrorKind::Http(expected));
}

#[test]
fn native_yaml_conditions_queries_indexes_transactions_jobs_and_feeds() {
    let daemon = Daemon::new(None, "", false);
    let c = daemon.client();
    c.health().unwrap();
    assert!(
        String::from_utf8(c.ready().unwrap().body)
            .unwrap()
            .contains("native-disk-v2")
    );
    c.stats().unwrap();
    assert!(
        String::from_utf8(c.metrics().unwrap().body)
            .unwrap()
            .contains("yamldb_uptime_seconds")
    );
    let checkpoint = field(&c.changes(None, 100).unwrap().body, "next_after");
    let original = "# authored\r\nname: 'Straße'\r\nn: 9007199254740993 # unchanged\r\n";
    let create = WriteOptions {
        condition: Condition::CreateOnly,
        request_id: None,
    };
    assert_eq!(
        c.put("examples", "one", original.as_bytes(), create)
            .unwrap()
            .status,
        201
    );
    let first = c.get("examples", "one", None).unwrap();
    assert_eq!(first.source, original.as_bytes());
    status(
        c.put("examples", "one", original.as_bytes(), create)
            .unwrap_err(),
        412,
    );
    let condition = WriteOptions {
        condition: Condition::IfMatch(&first.etag),
        request_id: None,
    };
    c.patch("examples", "one", br#"{"$inc":{"n":1}}"#, condition)
        .unwrap();
    let updated = c.get("examples", "one", None).unwrap();
    assert_eq!(
        updated.source,
        original
            .replace("9007199254740993", "9007199254740994")
            .as_bytes()
    );
    status(
        c.put("examples", "one", original.as_bytes(), condition)
            .unwrap_err(),
        412,
    );
    status(
        c.patch("examples", "one", br#"{"$inc":{"n":1}}"#, condition)
            .unwrap_err(),
        412,
    );
    status(c.delete("examples", "one", condition).unwrap_err(), 412);
    assert!(c.get("examples", "one", Some(&first.revision)).is_err());
    let query = c
        .query(
            "examples",
            br#"{"filter":{"n":9007199254740994},"explain":true,"limit":1}"#,
        )
        .unwrap();
    assert!(
        String::from_utf8(query.body)
            .unwrap()
            .contains("9007199254740994")
    );
    let index = br#"{"indexes":[{"collection":"examples","name":"words","fields":["$source"],"type":"text"}]}"#;
    c.set_indexes(index, Some(&updated.revision), None).unwrap();
    c.indexes().unwrap();
    assert!(
        String::from_utf8(
            c.search("examples", br#"{"index":"words","text":"STRASSE"}"#)
                .unwrap()
                .body
        )
        .unwrap()
        .contains("one")
    );
    c.aggregate(
        "examples",
        br#"{"pipeline":[{"$group":{"_id":null,"count":{"$sum":1}}}]}"#,
    )
    .unwrap();
    let before = c.ready().unwrap().revision;
    let tx = format!(
        r#"{{"revision":"{before}","operations":[{{"collection":"examples","document":"two","put":"name: second\nn: 9223372036854775807\n","create_only":true}}]}}"#
    );
    c.transaction(tx.as_bytes(), None).unwrap();
    status(c.transaction(tx.as_bytes(), None).unwrap_err(), 412);
    let page = c.documents_page("examples", 1, None, None).unwrap();
    let after = field(&page.body, "next_after");
    c.documents_page("examples", 1, Some(&after), Some(&page.revision))
        .unwrap();
    c.collections().unwrap();
    let job = c.start_index_build(br#"{"indexes":[]}"#, None).unwrap();
    let job_id = field(&job.body, "id");
    c.index_builds().unwrap();
    c.index_build(&job_id).unwrap();
    match c.cancel_index_build(&job_id) {
        Ok(cancelled) => {
            assert_eq!(cancelled.status, 202);
            assert!(
                String::from_utf8(cancelled.body)
                    .unwrap()
                    .contains("\"cancel_requested\":true")
            );
        }
        Err(error) => {
            // Publication cannot be cancelled, including its final audit handoff.
            status(error, 409);
            let deadline = Instant::now() + Duration::from_secs(5);
            let completed = loop {
                let current = c.index_build(&job_id).unwrap();
                if field(&current.body, "status") != "running" {
                    break current;
                }
                assert_eq!(field(&current.body, "phase"), "publishing");
                assert!(
                    Instant::now() < deadline,
                    "index publication did not complete"
                );
                thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(field(&completed.body, "status"), "succeeded");
        }
    }
    c.changes(Some(&checkpoint), 100).unwrap();
    c.delete("examples", "two", WriteOptions::default())
        .unwrap();
    status(c.get("examples", "two", None).unwrap_err(), 404);
    let current = c.get("examples", "one", None).unwrap();
    assert_eq!(
        c.put(
            "examples",
            "one",
            original.as_bytes(),
            WriteOptions {
                condition: Condition::IfMatch(&current.etag),
                request_id: None
            }
        )
        .unwrap()
        .status,
        200
    );
    let replaced = c.get("examples", "one", None).unwrap();
    assert_eq!(replaced.source, original.as_bytes());
    c.delete(
        "examples",
        "one",
        WriteOptions {
            condition: Condition::IfMatch(&replaced.etag),
            request_id: None,
        },
    )
    .unwrap();
    status(c.get("examples", "one", None).unwrap_err(), 404);
    let mut config = daemon.config.clone();
    config.read_token = Some("invalid".repeat(8));
    status(Client::new(config).unwrap().ready().unwrap_err(), 401);
    let mut config = daemon.config.clone();
    config.write_token = config.read_token.clone();
    status(
        Client::new(config)
            .unwrap()
            .put("examples", "forbidden", b"a: 1\n", WriteOptions::default())
            .unwrap_err(),
        401,
    );
}

#[test]
fn native_large_authored_yaml_round_trip() {
    let daemon = Daemon::new(None, "", false);
    let c = daemon.client();
    let original = format!(
        "# large authored YAML\r\nname: 'unchanged'\r\ntext: {}\r\n",
        "é".repeat(1600000)
    );
    c.put("large", "one", original.as_bytes(), WriteOptions::default())
        .unwrap();
    assert_eq!(
        c.get("large", "one", None).unwrap().source,
        original.as_bytes()
    );
}

#[test]
fn raw_example_runs_against_native_mutual_tls() {
    let certs = Certificates::new();
    let daemon = Daemon::new(Some(&certs), "server", false);
    let executable = std::env::var_os("YAMORA_RUST_EXAMPLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("examples/raw")
        });
    assert!(
        executable.is_file(),
        "build the raw example before native tests (cargo build --example raw)"
    );
    run(Command::new(executable)
        .env("YAMORA_ENDPOINT", &daemon.config.endpoint)
        .env("YAMORA_READ_TOKEN", "r".repeat(32))
        .env("YAMORA_WRITE_TOKEN", "w".repeat(32))
        .env("YAMORA_CA_FILE", certs.path("ca.pem"))
        .env("YAMORA_CLIENT_CERT", certs.path("client.pem"))
        .env("YAMORA_CLIENT_KEY", certs.path("client.key"))
        .env("YAMORA_SERVER_NAME", "yamora.test"));
    let document = daemon.client().get("examples", "one", None).unwrap();
    assert_eq!(
        document.source,
        b"# keep this comment\r\nname: 'first'\r\nn: 2\r\n"
    );
}

#[test]
fn native_replication_stages_and_durable_status() {
    let daemon = Daemon::new(None, "", true);
    let c = daemon.client();
    c.replication_status().unwrap();
    let begin = c
        .replication(
            ReplicationPhase::Begin,
            br#"{"revision":"0000000000000000","collections":[]}"#,
        )
        .unwrap();
    let session = field(&begin.body, "session");
    c.replication(
        ReplicationPhase::Abort,
        format!(r#"{{"session":"{session}"}}"#).as_bytes(),
    )
    .unwrap();
    // Invalid low-level envelopes reach the real server, not an invented success.
    status(
        c.follow_replication(ReplicationPhase::Begin, b"{}")
            .unwrap_err(),
        400,
    );
    status(
        c.put("examples", "one", b"n: 1\n", WriteOptions::default())
            .unwrap_err(),
        405,
    );
}

#[test]
fn native_full_and_incremental_replication_publish_exact_source() {
    let source_daemon = Daemon::new(None, "", false);
    let target_daemon = Daemon::new(None, "", true);
    let source = source_daemon.client();
    let target = target_daemon.client();
    let original = b"# preserved\r\nname: 'first'\r\nn: 1\r\n";
    source
        .put("examples", "one", original, WriteOptions::default())
        .unwrap();
    let document = source.get("examples", "one", None).unwrap();
    let checkpoint = field(&source.changes(None, 100).unwrap().body, "next_after");
    let begin = format!(
        r#"{{"revision":"{}","collections":["examples"],"full":true,"revision_scheme":"xor-fnv-v2","source_after":"{checkpoint}"}}"#,
        document.revision
    );
    let session = field(
        &target
            .replication(ReplicationPhase::Begin, begin.as_bytes())
            .unwrap()
            .body,
        "session",
    );
    let apply = format!(
        r##"{{"session":"{session}","operations":[{{"collection":"examples","document":"one","put":"# preserved\r\nname: 'first'\r\nn: 1\r\n"}}]}}"##
    );
    target
        .replication(ReplicationPhase::Apply, apply.as_bytes())
        .unwrap();
    status(target.get("examples", "one", None).unwrap_err(), 404);
    let commit = format!(
        r#"{{"session":"{session}","revision":"{}"}}"#,
        document.revision
    );
    target
        .replication(ReplicationPhase::Commit, commit.as_bytes())
        .unwrap();
    assert_eq!(
        target.get("examples", "one", None).unwrap().source,
        original
    );
    let changed = source
        .patch(
            "examples",
            "one",
            br#"{"$inc":{"n":1}}"#,
            WriteOptions::default(),
        )
        .unwrap();
    let page = source.changes(Some(&checkpoint), 100).unwrap();
    let token = field(&page.body, "token");
    let begin = format!(
        r#"{{"after":"{checkpoint}","token":"{token}","previous_revision":"{}","revision":"{}","operations":1}}"#,
        document.revision, changed.revision
    );
    let session = field(
        &target
            .follow_replication(ReplicationPhase::Begin, begin.as_bytes())
            .unwrap()
            .body,
        "session",
    );
    let apply = format!(
        r##"{{"session":"{session}","operations":[{{"collection":"examples","document":"one","put":"# preserved\r\nname: 'first'\r\nn: 2\r\n"}}]}}"##
    );
    target
        .follow_replication(ReplicationPhase::Apply, apply.as_bytes())
        .unwrap();
    target
        .follow_replication(
            ReplicationPhase::Commit,
            format!(r#"{{"session":"{session}"}}"#).as_bytes(),
        )
        .unwrap();
    assert_eq!(
        target.get("examples", "one", None).unwrap().source,
        source.get("examples", "one", None).unwrap().source
    );
    assert_eq!(
        field(&target.replication_status().unwrap().body, "after"),
        token
    );
}

#[test]
fn native_verified_tls13_mtls_and_real_verification_failures() {
    let certs = Certificates::new();
    let daemon = Daemon::new(Some(&certs), "server", false);
    let c = daemon.client();
    c.health().unwrap();
    let source = "# TLS exact bytes\r\nname: 'Straße'\r\n";
    c.put("tls", "one", source.as_bytes(), WriteOptions::default())
        .unwrap();
    assert_eq!(c.get("tls", "one", None).unwrap().source, source.as_bytes());
    let large = format!("# many TLS records\r\ntext: {}\r\n", "é".repeat(600000));
    c.put("tls", "large", large.as_bytes(), WriteOptions::default())
        .unwrap();
    assert_eq!(
        c.get("tls", "large", None).unwrap().source,
        large.as_bytes()
    );
    let mut config = daemon.config.clone();
    config.tls.as_mut().unwrap().server_name = Some("yamora.test".into());
    Client::new(config).unwrap().ready().unwrap();
    let mut wrong_ca = daemon.config.clone();
    wrong_ca.tls.as_mut().unwrap().ca_file = certs.path("other-ca.pem");
    let mut wrong_name = daemon.config.clone();
    wrong_name.tls.as_mut().unwrap().server_name = Some("wrong.test".into());
    let mut missing_client = daemon.config.clone();
    missing_client.tls.as_mut().unwrap().identity = None;
    for config in [wrong_ca, wrong_name, missing_client] {
        let err = Client::new(config).unwrap().ready().unwrap_err();
        assert!(matches!(err.kind, ErrorKind::Tls | ErrorKind::Io(_)));
        assert!(!err.may_have_committed);
    }
    let wrong_ip_daemon = Daemon::new(Some(&certs), "wrong-ip", false);
    assert_eq!(
        wrong_ip_daemon.client().health().unwrap_err().kind,
        ErrorKind::Tls
    );
    let mut wrong_key = daemon.config.clone();
    wrong_key
        .tls
        .as_mut()
        .unwrap()
        .identity
        .as_mut()
        .unwrap()
        .private_key = certs.path("server.key");
    assert!(Client::new(wrong_key).is_err());
    for name in [
        "",
        "*.test",
        "bad/name",
        "a\0b",
        "127.0.0.1",
        "-bad.test",
        "a..test",
    ] {
        let mut cfg = daemon.config.clone();
        cfg.tls.as_mut().unwrap().server_name = Some(name.into());
        assert!(Client::new(cfg).is_err());
    }
}

#[test]
fn tls12_only_peer_is_rejected_and_stalled_handshake_has_deadline() {
    let certs = Certificates::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    assert_ne!(address.port(), 8000);
    drop(listener);
    let _server = Process(
        Command::new("openssl")
            .args([
                "s_server",
                "-quiet",
                "-tls1_2",
                "-accept",
                &address.to_string(),
                "-cert",
            ])
            .arg(certs.path("server.pem"))
            .arg("-key")
            .arg(certs.path("server.key"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut cfg = Config::new(address.to_string());
    cfg.tls = Some(certs.options());
    let c = Client::new(cfg).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let error = c.health().unwrap_err();
        if error.kind == ErrorKind::Tls {
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    assert_ne!(address.port(), 8000);
    let worker = thread::spawn(move || {
        let (_socket, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_millis(200));
    });
    let mut cfg = Config::new(address.to_string());
    cfg.tls = Some(certs.options());
    cfg.timeout = Duration::from_millis(50);
    assert_eq!(
        Client::new(cfg).unwrap().health().unwrap_err().kind,
        ErrorKind::Timeout
    );
    worker.join().unwrap();
}
