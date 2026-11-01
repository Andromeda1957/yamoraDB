use std::os::unix::{ffi::OsStringExt, process::CommandExt};
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};
use yamora::{
    BinaryClient, BinaryConfig, BinaryIdentity, BinaryTlsConfig, Client, ClientIdentity, Config,
    TlsOptions,
};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
fn scratch_root() -> PathBuf {
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
    PathBuf::from(std::ffi::OsString::from_vec(validation.stdout))
}
pub struct Fixture {
    pub root: PathBuf,
    process: Child,
    pub port: u16,
    pub http_port: u16,
    pub native_port: u16,
}
impl Fixture {
    pub fn new(mode: &str) -> Self {
        let task_root = scratch_root();
        let root = task_root.join(format!(
            "rust-binary-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let mut command = Command::new("python3");
        command
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/binary_fixture.py"))
            .args(["--mode", mode])
            .arg("--root")
            .arg(&root);
        if matches!(mode, "native" | "legacy" | "relay" | "optional") {
            let binary = PathBuf::from(
                std::env::var_os("YAMORA_TEST_BINARY")
                    .expect("YAMORA_TEST_BINARY required; no native skip"),
            );
            assert!(
                binary.is_absolute() && binary.is_file(),
                "required immutable daemon missing"
            );
            command.arg("--native").arg(binary);
        }
        let process = command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(fs::File::create(root.join("fixture.out")).unwrap())
            .stderr(fs::File::create(root.join("fixture.err")).unwrap())
            .spawn()
            .unwrap();
        let mut f = Self {
            root,
            process,
            port: 0,
            http_port: 0,
            native_port: 0,
        };
        let until = Instant::now() + Duration::from_secs(25);
        loop {
            assert!(
                f.process.try_wait().unwrap().is_none(),
                "fixture exited: {}",
                f.text("fixture.err")
            );
            if let Ok(text) = fs::read_to_string(f.root.join("ready")) {
                let ports: Vec<u16> = text.lines().map(|p| p.parse().unwrap()).collect();
                f.port = ports[0];
                f.http_port = ports[1];
                f.native_port = ports[2];
                break;
            }
            assert!(
                Instant::now() < until,
                "fixture readiness timeout: {}",
                f.text("fixture.err")
            );
            thread::sleep(Duration::from_millis(10));
        }
        f
    }
    pub fn text(&self, file: &str) -> String {
        fs::read_to_string(self.root.join(file)).unwrap_or_default()
    }
    pub fn bytes(&self, file: &str) -> Vec<u8> {
        fs::read(self.root.join(file)).unwrap()
    }
    pub fn tls(&self) -> BinaryTlsConfig {
        BinaryTlsConfig {
            root_pem: self.bytes("ca.pem"),
            server_name: "127.0.0.1".into(),
            identity: Some(BinaryIdentity {
                certificate_pem: self.bytes("client.pem"),
                private_key_pem: self.bytes("client.key"),
            }),
        }
    }
    pub fn config(&self) -> BinaryConfig {
        let mut c = BinaryConfig::new(format!("127.0.0.1:{}", self.port), self.tls());
        c.timeout = Duration::from_secs(30);
        c.max_frame_bytes = 4096;
        c
    }
    pub fn client(&self) -> BinaryClient {
        BinaryClient::new(self.config()).unwrap()
    }
    pub fn http(&self) -> Client {
        let mut c = Config::new(format!("127.0.0.1:{}", self.http_port));
        c.timeout = Duration::from_secs(30);
        c.read_token = Some("r".repeat(32));
        c.write_token = Some("w".repeat(32));
        c.tls = Some(TlsOptions {
            ca_file: self.root.join("ca.pem"),
            server_name: None,
            identity: Some(ClientIdentity {
                certificate: self.root.join("client.pem"),
                private_key: self.root.join("client.key"),
            }),
        });
        Client::new(c).unwrap()
    }
    pub fn count(&self, key: &str) -> usize {
        let text = self.text("counts");
        let prefix = format!("\"{key}\": ");
        text.split_once(&prefix)
            .map(|(_, s)| s.split([',', '}']).next().unwrap().parse().unwrap())
            .unwrap_or(0)
    }
    pub fn wait_count(&self, key: &str, count: usize) {
        let until = Instant::now() + Duration::from_secs(3);
        while self.count(key) < count {
            assert!(
                Instant::now() < until,
                "dispatch observation missing: {key}"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.process.try_wait().unwrap().is_none() {
            let _ = Command::new("kill")
                .args(["-TERM", &self.process.id().to_string()])
                .status();
        }
        let until = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = self.process.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= until {
                let _ = Command::new("kill")
                    .args(["-KILL", "--", &format!("-{}", self.process.id())])
                    .status();
                let _ = self.process.wait();
                panic!("fixture failed bounded teardown; scratch retained");
            }
            thread::sleep(Duration::from_millis(10));
        };
        let diagnostics = self.text("fixture.err");
        // Python reaps native children, closes sockets and joins peer threads.
        if status.success() {
            fs::remove_dir_all(&self.root).expect("clean stopped fixture scratch");
        }
        assert!(
            status.success(),
            "fixture teardown failed; scratch retained: {diagnostics}"
        );
    }
}
