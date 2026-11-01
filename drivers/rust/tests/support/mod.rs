use std::os::unix::{ffi::OsStringExt, process::CommandExt};
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};
use yamora::{ClientIdentity, ClusterClient, ClusterConfig, ClusterSeed, TlsOptions};
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
    pub node: u8,
    pub ports: Vec<u16>,
}
impl Fixture {
    pub fn new(mode: &str, native: bool) -> Self {
        let binary = if native {
            let path = PathBuf::from(
                std::env::var_os("YAMORA_TEST_BINARY")
                    .expect("YAMORA_TEST_BINARY must name an existing TLS native daemon; no skip"),
            );
            assert!(path.is_absolute() && path.is_file());
            Some(path)
        } else {
            None
        };
        let root = scratch_root().join(format!(
            "rust-cluster-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let mut command = Command::new("python3");
        command
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/fixture.py"))
            .arg("--root")
            .arg(&root)
            .args(["--mode", mode]);
        if let Some(binary) = binary {
            command.arg("--native").arg(binary);
        }
        command.process_group(0);
        let process = command
            .stdin(Stdio::null())
            .stdout(fs::File::create(root.join("fixture.out")).unwrap())
            .stderr(fs::File::create(root.join("fixture.err")).unwrap())
            .spawn()
            .unwrap_or_else(|error| {
                fs::remove_dir_all(&root).unwrap();
                panic!("fixture spawn failed: {error}")
            });
        let mut fixture = Self {
            root,
            process,
            port: 0,
            node: 0,
            ports: Vec::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            assert!(
                fixture.process.try_wait().unwrap().is_none(),
                "fixture startup failed: {}",
                fixture.text("fixture.err")
            );
            if let Ok(text) = fs::read_to_string(fixture.root.join("ready")) {
                let values: Vec<u16> = text.lines().map(|s| s.parse().unwrap()).collect();
                fixture.port = values[0];
                fixture.node = values[1] as u8;
                fixture.ports = values[2..].to_vec();
                break;
            }
            assert!(
                Instant::now() < deadline,
                "fixture startup timed out: {}",
                fixture.text("fixture.err")
            );
            thread::sleep(Duration::from_millis(10));
        }
        fixture
    }
    pub fn tls(&self) -> TlsOptions {
        TlsOptions {
            ca_file: self.root.join("ca.pem"),
            identity: Some(ClientIdentity {
                certificate: self.root.join("client.pem"),
                private_key: self.root.join("client.key"),
            }),
            server_name: None,
        }
    }
    pub fn seed(&self, port: u16, node: u8) -> ClusterSeed {
        ClusterSeed::new(format!("127.0.0.1:{port}"), node, self.tls())
    }
    pub fn config(&self) -> ClusterConfig {
        let mut config = ClusterConfig::new(vec![self.seed(self.port, self.node)], 3);
        config.read_token = Some("r".repeat(32));
        config.write_token = Some("w".repeat(32));
        config.timeout = Duration::from_millis(700);
        config.attempt_timeout = Duration::from_millis(150);
        config
    }
    pub fn client(&self) -> ClusterClient {
        ClusterClient::new(self.config()).unwrap()
    }
    pub fn write(&self, name: &str, bytes: impl AsRef<[u8]>) {
        fs::write(self.root.join(name), bytes).unwrap();
    }
    pub fn text(&self, name: &str) -> String {
        fs::read_to_string(self.root.join(name)).unwrap_or_default()
    }
    pub fn count(&self, kind: &str) -> usize {
        self.text(&format!("count-{kind}")).parse().unwrap_or(0)
    }
    pub fn control(&self, command: &str) {
        let output = self.root.join("control.out");
        let _ = fs::remove_file(&output);
        self.write("control.in", command);
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            if self.text("control.out") == command {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "fixture control timed out: {}",
                self.text("fixture.err")
            );
            thread::sleep(Duration::from_millis(20));
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
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = self.process.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = Command::new("kill")
                    .args(["-KILL", "--", &format!("-{}", self.process.id())])
                    .status();
                break self.process.wait().expect("reap owned fixture group");
            }
            thread::sleep(Duration::from_millis(10));
        };
        if !status.success() {
            // Only this fixture's explicitly created process group is controlled.
            let _ = Command::new("kill")
                .args(["-KILL", "--", &format!("-{}", self.process.id())])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let error = self.text("fixture.err");
        fs::remove_dir_all(&self.root).expect("remove only own fixture directory");
        if !std::thread::panicking() {
            assert!(status.success(), "fixture teardown failed: {error}");
        }
    }
}
