use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};
use yamora::{
    Client, Condition, Config, ErrorKind, MAX_DOCUMENT_BYTES, MAX_REQUEST_BYTES, ReplicationPhase,
    WriteOptions,
};

fn options() -> WriteOptions<'static> {
    WriteOptions {
        condition: Condition::IfMatch("0123456789abcdef"),
        request_id: Some("1234567890abcdef1234567890abcdef"),
    }
}
fn request(socket: &mut TcpStream) -> Vec<u8> {
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut b = [0];
        socket.read_exact(&mut b).unwrap();
        bytes.push(b[0]);
        assert!(bytes.len() < 8192);
    }
    let text = std::str::from_utf8(&bytes).unwrap();
    let length = text
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .map(|n| n.parse::<usize>().unwrap())
        .unwrap_or(0);
    let h = bytes.len();
    bytes.resize(h + length, 0);
    socket.read_exact(&mut bytes[h..]).unwrap();
    bytes
}
fn fixture<F: FnOnce(TcpStream) + Send + 'static>(serve: F) -> (Config, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    assert_ne!(listener.local_addr().unwrap().port(), 8000);
    let config = Config::new(listener.local_addr().unwrap().to_string());
    let worker = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            match listener.accept() {
                Ok((s, _)) => {
                    serve(s);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "no request");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    (config, worker)
}
fn reply(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-YamlDB-Revision: 0123456789abcdef\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn replication_source_guard_is_typed_and_never_writes() {
    for value in [
        "false",
        "null",
        "\"false\"",
        "\"true\"",
        "0",
        "1",
        "[]",
        "{}",
        "true",
        "absent",
        "nested",
    ] {
        let field = match value {
            "absent" => String::new(),
            "nested" => ",\"nested\":{\"replication_policy_free\":false}".to_owned(),
            _ => format!(",\"replication_policy_free\":{value}"),
        };
        let body = format!("{{\"revision\":\"0123456789abcdef\"{field}}}");
        let expected = body.clone();
        let (config, worker) = fixture(move |mut socket| {
            assert!(request(&mut socket).starts_with(b"GET /readyz "));
            socket.write_all(reply(&body).as_bytes()).unwrap();
        });
        let result = Client::new(config).unwrap().require_replication_source();
        if matches!(value, "true" | "absent" | "nested") {
            assert_eq!(result.unwrap().body, expected.as_bytes());
        } else {
            let error = result.unwrap_err();
            assert!(!error.may_have_committed);
            if value == "false" {
                assert_eq!(error.kind, ErrorKind::SchemaPolicyReplicationUnsupported);
            } else {
                assert!(matches!(error.kind, ErrorKind::Invalid(_)));
            }
        }
        worker.join().unwrap();
    }
}

#[test]
fn rejects_bad_endpoints_credentials_timeouts_and_limits() {
    for endpoint in [
        "https://127.0.0.1:80",
        "localhost:80",
        "127.0.0.1:0",
        "127.0.0.1",
        "127.0.0.1:80/",
        "user@127.0.0.1:80",
        "127.0.0.1:80?x=1",
        "[::1]:80",
        "0.0.0.0:80",
        "8.8.8.8:80",
        "169.254.169.254:80",
        "100.64.0.1:80",
        "172.32.0.1:80",
        "127.00.0.1:80",
        "127.0.0.1:00080",
        "127.0.0.1:65536",
    ] {
        assert!(Client::new(Config::new(endpoint)).is_err(), "{endpoint}");
    }
    for endpoint in [
        "127.0.0.1:1",
        "127.255.255.255:1",
        "10.0.0.1:1",
        "172.16.0.1:1",
        "172.31.255.255:1",
        "192.168.0.1:1",
    ] {
        assert!(Client::new(Config::new(endpoint)).is_ok());
    }
    for token in [
        "".into(),
        "x".repeat(31),
        "x".repeat(513),
        format!("{}\r\nInjected: yes", "x".repeat(32)),
        " ".repeat(32),
        "é".repeat(32),
        "\0".repeat(32),
    ] {
        let mut config = Config::new("127.0.0.1:1");
        config.read_token = Some(token.clone());
        assert!(Client::new(config).is_err());
        let mut config = Config::new("127.0.0.1:1");
        config.write_token = Some(token);
        assert!(Client::new(config).is_err());
    }
    for timeout in [Duration::ZERO, Duration::from_secs(31)] {
        let mut c = Config::new("127.0.0.1:1");
        c.timeout = timeout;
        assert!(Client::new(c).is_err());
    }
    for max in [0, yamora::MAX_RESPONSE_BYTES + 1] {
        let mut c = Config::new("127.0.0.1:1");
        c.max_response_bytes = max;
        assert!(Client::new(c).is_err());
    }
}

#[test]
fn rejects_invalid_paths_conditions_payloads_and_cursors_before_connecting() {
    let mut config = Config::new("127.0.0.1:1");
    config.write_token = Some("w".repeat(32));
    let client = Client::new(config).unwrap();
    for bad in [
        "",
        "../escape",
        "a/b",
        "%2e",
        "A",
        "a?x=1",
        "é",
        "a\r\nHeader: x",
    ] {
        assert!(matches!(
            client.get(bad, "one", None).unwrap_err().kind,
            ErrorKind::Invalid(_)
        ));
        assert!(matches!(
            client
                .put("examples", bad, b"x: 1\n", WriteOptions::default())
                .unwrap_err()
                .kind,
            ErrorKind::Invalid(_)
        ));
        assert!(matches!(
            client.query(bad, b"{}").unwrap_err().kind,
            ErrorKind::Invalid(_)
        ));
    }
    assert!(client.get(&"a".repeat(129), "one", None).is_err());
    for tag in [
        "bad",
        "\"0123456789abcdef\"",
        "0123456789ABCDEF",
        "0123456789abcde\n",
    ] {
        assert!(matches!(
            client
                .put(
                    "examples",
                    "one",
                    b"a: 1\n",
                    WriteOptions {
                        condition: Condition::IfMatch(tag),
                        request_id: None
                    }
                )
                .unwrap_err()
                .kind,
            ErrorKind::Invalid(_)
        ));
    }
    for id in [
        "x",
        "00000000000000000000000000000000",
        "1234567890abcdef1234567890abcde\n",
    ] {
        assert!(matches!(
            client.transaction(b"{}", Some(id)).unwrap_err().kind,
            ErrorKind::Invalid(_)
        ));
    }
    assert!(client.put("examples", "one", b"", options()).is_err());
    assert!(client.put("examples", "one", b"\xff", options()).is_err());
    assert!(
        client
            .put(
                "examples",
                "one",
                &vec![b'x'; MAX_DOCUMENT_BYTES + 1],
                options()
            )
            .is_err()
    );
    assert!(
        client
            .transaction(&vec![b'x'; MAX_REQUEST_BYTES + 1], None)
            .is_err()
    );
    assert!(client.query("examples", b"{not json}").is_err());
    assert!(matches!(
        client
            .query("examples", &vec![b' '; 2 * 1024 * 1024 + 1])
            .unwrap_err()
            .kind,
        ErrorKind::Invalid(_)
    ));
    assert!(client.documents_page("examples", 0, None, None).is_err());
    assert!(
        client
            .documents_page("examples", 1, Some("one"), None)
            .is_err()
    );
    assert!(client.changes(Some("v1.invalid"), 10).is_err());
    assert!(client.changes(None, 101).is_err());
    assert!(client.index_build("../job").is_err());
    let create = WriteOptions {
        condition: Condition::CreateOnly,
        request_id: None,
    };
    assert!(client.patch("examples", "one", b"{}", create).is_err());
    assert!(client.delete("examples", "one", create).is_err());
}

#[test]
fn exact_yaml_headers_credentials_and_json_numbers_survive() {
    let source = "# authored\r\nname: 'Straße'\r\nn: 9223372036854775807 # exact\r\n";
    let (mut config, worker) = fixture(move |mut s| {
        let bytes = request(&mut s);
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("PUT /v1/collections/examples/documents/one HTTP/1.1\r\n"));
        assert!(text.contains(&format!("Authorization: Bearer {}\r\n", "w".repeat(32))));
        assert!(!text.contains(&"r".repeat(32)));
        assert!(text.contains("If-Match: \"0123456789abcdef\"\r\n"));
        assert!(text.contains("X-Yamora-Request-Id: 1234567890abcdef1234567890abcdef\r\n"));
        assert!(text.ends_with(source));
        s.write_all(reply(r#"{"n":9223372036854775807}"#).as_bytes())
            .unwrap();
    });
    config.read_token = Some("r".repeat(32));
    config.write_token = Some("w".repeat(32));
    let r = Client::new(config)
        .unwrap()
        .put("examples", "one", source.as_bytes(), options())
        .unwrap();
    assert_eq!(r.body, br#"{"n":9223372036854775807}"#);
    worker.join().unwrap();
}

#[test]
fn redirects_are_returned_once_without_contacting_location() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let location = target.local_addr().unwrap();
    for status in [301, 302, 303, 307, 308] {
        let (config, worker) = fixture(move |mut s| {
            request(&mut s);
            s.write_all(format!("HTTP/1.1 {status} Redirect\r\nLocation: http://{location}/secret\r\nContent-Length: 0\r\n\r\n").as_bytes()).unwrap();
        });
        let err = Client::new(config).unwrap().health().unwrap_err();
        assert_eq!(err.kind, ErrorKind::Http(status));
        worker.join().unwrap();
        assert_eq!(
            target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn rejects_truncated_oversize_ambiguous_and_invalid_responses() {
    let valid = reply("{}");
    let cases = vec![
        reply(&format!("{{}}{}", " ".repeat(63))),
        valid[..valid.len() - 1].to_owned(),
        valid.replace("Content-Length: 2", "Content-Length: 65"),
        valid.replace(
            "Content-Length: 2",
            "Content-Length: 999999999999999999999999999",
        ),
        valid.replace(
            "Content-Length: 2",
            "Content-Length: 2\r\ncontent-length: 2",
        ),
        valid.replace("Content-Length: 2\r\n", ""),
        valid.replace(
            "Content-Length: 2",
            "Content-Length: 2\r\nTransfer-Encoding: chunked",
        ),
        valid.replace(
            "Content-Length: 2",
            "Content-Length: 2\r\nContent-Encoding: gzip",
        ),
        valid.replace(
            "X-YamlDB-Revision: 0123456789abcdef",
            "X-YamlDB-Revision: invalid",
        ),
        valid.replace("Content-Type: application/json", "Content-Type: text/html"),
        valid.replace("{}", "[]"),
        "HTTP/1.1 200 OK\r\n folded: no\r\n\r\n".to_owned(),
        format!("HTTP/1.1 200 OK\r\nX-Large: {}", "a".repeat(16 * 1024)),
        format!(
            "HTTP/1.1 200 OK\r\n{}\r\n",
            (0..65).map(|i| format!("X-{i}: a\r\n")).collect::<String>()
        ),
    ];
    for response in cases {
        let (mut config, worker) = fixture(move |mut s| {
            request(&mut s);
            let _ = s.write_all(response.as_bytes());
        });
        config.max_response_bytes = 64;
        assert!(Client::new(config).unwrap().health().is_err());
        worker.join().unwrap();
    }
}

#[test]
fn deadline_is_absolute_even_when_peer_trickles_bytes() {
    let (mut config, worker) = fixture(|mut s| {
        request(&mut s);
        for b in reply("{}").bytes() {
            if s.write_all(&[b]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    });
    config.timeout = Duration::from_millis(80);
    let start = Instant::now();
    assert_eq!(
        Client::new(config).unwrap().health().unwrap_err().kind,
        ErrorKind::Timeout
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    worker.join().unwrap();
}

#[test]
fn lost_mutation_reply_is_uncertain_and_never_replayed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    assert_ne!(listener.local_addr().unwrap().port(), 8000);
    let mut config = Config::new(listener.local_addr().unwrap().to_string());
    let worker = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        request(&mut socket);
        drop(socket);
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_millis(150);
        while Instant::now() < deadline {
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "mutation replayed"
            );
            thread::sleep(Duration::from_millis(5));
        }
    });
    config.write_token = Some("w".repeat(32));
    let err = Client::new(config)
        .unwrap()
        .put("examples", "one", b"a: 1\n", options())
        .unwrap_err();
    assert!(err.may_have_committed);
    worker.join().unwrap();
    for status in [401, 403, 412, 408, 500, 503] {
        let (mut config, worker) = fixture(move |mut s| {
            request(&mut s);
            s.write_all(
                format!("HTTP/1.1 {status} Error\r\nContent-Length: 12\r\n\r\nprivate-data")
                    .as_bytes(),
            )
            .unwrap();
        });
        config.write_token = Some("w".repeat(32));
        let err = Client::new(config)
            .unwrap()
            .put("examples", "one", b"a: 1\n", options())
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Http(status));
        assert_eq!(err.may_have_committed, status == 408 || status >= 500);
        assert!(!format!("{err:?} {err}").contains("private-data"));
        worker.join().unwrap();
    }
}

#[test]
fn ignores_environment_proxy() {
    if let Ok(endpoint) = std::env::var("YAMORA_PROXY_CHILD") {
        Client::new(Config::new(endpoint))
            .unwrap()
            .health()
            .unwrap();
        return;
    }
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    assert_ne!(proxy.local_addr().unwrap().port(), 8000);
    proxy.set_nonblocking(true).unwrap();
    let (config, worker) = fixture(|mut s| {
        request(&mut s);
        s.write_all(reply("{}").as_bytes()).unwrap();
    });
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child
        .args(["--exact", "ignores_environment_proxy"])
        .env("YAMORA_PROXY_CHILD", config.endpoint)
        .env("NO_PROXY", "")
        .env("no_proxy", "");
    for key in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        child.env(key, format!("http://{}", proxy.local_addr().unwrap()));
    }
    assert!(child.status().unwrap().success());
    worker.join().unwrap();
    assert_eq!(
        proxy.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn named_operation_routes_use_correct_method_and_read_or_write_credential() {
    let calls: &[(&str, &str, bool)] = &[
        ("GET", "/v1/stats", false),
        ("POST", "/v1/query/examples", false),
        ("POST", "/v1/aggregate/examples", false),
        ("POST", "/v1/search/examples", false),
        ("POST", "/v1/transactions", true),
        ("PUT", "/v1/indexes", true),
        ("POST", "/v1/replication/begin", true),
        ("POST", "/v1/replication/follow/abort", true),
        ("GET", "/v1/cluster/leader", false),
    ];
    for (i, &(method, path, write)) in calls.iter().enumerate() {
        let (mut config, worker) = fixture(move |mut s| {
            let bytes = request(&mut s);
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(text.starts_with(&format!("{method} {path} HTTP/1.1\r\n")));
            let token = if write {
                "w".repeat(32)
            } else {
                "r".repeat(32)
            };
            assert!(text.contains(&format!("Authorization: Bearer {token}\r\n")));
            s.write_all(reply("{}").as_bytes()).unwrap();
        });
        config.read_token = Some("r".repeat(32));
        config.write_token = Some("w".repeat(32));
        let c = Client::new(config).unwrap();
        match i {
            0 => c.stats(),
            1 => c.query("examples", b"{}"),
            2 => c.aggregate("examples", b"{}"),
            3 => c.search("examples", b"{}"),
            4 => c.transaction(b"{}", None),
            5 => c.set_indexes(b"{}", None, None),
            6 => c.replication(ReplicationPhase::Begin, b"{}"),
            7 => c.follow_replication(ReplicationPhase::Abort, b"{}"),
            _ => c.cluster_leader(),
        }
        .unwrap();
        worker.join().unwrap();
    }
}

#[test]
fn native_identical_no_store_is_accepted_without_relaxing_framing_duplicates() {
    for fields in [
        "Cache-Control: no-store\r\nCache-Control: no-store\r\n",
        "cAcHe-CoNtRoL:\tNo-Store  \r\nCACHE-CONTROL:  no-store\t\r\n",
    ] {
        let wire = reply("{}").replace("Content-Type:", &format!("{fields}Content-Type:"));
        let (config, worker) = fixture(move |mut socket| {
            request(&mut socket);
            socket.write_all(wire.as_bytes()).unwrap();
        });
        Client::new(config).unwrap().health().unwrap();
        worker.join().unwrap();
    }
    for fields in [
        "Cache-Control: no-store\r\nCache-Control: public\r\n",
        "Content-Length: 2\r\n",
        "X-YamlDB-Revision: 0123456789abcdef\r\n",
        "ETag: \"0123456789abcdef\"\r\nETag: \"0123456789abcdef\"\r\n",
    ] {
        let wire = reply("{}").replace("Content-Type:", &format!("{fields}Content-Type:"));
        let (config, worker) = fixture(move |mut socket| {
            request(&mut socket);
            socket.write_all(wire.as_bytes()).unwrap();
        });
        assert!(Client::new(config).unwrap().health().is_err());
        worker.join().unwrap();
    }
}
