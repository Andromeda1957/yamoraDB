#[allow(dead_code)] // The same process fixture supports separate pure and native targets.
mod support;
use std::{
    net::TcpListener,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use support::Fixture;
use yamora::{
    CancellationToken, ClusterClient, ClusterConfig, ClusterError, Condition, ErrorKind,
    PreparedMutation, WriteOptions,
};
const ID: &str = "1234567890abcdef1234567890abcdef";
const REV: &str = "0123456789abcdef";
const TAG: &str = "fedcba9876543210";
const SOURCE: &[u8] = b"# exact\r\nn: 9223372036854775807 # comment\r\n";
fn options() -> WriteOptions<'static> {
    WriteOptions {
        condition: Condition::IfMatch(REV),
        request_id: Some(ID),
    }
}
fn uncertain(error: ClusterError) -> yamora::UncertainWriteError {
    match error {
        ClusterError::Uncertain(value) => *value,
        other => panic!("expected recoverable uncertainty: {other:?}"),
    }
}
fn failure(error: ClusterError) -> yamora::Error {
    match error {
        ClusterError::Failure(value) => value,
        other => panic!("expected definitive failure: {other:?}"),
    }
}
fn wait_count(fixture: &Fixture, kind: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while fixture.count(kind) == 0 {
        assert!(Instant::now() < deadline, "no {kind} dispatch");
        thread::sleep(Duration::from_millis(5));
    }
}
fn receipt() -> String {
    format!(
        r#"{{"status":"stored","collection":"a","document":"b","etag":"{TAG}","revision":"{REV}"}}"#
    )
}
fn status(node: u8, voters: u8) -> String {
    format!(
        r#"{{"node":{node},"leader":{node},"term":18446744073709551615,"role":"leader","voters":{voters},"last":2,"committed":2,"applied":2,"failed":false}}"#
    )
}
fn assert_prepared(value: &PreparedMutation, source: &[u8], request_id: &str) {
    assert_eq!(value.body(), source);
    assert_eq!(value.request_id(), request_id);
    assert_eq!(value.method(), "PUT");
    assert_eq!(value.path(), "/v1/collections/a/documents/b");
    assert!(matches!(value.condition(), Condition::IfMatch(REV)));
}
#[test]
fn frozen_source_preconditions_and_generated_or_supplied_ids_survive_lost_replies() {
    for supplied in [false, true] {
        let fixture = Fixture::new("drop-retry", false);
        let client = fixture.client();
        let mut source = SOURCE.to_vec();
        let mut tag = REV.to_owned();
        let mut request_id = ID.to_owned();
        let prepared = client
            .prepare_put(
                "a",
                "b",
                &source,
                WriteOptions {
                    condition: Condition::IfMatch(&tag),
                    request_id: supplied.then_some(&request_id),
                },
            )
            .unwrap();
        let saved = prepared.request_id().to_owned();
        source.fill(b'x');
        tag.clear();
        request_id.clear();
        let response = client.execute(&prepared).unwrap();
        assert_eq!(response.status, 200);
        assert!(
            std::str::from_utf8(&response.body)
                .unwrap()
                .contains("stored")
        );
        assert_prepared(&prepared, SOURCE, &saved);
        assert_eq!(fixture.count("write"), 2);
        for i in 1..=2 {
            assert_eq!(fixture.text(&format!("write-{i}.body")).as_bytes(), SOURCE);
            assert_eq!(fixture.text(&format!("write-{i}.id")), saved);
            let headers = fixture.text(&format!("write-{i}.headers"));
            assert!(headers.contains(&format!("If-Match: \"{REV}\"")));
            assert!(headers.contains(&format!("Authorization: Bearer {}", "w".repeat(32))));
            assert!(!headers.contains(&"r".repeat(32)));
        }
        assert_eq!(saved.len(), 32);
        assert!(saved.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(saved, "0".repeat(32));
        if supplied {
            assert_eq!(saved, ID);
        }
    }
}
#[test]
fn every_document_semantic_receipt_failure_recovers_exact_prepared_envelope() {
    let fixture = Fixture::new("good", false);
    let client = fixture.client();
    let prepared = client.prepare_put("a", "b", SOURCE, options()).unwrap();
    for body in [
        "{}".into(),
        receipt().replace("stored", "failed"),
        receipt().replace("\"a\"", "\"other\""),
        receipt().replace("\"b\"", "\"other\""),
        receipt().replace(TAG, "aaaaaaaaaaaaaaaa"),
        receipt().replace(REV, "ffffffffffffffff"),
        receipt().replace("\"status\":", "\"status\":\"stored\",\"status\":"),
        receipt().replace("\"status\":", "\"\\u0073tatus\":\"stored\",\"status\":"),
        receipt().replace("\"etag\"", "\"missing\""),
        "{\"status\":".into(),
    ] {
        fixture.write("receipt.body", body);
        let error = uncertain(client.execute(&prepared).unwrap_err());
        assert_prepared(&error.mutation, SOURCE, ID);
        assert!(error.cause.may_have_committed);
    }
    assert_eq!(fixture.count("write"), 10);
}
#[test]
fn raw_transaction_and_catalog_receipts_require_exact_operation_counts_and_revision() {
    let fixture = Fixture::new("good", false);
    let client = fixture.client();
    let transaction = br#"{"operations":[{"collection":"a","document":"b","put":"n: 1\n"},{"collection":"a","document":"c","delete":true}]}"#;
    let catalog = br#"{"indexes":[]}"#;
    for prepared in [
        client.prepare_transaction(transaction, None).unwrap(),
        client
            .prepare_set_indexes(catalog, Some(REV), Some(ID))
            .unwrap(),
    ] {
        let expected = if prepared.path() == "/v1/transactions" {
            "2"
        } else {
            "1"
        };
        for count in [
            "0",
            "3",
            "1.0",
            "2e0",
            "\"1\"",
            "18446744073709551616",
            "true",
        ] {
            fixture.write(
                "receipt.body",
                format!(r#"{{"status":"committed","operations":{count},"revision":"{REV}"}}"#),
            );
            let error = uncertain(client.execute(&prepared).unwrap_err());
            assert_eq!(error.mutation, prepared);
        }
        for body in [
            format!(r#"{{"status":"failed","operations":{expected},"revision":"{REV}"}}"#),
            format!(
                r#"{{"status":"committed","operations":{expected},"revision":"ffffffffffffffff"}}"#
            ),
        ] {
            fixture.write("receipt.body", body);
            assert_eq!(
                uncertain(client.execute(&prepared).unwrap_err()).mutation,
                prepared
            );
        }
        fixture.write(
            "receipt.body",
            format!(r#"{{"status":"committed","operations":{expected},"revision":"{REV}"}}"#),
        );
        client.execute(&prepared).unwrap();
    }
}
#[test]
fn malformed_framing_and_unexpected_http_successes_keep_generated_identity() {
    let fixture = Fixture::new("good", false);
    let client = fixture.client();
    let valid = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nX-YamlDB-Revision: {REV}\r\nETag: \"{TAG}\"\r\n\r\n{}",
        receipt().len(),
        receipt()
    );
    for wire in [
        valid[..valid.len() - 1].into(),
        valid.replace("Content-Length: ", "Content-Length: 1\r\nContent-Length: "),
        valid.replace(
            "Content-Length: ",
            "Transfer-Encoding: chunked\r\nContent-Length: ",
        ),
        valid.replace(
            "Content-Length: ",
            "Content-Encoding: gzip\r\nContent-Length: ",
        ),
        valid.replace("Content-Type: application/json", "Content-Type: text/html"),
        valid.replace(REV, "invalid"),
        valid.replace("200 OK", "202 Accepted"),
        valid.replace(
            "Content-Length: ",
            "Broken: \r\n folded: no\r\nContent-Length: ",
        ),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            yamora::MAX_RESPONSE_BYTES + 1
        ),
    ] {
        fixture.write("wire.reply", wire);
        let error = uncertain(
            client
                .put("a", "b", SOURCE, WriteOptions::default())
                .unwrap_err(),
        );
        assert_eq!(
            error.request_id(),
            fixture.text(&format!("write-{}.id", fixture.count("write")))
        );
        assert_eq!(error.mutation.body(), SOURCE);
    }
}
#[test]
fn http_rejections_are_definitive_until_an_earlier_attempt_is_ambiguous() {
    for status in [301, 307, 400, 401, 403, 408, 412, 429, 500, 502, 503] {
        let fixture = Fixture::new(&format!("http-{status}"), false);
        let client = fixture.client();
        let prepared = client.prepare_put("a", "b", SOURCE, options()).unwrap();
        let error = client.execute(&prepared).unwrap_err();
        if (400..500).contains(&status) && status != 408 {
            let error = failure(error);
            assert_eq!(error.kind, ErrorKind::Http(status));
            assert!(!error.may_have_committed);
        } else {
            assert_eq!(uncertain(error).mutation, prepared);
        }
    }
    for mode in ["drop-reject", "drop-discover-reject"] {
        let fixture = Fixture::new(mode, false);
        let client = fixture.client();
        let prepared = client.prepare_put("a", "b", SOURCE, options()).unwrap();
        let error = uncertain(client.execute(&prepared).unwrap_err());
        assert_eq!(error.mutation, prepared);
    }
}
#[test]
fn configured_tls_node_voter_and_numeric_binding_is_required_before_dispatch() {
    let fixture = Fixture::new("good", false);
    let client = fixture.client();
    let valid = status(1, 3);
    for body in [
        status(2, 3),
        status(1, 5),
        valid.replace("\"leader\":1", "\"leader\":2"),
        valid.replace("18446744073709551615", "18446744073709551616"),
        valid.replace("18446744073709551615", "1.0"),
        valid.replace("\"node\":1", "\"node\":1,\"\\u006eode\":1"),
        valid.replace("false", "true"),
        valid.replace("\"applied\":2", "\"applied\":3"),
        valid.replace(
            "\"voters\":3",
            "\"voters\":3,\"url\":\"https://127.0.0.1:1\"",
        ),
    ] {
        fixture.write("status.body", body);
        // Fresh clients avoid a legitimate cached route from earlier calls.
        let error = failure(
            ClusterClient::new(fixture.config())
                .unwrap()
                .put("a", "b", SOURCE, options())
                .unwrap_err(),
        );
        assert!(!error.may_have_committed);
        assert_eq!(fixture.count("write"), 0);
    }
    fixture.write("status.body", valid);
    client.put("a", "b", SOURCE, options()).unwrap();
    for alteration in ["ca", "name", "identity"] {
        let mut config = fixture.config();
        match alteration {
            "ca" => config.seeds[0].tls.ca_file = fixture.root.join("other-ca.pem"),
            "name" => config.seeds[0].tls.server_name = Some("wrong.test".into()),
            _ => config.seeds[0].tls.identity = None,
        }
        let before = fixture.count("write");
        let error = failure(
            ClusterClient::new(config)
                .unwrap()
                .put("a", "b", SOURCE, options())
                .unwrap_err(),
        );
        assert!(!error.may_have_committed);
        assert_eq!(fixture.count("write"), before);
    }
}
#[test]
fn redirects_and_advertised_addresses_never_receive_credentials() {
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    assert_ne!(trap.local_addr().unwrap().port(), 8000);
    let fixture = Fixture::new("good", false);
    fixture.write("wire.reply", format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: https://{}/steal\r\nContent-Length: 0\r\n\r\n", trap.local_addr().unwrap()));
    let error = uncertain(
        fixture
            .client()
            .put("a", "b", SOURCE, options())
            .unwrap_err(),
    );
    assert_eq!(error.cause.kind, ErrorKind::Http(307));
    assert_eq!(
        trap.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    fixture.write(
        "status.body",
        status(1, 3).replace(
            "\"role\":\"leader\"",
            &format!(
                "\"role\":\"leader\",\"location\":\"https://{}\"",
                trap.local_addr().unwrap()
            ),
        ),
    );
    assert!(matches!(
        fixture.client().health().unwrap_err(),
        ClusterError::Failure(_)
    ));
    assert_eq!(
        trap.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
#[test]
fn discovery_is_fair_and_deadline_is_absolute_through_backoff_and_trickling() {
    let stalled = Fixture::new("stall-discovery", false);
    let good = Fixture::new("good", false);
    let mut config = good.config();
    config.seeds.insert(0, stalled.seed(stalled.port, 2));
    config.attempt_timeout = Duration::from_secs(1);
    let start = Instant::now();
    ClusterClient::new(config).unwrap().health().unwrap();
    assert!(start.elapsed() < Duration::from_millis(650));
    assert!(stalled.count("discovery") > 0);
    assert!(good.count("read") > 0);
    for mode in ["stall", "trickle", "http-503", "stall-discovery"] {
        let fixture = Fixture::new(mode, false);
        let mut config = fixture.config();
        config.timeout = Duration::from_millis(160);
        config.attempt_timeout = Duration::from_secs(1);
        let start = Instant::now();
        let error = ClusterClient::new(config).unwrap().health().unwrap_err();
        assert_eq!(failure(error).kind, ErrorKind::Timeout);
        assert!(start.elapsed() < Duration::from_millis(500));
    }
}
#[test]
fn cancellation_before_discovery_during_discovery_and_after_dispatch_has_no_lingering_call() {
    for phase in ["before", "discovery", "write", "read"] {
        let fixture = Fixture::new(
            if phase == "discovery" {
                "stall-discovery"
            } else {
                "stall"
            },
            false,
        );
        let token = CancellationToken::new();
        let client = fixture.client().cancellable(&token);
        if phase == "before" {
            token.cancel();
        }
        let worker = thread::spawn(move || {
            if phase == "read" {
                client.health()
            } else {
                client.put("a", "b", SOURCE, options())
            }
        });
        if phase != "before" {
            wait_count(
                &fixture,
                if phase == "discovery" {
                    "discovery"
                } else if phase == "read" {
                    "read"
                } else {
                    "write"
                },
            );
            token.cancel();
        }
        let start = Instant::now();
        let error = worker.join().unwrap().unwrap_err();
        assert!(start.elapsed() < Duration::from_millis(300));
        if phase == "write" {
            let error = uncertain(error);
            assert_eq!(error.request_id(), ID);
            assert_eq!(error.cause.kind, ErrorKind::Cancelled);
        } else {
            assert_eq!(failure(error).kind, ErrorKind::Cancelled);
            assert_eq!(fixture.count("write"), 0);
        }
        let before = fixture.count("write");
        thread::sleep(Duration::from_millis(40));
        assert_eq!(before, fixture.count("write"));
    }
}
#[test]
fn concurrent_calls_keep_distinct_ids_and_preconditions_and_generation_safe_routes() {
    let fixture = Fixture::new("drop-retry", false);
    let client = Arc::new(fixture.client());
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let client = Arc::clone(&client);
            thread::spawn(move || {
                client
                    .put("a", "b", SOURCE, WriteOptions::default())
                    .unwrap()
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut duplicate = 0;
    for i in 1..=fixture.count("write") {
        if !ids.insert(fixture.text(&format!("write-{i}.id"))) {
            duplicate += 1;
        }
    }
    assert_eq!(ids.len(), 8);
    assert_eq!(duplicate, 1);
}
#[test]
fn local_validation_precedes_discovery_and_unsupported_operations_are_certain() {
    let fixture = Fixture::new("good", false);
    let client = fixture.client();
    assert!(
        client
            .prepare_put(
                "a",
                "b",
                SOURCE,
                WriteOptions {
                    request_id: Some("0".repeat(32).as_str()),
                    ..WriteOptions::default()
                }
            )
            .is_err()
    );
    assert!(client.prepare_patch("a", "b", b"{}", options()).is_err());
    assert!(
        client
            .prepare_transaction(br#"{"operations":[]}"#, None)
            .is_err()
    );
    assert!(client.prepare_transaction(br#"{"operations":[{"collection":"a","document":"b","delete":true},{"collection":"a","document":"b","delete":true}]}"#, None).is_err());
    assert!(
        client
            .prepare_set_indexes(br#"{"indexes":{},"indexes":[]}"#, None, None)
            .is_err()
    );
    assert!(
        client
            .prepare_delete(
                "a",
                "b",
                WriteOptions {
                    condition: Condition::CreateOnly,
                    request_id: None
                }
            )
            .is_err()
    );
    assert!(matches!(
        failure(
            client
                .start_index_build(br#"{"indexes":[]}"#, None)
                .unwrap_err()
        )
        .kind,
        ErrorKind::Http(405)
    ));
    assert_eq!(fixture.count("discovery"), 0);
    assert_eq!(fixture.count("write"), 0);
    for mut config in [
        ClusterConfig::new(vec![], 3),
        fixture.config(),
        fixture.config(),
        fixture.config(),
    ] {
        if !config.seeds.is_empty() {
            config.seeds[0].endpoint = "https://127.0.0.1:1".into();
        }
        assert!(ClusterClient::new(config).is_err());
    }
    for voters in [0, 1, 2, 4, 10] {
        let mut config = fixture.config();
        config.voters = voters;
        assert!(ClusterClient::new(config).is_err());
    }
    let mut config = fixture.config();
    config.seeds.push(config.seeds[0].clone());
    assert!(ClusterClient::new(config).is_err());
}

#[test]
fn stale_discovery_and_failure_cannot_overwrite_or_invalidate_a_newer_route() {
    let old = Fixture::new("stale", false);
    let good = Fixture::new("good", false);
    good.write("status.body", status(2, 3));
    let mut config = old.config();
    config.seeds.push(good.seed(good.port, 2));
    config.timeout = Duration::from_secs(3);
    config.attempt_timeout = Duration::from_secs(1);
    let client = Arc::new(ClusterClient::new(config).unwrap());
    let first = Arc::clone(&client);
    let delayed = thread::spawn(move || first.health().unwrap());
    wait_count(&old, "discovery");
    client.health().unwrap();
    assert_eq!(good.count("discovery"), 1);
    old.write("release-status", "");
    delayed.join().unwrap();
    client.health().unwrap();
    assert_eq!(
        good.count("discovery"),
        1,
        "stale completion erased a newer route"
    );
}

#[test]
fn raw_catalog_and_delete_receipt_metadata_remains_inside_recovery_boundary() {
    let fixture = Fixture::new("good", false);
    let client = fixture.client();
    let catalog = client
        .prepare_set_indexes(br#"{"indexes":[]}"#, None, None)
        .unwrap();
    let delete = client
        .prepare_delete("a", "b", WriteOptions::default())
        .unwrap();
    for mutation in [catalog, delete] {
        let body = if mutation.method() == "DELETE" {
            String::new()
        } else {
            format!(r#"{{"status":"committed","operations":1,"revision":"{REV}"}}"#)
        };
        let status = if mutation.method() == "DELETE" {
            204
        } else {
            200
        };
        for fields in [
            format!("X-YamlDB-Revision: {REV}\r\nETag: invalid\r\n"),
            String::new(),
            "X-YamlDB-Revision: invalid\r\n".into(),
        ] {
            fixture.write("wire.reply", format!("HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{fields}\r\n{body}", body.len()));
            assert_eq!(
                uncertain(client.execute(&mutation).unwrap_err()).mutation,
                mutation
            );
        }
    }
}

#[test]
fn put_receipt_status_must_agree_with_frozen_preconditions() {
    let fixture = Fixture::new("good", false);
    let client = fixture.client();
    for (condition, bad_status, good_status) in [
        (Condition::CreateOnly, 200, 201),
        (Condition::IfMatch(REV), 201, 200),
    ] {
        let prepared = client
            .prepare_put(
                "a",
                "b",
                SOURCE,
                WriteOptions {
                    condition,
                    request_id: Some(ID),
                },
            )
            .unwrap();
        for (status, valid) in [(bad_status, false), (good_status, true)] {
            fixture.write("wire.reply", format!("HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-YamlDB-Revision: {REV}\r\nETag: \"{TAG}\"\r\n\r\n{}", receipt().len(), receipt()));
            let result = client.execute(&prepared);
            if valid {
                assert_eq!(result.unwrap().status, status);
            } else {
                assert_eq!(uncertain(result.unwrap_err()).mutation, prepared);
            }
        }
    }
    for status in [200, 201] {
        fixture.write("wire.reply", format!("HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-YamlDB-Revision: {REV}\r\nETag: \"{TAG}\"\r\n\r\n{}", receipt().len(), receipt()));
        assert_eq!(
            client
                .put("a", "b", SOURCE, WriteOptions::default())
                .unwrap()
                .status,
            status
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn cancellable_tcp_connect_keeps_one_socket_beyond_the_poll_slice() {
    if let Ok(root) = std::env::var("YAMORA_DELAY_CONNECT_ROOT") {
        let port = std::env::var("YAMORA_DELAY_CONNECT_PORT").unwrap();
        let root = std::path::PathBuf::from(root);
        let tls = yamora::TlsOptions {
            ca_file: root.join("ca.pem"),
            identity: Some(yamora::ClientIdentity {
                certificate: root.join("client.pem"),
                private_key: root.join("client.key"),
            }),
            server_name: None,
        };
        let mut config = ClusterConfig::new(
            vec![yamora::ClusterSeed::new(
                format!("127.0.0.1:{port}"),
                1,
                tls,
            )],
            3,
        );
        config.read_token = Some("r".repeat(32));
        config.timeout = Duration::from_millis(800);
        config.attempt_timeout = Duration::from_millis(600);
        let mode = std::env::var("YAMORA_DELAY_CONNECT_MODE").unwrap();
        if mode == "deadline" {
            config.timeout = Duration::from_millis(45);
        }
        let token = CancellationToken::new();
        let cancellation = if mode == "cancel" {
            let token = token.clone();
            Some(thread::spawn(move || {
                thread::sleep(Duration::from_millis(35));
                token.cancel();
            }))
        } else {
            None
        };
        let start = Instant::now();
        let result = ClusterClient::new(config)
            .unwrap()
            .cancellable(&token)
            .health();
        match mode.as_str() {
            "slow" => {
                result.unwrap();
                assert!(start.elapsed() >= Duration::from_millis(200));
                assert!(start.elapsed() < Duration::from_millis(800));
            }
            "cancel" => {
                assert_eq!(failure(result.unwrap_err()).kind, ErrorKind::Cancelled);
                assert!(start.elapsed() < Duration::from_millis(250));
            }
            "deadline" => {
                assert_eq!(failure(result.unwrap_err()).kind, ErrorKind::Timeout);
                assert!(start.elapsed() < Duration::from_millis(250));
            }
            _ => panic!("unknown delayed-connect fixture mode"),
        }
        if let Some(worker) = cancellation {
            worker.join().unwrap();
        }
        return;
    }
    let fixture = Fixture::new("good", false);
    let shim = fixture.root.join("slow-connect.so");
    let compiled = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror"])
        .arg(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/support/slow_connect.c"),
        )
        .arg("-ldl")
        .arg("-o")
        .arg(&shim)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "connect fixture compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    for (mode, sockets) in [("slow", 2), ("cancel", 1), ("deadline", 1)] {
        let log = fixture.root.join(format!("connect-{mode}.log"));
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cancellable_tcp_connect_keeps_one_socket_beyond_the_poll_slice",
                "--test-threads=1",
            ])
            .env("LD_PRELOAD", &shim)
            .env("YAMORA_DELAY_CONNECT_ROOT", &fixture.root)
            .env("YAMORA_DELAY_CONNECT_PORT", fixture.port.to_string())
            .env("YAMORA_DELAY_CONNECT_LOG", &log)
            .env("YAMORA_DELAY_CONNECT_MODE", mode)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{mode} connect child: {} {}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(log).unwrap().lines().count(),
            sockets,
            "one retained socket per connect attempt"
        );
    }
    assert_eq!(fixture.count("discovery"), 1);
    assert_eq!(fixture.count("read"), 1);
}

#[test]
fn current_native_application_compaction_advisory_does_not_block_discovery() {
    let fixture = Fixture::new("good", false);
    let body = status(1, 3);
    fixture.write("status.body",format!("{},\"application_compaction\":{{\"enabled\":false,\"running\":false,\"attempted\":0}}}}",&body[..body.len()-1]));
    let result = fixture.client().health();
    assert!(
        result.is_ok(),
        "CURRENT_NATIVE_ADVISORY_ACCEPTED: {result:?}"
    );
    assert_eq!(fixture.count("discovery"), 1);
    assert_eq!(fixture.count("read"), 1);
}
