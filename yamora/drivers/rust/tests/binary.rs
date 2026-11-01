mod binary_support;
use binary_support::Fixture;
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use yamora::{
    BinaryClient, BinaryMethod, BinaryOptions, CancellationToken, ErrorKind, WriteOptions,
};
const SOURCE: &[u8] = "# café\r\nvalue: 01 # exact\r\ntext: 'λ'\r\n".as_bytes();
fn options(token: &str) -> BinaryOptions<'_> {
    BinaryOptions {
        bearer: Some(token),
        ..Default::default()
    }
}
fn status(error: yamora::BinaryError, wanted: u16) {
    assert_eq!(error.kind, ErrorKind::Http(wanted));
    assert!(!error.may_have_committed());
}
#[test]
fn native_mtls_crud_roles_http_and_frozen_trust() {
    let f = Fixture::new("native");
    let read = "r".repeat(32);
    let write = "w".repeat(32);
    let scoped = "s".repeat(32);
    let c = f.client();
    let http = f.http();
    let put = c
        .put(
            "config",
            "item",
            SOURCE,
            BinaryOptions {
                if_none_match: Some("*"),
                request_id: Some([7; 16]),
                ..options(&write)
            },
        )
        .unwrap();
    assert_eq!(put.status, 201);
    assert_eq!(http.get("config", "item", None).unwrap().source, SOURCE);
    let get = c
        .get(
            "config",
            "item",
            BinaryOptions {
                request_id: Some([8; 16]),
                ..options(&read)
            },
        )
        .unwrap();
    assert_eq!(get.body(), SOURCE);
    assert_eq!(get.etag, put.etag);
    assert_eq!(get.revision, put.revision);
    let head = c.head("config", "item", options(&read)).unwrap();
    assert_eq!(head.body(), b"");
    assert_eq!(head.representation_length, SOURCE.len());
    assert_eq!(head.etag, get.etag);
    status(
        c.put(
            "config",
            "item",
            SOURCE,
            BinaryOptions {
                if_none_match: Some("*"),
                ..options(&write)
            },
        )
        .unwrap_err(),
        412,
    );
    status(
        c.put(
            "config",
            "item",
            SOURCE,
            BinaryOptions {
                if_match: Some(""),
                ..options(&write)
            },
        )
        .unwrap_err(),
        400,
    );
    status(
        c.get("config", "item", BinaryOptions::default())
            .unwrap_err(),
        401,
    );
    status(
        c.put("config", "item", SOURCE, options(&read)).unwrap_err(),
        401,
    );
    status(c.get("config", "item", options(&write)).unwrap_err(), 401);
    status(
        c.put("private", "item", SOURCE, options(&scoped))
            .unwrap_err(),
        403,
    );
    assert_eq!(
        c.put("allowed", "item", SOURCE, options(&scoped))
            .unwrap()
            .status,
        201
    );
    assert_eq!(
        c.get("allowed", "item", options(&scoped)).unwrap().body(),
        SOURCE
    );
    http.put(
        "config",
        "item",
        b"# HTTP\r\nvalue: 2\r\n",
        WriteOptions::default(),
    )
    .unwrap();
    status(
        c.delete(
            "config",
            "item",
            BinaryOptions {
                if_match: get.etag.as_deref(),
                ..options(&write)
            },
        )
        .unwrap_err(),
        412,
    );
    let latest = c.get("config", "item", options(&read)).unwrap();
    assert_eq!(latest.body(), b"# HTTP\r\nvalue: 2\r\n");
    assert_eq!(
        c.put(
            "config",
            "item",
            SOURCE,
            BinaryOptions {
                if_match: latest.etag.as_deref(),
                ..options(&write)
            }
        )
        .unwrap()
        .status,
        200
    );
    let delete = c.delete("config", "item", options(&write)).unwrap();
    assert_eq!(delete.status, 204);
    assert!(delete.body().is_empty());
    assert_eq!(delete.representation_length, 0);
    status(c.head("config", "item", options(&read)).unwrap_err(), 404);
    let mut config = f.config();
    config.tls.server_name = "server.test".into();
    let frozen = BinaryClient::new(config).unwrap();
    for file in ["ca.pem", "client.pem", "client.key"] {
        std::fs::write(f.root.join(file), b"replaced").unwrap();
    }
    assert_eq!(
        frozen
            .get("allowed", "item", options(&read))
            .unwrap()
            .body(),
        SOURCE
    );
}
#[test]
fn native_tls_and_optional_mtls_fail_closed() {
    let f = Fixture::new("native");
    let token = "w".repeat(32);
    for case in 0..5 {
        let mut config = f.config();
        match case {
            0 => config.tls.identity = None,
            1 => config.tls.server_name = "wrong.test".into(),
            2 => config.tls.root_pem = f.bytes("other-ca.pem"),
            3 => config.endpoint = format!("127.0.0.1:{}", f.http_port),
            _ => {
                config.tls.identity = Some(yamora::BinaryIdentity {
                    certificate_pem: f.bytes("other-ca.pem"),
                    private_key_pem: f.bytes("other-ca.key"),
                })
            }
        }
        let error = BinaryClient::new(config)
            .unwrap()
            .put("c", "d", SOURCE, options(&token))
            .unwrap_err();
        assert!(!error.may_have_committed(), "TLS rejection before dispatch");
    }
    drop(f);
    let f = Fixture::new("optional");
    let mut config = f.config();
    config.tls.identity = None;
    let c = BinaryClient::new(config).unwrap();
    assert_eq!(
        c.put("c", "d", SOURCE, options(&token)).unwrap().status,
        201
    );
}
#[test]
fn native_full_16mib_over_4k_and_legacy_256k() {
    let write = "w".repeat(32);
    let read = "r".repeat(32);
    {
        let f = Fixture::new("native");
        let c = f.client();
        let mut source = SOURCE.to_vec();
        source.extend_from_slice(b"# ");
        source.resize(16777214, b'x');
        source.extend_from_slice(b"\r\n");
        assert_eq!(source.len(), 16777216);
        assert_eq!(
            c.put("config", "large", &source, options(&write))
                .unwrap()
                .status,
            201
        );
        assert_eq!(
            c.get("config", "large", options(&read)).unwrap().body(),
            source
        );
        assert_eq!(
            c.head("config", "large", options(&read))
                .unwrap()
                .representation_length,
            source.len()
        );
        assert_eq!(
            f.http().get("config", "large", None).unwrap().source,
            source
        );
        source.push(b'x');
        assert!(
            !c.put("config", "large", &source, options(&write))
                .unwrap_err()
                .may_have_committed()
        );
    }
    let f = Fixture::new("legacy");
    let c = f.client();
    let mut source = b"value: 1\r\n# ".to_vec();
    source.resize(262144, b'x');
    c.put("config", "item", &source, options(&write)).unwrap();
    source.push(b'x');
    status(
        c.put("config", "item", &source, options(&write))
            .unwrap_err(),
        413,
    );
    source.pop();
    assert_eq!(
        c.get("config", "item", options(&read)).unwrap().body(),
        source
    );
}
#[test]
fn hostile_receipts_framing_ids_and_source_hash_are_uncertain() {
    let f = Fixture::new("hostile");
    let c = f.client();
    let cases = [
        "eof",
        "error",
        "goaway",
        "oversize",
        "flags",
        "missing-id",
        "wrong-id",
        "bad-name",
        "bad-tag",
        "duplicate",
        "escaped-duplicate",
        "receipt-name",
        "receipt-revision",
        "receipt-number",
        "json-utf8",
        "deep",
        "ack-budget",
        "tlv-duplicate",
        "partial",
        "no-end",
        "partial-end",
        "create-status",
        "match-status",
    ];
    let selected = std::env::var("YAMORA_BINARY_CASE").ok();
    let mut exercised = 0;
    for name in cases {
        if selected.as_deref().is_some_and(|value| value != name) {
            continue;
        }
        exercised += 1;
        let before = f.count("dispatch");
        let result = c.put(
            "c",
            name,
            SOURCE,
            BinaryOptions {
                bearer: Some("private-synthetic"),
                if_none_match: (name == "create-status").then_some("*"),
                if_match: (name == "match-status").then_some("\"0123456789abcdef\""),
                request_id: Some([42; 16]),
                ..Default::default()
            },
        );
        f.wait_count("dispatch", before + 1);
        assert_eq!(
            f.count("dispatch"),
            before + 1,
            "HOSTILE_SINGLE_DISPATCH:{name}"
        );
        eprintln!("DISPATCH_CONFIRMED:{name}");
        assert!(result.is_err(), "HOSTILE_REJECT:{name}");
        let error = result.unwrap_err();
        assert!(error.may_have_committed(), "HOSTILE_UNCERTAIN:{name}");
        let envelope = error.envelope().unwrap();
        assert_eq!(envelope.source(), SOURCE);
        assert_eq!(envelope.request_id(), Some([42; 16]));
        assert_eq!(envelope.document(), name);
        assert!(!format!("{error:?}").contains("private-synthetic"));
        assert!(!format!("{envelope:?}").contains("café"));
        assert_eq!(
            f.count("dispatch"),
            before + 1,
            "HOSTILE_SINGLE_DISPATCH:{name}"
        );
    }
    let received = c.get("c", "fragmented", BinaryOptions::default()).unwrap();
    assert_eq!(received.body(), "# café\r\nvalue: 'λ'\r\n".as_bytes());
    for name in ["bad-tag", "unsolicited-id", "head-body"] {
        let result = if name == "head-body" {
            c.head("c", name, BinaryOptions::default())
        } else {
            c.get("c", name, BinaryOptions::default())
        };
        eprintln!("DISPATCH_CONFIRMED:get-{name}");
        assert!(result.is_err(), "HOSTILE_GET_REJECT:{name}");
        assert!(!result.unwrap_err().may_have_committed());
    }
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        f.count("connections"),
        exercised + 4,
        "every reconnect attempt observable"
    );
}
#[test]
fn lost_committed_native_receipts_observed_before_explicit_replay() {
    for name in ["lost", "partial"] {
        let f = Fixture::new("relay");
        let c = f.client();
        let write = "w".repeat(32);
        let error = c
            .put(
                "c",
                name,
                SOURCE,
                BinaryOptions {
                    if_none_match: Some("*"),
                    request_id: Some([9; 16]),
                    ..options(&write)
                },
            )
            .unwrap_err();
        assert!(error.may_have_committed());
        assert_eq!(
            f.bytes(&format!("observed-{name}")),
            SOURCE,
            "relay independently observed storage before dropping receipt"
        );
        assert_eq!(
            f.http().get("c", name, None).unwrap().source,
            SOURCE,
            "HTTP exact source observed BEFORE explicit repetition"
        );
        thread::sleep(Duration::from_millis(100));
        assert_eq!(f.count("connections"), 1);
        assert_eq!(f.count("dispatch"), 1);
        let mut config = f.config();
        config.endpoint = format!("127.0.0.1:{}", f.native_port);
        let recovery = BinaryClient::new(config).unwrap();
        status(
            recovery
                .replay(error.envelope().unwrap(), Some(&write), None)
                .unwrap_err(),
            412,
        );
        assert_eq!(f.http().get("c", name, None).unwrap().source, SOURCE);
    }
}
#[test]
fn concurrency_admission_deadlines_and_cancellation_release_owners() {
    let f = Fixture::new("hostile");
    let mut config = f.config();
    config.timeout = Duration::from_millis(450);
    config.max_concurrent_calls = 1;
    let c = Arc::new(BinaryClient::new(config).unwrap());
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let worker = c.clone();
    let first = thread::spawn(move || {
        worker
            .put(
                "c",
                "cancel",
                SOURCE,
                BinaryOptions {
                    cancellation: Some(&token),
                    ..Default::default()
                },
            )
            .unwrap_err()
    });
    f.wait_count("dispatch", 1);
    let queued = CancellationToken::new();
    queued.cancel();
    let error = c
        .put(
            "c",
            "never",
            SOURCE,
            BinaryOptions {
                cancellation: Some(&queued),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Cancelled);
    assert!(!error.may_have_committed());
    assert_eq!(f.count("connections"), 1);
    cancel.cancel();
    let error = first.join().unwrap();
    assert_eq!(error.kind, ErrorKind::Cancelled);
    assert!(error.may_have_committed());
    let started = Instant::now();
    let error = c
        .put("c", "stall", SOURCE, BinaryOptions::default())
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);
    assert!(error.may_have_committed());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        c.put("c", "good", SOURCE, BinaryOptions::default())
            .unwrap()
            .status,
        201,
        "admission released after all failures"
    );
    let mut config = f.config();
    config.max_concurrent_calls = 4;
    let c = Arc::new(BinaryClient::new(config).unwrap());
    let workers: Vec<_> = (0..8)
        .map(|i| {
            let c = c.clone();
            thread::spawn(move || {
                c.put(
                    "c",
                    &format!("parallel-{i}"),
                    SOURCE,
                    BinaryOptions::default(),
                )
                .unwrap()
                .status
            })
        })
        .collect();
    for worker in workers {
        assert_eq!(worker.join().unwrap(), 201);
    }
}
#[test]
fn tls_handshake_deadline_alpn_and_tls12() {
    for mode in ["alpn", "tls12", "handshake"] {
        let f = Fixture::new(mode);
        let mut config = f.config();
        config.timeout = Duration::from_millis(200);
        let error = BinaryClient::new(config)
            .unwrap()
            .put("c", "d", SOURCE, BinaryOptions::default())
            .unwrap_err();
        assert!(!error.may_have_committed());
        if mode == "handshake" {
            assert_eq!(error.kind, ErrorKind::Timeout);
        }
        assert_eq!(f.count("dispatch"), 0);
    }
}
#[test]
fn invalid_local_inputs_never_connect() {
    let f = Fixture::new("hostile");
    for endpoint in [
        "localhost:1234",
        "8.8.8.8:443",
        "127.000.0.1:123",
        "127.0.0.1:0",
    ] {
        let mut config = f.config();
        config.endpoint = endpoint.into();
        assert!(BinaryClient::new(config).is_err());
    }
    let c = f.client();
    for body in [b"".as_slice(), b"\xff"] {
        assert!(
            !c.put("c", "d", body, BinaryOptions::default())
                .unwrap_err()
                .may_have_committed()
        );
    }
    assert!(
        c.put(
            "c",
            "d",
            SOURCE,
            BinaryOptions {
                request_id: Some([0; 16]),
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(c.get("../", "d", BinaryOptions::default()).is_err());
    assert!(
        c.call(
            BinaryMethod::Get,
            "c",
            "d",
            SOURCE,
            BinaryOptions::default()
        )
        .is_err()
    );
    assert_eq!(f.count("connections"), 0);
}

#[test]
fn exactly_four_admitted_calls_own_sockets_and_queued_callers_wait() {
    let f = Fixture::new("hostile");
    let c = Arc::new(f.client());
    let workers: Vec<_> = (0..8)
        .map(|i| {
            let c = c.clone();
            thread::spawn(move || {
                c.put("c", &format!("gate-{i}"), SOURCE, BinaryOptions::default())
                    .unwrap()
                    .status
            })
        })
        .collect();
    f.wait_count("dispatch", 4);
    thread::sleep(Duration::from_millis(80));
    let admitted = f.count("dispatch");
    let sockets = f.count("connections");
    // Release and join before assertions, even for a concurrency mutant.
    std::fs::write(f.root.join("release"), b"release").unwrap();
    for worker in workers {
        assert_eq!(worker.join().unwrap(), 201);
    }
    assert_eq!(admitted, 4, "ADMISSION_FOUR_DISPATCHES");
    assert_eq!(sockets, 4, "ADMISSION_FOUR_SOCKETS");
    assert_eq!(f.count("dispatch"), 8);
}

#[test]
fn strict_owned_pem_trust_and_client_identity_have_no_bypass() {
    let f = Fixture::new("hostile");
    for case in 0..6 {
        let mut config = f.config();
        match case {
            0=>config.tls.root_pem.extend_from_slice(b"trailing garbage"),
            1=>config.tls.root_pem=config.tls.root_pem.repeat(33),
            2=>config.tls.identity.as_mut().unwrap().private_key_pem=f.bytes("other-ca.key"),
            3=>config.tls.root_pem=f.bytes("client.key"),
            4=>config.tls.root_pem.clear(),
            _=>config.tls.identity.as_mut().unwrap().private_key_pem=b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nunsupported\n-----END ENCRYPTED PRIVATE KEY-----".to_vec(),
        }
        assert!(
            BinaryClient::new(config).is_err(),
            "unsupported trust/identity {case}"
        );
    }
    assert_eq!(f.count("connections"), 0);
}
