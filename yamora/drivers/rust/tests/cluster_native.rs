#[allow(dead_code)] // Shared pure/native fixture owns children, certificates and scratch.
mod support;
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use support::Fixture;
use yamora::{ClusterClient, ClusterConfig, ClusterError, Condition, Response, WriteOptions};
const SOURCE: &str =
    "# authored exact source\r\nname: Alpha\r\nn: 0 # retained\r\nwide: 9223372036854775807\r\n";
fn config(fixture: &Fixture, gateway: bool) -> ClusterConfig {
    let seeds = if gateway {
        let mut seeds = vec![fixture.seed(fixture.port, fixture.node)];
        seeds.extend(
            fixture
                .ports
                .iter()
                .enumerate()
                .filter(|(i, _)| *i + 1 != usize::from(fixture.node))
                .map(|(i, p)| fixture.seed(*p, i as u8 + 1)),
        );
        seeds
    } else {
        fixture
            .ports
            .iter()
            .enumerate()
            .map(|(i, p)| fixture.seed(*p, i as u8 + 1))
            .collect()
    };
    let mut value = fixture.config();
    value.seeds = seeds;
    value.timeout = Duration::from_secs(15);
    value.attempt_timeout = Duration::from_secs(3);
    value
}
fn same(a: &Response, b: &Response) {
    assert_eq!(a.status, b.status);
    assert_eq!(a.body, b.body);
    assert_eq!(a.revision, b.revision);
    assert_eq!(a.etag, b.etag);
}
fn text(response: Response) -> String {
    String::from_utf8(response.body).unwrap()
}
#[test]
fn native_three_node_tls_discovery_failover_lost_reply_same_id_quorum_and_full_restart() {
    let fixture = Fixture::new("native", true);
    let direct_config = config(&fixture, false);
    let client = ClusterClient::new(direct_config.clone()).unwrap();
    let put = client
        .prepare_put(
            "manifests",
            "counter",
            SOURCE.as_bytes(),
            WriteOptions {
                condition: Condition::CreateOnly,
                request_id: Some("11111111111111111111111111111111"),
            },
        )
        .unwrap();
    let stored = client.execute(&put).unwrap_or_else(|error| {
        let statuses: Vec<_> = fixture
            .ports
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut single = yamora::Config::new(format!("127.0.0.1:{p}"));
                single.tls = Some(fixture.tls());
                single.read_token = Some("r".repeat(32));
                let status = yamora::Client::new(single).unwrap().cluster_status();
                format!(
                    "node{} {:?}",
                    i + 1,
                    status.map(|r| String::from_utf8(r.body))
                )
            })
            .collect();
        panic!("initial native mutation failed: {error:?}; statuses={statuses:?}")
    });
    same(&stored, &client.execute(&put).unwrap());
    assert_eq!(
        client.get("manifests", "counter", None).unwrap().source,
        SOURCE.as_bytes()
    );
    assert!(text(client.health().unwrap()).contains("ok"));
    client.ready().unwrap();
    client.stats().unwrap();
    assert!(text(client.metrics().unwrap()).contains("yamldb_uptime_seconds"));
    assert!(text(client.collections().unwrap()).contains("manifests"));
    assert!(text(client.documents_page("manifests", 100, None, None).unwrap()).contains("counter"));
    assert!(
        text(
            client
                .query("manifests", br#"{"filter":{"wide":9223372036854775807}}"#)
                .unwrap()
        )
        .contains("9223372036854775807")
    );
    let checkpoint = text(client.changes(None, 100).unwrap());
    let token = checkpoint
        .split("\"next_after\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let error = client
        .patch(
            "manifests",
            "counter",
            br#"{"$inc":{"n":1}}"#,
            WriteOptions {
                condition: Condition::IfMatch("0000000000000000"),
                request_id: None,
            },
        )
        .unwrap_err();
    assert!(
        matches!(error, ClusterError::Failure(e) if e.kind == yamora::ErrorKind::Http(412) && !e.may_have_committed)
    );

    let routed = ClusterClient::new(config(&fixture, true)).unwrap();
    // Ensure the configured gateway is selected before its committed response is lost.
    routed.get("manifests", "counter", None).unwrap();
    fixture.write("drop-next", "");
    fixture.write("crash-next", "");
    let increment = routed
        .prepare_patch(
            "manifests",
            "counter",
            br#"{"$inc":{"n":1}}"#,
            WriteOptions::default(),
        )
        .unwrap();
    let recovered = routed.execute(&increment).unwrap();
    assert_eq!(fixture.count("write"), 1);
    assert_eq!(fixture.text("write-1.id"), increment.request_id());
    assert_eq!(fixture.text("write-1.body").as_bytes(), increment.body());
    assert_eq!(fixture.text("receipt-1").as_bytes(), recovered.body);
    same(&recovered, &client.execute(&increment).unwrap());
    assert_eq!(
        client.get("manifests", "counter", None).unwrap().source,
        SOURCE.replace("n: 0", "n: 1").as_bytes()
    );
    let changes = text(client.changes(Some(&token), 100).unwrap());
    assert_eq!(
        changes.matches("\"document\":\"counter\"").count(),
        1,
        "one committed mutation after lost reply"
    );

    let client = Arc::new(client);
    let common = Arc::new(
        client
            .prepare_patch(
                "manifests",
                "counter",
                br#"{"$inc":{"n":1}}"#,
                WriteOptions {
                    request_id: Some("55555555555555555555555555555555"),
                    ..WriteOptions::default()
                },
            )
            .unwrap(),
    );
    let same_id_workers: Vec<_> = (0..8)
        .map(|_| {
            let client = Arc::clone(&client);
            let common = Arc::clone(&common);
            thread::spawn(move || client.execute(&common).unwrap())
        })
        .collect();
    let receipts: Vec<_> = same_id_workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    for receipt in &receipts {
        same(&receipts[0], receipt);
    }
    assert_eq!(
        client.get("manifests", "counter", None).unwrap().source,
        SOURCE.replace("n: 0", "n: 2").as_bytes()
    );
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let client = Arc::clone(&client);
            thread::spawn(move || {
                client
                    .patch(
                        "manifests",
                        "counter",
                        br#"{"$inc":{"n":1}}"#,
                        WriteOptions::default(),
                    )
                    .unwrap()
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(
        client.get("manifests", "counter", None).unwrap().source,
        SOURCE.replace("n: 0", "n: 10").as_bytes()
    );
    let transaction = client.prepare_transaction(br#"{"operations":[{"collection":"manifests","document":"counter","patch":{"$inc":{"n":1}}},{"collection":"manifests","document":"second","put":"name: Beta\nwide: -9223372036854775808\n","create_only":true}]}"#, Some("22222222222222222222222222222222")).unwrap();
    let receipt = client.execute(&transaction).unwrap();
    same(&receipt, &client.execute(&transaction).unwrap());
    assert!(
        text(
            client
                .query("manifests", br#"{"filter":{"name":"Beta"}}"#)
                .unwrap()
        )
        .contains("-9223372036854775808")
    );
    let catalog = client.prepare_set_indexes(br#"{"indexes":[{"collection":"manifests","name":"n","fields":["n"]},{"collection":"manifests","name":"text","fields":["$source"],"type":"text"}]}"#, None, Some("33333333333333333333333333333333")).unwrap();
    let receipt = client.execute(&catalog).unwrap();
    same(&receipt, &client.execute(&catalog).unwrap());
    assert!(text(client.indexes().unwrap()).contains("text"));
    assert!(
        text(
            client
                .search("manifests", br#"{"index":"text","text":"retained"}"#)
                .unwrap()
        )
        .contains("counter")
    );
    assert!(
        text(
            client
                .aggregate(
                    "manifests",
                    br#"{"pipeline":[{"$group":{"_id":null,"total":{"$sum":"$n"}}}]}"#
                )
                .unwrap()
        )
        .contains("11")
    );
    let deletion = client
        .prepare_delete(
            "manifests",
            "second",
            WriteOptions {
                request_id: Some("44444444444444444444444444444444"),
                ..WriteOptions::default()
            },
        )
        .unwrap();
    let receipt = client.execute(&deletion).unwrap();
    client
        .put(
            "manifests",
            "second",
            b"name: recreated\n",
            WriteOptions::default(),
        )
        .unwrap();
    same(&receipt, &client.execute(&deletion).unwrap());
    assert_eq!(
        client.get("manifests", "second", None).unwrap().source,
        b"name: recreated\n"
    );

    fixture.control("quorum-loss");
    let mut short = direct_config;
    short.timeout = Duration::from_millis(750);
    short.attempt_timeout = Duration::from_millis(250);
    let isolated = ClusterClient::new(short).unwrap();
    let quorum_write = isolated
        .prepare_patch(
            "manifests",
            "counter",
            br#"{"$inc":{"n":1}}"#,
            WriteOptions::default(),
        )
        .unwrap();
    let start = Instant::now();
    let uncertain = isolated.execute(&quorum_write).unwrap_err();
    assert!(start.elapsed() < Duration::from_secs(2));
    match uncertain {
        ClusterError::Uncertain(error) => assert_eq!(error.mutation, quorum_write),
        other => panic!("dispatched quorum-loss write must be recoverable: {other:?}"),
    }
    fixture.control("restart");
    let receipt = client.execute(&quorum_write).unwrap();
    same(&receipt, &client.execute(&quorum_write).unwrap());
    let expected = SOURCE.replace("n: 0", "n: 12");
    assert_eq!(
        client.get("manifests", "counter", None).unwrap().source,
        expected.as_bytes()
    );
    fixture.control("restart");
    let reopened = ClusterClient::new(config(&fixture, false)).unwrap();
    assert_eq!(
        reopened.get("manifests", "counter", None).unwrap().source,
        expected.as_bytes()
    );
    same(&receipt, &reopened.execute(&quorum_write).unwrap());
    same(&recovered, &reopened.execute(&increment).unwrap());
    same(&stored, &reopened.execute(&put).unwrap());
    assert_eq!(
        reopened.get("manifests", "second", None).unwrap().source,
        b"name: recreated\n"
    );
}
#[test]
fn native_committed_malformed_receipts_preserve_recoverable_raw_and_catalog_operations() {
    let fixture = Fixture::new("native", true);
    let mut config = config(&fixture, false);
    config.seeds = vec![fixture.seed(fixture.port, fixture.node)];
    let client = ClusterClient::new(config).unwrap();
    let mutations = [
        client
            .prepare_put("a", "b", SOURCE.as_bytes(), WriteOptions::default())
            .unwrap(),
        client
            .prepare_patch("a", "b", br#"{"$inc":{"n":1}}"#, WriteOptions::default())
            .unwrap(),
        client
            .prepare_transaction(
                br#"{"operations":[{"collection":"a","document":"b","patch":{"$inc":{"n":1}}}]}"#,
                None,
            )
            .unwrap(),
        client
            .prepare_set_indexes(br#"{"indexes":[]}"#, None, None)
            .unwrap(),
        client
            .prepare_delete("a", "b", WriteOptions::default())
            .unwrap(),
    ];
    for mutation in &mutations {
        fixture.write("corrupt-next", "");
        let error = match client.execute(mutation).unwrap_err() {
            ClusterError::Uncertain(value) => value,
            other => panic!("lost semantic receipt: {other:?}"),
        };
        assert_eq!(&error.mutation, mutation);
        let original_receipt = fixture.text(&format!("receipt-{}", fixture.count("write")));
        let recovered = client.execute(&error.mutation).unwrap();
        assert_eq!(recovered.body, original_receipt.as_bytes());
        same(&recovered, &client.execute(mutation).unwrap());
    }
    assert!(
        matches!(client.get("a", "b", None).unwrap_err(), ClusterError::Failure(e) if e.kind == yamora::ErrorKind::Http(404))
    );
}

fn gated_dispatches(same_id: bool) {
    let fixture = Fixture::new("native", true);
    let mut config = config(&fixture, false);
    config.seeds = vec![fixture.seed(fixture.port, fixture.node)];
    let client = Arc::new(ClusterClient::new(config).unwrap());
    client
        .put(
            "a",
            "b",
            b"# gated\r\nn: 0 # exact\r\n",
            WriteOptions::default(),
        )
        .unwrap();
    let mutation = Arc::new(
        client
            .prepare_patch("a", "b", br#"{"$inc":{"n":1}}"#, WriteOptions::default())
            .unwrap(),
    );
    fixture.write("gate-enable", "");
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let client = Arc::clone(&client);
            let mutation = Arc::clone(&mutation);
            thread::spawn(move || {
                if same_id {
                    client.execute(&mutation)
                } else {
                    client.patch("a", "b", br#"{"$inc":{"n":1}}"#, WriteOptions::default())
                }
            })
        })
        .collect();
    // Join every caller before assertions, including deliberately serialized reds.
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    let deadline = Instant::now() + Duration::from_secs(1);
    let stats = loop {
        let values: Vec<usize> = fixture
            .text("gate-stats")
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        if values.len() == 4 && values[0] == 0 {
            break values;
        }
        assert!(Instant::now() < deadline, "gateway did not drain");
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(
        stats,
        [0, 4, 4, 0],
        "gate must observe four dispatched mutations before release"
    );
    let receipts: Vec<_> = results.into_iter().map(Result::unwrap).collect();
    if same_id {
        for receipt in &receipts {
            same(&receipts[0], receipt);
        }
    }
    let mut ids = std::collections::BTreeSet::new();
    for sequence in 2..=5 {
        ids.insert(fixture.text(&format!("write-{sequence}.id")));
    }
    assert_eq!(ids.len(), if same_id { 1 } else { 4 });
    assert_eq!(
        client.get("a", "b", None).unwrap().source,
        format!("# gated\r\nn: {} # exact\r\n", if same_id { 1 } else { 4 }).as_bytes()
    );
}
#[test]
fn native_gate_proves_overlapping_same_id_dispatches() {
    gated_dispatches(true);
}
#[test]
fn native_gate_proves_overlapping_distinct_id_dispatches() {
    gated_dispatches(false);
}
