use super::*;
use std::time::Duration;

fn control() -> Control {
    Control {
        deadline: Instant::now() + Duration::from_secs(30),
        cancellation: None,
    }
}
fn envelope(method: BinaryOperationMethod, target: &str) -> BinaryOperationEnvelope {
    prepare(
        method,
        target,
        if method == BinaryOperationMethod::Get {
            ""
        } else {
            "application/json"
        },
        &[],
        &BinaryOptions {
            request_id: Some([7; 16]),
            ..Default::default()
        },
        &control(),
    )
    .unwrap()
}
fn fields(
    schema: u16,
    status: u16,
    length: u64,
    mode: Option<u8>,
    id: Option<[u8; 16]>,
) -> Vec<u8> {
    let mut list = vec![
        (1u16, status.to_be_bytes().to_vec()),
        (
            2,
            if mode == Some(1) {
                b"application/x-ndjson".to_vec()
            } else {
                b"application/json".to_vec()
            },
        ),
        (3, length.to_be_bytes().to_vec()),
        (4, length.to_be_bytes().to_vec()),
        (5, b"0123456789abcdef".to_vec()),
    ];
    if let Some(id) = id {
        list.push((12, id.to_vec()));
    }
    if let Some(mode) = mode {
        list.push((13, vec![mode]));
    }
    let mut out = schema.to_be_bytes().to_vec();
    out.extend_from_slice(&(list.len() as u16).to_be_bytes());
    for (key, value) in list {
        out.extend_from_slice(&key.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(&value);
    }
    out
}
fn cursor(n: u64) -> String {
    format!("v1.{}.{}", "a".repeat(32), format_args!("{n:016x}"))
}
fn empty_page(n: u64) -> Vec<u8> {
    format!("{{\"transactions\":[],\"next_after\":\"{}\",\"oldest_after\":\"{}\",\"checkpoint\":\"{}\",\"revision\":\"0123456789abcdef\",\"has_more\":false}}\n", cursor(n), cursor(0), cursor(n)).into_bytes()
}
#[test]
fn schema2_finite_query_patch_and_feed_metadata_are_additive() {
    for (method, target, streaming) in [
        (BinaryOperationMethod::Post, "/v1/query/a", false),
        (
            BinaryOperationMethod::Patch,
            "/v1/collections/a/documents/b",
            false,
        ),
        (
            BinaryOperationMethod::Get,
            "/v1/changes/stream?after=x",
            true,
        ),
    ] {
        let e = envelope(method, target);
        let bytes = fields(
            2,
            200,
            if streaming { 0 } else { 25 },
            Some(u8::from(streaming)),
            Some([7; 16]),
        );
        let m = metadata_schema(&bytes, 2).unwrap();
        assert!(
            correlate(&m, &e, streaming).is_ok(),
            "SCHEMA2_OPERATION_ACCEPTED"
        );
        assert!(metadata_schema(&bytes, 1).is_err(), "V1_SCHEMA_BOUNDARY");
    }
}
#[test]
fn schema2_mode_and_actual_request_identity_are_mandatory() {
    let e = envelope(BinaryOperationMethod::Post, "/v1/query/a");
    assert!(
        metadata_schema(&fields(2, 200, 1, None, Some([7; 16])), 2).is_err(),
        "MISSING_MODE_REJECTED"
    );
    assert!(
        metadata_schema(&fields(2, 200, 1, Some(2), Some([7; 16])), 2).is_err(),
        "UNKNOWN_MODE_REJECTED"
    );
    assert!(
        metadata_schema(&fields(2, 200, 1, Some(1), Some([7; 16])), 2).is_err(),
        "STREAM_LENGTH_REJECTED"
    );
    for id in [None, Some([8; 16])] {
        let m = metadata_schema(&fields(2, 200, 1, Some(0), id), 2).unwrap();
        assert!(
            correlate(&m, &e, false).is_err(),
            "OPERATION_ID_CORRELATION"
        );
    }
}
#[test]
fn raw_numbers_and_original_operation_envelope_are_lossless() {
    let bytes =
        b"{\"revision\":\"0123456789abcdef\",\"documents\":[9007199254740993,1.2300,1e999999]}";
    let c = control();
    let e = prepare(
        BinaryOperationMethod::Post,
        "/v1/query/a",
        "Application/JSON; charset=utf-8",
        bytes,
        &BinaryOptions {
            if_match: Some(""),
            request_id: Some([7; 16]),
            ..Default::default()
        },
        &c,
    )
    .unwrap();
    assert!(!e.is_mutation());
    assert_eq!(e.source(), bytes);
    assert_eq!(e.if_match(), Some(""));
    let m = metadata_schema(
        &fields(2, 200, bytes.len() as u64, Some(0), Some([7; 16])),
        2,
    )
    .unwrap();
    finite_body(&m, &e, bytes, &c).unwrap();
    let copied = e.clone();
    assert_eq!(copied.source(), bytes);
    assert_eq!(copied.content_type(), "Application/JSON; charset=utf-8");
    assert!(envelope(BinaryOperationMethod::Post, "/v1/transactions").is_mutation());
    assert!(
        envelope(
            BinaryOperationMethod::Patch,
            "/v1/collections/a/documents/b"
        )
        .is_mutation()
    );
}
#[test]
fn receipts_are_correlated_without_treating_patch_as_raw_put() {
    let c = control();
    let e = envelope(
        BinaryOperationMethod::Patch,
        "/v1/collections/a/documents/b",
    );
    let mut m = metadata_schema(&fields(2, 200, 1, Some(0), Some([7; 16])), 2).unwrap();
    m.etag = Some("\"fedcba9876543210\"".into());
    let body = br#"{"status":"stored","collection":"a","document":"b","etag":"fedcba9876543210","revision":"0123456789abcdef"}"#;
    finite_body(&m, &e, body, &c).unwrap();
    m.revision = "0000000000000000".into();
    assert!(
        finite_body(&m, &e, body, &c).is_err(),
        "PATCH_RECEIPT_CORRELATION"
    );
    let e = envelope(BinaryOperationMethod::Post, "/v1/transactions");
    m.revision = "0123456789abcdef".into();
    finite_body(
        &m,
        &e,
        br#"{"status":"committed","operations":2,"revision":"0123456789abcdef"}"#,
        &c,
    )
    .unwrap();
    assert!(
        finite_body(
            &m,
            &e,
            br#"{"status":"committed","operations":"2","revision":"0123456789abcdef"}"#,
            &c
        )
        .is_err(),
        "TRANSACTION_TYPED_COUNT"
    );
}
#[test]
fn feed_pages_validate_cursor_and_json_before_exposure() {
    let c = control();
    let bytes = empty_page(5);
    let accepted = page(bytes.clone(), &cursor(5), &c).unwrap();
    assert_eq!(accepted.bytes(), bytes);
    assert_eq!(accepted.after, cursor(5));
    assert!(
        page(bytes[..bytes.len() - 1].to_vec(), &cursor(5), &c).is_err(),
        "PARTIAL_PAGE_REJECTED"
    );
    assert!(
        page(bytes.clone(), &cursor(6), &c).is_err(),
        "CURSOR_REGRESSION_REJECTED"
    );
    let bad = String::from_utf8(bytes.clone()).unwrap().replace(
        "\"has_more\":false",
        "\"has_more\":false,\"has_\\u006dore\":false",
    );
    assert!(
        page(bad.into_bytes(), &cursor(5), &c).is_err(),
        "DUPLICATE_PAGE_REJECTED"
    );
    let terminal = format!(
        "{{\"terminal\":true,\"status\":410,\"after\":\"{}\",\"detail\":{{\"error\":\"change_token_expired\"}}}}\n",
        cursor(5)
    );
    assert_eq!(
        page(terminal.as_bytes().to_vec(), &cursor(5), &c)
            .unwrap()
            .terminal_status,
        Some(410)
    );
    assert!(
        page(terminal.into_bytes(), &cursor(6), &c).is_err(),
        "TERMINAL_LAST_CURSOR"
    );
    assert!(!token(&format!("v1.{}é{}", "a".repeat(31), "0".repeat(16))));
}
#[test]
fn feed_transaction_source_create_collection_and_resnapshot_are_native() {
    let c = control();
    let raw = format!(
        "{{\"transactions\":[{{\"token\":\"{}\",\"previous_revision\":\"0000000000000000\",\"revision\":\"0123456789abcdef\",\"resnapshot_required\":false,\"operations\":[{{\"collection\":\"a\",\"create_collection\":true}},{{\"collection\":\"a\",\"document\":\"b\",\"put\":\"# exact\\r\\nn: 9007199254740993\\r\\n\"}}]}}],\"next_after\":\"{}\",\"oldest_after\":\"{}\",\"checkpoint\":\"{}\",\"revision\":\"0123456789abcdef\",\"has_more\":false}}\n",
        cursor(1),
        cursor(1),
        cursor(0),
        cursor(1)
    );
    assert_eq!(
        page(raw.as_bytes().to_vec(), &cursor(0), &c)
            .unwrap()
            .bytes(),
        raw.as_bytes()
    );
    assert!(
        page(
            raw.replace(
                "\"resnapshot_required\":false",
                "\"resnapshot_required\":true"
            )
            .into_bytes(),
            &cursor(0),
            &c
        )
        .is_err()
    );
}
