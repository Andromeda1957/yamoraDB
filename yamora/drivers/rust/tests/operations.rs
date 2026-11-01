//! Exercise page delivery through the public API and an independent TLS peer.
#[allow(dead_code)] // Reuse owned certificate/process lifecycle, without native helpers.
mod binary_support;
use binary_support::Fixture;
use std::time::{Duration, Instant};
use yamora::{BinaryClient, BinaryOptions, CancellationToken, ErrorKind};

const AFTER: &str = "v1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.0000000000000005";
fn target(case: &str) -> String {
    format!("/v1/changes/stream?after={AFTER}&case={case}")
}
fn options(token: Option<&CancellationToken>) -> BinaryOptions<'_> {
    BinaryOptions {
        request_id: Some([7; 16]),
        cancellation: token,
        ..Default::default()
    }
}

#[test]
fn callback_cancellation_keeps_the_delivered_cursor_and_does_not_expose_a_second_page() {
    for cancel_token in [false, true] {
        let fixture = Fixture::new("operations");
        let client = fixture.client();
        let token = CancellationToken::new();
        let mut count = 0;
        let error = client
            .feed(&target("complete"), options(Some(&token)), |page| {
                count += 1;
                assert!(page.bytes().ends_with(b"\n"));
                assert_eq!(page.after, AFTER);
                if cancel_token {
                    token.cancel();
                }
                cancel_token
            })
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Cancelled);
        assert_eq!(count, 1, "CALLBACK_BACKPRESSURE_CANCEL");
        assert_eq!(
            error.last_after.as_deref(),
            Some(AFTER),
            "DELIVERED_CANCEL_CURSOR"
        );
        assert_eq!(error.metadata.as_ref().unwrap().status, 200);
        assert!(!error.may_have_committed());
        assert_eq!(fixture.count("dispatch"), 1);
    }
}

#[test]
fn normal_end_and_truncated_next_page_have_distinct_outcomes() {
    for (case, expected) in [("complete", 2), ("partial", 1)] {
        let fixture = Fixture::new("operations");
        let mut count = 0;
        let result = fixture.client().feed(&target(case), options(None), |_| {
            count += 1;
            true
        });
        assert_eq!(count, expected, "COMPLETE_PREFIX_ONLY");
        if case == "complete" {
            let result = result.unwrap();
            assert_eq!(result.last_after.as_deref(), Some(AFTER));
            assert_eq!(result.terminal_status, None);
        } else {
            let error = result.unwrap_err();
            assert!(matches!(error.kind, ErrorKind::Invalid(_)));
            assert_eq!(error.last_after.as_deref(), Some(AFTER));
        }
    }
}

#[test]
fn deadline_includes_waiting_for_end_after_a_complete_delivered_page() {
    let fixture = Fixture::new("operations");
    let mut config = fixture.config();
    config.timeout = Duration::from_secs(1);
    let client = BinaryClient::new(config).unwrap();
    let mut count = 0;
    let start = Instant::now();
    let error = client
        .feed(&target("deadline"), options(None), |_| {
            count += 1;
            true
        })
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);
    assert_eq!(count, 1, "DEADLINE_COMPLETE_PREFIX");
    assert_eq!(
        error.last_after.as_deref(),
        Some(AFTER),
        "DEADLINE_DELIVERED_CURSOR"
    );
    assert!(start.elapsed() < Duration::from_millis(1400));
    assert!(!error.may_have_committed());
}
