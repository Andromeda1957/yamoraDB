use super::*;
use std::time::{Duration, Instant};
#[test]
fn native_hash_unsigned_octets_and_cooperative_deadline() {
    let control = Control {
        deadline: Instant::now() + Duration::from_secs(1),
        cancellation: None,
    };
    assert_eq!(source_etag(b"", &control).unwrap(), "\"14650fb0739d0383\"");
    let expired = Control {
        deadline: Instant::now(),
        cancellation: None,
    };
    assert_eq!(
        source_etag(b"value: 1\n", &expired).unwrap_err().kind,
        ErrorKind::Timeout
    );
}
