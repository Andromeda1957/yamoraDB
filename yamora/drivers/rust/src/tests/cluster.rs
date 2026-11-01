use super::*;
#[test]
fn native_advisory_is_not_a_routing_extension() {
    let mut response=Response {status:200,body:br#"{"node":1,"leader":1,"term":1,"role":"leader","voters":3,"last":1,"committed":1,"applied":1,"failed":false,"application_compaction":{"enabled":false,"running":false,"attempted":0}}"#.to_vec(),revision:"0123456789abcdef".into(),etag:None,content_type:"application/json".into()};
    assert!(
        leader(&response, 1, 3).is_ok(),
        "CURRENT_NATIVE_ADVISORY_ACCEPTED"
    );
    response.body=br#"{"node":1,"leader":1,"term":1,"role":"leader","voters":3,"last":1,"committed":1,"applied":1,"failed":false,"application_compaction":false}"#.to_vec();
    assert!(leader(&response, 1, 3).is_err(), "ADVISORY_REQUIRES_OBJECT");
    response.body=br#"{"node":1,"leader":1,"term":1,"role":"leader","voters":3,"last":1,"committed":1,"applied":1,"failed":false,"alternate_address":"127.0.0.1:7401"}"#.to_vec();
    assert!(
        leader(&response, 1, 3).is_err(),
        "UNKNOWN_ROUTING_EXTENSION_REJECTED"
    );
}
