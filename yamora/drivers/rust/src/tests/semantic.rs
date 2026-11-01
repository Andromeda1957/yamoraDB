use super::*;
#[test]
fn numeric_lexemes_and_unicode_are_exact() {
    let v = decode(r#"{"n":18446744073709551615,"negative":-9223372036854775808,"float":1e999,"str":"\ud83d\ude00\u0085é"}"#.as_bytes(), false).unwrap();
    assert_eq!(v.get("n").unwrap().uint().unwrap(), u64::MAX);
    assert_eq!(
        v.get("negative").unwrap(),
        &Value::Number("-9223372036854775808".into())
    );
    assert_eq!(v.get("float").unwrap(), &Value::Number("1e999".into()));
    assert_eq!(v.get("str").unwrap().text().unwrap(), "😀\u{85}é");
    for number in ["-0", "1.0", "1e0", "18446744073709551616", "\"1\"", "true"] {
        assert!(
            decode(format!("{{\"n\":{number}}}").as_bytes(), false)
                .unwrap()
                .get("n")
                .unwrap()
                .uint()
                .is_err()
        );
    }
}
#[test]
fn duplicate_decoded_keys_are_rejected_at_every_depth() {
    for body in [r#"{"node":1,"\u006eode":2}"#, r#"{"a":[{"x":0,"x":1}]}"#] {
        assert!(decode(body.as_bytes(), false).is_err());
    }
}
