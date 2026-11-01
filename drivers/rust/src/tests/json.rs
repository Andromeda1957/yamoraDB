use super::json;

#[test]
fn accepts_json_without_changing_numeric_or_string_bytes() {
    for source in [
        r#"{}"#,
        r#"{"n":9223372036854775807,"x":-0.4e+19,"s":"\ud83d\ude00\n\u0085","v":[true,false,null]}"#,
        "{\"s\":\"Straße\"}",
    ] {
        assert!(json::object(source.as_bytes(), true).is_ok(), "{source}");
    }
}

#[test]
fn rejects_invalid_json_and_excessive_complexity() {
    for source in [
        "",
        "[]",
        "null",
        "{} {}",
        "{a:1}",
        "{\"a\":01}",
        "{\"a\":1.}",
        "{\"a\":1e}",
        "{\"a\":-}",
        "{\"a\":NaN}",
        "{\"a\":true,}",
        "{\"a\":[1,]}",
        "{\"a\":\"\n\"}",
        r#"{"a":"\ud800"}"#,
        r#"{"a":"\udc00"}"#,
        r#"{"a":"\ud800\u0041"}"#,
        r#"{"a":"\x00"}"#,
        "{\"a\":\"\u{0085}\"}",
    ] {
        assert!(json::object(source.as_bytes(), true).is_err(), "{source}");
    }
    let deep = format!("{{\"a\":{}{}}}", "[".repeat(81), "]".repeat(81));
    assert!(json::object(deep.as_bytes(), true).is_err());
    assert!(json::object(b"{\"a\":\"\xff\"}", false).is_err());
}
