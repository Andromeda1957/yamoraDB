//! Bounded semantic JSON for cluster metadata and receipts. Numeric lexemes are
//! retained verbatim: consensus u64s never pass through floating point.
use crate::{Error, Result, json, transport::Control};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}
impl Value {
    pub(crate) fn get(&self, key: &str) -> Result<&Self> {
        self.map()?.get(key).ok_or_else(invalid)
    }
    pub(crate) fn optional(&self, key: &str) -> Result<Option<&Self>> {
        Ok(self.map()?.get(key))
    }
    pub(crate) fn map(&self) -> Result<&BTreeMap<String, Self>> {
        if let Self::Object(v) = self {
            Ok(v)
        } else {
            Err(invalid())
        }
    }
    pub(crate) fn array(&self) -> Result<&[Self]> {
        if let Self::Array(v) = self {
            Ok(v)
        } else {
            Err(invalid())
        }
    }
    pub(crate) fn text(&self) -> Result<&str> {
        if let Self::String(v) = self {
            Ok(v)
        } else {
            Err(invalid())
        }
    }
    pub(crate) fn uint(&self) -> Result<u64> {
        if let Self::Number(v) = self {
            if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
                return v.parse().map_err(|_| invalid());
            }
        }
        Err(invalid())
    }
    pub(crate) fn boolean(&self) -> Result<bool> {
        if let Self::Bool(v) = self {
            Ok(*v)
        } else {
            Err(invalid())
        }
    }
    pub(crate) fn keys(&self, permitted: &[&str]) -> Result<()> {
        if self.map()?.keys().any(|k| !permitted.contains(&k.as_str())) {
            return Err(invalid());
        }
        Ok(())
    }
}
fn invalid() -> Error {
    Error::invalid("invalid cluster JSON schema")
}
pub(crate) fn decode(bytes: &[u8], request: bool) -> Result<Value> {
    json::object(bytes, request)?;
    parse(bytes, None)
}
pub(crate) fn decode_controlled(bytes: &[u8], control: &Control) -> Result<Value> {
    json::object_controlled(bytes, false, control)?;
    parse(bytes, Some(control))
}
fn parse(bytes: &[u8], control: Option<&Control>) -> Result<Value> {
    let mut parser = Parser {
        text: std::str::from_utf8(bytes).map_err(|_| invalid())?,
        pos: 0,
        nodes: 0,
        control,
    };
    parser.value(0)
}
struct Parser<'a> {
    text: &'a str,
    pos: usize,
    nodes: usize,
    control: Option<&'a Control>,
}
impl Parser<'_> {
    fn byte(&self) -> u8 {
        self.text.as_bytes().get(self.pos).copied().unwrap_or(0)
    }
    fn space(&mut self) {
        while matches!(self.byte(), b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
        if let Some(control) = self.control {
            control.remaining()?;
        }
        self.nodes += 1;
        if depth > 80 || self.nodes > 65_536 {
            return Err(invalid());
        }
        self.space();
        match self.byte() {
            b'{' => {
                self.pos += 1;
                self.space();
                let mut map = BTreeMap::new();
                while self.byte() != b'}' {
                    let key = self.string()?;
                    self.space();
                    self.pos += 1; // colon, syntax already validated
                    let value = self.value(depth + 1)?;
                    if map.insert(key, value).is_some() {
                        return Err(Error::invalid("duplicate JSON field"));
                    }
                    self.space();
                    if self.byte() != b',' {
                        break;
                    }
                    self.pos += 1;
                    self.space();
                }
                self.pos += 1;
                Ok(Value::Object(map))
            }
            b'[' => {
                self.pos += 1;
                self.space();
                let mut array = Vec::new();
                while self.byte() != b']' {
                    array.push(self.value(depth + 1)?);
                    self.space();
                    if self.byte() != b',' {
                        break;
                    }
                    self.pos += 1;
                }
                self.pos += 1;
                Ok(Value::Array(array))
            }
            b'"' => Ok(Value::String(self.string()?)),
            b't' => {
                self.pos += 4;
                Ok(Value::Bool(true))
            }
            b'f' => {
                self.pos += 5;
                Ok(Value::Bool(false))
            }
            b'n' => {
                self.pos += 4;
                Ok(Value::Null)
            }
            _ => {
                let start = self.pos;
                while matches!(self.byte(), b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                    if self.pos & 4095 == 0 {
                        if let Some(control) = self.control {
                            control.remaining()?;
                        }
                    }
                    self.pos += 1;
                }
                Ok(Value::Number(self.text[start..self.pos].to_owned()))
            }
        }
    }
    fn code(&mut self) -> Result<u32> {
        let end = self.pos + 4;
        let value = u32::from_str_radix(self.text.get(self.pos..end).ok_or_else(invalid)?, 16)
            .map_err(|_| invalid())?;
        self.pos = end;
        Ok(value)
    }
    fn string(&mut self) -> Result<String> {
        self.pos += 1;
        let mut result = String::new();
        let mut start = self.pos;
        loop {
            if self.pos & 4095 == 0 {
                if let Some(control) = self.control {
                    control.remaining()?;
                }
            }
            match self.byte() {
                b'"' => {
                    result.push_str(self.text.get(start..self.pos).ok_or_else(invalid)?);
                    self.pos += 1;
                    return Ok(result);
                }
                b'\\' => {
                    result.push_str(self.text.get(start..self.pos).ok_or_else(invalid)?);
                    self.pos += 1;
                    let escape = self.byte();
                    self.pos += 1;
                    let ch = match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut code = self.code()?;
                            if (0xd800..=0xdbff).contains(&code) {
                                self.pos += 2;
                                code = 0x10000 + ((code - 0xd800) << 10) + self.code()? - 0xdc00;
                            }
                            char::from_u32(code).ok_or_else(invalid)?
                        }
                        _ => return Err(invalid()),
                    };
                    result.push(ch);
                    start = self.pos;
                }
                0 => return Err(invalid()),
                _ => self.pos += 1,
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/semantic.rs"]
mod tests;
