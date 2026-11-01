//! Syntax validation only; preserve bytes and numbers without constructing a value tree.
use crate::{Error, Result, transport::Control};

pub(crate) fn object(bytes: &[u8], request: bool) -> Result<()> {
    validate(bytes, request, None)
}
pub(crate) fn object_controlled(bytes: &[u8], request: bool, control: &Control) -> Result<()> {
    validate(bytes, request, Some(control))
}
fn validate(bytes: &[u8], request: bool, control: Option<&Control>) -> Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::invalid("JSON requires UTF-8"))?;
    // Native structured input uses YAML's JSON subset. Literal NEL has YAML
    // line-break semantics even inside a JSON string. Require an authored escape.
    if request && text.contains('\u{0085}') {
        return Err(Error::invalid("escape NEL as \\u0085 in JSON requests"));
    }
    let mut p = Parser {
        bytes,
        pos: 0,
        nodes: 0,
        control,
    };
    p.space();
    if p.peek() != Some(b'{') {
        return Err(Error::invalid("JSON object required"));
    }
    p.value(0)?;
    p.space();
    if p.pos != bytes.len() {
        return Err(Error::invalid("trailing JSON bytes"));
    }
    Ok(())
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    nodes: usize,
    control: Option<&'a Control>,
}
impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }
    fn take(&mut self, b: u8) -> Result<()> {
        if self.peek() != Some(b) {
            return Err(Error::invalid("malformed JSON"));
        }
        self.pos += 1;
        Ok(())
    }
    fn value(&mut self, depth: usize) -> Result<()> {
        if let Some(control) = self.control {
            control.remaining()?;
        }
        self.nodes += 1;
        if depth > 80 || self.nodes > 1_000_000 {
            return Err(Error::invalid("JSON complexity exceeds limit"));
        }
        self.space();
        match self.peek() {
            Some(b'{' | b'[') => {
                let map = self.peek() == Some(b'{');
                self.pos += 1;
                self.space();
                let end = if map { b'}' } else { b']' };
                if self.peek() == Some(end) {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    if map {
                        self.string()?;
                        self.space();
                        self.take(b':')?;
                    }
                    self.value(depth + 1)?;
                    self.space();
                    if self.peek() == Some(end) {
                        self.pos += 1;
                        break;
                    }
                    self.take(b',')?;
                    self.space();
                }
                Ok(())
            }
            Some(b'"') => self.string(),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(Error::invalid("malformed JSON value")),
        }
    }
    fn literal(&mut self, value: &[u8]) -> Result<()> {
        if self.bytes.get(self.pos..self.pos + value.len()) != Some(value) {
            return Err(Error::invalid("malformed JSON literal"));
        }
        self.pos += value.len();
        Ok(())
    }
    fn hex(&mut self) -> Result<u16> {
        let mut n = 0;
        for _ in 0..4 {
            let digit = self
                .peek()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or_else(|| Error::invalid("malformed JSON escape"))?;
            self.pos += 1;
            n = n * 16 + digit as u16;
        }
        Ok(n)
    }
    fn string(&mut self) -> Result<()> {
        self.take(b'"')?;
        loop {
            if self.pos & 4095 == 0 {
                if let Some(control) = self.control {
                    control.remaining()?;
                }
            }
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                            self.pos += 1
                        }
                        Some(b'u') => {
                            self.pos += 1;
                            let code = self.hex()?;
                            if (0xd800..=0xdbff).contains(&code) {
                                self.take(b'\\')?;
                                self.take(b'u')?;
                                if !(0xdc00..=0xdfff).contains(&self.hex()?) {
                                    return Err(Error::invalid("unpaired JSON surrogate"));
                                }
                            } else if (0xdc00..=0xdfff).contains(&code) {
                                return Err(Error::invalid("unpaired JSON surrogate"));
                            }
                        }
                        _ => return Err(Error::invalid("malformed JSON escape")),
                    }
                }
                Some(0..=31) | None => return Err(Error::invalid("malformed JSON string")),
                _ => self.pos += 1,
            }
        }
    }
    fn number(&mut self) -> Result<()> {
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        if self.peek() == Some(b'0') {
            self.pos += 1;
        } else {
            self.digits()?;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.digits()?;
        }
        Ok(())
    }
    fn digits(&mut self) -> Result<()> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            if self.pos & 4095 == 0 {
                if let Some(control) = self.control {
                    control.remaining()?;
                }
            }
            self.pos += 1;
        }
        if start == self.pos {
            return Err(Error::invalid("malformed JSON number"));
        }
        Ok(())
    }
}
