//! Complete END plus correlated native metadata/source/receipt is success.
use crate::{
    Error, ErrorKind, MAX_DOCUMENT_BYTES, Result,
    binary::{BinaryEnvelope, BinaryMethod, BinaryResponse, invalid, source_etag},
    binary_wire::Wire,
    semantic,
    transport::Control,
};
pub(crate) struct Metadata {
    pub status: u16,
    pub media: String,
    pub length: usize,
    pub representation: usize,
    pub revision: String,
    pub etag: Option<String>,
    pub collection: Option<String>,
    pub document: Option<String>,
    pub id: Option<[u8; 16]>,
    pub allow: bool,
    pub authenticate: bool,
    pub streaming: bool,
}
fn text(bytes: &[u8], max: usize) -> Result<String> {
    if bytes.is_empty() || bytes.len() > max || !bytes.iter().all(|b| (32..=126).contains(b)) {
        return Err(invalid());
    }
    Ok(std::str::from_utf8(bytes)
        .map_err(|_| invalid())?
        .to_owned())
}
fn uint(bytes: &[u8], width: usize) -> Result<u64> {
    if bytes.len() != width {
        return Err(invalid());
    }
    Ok(bytes
        .iter()
        .fold(0, |value, b| (value << 8) | u64::from(*b)))
}
fn metadata(bytes: &[u8]) -> Result<Metadata> {
    metadata_schema(bytes, 1)
}
pub(crate) fn metadata_schema(bytes: &[u8], schema: u16) -> Result<Metadata> {
    if !(1..=2).contains(&schema)
        || bytes.len() < 4
        || bytes.len() > 2048
        || bytes[..2] != schema.to_be_bytes()
    {
        return Err(invalid());
    }
    let count = uint(&bytes[2..4], 2)?;
    let maximum = if schema == 2 { 13 } else { 12 };
    if !(5..=maximum as u64).contains(&count) {
        return Err(invalid());
    }
    let mut fields: [Option<&[u8]>; 14] = [None; 14];
    let mut position = 4;
    let mut last = 0;
    for _ in 0..count {
        if position + 4 > bytes.len() {
            return Err(invalid());
        }
        let id = uint(&bytes[position..position + 2], 2)? as usize;
        let len = uint(&bytes[position + 2..position + 4], 2)? as usize;
        position += 4;
        if id <= last || id > maximum || position + len > bytes.len() {
            return Err(invalid());
        }
        fields[id] = Some(&bytes[position..position + len]);
        position += len;
        last = id;
    }
    if position != bytes.len() || fields[1..=5].iter().any(Option::is_none) {
        return Err(invalid());
    }
    let required = |n: usize| fields[n].ok_or_else(invalid);
    let status = uint(required(1)?, 2)? as u16;
    let media = text(required(2)?, 95)?;
    let length = uint(required(3)?, 8)?;
    let representation = uint(required(4)?, 8)?;
    let revision = text(required(5)?, 16)?;
    if !(200..=599).contains(&status)
        || length > MAX_DOCUMENT_BYTES as u64
        || representation > MAX_DOCUMENT_BYTES as u64
        || (length != 0 && length != representation)
        || (status == 204 && (length != 0 || representation != 0))
        || (status == 304 && length != 0)
        || !crate::hex(&revision, 16)
    {
        return Err(invalid());
    }
    let etag = fields[6]
        .map(|b| {
            let t = text(b, 18)?;
            if t.len() != 18
                || !t.starts_with('"')
                || !t.ends_with('"')
                || !crate::hex(&t[1..17], 16)
            {
                return Err(invalid());
            }
            Ok(t)
        })
        .transpose()?;
    let name = |id: usize| -> Result<Option<String>> {
        fields[id]
            .map(|b| {
                let t = text(b, 128)?;
                crate::id(&t)?;
                Ok(t)
            })
            .transpose()
    };
    let collection = name(7)?;
    let document = name(8)?;
    if let Some(b) = fields[9] {
        let mask = uint(b, 1)?;
        if !(1..=if schema == 2 { 63 } else { 15 }).contains(&mask) || status != 405 {
            return Err(invalid());
        }
    }
    if let Some(b) = fields[10] {
        if uint(b, 1)? != 1 || status != 401 {
            return Err(invalid());
        }
    }
    if let Some(b) = fields[11] {
        uint(b, 4)?;
        if status != 429 && status != 503 {
            return Err(invalid());
        }
    }
    let id = fields[12]
        .map(|b| {
            let id: [u8; 16] = b.try_into().map_err(|_| invalid())?;
            if id == [0; 16] {
                return Err(invalid());
            }
            Ok(id)
        })
        .transpose()?;
    let streaming = if schema == 2 {
        let mode = uint(required(13)?, 1)?;
        if mode > 1 || (mode == 1 && (status != 200 || length != 0 || representation != 0)) {
            return Err(invalid());
        }
        mode == 1
    } else {
        false
    };
    Ok(Metadata {
        status,
        media,
        length: length as usize,
        representation: representation as usize,
        revision,
        etag,
        collection,
        document,
        id,
        allow: fields[9].is_some(),
        authenticate: fields[10].is_some(),
        streaming,
    })
}
fn correlate(m: &Metadata, e: &BinaryEnvelope) -> Result<()> {
    let head = e.method() == BinaryMethod::Head;
    if m.id != e.request_id()
        || m.collection.as_deref().is_some_and(|c| c != e.collection())
        || m.document.as_deref().is_some_and(|d| d != e.document())
        || (head && m.length != 0)
        || (!head && m.length != m.representation)
        || ((e.method().is_mutation() || m.status >= 400) && m.representation > 4096)
        || (m.status == 401 && !m.authenticate)
        || (m.status == 405 && !m.allow)
    {
        return Err(invalid());
    }
    let base = m.media.split(';').next().unwrap_or("");
    let json = base.eq_ignore_ascii_case("application/json");
    if m.status >= 400 {
        return if json { Ok(()) } else { Err(invalid()) };
    }
    match e.method() {
        BinaryMethod::Get | BinaryMethod::Head => {
            if m.status != 200
                || !(base.eq_ignore_ascii_case("application/yaml")
                    || base.eq_ignore_ascii_case("text/yaml"))
                || m.etag.is_none()
                || m.collection.as_deref() != Some(e.collection())
                || m.document.as_deref() != Some(e.document())
            {
                return Err(invalid());
            }
        }
        BinaryMethod::Put => {
            if !json
                || !matches!(m.status, 200 | 201)
                || m.length == 0
                || m.etag.is_none()
                || (e.if_none_match() == Some("*") && m.status != 201)
                || (e.if_match().is_some() && m.status != 200)
            {
                return Err(invalid());
            }
        }
        BinaryMethod::Delete => {
            if !json || m.status != 204 || m.etag.is_some() {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
pub(crate) fn receive(
    wire: &mut Wire,
    e: &BinaryEnvelope,
    control: &Control,
) -> Result<BinaryResponse> {
    let first = wire.receive()?;
    if first.kind != 3 {
        return Err(invalid());
    }
    let m = metadata(&first.body)?;
    correlate(&m, e)?;
    // Method/status budget and full metadata correlation precede allocation.
    let mut body = Vec::new();
    body.try_reserve_exact(m.length).map_err(|_| invalid())?;
    loop {
        let next = wire.receive()?;
        match next.kind {
            4 if next.body.len() <= m.length - body.len() => body.extend_from_slice(&next.body),
            5 if body.len() == m.length => break,
            _ => return Err(invalid()), // includes ERROR1/GOAWAY/HELLO/PONG/partial END
        }
    }
    control.remaining()?;
    if e.method() == BinaryMethod::Get && m.status == 200 {
        if Some(source_etag(&body, control)?) != m.etag {
            return Err(invalid());
        }
    } else if e.method() != BinaryMethod::Head && m.status != 204 {
        // JSON is at most 4096 bytes: strict UTF-8, no duplicates, bounded
        // depth/nodes and retained integer lexemes through the native parser.
        let value = semantic::decode(&body, false)?;
        if m.status >= 400 {
            value.keys(&["error"])?;
            let error = value.get("error")?.text()?;
            if error.is_empty()
                || error.len() > 128
                || !error
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(invalid());
            }
        } else if e.method() == BinaryMethod::Put {
            value.keys(&["status", "collection", "document", "revision", "etag"])?;
            let tag = value.get("etag")?.text()?;
            if value.get("status")?.text()? != "stored"
                || value.get("collection")?.text()? != e.collection()
                || value.get("document")?.text()? != e.document()
                || value.get("revision")?.text()? != m.revision
                || !crate::hex(tag, 16)
                || m.etag.as_deref() != Some(format!("\"{tag}\"").as_str())
                || Some(source_etag(e.source(), control)?) != m.etag
            {
                return Err(invalid());
            }
        } else {
            return Err(invalid());
        }
    }
    control.remaining()?;
    if m.status >= 400 {
        return Err(Error::new(ErrorKind::Http(m.status)));
    }
    Ok(BinaryResponse::new(
        m.status,
        m.revision,
        m.etag,
        m.representation,
        body,
    ))
}
#[cfg(test)]
#[path = "tests/binary_reply.rs"]
mod tests;
