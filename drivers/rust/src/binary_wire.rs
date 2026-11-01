//! Strict single-stream frame and request codec; lengths checked before allocation.
use crate::{
    Result,
    binary::{BinaryEnvelope, BinaryMethod, invalid},
    tls,
    transport::Control,
};
pub(crate) struct Frame {
    pub kind: u8,
    pub body: Vec<u8>,
}
pub(crate) struct Wire {
    stream: tls::Stream,
    pub cap: usize,
    control: Control,
    pings: u8,
}
impl Wire {
    pub fn new(stream: tls::Stream, cap: usize, control: Control) -> Self {
        Self {
            stream,
            cap,
            control,
            pings: 0,
        }
    }
    pub fn send(&mut self, kind: u8, id: u32, body: &[u8]) -> Result<()> {
        self.control.remaining()?;
        if body.len() > self.cap {
            return Err(invalid());
        }
        let mut header = [0; 16];
        header[..4].copy_from_slice(b"YMBF");
        header[4] = 1;
        header[5] = kind;
        header[8..12].copy_from_slice(&id.to_be_bytes());
        header[12..].copy_from_slice(&(body.len() as u32).to_be_bytes());
        self.stream.write_bytes(&header)?;
        self.stream.write_bytes(body)?;
        self.control.remaining()?;
        Ok(())
    }
    fn exact(&mut self, bytes: &mut [u8]) -> Result<()> {
        let mut position = 0;
        while position < bytes.len() {
            let count = self.stream.read_bytes(&mut bytes[position..])?;
            if count == 0 {
                return Err(invalid());
            }
            position += count;
        }
        self.control.remaining()?;
        Ok(())
    }
    fn read(&mut self) -> Result<Frame> {
        let mut header = [0; 16];
        self.exact(&mut header)?;
        let kind = header[5];
        let id = u32::from_be_bytes(header[8..12].try_into().unwrap());
        let n = u32::from_be_bytes(header[12..].try_into().unwrap()) as usize;
        let shape = match kind {
            1 => id == 0 && n == 12,
            3 => id == 1 && (1..=2048).contains(&n),
            4 => id == 1 && n > 0,
            5 => id == 1 && n == 0,
            7 => id == 1 && n == 4,
            8 | 9 => id == 0 && n == 8,
            10 => id == 0 && n == 0,
            _ => false,
        };
        if &header[..4] != b"YMBF"
            || header[4] != 1
            || header[6..8] != [0, 0]
            || n > self.cap
            || !shape
        {
            return Err(invalid());
        }
        let mut body = vec![0; n];
        self.exact(&mut body)?;
        Ok(Frame { kind, body })
    }
    pub fn hello(&mut self) -> Result<()> {
        self.hello_protocol(1)
    }
    pub fn hello_protocol(&mut self, protocol: u16) -> Result<()> {
        let mut body = [0; 12];
        body[..2].copy_from_slice(&1u16.to_be_bytes());
        body[2..4].copy_from_slice(&protocol.to_be_bytes());
        body[4..8].copy_from_slice(&(self.cap as u32).to_be_bytes());
        body[8..].copy_from_slice(&1u32.to_be_bytes());
        self.send(1, 0, &body)?;
        let peer = self.read()?;
        if peer.kind != 1 {
            return Err(invalid());
        }
        let min = u16::from_be_bytes(peer.body[..2].try_into().unwrap());
        let max = u16::from_be_bytes(peer.body[2..4].try_into().unwrap());
        let frame = u32::from_be_bytes(peer.body[4..8].try_into().unwrap()) as usize;
        let streams = u32::from_be_bytes(peer.body[8..].try_into().unwrap());
        if !(1..=2).contains(&protocol)
            || min == 0
            || min > protocol
            || max < protocol
            || max < min
            || !(4096..=1048576).contains(&frame)
            || !(1..=128).contains(&streams)
        {
            return Err(invalid());
        }
        self.cap = self.cap.min(frame);
        Ok(())
    }
    pub fn receive(&mut self) -> Result<Frame> {
        loop {
            let frame = self.read()?;
            if frame.kind != 8 {
                return Ok(frame);
            }
            self.pings += 1;
            if self.pings > 16 {
                return Err(invalid());
            }
            self.send(9, 0, &frame.body)?;
        }
    }
}
fn tlv(out: &mut Vec<u8>, id: u16, value: &[u8]) {
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}
pub(crate) fn request(
    e: &BinaryEnvelope,
    bearer: Option<&str>,
    control: &Control,
) -> Result<Vec<u8>> {
    let remaining = control.remaining()?.as_millis().clamp(1, 30000) as u32;
    let target = crate::document_path(e.collection(), e.document())?;
    let mut out = vec![0, 1, 0, 0];
    let mut count = 5u16;
    tlv(&mut out, 1, &[e.method() as u8]);
    tlv(&mut out, 2, target.as_bytes());
    tlv(
        &mut out,
        3,
        if e.method() == BinaryMethod::Put {
            b"application/yaml"
        } else {
            b""
        },
    );
    tlv(&mut out, 4, &(e.source().len() as u64).to_be_bytes());
    if let Some(token) = bearer {
        tlv(&mut out, 5, format!("Bearer {token}").as_bytes());
        count += 1;
    }
    if let Some(value) = e.if_match() {
        tlv(&mut out, 6, value.as_bytes());
        count += 1;
    }
    if let Some(value) = e.if_none_match() {
        tlv(&mut out, 7, value.as_bytes());
        count += 1;
    }
    if let Some(value) = e.request_id() {
        tlv(&mut out, 8, &value);
        count += 1;
    }
    tlv(&mut out, 9, &remaining.to_be_bytes());
    out[2..4].copy_from_slice(&count.to_be_bytes());
    Ok(out)
}
