use crate::{CancellationToken, Error, ErrorKind, Result, TlsOptions, tls};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub(crate) struct Control {
    pub deadline: Instant,
    pub cancellation: Option<CancellationToken>,
}
impl Control {
    pub fn remaining(&self) -> Result<Duration> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(Error::new(ErrorKind::Cancelled));
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| Error::new(ErrorKind::Timeout))
    }
    fn slice(&self) -> Result<Duration> {
        Ok(if self.cancellation.is_some() {
            self.remaining()?.min(Duration::from_millis(20))
        } else {
            self.remaining()?
        })
    }
    fn retry(&self, e: &std::io::Error) -> Result<bool> {
        self.remaining()?;
        Ok(self.cancellation.is_some()
            && matches!(
                e.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ))
    }
}
pub(crate) fn remaining(control: &Control) -> Result<Duration> {
    control.remaining()
}
pub(crate) fn io(error: std::io::Error) -> Error {
    Error::new(
        if matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            ErrorKind::Timeout
        } else {
            ErrorKind::Io(error.kind())
        },
    )
}
pub(crate) fn read_socket(
    socket: &mut TcpStream,
    buf: &mut [u8],
    control: &Control,
) -> Result<usize> {
    loop {
        socket
            .set_read_timeout(Some(control.slice()?))
            .map_err(io)?;
        match socket.read(buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if control.retry(&e)? => continue,
            result => return result.map_err(io),
        }
    }
}
pub(crate) fn write_socket(
    socket: &mut TcpStream,
    mut buf: &[u8],
    control: &Control,
) -> Result<()> {
    while !buf.is_empty() {
        socket
            .set_write_timeout(Some(control.slice()?))
            .map_err(io)?;
        match socket.write(buf) {
            Ok(0) => return Err(Error::new(ErrorKind::Io(std::io::ErrorKind::WriteZero))),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if control.retry(&e)? => continue,
            Err(e) => return Err(io(e)),
        }
    }
    Ok(())
}
enum Socket {
    Plain(TcpStream),
    Secure(tls::Stream),
}
pub(crate) struct Connection {
    socket: Socket,
    control: Control,
}
impl Connection {
    pub(crate) fn connect(
        address: SocketAddr,
        timeout: Duration,
        options: Option<&TlsOptions>,
    ) -> Result<Self> {
        Self::connect_control(
            address,
            Control {
                deadline: Instant::now() + timeout,
                cancellation: None,
            },
            options,
        )
    }
    pub(crate) fn connect_control(
        address: SocketAddr,
        control: Control,
        options: Option<&TlsOptions>,
    ) -> Result<Self> {
        let socket = if control.cancellation.is_some() {
            crate::socket::connect(address, &control)?
        } else {
            TcpStream::connect_timeout(&address, control.remaining()?).map_err(io)?
        };
        socket.set_nodelay(true).map_err(io)?;
        let socket = if let Some(options) = options {
            Socket::Secure(tls::Stream::connect(
                socket,
                control.clone(),
                options,
                &address.ip().to_string(),
            )?)
        } else {
            Socket::Plain(socket)
        };
        Ok(Self { socket, control })
    }
    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &mut self.socket {
            Socket::Plain(s) => write_socket(s, bytes, &self.control),
            Socket::Secure(s) => s.write_bytes(bytes),
        }
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize> {
        match &mut self.socket {
            Socket::Plain(s) => read_socket(s, bytes, &self.control),
            Socket::Secure(s) => s.read_bytes(bytes),
        }
    }
    pub(crate) fn response(&mut self, maximum: usize, statuses: &[u16]) -> Result<WireResponse> {
        let mut header = Vec::new();
        // Read exactly the header: no unbounded read-ahead of an untrusted body.
        // Buffered body reads below carry the same absolute deadline.
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() == 16 * 1024 {
                return Err(Error::invalid("response headers exceed limit"));
            }
            let mut b = [0];
            if self.read(&mut b)? == 0 {
                return Err(Error::invalid("truncated response headers"));
            }
            header.push(b[0]);
        }
        let (status, headers) = parse_header(&header)?;
        if !statuses.contains(&status) {
            return Err(Error::new(ErrorKind::Http(status)));
        }
        if headers.contains_key("transfer-encoding") || headers.contains_key("content-encoding") {
            return Err(Error::invalid("unsupported response encoding"));
        }
        let length = headers
            .get("content-length")
            .ok_or_else(|| Error::invalid("missing Content-Length"))?;
        if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::invalid("invalid Content-Length"));
        }
        let length: usize = length
            .parse()
            .map_err(|_| Error::invalid("invalid Content-Length"))?;
        if length > maximum {
            return Err(Error::invalid("response body exceeds limit"));
        }
        let mut body = Vec::new();
        body.try_reserve_exact(length)
            .map_err(|_| Error::invalid("response allocation failed"))?;
        let mut buffer = [0; 16 * 1024];
        while body.len() < length {
            let remaining = (length - body.len()).min(buffer.len());
            let n = self.read(&mut buffer[..remaining])?;
            if n == 0 {
                return Err(Error::invalid("truncated response body"));
            }
            body.extend_from_slice(&buffer[..n]);
        }
        remaining(&self.control)?;
        Ok(WireResponse {
            status,
            headers,
            body,
        })
    }
}
pub(crate) struct WireResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}
fn parse_header(header: &[u8]) -> Result<(u16, BTreeMap<String, String>)> {
    let text =
        std::str::from_utf8(header).map_err(|_| Error::invalid("invalid response headers"))?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| Error::invalid("missing status"))?;
    let bytes = status.as_bytes();
    if bytes.len() < 12
        || !status.starts_with("HTTP/1.1 ")
        || !bytes[9..12].iter().all(u8::is_ascii_digit)
        || (bytes.len() > 12 && bytes[12] != b' ')
        || bytes.iter().any(|b| !(32..=126).contains(b))
    {
        return Err(Error::invalid("invalid response status"));
    }
    let status: u16 = status[9..12]
        .parse()
        .map_err(|_| Error::invalid("invalid status"))?;
    if !(200..=599).contains(&status) {
        return Err(Error::invalid("unsupported response status"));
    }
    let mut result: BTreeMap<String, String> = BTreeMap::new();
    for (i, line) in lines.enumerate() {
        if i >= 64 {
            return Err(Error::invalid("too many response fields"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| Error::invalid("malformed response field"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || !value.bytes().all(|b| b == b'\t' || (32..=126).contains(&b))
        {
            return Err(Error::invalid("malformed response field"));
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim_matches([' ', '\t']).to_string();
        if let Some(previous) = result.get(&name) {
            // Native cluster metadata currently emits no-store twice. Cache-Control
            // is a list field: repeating this one directive is unambiguous. Keep
            // every framing/identity duplicate and conflicting cache policy fatal.
            if name != "cache-control"
                || !previous.eq_ignore_ascii_case("no-store")
                || !value.eq_ignore_ascii_case("no-store")
            {
                return Err(Error::invalid("duplicate response field"));
            }
        } else {
            result.insert(name, value);
        }
    }
    Ok((status, result))
}
