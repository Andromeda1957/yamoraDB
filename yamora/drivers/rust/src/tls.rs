//! OpenSSL owns cryptography, verification and TLS state in this unsafe module.
//! Memory BIOs keep socket I/O in Rust (absolute deadlines and no SIGPIPE).
//! No raw pointer leaves this module; a context and SSL are local to one call.
use crate::{
    Error, Result, TlsOptions,
    transport::{Control, read_socket, remaining, write_socket},
};
use std::{
    ffi::{CString, c_char, c_int, c_long, c_void},
    net::TcpStream,
    ptr::{self, NonNull},
};
type Opaque = c_void;
#[link(name = "ssl")]
unsafe extern "C" {
    fn TLS_client_method() -> *const Opaque;
    fn SSL_CTX_new(method: *const Opaque) -> *mut Opaque;
    fn SSL_CTX_free(ctx: *mut Opaque);
    fn SSL_CTX_ctrl(ctx: *mut Opaque, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn SSL_CTX_set_verify(
        ctx: *mut Opaque,
        mode: c_int,
        callback: Option<unsafe extern "C" fn(c_int, *mut Opaque) -> c_int>,
    );
    fn SSL_CTX_load_verify_locations(
        ctx: *mut Opaque,
        file: *const c_char,
        dir: *const c_char,
    ) -> c_int;
    fn SSL_CTX_set_default_passwd_cb(
        ctx: *mut Opaque,
        cb: Option<unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int>,
    );
    fn SSL_CTX_use_certificate_chain_file(ctx: *mut Opaque, file: *const c_char) -> c_int;
    fn SSL_CTX_use_PrivateKey_file(ctx: *mut Opaque, file: *const c_char, kind: c_int) -> c_int;
    fn SSL_CTX_check_private_key(ctx: *const Opaque) -> c_int;
    fn SSL_new(ctx: *mut Opaque) -> *mut Opaque;
    fn SSL_free(ssl: *mut Opaque);
    fn SSL_set_bio(ssl: *mut Opaque, read: *mut Opaque, write: *mut Opaque);
    fn SSL_set1_host(ssl: *mut Opaque, host: *const c_char) -> c_int;
    fn SSL_get0_alpn_selected(ssl: *const Opaque, data: *mut *const u8, len: *mut u32);
    fn SSL_CTX_use_certificate(ctx: *mut Opaque, cert: *mut Opaque) -> c_int;
    fn SSL_CTX_use_PrivateKey(ctx: *mut Opaque, key: *mut Opaque) -> c_int;
    fn SSL_CTX_get_cert_store(ctx: *const Opaque) -> *mut Opaque;
    fn SSL_get0_param(ssl: *mut Opaque) -> *mut Opaque;
    fn SSL_ctrl(ssl: *mut Opaque, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn SSL_set_alpn_protos(ssl: *mut Opaque, protos: *const u8, len: u32) -> c_int;
    fn SSL_connect(ssl: *mut Opaque) -> c_int;
    fn SSL_get_error(ssl: *const Opaque, result: c_int) -> c_int;
    fn SSL_get_verify_result(ssl: *const Opaque) -> c_long;
    fn SSL_version(ssl: *const Opaque) -> c_int;
    fn SSL_read_ex(ssl: *mut Opaque, buf: *mut c_void, size: usize, read: *mut usize) -> c_int;
    fn SSL_write_ex(
        ssl: *mut Opaque,
        buf: *const c_void,
        size: usize,
        written: *mut usize,
    ) -> c_int;
}
#[link(name = "crypto")]
unsafe extern "C" {
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut Opaque;
    fn PEM_read_bio_X509(
        bio: *mut Opaque,
        cert: *mut *mut Opaque,
        cb: Option<unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int>,
        data: *mut c_void,
    ) -> *mut Opaque;
    fn PEM_read_bio_PrivateKey(
        bio: *mut Opaque,
        key: *mut *mut Opaque,
        cb: Option<unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int>,
        data: *mut c_void,
    ) -> *mut Opaque;
    fn X509_STORE_add_cert(store: *mut Opaque, cert: *mut Opaque) -> c_int;
    fn X509_free(cert: *mut Opaque);
    fn EVP_PKEY_free(key: *mut Opaque);
    fn RAND_bytes(bytes: *mut u8, count: c_int) -> c_int;
    fn BIO_s_mem() -> *const Opaque;
    fn BIO_new(method: *const Opaque) -> *mut Opaque;
    fn BIO_free(bio: *mut Opaque) -> c_int;
    fn BIO_read(bio: *mut Opaque, buf: *mut c_void, size: c_int) -> c_int;
    fn BIO_write(bio: *mut Opaque, buf: *const c_void, size: c_int) -> c_int;
    fn BIO_ctrl_pending(bio: *mut Opaque) -> usize;
    fn X509_VERIFY_PARAM_set1_ip_asc(param: *mut Opaque, ip: *const c_char) -> c_int;
    fn X509_VERIFY_PARAM_set_hostflags(param: *mut Opaque, flags: u32);
    fn ERR_clear_error();
}

struct Context(NonNull<Opaque>);
impl Drop for Context {
    fn drop(&mut self) {
        unsafe { SSL_CTX_free(self.0.as_ptr()) }
    }
}
unsafe extern "C" fn no_password(_: *mut c_char, _: c_int, _: c_int, _: *mut c_void) -> c_int {
    0
}
fn cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::invalid("NUL in TLS configuration"))
}
fn check(ok: c_int) -> Result<()> {
    if ok == 1 { Ok(()) } else { Err(Error::tls()) }
}
impl Context {
    fn new(options: &TlsOptions) -> Result<Self> {
        let ca = cstring(
            options
                .ca_file
                .to_str()
                .ok_or_else(|| Error::invalid("TLS path requires UTF-8"))?,
        )?;
        // SAFETY: strings stay live through each call; OpenSSL copies file data.
        // The nonnull context is exclusively owned and freed on every exit path.
        unsafe {
            ERR_clear_error();
            let ctx = Self(NonNull::new(SSL_CTX_new(TLS_client_method())).ok_or_else(Error::tls)?);
            for cmd in [123, 124] {
                // SSL_CTRL_SET_{MIN,MAX}_PROTO_VERSION; TLS1_3_VERSION
                if SSL_CTX_ctrl(ctx.0.as_ptr(), cmd, 0x0304, ptr::null_mut()) != 1 {
                    return Err(Error::tls());
                }
            }
            SSL_CTX_set_verify(ctx.0.as_ptr(), 1, None); // SSL_VERIFY_PEER; built-in verifier
            SSL_CTX_set_default_passwd_cb(ctx.0.as_ptr(), Some(no_password));
            check(SSL_CTX_load_verify_locations(
                ctx.0.as_ptr(),
                ca.as_ptr(),
                ptr::null(),
            ))?;
            if let Some(identity) = &options.identity {
                let cert = cstring(
                    identity
                        .certificate
                        .to_str()
                        .ok_or_else(|| Error::invalid("TLS path requires UTF-8"))?,
                )?;
                let key = cstring(
                    identity
                        .private_key
                        .to_str()
                        .ok_or_else(|| Error::invalid("TLS path requires UTF-8"))?,
                )?;
                check(SSL_CTX_use_certificate_chain_file(
                    ctx.0.as_ptr(),
                    cert.as_ptr(),
                ))?;
                check(SSL_CTX_use_PrivateKey_file(ctx.0.as_ptr(), key.as_ptr(), 1))?; // SSL_FILETYPE_PEM
                check(SSL_CTX_check_private_key(ctx.0.as_ptr()))?;
            }
            Ok(ctx)
        }
    }
}
pub(crate) fn validate(options: &TlsOptions) -> Result<()> {
    if let Some(name) = &options.server_name {
        if name.len() > 253
            || name.is_empty()
            || name.parse::<std::net::IpAddr>().is_ok()
            || !name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(Error::invalid("invalid TLS DNS verification name"));
        }
    }
    Context::new(options).map(|_| ())
}

pub(crate) struct Stream {
    ssl: NonNull<Opaque>,
    read_bio: NonNull<Opaque>,
    write_bio: NonNull<Opaque>,
    _context: Context,
    socket: TcpStream,
    control: Control,
}
impl Drop for Stream {
    fn drop(&mut self) {
        unsafe { SSL_free(self.ssl.as_ptr()) }
    }
}
impl Stream {
    pub(crate) fn connect(
        socket: TcpStream,
        control: Control,
        options: &TlsOptions,
        ip: &str,
    ) -> Result<Self> {
        let context = Context::new(options)?;
        Self::connect_context(
            socket,
            control,
            context,
            options.server_name.as_deref().unwrap_or(ip),
            options.server_name.is_some(),
            false,
        )
    }
    pub(crate) fn connect_binary(
        socket: TcpStream,
        control: Control,
        options: &crate::binary::BinaryTlsConfig,
    ) -> Result<Self> {
        let context = Context::binary(options)?;
        Self::connect_context(
            socket,
            control,
            context,
            &options.server_name,
            options.server_name.parse::<std::net::Ipv4Addr>().is_err(),
            true,
        )
    }
    fn connect_context(
        socket: TcpStream,
        control: Control,
        context: Context,
        identity: &str,
        dns: bool,
        binary: bool,
    ) -> Result<Self> {
        // SAFETY: ownership transfers to Stream immediately. Distinct memory BIOs
        // transfer to SSL_set_bio; SSL_free frees them once, before context.
        let mut stream = unsafe {
            let ssl = NonNull::new(SSL_new(context.0.as_ptr())).ok_or_else(Error::tls)?;
            let read = NonNull::new(BIO_new(BIO_s_mem()));
            let write = NonNull::new(BIO_new(BIO_s_mem()));
            let (Some(read_bio), Some(write_bio)) = (read, write) else {
                if let Some(bio) = read {
                    BIO_free(bio.as_ptr());
                }
                if let Some(bio) = write {
                    BIO_free(bio.as_ptr());
                }
                SSL_free(ssl.as_ptr());
                return Err(Error::tls());
            };
            SSL_set_bio(ssl.as_ptr(), read_bio.as_ptr(), write_bio.as_ptr());
            Self {
                ssl,
                read_bio,
                write_bio,
                _context: context,
                socket,
                control,
            }
        };
        let name = cstring(identity)?;
        unsafe {
            let ssl = stream.ssl.as_ptr();
            let param = SSL_get0_param(ssl);
            // X509_CHECK_FLAG_NEVER_CHECK_SUBJECT: require subjectAltName.
            X509_VERIFY_PARAM_set_hostflags(param, 0x20);
            if dns {
                check(SSL_set1_host(ssl, name.as_ptr()))?;
                if SSL_ctrl(ssl, 55, 0, name.as_ptr().cast_mut().cast()) != 1 {
                    return Err(Error::tls());
                }
            } else {
                check(X509_VERIFY_PARAM_set1_ip_asc(param, name.as_ptr()))?;
            }
            let alpn: &[u8] = if binary {
                b"\x0fyamora-binary/1"
            } else {
                b"\x08http/1.1"
            };
            if SSL_set_alpn_protos(ssl, alpn.as_ptr(), alpn.len() as u32) != 0 {
                return Err(Error::tls());
            }
        }
        loop {
            remaining(&stream.control)?;
            let (rc, error) = unsafe {
                ERR_clear_error();
                let rc = SSL_connect(stream.ssl.as_ptr());
                (rc, SSL_get_error(stream.ssl.as_ptr(), rc))
            };
            stream.flush_tls()?;
            if rc == 1 {
                break;
            }
            stream.advance(error)?;
        }
        unsafe {
            if SSL_get_verify_result(stream.ssl.as_ptr()) != 0
                || SSL_version(stream.ssl.as_ptr()) != 0x0304
            {
                return Err(Error::tls());
            }
        }
        if binary {
            let mut selected = ptr::null();
            let mut length = 0;
            // SAFETY: OpenSSL retains this slice until SSL_free. Compare only
            // after checking its length and nonnull pointer; never expose it.
            unsafe {
                SSL_get0_alpn_selected(stream.ssl.as_ptr(), &mut selected, &mut length);
                if length != 15
                    || selected.is_null()
                    || std::slice::from_raw_parts(selected, length as usize) != b"yamora-binary/1"
                {
                    return Err(Error::tls());
                }
            }
        }
        remaining(&stream.control)?;
        Ok(stream)
    }
    fn flush_tls(&mut self) -> Result<()> {
        let mut buf = [0u8; 16 * 1024];
        unsafe {
            while BIO_ctrl_pending(self.write_bio.as_ptr()) != 0 {
                remaining(&self.control)?;
                let n = BIO_read(
                    self.write_bio.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len() as c_int,
                );
                if n <= 0 {
                    return Err(Error::tls());
                }
                write_socket(&mut self.socket, &buf[..n as usize], &self.control)?;
            }
        }
        Ok(())
    }
    fn advance(&mut self, error: c_int) -> Result<()> {
        if error != 2 {
            return Err(Error::tls());
        } // SSL_ERROR_WANT_READ (memory BIOs cannot WANT_WRITE)
        let mut buf = [0u8; 16 * 1024];
        let n = read_socket(&mut self.socket, &mut buf, &self.control)?;
        if n == 0 {
            return Err(Error::tls());
        } // truncated TLS never becomes close_notify
        unsafe {
            if BIO_write(self.read_bio.as_ptr(), buf.as_ptr().cast(), n as c_int) != n as c_int {
                return Err(Error::tls());
            }
        }
        Ok(())
    }
    pub(crate) fn read_bytes(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            remaining(&self.control)?;
            let mut n = 0;
            let (rc, error) = unsafe {
                ERR_clear_error();
                let rc = SSL_read_ex(
                    self.ssl.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    &mut n,
                );
                (rc, SSL_get_error(self.ssl.as_ptr(), rc))
            };
            self.flush_tls()?;
            if rc == 1 {
                return Ok(n);
            }
            if error == 6 {
                return Ok(0);
            } // authenticated close_notify
            self.advance(error)?;
        }
    }
    pub(crate) fn write_bytes(&mut self, buf: &[u8]) -> Result<()> {
        // One record at a time bounds BIO output independently of body size.
        for chunk in buf.chunks(16 * 1024) {
            loop {
                remaining(&self.control)?;
                let mut n = 0;
                let (rc, error) = unsafe {
                    ERR_clear_error();
                    let rc = SSL_write_ex(
                        self.ssl.as_ptr(),
                        chunk.as_ptr().cast(),
                        chunk.len(),
                        &mut n,
                    );
                    (rc, SSL_get_error(self.ssl.as_ptr(), rc))
                };
                self.flush_tls()?;
                if rc == 1 {
                    if n != chunk.len() {
                        return Err(Error::tls());
                    }
                    break;
                }
                self.advance(error)?;
            }
        }
        Ok(())
    }
}

// Binary configuration never retains paths or caller-controlled OpenSSL objects.
// Each PEM block is bounded, parsed into a new owned object, then released after
// OpenSSL has acquired its reference. Extra-chain insertion transfers ownership.
impl Context {
    fn binary(options: &crate::binary::BinaryTlsConfig) -> Result<Self> {
        unsafe {
            ERR_clear_error();
            let ctx = Self(NonNull::new(SSL_CTX_new(TLS_client_method())).ok_or_else(Error::tls)?);
            for command in [123, 124] {
                if SSL_CTX_ctrl(ctx.0.as_ptr(), command, 0x0304, ptr::null_mut()) != 1 {
                    return Err(Error::tls());
                }
            }
            SSL_CTX_set_verify(ctx.0.as_ptr(), 1, None);
            SSL_CTX_set_default_passwd_cb(ctx.0.as_ptr(), Some(no_password));
            for block in pem_blocks(&options.root_pem, "CERTIFICATE", 32)? {
                let certificate = read_pem(block, false)?;
                let result = X509_STORE_add_cert(
                    SSL_CTX_get_cert_store(ctx.0.as_ptr()),
                    certificate.as_ptr(),
                );
                X509_free(certificate.as_ptr());
                check(result)?;
            }
            if let Some(identity) = &options.identity {
                for (index, block) in pem_blocks(&identity.certificate_pem, "CERTIFICATE", 32)?
                    .iter()
                    .enumerate()
                {
                    let certificate = read_pem(block, false)?;
                    if index == 0 {
                        let result = SSL_CTX_use_certificate(ctx.0.as_ptr(), certificate.as_ptr());
                        X509_free(certificate.as_ptr());
                        check(result)?;
                    } else if SSL_CTX_ctrl(ctx.0.as_ptr(), 14, 0, certificate.as_ptr()) != 1 {
                        // SSL_CTRL_EXTRA_CHAIN_CERT takes the reference only on success.
                        X509_free(certificate.as_ptr());
                        return Err(Error::tls());
                    }
                }
                let label = if identity
                    .private_key_pem
                    .starts_with(b"-----BEGIN RSA PRIVATE KEY-----")
                {
                    "RSA PRIVATE KEY"
                } else if identity
                    .private_key_pem
                    .starts_with(b"-----BEGIN EC PRIVATE KEY-----")
                {
                    "EC PRIVATE KEY"
                } else {
                    "PRIVATE KEY"
                };
                let blocks = pem_blocks(&identity.private_key_pem, label, 1)?;
                let key = read_pem(blocks[0], true)?;
                let result = SSL_CTX_use_PrivateKey(ctx.0.as_ptr(), key.as_ptr());
                EVP_PKEY_free(key.as_ptr());
                check(result)?;
                check(SSL_CTX_check_private_key(ctx.0.as_ptr()))?;
            }
            Ok(ctx)
        }
    }
}
fn pem_blocks<'a>(bytes: &'a [u8], label: &str, maximum: usize) -> Result<Vec<&'a [u8]>> {
    if bytes.is_empty() || bytes.len() > 65536 {
        return Err(Error::tls());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::tls())?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut tail = text.trim_matches(|c: char| c.is_ascii_whitespace());
    let mut result = Vec::new();
    while !tail.is_empty() {
        if result.len() == maximum || !tail.starts_with(&begin) {
            return Err(Error::tls());
        }
        let length = tail.find(&end).ok_or_else(Error::tls)? + end.len();
        let block = &tail[..length];
        if block.matches("-----BEGIN ").count() != 1 {
            return Err(Error::tls());
        }
        result.push(block.as_bytes());
        tail = tail[length..].trim_matches(|c: char| c.is_ascii_whitespace());
    }
    if result.is_empty() {
        return Err(Error::tls());
    }
    Ok(result)
}
fn read_pem(bytes: &[u8], key: bool) -> Result<NonNull<Opaque>> {
    // SAFETY: memory BIO borrows the bounded input only until BIO_free below.
    // The returned X509/EVP_PKEY owns its decoded allocation independently.
    unsafe {
        let bio = NonNull::new(BIO_new_mem_buf(bytes.as_ptr().cast(), bytes.len() as c_int))
            .ok_or_else(Error::tls)?;
        let object = if key {
            PEM_read_bio_PrivateKey(
                bio.as_ptr(),
                ptr::null_mut(),
                Some(no_password),
                ptr::null_mut(),
            )
        } else {
            PEM_read_bio_X509(bio.as_ptr(), ptr::null_mut(), None, ptr::null_mut())
        };
        BIO_free(bio.as_ptr());
        NonNull::new(object).ok_or_else(Error::tls)
    }
}
pub(crate) fn validate_binary(options: &crate::binary::BinaryTlsConfig) -> Result<()> {
    Context::binary(options).map(|_| ())
}
pub(crate) fn binary_random() -> Result<[u8; 16]> {
    let mut bytes = [0; 16];
    // SAFETY: RAND_bytes receives exactly 16 writable bytes, no callbacks.
    unsafe {
        check(RAND_bytes(bytes.as_mut_ptr(), 16))?;
    }
    if bytes == [0; 16] {
        return Err(Error::tls());
    }
    Ok(bytes)
}
