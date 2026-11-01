//! Cancellable Linux TCP connect. One owned nonblocking socket survives every
//! poll slice; cancellation never restarts a SYN or leaves a connecting worker.
use crate::{Error, Result, transport::Control};
use std::net::{SocketAddr, TcpStream};

pub(crate) fn connect(address: SocketAddr, control: &Control) -> Result<TcpStream> {
    #[cfg(target_os = "linux")]
    {
        linux::connect(address, control)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (address, control);
        Err(Error::invalid(
            "cancellable TCP connect is qualified only on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::transport::io as map_io;
    use std::{
        ffi::{c_int, c_short, c_void},
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        time::Duration,
    };
    #[repr(C)]
    struct Address {
        family: u16,
        port: u16,
        ip: [u8; 4],
        zero: [u8; 8],
    }
    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: c_short,
        revents: c_short,
    }
    unsafe extern "C" {
        fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        #[link_name = "connect"]
        fn connect_fd(fd: c_int, address: *const c_void, length: u32) -> c_int;
        fn poll(fds: *mut PollFd, count: usize, timeout: c_int) -> c_int;
        fn getsockopt(
            fd: c_int,
            level: c_int,
            option: c_int,
            value: *mut c_void,
            length: *mut u32,
        ) -> c_int;
    }
    pub(super) fn connect(address: SocketAddr, control: &Control) -> Result<TcpStream> {
        let SocketAddr::V4(address) = address else {
            return Err(Error::invalid("numeric IPv4 required"));
        };
        control.remaining()?;
        // Linux AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC. OwnedFd
        // closes on every cancellation/error; no raw descriptor is shared.
        let raw = unsafe { socket(2, 1 | 0x800 | 0x80000, 0) };
        if raw < 0 {
            return Err(map_io(std::io::Error::last_os_error()));
        }
        // SAFETY: socket returned a new, nonnegative exclusively owned fd.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let target = Address {
            family: 2,
            port: address.port().to_be(),
            ip: address.ip().octets(),
            zero: [0; 8],
        };
        // SAFETY: repr(C) sockaddr_in has Linux's exact 16-byte IPv4 layout;
        // target lives throughout this call and connect does not retain it.
        let result = unsafe {
            connect_fd(
                socket.as_raw_fd(),
                (&target as *const Address).cast(),
                size_of::<Address>() as u32,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(4 | 114 | 115)) {
                // EINTR/EALREADY/EINPROGRESS
                return Err(map_io(error));
            }
            loop {
                let wait = control.remaining()?.min(Duration::from_millis(20));
                let millis = wait.as_millis().max(1) as c_int;
                let mut descriptor = PollFd {
                    fd: socket.as_raw_fd(),
                    events: 4,
                    revents: 0,
                }; // POLLOUT
                // SAFETY: one initialized pollfd, exclusively borrowed for poll.
                let ready = unsafe { poll(&mut descriptor, 1, millis) };
                if ready < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(map_io(error));
                }
                control.remaining()?;
                if ready == 0 {
                    continue;
                }
                let mut error: c_int = 0;
                let mut length = size_of::<c_int>() as u32;
                // SAFETY: both output pointers have exactly the declared sizes;
                // SOL_SOCKET/SO_ERROR queries the same owned connecting socket.
                let checked = unsafe {
                    getsockopt(
                        socket.as_raw_fd(),
                        1,
                        4,
                        (&mut error as *mut c_int).cast(),
                        &mut length,
                    )
                };
                if checked != 0 {
                    return Err(map_io(std::io::Error::last_os_error()));
                }
                if error != 0 {
                    return Err(map_io(std::io::Error::from_raw_os_error(error)));
                }
                if descriptor.revents & 4 == 0 {
                    return Err(map_io(std::io::Error::from(
                        std::io::ErrorKind::ConnectionAborted,
                    )));
                }
                break;
            }
        }
        control.remaining()?;
        let stream = TcpStream::from(socket);
        stream.set_nonblocking(false).map_err(map_io)?;
        Ok(stream)
    }
}
