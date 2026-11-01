"""Standard-library HTTPS with one deadline across TCP and TLS setup."""

import http.client
import ssl
import time


class DeadlineHTTPSConnection(http.client.HTTPSConnection):
    # Runtime fields initialized by the stdlib; omitted by its typing stubs.
    _tunnel_host: str | None
    _context: ssl.SSLContext

    def __init__(self, host, port, *, deadline, context):
        self._deadline = deadline
        super().__init__(
            host, port, timeout=max(0.001, deadline - time.monotonic()), context=context
        )

    def _remaining(self):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request deadline expired")
        return remaining

    def connect(self):
        if self._tunnel_host:
            raise OSError("proxy tunnels are unsupported")
        self.timeout = self._remaining()
        http.client.HTTPConnection.connect(self)
        # HTTPConnection has completed only TCP. TLS receives the time left,
        # rather than another copy of the original connection timeout.
        self.sock.settimeout(self._remaining())
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
