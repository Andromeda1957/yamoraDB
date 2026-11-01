"""Run one PHP probe with a controlling TTY and reap it if a PEM prompt blocks."""

from __future__ import annotations

import errno
import os
import pty
import select
import signal
import sys
import time


def main():
    pid, terminal = pty.fork()
    if pid == 0:
        os.execvp(sys.argv[1], sys.argv[1:])
    status = None
    deadline = time.monotonic() + 1.5
    output = bytearray()
    try:
        while True:
            if select.select([terminal], [], [], 0.02)[0]:
                try:
                    data = os.read(terminal, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not data:
                    break
                output.extend(data)
            if time.monotonic() >= deadline:
                raise TimeoutError("PHP probe blocked with a controlling TTY")
        _, status = os.waitpid(pid, 0)
        return os.waitstatus_to_exitcode(status)
    except TimeoutError as error:
        print(error, file=sys.stderr)
        return 124
    finally:
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
        os.close(terminal)
        sys.stdout.buffer.write(output)


if __name__ == "__main__":
    sys.exit(main())
