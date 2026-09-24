"""
FAKE pyserial (HANYA untuk pengujian di lingkungan tanpa pyserial/port serial).
Meniru subset API pyserial yang dipakai uart_channel.py: serial_for_url(),
write/flush/read/in_waiting/reset_input_buffer/close/timeout.

URL: fake://<nama>#a  dan  fake://<nama>#b  = dua ujung kabel serial virtual
(dua FIFO di /tmp, jadi bisa lintas-PROSES). Ini BUKAN pyserial asli -- jalur
serial nyata (COM/tty) dan pyserial asli harus diuji di komputer Anda.
"""
import fcntl
import os
import select
import struct
import termios
import time

VERSION = "fake-0"


class Serial:
    def __init__(self, url, baudrate=115200, timeout=None):
        name, _, side = url[len("fake://"):].partition("#")
        a2b, b2a = f"/tmp/fakeser_{name}_a2b", f"/tmp/fakeser_{name}_b2a"
        for p in (a2b, b2a):
            if not os.path.exists(p):
                try:
                    os.mkfifo(p)
                except FileExistsError:
                    pass
        rd, wr = (b2a, a2b) if side == "a" else (a2b, b2a)
        self._rfd = os.open(rd, os.O_RDWR | os.O_NONBLOCK)
        self._wfd = os.open(wr, os.O_RDWR | os.O_NONBLOCK)
        self.timeout = timeout
        self.baudrate = baudrate

    @property
    def in_waiting(self):
        buf = fcntl.ioctl(self._rfd, termios.FIONREAD, struct.pack("i", 0))
        return struct.unpack("i", buf)[0]

    def write(self, data):
        view = memoryview(data)
        while view:
            try:
                n = os.write(self._wfd, view)
                view = view[n:]
            except BlockingIOError:
                select.select([], [self._wfd], [], 0.05)
        return len(data)

    def flush(self):
        pass

    def read(self, n=1):
        r, _, _ = select.select([self._rfd], [], [], self.timeout or 0)
        if not r:
            return b""
        try:
            return os.read(self._rfd, n)
        except BlockingIOError:
            return b""

    def reset_input_buffer(self):
        while self.in_waiting:
            os.read(self._rfd, 65536)

    def close(self):
        for fd in (self._rfd, self._wfd):
            try:
                os.close(fd)
            except OSError:
                pass


def serial_for_url(url, baudrate=115200, timeout=None, **kw):
    if not url.startswith("fake://"):
        raise ValueError("fake serial hanya mendukung fake://nama#a|b")
    return Serial(url, baudrate, timeout)
