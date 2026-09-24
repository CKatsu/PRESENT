"""
uart_channel.py
================
Jalur komunikasi serial (Tabel 1: "pustaka pyserial (atau virtual serial port)").

Kelas:
  UartChannel : pyserial. `port` boleh port nyata ("COM5", "/dev/ttyACM0" -- ESP32-S3
                lewat USB) ATAU URL pyserial ("socket://127.0.0.1:7000",
                "loop://", "rfc2217://...") lewat serial.serial_for_url().
  TcpChannel  : pengganti UART TANPA driver serial virtual (com0com sering bermasalah
                di Windows modern). Framing identik. Di CSV ditandai
                link="tcp-loopback" -- jangan dilaporkan sebagai "pengukuran UART
                hardware" (lihat README "Catatan jujur soal UART").

Keduanya berbagi logika baris/threading (`_StreamChannel`):
  * peran DEVICE: thread pembaca memanggil ack-callback untuk tiap ACK; send_data()
    dilindungi lock, sehingga banyak "perangkat" (thread) dapat berbagi SATU
    kabel serial (model gateway: 50 node dimultipleks pada satu uplink).
  * peran RECEIVER: recv_data()/send_ack() dipanggil dari thread listener.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Optional

import channel_base as cb
import config


class _StreamChannel(cb.Channel):
    def __init__(self, role: str, wire_tap=None):
        super().__init__(wire_tap)
        if role not in ("device", "receiver"):
            raise ValueError("role harus 'device' atau 'receiver'")
        self.role = role
        self._wlock = threading.Lock()
        self._buf = bytearray()
        self._stop = threading.Event()
        self._reader: Optional[threading.Thread] = None

    # --- primitif yang diimplementasikan subclass ---------------------------
    def _open(self) -> None: raise NotImplementedError
    def _close(self) -> None: raise NotImplementedError
    def _write(self, data: bytes) -> None: raise NotImplementedError
    def _read_some(self, timeout_s: float) -> Optional[bytes]:
        """Baca chunk byte (boleh kosong bila timeout); None bila koneksi tertutup."""
        raise NotImplementedError

    # --- logika bersama -----------------------------------------------------
    def connect(self) -> None:
        self._open()
        self._stop.clear()
        if self.role == "device":
            self._reader = threading.Thread(target=self._reader_loop, name="uart-ack-reader", daemon=True)
            self._reader.start()

    def close(self) -> None:
        self._stop.set()
        if self._reader is not None:
            self._reader.join(timeout=2.0)
            self._reader = None
        self._close()

    def _next_line(self, timeout_s: float) -> Optional[bytes]:
        """Satu baris lengkap (tanpa newline) atau None bila timeout/tertutup."""
        deadline = time.monotonic() + timeout_s
        while True:
            nl = self._buf.find(b"\n")
            if nl >= 0:
                line = bytes(self._buf[:nl])
                del self._buf[:nl + 1]
                return line
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            chunk = self._read_some(min(remaining, 0.05))
            if chunk is None:
                return None
            self._buf.extend(chunk)

    def _reader_loop(self) -> None:
        while not self._stop.is_set():
            line = self._next_line(0.2)
            if line is None:
                continue
            obj = cb.decode_line(line)
            if obj is not None and self._ack_cb is not None:
                self._ack_cb(obj)

    def send_data(self, env: dict) -> int:
        data = cb.encode_line(env)
        if self.wire_tap is not None:
            self.wire_tap.write(data)
        with self._wlock:
            self._write(data)
        return len(data)

    def send_ack(self, ack: dict) -> None:
        with self._wlock:
            self._write(cb.encode_line(ack))

    def recv_data(self, timeout_s: float) -> Optional[dict]:
        deadline = time.monotonic() + timeout_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            line = self._next_line(remaining)
            if line is None:
                return None
            obj = cb.decode_line(line)
            if obj is not None:
                return obj          # baris non-protokol/korup: diabaikan, lanjut membaca


class UartChannel(_StreamChannel):
    name = "uart"
    link = "serial"

    def __init__(self, role: str, port: str = config.UART_PORT, baudrate: int = config.UART_BAUDRATE,
                 settle_s: float = 2.0, wire_tap=None):
        super().__init__(role, wire_tap)
        self.port, self.baudrate, self.settle_s = port, baudrate, settle_s
        self._ser = None

    def _open(self) -> None:
        import serial  # pyserial (lazy: modul lain tidak wajib punya pyserial)
        self._ser = serial.serial_for_url(self.port, baudrate=self.baudrate, timeout=0.05)
        # ESP32 reset saat DTR/RTS berubah ketika port dibuka -> beri waktu boot
        if not self.port.startswith(("loop://", "socket://", "fake://")):
            time.sleep(self.settle_s)
        self._ser.reset_input_buffer()

    def _close(self) -> None:
        if self._ser is not None:
            self._ser.close()
            self._ser = None

    def _write(self, data: bytes) -> None:
        self._ser.write(data)
        self._ser.flush()

    def _read_some(self, timeout_s: float) -> Optional[bytes]:
        self._ser.timeout = timeout_s
        n = max(1, getattr(self._ser, "in_waiting", 0) or 1)
        return self._ser.read(n)


class TcpChannel(_StreamChannel):
    """role=receiver: bind+listen lalu accept SATU koneksi (connect() memblokir
    sampai device tersambung -- jalankan receiver LEBIH DULU).
    role=device  : connect dengan retry singkat."""
    name = "uart"
    link = "tcp-loopback"

    def __init__(self, role: str, host: str = config.TCP_HOST, port: int = config.TCP_PORT, wire_tap=None):
        super().__init__(role, wire_tap)
        self.host, self.port = host, port
        self._sock: Optional[socket.socket] = None
        self._listen: Optional[socket.socket] = None

    def _accept(self) -> None:
        """Tunggu SATU koneksi masuk (bisa dipanggil ulang saat device putus/sambung lagi)."""
        while not self._stop.is_set():
            try:
                self._sock, _ = self._listen.accept()
                self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self._buf.clear()
                return
            except socket.timeout:
                continue

    def _open(self) -> None:
        if self.role == "receiver":
            self._listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listen.bind((self.host, self.port))
            self._listen.listen(1)
            self._listen.settimeout(0.5)
            self._accept()
        else:
            last = None
            for _ in range(30):
                try:
                    self._sock = socket.create_connection((self.host, self.port), timeout=2.0)
                    last = None
                    break
                except OSError as exc:
                    last = exc
                    time.sleep(0.5)
            if last is not None:
                raise ConnectionError(f"Gagal connect ke {self.host}:{self.port} -- jalankan receiver_server.py "
                                      f"--tcp-port {self.port} LEBIH DULU. Error: {last}")
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _close(self) -> None:
        for s in (self._sock, self._listen):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        self._sock = self._listen = None

    def _write(self, data: bytes) -> None:
        self._sock.sendall(data)

    def _read_some(self, timeout_s: float) -> Optional[bytes]:
        if self._sock is None:
            return None
        self._sock.settimeout(timeout_s)
        try:
            data = self._sock.recv(65536)
        except socket.timeout:
            return b""
        except OSError:
            data = b""
        if data:
            return data
        # koneksi ditutup lawan bicara
        if self.role == "receiver" and self._listen is not None and not self._stop.is_set():
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._accept()                 # tunggu device berikutnya (sesi baru)
            return b""
        return None
