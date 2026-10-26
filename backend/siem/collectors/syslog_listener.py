"""UDP syslog receiver. Point rsyslog, a firewall or a router at SIEM_SYSLOG_PORT."""

import logging
import socket
import time

from .. import pipeline

log = logging.getLogger("siem.syslog")

FLUSH_SECONDS = 1.0
FLUSH_SIZE = 200
MAX_DATAGRAM = 64 * 1024


class SyslogListener:
    def __init__(self, db_path, host, port):
        self.db_path = db_path
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.5)
        self.address = self.sock.getsockname()
        self.received = 0

    def run(self, stop):
        log.info("Listening for syslog on udp://%s:%d", *self.address)
        buffer = []  # (line, sender ip)
        last_flush = time.monotonic()
        try:
            while not stop.is_set():
                try:
                    data, (sender, _port) = self.sock.recvfrom(MAX_DATAGRAM)
                    text = data.decode("utf-8", errors="replace")
                    buffer.extend((line, sender) for line in text.splitlines() if line.strip())
                except socket.timeout:
                    pass
                except OSError:
                    if stop.is_set():
                        break
                    raise

                due = time.monotonic() - last_flush >= FLUSH_SECONDS
                if buffer and (due or len(buffer) >= FLUSH_SIZE):
                    self._flush(buffer)
                    buffer = []
                    last_flush = time.monotonic()
                elif due:
                    last_flush = time.monotonic()
            if buffer:
                self._flush(buffer)
        finally:
            self.sock.close()

    def _flush(self, buffer):
        # Group by sender so the sender IP can be the host fallback.
        by_sender = {}
        for line, sender in buffer:
            by_sender.setdefault(sender, []).append(line)
        for sender, lines in by_sender.items():
            try:
                self.received += len(pipeline.store(self.db_path, lines=lines, default_host=sender))
            except Exception:
                log.exception("Failed to store %d syslog lines from %s", len(lines), sender)
