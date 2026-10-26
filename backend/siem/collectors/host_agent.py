"""Collects real security-relevant activity from the machine running the backend.

Each poll compares against the previous snapshot and reports:
- processes that started,
- listening ports that opened or closed,
- new outbound connections to public addresses.
The first poll only records a baseline.
"""

import ipaddress
import logging
import os
import socket
import time

import psutil

from .. import pipeline

log = logging.getLogger("siem.host_agent")

CONNECTION_MEMORY_SECONDS = 3600


def _is_public(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global


class HostAgent:
    def __init__(self, hostname=None):
        self.hostname = hostname or socket.gethostname()
        self.processes = None   # {(pid, create_time): name}
        self.listening = None   # {(ip, port): process name}
        self.recent_connections = {}  # (ip, port, name) -> last seen
        self.connections_available = True
        self.own_pid = os.getpid()

    def _event(self, **fields):
        return {"source": "host-agent", "host": self.hostname, **fields}

    def _snapshot_processes(self):
        current = {}
        for proc in psutil.process_iter(["pid", "name", "username", "create_time", "exe"]):
            info = proc.info
            if info["create_time"] is None:
                continue
            current[(info["pid"], info["create_time"])] = info
        return current

    def _snapshot_connections(self):
        if not self.connections_available:
            return [], {}
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            log.warning("Host agent cannot read network connections without elevated rights; skipping them")
            self.connections_available = False
            return [], {}
        listening = {}
        for conn in conns:
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                listening[(conn.laddr.ip, conn.laddr.port)] = conn.pid
        return conns, listening

    def poll(self, now=None):
        now = now or time.time()
        events = []
        baseline = self.processes is None

        processes = self._snapshot_processes()
        names = {key[0]: info["name"] for key, info in processes.items()}
        if self.processes is not None:
            for key in processes.keys() - self.processes.keys():
                info = processes[key]
                events.append(self._event(
                    category="process", action="process_started", outcome="success", severity="info",
                    user=info.get("username"), process=info.get("name"),
                    message=f"Process started: {info.get('name')} (pid {info['pid']})",
                    raw=info.get("exe"),
                ))
        self.processes = processes

        conns, listening = self._snapshot_connections()
        if self.listening is not None:
            for ip, port in listening.keys() - self.listening.keys():
                # The SIEM's own ports (web server, syslog) are expected, not news.
                if listening[(ip, port)] == self.own_pid:
                    continue
                name = names.get(listening[(ip, port)])
                events.append(self._event(
                    category="network", action="port_opened", outcome="success", severity="low",
                    dst_ip=ip, dst_port=port, process=name,
                    message=f"Port {port} opened for listening on {ip}" + (f" by {name}" if name else ""),
                ))
            for ip, port in self.listening.keys() - listening.keys():
                events.append(self._event(
                    category="network", action="port_closed", outcome="success", severity="info",
                    dst_ip=ip, dst_port=port,
                    message=f"Port {port} on {ip} stopped listening",
                ))
        self.listening = listening

        for conn in conns:
            if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr or not _is_public(conn.raddr.ip):
                continue
            name = names.get(conn.pid)
            key = (conn.raddr.ip, conn.raddr.port, name)
            first_time = key not in self.recent_connections
            self.recent_connections[key] = now
            if first_time and not baseline:
                events.append(self._event(
                    category="network", action="outbound_connection", outcome="success", severity="info",
                    src_ip=conn.laddr.ip if conn.laddr else None, src_port=conn.laddr.port if conn.laddr else None,
                    dst_ip=conn.raddr.ip, dst_port=conn.raddr.port, process=name,
                    message=f"{name or 'Unknown process'} connected to {conn.raddr.ip}:{conn.raddr.port}",
                ))
        cutoff = now - CONNECTION_MEMORY_SECONDS
        self.recent_connections = {k: t for k, t in self.recent_connections.items() if t >= cutoff}

        return events

    def run(self, stop, db_path, interval):
        log.info("Host agent watching %s every %ss", self.hostname, interval)
        while not stop.is_set():
            try:
                events = self.poll()
                if events:
                    pipeline.store(db_path, items=events)
            except Exception:
                log.exception("Host agent poll failed")
            stop.wait(interval)
