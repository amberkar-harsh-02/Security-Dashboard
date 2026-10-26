"""Live performance of the machine running the SIEM, for the Performance page.

A background thread samples CPU, memory, disk and network every few seconds and keeps
one hour of history in memory. Rates (bytes per second) come from the difference between
two readings of psutil's counters. Nothing is written to the database.
"""

import logging
import platform
import socket
import threading
import time
from collections import deque

import psutil

log = logging.getLogger("siem.performance")

HISTORY_SECONDS = 3600
TOP_PROCESSES = 10
# Pseudo and container file systems that are not real disks.
SKIP_FSTYPES = {"squashfs", "tmpfs", "devtmpfs", "overlay", "proc", "sysfs", "cgroup", "cgroup2"}


def _rate(current, previous, seconds):
    """Bytes per second between two counter readings. Counters can reset (reboot, wrap): never negative."""
    if previous is None or seconds <= 0:
        return 0.0
    return max(0.0, (current - previous) / seconds)


class PerformanceMonitor:
    def __init__(self, interval=2.0):
        self.interval = interval
        self.history = deque(maxlen=max(1, int(HISTORY_SECONDS / interval)))
        self.lock = threading.Lock()
        self._last_counters = None  # (monotonic time, disk io, net io)
        self._processes = {}  # pid -> psutil.Process, kept so cpu_percent() has an interval
        self.processes = []
        self.disks = []
        self.load = None
        psutil.cpu_percent(percpu=True)  # first call primes the CPU counters

    # --- Static facts ---------------------------------------------------------------------

    def info(self):
        frequency = None
        try:
            freq = psutil.cpu_freq()
            frequency = round(freq.current) if freq else None
        except (OSError, NotImplementedError, AttributeError):
            pass
        return {
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "cores_logical": psutil.cpu_count(logical=True),
            "cores_physical": psutil.cpu_count(logical=False),
            "cpu_mhz": frequency,
            "memory_total": psutil.virtual_memory().total,
            "boot_time": psutil.boot_time(),
        }

    # --- Sampling -------------------------------------------------------------------------

    def _read_counters(self):
        try:
            disk = psutil.disk_io_counters()
        except (OSError, RuntimeError):
            disk = None
        net = psutil.net_io_counters()
        return time.monotonic(), disk, net

    def sample(self, now=None):
        """Take one sample, add it to the history and refresh the current-only data. Returns the sample."""
        per_core = psutil.cpu_percent(percpu=True)
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        moment, disk, net = self._read_counters()

        previous = self._last_counters
        seconds = moment - previous[0] if previous else 0
        prev_disk = previous[1] if previous else None
        prev_net = previous[2] if previous else None
        self._last_counters = (moment, disk, net)

        point = {
            "t": int((now if now is not None else time.time()) * 1000),
            "cpu": round(sum(per_core) / len(per_core), 1) if per_core else 0.0,
            "cores": [round(c, 1) for c in per_core],
            "mem_used": memory.total - memory.available,
            "mem_percent": round(memory.percent, 1),
            "swap_percent": round(swap.percent, 1),
            "disk_read": round(_rate(disk.read_bytes, prev_disk.read_bytes if prev_disk else None, seconds)) if disk else 0,
            "disk_write": round(_rate(disk.write_bytes, prev_disk.write_bytes if prev_disk else None, seconds)) if disk else 0,
            "net_recv": round(_rate(net.bytes_recv, prev_net.bytes_recv if prev_net else None, seconds)),
            "net_sent": round(_rate(net.bytes_sent, prev_net.bytes_sent if prev_net else None, seconds)),
        }

        processes = self._sample_processes()
        disks = self._sample_disks()
        try:
            load = [round(x, 2) for x in psutil.getloadavg()]
        except (OSError, AttributeError):
            load = None

        with self.lock:
            self.history.append(point)
            self.processes = processes
            self.disks = disks
            self.load = load
        return point

    def _sample_processes(self):
        seen = {}
        rows = []
        cores = psutil.cpu_count() or 1
        for fresh in psutil.process_iter(["pid", "name", "username", "memory_info"]):
            info = fresh.info
            pid = info["pid"]
            if pid == 0:  # the idle process on Windows reports free CPU, not real use
                continue
            # cpu_percent() measures since the previous call on the same Process object,
            # so keep one object per pid between samples.
            cached = self._processes.get(pid)
            timer = cached if cached is not None and cached.is_running() else fresh
            seen[pid] = timer
            try:
                cpu = timer.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            memory = info["memory_info"].rss if info.get("memory_info") else 0
            rows.append({"pid": pid, "name": info.get("name") or "?", "user": info.get("username"),
                         "cpu": round(cpu / cores, 1), "memory": memory})
        self._processes = seen

        by_cpu = sorted(rows, key=lambda r: (r["cpu"], r["memory"]), reverse=True)[:TOP_PROCESSES]
        by_memory = sorted(rows, key=lambda r: r["memory"], reverse=True)[:TOP_PROCESSES]
        top = {r["pid"]: r for r in by_cpu + by_memory}
        return {"count": len(rows), "top": list(top.values())}

    def _sample_disks(self):
        disks = []
        for part in psutil.disk_partitions(all=False):
            if part.fstype in SKIP_FSTYPES or "loop" in part.device:
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue
            disks.append({"mount": part.mountpoint, "fstype": part.fstype, "total": usage.total,
                          "used": usage.used, "percent": round(usage.percent, 1)})
        return disks

    # --- Reading --------------------------------------------------------------------------

    def snapshot(self, since=None):
        """Everything the Performance page needs. `since` (epoch ms) returns only newer history."""
        with self.lock:
            empty = not self.history
        if empty:
            self.sample()
        with self.lock:
            history = [p for p in self.history if since is None or p["t"] > since]
            return {
                "info": self.info(),
                "interval_seconds": self.interval,
                "uptime_seconds": int(time.time() - psutil.boot_time()),
                "load": self.load,
                "history": history,
                "disks": self.disks,
                "processes": self.processes,
            }

    def run(self, stop):
        log.info("Performance monitor sampling every %ss", self.interval)
        while not stop.is_set():
            try:
                self.sample()
            except Exception:
                log.exception("Performance sample failed")
            stop.wait(self.interval)
