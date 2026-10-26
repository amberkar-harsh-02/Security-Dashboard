"""Background threads: retention sweep, collectors and the noise generator."""

import logging
import threading

from . import blocks, db, simulator
from .collectors.host_agent import HostAgent
from .collectors.syslog_listener import SyslogListener
from .events import purge_older_than

log = logging.getLogger("siem.jobs")

RETENTION_INTERVAL_SECONDS = 3600


def _retention(stop, config):
    while not stop.is_set():
        conn = db.connect(config.DB_PATH)
        try:
            removed = purge_older_than(conn, config.RETENTION_DAYS)
            if removed:
                log.info("Retention: removed %d events older than %d days", removed, config.RETENTION_DAYS)
        except Exception:
            log.exception("Retention job failed")
        finally:
            conn.close()
        stop.wait(RETENTION_INTERVAL_SECONDS)


BLOCK_EXPIRY_SECONDS = 60


def _block_expiry(stop, config):
    """Record blocks whose time ran out (nftables already dropped them) and refresh the file."""
    while not stop.wait(BLOCK_EXPIRY_SECONDS):
        conn = db.connect(config.DB_PATH)
        try:
            blocks.expire(conn)
        except Exception:
            log.exception("Block expiry check failed")
        finally:
            conn.close()


def _thread(name, target, *args):
    threading.Thread(target=target, args=args, name=name, daemon=True).start()


def start(config, performance=None):
    """Start every enabled job. Returns an Event that stops them all when set."""
    stop = threading.Event()
    _thread("retention", _retention, stop, config)
    _thread("block-expiry", _block_expiry, stop, config)

    if performance is not None:
        _thread("performance", performance.run, stop)

    if config.SYSLOG_PORT:
        try:
            listener = SyslogListener(config.DB_PATH, config.SYSLOG_HOST, config.SYSLOG_PORT)
            _thread("syslog", listener.run, stop)
        except OSError as exc:
            log.error("Syslog listener could not bind udp://%s:%s: %s", config.SYSLOG_HOST, config.SYSLOG_PORT, exc)

    if config.HOST_AGENT_ENABLED:
        _thread("host-agent", HostAgent().run, stop, config.DB_PATH, config.HOST_AGENT_INTERVAL)

    if config.SIMULATOR_ENABLED and config.NOISE_RATE > 0:
        _thread("noise", simulator.run_noise, stop, config.DB_PATH, config.NOISE_RATE)

    return stop
