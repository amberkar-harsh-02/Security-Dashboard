"""Detection: one shared engine per process, called by the ingest pipeline after each insert."""

import logging

from .engine import Engine
from .rules import RuleError

log = logging.getLogger("siem.detection")

_engine = None


def configure(engine):
    global _engine
    _engine = engine


def get_engine():
    return _engine


def evaluate(conn, event_ids):
    """Run detection on newly stored events. Never raises: ingest must not fail because of a rule."""
    if _engine is None or not event_ids:
        return []
    try:
        return _engine.evaluate(conn, event_ids)
    except Exception:
        log.exception("Detection failed for %d events", len(event_ids))
        return []


__all__ = ["Engine", "RuleError", "configure", "evaluate", "get_engine"]
