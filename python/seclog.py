#!/usr/bin/env python3
# ============================================================================
#  seclog.py — small structured logger (JSON lines) with centralized redaction.
#  ---------------------------------------------------------------------------
#  - levels: DEBUG, INFO, WARN, ERROR
#  - emits one JSON object per line to stderr (or a file)
#  - EVERY message and extra field passes through redact.redact()
#  - never logs full HTTP bodies by default; callers pass excerpts
# ============================================================================

from __future__ import annotations

import json
import os
import sys
import threading
import time

import redact

LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
_lock = threading.Lock()


class SecLogger:
    def __init__(self, name: str = "seclog", level: str = "INFO",
                 path: str | None = None):
        self.name = name
        try:
            self.level = LEVELS.get(str(level).upper(), 20)
        except Exception:
            self.level = 20
        self.path = path
        self._fd = None

    def _emit(self, lvl: str, msg: str, **fields):
        if LEVELS[lvl] < self.level:
            return
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "level": lvl, "logger": self.name,
               "msg": redact.redact_text(msg)}
        for k, v in fields.items():
            # key-aware redaction: a field NAMED password/token/... is
            # replaced entirely even if its value is not pattern-shaped.
            rec[k] = redact.redact_value(v, key=str(k))
        line = json.dumps(rec, ensure_ascii=False, default=str)
        with _lock:
            if self.path:
                try:
                    if self._fd is None:
                        self._fd = open(self.path, "a", encoding="utf-8")
                    self._fd.write(line + "\n")
                    self._fd.flush()
                    return
                except Exception:
                    pass  # fall back to stderr
            try:
                sys.stderr.write(line + "\n")
                sys.stderr.flush()
            except Exception:
                pass

    def debug(self, msg, **kw):
        self._emit("DEBUG", msg, **kw)

    def info(self, msg, **kw):
        self._emit("INFO", msg, **kw)

    def warn(self, msg, **kw):
        self._emit("WARN", msg, **kw)

    def error(self, msg, **kw):
        self._emit("ERROR", msg, **kw)

    def close(self):
        with _lock:
            if self._fd:
                try:
                    self._fd.close()
                except Exception:
                    pass
                self._fd = None


_default = SecLogger()


def get_logger(name: str | None = None):
    if not name:
        return _default
    return SecLogger(name, level=_default.level, path=_default.path)


def configure(level: str = "INFO", path: str | None = None):
    _default.level = LEVELS.get(str(level).upper(), 20)
    _default.path = path


def log(level: str, msg: str, **fields):
    _default._emit(level.upper(), msg, **fields)


def debug(msg, **kw):
    _default.debug(msg, **kw)


def info(msg, **kw):
    _default.info(msg, **kw)


def warn(msg, **kw):
    _default.warn(msg, **kw)


def error(msg, **kw):
    _default.error(msg, **kw)
