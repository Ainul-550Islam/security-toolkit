#!/usr/bin/env python3
# ============================================================================
#  notify.py — Phase 5 provider-neutral notifications + secure webhook
#              delivery.
#  ---------------------------------------------------------------------------
#  - Provider abstraction: WebhookProvider (real, SSRF-hardened, HMAC-signed),
#    EmailProvider (interface only — no SMTP bundled; no external creds
#    required anywhere, tests never touch the network).
#  - Webhook SSRF defense: https-only, URL userinfo rejected, host/IP
#    denylist (localhost/loopback/private/link-local/metadata/reserved),
#    DNS resolution re-checked (all addresses must be public), no redirects,
#    bounded timeout + bounded response, explicit port allowlist.
#  - HMAC: X-Security-Toolkit-Timestamp + X-Security-Toolkit-Signature over
#    "timestamp.body"; constant-time verification helper for inbound hooks.
#  - Delivery idempotency: notification id is deterministic per
#    (project, occurrence event, channel) — re-dispatch can never duplicate.
#  - Retries: bounded attempts, deterministic backoff, permanent config
#    errors dead-letter immediately; dead-lettered rows are manual-retry-only.
#  - Secrets (webhook secret) are read ONLY by the provider; every view,
#    attempt record and audit payload is redacted; never logged.
# ============================================================================

from __future__ import annotations

import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from services.crypto import (
    CryptoError,
    CryptoNotConfigured,
    CryptoService,
    EncryptedValueError,
)

import errors
import metrics
import models
import redact
import store

# --- bounds (never unbounded I/O) -------------------------------------------
WEBHOOK_TIMEOUT_SECONDS = 6.0
WEBHOOK_MAX_RESPONSE = 8192          # bytes read from a webhook response
WEBHOOK_PORTS = (443, 8443, 9443)    # https ports (explicit allowlist)
NOTIFICATION_MAX_ATTEMPTS = 3
NOTIFY_RETRY_LIMIT = 20        # manual retries per actor per window
NOTIFY_RETRY_WINDOW = 300      # seconds
RETRY_BASE_SECONDS = 60              # 60s, 120s, 240s (deterministic backoff)
MAX_RESPONSE_HEADERS = 24
_SECRET_MIN_LEN = 8
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,24}$")
_TS_TOLERANCE_SECONDS = 300


def _safe_delivery_error(outcome: str, error: Any) -> str:
    """Return a closed, client-safe delivery error; never retain provider text."""
    try:
        candidate = str(error or "")[:500]
    except Exception:
        candidate = ""
    normalized = candidate.strip().lower()
    if re.fullmatch(r"http [1-5][0-9]{2}", normalized):
        return normalized
    if normalized in {
        "email transport not configured (no recipient)",
        "email transport not configured (smtp adapter required — see docs)",
    }:
        return "email transport not configured"
    if normalized == "recording provider failure":
        return "recording provider failure"
    if normalized == "unknown provider channel":
        return "unknown provider channel"
    if normalized == "webhook destination rejected":
        return normalized
    if normalized == "webhook redirect refused":
        return normalized
    if normalized == "webhook request timed out":
        return normalized
    if normalized == "webhook delivery failed":
        return normalized
    if normalized == "provider request timed out":
        return normalized
    if outcome == "invalid":
        return "provider configuration rejected"
    if outcome == "redirect":
        return "provider redirect refused"
    if outcome == "timeout":
        return "provider request timed out"
    if outcome == "skipped":
        return "provider unavailable"
    return "provider delivery failed"


def _epoch(ts: str) -> float:
    try:
        return time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return 0.0


def _iso(ep: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ep))


# ---------------------------------------------------------------------------
# SSRF-safe URL validation
# ---------------------------------------------------------------------------
_HOST_DENYLIST_SUFFIXES = (".local", ".internal", ".localhost", ".home.arpa",
                           ".lan", ".test", ".invalid", ".example")
_DENYLIST_HOSTS = frozenset({"localhost", "metadata", "metadata.google.internal",
                             "169.254.169.254"})


def _ip_allowed(ip: str) -> bool:
    """Public IPs only (fail closed on anything ambiguous)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local or \
            addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return False
    return True


def validate_webhook_url(url: str, *, resolve: bool = True) -> str:
    """Raise ValidationError unless the destination is a safe, public,
    https endpoint. `resolve=False` skips DNS (format checks only)."""
    raw = str(url or "").strip()
    if len(raw) > 512:
        raise errors.ValidationError("webhook_url_rejected: too long")
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme != "https":
        raise errors.ValidationError(
            "webhook_url_rejected: https required (HTTP is refused; use a "
            "TLS-terminating relay)")
    if parts.username or parts.password:
        raise errors.ValidationError(
            "webhook_url_rejected: userinfo is not allowed")
    if parts.port and parts.port not in WEBHOOK_PORTS:
        raise errors.ValidationError(
            f"webhook_url_rejected: port {parts.port} not allowed "
            f"(ports {WEBHOOK_PORTS})")
    host = (parts.hostname or "").strip().rstrip(".")
    if not host:
        raise errors.ValidationError("webhook_url_rejected: empty host")
    host_l = host.lower()
    if host_l in _DENYLIST_HOSTS:
        raise errors.ValidationError(
            "webhook_url_rejected: host is on the denylist")
    for suffix in _HOST_DENYLIST_SUFFIXES:
        if host_l.endswith(suffix):
            raise errors.ValidationError(
                f"webhook_url_rejected: {suffix} hosts are refused")
    # literal IP: check directly (no DNS needed); hostnames resolve below
    try:
        ipaddress.ip_address(host)
        is_literal = True
    except ValueError:
        is_literal = False
    if is_literal and not _ip_allowed(host):
        raise errors.ValidationError(
            "webhook_url_rejected: non-public address")
    if resolve:
        try:
            infos = socket.getaddrinfo(host, parts.port or 443,
                                       proto=socket.IPPROTO_TCP)
        except OSError as e:
            raise errors.ValidationError(
                f"webhook_url_rejected: resolution failed ({e})") from e
        seen = set()
        for info in infos:
            ip = info[4][0]
            if ip in seen:
                continue
            seen.add(ip)
            if not _ip_allowed(ip):
                raise errors.ValidationError(
                    "webhook_url_rejected: destination resolves to a "
                    "non-public address")
        if not seen:
            raise errors.ValidationError(
                "webhook_url_rejected: no addresses resolved")
    return raw


# ---------------------------------------------------------------------------
# HMAC signing (constant-time verification for inbound validation)
# ---------------------------------------------------------------------------
def sign_payload(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(str(secret).encode("utf-8"),
                   f"{timestamp}.{body.decode('utf-8', 'replace')}"
                   .encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()


def verify_signature(secret: str, timestamp: str, body: bytes,
                     signature: str) -> bool:
    """Constant-time verification of X-Security-Toolkit-Signature plus a
    bounded timestamp window (replay guard)."""
    try:
        ts = float(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(time.time() - ts) > _TS_TOLERANCE_SECONDS:
        return False
    expected = sign_payload(secret, timestamp, body)
    if not isinstance(signature, str):
        return False
    return hmac.compare_digest(expected, signature.lower())


# ---------------------------------------------------------------------------
# Provider adapters (provider-neutral; no hard-coded external services)
# ---------------------------------------------------------------------------
_LEGACY_KEYFILE_NAME = ".secutoolkit_webhook.key"
_LEGACY_KEY_BYTES = 32
_LEGACY_MAX_BYTES = 1_048_576
_LEGACY_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
_AEAD_PREFIX = "st-aesgcm:"


def _notification_secret_aad(org_id: str, project_id: str) -> str:
    tenant = str(org_id or "")
    project = str(project_id or "")
    if not tenant or not project or ":" in tenant or ":" in project:
        raise errors.ConfigurationError("notification_secret_context_invalid")
    return f"notification-settings:webhook-secret:v1:{tenant}:{project}"


def _legacy_keyfile_path(db_path: str) -> str:
    """Locate the historical local key solely for one-way data migration."""
    directory = os.path.dirname(os.path.abspath(str(db_path) or "."))
    return os.path.join(directory, _LEGACY_KEYFILE_NAME)


def _load_legacy_key(db_path: str) -> bytes:
    """Read a pre-existing legacy key; never create or replace one."""
    path = _legacy_keyfile_path(db_path)
    try:
        with open(path, "rb") as handle:
            key = handle.read(_LEGACY_KEY_BYTES + 1)
    except FileNotFoundError:
        legacy_environment_key = os.environ.get("SECTOOLKIT_WEBHOOK_KEY", "")
        if legacy_environment_key:
            return hashlib.sha256(legacy_environment_key.encode("utf-8")).digest()
        raise errors.ConfigurationError(
            "legacy_webhook_key_unavailable: existing notification secret cannot be migrated"
        ) from None
    except OSError:
        legacy_environment_key = os.environ.get("SECTOOLKIT_WEBHOOK_KEY", "")
        if legacy_environment_key:
            return hashlib.sha256(legacy_environment_key.encode("utf-8")).digest()
        raise errors.ConfigurationError(
            "legacy_webhook_key_unavailable: existing notification secret cannot be migrated"
        ) from None
    if len(key) != _LEGACY_KEY_BYTES:
        raise errors.ConfigurationError(
            "legacy_webhook_key_invalid: existing notification secret cannot be migrated"
        )
    return key


def _legacy_keystream(key: bytes, length: int) -> bytes:
    """Reproduce the retired format for decrypt-only migration compatibility."""
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(key + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def _decrypt_legacy_xor(blob: str, db_path: str) -> str:
    """Decrypt the unauthenticated historical format only for AEAD migration."""
    if (
        not isinstance(blob, str)
        or not blob
        or len(blob) % 2
        or len(blob) > _LEGACY_MAX_BYTES * 2
        or not _LEGACY_HEX_RE.fullmatch(blob)
    ):
        raise errors.ConfigurationError(
            "legacy_webhook_ciphertext_invalid: migration is required"
        )
    try:
        ciphertext = binascii.unhexlify(blob)
        key = _load_legacy_key(db_path)
        stream = _legacy_keystream(key, len(ciphertext))
        plaintext = bytes(left ^ right for left, right in zip(ciphertext, stream))
        return plaintext.decode("utf-8", "strict")
    except (UnicodeDecodeError, ValueError, binascii.Error):
        raise errors.ConfigurationError(
            "legacy_webhook_migration_failed: secret could not be migrated"
        ) from None


def _encrypt_secret(
    secret: str,
    db_path: str,
    associated_data: str = "notification:webhook-secret",
) -> str:
    """Compatibility helper backed only by the shared AES-GCM service."""
    del db_path
    if not secret:
        return ""
    try:
        return CryptoService().encrypt_text(
            str(secret), associated_data=associated_data
        )
    except CryptoNotConfigured:
        raise errors.ConfigurationError(
            "notification_secret_encryption_unavailable"
        ) from None
    except EncryptedValueError:
        raise errors.ValidationError(
            "notification_secret_encryption_failed"
        ) from None
    except CryptoError:
        raise errors.ConfigurationError(
            "notification_secret_encryption_unavailable"
        ) from None


def _decrypt_secret(
    blob: str,
    db_path: str,
    associated_data: str = "notification:webhook-secret",
) -> str:
    """Decrypt current AEAD or read a legacy value for immediate migration."""
    if not blob:
        return ""
    if str(blob).startswith(_AEAD_PREFIX):
        try:
            return CryptoService().decrypt_text(
                str(blob), associated_data=associated_data
            )
        except CryptoNotConfigured:
            raise errors.ConfigurationError(
                "notification_secret_decryption_unavailable"
            ) from None
        except EncryptedValueError:
            raise errors.PersistenceError(
                "notification_secret_authentication_failed"
            ) from None
    return _decrypt_legacy_xor(str(blob), db_path)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused",
                                     headers, fp)


class WebhookProvider:
    """Real HTTPS delivery with SSRF protection + HMAC signing."""

    name = "webhook"

    def send(self, settings: dict, payload: dict) -> dict:
        url = str(settings.get("webhook_url", "") or "")
        try:
            validate_webhook_url(url)
        except errors.ValidationError:
            return {"ok": False, "outcome": "invalid",
                    "error": "webhook destination rejected"}
        secret = str(settings.get("webhook_secret", "") or "")
        body = json.dumps(redact.redact(payload), ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
        ts = str(int(time.time()))
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SecuToolkit-Monitor/1.0",
            "X-Security-Toolkit-Timestamp": ts,
            "X-Security-Toolkit-Signature": sign_payload(secret, ts, body),
        }
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method="POST")
        opener = urllib.request.build_opener(_NoRedirect)
        started = time.time()
        try:
            with opener.open(req, timeout=WEBHOOK_TIMEOUT_SECONDS) as resp:
                status = int(resp.status)
                data = resp.read(WEBHOOK_MAX_RESPONSE)
                if status >= 300:
                    return {"ok": False, "outcome": "failed",
                            "error": f"http {status}", "status": status}
                return {"ok": True, "outcome": "sent", "status": status,
                        "duration_ms": round((time.time() - started) * 1000, 1)}
        except urllib.error.HTTPError as e:  # includes refused redirects
            redirect = e.code in (301, 302, 303, 307, 308)
            return {"ok": False,
                    "outcome": "redirect" if redirect else "failed",
                    "error": "webhook redirect refused" if redirect else f"http {e.code}",
                    "status": int(e.code)}
        except (urllib.error.URLError, socket.timeout, TimeoutError,
                ssl.SSLError, ConnectionError, OSError) as exc:
            timed_out = isinstance(exc, (socket.timeout, TimeoutError))
            return {
                "ok": False,
                "outcome": "timeout" if timed_out else "failed",
                "error": "webhook request timed out" if timed_out else "webhook delivery failed",
            }
        except Exception:
            return {"ok": False, "outcome": "failed",
                    "error": "webhook delivery failed"}


class EmailProvider:
    """Email interface (provider-neutral). No SMTP client is bundled —
    deployments provide an adapter with their own transport; until then the
    interface reports an explicit configuration error (honest, no fake send)."""

    name = "email"

    def send(self, settings: dict, payload: dict) -> dict:
        to = str(settings.get("email_to", "") or "")
        if not to:
            return {"ok": False, "outcome": "invalid",
                    "error": "email transport not configured (no recipient)"}
        return {"ok": False, "outcome": "invalid",
                "error": "email transport not configured (SMTP adapter "
                         "required — see docs)"}


class RecordingProvider:
    """Deterministic in-memory provider for tests/demos (never network)."""

    def __init__(self, *, fail: bool = False):
        self.name = "recording"
        self.fail = bool(fail)
        self.deliveries: list[dict] = []

    def send(self, settings: dict, payload: dict) -> dict:
        if self.fail:
            return {"ok": False, "outcome": "failed",
                    "error": "recording provider failure"}
        self.deliveries.append(dict(payload))
        return {"ok": True, "outcome": "sent", "status": 200, "duration_ms": 1.0}


PROVIDERS = {"webhook": WebhookProvider(), "email": EmailProvider()}


# ---------------------------------------------------------------------------
# Settings (provisioning; secret never serialized)
# ---------------------------------------------------------------------------
class NotificationService:
    """Dispatcher: deterministic delivery, idempotency, bounded retries."""

    def __init__(self, platform, *, providers: dict | None = None,
                 limiter=None):
        self.svc = platform
        self.db = platform.db
        self.providers = dict(providers or PROVIDERS)
        self.limiter = limiter
        self.max_attempts = NOTIFICATION_MAX_ATTEMPTS

    def _acquire(self, key: str, limit: int, window: int) -> None:
        """Rate-limit gate for user-driven notification operations."""
        if self.limiter is None:
            import identity as _id
            self.limiter = _id.RateLimiter()
        ok, retry = self.limiter.allowed(key, limit, window)
        if not ok:
            raise errors.RateLimitedError(
                f"rate_limited: retry after {retry}s ({limit}/{window}s)")

    # ------------------------------------------------------- settings
    def settings_get(self, project_id: str) -> dict:
        project = self.svc.project_require(project_id)
        rows = self.db.query(
            "SELECT * FROM notification_settings WHERE project_id=? LIMIT 1",
            (project_id,))
        if not rows:
            return {"project_id": project_id, "email_enabled": False,
                    "email_to": "", "webhook_enabled": False,
                    "webhook_url": "", "webhook_secret": "",
                    "has_secret": False}
        r = rows[0]
        stored_secret = str(r.get("webhook_secret", "") or "")
        context = _notification_secret_aad(project.org_id, project_id)
        secret = _decrypt_secret(stored_secret, self.svc.db_path, context)
        if stored_secret and not stored_secret.startswith(_AEAD_PREFIX):
            migrated = _encrypt_secret(secret, self.svc.db_path, context)
            changed = self.db.execute_affected(
                "UPDATE notification_settings SET webhook_secret=?, updated_at=? "
                "WHERE project_id=? AND webhook_secret=?",
                (migrated, models.utcnow(), project_id, stored_secret),
            )
            if changed:
                self.svc.audit(
                    "notification.secret.migrated",
                    object_type="project",
                    object_id=project_id,
                    org_id=project.org_id,
                    project_id=project_id,
                    actor="crypto:migration",
                    metadata={"cipher_version": "v1"},
                )
            else:
                latest = self.db.query(
                    "SELECT webhook_secret FROM notification_settings "
                    "WHERE project_id=? LIMIT 1",
                    (project_id,),
                )
                if not latest or latest[0].get("webhook_secret") == stored_secret:
                    raise errors.PersistenceError(
                        "notification_secret_migration_conflict"
                    )
                secret = _decrypt_secret(
                    str(latest[0].get("webhook_secret", "") or ""),
                    self.svc.db_path,
                    context,
                )
        return {"project_id": project_id,
                "email_enabled": bool(r.get("email_enabled")),
                # Internal delivery configuration only. Public consumers must
                # use settings_view(), which redacts endpoint values.
                "email_to": str(r.get("email_to", "")),
                "webhook_enabled": bool(r.get("webhook_enabled")),
                "webhook_url": str(r.get("webhook_url", "")),
                # internal only (signing); every view masks this key
                "webhook_secret": secret,
                "has_secret": bool(stored_secret)}

    def settings_view(self, project_id: str) -> dict:
        self.svc.project_require(project_id)
        rows = self.db.query(
            "SELECT email_enabled, email_to, webhook_enabled, webhook_url, "
            "webhook_secret FROM notification_settings WHERE project_id=? "
            "LIMIT 1",
            (project_id,),
        )
        if not rows:
            return {"project_id": project_id, "email_enabled": False,
                    "email_to": "", "webhook_enabled": False,
                    "webhook_url": "", "has_secret": False}
        row = rows[0]
        return {
            "project_id": project_id,
            "email_enabled": bool(row.get("email_enabled")),
            "email_to": redact.redact_text(str(row.get("email_to", ""))),
            "webhook_enabled": bool(row.get("webhook_enabled")),
            "webhook_url": redact.redact_text(str(row.get("webhook_url", ""))),
            "has_secret": bool(row.get("webhook_secret", "")),
        }

    def settings_set(self, project_id: str, *, email_enabled: bool = False,
                     email_to: str = "", webhook_enabled: bool = False,
                     webhook_url: str = "", webhook_secret: str = "",
                     keep_secret: bool = False, actor: str = "cli") -> dict:
        self.svc.project_require(project_id)
        project = self.svc.project_get(project_id)
        if email_enabled:
            if not _EMAIL_RE.match(str(email_to or "").strip()):
                raise errors.ValidationError(
                    "settings_rejected: invalid email_to address")
        if webhook_enabled:
            # format + deny-list checks at save time; the DNS re-check runs
            # at delivery time (WebhookProvider) so a transient DNS outage
            # never blocks configuration while delivery stays fail-closed.
            validate_webhook_url(webhook_url, resolve=False)
        secret = str(webhook_secret or "")
        if secret and len(secret) < _SECRET_MIN_LEN:
            raise errors.ValidationError(
                "settings_rejected: webhook secret must be at least "
                f"{_SECRET_MIN_LEN} characters")
        if len(secret.encode("utf-8")) > 4096:
            raise errors.ValidationError("settings_rejected: webhook secret is too large")
        existing = self.db.query(
            "SELECT * FROM notification_settings WHERE project_id=? LIMIT 1",
            (project_id,))
        context = _notification_secret_aad(project.org_id, project_id)
        legacy_migrated = False
        if not secret and keep_secret and existing:
            stored_secret = str(existing[0].get("webhook_secret", "") or "")
            if stored_secret and not stored_secret.startswith(_AEAD_PREFIX):
                legacy_plaintext = _decrypt_secret(
                    stored_secret, self.svc.db_path, context
                )
                stored_secret = _encrypt_secret(
                    legacy_plaintext, self.svc.db_path, context
                )
                legacy_migrated = True
        else:
            stored_secret = _encrypt_secret(secret, self.svc.db_path, context)
        now = models.utcnow()
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO notification_settings (project_id, org_id, "
                "email_enabled, email_to, webhook_enabled, webhook_url, "
                "webhook_secret, updated_at) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(project_id) DO UPDATE SET email_enabled="
                "excluded.email_enabled, email_to=excluded.email_to, "
                "webhook_enabled=excluded.webhook_enabled, "
                "webhook_url=excluded.webhook_url, "
                "webhook_secret=excluded.webhook_secret, "
                "updated_at=excluded.updated_at",
                (project_id, project.org_id, 1 if email_enabled else 0,
                 str(email_to)[:200], 1 if webhook_enabled else 0,
                 str(webhook_url)[:512], stored_secret, now))
        self.svc.audit("notification.settings.updated",
                       object_type="project", object_id=project_id,
                       org_id=project.org_id, project_id=project_id,
                       actor=actor,
                       metadata={"email_enabled": bool(email_enabled),
                                 "webhook_enabled": bool(webhook_enabled),
                                 "webhook_url": redact.redact_text(
                                     str(webhook_url)[:200])})
        if legacy_migrated:
            self.svc.audit(
                "notification.secret.migrated",
                object_type="project",
                object_id=project_id,
                org_id=project.org_id,
                project_id=project_id,
                actor="crypto:migration",
                metadata={"cipher_version": "v1"},
            )
        return self.settings_view(project_id)

    # ------------------------------------------------------ dispatch
    def dispatch_alert(self, alert_id: str, occurrence_event_id: str,
                       rule: dict, *, actor: str = "scheduler",
                       org_id: str | None = None) -> int:
        """Create idempotent pending notifications for one alert tenant."""
        if org_id:
            rows = self.db.query(
                "SELECT * FROM alerts WHERE id=? AND org_id=? LIMIT 1",
                (alert_id, org_id),
            )
        else:
            rows = self.db.query("SELECT * FROM alerts WHERE id=? LIMIT 1",
                                 (alert_id,))
        if not rows:
            return 0
        alert = rows[0]
        settings = self.settings_get(alert["project_id"])
        created = 0
        for channel in ("email", "webhook"):
            enabled = settings.get(f"{channel}_enabled")
            if not enabled:
                continue
            nid = models.stable_id(
                models.NS_NOTIF,
                f"{alert['project_id']}|{occurrence_event_id}|{channel}")
            with self.db.transaction() as conn:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO notifications (id, project_id, "
                    "org_id, alert_id, occurrence_event_id, channel, "
                    "provider_key, status, attempts, next_retry_at, "
                    "last_error, created_at, updated_at, sent_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (nid, alert["project_id"], alert["org_id"], alert_id,
                     str(occurrence_event_id)[:160], channel, channel,
                     "pending", 0, "", "", models.utcnow(), models.utcnow(),
                     ""))
                if cur.rowcount == 1:
                    created += 1
        self.process_pending(limit=10, org_id=str(alert["org_id"]))
        return created

    def process_pending(self, *, limit: int = 10,
                        now: str | None = None,
                        org_id: str | None = None) -> int:
        """Attempt due pending notifications; optionally constrain to a tenant."""
        now = now or models.utcnow()
        tenant_clause = " AND org_id=?" if org_id else ""
        params: tuple = (now, org_id, min(max(int(limit), 1), 100)) if org_id else (
            now, min(max(int(limit), 1), 100)
        )
        rows = self.db.query(
            "SELECT * FROM notifications WHERE status='pending' AND "
            "(next_retry_at='' OR next_retry_at<=?)" + tenant_clause +
            " ORDER BY created_at, id LIMIT ?", params)
        done = 0
        for n in rows:
            if self._attempt(dict(n)):
                done += 1
        return done

    def retry_due(self, *, limit: int = 20, now: str | None = None,
                  org_id: str | None = None) -> int:
        return self.process_pending(limit=limit, now=now, org_id=org_id)

    def retry_manual(self, notification_id: str, *,
                     actor: str = "cli",
                     org_id: str | None = None) -> dict:
        self._acquire(f"notify:retry:{actor}",
                      NOTIFY_RETRY_LIMIT, NOTIFY_RETRY_WINDOW)
        if org_id:
            rows = self.db.query(
                "SELECT * FROM notifications WHERE id=? AND org_id=? LIMIT 1",
                (notification_id, org_id),
            )
        else:
            rows = self.db.query("SELECT * FROM notifications WHERE id=? LIMIT 1",
                                 (notification_id,))
        if not rows:
            raise errors.NotFoundError("notification not found")
        n = rows[0]
        if n["status"] in ("sent",):
            raise errors.LifecycleError(
                "validation_rejected: already delivered")
        update_tenant_clause = " AND org_id=?" if org_id else ""
        update_params = (models.utcnow(), notification_id, org_id) if org_id else (
            models.utcnow(), notification_id
        )
        self.db.execute(
            "UPDATE notifications SET status='pending', next_retry_at='', "
            "updated_at=? WHERE id=? AND status<>'sent'" + update_tenant_clause,
            update_params,
        )
        self.svc.audit("notification.retried", object_type="notification",
                       object_id=notification_id, project_id=n["project_id"],
                       org_id=n["org_id"], actor=actor,
                       metadata={"attempts": n["attempts"]})
        self.process_pending(limit=1, org_id=org_id)
        return self.notification_view(notification_id, org_id=org_id)

    # ---------------------------------------------------------- attempt
    def _attempt(self, n: dict) -> bool:
        """One delivery attempt. Never raises — failures are recorded."""
        provider = self.providers.get(n.get("channel", ""))
        if provider is None:
            self._record_attempt(n, "skipped",
                                 "unknown provider channel", 0.0)
            self._mark(n["id"], "dead_letter", "unknown provider channel")
            return True
        payload = self._payload_for(n)
        started = time.time()
        try:
            result = provider.send(self._settings_for(n["project_id"]), payload)
        except Exception:
            result = {"ok": False, "outcome": "failed", "error": ""}
        duration = round((time.time() - started) * 1000, 1)
        if not isinstance(result, dict):
            result = {"ok": False, "outcome": "failed", "error": ""}
        attempt = int(n.get("attempts") or 0) + 1
        outcome_value = result.get("outcome", "failed")
        outcome = outcome_value if isinstance(outcome_value, str) and outcome_value in models.NOTIFICATION_OUTCOMES else "failed"
        if outcome == "sent" and result.get("ok") is not True:
            outcome = "failed"
        error = _safe_delivery_error(outcome, result.get("error", ""))
        # every attempt advances the counter (also on terminal outcomes)
        self.db.execute("UPDATE notifications SET attempts=? WHERE id=?",
                        (attempt, n["id"]))
        if result.get("ok") is True:
            self._record_attempt(n, "sent", "", duration)
            self.db.execute(
                "UPDATE notifications SET status='sent', attempts=?, "
                "sent_at=?, last_error='', updated_at=? WHERE id=?",
                (attempt, models.utcnow(), models.utcnow(), n["id"]))
            metrics.inc("notifications_sent")
            return True
        permanent = outcome in ("invalid", "skipped")
        self._record_attempt(n, outcome, error, duration)
        if permanent or attempt >= self.max_attempts:
            self._mark(n["id"], "dead_letter", error or outcome)
            metrics.inc("notifications_failed")
            self._signal_failure(n, outcome, error)
            return True
        backoff = RETRY_BASE_SECONDS * (2 ** max(0, attempt - 1))
        self.db.execute(
            "UPDATE notifications SET status='pending', attempts=?, "
            "next_retry_at=?, last_error=?, updated_at=? WHERE id=?",
            (attempt, _iso(_epoch(models.utcnow()) + backoff),
             error[:500], models.utcnow(), n["id"]))
        metrics.inc("notifications_failed")
        metrics.inc("notification_retries")
        return True

    def _signal_failure(self, n: dict, outcome: str, error: str) -> None:
        """Monitoring failure event (no recursion: events → alerts → a NEW
        notification would need a fresh occurrence; the cooldown bounds it,
        and the failure is recorded here so the channel cannot storm itself)."""
        try:
            from alerts import pipeline_event
            pipeline_event(
                self.svc, project_id=n["project_id"],
                event_type="monitoring.notification_failure",
                key=f"notif|{n['id']}", scan_id="",
                new_state={"channel": n.get("channel", ""),
                           "outcome": outcome,
                           "error": error[:120]},
                source="notification-dispatcher", confidence=0.8)
        except Exception:
            pass

    # ---------------------------------------------------------- helpers
    def _settings_for(self, project_id: str) -> dict:
        s = self.settings_get(project_id)
        s["project_id"] = project_id
        return s

    def _payload_for(self, n: dict) -> dict:
        rows = self.db.query("SELECT * FROM alerts WHERE id=? LIMIT 1",
                             (n["alert_id"],))
        alert = dict(rows[0]) if rows else {}
        return redact.redact({
            "alert_id": alert.get("id", ""),
            "title": str(alert.get("title", ""))[:200],
            "severity": alert.get("severity", ""),
            "state": alert.get("state", ""),
            "occurrence_count": alert.get("occurrence_count", 0),
            "event_type": alert.get("event_type", ""),
            "asset_id": alert.get("asset_id", ""),
            "fingerprint": alert.get("fingerprint", ""),
            "project_id": alert.get("project_id", ""),
            "occurrence_event_id": n.get("occurrence_event_id", ""),
            "sent_at": models.utcnow(),
        })

    def _record_attempt(self, n: dict, outcome: str, error: str,
                        duration_ms: float) -> None:
        attempt = int(n.get("attempts") or 0) + 1
        aid = models.stable_id(models.NS_NATT,
                               f"{n['id']}|{attempt}")
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO notification_attempts (id, "
                "notification_id, attempt_n, ts, outcome, error, "
                "duration_ms) VALUES (?,?,?,?,?,?,?)",
                (aid, n["id"], attempt, models.utcnow(),
                 outcome if outcome in models.NOTIFICATION_OUTCOMES
                 else "failed", str(error)[:500], float(duration_ms)))

    def _mark(self, notification_id: str, status: str, error: str) -> None:
        self.db.execute(
            "UPDATE notifications SET status=?, last_error=?, updated_at=? "
            "WHERE id=?", (status, str(error)[:500], models.utcnow(),
                           notification_id))

    # ------------------------------------------------------------- reads
    def notification_view(self, notification_id: str, *,
                          org_id: str | None = None) -> dict:
        if org_id:
            rows = self.db.query(
                "SELECT * FROM notifications WHERE id=? AND org_id=? LIMIT 1",
                (notification_id, org_id),
            )
        else:
            rows = self.db.query("SELECT * FROM notifications WHERE id=? LIMIT 1",
                                 (notification_id,))
        if not rows:
            raise errors.NotFoundError("notification not found")
        v = dict(rows[0])
        v["attempts_list"] = [dict(a) for a in self.db.query(
            "SELECT * FROM notification_attempts WHERE notification_id=? "
            "ORDER BY attempt_n LIMIT ?", (notification_id, 10))]
        for a in v["attempts_list"]:
            a["error"] = redact.redact_text(str(a.get("error", "")))[:300]
        return redact.redact(v)

    def list_notifications(self, project_id: str, *, status: str = "",
                           limit: int = 100) -> list[dict]:
        self.svc.project_require(project_id)
        limit = min(max(int(limit), 1), 500)
        if status:
            if status not in models.NOTIFICATION_STATUSES:
                raise errors.ValidationError(
                    f"notification_status_unknown: {status!r}")
            rows = self.db.query(
                "SELECT * FROM notifications WHERE project_id=? AND "
                "status=? ORDER BY created_at DESC, id DESC LIMIT ?",
                (project_id, status, limit))
        else:
            rows = self.db.query(
                "SELECT * FROM notifications WHERE project_id=? ORDER BY "
                "created_at DESC, id DESC LIMIT ?", (project_id, limit))
        return [redact.redact(dict(r)) for r in rows]

    def notification_counts(self, project_id: str) -> dict:
        self.svc.project_require(project_id)
        rows = self.db.query(
            "SELECT status, COUNT(*) AS n FROM notifications WHERE "
            "project_id=? GROUP BY status", (project_id,))
        out = {r["status"]: r["n"] for r in rows}
        out["total"] = sum(out.values())
        return out
