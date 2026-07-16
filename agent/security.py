"""
SENTRIX — API Security
======================
Fixes the v3 hole where anyone who could reach the port could forge agent
cycles and push fake alerts to every dashboard. Write endpoints now require a
bearer token; read endpoints stay open for the dashboard.

  SENTRIX_API_TOKEN  — shared secret for write/ingest endpoints.
                       If unset in development, writes are allowed (with a
                       one-time warning) so local dev isn't blocked.
                       If unset in production (SENTRIX_ENV=production), the
                       app refuses to start — no accidental open write API.

  SENTRIX_HMAC_KEY   — signs the tamper-evident audit trail and outgoing
                       action-webhook payloads. Production refuses to start
                       while it's the public default: signatures made with a
                       known key are forgeable, which defeats the entire
                       point of a tamper-evident log.

Token comparison uses hmac.compare_digest (constant-time) — the same pattern
audit_logger.verify_signature already uses — so the bearer check can't leak
prefix information through response-timing differences.
"""
from __future__ import annotations

import hmac
import sys

from fastapi import Header, HTTPException

from agent import config
from agent.logging_setup import get_logger

_log = get_logger("security")

_warned = False


def enforce_startup_policy():
    """Call at app startup. Hard-fail an unprotected production API."""
    if config.ENV_NAME == "production":
        fatal = []
        if not config.API_TOKEN:
            fatal.append("SENTRIX_API_TOKEN is required in production "
                         "(protects write/ingest endpoints).")
        if config.HMAC_KEY_IS_DEFAULT:
            fatal.append("SENTRIX_HMAC_KEY is unset or still a known default in "
                         "production (audit-trail and webhook signatures would be "
                         "forgeable). Set a strong random value, e.g.: "
                         "python -c \"import secrets; print(secrets.token_hex(32))\"")
        if fatal:
            for msg in fatal:
                _log.critical(msg)
            _log.critical("Refusing to start.")
            sys.exit(1)


async def require_write_token(authorization: str = Header(default="")):
    """FastAPI dependency guarding write/ingest endpoints."""
    global _warned
    if not config.API_TOKEN:
        if config.ENV_NAME != "production" and not _warned:
            _log.warning("No SENTRIX_API_TOKEN set — write endpoints are "
                         "OPEN (development only). Set one before deploying.")
            _warned = True
        return True
    token = ""
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    # Constant-time comparison — plain != short-circuits on the first
    # differing byte, which leaks token prefixes via response timing.
    if not hmac.compare_digest(token.encode(), config.API_TOKEN.encode()):
        raise HTTPException(status_code=401, detail="invalid or missing write token")
    return True
