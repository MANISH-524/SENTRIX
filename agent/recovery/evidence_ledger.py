"""
SENTRIX — Restore Evidence Ledger
=================================
PS284 names "restore test records" as a primary data input. Treating that as a
single `days_overdue` integer throws away everything that makes it evidence.

A restore test record is:

    {asset_id, test_type, started_at, outcome, bytes_restored,
     rto_actual_seconds, checksum_verified, notes}

...because those fields answer questions a counter cannot:
  • WHAT was proven — a checksum verify is not a recovery drill.
  • Did it actually MEET the RTO target, or just eventually finish?
  • Was the restored data VERIFIED, or just written?
  • Did it FAIL? (A failed drill is the most valuable record in the ledger —
    it is proof of non-recoverability, and conventional tools discard it.)

Append-only and HMAC-signed with the same key as the audit trail: restore
evidence is exactly the kind of record that gets quietly edited after a bad
audit, so it is tamper-evident by construction.

Storage is a JSONL ledger (portable, greppable, diffable, survives the
container via the named volume) with an in-memory index for scoring.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import config
from agent.logging_setup import get_logger

_log = get_logger("evidence")

LEDGER_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "restore_evidence.jsonl"

VALID_TEST_TYPES = {"full_restore_drill", "partial_restore", "checksum_verify"}
VALID_OUTCOMES = {"passed", "failed", "partial"}

_lock = threading.Lock()
_index: dict = {}      # asset_id -> latest usable record
_loaded = False


def _sign(record: dict) -> str:
    payload = json.dumps(record, sort_keys=True, default=str).encode()
    return hmac.new(config.HMAC_KEY.encode(), payload, hashlib.sha256).hexdigest()


def verify_signature(record: dict) -> bool:
    """Constant-time verification — same discipline as the audit trail."""
    rec = {k: v for k, v in record.items() if k != "signature"}
    return hmac.compare_digest(_sign(rec), record.get("signature", ""))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_test(asset_id: str, test_type: str, outcome: str,
                rto_actual_seconds: float = None, bytes_restored: int = None,
                checksum_verified: bool = None, notes: str = "",
                started_at: str = None, cycle_id: str = "") -> dict:
    """Append one restore-test record to the ledger. Returns the signed record.

    This is the write side of the loop: when a scheduled test completes, its
    result lands here and the next scoring pass picks it up automatically.
    """
    test_type = str(test_type or "").strip()
    outcome = str(outcome or "").strip().lower()
    if test_type not in VALID_TEST_TYPES:
        raise ValueError(f"invalid test_type: {test_type!r}")
    if outcome not in VALID_OUTCOMES:
        raise ValueError(f"invalid outcome: {outcome!r}")

    rec = {
        "record_id": uuid.uuid4().hex[:12],
        "asset_id": str(asset_id),
        "test_type": test_type,
        "outcome": outcome,
        "started_at": started_at or _now(),
        "recorded_at": _now(),
        "rto_actual_seconds": rto_actual_seconds,
        "bytes_restored": bytes_restored,
        "checksum_verified": checksum_verified,
        "notes": str(notes)[:500],
        "cycle_id": cycle_id,
    }
    rec["signature"] = _sign(rec)

    with _lock:
        try:
            LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
            with LEDGER_PATH.open("a") as f:
                f.write(json.dumps(rec, default=str) + "\n")
        except Exception as e:
            _log.error("evidence ledger write failed: %s", e)
        _reindex_one(rec)

    _log.info("restore test recorded", extra={
        "asset_id": asset_id, "test_type": test_type, "outcome": outcome})
    return rec


def _reindex_one(rec: dict):
    """Keep only the most recent record per asset for scoring purposes."""
    aid = rec.get("asset_id")
    cur = _index.get(aid)
    if cur is None or rec.get("started_at", "") >= cur.get("started_at", ""):
        _index[aid] = rec


def load():
    """Load the ledger into the scoring index. Idempotent."""
    global _loaded
    with _lock:
        if _loaded:
            return
        _loaded = True
        if not LEDGER_PATH.exists():
            return
        bad = 0
        try:
            for line in LEDGER_PATH.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    bad += 1
                    continue
                if not verify_signature(rec):
                    # Tamper-evident: a record that fails verification is
                    # reported and excluded, never silently trusted.
                    bad += 1
                    _log.warning("evidence record failed signature check — excluded",
                                 extra={"record_id": rec.get("record_id")})
                    continue
                _reindex_one(rec)
        except Exception as e:
            _log.error("evidence ledger load failed: %s", e)
        if bad:
            _log.warning("%s evidence record(s) rejected during load", bad)


def latest_for(asset_id: str) -> dict | None:
    load()
    return _index.get(str(asset_id))


def evidence_for_asset(asset_id: str) -> dict:
    """Shape the latest record for the confidence model.
    Returns the `last_restore_test` sub-document score_asset() expects."""
    rec = latest_for(asset_id)
    if not rec:
        return {"type": "none", "days_ago": 0.0, "passed": False}
    try:
        started = datetime.fromisoformat(rec["started_at"])
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        days = (datetime.now(timezone.utc) - started).total_seconds() / 86400.0
    except Exception:
        days = 0.0
    return {
        "type": rec.get("test_type", "none"),
        "days_ago": round(max(days, 0.0), 2),
        "passed": rec.get("outcome") == "passed",
        "outcome": rec.get("outcome"),
        "rto_actual_seconds": rec.get("rto_actual_seconds"),
        "record_id": rec.get("record_id"),
    }


def enrich(assets: list) -> list:
    """Attach real restore evidence to each asset before scoring.

    Falls back to the simulator's synthetic `restore_test_days_overdue` only
    when the ledger has nothing for that asset — so a fresh install still
    demonstrates the model, and real records take over the moment they exist.
    """
    load()
    out = []
    for a in assets or []:
        a = dict(a)
        aid = a.get("asset_id")
        if aid in _index:
            a["last_restore_test"] = evidence_for_asset(aid)
            a.setdefault("evidence_source", "ledger")
        else:
            a["last_restore_test"] = _synthesize(a)
            a["evidence_source"] = "simulated"
        a.setdefault("config_changes_since_restore_test", _synth_drift(a))
        out.append(a)
    return out


def _synthesize(asset: dict) -> dict:
    """Derive a plausible last-test record from the simulator's fields, so the
    confidence model has something to chew on before real tests exist.
    Clearly marked as simulated — never presented as real evidence."""
    tier = int(asset.get("tier", 3) or 3)
    cadence = {1: 30, 2: 45, 3: 90, 4: 180}.get(tier, 90)
    overdue = float(asset.get("restore_test_days_overdue", 0) or 0)
    # days_ago = the point in the cadence we're at, plus however overdue we are
    days_ago = cadence * 0.6 + overdue
    tier_type = {1: "full_restore_drill", 2: "full_restore_drill",
                 3: "partial_restore", 4: "checksum_verify"}.get(tier, "partial_restore")
    return {"type": tier_type, "days_ago": round(days_ago, 1), "passed": True,
            "simulated": True}


def _synth_drift(asset: dict) -> int:
    """Drift proxy until a real change feed is wired in: busier, more critical
    systems change more, and drift accumulates with evidence age."""
    tier = int(asset.get("tier", 3) or 3)
    rate = {1: 0.9, 2: 0.6, 3: 0.3, 4: 0.05}.get(tier, 0.3)  # changes/day
    days = float((asset.get("last_restore_test") or {}).get("days_ago", 0) or 0)
    return int(days * rate)


def stats() -> dict:
    load()
    by_type: dict = {}
    by_outcome: dict = {}
    for rec in _index.values():
        by_type[rec.get("test_type")] = by_type.get(rec.get("test_type"), 0) + 1
        by_outcome[rec.get("outcome")] = by_outcome.get(rec.get("outcome"), 0) + 1
    return {
        "assets_with_evidence": len(_index),
        "by_test_type": by_type,
        "by_outcome": by_outcome,
        "ledger_path": str(LEDGER_PATH),
        "ledger_exists": LEDGER_PATH.exists(),
    }


def history(asset_id: str = None, limit: int = 100) -> list:
    """Full append-only history — the provenance chain the dashboard shows."""
    load()
    if not LEDGER_PATH.exists():
        return []
    out = []
    try:
        for line in LEDGER_PATH.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if asset_id and rec.get("asset_id") != asset_id:
                continue
            rec["signature_valid"] = verify_signature(rec)
            out.append(rec)
    except Exception as e:
        _log.error("evidence history read failed: %s", e)
    return out[-limit:][::-1]


def reset():
    """Test helper — clears the in-memory index."""
    global _loaded
    with _lock:
        _index.clear()
        _loaded = False
