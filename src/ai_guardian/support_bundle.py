#!/usr/bin/env python3
"""
Support Bundle — sanitized export for troubleshooting.

Two-step process:
1. prepare() — creates sanitized bundle in temp dir for user review
2. send() — sends approved bundle to preconfigured destination

Issue #477
"""

import json
import logging
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_active_bundles: Dict[str, Dict[str, Any]] = {}


def _get_support_config() -> Dict:
    """Load support config from ai-guardian.json."""
    from ai_guardian.config_utils import get_config_dir
    config_path = get_config_dir() / "ai-guardian.json"
    if not config_path.exists():
        config_path = Path.cwd() / ".ai-guardian.json"
    if not config_path.exists():
        return {}
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        return config.get("support", {})
    except Exception:
        return {}


def _sanitize_config(config: Dict) -> tuple:
    """Sanitize config by redacting sensitive values. Returns (sanitized, redaction_count)."""
    import copy
    sanitized = copy.deepcopy(config)
    redactions = 0

    sensitive_keys = {
        "token", "api_key", "password", "secret", "auth_token",
        "token_env", "url", "remote_config_url",
    }

    def _redact(obj, path=""):
        nonlocal redactions
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                if key.startswith("_comment"):
                    del obj[key]
                    continue
                if any(s in key.lower() for s in sensitive_keys):
                    if isinstance(obj[key], str) and obj[key]:
                        obj[key] = "[REDACTED]"
                        redactions += 1
                else:
                    _redact(obj[key], f"{path}.{key}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _redact(item, f"{path}[{i}]")

    _redact(sanitized)
    return sanitized, redactions


def _sanitize_violations(violations: List[Dict]) -> tuple:
    """Sanitize violation entries. Returns (sanitized_list, redaction_count)."""
    import copy
    sanitized = []
    redactions = 0

    for v in violations:
        entry = copy.deepcopy(v)
        ctx = entry.get("context", {})

        if "file_path" in ctx and ctx["file_path"]:
            parts = Path(ctx["file_path"]).parts
            if len(parts) > 2:
                ctx["file_path"] = str(Path("...") / Path(*parts[-2:]))
                redactions += 1

        if "content_preview" in ctx:
            del ctx["content_preview"]
            redactions += 1
        if "matched_pattern" in ctx:
            del ctx["matched_pattern"]
            redactions += 1

        entry["context"] = ctx
        sanitized.append(entry)

    return sanitized, redactions


def _get_system_info() -> Dict:
    """Collect non-sensitive system information."""
    import platform
    from ai_guardian import __version__
    return {
        "ai_guardian_version": __version__,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "os": platform.system(),
        "architecture": platform.machine(),
    }


def _get_sanitized_log() -> tuple:
    """Get sanitized full ai-guardian log. Returns (text, redaction_count)."""
    from ai_guardian.config_utils import get_state_dir
    log_path = get_state_dir() / "ai-guardian.log"
    if not log_path.exists():
        return "", 0

    try:
        text = log_path.read_text(errors="replace")

        from ai_guardian.sanitizer import sanitize_text
        result = sanitize_text(text)
        redactions = result.get("stats", {}).get("total", 0)
        return result.get("sanitized_text", text), redactions
    except Exception as e:
        logger.debug("Log error: %s", e)
        return "", 0


def prepare_bundle() -> Dict[str, Any]:
    """Prepare a sanitized support bundle for user review.

    Returns dict with bundle_id, temp_path, destination, and file list.
    """
    support_config = _get_support_config()
    destination = support_config.get("export_destination", "")
    if not destination:
        from ai_guardian.config_utils import get_state_dir
        destination = str(get_state_dir() / "support-bundles")
    ttl = support_config.get("bundle_ttl_minutes", 30)

    bundle_id = f"support-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
    temp_dir = Path(tempfile.mkdtemp(prefix="ai-guardian-support-"))

    # Protect bundle from direct AI agent access
    (temp_dir / ".ai-read-deny").touch()

    files_info = []

    # 1. Config (sanitized)
    try:
        from ai_guardian.config_utils import get_config_dir
        config_path = get_config_dir() / "ai-guardian.json"
        if config_path.exists():
            with open(config_path, "r") as f:
                raw_config = json.load(f)
            sanitized, count = _sanitize_config(raw_config)
            (temp_dir / "config.json").write_text(json.dumps(sanitized, indent=2))
            files_info.append({
                "name": "config.json",
                "sanitized": count > 0,
                "redactions": count,
                "note": f"{count} sensitive values redacted" if count else "No sensitive data found",
            })
    except Exception as e:
        logger.debug("Bundle config error: %s", e)

    # 2. Violations (sanitized)
    try:
        from ai_guardian.violation_logger import ViolationLogger
        vl = ViolationLogger()
        violations = vl.get_recent_violations(limit=100)
        sanitized, count = _sanitize_violations(violations)
        (temp_dir / "violations.json").write_text(json.dumps(sanitized, indent=2))
        files_info.append({
            "name": "violations.json",
            "sanitized": count > 0,
            "redactions": count,
            "note": f"{count} file paths and content redacted" if count else "No sensitive data found",
        })
    except Exception as e:
        logger.debug("Bundle violations error: %s", e)

    # 3. Metrics (aggregate only)
    try:
        from ai_guardian.metrics import MetricsComputer
        mc = MetricsComputer(since_days=30)
        report = mc.compute()
        metrics = {
            "total_violations": report.total_violations,
            "by_type": dict(report.by_type),
            "by_severity": dict(report.by_severity),
            "resolved": report.resolved_count,
            "unresolved": report.unresolved_count,
        }
        (temp_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
        files_info.append({
            "name": "metrics.json",
            "sanitized": False,
            "redactions": 0,
            "note": "Aggregate stats only, no sensitive data",
        })
    except Exception as e:
        logger.debug("Bundle metrics error: %s", e)

    # 4. Doctor (health check)
    try:
        from ai_guardian.doctor import Doctor
        doc = Doctor()
        report = doc.run_all()
        checks = [{"name": c.name, "status": c.status.value, "message": c.message} for c in report.checks]
        (temp_dir / "doctor.json").write_text(json.dumps({"checks": checks}, indent=2))
        files_info.append({
            "name": "doctor.json",
            "sanitized": False,
            "redactions": 0,
            "note": "Health check results",
        })
    except Exception as e:
        logger.debug("Bundle doctor error: %s", e)

    # 5. System info
    try:
        info = _get_system_info()
        (temp_dir / "system-info.json").write_text(json.dumps(info, indent=2))
        files_info.append({
            "name": "system-info.json",
            "sanitized": False,
            "redactions": 0,
            "note": "Python version, platform, ai-guardian version",
        })
    except Exception as e:
        logger.debug("Bundle system info error: %s", e)

    # 6. Full log (sanitized)
    try:
        log_text, count = _get_sanitized_log()
        if log_text:
            (temp_dir / "ai-guardian.log").write_text(log_text)
            files_info.append({
                "name": "ai-guardian.log",
                "sanitized": count > 0,
                "redactions": count,
                "note": f"Full log, {count} items redacted" if count else "Full log",
            })
    except Exception as e:
        logger.debug("Bundle log error: %s", e)

    _active_bundles[bundle_id] = {
        "temp_path": str(temp_dir),
        "destination": destination,
        "created": datetime.now(timezone.utc).isoformat(),
        "ttl_minutes": ttl,
        "files": files_info,
    }

    return {
        "bundle_id": bundle_id,
        "temp_path": str(temp_dir),
        "destination": destination,
        "files": files_info,
    }


def send_bundle(bundle_id: str) -> Dict[str, Any]:
    """Send a previously prepared support bundle to the configured destination.

    Only works with a valid bundle_id from prepare_bundle().
    """
    if bundle_id not in _active_bundles:
        return {"status": "error", "message": f"Bundle '{bundle_id}' not found or expired. Prepare a new bundle first."}

    bundle = _active_bundles[bundle_id]
    temp_path = Path(bundle["temp_path"])
    destination = bundle["destination"]

    if not temp_path.exists():
        del _active_bundles[bundle_id]
        return {"status": "error", "message": "Bundle temp directory no longer exists. Prepare a new bundle."}

    # Check TTL
    created = datetime.fromisoformat(bundle["created"])
    age_minutes = (datetime.now(timezone.utc) - created).total_seconds() / 60
    ttl = bundle.get("ttl_minutes", 30)
    if age_minutes > ttl:
        _cleanup_bundle(bundle_id)
        return {"status": "error", "message": f"Bundle expired ({ttl} min TTL). Prepare a new bundle."}

    try:
        if destination.startswith("s3://"):
            return _send_to_s3(bundle_id, temp_path, destination)
        elif destination.startswith("/") or destination.startswith("~"):
            return _send_to_local(bundle_id, temp_path, destination)
        elif not destination:
            return {
                "status": "error",
                "message": "No export destination configured. Add 'support.export_destination' to ai-guardian.json.",
            }
        else:
            return {"status": "error", "message": f"Unsupported destination: {destination}"}
    finally:
        _cleanup_bundle(bundle_id)


def _send_to_local(bundle_id: str, temp_path: Path, destination: str) -> Dict:
    """Copy bundle to a local directory."""
    dest = Path(destination).expanduser()
    bundle_dest = dest / bundle_id
    bundle_dest.mkdir(parents=True, exist_ok=True)

    for item in temp_path.iterdir():
        if item.name == ".ai-read-deny":
            continue
        shutil.copy2(item, bundle_dest / item.name)

    return {"status": "sent", "destination": str(bundle_dest), "message": f"Bundle copied to {bundle_dest}"}


def _send_to_s3(bundle_id: str, temp_path: Path, destination: str) -> Dict:
    """Upload bundle to S3."""
    try:
        import boto3
    except ImportError:
        return {
            "status": "error",
            "message": "S3 upload requires boto3. Install with: pip install boto3. "
                       f"Bundle files are available at: {temp_path}",
        }

    support_config = _get_support_config()
    auth = support_config.get("auth", {})

    parts = destination.replace("s3://", "").split("/", 1)
    bucket = parts[0]
    prefix = parts[1] if len(parts) > 1 else ""
    key_prefix = f"{prefix}/{bundle_id}".strip("/")

    try:
        token_env = auth.get("token_env", "")
        session_kwargs = {}
        if token_env and os.environ.get(token_env):
            session_kwargs["aws_session_token"] = os.environ[token_env]

        s3 = boto3.client("s3", **session_kwargs)
        uploaded = 0
        for item in temp_path.iterdir():
            if item.name == ".ai-read-deny":
                continue
            s3.upload_file(str(item), bucket, f"{key_prefix}/{item.name}")
            uploaded += 1

        return {
            "status": "sent",
            "destination": f"s3://{bucket}/{key_prefix}/",
            "message": f"{uploaded} files uploaded to S3",
        }
    except Exception as e:
        return {"status": "error", "message": f"S3 upload failed: {e}. Bundle files at: {temp_path}"}


def _cleanup_bundle(bundle_id: str) -> None:
    """Remove temp directory and tracking entry for a bundle."""
    if bundle_id in _active_bundles:
        temp_path = Path(_active_bundles[bundle_id]["temp_path"])
        if temp_path.exists():
            shutil.rmtree(temp_path, ignore_errors=True)
        del _active_bundles[bundle_id]
