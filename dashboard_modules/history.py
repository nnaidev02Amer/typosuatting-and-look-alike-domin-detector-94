"""Local scan history (JSON index) and analyst annotations.

Layout:
  scan_history/index.json        records + dismissed import hashes
  scan_history/annotations.json  analyst decisions {scan_id: {domain: {...}}}
  scan_history/results/*.json    raw dnstwist output, one file per scan
"""
import hashlib
import json
import os
import re
import shutil
import threading
import uuid
from datetime import datetime, timezone

from . import HISTORY_DIR, RESULTS_DIR, ROOT, parser

INDEX = HISTORY_DIR / "index.json"
ANNOTATIONS = HISTORY_DIR / "annotations.json"
_lock = threading.RLock()

MANUAL_STATUSES = ["Not reviewed", "Under review", "Reviewed - no concern", "Manually confirmed malicious"]


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _read(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (json.JSONDecodeError, UnicodeDecodeError):
        # keep the unreadable file for inspection instead of silently overwriting it
        os.replace(path, str(path) + ".corrupt-" + datetime.now().strftime("%Y%m%d%H%M%S"))
        return default


def _write(path, obj):
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _load_index():
    idx = _read(INDEX, {})
    idx.setdefault("records", [])
    idx.setdefault("dismissed_imports", [])
    return idx


def new_scan_id():
    return datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]


def safe_name(text):
    return re.sub(r"[^a-z0-9.-]+", "_", text.lower())[:80].strip("._") or "scan"


def unique_result_path(domain, scan_id):
    """Path inside scan_history/results that does not exist yet."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return RESULTS_DIR / "{}_{}.json".format(safe_name(domain), scan_id)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def add_record(record):
    with _lock:
        idx = _load_index()
        idx["records"].append(record)
        _write(INDEX, idx)
    return record


def list_records():
    """All records, newest first (unknown timestamps last)."""
    with _lock:
        recs = _load_index()["records"]
    return sorted(recs, key=lambda r: r.get("started_at") or r.get("imported_at") or "", reverse=True)


def get_record(scan_id):
    return next((r for r in list_records() if r["id"] == scan_id), None)


def result_path(record):
    return (ROOT / record["result_file"]) if record.get("result_file") else None


def delete_record(scan_id):
    """Remove the index entry, its stored result copy and its annotations."""
    with _lock:
        idx = _load_index()
        rec = next((r for r in idx["records"] if r["id"] == scan_id), None)
        if not rec:
            return False
        idx["records"] = [r for r in idx["records"] if r["id"] != scan_id]
        if rec.get("imported") and rec.get("sha256"):
            idx["dismissed_imports"].append(rec["sha256"])  # do not auto re-import
        _write(INDEX, idx)
        p = result_path(rec)
        # only ever delete files inside the dashboard's own results folder
        if p and p.exists() and RESULTS_DIR.resolve() in p.resolve().parents:
            p.unlink()
        ann = _read(ANNOTATIONS, {})
        if scan_id in ann:
            del ann[scan_id]
            _write(ANNOTATIONS, ann)
    return True


def import_results_file(path, force=False):
    """Import an existing dnstwist JSON file as a history record.

    Returns (status, message, record) with status in imported|duplicate|invalid|dismissed.
    The source file is copied, never moved or modified. No scan time is invented.
    """
    try:
        data = parser.load_file(path)
    except parser.ParseError as e:
        return "invalid", str(e), None
    digest = sha256_file(path)
    with _lock:
        idx = _load_index()
        if any(r.get("sha256") == digest for r in idx["records"]):
            return "duplicate", "This file was already imported.", None
        if digest in idx["dismissed_imports"] and not force:
            return "dismissed", "This file was imported before and then deleted from history.", None
        if force and digest in idx["dismissed_imports"]:
            idx["dismissed_imports"].remove(digest)
        scan_id = new_scan_id()
        dest = unique_result_path(data.target or "import", scan_id)
        shutil.copyfile(path, dest)
        rec = {
            "id": scan_id,
            "domain": data.target,
            "started_at": None,
            "finished_at": None,
            "original_scan_time": "unknown",
            "imported": True,
            "imported_at": now_iso(),
            "source_file": os.path.basename(str(path)),
            "duration_s": None,
            "status": "imported",
            "options": {"note": "options unknown (imported file)"},
            "result_file": os.path.relpath(dest, ROOT).replace("\\", "/"),
            "sha256": digest,
            "stats": parser.stats(data),
            "error": None,
        }
        idx["records"].append(rec)
        _write(INDEX, idx)
    return "imported", "Imported {} ({} candidate domains).".format(data.target, rec["stats"]["permutations"]), rec


# ---- analyst annotations (manual decisions only) ---------------------------

def get_annotations(scan_id):
    with _lock:
        return _read(ANNOTATIONS, {}).get(scan_id, {})


def set_annotation(scan_id, domain, status, note):
    with _lock:
        ann = _read(ANNOTATIONS, {})
        scan = ann.setdefault(scan_id, {})
        if status == "Not reviewed" and not note.strip():
            scan.pop(domain, None)
        else:
            scan[domain] = {"status": status, "note": note.strip(), "updated_at": now_iso()}
        _write(ANNOTATIONS, ann)
