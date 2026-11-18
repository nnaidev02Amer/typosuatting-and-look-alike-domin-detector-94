"""Run the unmodified dnstwist engine as a subprocess in a background thread.

* shell=False, argument list, one validated domain as the only positional arg
* a process-wide lock allows only one scan at a time (survives Streamlit reruns,
  because this module is imported once per server process)
* the worker thread itself saves the history record, so a rerun can never
  save a scan twice
* output goes to a new file (dnstwist opens --output with mode 'x', so an
  existing file is never overwritten)
"""
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

from . import DNSTWIST_PY, ROOT, history, parser, validators

DEFAULT_TIMEOUT = 900
_state_lock = threading.Lock()
_current = None   # the running or most recent ScanJob
_jobs = {}


class ScanBusy(Exception):
    pass


def detect_capabilities():
    """Ask the engine (in a subprocess) which optional modules it can use."""
    code = ("import sys, json; sys.path.insert(0, r'{root}'); import dnstwist as d; "
            "print(json.dumps({{'version': d.__version__, 'dns': bool(d.MODULE_DNSPYTHON), "
            "'ssdeep': bool(d.MODULE_SSDEEP), 'tlsh': bool(d.MODULE_TLSH), 'pil': bool(d.MODULE_PIL), "
            "'selenium': bool(d.MODULE_SELENIUM), 'geoip': bool(d.MODULE_GEOIP)}}))").format(root=ROOT)
    try:
        import json
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, cwd=str(ROOT))
        caps = json.loads(out.stdout.strip().splitlines()[-1])
        caps["phash"] = caps["pil"] and caps["selenium"]
        caps["error"] = None
    except Exception as e:  # noqa: BLE001 - report instead of crashing the UI
        caps = {"version": "unknown", "dns": False, "ssdeep": False, "tlsh": False, "pil": False,
                "selenium": False, "geoip": False, "phash": False, "error": str(e)}
    return caps


def build_command(domain, output_path, options):
    cmd = [sys.executable, str(DNSTWIST_PY), "--format", "json", "--output", str(output_path),
           "--threads", str(int(options.get("threads", 50)))]
    if options.get("lsh"):
        cmd += ["--lsh", options["lsh"]]       # 'ssdeep' or 'tlsh'
    if options.get("phash"):
        cmd += ["--phash"]
    cmd += ["--", domain]
    return cmd


class ScanJob:
    def __init__(self, domain, options, timeout):
        self.id = history.new_scan_id()
        self.domain = domain
        self.options = options
        self.timeout = timeout
        self.output_path = history.unique_result_path(domain, self.id)
        self.command = build_command(domain, self.output_path, options)
        self.status = "running"      # running|completed|failed|timeout|cancelled
        self.error = None
        self.stdout = ""
        self.stderr = ""
        self.returncode = None
        self.started = time.time()
        self.started_at = history.now_iso()
        self.finished = None
        self.record = None
        self._proc = None
        self._cancel = False
        self._done = False

    @property
    def elapsed(self):
        return (self.finished or time.time()) - self.started

    @property
    def running(self):
        # stays True until the history record has been written
        return not self._done

    def cancel(self):
        self._cancel = True
        if self._proc and self._proc.poll() is None:
            self._proc.kill()

    # -- worker thread -----------------------------------------------------
    def run(self):
        try:
            self._proc = subprocess.Popen(
                self.command, cwd=str(ROOT), shell=False,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace")
            try:
                self.stdout, self.stderr = self._proc.communicate(timeout=self.timeout)
                self.returncode = self._proc.returncode
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self.stdout, self.stderr = self._proc.communicate()
                self.status, self.error = "timeout", "Scan exceeded the {} s timeout and was stopped.".format(self.timeout)
            if self._cancel:
                self.status, self.error = "cancelled", "Scan cancelled by the user."
            elif self.status == "running":
                self._finish_process()
        except Exception as e:  # noqa: BLE001
            self.status, self.error = "failed", "Could not run the scanner: {}".format(e)
        finally:
            self.finished = time.time()
            try:
                self._save_record()
            finally:
                self._done = True

    def _finish_process(self):
        if self.returncode != 0:
            msg = (self.stderr or self.stdout).strip().splitlines()
            self.status = "failed"
            self.error = "dnstwist exited with code {}: {}".format(self.returncode, msg[-1] if msg else "no error output")
            return
        try:
            data = parser.load_file(self.output_path)
        except parser.ParseError as e:
            self.status, self.error = "failed", "Scan finished but the output could not be read: {}".format(e)
            return
        self._stats = parser.stats(data)
        self.status = "completed"

    def _save_record(self):
        has_file = self.output_path.exists() and self.status == "completed"
        if not has_file and self.output_path.exists():
            # dnstwist creates --output on start; drop the empty/partial file of a failed, timed-out or cancelled scan
            try:
                self.output_path.unlink()
            except OSError:
                pass
        self.record = history.add_record({
            "id": self.id,
            "domain": self.domain,
            "started_at": self.started_at,
            "finished_at": history.now_iso(),
            "original_scan_time": "known",
            "imported": False,
            "duration_s": round(self.finished - self.started, 1),
            "status": self.status,
            "options": self.options,
            "result_file": self.output_path.relative_to(ROOT).as_posix() if has_file else None,
            "sha256": history.sha256_file(self.output_path) if has_file else None,
            "stats": getattr(self, "_stats", None),
            "error": self.error,
            "stderr_tail": "\n".join(self.stderr.strip().splitlines()[-10:]) if self.stderr else "",
            "command": [_relative(a) for a in self.command],
        })


def _relative(arg):
    """Store the command without absolute local paths."""
    return arg.replace(str(ROOT), ".") if isinstance(arg, str) else arg


def start_scan(raw_domain, options, timeout=DEFAULT_TIMEOUT):
    """Validate and start a scan. Raises ValueError (bad input) or ScanBusy."""
    global _current
    ok, domain, msg = validators.validate_domain(raw_domain)
    if not ok:
        raise ValueError(msg)
    options = dict(options or {})
    if options.get("lsh") not in (None, "ssdeep", "tlsh"):
        raise ValueError("Unsupported LSH algorithm.")
    options["threads"] = max(1, min(200, int(options.get("threads", 50))))
    options["phash"] = bool(options.get("phash"))
    with _state_lock:
        if _current is not None and _current.running:
            raise ScanBusy("A scan of {} is already running.".format(_current.domain))
        job = ScanJob(domain, options, timeout)
        _current = job
        _jobs[job.id] = job
    threading.Thread(target=job.run, name="dnstwist-scan-" + job.id, daemon=True).start()
    return job


def current_job():
    return _current


def get_job(job_id):
    return _jobs.get(job_id)
