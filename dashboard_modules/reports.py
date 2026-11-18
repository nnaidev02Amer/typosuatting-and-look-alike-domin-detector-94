"""JSON / CSV / summary reports built from real scan data."""
import json
from datetime import datetime

from . import REPORTS_DIR, history, parser
from .analytics import RULES, apply_analysis

DISCLAIMER = ("DNS resolution, MX records and domain similarity do not prove that a domain is malicious or "
              "used for phishing. 'Needs investigation' is a rule-based triage flag for manual review. "
              "'Manually confirmed malicious' appears only where an analyst assigned it.")

CSV_COLUMNS = ["domain", "fuzzer", "dns_status", "analysis_status", "review_reasons", "ipv4", "ipv6",
               "nameservers", "mx", "ssdeep", "tlsh", "phash", "geoip", "whois_created", "whois_registrar",
               "banner_http", "banner_smtp", "mx_spy", "dns_error_types", "analyst_status", "analyst_note"]


def _meta(record):
    return {
        "target_domain": record.get("domain"),
        "scan_id": record.get("id"),
        "scan_started_at": record.get("started_at") or "unknown (imported file without original scan time)",
        "scan_duration_s": record.get("duration_s"),
        "scan_status": record.get("status"),
        "imported": bool(record.get("imported")),
        "scan_configuration": record.get("options"),
        "report_generated_at": history.now_iso(),
    }


def analysed(data, record, lsh_threshold=50):
    return apply_analysis(data.df, history.get_annotations(record["id"]), lsh_threshold)


def build_json(data, record, lsh_threshold=50):
    df = analysed(data, record, lsh_threshold)
    by_dom = {r["domain"]: r for r in df.to_dict("records")}
    cands = []
    for rec in data.raw:
        if rec["fuzzer"] == parser.ORIGINAL:
            continue
        a = by_dom.get(rec["domain"], {})
        cands.append({**rec,
                      "analysis": {"dns_status": a.get("dns_status"), "analysis_status": a.get("analysis_status"),
                                   "review_reasons": a.get("review_reasons", ""),
                                   "analyst_status": a.get("analyst_status", ""), "analyst_note": a.get("analyst_note", "")}})
    return {
        **_meta(record),
        "statistics": parser.stats(data),
        "original_domain_record": data.original,
        "candidates": cands,
        "analysis_notes": {"disclaimer": DISCLAIMER, "triage_lsh_threshold": lsh_threshold,
                           "rules": [{"id": i, "rule": r, "why": w} for i, r, w in RULES]},
    }


def _csv_safe(v):
    """Neutralise spreadsheet formula injection in text cells."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def frame_to_csv(df):
    df = df.copy()
    for c in df.columns:
        if df[c].dtype == object:
            df[c] = df[c].map(_csv_safe)
    return df.to_csv(index=False)


def build_csv(data, record, lsh_threshold=50):
    return frame_to_csv(analysed(data, record, lsh_threshold)[CSV_COLUMNS])


def build_summary(data, record, lsh_threshold=50):
    s = parser.stats(data)
    df = analysed(data, record, lsh_threshold)
    m = _meta(record)
    lines = [
        "dnstwist scan summary",
        "=====================",
        "Target domain      : {}".format(m["target_domain"]),
        "Scan started       : {}".format(m["scan_started_at"]),
        "Scan duration (s)  : {}".format(m["scan_duration_s"]),
        "Scan configuration : {}".format(json.dumps(m["scan_configuration"])),
        "Report generated   : {}".format(m["report_generated_at"]),
        "",
        "Statistics (original domain excluded)",
        "  Permutations generated : {}".format(s["permutations"]),
        "  Resolved candidates    : {}".format(s["resolved"]),
        "  Unresolved candidates  : {}".format(s["unresolved"]),
        "  DNS errors (ServFail)  : {}".format(s["dns_errors"]),
        "  With IPv4 / IPv6 / MX  : {} / {} / {}".format(s["ipv4"], s["ipv6"], s["mx"]),
        "  With LSH similarity    : {}".format(s["with_lsh"] or "none (LSH not run or no data)"),
        "  With TLSH similarity   : {}".format(s["with_tlsh"] or "none (TLSH not run or no data)"),
        "  With pHash similarity  : {}".format(s["with_phash"] or "none (pHash not run or no data)"),
        "",
        "Resolved candidates by permutation type",
    ]
    for k, v in sorted(s["resolved_by_fuzzer"].items(), key=lambda kv: -kv[1]):
        lines.append("  {:<14} {} of {}".format(k, v, s["by_fuzzer"].get(k, 0)))
    flagged = df[df.analysis_status == "Needs investigation"]
    lines += ["", "Flagged for manual investigation: {} (rules: {})".format(
        len(flagged), "; ".join("{} {}".format(i, r) for i, r, _ in RULES))]
    for _, r in flagged.head(50).iterrows():
        lines.append("  {}  [{}]  {}".format(r["domain"], r["fuzzer"], r["review_reasons"]))
    if len(flagged) > 50:
        lines.append("  ... and {} more (see CSV/JSON)".format(len(flagged) - 50))
    ann = df[df.analyst_status != ""]
    lines += ["", "Analyst decisions: {}".format(len(ann))]
    for _, r in ann.iterrows():
        lines.append("  {}: {}{}".format(r["domain"], r["analyst_status"], " - " + r["analyst_note"] if r["analyst_note"] else ""))
    lines += ["", "Note: " + DISCLAIMER, ""]
    return "\n".join(lines)


def file_stem(record, kind):
    return "{}_{}_{}".format(history.safe_name(record.get("domain") or "scan"), record["id"], kind)


def save_copy(content, record, kind, ext):
    """Write a report into reports/ under a unique name; never overwrites."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    n = 0
    while True:
        name = "{}_{}{}.{}".format(file_stem(record, kind), stamp, "" if n == 0 else "-{}".format(n), ext)
        try:
            with open(REPORTS_DIR / name, "x", encoding="utf-8", newline="") as f:
                f.write(content)
            return REPORTS_DIR / name
        except FileExistsError:
            n += 1
