"""Parse dnstwist JSON output into analysis-ready structures.

Nothing is invented: missing fields stay empty/None, and the raw scanner
records are preserved untouched in ScanData.raw.
"""
import json

import pandas as pd

ORIGINAL = "*original"
SERVFAIL = "!ServFail"
DNS_FIELDS = ("dns_a", "dns_aaaa", "dns_ns", "dns_mx")
RECORD_LABEL = {"dns_a": "A", "dns_aaaa": "AAAA", "dns_ns": "NS", "dns_mx": "MX"}

ST_RESOLVED = "Resolved"
ST_UNRESOLVED = "Unresolved"
ST_ERROR = "DNS error"

COLUMNS = ["domain", "fuzzer", "dns_status", "ipv4", "ipv6", "nameservers", "mx",
           "ssdeep", "tlsh", "phash", "geoip", "whois_created", "whois_registrar",
           "banner_http", "banner_smtp", "mx_spy", "dns_error_types"]


class ParseError(Exception):
    pass


class ScanData:
    def __init__(self, raw, original, df):
        self.raw = raw            # untouched list of scanner records
        self.original = original  # raw record of the original domain
        self.df = df              # candidates only (original excluded)

    @property
    def target(self):
        return self.original["domain"] if self.original else None

    def raw_by_domain(self):
        return {r["domain"]: r for r in self.raw}


def _clean(values):
    """Record strings with empty values removed (e.g. MX [''])."""
    if not isinstance(values, (list, tuple, set)):
        return []
    return [str(v) for v in values if isinstance(v, str) and v.strip()]


def _real(values):
    return [v for v in _clean(values) if v != SERVFAIL]


def classify_dns(rec):
    """Return (status, error_record_types) for one scanner record.

    Resolved   : at least one real A/AAAA/NS/MX value.
    DNS error  : no real values, but at least one lookup returned !ServFail.
    Unresolved : the scanner returned no DNS records for the domain.
    """
    valid, errors = False, []
    for field in DNS_FIELDS:
        vals = rec.get(field)
        if isinstance(vals, (list, tuple, set)) and SERVFAIL in vals:
            errors.append(RECORD_LABEL[field])
        if _real(vals):
            valid = True
    if valid:
        return ST_RESOLVED, errors
    if errors:
        return ST_ERROR, errors
    return ST_UNRESOLVED, errors


def validate_raw(raw):
    if not isinstance(raw, list):
        raise ParseError("Expected a JSON array of domain records (dnstwist --format json).")
    if not raw:
        raise ParseError("The result file contains no records.")
    for i, rec in enumerate(raw):
        if not isinstance(rec, dict) or "domain" not in rec or "fuzzer" not in rec:
            raise ParseError("Record {} is not a dnstwist record (missing 'domain'/'fuzzer').".format(i))
    if not any(r.get("fuzzer") == ORIGINAL for r in raw):
        raise ParseError("No original-domain record ('*original') found; this does not look like a full dnstwist scan.")


def load_file(path):
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise ParseError("Result file not found: {}".format(path))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ParseError("Result file is not valid JSON: {}".format(e))
    return parse(raw)


def parse(raw):
    validate_raw(raw)
    original, rows = None, []
    for rec in raw:
        if rec["fuzzer"] == ORIGINAL:
            original = original or rec
            continue
        status, err_types = classify_dns(rec)
        rows.append({
            "domain": rec["domain"],
            "fuzzer": rec["fuzzer"],
            "dns_status": status,
            "ipv4": ", ".join(_real(rec.get("dns_a"))),
            "ipv6": ", ".join(_real(rec.get("dns_aaaa"))),
            "nameservers": ", ".join(_real(rec.get("dns_ns"))),
            "mx": ", ".join(_real(rec.get("dns_mx"))),
            "ssdeep": rec.get("ssdeep"),
            "tlsh": rec.get("tlsh"),
            "phash": rec.get("phash"),
            "geoip": rec.get("geoip"),
            "whois_created": rec.get("whois_created"),
            "whois_registrar": rec.get("whois_registrar"),
            "banner_http": rec.get("banner_http"),
            "banner_smtp": rec.get("banner_smtp"),
            "mx_spy": bool(rec.get("mx_spy")) if "mx_spy" in rec else None,
            "dns_error_types": ", ".join(err_types),
        })
    df = pd.DataFrame(rows, columns=COLUMNS)
    for col in ("ssdeep", "tlsh", "phash"):
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return ScanData(raw, original, df)


def stats(data):
    """Summary statistics for one scan (candidates only; original excluded)."""
    df = data.df
    res = df[df.dns_status == ST_RESOLVED]
    return {
        "permutations": int(len(df)),
        "resolved": int((df.dns_status == ST_RESOLVED).sum()),
        "unresolved": int((df.dns_status == ST_UNRESOLVED).sum()),
        "dns_errors": int((df.dns_status == ST_ERROR).sum()),
        "ipv4": int((df.ipv4 != "").sum()),
        "ipv6": int((df.ipv6 != "").sum()),
        "mx": int((df.mx != "").sum()),
        "ipv4_only": int(((res.ipv4 != "") & (res.ipv6 == "")).sum()),
        "ipv6_only": int(((res.ipv4 == "") & (res.ipv6 != "")).sum()),
        "ipv4_and_ipv6": int(((res.ipv4 != "") & (res.ipv6 != "")).sum()),
        "with_lsh": int(df.ssdeep.notna().sum()),
        "with_tlsh": int(df.tlsh.notna().sum()),
        "with_phash": int(df.phash.notna().sum()),
        "by_fuzzer": {k: int(v) for k, v in df.fuzzer.value_counts().items()},
        "resolved_by_fuzzer": {k: int(v) for k, v in res.fuzzer.value_counts().items()},
    }
