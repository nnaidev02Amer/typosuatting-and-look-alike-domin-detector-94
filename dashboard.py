"""Typosquatting & Lookalike Domain Detection System - Streamlit dashboard.

Run:  streamlit run dashboard.py      (http://localhost:8501)

The scanning engine is the unmodified dnstwist.py, executed as a subprocess.
"""
import html
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dashboard_modules import ASSETS_DIR, ROOT, analytics, history, parser, reports, scanner, validators  # noqa: E402

st.set_page_config(page_title="Typosquatting & Lookalike Domain Detection", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

PAGES = ["Overview", "Domain Scanner", "Scan Results", "Threat Analysis",
         "Similarity Analysis", "Scan History", "Reports & Exports"]


# ---------------------------------------------------------------- helpers ---
@st.cache_resource(show_spinner=False)
def get_caps():
    return scanner.detect_capabilities()


@st.cache_data(show_spinner=False, max_entries=6)
def load_scan(path_str, mtime):
    """Parse a result file. Cache key includes mtime; result files are immutable."""
    return parser.load_file(path_str)


def esc(x):
    return html.escape(str(x))


def card(label, value, sub="", tone="blue", small=False):
    if isinstance(value, int):
        value = "{:,}".format(value)
    st.markdown('<div class="card {t}"><div class="label">{l}</div><div class="value{s}">{v}</div>'
                '<div class="sub">{u}</div></div>'.format(t=tone, l=esc(label), v=esc(value), u=esc(sub),
                                                         s=" small" if small else ""), unsafe_allow_html=True)


def badge(text, kind):
    return '<span class="badge {}">{}</span>'.format(kind, esc(text))


def header(title, sub):
    st.title(title)
    st.markdown('<div class="page-sub">{}</div>'.format(esc(sub)), unsafe_allow_html=True)


def fmt_time(rec):
    if rec.get("started_at"):
        return rec["started_at"][:16].replace("T", " ")
    return "unknown (imported)"


def fmt_dur(s):
    if s is None:
        return "-"
    s = int(s)
    return "{}m {:02d}s".format(s // 60, s % 60)


def goto(page):
    st.session_state["_goto"] = page
    st.rerun()


def empty_state(msg="No scans yet. Run a scan to populate the dashboard."):
    st.markdown('<div class="panel"><b>No data</b><div class="page-sub" style="margin:6px 0 0">{}</div></div>'.format(esc(msg)),
                unsafe_allow_html=True)
    if st.button("Go to Domain Scanner", key="empty_go_" + msg[:12]):
        goto("Domain Scanner")


def usable_records():
    return [r for r in history.list_records() if r.get("result_file") and r["status"] in ("completed", "imported")]


def scan_selector(key):
    """Pick a stored scan; returns (record, ScanData) or (None, None)."""
    recs = usable_records()
    if not recs:
        empty_state()
        return None, None
    ids = [r["id"] for r in recs]
    active = st.session_state.get("active_scan_id")
    idx = ids.index(active) if active in ids else 0
    labels = {r["id"]: "{}  |  {}  |  {:,} candidates".format(r["domain"], fmt_time(r), (r.get("stats") or {}).get("permutations", 0))
              for r in recs}
    chosen = st.selectbox("Scan", ids, index=idx, format_func=labels.get, key=key)
    st.session_state["active_scan_id"] = chosen
    rec = next(r for r in recs if r["id"] == chosen)
    path = history.result_path(rec)
    try:
        data = load_scan(str(path), path.stat().st_mtime)
    except (parser.ParseError, OSError) as e:
        st.error("Could not read the result file for this scan: {}".format(e))
        return rec, None
    if rec.get("imported"):
        st.caption("Imported record: the original scan time and configuration are unknown.")
    return rec, data


def analysed_frame(rec, data):
    thr = st.session_state.get("lsh_thr", 50)
    return analytics.apply_analysis(data.df, history.get_annotations(rec["id"]), thr)


def plot(fig, empty_msg="No data to chart."):
    if fig is None:
        st.caption(empty_msg)
    else:
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})


# -------------------------------------------------------------------- app ---
st.markdown("<style>{}</style>".format((ASSETS_DIR / "style.css").read_text(encoding="utf-8")), unsafe_allow_html=True)

if st.session_state.get("_goto"):
    st.session_state["nav"] = st.session_state.pop("_goto")

# import the existing results.json once per session (deduplicated by content hash)
if not st.session_state.get("_import_checked"):
    st.session_state["_import_checked"] = True
    src = ROOT / "results.json"
    if src.exists():
        status, msg, _ = history.import_results_file(src)
        if status == "imported":
            st.toast(msg)

caps = get_caps()

with st.sidebar:
    st.markdown('<div class="brand">Typosquatting &amp; Lookalike<br>Domain Detection</div>'
                '<div class="brand-sub">Powered by dnstwist {}</div>'.format(esc(caps.get("version", ""))), unsafe_allow_html=True)
    page = st.radio("Navigation", PAGES, key="nav", label_visibility="collapsed")
    st.divider()
    job = scanner.current_job()
    if job is not None and job.running:
        st.markdown(badge("SCAN RUNNING", "warn") + "<div class='page-sub' style='margin:6px 0 0'>{}</div>".format(esc(job.domain)),
                    unsafe_allow_html=True)
    st.markdown("**Engine features**")
    for label, ok in (("DNS (dnspython)", caps["dns"]), ("LSH ssdeep", caps["ssdeep"]), ("LSH TLSH", caps["tlsh"]),
                      ("pHash screenshots", caps["phash"])):
        st.markdown("{} &nbsp;{}".format(badge("ON" if ok else "OFF", "ok" if ok else "off"), esc(label)), unsafe_allow_html=True)
    st.caption("Scan only domains you own or are authorized to assess.")


# ----------------------------------------------------------------- pages ---
def page_overview():
    header("Overview", "Statistics from locally stored scan history. Nothing on this page is sample data.")
    recs = history.list_records()
    done = [r for r in recs if r.get("stats")]
    if not recs:
        empty_state()
        return
    scope = st.radio("Scope", ["Latest scan", "All scans combined"], horizontal=True, label_visibility="collapsed")
    if not done:
        st.warning("No completed scans yet; only failed or cancelled scans are in history.")
        return
    latest = done[0]
    s = latest["stats"] if scope == "Latest scan" else analytics.combine_stats([r["stats"] for r in done])
    n_scans = len(recs)
    st.caption("Showing: {}".format("{} - {}".format(latest["domain"], fmt_time(latest)) if scope == "Latest scan"
                                    else "{} scans with results (candidates counted per scan; re-scans of one domain add up)".format(len(done))))

    c = st.columns(5)
    with c[0]: card("Total scans", n_scans, "{} completed, {} imported".format(sum(r["status"] == "completed" for r in recs), sum(bool(r.get("imported")) for r in recs)))
    with c[1]: card("Permutations generated", s["permutations"], "original domain excluded")
    with c[2]: card("DNS candidates (resolved)", s["resolved"], "have A / AAAA / NS / MX data", "teal")
    with c[3]: card("Unresolved", s["unresolved"], "no DNS records returned", "grey")
    with c[4]: card("DNS errors", s["dns_errors"], "lookup returned ServFail", "amber")
    st.write("")
    c = st.columns(5)
    with c[0]: card("With IPv4 (A)", s["ipv4"], "", "blue")
    with c[1]: card("With IPv6 (AAAA)", s["ipv6"], "", "blue")
    with c[2]: card("With MX records", s["mx"], "", "blue")
    with c[3]: card("Latest scanned domain", latest["domain"], "", "grey", small=True)
    with c[4]: card("Last scan time", fmt_time(latest), "", "grey", small=True)
    st.write("")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Permutation categories")
        plot(analytics.fuzzer_chart(s["by_fuzzer"], s["resolved_by_fuzzer"]))
    with right:
        st.subheader("DNS resolution status")
        plot(analytics.status_chart(s))
    a, b, c3 = st.columns(3)
    with a:
        st.subheader("IPv4 vs IPv6 (resolved)")
        plot(analytics.ip_chart(s), "No resolved candidates with IP addresses.")
    with b:
        st.subheader("MX availability (resolved)")
        plot(analytics.mx_chart(s), "No resolved candidates.")
    with c3:
        st.subheader("Scan activity")
        plot(analytics.activity_chart(recs), "No timestamped scans yet.")

    st.subheader("Recent scans")
    rows = [{"Target": r["domain"], "Started": fmt_time(r), "Status": r["status"],
             "Candidates": (r.get("stats") or {}).get("permutations"), "Resolved": (r.get("stats") or {}).get("resolved"),
             "Duration": fmt_dur(r.get("duration_s"))} for r in recs[:8]]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    if st.button("New scan", type="primary"):
        goto("Domain Scanner")


@st.fragment(run_every=1)
def scan_monitor():
    job = scanner.current_job()
    if job is None or not job.running:
        st.rerun()
        return
    st.markdown(
        '<div class="panel scanning"><b>Scanning {d}</b><div class="page-sub" style="margin:6px 0 0">'
        '<span class="spin"></span>dnstwist is running. Elapsed: <span class="mono">{m:d}:{s:02d}</span> &nbsp;|&nbsp; timeout {t} min. '
        'The scanner does not report real progress, so none is shown.</div></div>'.format(
            d=esc(job.domain), m=int(job.elapsed) // 60, s=int(job.elapsed) % 60, t=job.timeout // 60),
        unsafe_allow_html=True)
    if st.button("Cancel scan", key="cancel_scan"):
        job.cancel()


def page_scanner():
    header("Domain Scanner", "Run the dnstwist engine against a domain and review the real results.")
    job = scanner.current_job()
    running = job is not None and job.running

    st.markdown('<div class="panel">Only scan domains that <b>you own or are explicitly authorized to assess</b>. '
                'DNS lookups are sent to your configured resolver for every generated permutation.</div>', unsafe_allow_html=True)
    domain_in = st.text_input("Enter target domain", placeholder="example.com", disabled=running, key="target_input")
    ok, normalized, msg = validators.validate_domain(domain_in) if domain_in else (False, "", "")
    if domain_in:
        (st.caption if ok else st.error)(("Will scan: " + normalized) if ok else msg)

    with st.expander("Scan configuration", expanded=True):
        c1, c2 = st.columns(2)
        with c1:
            st.checkbox("DNS scanning", value=True, disabled=True, help="Always on. Core dnstwist function (A, AAAA, NS, MX).")
            lsh_choices = ["Off"] + [n for n, k in (("ssdeep", "ssdeep"), ("tlsh", "tlsh")) if caps.get(k)]
            lsh = st.selectbox("HTML similarity (LSH)", lsh_choices, disabled=running,
                               help="Fetches the target's web page and each resolved candidate's page, then compares fuzzy hashes.")
            lsh_ack = True
            if lsh != "Off":
                st.warning("LSH makes dnstwist **send HTTP(S) requests to every resolved candidate domain**, which may be "
                           "attacker-controlled, and TLS certificates are not verified for them. Your IP address will be visible "
                           "to those sites. Fetched content is hashed, never rendered or opened in a browser.")
                lsh_ack = st.checkbox("I understand and accept this", key="lsh_ack", disabled=running)
            if not caps["tlsh"]:
                st.checkbox("TLSH similarity", value=False, disabled=True, help="Unavailable: install py-tlsh (see Similarity Analysis).")
            phash = st.checkbox("Screenshot similarity (pHash)", value=False, disabled=running or not caps["phash"],
                                help="Requires Pillow + Selenium + browser driver." if not caps["phash"] else
                                "Renders candidate pages in a headless browser (executes remote JavaScript).")
        with c2:
            registered_view = st.checkbox("Registered-domain filtering (default view)", value=False, disabled=running,
                                          help="Scans every permutation, then opens results showing resolved candidates only. "
                                               "Unresolved totals are still recorded.")
            threads = st.number_input("Scanner threads", 1, 200, 50, disabled=running)
            timeout_min = st.number_input("Timeout (minutes)", 1, 240, 15, disabled=running)
        if not caps["tlsh"]:
            st.caption("TLSH: unavailable (py-tlsh not installed). pHash: " + ("available" if caps["phash"] else "unavailable (Pillow/Selenium/driver missing)") + ".")

    authorized = st.checkbox("I own this domain or am authorized to assess it.", key="auth_ack", disabled=running)
    can_start = ok and authorized and lsh_ack and not running
    if st.button("START SCAN", type="primary", disabled=not can_start, key="start_scan"):
        options = {"dns": True, "lsh": None if lsh == "Off" else lsh, "phash": bool(phash),
                   "threads": int(threads), "timeout_s": int(timeout_min) * 60, "registered_view": bool(registered_view)}
        try:
            scanner.start_scan(domain_in, options, timeout=int(timeout_min) * 60)
        except scanner.ScanBusy as e:
            st.warning(str(e))
        except ValueError as e:
            st.error(str(e))
        else:
            st.rerun()
    if not authorized and ok and not running:
        st.caption("Confirm authorization to enable the scan.")

    job = scanner.current_job()
    if job is None:
        return
    if job.running:
        scan_monitor()
        return
    # finished job summary (server-wide, survives browser refresh)
    rec = job.record or {}
    if job.status == "completed":
        if st.session_state.get("_seen_job") != job.id:
            st.session_state["_seen_job"] = job.id
            st.session_state["active_scan_id"] = job.id
            if (job.options or {}).get("registered_view"):
                st.session_state["res_registered_only"] = True
        s = rec.get("stats") or {}
        st.success("Scan of {} completed in {}: {:,} permutations, {:,} resolved, {:,} unresolved, {:,} DNS errors."
                   .format(job.domain, fmt_dur(job.elapsed), s.get("permutations", 0), s.get("resolved", 0),
                           s.get("unresolved", 0), s.get("dns_errors", 0)))
        if st.button("View results", type="primary", key="view_res"):
            goto("Scan Results")
    else:
        st.error("Scan of {} {}: {}".format(job.domain, job.status, job.error))
    with st.expander("Scanner output (stdout / stderr)"):
        st.code(" ".join(rec.get("command", [])), language="text")
        st.text("exit code: {}".format(job.returncode))
        st.text_area("stderr", job.stderr or "(empty)", height=120, disabled=True)
        st.text_area("stdout", job.stdout or "(empty - results are written to the JSON file)", height=80, disabled=True)


def page_results():
    header("Scan Results", "Interactive view of the raw dnstwist output. Resolution status is DNS data only, not a verdict.")
    rec, data = scan_selector("sel_results")
    if data is None:
        return
    df = analysed_frame(rec, data)
    s = parser.stats(data)

    orig = data.original or {}
    with st.expander("Original domain: {}".format(data.target)):
        st.write("The original domain is shown here only and is **not** counted as a candidate.")
        st.json({k: v for k, v in orig.items() if k not in ("fuzzer",)})

    f1, f2, f3 = st.columns([2, 2, 2])
    q = f1.text_input("Search domain", placeholder="e.g. exampl", key="res_q")
    fuzzers = sorted(df.fuzzer.unique())
    pick_f = f2.multiselect("Permutation type", fuzzers, placeholder="All types")
    statuses = [parser.ST_RESOLVED, parser.ST_UNRESOLVED, parser.ST_ERROR]
    pick_s = f3.multiselect("DNS status", statuses, placeholder="All statuses")
    registered_only = st.checkbox("Registered / resolved candidates only", key="res_registered_only")

    view = df
    if q:
        view = view[view.domain.str.contains(q.strip().lower(), case=False, regex=False)]
    if pick_f:
        view = view[view.fuzzer.isin(pick_f)]
    if pick_s:
        view = view[view.dns_status.isin(pick_s)]
    if registered_only:
        view = view[view.dns_status == parser.ST_RESOLVED]

    c = st.columns(5)
    with c[0]: card("Candidates", s["permutations"], "generated (original excluded)", "grey")
    with c[1]: card("Showing", len(view), "after filters", "blue")
    with c[2]: card("Resolved", s["resolved"], "", "teal")
    with c[3]: card("Unresolved", s["unresolved"], "", "grey")
    with c[4]: card("DNS errors", s["dns_errors"], "", "amber")
    st.write("")

    cols = ["domain", "fuzzer", "dns_status", "analysis_status", "ipv4", "ipv6", "nameservers", "mx", "ssdeep", "tlsh", "phash", "geoip"]
    notes = []
    for opt in ("ssdeep", "tlsh", "phash", "geoip"):
        if df[opt].isna().all() and opt in cols:
            cols.remove(opt)
            notes.append(opt)
    config = {
        "domain": st.column_config.TextColumn("Domain", width="medium"),
        "fuzzer": st.column_config.TextColumn("Permutation type"),
        "dns_status": st.column_config.TextColumn("DNS status"),
        "analysis_status": st.column_config.TextColumn("Analysis status"),
        "ipv4": st.column_config.TextColumn("IPv4"), "ipv6": st.column_config.TextColumn("IPv6"),
        "nameservers": st.column_config.TextColumn("Nameservers"), "mx": st.column_config.TextColumn("MX"),
        "ssdeep": st.column_config.ProgressColumn("LSH ssdeep", min_value=0, max_value=100, format="%d"),
        "tlsh": st.column_config.ProgressColumn("LSH TLSH", min_value=0, max_value=100, format="%d"),
        "phash": st.column_config.ProgressColumn("pHash", min_value=0, max_value=100, format="%d"),
        "geoip": st.column_config.TextColumn("GeoIP"),
    }
    ev = st.dataframe(view[cols], hide_index=True, width="stretch", height=460, column_config=config,
                      on_select="rerun", selection_mode="single-row", key="res_table")
    if notes:
        st.caption("Columns hidden because this scan has no data for them: {}.".format(", ".join(notes)))
    st.caption("Click a column header to sort. Select a row for details.")

    sel = ev.selection.rows if ev is not None else []
    if sel and sel[0] < len(view):
        row = view.iloc[sel[0]]
        raw = data.raw_by_domain().get(row["domain"], {})
        st.subheader("Domain details")
        a, b = st.columns(2)
        with a:
            st.markdown("**Domain** `{}`  \n**Permutation type** `{}`  \n**DNS status** {}  \n**Analysis status** {}".format(
                row["domain"], row["fuzzer"], row["dns_status"], row["analysis_status"]))
            if row["review_reasons"]:
                st.markdown("**Triage reasons** " + row["review_reasons"])
            if row["dns_error_types"]:
                st.markdown("**Lookups with ServFail** " + row["dns_error_types"])
            if row["analyst_status"]:
                st.markdown("**Analyst decision** {} - {}".format(row["analyst_status"], row["analyst_note"] or "no note"))
            st.caption("The domain is shown as text on purpose. Do not open it from here; use an isolated environment if you must inspect it.")
        with b:
            st.json(raw)

    d1, d2, _ = st.columns([1, 1, 3])
    d1.download_button("Download filtered CSV", reports.frame_to_csv(view[[c for c in reports.CSV_COLUMNS if c in view.columns]]),
                       file_name=reports.file_stem(rec, "filtered") + ".csv", mime="text/csv")
    d2.download_button("Download full JSON", json.dumps(reports.build_json(data, rec, st.session_state.get("lsh_thr", 50)), indent=2),
                       file_name=reports.file_stem(rec, "report") + ".json", mime="application/json")


def page_threat():
    header("Threat Analysis", "Triage view for manual investigation. These flags are not verdicts.")
    st.markdown('<div class="panel"><b>Read this first.</b> DNS resolution, MX records or name similarity do <b>not</b> prove a domain is '
                'malicious or used for phishing. "Needs investigation" only means a documented rule matched. '
                '"Manually confirmed malicious" can only be set by an analyst below. No risk scores are computed and no candidate '
                'website is ever visited by this dashboard.</div>', unsafe_allow_html=True)
    rec, data = scan_selector("sel_threat")
    if data is None:
        return
    with st.expander("Methodology: triage rules"):
        for rid, rule, why in analytics.RULES:
            st.markdown("**{}** - {}  \n<span style='color:#8fa0ba'>{}</span>".format(rid, rule, why), unsafe_allow_html=True)
        st.session_state["lsh_thr"] = st.slider("R3 LSH similarity threshold (analyst setting)", 1, 100,
                                                 st.session_state.get("lsh_thr", 50),
                                                 help="Only matters when the scan included LSH. Not a proof of phishing.")
    df = analysed_frame(rec, data)
    counts = df.analysis_status.value_counts()
    c = st.columns(5)
    with c[0]: card("Resolved", int(counts.get("Resolved", 0)), "no rule matched", "teal")
    with c[1]: card("Unresolved", int(counts.get("Unresolved", 0)), "", "grey")
    with c[2]: card("DNS error", int(counts.get("DNS error", 0)), "", "amber")
    with c[3]: card("Needs investigation", int(counts.get("Needs investigation", 0)), "rule-based flag", "blue")
    with c[4]: card("Manually confirmed malicious", int(counts.get("Manually confirmed malicious", 0)), "analyst decision only", "red")
    st.write("")

    st.subheader("Investigation queue")
    queue = df[df.needs_review | (df.analysis_status == analytics.ST_MALICIOUS)]
    if queue.empty:
        st.info("No candidate matched a triage rule in this scan.")
    else:
        pick = st.multiselect("Filter by permutation type", sorted(queue.fuzzer.unique()), key="q_f", placeholder="All types")
        qv = queue[queue.fuzzer.isin(pick)] if pick else queue
        st.dataframe(qv[["domain", "fuzzer", "analysis_status", "review_reasons", "ipv4", "ipv6", "nameservers", "mx", "analyst_status"]],
                     hide_index=True, width="stretch", height=min(420, 38 + 35 * len(qv)))

    st.subheader("Candidates by permutation type")
    for fz in sorted(df.fuzzer.unique()):
        g = df[df.fuzzer == fz]
        res = g[g.dns_status == "Resolved"]
        with st.expander("{}  -  {:,} generated | {:,} resolved | {:,} flagged".format(fz, len(g), len(res), int(g.needs_review.sum()))):
            show_all = st.checkbox("Include unresolved / error candidates", key="all_" + fz)
            gv = g if show_all else res
            if gv.empty:
                st.caption("No resolved candidates for this type.")
            else:
                st.dataframe(gv[["domain", "dns_status", "analysis_status", "ipv4", "ipv6", "nameservers", "mx"]],
                             hide_index=True, width="stretch", height=min(360, 38 + 35 * len(gv)))

    st.subheader("Analyst review")
    st.caption("Decisions are stored locally in scan_history/annotations.json and included in reports.")
    reviewable = list(queue.domain) + [d for d in df[df.dns_status == "Resolved"].domain if d not in set(queue.domain)]
    if not reviewable:
        st.info("No resolved candidates to review.")
        return
    dom = st.selectbox("Candidate", reviewable, key="rev_dom")
    cur = history.get_annotations(rec["id"]).get(dom, {})
    with st.form("analyst_form_" + dom):
        cur_status = cur.get("status", "Not reviewed")
        status = st.selectbox("Manual status", history.MANUAL_STATUSES, index=history.MANUAL_STATUSES.index(cur_status)
                              if cur_status in history.MANUAL_STATUSES else 0)
        note = st.text_area("Analyst notes", value=cur.get("note", ""), placeholder="Evidence, sources, ticket numbers...")
        verified = st.checkbox("I independently verified this domain is malicious (required for 'Manually confirmed malicious').")
        if st.form_submit_button("Save decision"):
            if status == analytics.ST_MALICIOUS and not verified:
                st.error("Confirm independent verification to mark a domain as manually confirmed malicious.")
            else:
                history.set_annotation(rec["id"], dom, status, note)
                st.success("Saved decision for {}.".format(dom))
                st.rerun()


def page_similarity():
    header("Similarity Analysis", "Shows only comparison data the scanner actually produced.")
    rec, data = scan_selector("sel_sim")
    s = parser.stats(data) if data is not None else None
    cfg = (rec or {}).get("options") or {}

    def similarity_block(title, avail_ok, install, col, scan_n):
        st.subheader(title)
        st.markdown(badge("Supported" if avail_ok else "Unavailable", "ok" if avail_ok else "off"), unsafe_allow_html=True)
        if not avail_ok:
            st.markdown(install)
            return False
        if data is None:
            return False
        if not scan_n:
            st.info("This scan contains no {} values. Re-scan with this option enabled on the Domain Scanner page "
                    "(scan config: {}).".format(title, json.dumps({k: v for k, v in cfg.items() if k in ("lsh", "phash")})))
            return False
        tab = data.df[data.df[col].notna()][["domain", "fuzzer", "dns_status", col]].sort_values(col, ascending=False)
        st.caption("{:,} candidates have a comparison score (0-100, higher = more similar to the original). "
                   "Candidates without a score were not fetched/compared or produced no usable content.".format(len(tab)))
        st.dataframe(tab, hide_index=True, width="stretch", height=min(380, 38 + 35 * len(tab)),
                     column_config={col: st.column_config.ProgressColumn(title, min_value=0, max_value=100, format="%d")})
        st.caption("A high score means similar page content, which is expected for parked pages, redirects and legitimate "
                   "mirrors. It is not evidence of phishing by itself.")
        return True

    similarity_block("LSH ssdeep", caps["ssdeep"],
                     "`ssdeep` is not available. dnstwist can fall back to `ppdeep`: `pip install ppdeep`.",
                     "ssdeep", s["with_lsh"] if s else 0)
    similarity_block("LSH TLSH", caps["tlsh"],
                     "Requires the `py-tlsh` package (not installed):\n\n```\npip install py-tlsh\n```\nThen restart the dashboard.",
                     "tlsh", s["with_tlsh"] if s else 0)
    similarity_block("pHash", caps["phash"],
                     "Screenshot similarity (pHash) needs **Pillow**, **Selenium** and a **Chrome/Chromium browser plus matching "
                     "chromedriver** on PATH:\n\n```\npip install Pillow selenium\n```\n"
                     ":warning: pHash renders every resolved candidate page in a headless browser, which executes remote JavaScript "
                     "from potentially hostile sites. Use an isolated machine/VM. The dashboard never does this automatically.",
                     "phash", s["with_phash"] if s else 0)


def page_history():
    header("Scan History", "Every scan is stored locally in scan_history/. Open, search or delete previous scans.")
    recs = history.list_records()
    top = st.columns([3, 1])
    q = top[0].text_input("Search by domain", placeholder="Filter history...", key="hist_q")
    with top[1]:
        st.write("")
        if (ROOT / "results.json").exists() and st.button("Import results.json"):
            status, msg, _ = history.import_results_file(ROOT / "results.json", force=True)
            (st.success if status == "imported" else st.info)(msg)
            if status == "imported":
                st.rerun()
    if q:
        recs = [r for r in recs if q.strip().lower() in (r.get("domain") or "").lower()]
    if not recs:
        empty_state("No scans in history." if not q else "No scans match the search.")
        return
    rows = [{"Target": r["domain"], "Started": fmt_time(r), "Status": r["status"],
             "Permutations": (r.get("stats") or {}).get("permutations"), "Resolved": (r.get("stats") or {}).get("resolved"),
             "DNS errors": (r.get("stats") or {}).get("dns_errors"), "Duration": fmt_dur(r.get("duration_s")),
             "Imported": "yes" if r.get("imported") else "", "Config": json.dumps(r.get("options"), sort_keys=True), "ID": r["id"]} for r in recs]
    ev = st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", on_select="rerun",
                      selection_mode="single-row", key="hist_table")
    st.caption("Select a row to open, inspect or delete it.")
    sel = ev.selection.rows if ev is not None else []
    if not sel:
        return
    r = recs[sel[0]]
    st.subheader("{} - {}".format(r["domain"], fmt_time(r)))
    a, b = st.columns(2)
    with a:
        st.markdown("**Status** {}  \n**Result file** `{}`  \n**Scan ID** `{}`".format(r["status"], r.get("result_file") or "none", r["id"]))
        if r.get("error"):
            st.error(r["error"])
        if r.get("stderr_tail"):
            st.text_area("stderr (last lines)", r["stderr_tail"], height=100, disabled=True)
    with b:
        st.json({"options": r.get("options"), "stats": {k: v for k, v in (r.get("stats") or {}).items() if not isinstance(v, dict)}})
    btn = st.columns([1, 1, 1, 3])
    if r.get("result_file"):
        if btn[0].button("Open results", type="primary", key="open_" + r["id"]):
            st.session_state["active_scan_id"] = r["id"]
            goto("Scan Results")
        if btn[1].button("Open reports", key="rep_" + r["id"]):
            st.session_state["active_scan_id"] = r["id"]
            goto("Reports & Exports")
    with btn[3]:
        confirm = st.checkbox("Confirm: permanently delete this history entry and its stored result copy", key="del_ok_" + r["id"])
        if st.button("Delete entry", disabled=not confirm, key="del_" + r["id"]):
            history.delete_record(r["id"])
            if st.session_state.get("active_scan_id") == r["id"]:
                st.session_state.pop("active_scan_id")
            st.rerun()


def page_reports():
    header("Reports & Exports", "Reports are built from the stored scanner output plus your analyst notes.")
    rec, data = scan_selector("sel_rep")
    if data is None:
        return
    thr = st.session_state.get("lsh_thr", 50)
    jtxt = json.dumps(reports.build_json(data, rec, thr), indent=2, ensure_ascii=False)
    ctxt = reports.build_csv(data, rec, thr)
    stxt = reports.build_summary(data, rec, thr)
    c = st.columns(3)
    c[0].download_button("Download JSON report", jtxt, file_name=reports.file_stem(rec, "report") + ".json", mime="application/json", width="stretch")
    c[1].download_button("Download CSV report", ctxt, file_name=reports.file_stem(rec, "report") + ".csv", mime="text/csv", width="stretch")
    c[2].download_button("Download scan summary", stxt, file_name=reports.file_stem(rec, "summary") + ".txt", mime="text/plain", width="stretch")
    st.caption("Sizes: JSON {:,} KB, CSV {:,} KB. CSV cells starting with = + - @ are prefixed with ' to prevent spreadsheet formula injection.".format(len(jtxt) // 1024, len(ctxt) // 1024))
    if st.button("Save copies to reports/ folder"):
        paths = [reports.save_copy(jtxt, rec, "report", "json"), reports.save_copy(ctxt, rec, "report", "csv"),
                 reports.save_copy(stxt, rec, "summary", "txt")]
        st.success("Saved (unique filenames, nothing overwritten):")
        for p in paths:
            st.code(str(p.relative_to(ROOT)), language="text")
    with st.expander("Summary preview", expanded=True):
        st.code(stxt, language="text")


{"Overview": page_overview, "Domain Scanner": page_scanner, "Scan Results": page_results,
 "Threat Analysis": page_threat, "Similarity Analysis": page_similarity, "Scan History": page_history,
 "Reports & Exports": page_reports}[page]()
