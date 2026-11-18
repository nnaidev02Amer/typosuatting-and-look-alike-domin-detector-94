"""Triage rules and Plotly charts. All inputs come from real scan data."""
import pandas as pd
import plotly.graph_objects as go

from .parser import ST_ERROR, ST_RESOLVED, ST_UNRESOLVED

ST_REVIEW = "Needs investigation"
ST_MALICIOUS = "Manually confirmed malicious"

# Documented triage rules. These select candidates for MANUAL review; they are
# not verdicts, and there is no risk score.
RULES = [
    ("R1", "Resolves to an IP address AND publishes MX records",
     "The domain could receive email. Lookalike domains with mail setup deserve a manual look."),
    ("R2", "dnstwist mx_spy flag set (--mxcheck)",
     "The scanner reports the MX host could be used to intercept the target's email."),
    ("R3", "LSH (ssdeep/TLSH) page similarity at or above an analyst-set threshold",
     "The fetched HTML is similar to the original page. The threshold is a triage setting, not a proof."),
]

COLORS = {"Resolved": "#2dd4bf", "Unresolved": "#64748b", "DNS error": "#f59e0b",
          "blue": "#3b82f6", "violet": "#8b5cf6", "red": "#ef4444", "text": "#cbd5e1", "grid": "#1e293b"}


def triage(df, lsh_threshold=50):
    """Add 'review_reasons' and 'needs_review' columns (rules R1-R3)."""
    out = df.copy()
    reasons = []
    for _, r in out.iterrows():
        why = []
        has_ip = bool(r["ipv4"] or r["ipv6"])
        if has_ip and r["mx"]:
            why.append("R1: resolves + has MX")
        if r["mx_spy"] is True:
            why.append("R2: mx_spy")
        lsh = pd.concat([pd.Series([r["ssdeep"]]), pd.Series([r["tlsh"]])]).max()
        if pd.notna(lsh) and lsh >= lsh_threshold:
            why.append("R3: LSH {:.0f} >= {}".format(lsh, lsh_threshold))
        reasons.append("; ".join(why))
    out["review_reasons"] = reasons
    out["needs_review"] = out["review_reasons"] != ""
    return out


def apply_analysis(df, annotations, lsh_threshold=50):
    """Add analysis_status / analyst_status / analyst_note.

    Precedence: analyst-confirmed malicious > needs investigation (rule hit) > DNS status.
    'Manually confirmed malicious' can only come from an analyst annotation.
    """
    out = triage(df, lsh_threshold)
    ann = annotations or {}
    out["analyst_status"] = out["domain"].map(lambda d: ann.get(d, {}).get("status", ""))
    out["analyst_note"] = out["domain"].map(lambda d: ann.get(d, {}).get("note", ""))

    def status(r):
        if r["analyst_status"] == ST_MALICIOUS:
            return ST_MALICIOUS
        if r["needs_review"] and r["dns_status"] == ST_RESOLVED:
            return ST_REVIEW
        return r["dns_status"]
    out["analysis_status"] = out.apply(status, axis=1)
    return out


# ---- charts ------------------------------------------------------------------

def _style(fig, height=300, legend=True):
    fig.update_layout(
        height=height, margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=COLORS["text"], family="Inter, Segoe UI, sans-serif", size=12),
        showlegend=legend, legend=dict(orientation="h", y=-0.1, font=dict(size=11)),
    )
    return fig


def _donut(labels, values, colors, height=280):
    pairs = [(l, v, c) for l, v, c in zip(labels, values, colors) if v > 0]
    if not pairs:
        return None
    fig = go.Figure(go.Pie(labels=[p[0] for p in pairs], values=[p[1] for p in pairs], hole=0.62,
                           marker=dict(colors=[p[2] for p in pairs], line=dict(color="#0b1220", width=2)),
                           textinfo="value", sort=False, hovertemplate="%{label}: %{value} (%{percent})<extra></extra>"))
    return _style(fig, height)


def fuzzer_chart(by_fuzzer, resolved_by_fuzzer):
    """Horizontal bars: generated permutations and resolved candidates per category."""
    if not by_fuzzer:
        return None
    cats = sorted(by_fuzzer, key=lambda k: by_fuzzer[k])
    fig = go.Figure()
    fig.add_bar(y=cats, x=[by_fuzzer[c] for c in cats], orientation="h", name="Generated",
                marker_color="#334155", hovertemplate="%{y}: %{x} generated<extra></extra>")
    fig.add_bar(y=cats, x=[resolved_by_fuzzer.get(c, 0) for c in cats], orientation="h", name="Resolved",
                marker_color=COLORS["Resolved"], hovertemplate="%{y}: %{x} resolved<extra></extra>")
    log = max(by_fuzzer.values()) > 20 * max(1, min(by_fuzzer.values()))
    xaxis = dict(gridcolor=COLORS["grid"], type="log" if log else "linear", title="candidates (log scale)" if log else "candidates")
    if log:
        xaxis.update(dtick=1, minor=dict(showgrid=False, ticks=""))
    fig.update_layout(barmode="overlay", xaxis=xaxis, yaxis=dict(gridcolor=COLORS["grid"]))
    return _style(fig, max(260, 28 * len(cats) + 80))


def status_chart(s):
    return _donut(["Resolved", "Unresolved", "DNS error"], [s["resolved"], s["unresolved"], s["dns_errors"]],
                  [COLORS["Resolved"], COLORS["Unresolved"], COLORS["DNS error"]])


def ip_chart(s):
    return _donut(["IPv4 only", "IPv6 only", "IPv4 + IPv6"], [s["ipv4_only"], s["ipv6_only"], s["ipv4_and_ipv6"]],
                  [COLORS["blue"], COLORS["violet"], COLORS["Resolved"]])


def mx_chart(s):
    # restricted to resolved candidates so the two slices add up to the resolved count
    return _donut(["Has MX", "No MX"], [s["mx"], max(s["resolved"] - s["mx"], 0)],
                  [COLORS["blue"], COLORS["Unresolved"]])


def activity_chart(records):
    """Scans per day from stored history (imported records with unknown time are excluded)."""
    days = {}
    for r in records:
        if r.get("started_at"):
            days[r["started_at"][:10]] = days.get(r["started_at"][:10], 0) + 1
    if not days:
        return None
    keys = sorted(days)
    fig = go.Figure(go.Bar(x=keys, y=[days[k] for k in keys], marker_color=COLORS["blue"],
                           hovertemplate="%{x}: %{y} scan(s)<extra></extra>"))
    fig.update_layout(xaxis=dict(type="category", gridcolor=COLORS["grid"]),
                      yaxis=dict(gridcolor=COLORS["grid"], dtick=1, rangemode="tozero"))
    return _style(fig, 260, legend=False)


def combine_stats(stat_list):
    """Sum stats dicts across scans (for the aggregate Overview scope)."""
    total = {}
    for s in stat_list:
        for k, v in s.items():
            if isinstance(v, dict):
                d = total.setdefault(k, {})
                for kk, vv in v.items():
                    d[kk] = d.get(kk, 0) + vv
            else:
                total[k] = total.get(k, 0) + v
    return total
