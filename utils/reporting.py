import os
from datetime import datetime
from typing import List, Dict, Any
import pandas as pd
from fpdf import FPDF
from fpdf.errors import FPDFException
from utils.feature_engineering import canonicalize_columns


def _shorten(text: str, max_len: int = 200) -> str:
    if text is None:
        return ""
    s = str(text)
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _vt_summary(vt: Dict[str, Any]) -> str:
    if not isinstance(vt, dict):
        return "N/A"
    status = vt.get("status")
    if status == "ok":
        mal = vt.get("malicious")
        sus = vt.get("suspicious")
        har = vt.get("harmless")
        return f"mal:{mal} sus:{sus} har:{har}"
    return f"status:{status}"


def _abuse_summary(ab: Dict[str, Any]) -> str:
    if not isinstance(ab, dict):
        return "N/A"
    status = ab.get("status")
    if status == "ok":
        score = ab.get("abuseConfidenceScore")
        reports = ab.get("totalReports")
        white = ab.get("isWhitelisted")
        return f"score:{score} reports:{reports} white:{white}"
    return f"status:{status}"


def _page_width(pdf: FPDF) -> float:
    return pdf.w - pdf.l_margin - pdf.r_margin


def _write_wrapped(pdf: FPDF, text: str, h: float = 5):
    pdf.set_x(pdf.l_margin)
    w = _page_width(pdf)
    s = _shorten(text, 500)
    try:
        pdf.multi_cell(w, h, s)
    except FPDFException:
        for max_len in (200, 120, 80, 40):
            try:
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(w, h, _shorten(s, max_len))
                return
            except FPDFException:
                continue
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(w, h, "[content truncated]")


def generate_pdf_report(alerts_df: pd.DataFrame, enrichment: List[Dict[str, Any]], out_dir: str = "reports") -> str:
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(out_dir, f"soc_report_{ts}.pdf")

    # Normalize columns so canonical fields are detected
    alerts_df = canonicalize_columns(alerts_df)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    _write_wrapped(pdf, "SOC Assistant Report", h=10)

    pdf.set_font("Arial", size=11)
    _write_wrapped(pdf, f"Generated (UTC): {datetime.utcnow().isoformat()}", h=8)
    pdf.ln(4)

    # Summary
    pdf.set_font("Arial", "B", 13)
    _write_wrapped(pdf, "Summary", h=8)
    pdf.set_font("Arial", size=11)
    n = len(alerts_df)
    cls_series = alerts_df.get("classification", pd.Series([], dtype=object))
    n_mal = (cls_series == "malicious").sum()
    n_sus = (cls_series == "suspicious").sum()
    n_ben = (cls_series == "benign").sum()
    _write_wrapped(pdf, f"Analyzed alerts: {n}\nMalicious: {n_mal}, Suspicious: {n_sus}, Benign: {n_ben}", h=6)
    pdf.ln(2)

    # Details table (limited)
    pdf.set_font("Arial", "B", 13)
    _write_wrapped(pdf, "Alerts", h=8)
    pdf.set_font("Arial", size=10)
    preferred = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "event_type",
        "username",
        "status",
        "classification",
        "risk_score",
    ]

    # Only include columns that exist; do not force N/A
    cols = [c for c in preferred if c in alerts_df.columns]

    sub = alerts_df.copy()
    if "risk_score" in sub.columns:
        try:
            sub["risk_score"] = pd.to_numeric(sub["risk_score"], errors="coerce")
        except Exception:
            pass

    for _, r in sub[cols].head(50).iterrows():
        fields = []
        for c in cols:
            val = r.get(c, "")
            if isinstance(val, float) and c == "risk_score" and not pd.isna(val):
                val = f"{val:.2f}"
            fields.append(f"{c}: {_shorten(val, 160)}")
        line = ", ".join(fields)
        _write_wrapped(pdf, line, h=5)
        pdf.ln(1)

    # Threat intel snippets (summarized)
    pdf.set_font("Arial", "B", 13)
    _write_wrapped(pdf, "Threat Intelligence", h=8)
    pdf.set_font("Arial", size=9)
    for row in enrichment[:20]:
        src_ip = row.get("source_ip", "")
        dst_ip = row.get("destination_ip", "")
        _write_wrapped(pdf, f"Source IP: {src_ip} | Dest IP: {dst_ip}", h=5)
        for fld in ["source_ip", "destination_ip"]:
            vt = row.get("vt", {}).get(fld, {})
            ab = row.get("abuse", {}).get(fld, {})
            vt_s = _vt_summary(vt)
            ab_s = _abuse_summary(ab)
            _write_wrapped(pdf, f" - {fld} VT: {vt_s}", h=5)
            _write_wrapped(pdf, f" - {fld} AbuseIPDB: {ab_s}", h=5)
        pdf.ln(1)

    pdf.output(out_path)
    return out_path
