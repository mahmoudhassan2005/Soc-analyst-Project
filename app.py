import os
import io
import time
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from model.predict import load_or_train_model, predict_batch, explain_prediction
from utils.feature_engineering import preprocess_dataframe, canonicalize_columns
from utils.recommendations import recommend_actions
from utils.reporting import generate_pdf_report
from api.virustotal import enrich_ip_with_virustotal
from api.abuseipdb import enrich_ip_with_abuseipdb

load_dotenv()

st.set_page_config(page_title="SOC Assistant", layout="wide")
st.title("🔎 SOC Assistant - AI-powered Alert Analysis")

@st.cache_data(show_spinner=False)
def load_sample() -> pd.DataFrame:
    path = os.path.join("data", "sample_logs.csv")
    if os.path.exists(path):
        return pd.read_csv(path)
    return pd.DataFrame()

@st.cache_resource(show_spinner=True)
def get_model():
    return load_or_train_model(
        data_path=os.path.join("data", "sample_logs.csv"),
        model_path=os.path.join("model", "model.pkl"),
    )

with st.sidebar:
    st.header("Inputs")
    uploaded = st.file_uploader("Upload CSV logs", type=["csv"]) 
    st.markdown("Or enter a single alert:")
    col1, col2 = st.columns(2)
    with col1:
        ts = st.text_input("timestamp", value="2025-11-03T10:15:00Z")
        source_ip = st.text_input("source_ip", value="10.0.0.5")
        event_type = st.text_input("event_type", value="login_failure")
    with col2:
        destination_ip = st.text_input("destination_ip", value="185.199.108.153")
        username = st.text_input("username", value="alice")
        status = st.text_input("status", value="failed")

    st.markdown("---")
    st.subheader("Performance")
    analyze_all = st.checkbox("Analyze all rows", value=True)
    max_rows = st.number_input("Max rows to analyze", min_value=1, max_value=2000000, value=1000, step=100)
    enable_enrich = st.checkbox("Enable threat enrichment", value=True)
    max_enrich = st.number_input("Max rows to enrich (top risk)", min_value=0, max_value=1000, value=20, step=5)

    single_alert = {
        "timestamp": ts,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "event_type": event_type,
        "username": username,
        "status": status,
    }

model = get_model()
sample_df = load_sample()

st.subheader("Data Preview")
if uploaded is not None:
    try:
        raw_df = pd.read_csv(uploaded)
        user_df = canonicalize_columns(raw_df)
        if not analyze_all and len(user_df) > max_rows:
            st.info(f"Truncating {len(user_df)} rows to first {max_rows} for performance.")
            user_df = user_df.head(max_rows)
        st.dataframe(user_df.head(50), use_container_width=True)
    except Exception as e:
        st.error(f"Failed to read CSV: {e}")
        user_df = None
else:
    st.dataframe(sample_df.head(20), use_container_width=True)
    user_df = None

st.subheader("Analysis")
run_btn = st.button("Run Analysis", type="primary")

if run_btn:
    start_time = time.time()
    if user_df is None:
        user_df = pd.DataFrame([single_alert])
        user_df = canonicalize_columns(user_df)

    with st.spinner("Analyzing..."):
        processed = preprocess_dataframe(user_df)
        preds, probs = predict_batch(model, processed)

        # Map to labels
        labels = []
        risk_scores = []
        for p, pr in zip(preds, probs):
            risk = float(pr.max()) if hasattr(pr, "max") else float(pr)
            risk_scores.append(risk)
            if risk >= 0.8:
                labels.append("malicious")
            elif risk >= 0.5:
                labels.append("suspicious")
            else:
                labels.append("benign")

        result_df = user_df.copy()
        result_df["risk_score"] = risk_scores
        result_df["classification"] = labels

        # Threat intel enrichment (only top-K by risk)
        enriched_rows = []
        if enable_enrich and max_enrich > 0 and len(result_df) > 0:
            top_idx = result_df["risk_score"].nlargest(min(max_enrich, len(result_df))).index
            to_enrich = result_df.loc[top_idx]
            prog = st.progress(0.0, text="Enriching threat intel...")
            total = len(to_enrich)
            for i, (_, row) in enumerate(to_enrich.iterrows(), start=1):
                row_info = {
                    "source_ip": row.get("source_ip", ""),
                    "destination_ip": row.get("destination_ip", ""),
                    "vt": {},
                    "abuse": {},
                }
                for ip_field in ["source_ip", "destination_ip"]:
                    ip = row.get(ip_field)
                    if isinstance(ip, str) and len(ip) > 0:
                        vt = enrich_ip_with_virustotal(ip)
                        ab = enrich_ip_with_abuseipdb(ip)
                        row_info["vt"][ip_field] = vt
                        row_info["abuse"][ip_field] = ab
                enriched_rows.append(row_info)
                if total:
                    prog.progress(i / total)
        else:
            enriched_rows = []

        st.write("Predictions:")
        st.dataframe(result_df, use_container_width=True)

        # Explainability for first row
        st.subheader("Explainability")
        try:
            if not processed.empty:
                exp = explain_prediction(model, processed.iloc[[0]])
                st.bar_chart(exp.sort_values(ascending=False).head(20))
        except Exception as e:
            st.info(f"Explainability not available: {e}")

        # Recommendations
        st.subheader("Recommended Actions")
        recs = recommend_actions(result_df)
        for r in recs:
            st.markdown(f"- {r}")

        # persist results for report generation
        st.session_state["soc_result_df"] = result_df
        st.session_state["soc_enriched"] = enriched_rows

        elapsed = time.time() - start_time
        st.caption(f"Completed in {elapsed:.2f}s (rows analyzed: {len(result_df)}; intel entries: {len(enriched_rows)})")

# Report section rendered independently so button persists across reruns
st.subheader("Report")
if "soc_result_df" in st.session_state and "soc_enriched" in st.session_state:
    if st.button("Generate PDF Report"):
        file_path = generate_pdf_report(
            alerts_df=st.session_state["soc_result_df"],
            enrichment=st.session_state["soc_enriched"],
            out_dir="reports",
        )
        st.success(f"Report saved to {file_path}")
        try:
            with open(file_path, "rb") as f:
                st.download_button(
                    label="Download PDF",
                    data=f,
                    file_name=os.path.basename(file_path),
                    mime="application/pdf",
                )
        except Exception:
            pass
else:
    st.caption("Run analysis first to enable report generation.")

st.sidebar.markdown("---")
st.sidebar.caption("© 2025 SOC Assistant Prototype")
