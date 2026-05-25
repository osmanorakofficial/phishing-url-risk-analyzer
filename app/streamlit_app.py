import pandas as pd
import streamlit as st
import base64

from pathlib import Path
from utils import normalize_url
from model_service import load_model_and_features, predict_url
from url_features import extract_live_url_features
from html_features import analyze_live_html
from network_features import analyze_network_features
from risk_engine import calculate_final_risk
from intelligence_features import analyze_intelligence_features
from report_service import create_pdf_report, create_csv_report


st.set_page_config(
    page_title="Phishing URL Risk Analyzer",
    page_icon="🛡️",
    layout="wide"
)


CUSTOM_CSS = """
<style>
.main {
    background-color: #f7f9fc;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    max-width: 1400px;
}

.hero-card {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 55%, #0f766e 100%);
    padding: 32px;
    border-radius: 24px;
    color: white;
    box-shadow: 0 20px 45px rgba(15, 23, 42, 0.22);
    margin-bottom: 28px;
}



.hero-content {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 28px;
}

.hero-left {
    flex: 1;
}

.hero-logo {
    width: 125px;
    height: 125px;
    border-radius: 20px;
    object-fit: cover;
    box-shadow: 0 14px 32px rgba(0, 0, 0, 0.28);
}

.hero-title {
    font-size: 42px;
    font-weight: 800;
    margin-bottom: 8px;
}

.hero-subtitle {
    font-size: 17px;
    color: #dbeafe;
    max-width: 900px;
    line-height: 1.6;
}

.badge-row {
    margin-top: 18px;
}

.badge {
    display: inline-block;
    padding: 8px 13px;
    margin-right: 8px;
    border-radius: 999px;
    background: rgba(255,255,255,0.13);
    color: #e0f2fe;
    font-size: 13px;
    border: 1px solid rgba(255,255,255,0.18);
}

.section-title {
    font-size: 26px;
    font-weight: 750;
    margin-top: 16px;
    margin-bottom: 14px;
    color: #0f172a;
}

.metric-card {
    background: white;
    border-radius: 18px;
    padding: 22px;
    border: 1px solid #e5e7eb;
    box-shadow: 0 12px 25px rgba(15, 23, 42, 0.06);
    min-height: 130px;
}

.metric-label {
    color: #64748b;
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 10px;
}

.metric-value {
    color: #0f172a;
    font-size: 31px;
    font-weight: 800;
}

.metric-help {
    color: #64748b;
    font-size: 13px;
    margin-top: 8px;
}

.status-box {
    padding: 18px 22px;
    border-radius: 18px;
    font-size: 18px;
    font-weight: 700;
    margin-top: 18px;
    margin-bottom: 18px;
}

.status-low {
    background: #dcfce7;
    color: #166534;
    border: 1px solid #86efac;
}

.status-medium {
    background: #fef9c3;
    color: #854d0e;
    border: 1px solid #fde68a;
}

.status-high {
    background: #ffedd5;
    color: #9a3412;
    border: 1px solid #fdba74;
}

.status-critical {
    background: #fee2e2;
    color: #991b1b;
    border: 1px solid #fca5a5;
}

.signal-card {
    background: white;
    padding: 16px 18px;
    border-radius: 16px;
    border: 1px solid #e5e7eb;
    margin-bottom: 10px;
    box-shadow: 0 8px 18px rgba(15, 23, 42, 0.04);
}

.signal-risk {
    border-left: 5px solid #ef4444;
}

.signal-safe {
    border-left: 5px solid #22c55e;
}

.export-card {
    background: white;
    border-radius: 20px;
    padding: 22px;
    border: 1px solid #e5e7eb;
    box-shadow: 0 12px 25px rgba(15, 23, 42, 0.06);
    margin-top: 22px;
    margin-bottom: 22px;
}

.small-muted {
    color: #64748b;
    font-size: 14px;
}

.footer-note {
    color: #64748b;
    font-size: 13px;
    margin-top: 20px;
}
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_model():
    return load_model_and_features()


def get_image_base64(image_path: str) -> str:
    image_bytes = Path(image_path).read_bytes()
    return base64.b64encode(image_bytes).decode()    


def get_status_class(risk_level: str) -> str:
    if risk_level == "Low Risk":
        return "status-low"
    if risk_level == "Medium Risk":
        return "status-medium"
    if risk_level == "High Risk":
        return "status-high"
    return "status-critical"


def run_analysis(url_input: str):
    url = normalize_url(url_input)

    url_features = extract_live_url_features(url)
    html_features = analyze_live_html(url)
    network_features = analyze_network_features(url)
    intelligence_features = analyze_intelligence_features(url)

    model_result = predict_url(
        model,
        selected_features,
        url_features
    )

    risk_result = calculate_final_risk(
        model_result,
        html_features,
        network_features,
        intelligence_features
    )

    return {
        "url": url,
        "url_features": url_features,
        "html_features": html_features,
        "network_features": network_features,
        "intelligence_features": intelligence_features,
        "model_result": model_result,
        "risk_result": risk_result
    }


def save_to_history(analysis):
    if "history" not in st.session_state:
        st.session_state.history = []

    risk_result = analysis["risk_result"]

    st.session_state.history.append({
        "url": analysis["url"],
        "final_score": risk_result["final_score"],
        "risk_level": risk_result["risk_level"],
        "decision": risk_result["decision"],
        "confidence": risk_result["confidence"]
    })

    st.session_state.history = st.session_state.history[-20:]


def render_signal_cards(title: str, items: list, card_type: str):
    st.markdown(f"### {title}")

    if not items:
        st.markdown(
            f"""
            <div class="signal-card">
                No significant finding detected.
            </div>
            """,
            unsafe_allow_html=True
        )
        return

    css_class = "signal-risk" if card_type == "risk" else "signal-safe"

    for item in items:
        st.markdown(
            f"""
            <div class="signal-card {css_class}">
                {item}
            </div>
            """,
            unsafe_allow_html=True
        )


def show_result(analysis):
    url = analysis["url"]
    url_features = analysis["url_features"]
    html_features = analysis["html_features"]
    network_features = analysis["network_features"]
    intelligence_features = analysis["intelligence_features"]
    model_result = analysis["model_result"]
    risk_result = analysis["risk_result"]

    st.markdown('<div class="section-title">Analysis Overview</div>', unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Final Risk Score</div>
                <div class="metric-value">{risk_result['final_score']:.2f}/100</div>
                <div class="metric-help">Combined rule engine score</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Risk Level</div>
                <div class="metric-value">{risk_result['risk_level']}</div>
                <div class="metric-help">Final classification</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Final Decision</div>
                <div class="metric-value">{risk_result['decision']}</div>
                <div class="metric-help">User-facing security decision</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">AI Confidence</div>
                <div class="metric-value">{risk_result['confidence']}%</div>
                <div class="metric-help">Decision confidence</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    status_class = get_status_class(risk_result["risk_level"])

    st.markdown(
        f"""
        <div class="status-box {status_class}">
            {risk_result["risk_level"]} — {risk_result["decision"]}
        </div>
        """,
        unsafe_allow_html=True
    )

    st.progress(int(risk_result["final_score"]))

    st.markdown('<div class="section-title">Threat Explanation</div>', unsafe_allow_html=True)

    risk_col, safe_col = st.columns(2)

    with risk_col:
        render_signal_cards(
            "Detected Risk Indicators",
            risk_result["risk_reasons"],
            "risk"
        )

    with safe_col:
        render_signal_cards(
            "Positive Security Signals",
            risk_result["safe_reasons"],
            "safe"
        )

    st.markdown('<div class="section-title">Technical Analysis</div>', unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs([
        "URL Features",
        "HTML Analysis",
        "Network Analysis",
        "Intelligence Analysis"
    ])

    with tab1:
        st.dataframe(pd.DataFrame([url_features]), use_container_width=True)

    with tab2:
        st.dataframe(pd.DataFrame([html_features]), use_container_width=True)

    with tab3:
        st.dataframe(pd.DataFrame([network_features]), use_container_width=True)

    with tab4:
        intelligence_table = intelligence_features.copy()
        intelligence_table["intelligence_reasons"] = ", ".join(
            intelligence_table.get("intelligence_reasons", [])
        )
        intelligence_table["intelligence_safe_reasons"] = ", ".join(
            intelligence_table.get("intelligence_safe_reasons", [])
        )
        st.dataframe(pd.DataFrame([intelligence_table]), use_container_width=True)

    st.markdown(
        """
        <div class="export-card">
            <div class="section-title" style="margin-top:0;">Export Center</div>
            <div class="small-muted">
                Download a structured report for documentation, presentation, or GitHub demo usage.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    pdf_report = create_pdf_report(
        url,
        risk_result,
        model_result,
        html_features,
        network_features,
        intelligence_features
    )

    csv_report = create_csv_report(
        url,
        risk_result,
        model_result,
        html_features,
        network_features,
        intelligence_features
    )

    col_pdf, col_csv = st.columns(2)

    with col_pdf:
        st.download_button(
            label="📄 Download PDF Report",
            data=pdf_report,
            file_name="phishing_url_analysis_report.pdf",
            mime="application/pdf",
            key="download_pdf_report"
        )

    with col_csv:
        st.download_button(
            label="📊 Download CSV Report",
            data=csv_report,
            file_name="phishing_url_analysis_report.csv",
            mime="text/csv",
            key="download_csv_report"
        )


def show_history():
    st.markdown('<div class="section-title">Analysis History</div>', unsafe_allow_html=True)

    if "history" not in st.session_state or len(st.session_state.history) == 0:
        st.info("No analysis has been performed yet.")
        return

    history_df = pd.DataFrame(st.session_state.history)

    st.dataframe(history_df, use_container_width=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Total Analyses</div>
                <div class="metric-value">{len(history_df)}</div>
                <div class="metric-help">Stored in current session</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:
        avg_score = round(history_df["final_score"].mean(), 2)
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Average Risk Score</div>
                <div class="metric-value">{avg_score}</div>
                <div class="metric-help">Last 20 analyses</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.bar_chart(history_df["risk_level"].value_counts())


model, selected_features = get_model()

if "history" not in st.session_state:
    st.session_state.history = []

logo_base64 = get_image_base64("app/static/logo.png")    

st.markdown(
    f"""
    <div class="hero-card">
        <div class="hero-content">
            <div class="hero-left">
                <div class="hero-title">🛡️ Phishing URL Risk Analyzer</div>
                <div class="hero-subtitle">
                    A professional phishing risk assessment dashboard powered by machine learning,
                    HTML inspection, SSL/DNS/WHOIS checks, and URL intelligence analysis.
                </div>
                <div class="badge-row">
                    <span class="badge">Machine Learning</span>
                    <span class="badge">HTML Inspection</span>
                    <span class="badge">SSL / DNS / WHOIS</span>
                    <span class="badge">URL Intelligence</span>
                    <span class="badge">PDF / CSV Report</span>
                </div>
            </div>
            <img src="data:image/png;base64,{logo_base64}" class="hero-logo">
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown('<div class="section-title">Analyze a URL</div>', unsafe_allow_html=True)

with st.container():
    url_input = st.text_input(
        "Enter URL",
        placeholder="https://www.google.com",
        label_visibility="collapsed"
    )

    analyze_clicked = st.button("🔍 Analyze URL", use_container_width=False)

if analyze_clicked:
    if not url_input:
        st.warning("Please enter a URL.")
    else:
        with st.spinner("Analyzing URL..."):
            analysis = run_analysis(url_input)

        st.session_state.last_analysis = analysis
        save_to_history(analysis)

if "last_analysis" in st.session_state:
    show_result(st.session_state.last_analysis)

show_history()

st.markdown(
    """
    <div class="footer-note">
        Disclaimer: This tool provides risk assessment support and does not guarantee absolute security.
        Always verify suspicious URLs using multiple independent security sources.
        <br><br>
        For more information, visit <b>https://sibertechai.com</b>
    </div>
    """,
    unsafe_allow_html=True
)