import streamlit as st
import requests
import pandas as pd
from datetime import datetime

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AI Cyber Shield | Secure Integration Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. THEME & STYLING (THE "ULTIMATE" VISIBILITY FIX) ---
st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] {
        background-color: #0e1117;
    }
    html, body, [class*="css"], .stMarkdown, p, div, label, span {
        color: #ffffff !important;
    }
    [data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #30363d;
    }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
        color: #00f2ff !important;
    }
    div[data-baseweb="select"] > div {
        background-color: #0d1117 !important;
        border: 1px solid #00f2ff !important;
    }
    div[data-baseweb="popover"] ul {
        background-color: #161b22 !important;
        border: 1px solid #00f2ff !important;
    }
    div[data-baseweb="popover"] li {
        background-color: #161b22 !important;
        color: #ffffff !important;
    }
    div[data-baseweb="popover"] li:hover {
        background-color: #00f2ff !important;
        color: #0e1117 !important;
    }
    .stTextArea textarea {
        background-color: #0d1117 !important;
        color: #00f2ff !important;
        border: 1px solid #30363d !important;
    }
    .stButton>button {
        background-color: #00f2ff;
        color: #0e1117 !important;
        font-weight: bold;
        border-radius: 5px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 3. SIDEBAR ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=80)
    st.title("Admin Console")
    st.markdown("---")
    menu = ["🔐 Threat Scanner", "📊 Forensic Audit Logs", "🛡️ Integration Specs"]
    choice = st.selectbox("System Module", menu)
    st.markdown("---")
    st.write(f"**API Status:** ONLINE ✅")
    st.write(f"**Database:** SQLite CONNECTED 🗄️")
    st.write(f"**Logged in as:** Divya Agarwal")

# --- 4. MODULE: THREAT SCANNER ---
if choice == "🔐 Threat Scanner":
    st.title("🔐 Real-Time API Threat Analysis")
    st.write("This module integrates NLP and Signal Processing models via Secure REST API.")
    
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📩 Phishing/URL Analysis")
        text_input = st.text_area("Input to Scan:", height=150, placeholder="Paste suspicious content or URL...")
        
        if st.button("EXECUTE SCAN"):
            if text_input:
                with st.spinner("Sanitizing & Predicting..."):
                    try:
                        # Call Divya's Secure API
                        res = requests.post("http://127.0.0.1:5000/predict-phishing", json={"text": text_input})
                        data = res.json()
                        
                        if "Phishing" in data['result']:
                            st.error(f"### 🚨 THREAT DETECTED: {data['result']}")
                            m1, m2 = st.columns(2)
                            m1.metric("Risk Level", data['risk_level'], delta="CRITICAL", delta_color="inverse")
                            m2.metric("AI Confidence", f"{data['confidence']}%", delta="High Certainty")
                        else:
                            st.success(f"### ✅ RESULT: Legitimate")
                            m1, m2 = st.columns(2)
                            m1.metric("Risk Level", "Low", delta="SECURE")
                            m2.metric("AI Confidence", f"{data['confidence']}%")
                            
                    except Exception as e:
                        st.error(f"Backend Offline. Start app.py first. Error: {e}")
            else:
                st.warning("Please enter text to scan.")

    with col2:
        st.subheader("🎙️ Deepfake Audio Verification")
        audio_file = st.file_uploader("Upload Audio Sample:", type=['wav', 'mp3'])
        if st.button("VERIFY AUTHENTICITY"):
            if audio_file:
                with st.spinner("Analyzing Audio Frequencies..."):
                    try:
                        files = {"file": audio_file}
                        res = requests.post("http://127.0.0.1:5000/predict-audio", files=files)
                        data = res.json()
                        st.info(f"**Prediction:** {data['prediction']}")
                        st.write(f"**Security Risk:** {data['risk_score']}")
                    except:
                        st.error("Backend Error.")

# --- 5. MODULE: FORENSIC AUDIT LOGS ---
elif choice == "📊 Forensic Audit Logs":
    st.title("📊 Security Audit Trail")
    st.write("Direct integration with the SQLite 'security_auditor.db' for threat monitoring.")
    
    if st.button("REFRESH THREAT LOGS"):
        try:
            res = requests.get("http://127.0.0.1:5000/audit-logs")
            logs = res.json()['logs']
            df = pd.DataFrame(logs, columns=["ID", "Module", "Payload Snippet", "Detection", "Risk", "Timestamp"])
            st.dataframe(df, use_container_width=True)
            st.download_button("Export Forensic Data (CSV)", df.to_csv(index=False), "threat_audit.csv")
        except:
            st.error("Database connection failed. Ensure the Flask API is running.")

# --- 6. MODULE: INTEGRATION SPECS ---
elif choice == "🛡️ Integration Specs":
    st.title("🛡️ Backend & Security Architecture")
    st.info("""
    ### **Secure Integration Layer**
    1. **Secure API Design:** Developed using Flask with REST architecture. 
    2. **Input Sanitization:** Regex-based filtering to prevent XSS and SQL injection.
    3. **Forensic Logging:** Implementation of a persistent SQLite database to track every scan attempt.
    4. **Path Sanitization:** Using `werkzeug.secure_filename` to prevent path traversal attacks.
    5. **Risk Engine:** Heuristic URL checker (IP detection, subdomain counting, keyword matching).
    """)
    st.subheader("System Components")
    st.json({
        "Language": "Python 3.x",
        "API_Framework": "Flask",
        "Frontend": "Streamlit",
        "Database": "SQLite3"
    })