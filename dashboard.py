import streamlit as st
import requests

# Page Config
st.set_page_config(page_title="AI Cyber Shield", page_icon="🛡️", layout="wide")

st.title("🛡️ AI-Powered Phishing & Deepfake Detection")
st.markdown("---")

# Sidebar for Navigation
menu = ["Home", "Scan Phishing", "Analyze Audio", "Security Audit Logs"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome, Security Auditor")
    st.write("This system uses Machine Learning to detect modern cyber threats.")
    st.info("👈 Use the sidebar to select a detection module.")

elif choice == "Scan Phishing":
    st.subheader("📧 Phishing Email & URL Detection")
    user_input = st.text_area("Paste the Email text or suspicious URL below:", height=150)
    
    if st.button("Run Security Scan"):
        if user_input:
            with st.spinner("Analyzing with AI Model..."):
                try:
                    # Calling your Flask API
                    response = requests.post("http://127.0.0.1:5000/predict-phishing", json={"text": user_input})
                    res_data = response.json()
                    
                    if res_data['result'] == "Phishing" or res_data['result'] == "Phishing/Suspicious":
                        st.error(f"🚨 ALERT: {res_data['result']}")
                        st.warning(f"Risk Level: {res_data['risk_level']}")
                    else:
                        st.success(f"✅ Result: {res_data['result']}")
                        st.write("This content appears to be safe.")
                except Exception as e:
                    st.error(f"Error connecting to Backend: {e}")
        else:
            st.warning("Please enter some text first.")

elif choice == "Analyze Audio":
    st.subheader("🎙️ AI Deepfake Audio Detection")
    audio_file = st.file_uploader("Upload an audio file (WAV/MP3)", type=["wav", "mp3"])
    
    if st.button("Verify Audio Authenticity"):
        if audio_file:
            with st.spinner("Analyzing Audio Frequency..."):
                try:
                    files = {"file": audio_file}
                    response = requests.post("http://127.0.0.1:5000/predict-audio", files=files)
                    res_data = response.json()
                    
                    st.write(f"**Prediction:** {res_data['prediction']}")
                    st.write(f"**Risk Score:** {res_data['risk_score']}")
                except Exception as e:
                    st.error(f"Error connecting to Backend: {e}")
        else:
            st.warning("Please upload an audio file.")

elif choice == "Security Audit Logs":
    st.subheader("📝 Threat Monitoring Logs")
    st.write("This log shows the most recent threat scans recorded in the database.")
    
    if st.button("Refresh Logs"):
        try:
            # You need to add the /audit-logs route to your app.py first!
            response = requests.get("http://127.0.0.1:5000/audit-logs")
            logs = response.json()['logs']
            st.table(logs)
        except:
            st.info("Ensure the backend 'audit-logs' route is implemented.")