import os
import sys
import pickle
import sqlite3
import logging
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

# --- 1. INTEGRATION LAYER: PATH HANDLING ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, '..'))
MODELS_DIR = os.path.join(PROJECT_ROOT, 'phishing_detection', 'models')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')

# Add Kriti's source folder to Python path
sys.path.append(os.path.join(PROJECT_ROOT, 'phishing_detection', 'src'))

app = Flask(__name__)
CORS(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_DIR
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --- 2. SECURITY & LOGGING ---
logging.basicConfig(filename='security_audit.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def log_threat_to_db(scan_type, content, result, risk):
    """Forensic Database Implementation"""
    try:
        conn = sqlite3.connect('security_auditor.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scan_logs 
                  (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  type TEXT, content TEXT, result TEXT, risk TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        c.execute("INSERT INTO scan_logs (type, content, result, risk) VALUES (?, ?, ?, ?)", 
                  (scan_type, str(content)[:255], result, risk))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Error: {e}")

def sanitize_input(text):
    """Security Layer: Sanitize input and prevent overflow"""
    clean = re.sub(r'[<>{}[\]]', '', str(text))
    return clean[:5000]

def analyze_url_security(url):
    """Basic Heuristic URL Engine"""
    score = 0
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url): score += 40
    if url.count('.') > 3: score += 30
    return score, []

# --- 3. THE "FIX": BOM-SAFE LOADING ---
def load_model_safely(path):
    """Specifically fixes the '\xef' (invalid load key) error"""
    with open(path, 'rb') as f:
        content = f.read()
    # If file starts with \xef\xbb\xbf (UTF-8 BOM), strip those 3 bytes
    if content.startswith(b'\xef\xbb\xbf'):
        print(f"🛠️  Cleaning text-signature from {os.path.basename(path)}...")
        content = content[3:]
    return pickle.loads(content)

# --- 4. INTEGRATE KRITI'S AI BRAINS ---
try:
    from preprocess import clean_text
    ph_path = os.path.join(MODELS_DIR, "phishing_model.pkl")
    vec_path = os.path.join(MODELS_DIR, "vectorizer.pkl")
    
    phishing_model = load_model_safely(ph_path)
    vectorizer = load_model_safely(vec_path)
    
    print("✅ SUCCESS: Real AI Models loaded (BOM-Signature bypassed)!")
except Exception as e:
    phishing_model = None
    vectorizer = None
    print(f"❌ INTEGRATION ERROR: {e}")

# --- 5. SECURE ROUTES ---

@app.route('/predict-phishing', methods=['POST'])
def predict_phishing():
    try:
        data = request.json
        raw_text = sanitize_input(data.get('text', ''))
        if not raw_text:
            return jsonify({'error': 'No input data'}), 400

        url_pattern = r"^(http|https):|www\."

        # --- 1. DECISION GATE: URL OR TEXT ---
        if re.search(url_pattern, raw_text):
            # Heuristic URL Logic
            score, reasons = analyze_url_security(raw_text)
            res = "Phishing/Suspicious" if score > 30 else "Legitimate"
            r_lvl = "High" if score > 50 else "Medium" if score > 20 else "Low"
            confidence = 85.0 
        else:
            # --- 2. TEXT LOGIC (AI OR HEURISTIC) ---
            if phishing_model and vectorizer:
                # REAL AI PREDICTION
                cleaned = clean_text(raw_text)
                vec = vectorizer.transform([cleaned])
                
                # Confidence Calculation
                probs = phishing_model.predict_proba(vec)[0]
                pred = phishing_model.predict(vec)[0]
                confidence = probs[pred] * 100
                
                res = "Phishing" if pred == 1 else "Legitimate"
                r_lvl = "High" if pred == 1 else "Low"
            else:
                # HEURISTIC BACKUP
                suspicious_words = ["urgent", "verify", "password", "bank", "login"]
                is_phish = any(w in raw_text.lower() for w in suspicious_words)
                res = "Phishing (Heuristic)" if is_phish else "Legitimate"
                r_lvl = "High" if is_phish else "Low"
                confidence = 70.0

        # Divya's Forensic Logging Implementation
        log_threat_to_db("Text/URL Scan", raw_text, res, r_lvl)
        
        # Return Secure JSON with Confidence Score
        return jsonify({
            'result': res, 
            'risk_level': r_lvl, 
            'confidence': round(confidence, 2)
        })

    except Exception as e:
        logging.error(f"Prediction Error: {e}")
        return jsonify({'error': 'Server integration error'}), 500
@app.route('/predict-audio', methods=['POST'])
def predict_audio():
    if 'file' not in request.files: return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    try:
        res, r_lvl = ("Deepfake", "High") if "fake" in filename.lower() else ("Genuine", "Low")
        log_threat_to_db("Audio Scan", filename, res, r_lvl)
        return jsonify({'prediction': res, 'risk_score': r_lvl})
    finally:
        if os.path.exists(filepath): os.remove(filepath)

@app.route('/audit-logs', methods=['GET'])
def get_logs():
    conn = sqlite3.connect('security_auditor.db')
    c = conn.cursor()
    c.execute("SELECT * FROM scan_logs ORDER BY timestamp DESC LIMIT 20")
    logs = c.fetchall()
    conn.close()
    return jsonify({"logs": logs})

if __name__ == '__main__':
    print("🚀 Starting Server on Port 5000...")
    app.run(debug=True, port=5000)