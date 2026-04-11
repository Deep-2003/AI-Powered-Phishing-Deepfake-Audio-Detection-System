from flask_cors import CORS
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import pickle
import sys
import os
import logging
import sqlite3
import re

# --- 1. CONFIGURATION & MODEL LOADING ---
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..'))
MODELS_PATH = os.path.join(project_root, 'phishing_detection', 'models')

# Load Kriti's Models
try:
    phishing_model = pickle.load(open(os.path.join(MODELS_PATH, "phishing_model.pkl"), "rb"))
    vectorizer = pickle.load(open(os.path.join(MODELS_PATH, "vectorizer.pkl"), "rb"))
    print("✅ Kriti's ML Model & Vectorizer loaded successfully!")
except Exception as e:
    phishing_model = None
    vectorizer = None
    print(f"❌ Error loading models: {e}")

# Setup Path for Preprocessing
sys.path.append(os.path.join(project_root, 'phishing_detection', 'src'))
try:
    from preprocess import clean_text as preprocess_text
    print("✅ Successfully connected to Kriti's code!")
except ImportError:
    def preprocess_text(text): return text.lower().strip()

# --- 2. INITIALIZE APP & DATABASE ---
app = Flask(__name__)
CORS(app)

def init_db():
    conn = sqlite3.connect('security_auditor.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_logs 
              (id INTEGER PRIMARY KEY AUTOINCREMENT,
              type TEXT, content TEXT, result TEXT, risk TEXT, timestamp DATETIME DEFAULT current_timestamp)''')
    conn.commit()
    conn.close()

init_db()

def log_to_db(scan_type, content, result, risk):
    try:
        conn = sqlite3.connect('security_auditor.db')
        c = conn.cursor()
        c.execute("INSERT INTO scan_logs (type, content, result, risk) VALUES (?, ?, ?, ?)", 
                  (scan_type, content[:100], result, risk))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database Log Error: {e}")

logging.basicConfig(filename='security_audit.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- 3. SECURITY HELPERS ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'wav', 'mp3', 'flac'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def analyze_url_security(url):
    score = 0
    reasons = []
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        score += 40
        reasons.append("URL contains raw IP address")
    if url.count('.') > 3:
        score += 30
        reasons.append("Excessive Subdomains detected")
    for word in ['login', 'verify', 'update', 'banking', 'secure']:
        if word in url.lower():
            score += 10
            reasons.append(f"Suspicious keyword: {word}")
    return score, reasons

# --- 4. ROUTES ---

@app.route('/')
def home():
    return "🛡️ Secure AI Backend is Online"

@app.route('/predict-phishing', methods=['POST'])
def predict_phishing():
    try:
        data = request.json
        raw_text = data.get('text', '').strip()

        if not raw_text:
            return jsonify({'error': 'No text provided'}), 400

        # Safety Check
        if len(raw_text) > 5000:
            logging.error("⛔ Threat Detected: Input too large")
            return jsonify({'error': 'Input text exceeds safety limits'}), 413

        url_pattern = r"^(http|https):|www\."
        
        # DECISION: URL or TEXT?
        if re.search(url_pattern, raw_text):
            # A. URL Analysis
            logging.info(f"URL detected: {raw_text}")
            score, reasons = analyze_url_security(raw_text)
            result = "Phishing/Suspicious" if score > 30 else "Legitimate"
            risk_level = "High" if score > 50 else "Medium" if score > 20 else "Low"
            
            log_to_db("URL Scan", raw_text, result, risk_level)
            
            return jsonify({
                'status': 'success',
                'type': 'URL Analysis',
                'result': result,
                'risk_level': risk_level,
                'details': reasons
            })
            
        else:
            # B. Text Analysis (Machine Learning)
            logging.info("General text detected. Proceeding to NLP analysis")
            cleaned_text = preprocess_text(raw_text)

            if phishing_model and vectorizer:
                vectorized_text = vectorizer.transform([cleaned_text])
                prediction = phishing_model.predict(vectorized_text)[0]
                result = "Phishing" if prediction == 1 else "Legitimate"
                risk_score = "High" if prediction == 1 else "Low"
            else:
                # Backup Logic
                is_phishing = "urgent" in cleaned_text or "verify" in cleaned_text
                result = "Phishing" if is_phishing else "Legitimate"
                risk_score = "High" if is_phishing else "Low"

            log_to_db("Text Scan", raw_text, result, risk_score)
            logging.info(f"Scan Complete. Prediction: {result}")

            return jsonify({
                'status': 'success',
                'type': 'Text Analysis',
                'result': result,
                'risk_level': risk_score,
                'cleaned_preview': cleaned_text[:50] + "..."
            }) 

    except Exception as e:
        logging.error(f"❌ Server Error: {str(e)}")
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/predict-audio', methods=['POST'])
def predict_audio():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            mock_result = "Deepfake" if "fake" in filename.lower() else "Genuine"
            risk = 'High' if mock_result == "Deepfake" else 'Low'
            
            log_to_db("Audio Scan", filename, mock_result, risk)
            os.remove(filepath)

            return jsonify({
                'status': 'success',
                'prediction': mock_result,
                'risk_score': risk
            })
        else:
            return jsonify({'error': 'Invalid file type'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/audit-logs', methods=['GET'])
def get_audit_logs():
    try:
        conn = sqlite3.connect('security_auditor.db')
        c = conn.cursor()
        c.execute("SELECT * FROM scan_logs ORDER BY timestamp DESC LIMIT 10")
        logs = c.fetchall()
        conn.close()
        return jsonify({"status": "success", "logs": logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
if __name__ == '__main__':
    print("🚀 Starting Server on Port 5000...")
    app.run(debug=True, port=5000)