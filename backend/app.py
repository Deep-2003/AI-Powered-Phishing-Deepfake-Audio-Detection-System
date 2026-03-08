from flask_cors import CORS

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import sys
import os
import logging
import sqlite3
import re
app = Flask(__name__)
CORS(app)
def init_db():
    """Create a database table to store all threat scans"""
    conn=sqlite3.connect('security_auditor.db')
    c=conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_logs 
              (id INTEGER  PRIMARY KEY AUTOINCREMENT,
              type TEXT, content TEXT, result TEXT, risk TEXT, timestamp DATATIME DEFAULT current_timestamp)''' )
    conn.commit()
    conn.close()
# calling to make sure is db ready
init_db()
def log_to_db(scan_type, content, result, risk):
    """Helper function to save a record of the scan"""
    try:
        conn = sqlite3.connect('security_audit.db')
        c = conn.cursor()
        c.execute("INSERT INTO scan_logs (type, content, result, risk) VALUES (?, ?, ?, ?)", 
                  (scan_type, content[:100], result, risk)) # We save first 100 chars of content
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database Log Error: {e}")
# --- 1. CONFIGURATION (Connecting to Kriti's Code) ---
# Since app.py is in the 'backend' folder, we need to go UP one level ('..') 
# to find the 'phishing_detection' folder.
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.append(os.path.join(project_root, 'phishing_detection', 'src'))

# Try to import Kriti's preprocessing function
try:
    # 🚨 FIX: We import 'clean_text' but rename it to 'preprocess_text' so your code works!
    from preprocess import clean_text as preprocess_text
    print("✅ Successfully connected to Kriti's code!")
except ImportError as e:
    print(f"❌ Warning: Could not import preprocess. (Error: {e})")
    # Backup function so the server doesn't crash
    def preprocess_text(text): return text.lower()

# --- 2. SECURITY LOGGING (Your Role) ---
# Create a log file to track potential attacks
logging.basicConfig(filename='security_audit.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- CONFIGURATION FOR AUDIO ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'wav', 'mp3', 'flac'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def analyze_url_security(url):
    """Basic Cyber Security heck for suspicious URL patterns"""
    score=0
    reasons=[]
    # checking for id address in url (coomon phishing attacks)
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',url):
        score+=40
        reasons.append("URL contains raw IP address")
    if url.count('.')>3:
        score+=30
        reasons.append("Excessive Subdomains detected")
    for word in ['login','verify','update','banking','secure']:
      if word in url.lower():
       score +=10
       reasons.append(f"Suspicious keywords:,{word}")
    return score,reasons
# --- ROUTES ---

@app.route('/')
def home():
    return "🛡️ Secure AI Backend is Online"

@app.route('/predict-phishing', methods=['POST'])
def predict_phishing():
    try:
        # A. Secure Input Validation
        if not request.json or 'text' not in request.json:
            logging.warning("⚠️ Invalid Request: No text data found.")
            return jsonify({'error': 'No text provided'}), 400

        raw_text = request.json['text']

        # B. Safety Check (Preventing large payload attacks)
        if len(raw_text) > 5000:
            logging.error("⛔ Threat Detected: Input too large (Buffer Overflow Attempt)")
            return jsonify({'error': 'Input text exceeds safety limits'}), 413

        # C. Processing (Using the team's logic)
        cleaned_text = preprocess_text(raw_text)

        # D. Mock Prediction (Placeholder until you get the .pkl file)
        # Logic: If the email contains "urgent", we pretend it's phishing
        is_phishing = "urgent" in cleaned_text or "verify" in cleaned_text
        result = "Phishing" if is_phishing else "Legitimate"
        risk_score = "High" if is_phishing else "Low"

        # Log the result
        logging.info(f"Scan Complete. Prediction: {result}, Risk: {risk_score}")

        return jsonify({
            'status': 'success',
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
        # 1. Security Check: Is there a file?
        if 'file' not in request.files:
            logging.warning("⚠️ Audio Scan: No file part in request")
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        
        # 2. Security Check: Empty filename?
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # 3. Security Check: Is it a valid audio file? (Your Job!)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # 4. Mock Prediction (Waiting for Deepanshu's Model)
            # We just pretend for now
            mock_result = "Deepfake" if "fake" in filename else "Genuine"
            
            logging.info(f"Audio processed: {filename} -> {mock_result}")
            
            # Cleanup: Delete file after scanning to save space
            os.remove(filepath)

            return jsonify({
                'status': 'success',
                'file_name': filename,
                'prediction': mock_result,
                'risk_score': 'High' if mock_result == "Deepfake" else 'Low'
            })
        else:
            logging.warning(f"⛔ Blocked invalid file type: {file.filename}")
            return jsonify({'error': 'Invalid file type. Only WAV/MP3 allowed.'}), 400

    except Exception as e:
        logging.error(f"Audio Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting Server on Port 5000...")
    app.run(debug=True, port=5000)