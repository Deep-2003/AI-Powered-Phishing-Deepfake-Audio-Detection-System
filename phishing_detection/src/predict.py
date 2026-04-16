import pickle
from preprocess import clean_text

# Load model
model = pickle.load(open("../models/phishing_model.pkl", "rb"))
vectorizer = pickle.load(open("../models/vectorizer.pkl", "rb"))

def predict_email(text):
    cleaned = clean_text(text)
    vector = vectorizer.transform([cleaned])
    prediction = model.predict(vector)[0]

    if prediction == 1:
        return "⚠️ Phishing Email Detected"
    else:
        return "✅ Legitimate Email"


# Test
if __name__ == "__main__":
    sample = "Your bank account has been suspended. Click here to verify immediately."
    print(predict_email(sample))