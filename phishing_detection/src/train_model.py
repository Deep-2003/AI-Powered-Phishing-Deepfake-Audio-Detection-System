import pandas as pd
import pickle

from preprocess import clean_text

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report


# Load dataset
# This tells Python to look in the 'dataset' folder inside the project
df = pd.read_csv("../dataset/phishing_email.csv")

# Clean text
df['cleaned_text'] = df['text_combined'].apply(clean_text)

# Features and labels
X = df['cleaned_text']
y = df['label']

# Convert text → numbers (TF-IDF)
vectorizer = TfidfVectorizer(max_features=5000)
X_vectorized = vectorizer.fit_transform(X)

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized, y, test_size=0.2, random_state=42
)

# Train model (Naive Bayes)
model = MultinomialNB()
model.fit(X_train, y_train)

# Predictions
y_pred = model.predict(X_test)

# Evaluation
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Save model
pickle.dump(model, open("../models/phishing_model.pkl", "wb"))
pickle.dump(vectorizer, open("../models/vectorizer.pkl", "wb"))

print("\nModel and vectorizer saved successfully!")