import pandas as pd
import re
import nltk
from nltk.corpus import stopwords

# download stopwords once
nltk.download('stopwords')

stop_words = set(stopwords.words('english'))

def clean_text(text):

    # convert to lowercase
    text = text.lower()

    # remove URLs
    text = re.sub(r'http\S+', '', text)

    # remove numbers
    text = re.sub(r'\d+', '', text)

    # remove special characters
    text = re.sub(r'[^a-zA-Z\s]', '', text)

    # remove extra spaces
    text = re.sub(r'\s+', ' ', text).strip()

    # remove stopwords
    words = text.split()
    words = [word for word in words if word not in stop_words]

    return " ".join(words)

if __name__ == "__main__":

    df = pd.read_csv("E:\code\projects\AI-Powered-Phishing-Deepfake-Audio-Detection-System\phishing_detection\dataset\phishing_email.csv")

    print("Before Cleaning:")
    print(df['text_combined'].iloc[0])

    cleaned = clean_text(df['text_combined'].iloc[0])

    print("\nAfter Cleaning:")
    print(cleaned)