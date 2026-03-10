import pandas as pd

# Load dataset
df = pd.read_csv("../dataset/phishing_email.csv")

# Display first rows
print("First 5 rows:")
print(df.head())

# Show dataset info
print("\nDataset shape:")
print(df.shape)

# Show column names
print("\nColumns:")
print(df.columns)

# Check label distribution
print("\nLabel distribution:")
print(df['label'].value_counts())