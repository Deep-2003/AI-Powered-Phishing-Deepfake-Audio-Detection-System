import os

# Update this path to where your model is
model_path = r"phishing_detection/models/phishing_model.pkl"

if os.path.exists(model_path):
    with open(model_path, 'rb') as f:
        first_bytes = f.read(20)
        print(f"DEBUG: First 20 bytes of the file: {first_bytes}")
else:
    print("File not found at that path!")