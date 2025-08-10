import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import json

# Load dataset
data = pd.read_csv("datasets/phishing_urls.csv")

# Prepare features and target
X = data.drop("CLASS_LABEL", axis=1)  # All columns except the label
y = data["CLASS_LABEL"]               # Target variable

# Save feature names FIRST
with open("model/feature_names.json", "w") as f:
    json.dump(list(X.columns), f)

# Verify shapes
print("Features shape:", X.shape)
print("Target shape:", y.shape)

# Split data (80% training, 20% testing)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
train_score = model.score(X_train, y_train)
test_score = model.score(X_test, y_test)
print(f"Training Accuracy: {train_score:.2f}")
print(f"Test Accuracy: {test_score:.2f}")

# Save model
joblib.dump(model, "model/phishing_model.pkl")
print("✅ Model trained and saved!")