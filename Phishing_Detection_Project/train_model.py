# train_model.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# 1. Create a small synthetic dataset (for demo/testing)
np.random.seed(42)
n = 200
df = pd.DataFrame({
    "Have_IP": np.random.choice([0,1], size=n, p=[0.8,0.2]),
    "URL_Length": np.random.randint(20, 200, size=n),
    "Have_At": np.random.choice([0,1], size=n, p=[0.9,0.1]),
    "Double_Slash": np.random.choice([0,1], size=n, p=[0.95,0.05]),
    "Prefix_Suffix": np.random.choice([0,1], size=n, p=[0.9,0.1]),
    "SSLfinal_State": np.random.randint(0,4,size=n),
    # target: 1 = phishing, 0 = legitimate
    "Result": (np.random.rand(n) < (
        0.05 + 0.35* (np.random.rand(n) < 0.2)
    )).astype(int)
})
# Slight correlation: longer URLs more likely phishing
extra_phish_idx = df['URL_Length'] > 120
df.loc[extra_phish_idx, 'Result'] = (df.loc[extra_phish_idx, 'Result'] | (np.random.rand(extra_phish_idx.sum()) < 0.35)).astype(int)

# 2. Separate features and labels
X = df.drop('Result', axis=1)
y = df['Result']

# 3. Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# 4. Train Random Forest model
model = RandomForestClassifier(n_estimators=150, random_state=42)
model.fit(X_train, y_train)

# 5. Evaluate
y_pred = model.predict(X_test)
print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# 6. Save model
joblib.dump(model, "model.pkl")
print("\nModel saved as model.pkl")
