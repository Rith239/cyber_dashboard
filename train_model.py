"""
train_model.py

One-time (re-runnable) script that:
1. Loads the real labeled URL dataset from data/phishing_data.csv
2. Extracts numeric features from every URL using app/ml/feature_extraction.py
3. Splits the data into training and test sets
4. Trains a Random Forest classifier
5. Evaluates it honestly on the held-out test set
6. Saves the trained model to app/ml/phishing_model.pkl

Run this whenever you want to retrain (e.g. after changing features).
"""

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from app.ml.feature_extraction import extract_features, FEATURE_NAMES

DATA_PATH = 'data/phishing_data.csv'
MODEL_OUTPUT_PATH = 'app/ml/phishing_model.pkl'

# For speed on a laptop, we sample a subset of the full 549K rows.
# Increase this if you want to train on more data (will take longer).
SAMPLE_SIZE = 20000


def load_and_prepare_data():
    print(f"Loading dataset from {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH)

    # Normalize label values: 'bad' -> 1 (phishing), 'good' -> 0 (legitimate)
    df['label'] = df['Label'].str.strip().str.lower().map({'bad': 1, 'good': 0})
    df = df.dropna(subset=['label', 'URL'])

    print(f"Full dataset size: {len(df)} rows")
    print("Class balance in full dataset:")
    print(df['label'].value_counts())

    # Take a random sample for faster training.
    # random_state=42 makes this reproducible -- same sample every run.
    if len(df) > SAMPLE_SIZE:
        df = df.sample(n=SAMPLE_SIZE, random_state=42)

    print(f"\nUsing {len(df)} rows for training/testing.")
    return df


def main():
    df = load_and_prepare_data()

    print("\nExtracting features from URLs (this may take a minute)...")
    feature_rows = [extract_features(url) for url in df['URL']]
    X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    y = df['label']

    # Hold back 20% of the data purely for honest evaluation --
    # the model never sees this during training.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"Training set: {len(X_train)} rows | Test set: {len(X_test)} rows")

    print("\nTraining Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1,  # use all available CPU cores
        class_weight='balanced'  # compensate for more legitimate than phishing examples
    )
    model.fit(X_train, y_train)

    print("\nEvaluating on held-out test set (data the model never saw)...")
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['legitimate', 'phishing']))
    print("Confusion Matrix (rows=actual, cols=predicted):")
    print(confusion_matrix(y_test, y_pred))

    # Feature importance -- which features the model relied on most
    print("\nFeature Importance:")
    importances = sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    for name, importance in importances:
        print(f"  {name}: {importance:.4f}")

    joblib.dump(model, MODEL_OUTPUT_PATH)
    print(f"\nModel saved to {MODEL_OUTPUT_PATH}")


if __name__ == '__main__':
    main()