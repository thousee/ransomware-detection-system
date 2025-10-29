import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import numpy as np
import joblib
import os
from pathlib import Path

# Assuming Config class is available in src/config.py
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.config import Config
from src.ransomware_detector import FeatureExtractor # To get feature names

def evaluate_model():
    print("📊 Model Evaluation Script")
    print("=" * 50)

    # Load configuration
    model_config = Config.get_model_config()['random_forest']
    training_data_path = Config.TRAINING_DATASET_PATH

    # Load dataset
    print(f"Loading training data from: {training_data_path}")
    try:
        df = pd.read_csv(training_data_path)
    except FileNotFoundError:
        print(f"❌ Error: Training data file not found at {training_data_path}")
        print("Please ensure `src/test_data/training_dataset.csv` exists, or run `python src/test_data_generator.py` to generate it.")
        return

    # Define features and labels
    feature_extractor = FeatureExtractor()
    X = df[feature_extractor.feature_names].values
    y = df['label'].values

    print(f"Dataset loaded with {len(X)} samples and {len(feature_extractor.feature_names)} features.")
    print(f"Ransomware samples (label=1): {np.sum(y == 1)}")
    print(f"Benign samples (label=0): {np.sum(y == 0)}")

    # Split data into training and testing sets
    print("Splitting data into training and testing sets (80/20 split)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=Config.get_model_config()['random_forest']['random_state'], stratify=y)
    print(f"Training set size: {len(X_train)} samples")
    print(f"Testing set size: {len(X_test)} samples")

    # Scale features
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Initialize and train the Random Forest Classifier
    print("Initializing and training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=model_config['n_estimators'],
        max_depth=model_config['max_depth'],
        min_samples_split=model_config['min_samples_split'],
        min_samples_leaf=model_config['min_samples_leaf'],
        random_state=model_config['random_state'],
        n_jobs=model_config['n_jobs']
    )
    model.fit(X_train_scaled, y_train)
    print("✅ Model training completed.")

    # Make predictions
    print("Making predictions on the test set...")
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1] # Probability of ransomware

    # Compute performance metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    false_positive_rate = fp / (fp + tn) if (fp + tn) != 0 else 0

    # Display results
    print("\n" + "=" * 50)
    print("✨ Model Performance Metrics ✨")
    print("=" * 50)

    metrics_table = pd.DataFrame({
        'Metric': ['Accuracy', 'Precision', 'Recall', 'F1-score', 'False Positive Rate'],
        'Value': [f'{accuracy:.4f}', f'{precision:.4f}', f'{recall:.4f}', f'{f1:.4f}', f'{false_positive_rate:.4f}']
    })
    print(metrics_table.to_string(index=False))

    print("\n" + "=" * 50)
    print("📊 Classification Report")
    print("=" * 50)
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Ransomware']))

    print("\n" + "=" * 50)
    print("📉 Confusion Matrix")
    print("=" * 50)
    cm = confusion_matrix(y_test, y_pred)
    cm_df = pd.DataFrame(cm, index=['Actual Benign', 'Actual Ransomware'], columns=['Predicted Benign', 'Predicted Ransomware'])
    print(cm_df.to_string())
    print(f"\nTrue Negatives (TN): {tn}")
    print(f"False Positives (FP): {fp}")
    print(f"False Negatives (FN): {fn}")
    print(f"True Positives (TP): {tp}")

    print("\n" + "=" * 50)
    print("Saving trained model and scaler...")
    Config.MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(model, Config.DEFAULT_MODEL_PATH)
    joblib.dump(scaler, Config.FEATURE_SCALER_PATH)
    print(f"✅ Model saved to: {Config.DEFAULT_MODEL_PATH}")
    print(f"✅ Scaler saved to: {Config.FEATURE_SCALER_PATH}")

    print("\n✅ Model evaluation completed successfully.")

if __name__ == "__main__":
    evaluate_model()
