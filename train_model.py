"""
Model Training Script
======================
Train the RandomForest phishing detection model from the sample dataset.

Usage:
    python train_model.py

This will:
  1. Load models/sample_dataset.csv
  2. Extract features from each URL
  3. Train a RandomForestClassifier
  4. Save the model to models/phishing_model.pkl
  5. Print accuracy and F1 metrics
"""

import os
import sys

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.ml_engine import train_model


def main():
    dataset_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "models",
        "sample_dataset.csv",
    )

    if not os.path.isfile(dataset_path):
        print(f"ERROR: Dataset not found at {dataset_path}")
        sys.exit(1)

    print("=" * 60)
    print("  Phishing Detection Model Training")
    print("=" * 60)
    print(f"\n  Dataset : {dataset_path}")
    print("  Training...")

    try:
        metrics = train_model(dataset_path)
        print(f"\n  ✅  Model trained successfully!")
        print(f"  Accuracy   : {metrics['accuracy']:.4f}")
        print(f"  F1 Score   : {metrics['f1_score']:.4f}")
        print(f"  Train size : {metrics['train_size']}")
        print(f"  Test size  : {metrics['test_size']}")
        print(f"  Model saved: {metrics['model_path']}")
    except Exception as e:
        print(f"\n  ❌  Training failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
