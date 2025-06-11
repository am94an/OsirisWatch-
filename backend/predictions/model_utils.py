import os
import joblib
import torch
import json
import pandas as pd
from pytorch_tabnet.tab_model import TabNetClassifier

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAVE_FOLDER = os.path.join(BASE_DIR, 'saved_model')

scaler_file_path = os.path.join(SAVE_FOLDER, 'scaler.joblib')
scaler = joblib.load(scaler_file_path)

label_mapping_file_path = os.path.join(SAVE_FOLDER, 'label_mapping.json')
with open(label_mapping_file_path, 'r') as f:
    label_mapping = json.load(f)

idx_to_label = {int(v): k for k, v in label_mapping.items()}

feature_names_file_path = os.path.join(SAVE_FOLDER, 'feature_names.json')
with open(feature_names_file_path, 'r') as f:
    feature_names = json.load(f)

fit_params_file_path = os.path.join(SAVE_FOLDER, 'fit_params.pkl')
fit_params = joblib.load(fit_params_file_path)

clf_file_path = os.path.join(SAVE_FOLDER, 'tabnet_clf_0.zip')
clf = TabNetClassifier()
clf.load_model(clf_file_path)
clf.fit_params = fit_params
print("Model and fit parameters loaded successfully.")

def predict(input_data):
    input_data = input_data.reindex(columns=feature_names)

    missing_cols = set(feature_names) - set(input_data.columns)
    if missing_cols:
        raise ValueError(f"The following required columns are missing: {missing_cols}")

    X_scaled = pd.DataFrame(scaler.transform(input_data), columns=feature_names)

    predictions = clf.predict(X_scaled.values)
    predicted_labels = [idx_to_label.get(int(pred), 'Unknown') for pred in predictions]

    return predicted_labels