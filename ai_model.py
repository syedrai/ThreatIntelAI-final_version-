#!/usr/bin/env python3
"""
Train and predict risk levels using RandomForestClassifier.
Training CSV must contain a 'label' column (Low/Medium/High).
"""
import os
import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

MODEL_PATH = os.getenv('MODEL_PATH', 'models/risk_predictor.pkl')

def _prepare_features(df: pd.DataFrame):
    df = df.copy()
    df['reputation_score'] = pd.to_numeric(df.get('reputation_score'), errors='coerce').fillna(0)
    df['malicious_votes'] = pd.to_numeric(df.get('malicious_votes'), errors='coerce').fillna(0)
    df['asn'] = df.get('asn', '').astype(str).str.extract(r'(\d+)', expand=False).fillna('0').astype(int)
    X = df[['reputation_score', 'malicious_votes', 'asn']]
    return X

def train(training_csv='data/training_iocs.csv', model_out=MODEL_PATH):
    df = pd.read_csv(training_csv)
    if 'label' not in df.columns:
        raise ValueError("training CSV must include a 'label' column")
    X = _prepare_features(df)
    le = LabelEncoder()
    y = le.fit_transform(df['label'].astype(str))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=200, random_state=42)
    clf.fit(X_train, y_train)
    score = clf.score(X_test, y_test)
    Path(model_out).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({'model': clf, 'label_encoder': le}, model_out)
    print(f"Model saved to {model_out} (test_score={score:.3f})")

def predict(input_csv, model_path=MODEL_PATH, out_csv='data/predicted_iocs.csv'):
    df = pd.read_csv(input_csv)
    artefact = joblib.load(model_path)
    clf = artefact['model']
    le = artefact['label_encoder']
    X = _prepare_features(df)
    preds = clf.predict(X)
    labels = le.inverse_transform(preds)
    df_out = df.copy()
    df_out['risk'] = labels
    Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    df_out.to_csv(out_csv, index=False)
    print(f"Wrote predictions -> {out_csv}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='cmd')
    t = sub.add_parser('train')
    t.add_argument('--data', default='data/training_iocs.csv')
    t.add_argument('--out', default=MODEL_PATH)
    p = sub.add_parser('predict')
    p.add_argument('file')
    p.add_argument('--model', default=MODEL_PATH)
    p.add_argument('--out', default='data/predicted_iocs.csv')
    args = parser.parse_args()
    if args.cmd == 'train':
        train(args.data, args.out)
    elif args.cmd == 'predict':
        predict(args.file, args.model, args.out)
    else:
        parser.print_help()
