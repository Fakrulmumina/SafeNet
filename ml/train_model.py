"""
train_model.py
Full pipeline: load URLs -> extract features -> train Random Forest -> evaluate.
"""
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.tree import export_text

from feature_engineering import build_feature_dataframe

# ---------- Step 1: Load data ----------
df = pd.read_csv('real_dataset_enriched.csv')
print(f"Loaded {len(df)} URLs  |  phishing={sum(df.label==1)}  legitimate={sum(df.label==0)}")

# ---------- Step 2: Feature engineering ----------
X = build_feature_dataframe(df['url'])
y = df['label']
print(f"\nExtracted {X.shape[1]} features per URL:")
print(list(X.columns))

# ---------- Step 3: Train/test split ----------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)
print(f"\nTrain size: {len(X_train)}  |  Test size: {len(X_test)}")

# ---------- Step 4: Train Random Forest ----------
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=6,
    random_state=42,
    class_weight='balanced'
)
model.fit(X_train, y_train)

# ---------- Step 5: Evaluate ----------
y_pred = model.predict(X_test)

print("\n" + "=" * 50)
print("EVALUATION METRICS")
print("=" * 50)
print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1 Score : {f1_score(y_test, y_pred):.3f}")

cm = confusion_matrix(y_test, y_pred)
print(f"\nConfusion Matrix:")
print(f"                 Predicted Safe   Predicted Phishing")
print(f"Actual Safe          {cm[0][0]:>5}              {cm[0][1]:>5}")
print(f"Actual Phishing      {cm[1][0]:>5}              {cm[1][1]:>5}")

print("\n" + classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

# ---------- Step 6: Feature importance ----------
importances = pd.Series(model.feature_importances_, index=X.columns).sort_values(ascending=False)
print("=" * 50)
print("FEATURE IMPORTANCE (which signals matter most)")
print("=" * 50)
print(importances.to_string())

# ---------- Step 7: Preview decision rules of ONE tree (for later JS hand-porting) ----------
print("\n" + "=" * 50)
print("SAMPLE DECISION TREE (tree #0 of the forest) — first 20 lines")
print("=" * 50)
tree_text = export_text(model.estimators_[0], feature_names=list(X.columns))
print('\n'.join(tree_text.split('\n')[:20]))

# ---------- Step 8: Save the trained model ----------
import joblib
joblib.dump(model, 'safenet_model.joblib')
print("\nModel saved to safenet_model.joblib")
