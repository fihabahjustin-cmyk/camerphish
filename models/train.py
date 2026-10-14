"""
CamerPhish - Étape 3 : Entraînement du Modèle ML
=================================================
Entraîne un classificateur Random Forest sur le dataset d'URLs.
Évalue les performances et sauvegarde le modèle.

Concepts ML abordés :
  - Train/Test split
  - Random Forest (ensemble de décision trees)
  - Métriques : Précision, Rappel, F1-score, Matrice de confusion
  - Feature Importance : quelles features comptent le plus ?
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix,
                              accuracy_score, roc_auc_score)
from sklearn.preprocessing import StandardScaler
from data.feature_extractor import url_to_feature_vector, get_feature_names
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ──────────────────────────────────────────────
# ÉTAPE 1 : Charger le dataset
# ──────────────────────────────────────────────
def load_dataset(csv_path: str):
    console.print("\n[bold cyan]📂 Chargement du dataset...[/]")
    df = pd.read_csv(csv_path)
    console.print(f"   → {len(df)} URLs chargées")
    console.print(f"   → Légitimes  (0) : {(df['label']==0).sum()}")
    console.print(f"   → Phishing   (1) : {(df['label']==1).sum()}")
    return df

# ──────────────────────────────────────────────
# ÉTAPE 2 : Extraire les features
# ──────────────────────────────────────────────
def extract_features_from_df(df: pd.DataFrame):
    console.print("\n[bold cyan]⚙️  Extraction des features (22 features/URL)...[/]")
    feature_matrix = []
    errors = 0
    for i, url in enumerate(df["url"]):
        try:
            vec = url_to_feature_vector(str(url))
            feature_matrix.append(vec)
        except Exception:
            feature_matrix.append([0] * len(get_feature_names()))
            errors += 1
        if (i + 1) % 100 == 0:
            console.print(f"   [{i+1}/{len(df)}] traités...", end="\r")

    X = pd.DataFrame(feature_matrix, columns=get_feature_names())
    y = df["label"].values
    console.print(f"\n   → Matrice X : {X.shape[0]} lignes × {X.shape[1]} colonnes")
    console.print(f"   → Erreurs ignorées : {errors}")
    return X, y

# ──────────────────────────────────────────────
# ÉTAPE 3 : Entraîner le modèle
# ──────────────────────────────────────────────
def train_model(X, y):
    console.print("\n[bold cyan]🤖 Entraînement du modèle Random Forest...[/]")

    # Split : 80% entraînement, 20% test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    console.print(f"   → Train : {len(X_train)} échantillons")
    console.print(f"   → Test  : {len(X_test)} échantillons")

    # Random Forest : 200 arbres de décision
    # n_estimators=200 → 200 arbres (plus stable qu'avec 100)
    # max_depth=None   → arbres complets (pas de limite de profondeur)
    # class_weight='balanced' → gère les déséquilibres de classes
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        max_features="sqrt",
        class_weight="balanced",
        n_jobs=-1,
        random_state=42
    )
    model.fit(X_train, y_train)
    console.print("   → Modèle entraîné ✅")

    # ── ÉVALUATION ──
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    accuracy  = accuracy_score(y_test, y_pred)
    roc_auc   = roc_auc_score(y_test, y_proba)
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="f1")

    console.print(f"\n[bold green]📊 RÉSULTATS DU MODÈLE[/]")
    console.print(f"   Précision globale  : [bold]{accuracy*100:.2f}%[/]")
    console.print(f"   ROC-AUC Score      : [bold]{roc_auc:.4f}[/]")
    console.print(f"   F1 Cross-val (5-fold) : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Rapport détaillé
    print("\n" + "─"*50)
    print(classification_report(
        y_test, y_pred,
        target_names=["Légitime", "Phishing"]
    ))

    # Matrice de confusion
    cm = confusion_matrix(y_test, y_pred)
    table = Table(title="Matrice de Confusion", box=box.ROUNDED, border_style="cyan")
    table.add_column("", style="bold")
    table.add_column("Prédit: Légitime", justify="center")
    table.add_column("Prédit: Phishing", justify="center")
    table.add_row("Réel: Légitime",
                  f"[green]{cm[0][0]}[/] (Vrais Négatifs)",
                  f"[red]{cm[0][1]}[/] (Faux Positifs)")
    table.add_row("Réel: Phishing",
                  f"[red]{cm[1][0]}[/] (Faux Négatifs)",
                  f"[green]{cm[1][1]}[/] (Vrais Positifs)")
    console.print(table)

    return model, X_test, y_test, y_pred

# ──────────────────────────────────────────────
# ÉTAPE 4 : Feature Importance
# ──────────────────────────────────────────────
def show_feature_importance(model, feature_names):
    console.print("\n[bold cyan]🔍 Importance des Features (Top 10)[/]")
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    table = Table(box=box.SIMPLE, border_style="dim")
    table.add_column("Rang", justify="center", style="bold cyan")
    table.add_column("Feature", style="white")
    table.add_column("Importance", justify="right")
    table.add_column("Barre", style="green")

    for rank, idx in enumerate(indices[:10], 1):
        imp = importances[idx]
        bar = "█" * int(imp * 100)
        table.add_row(str(rank), feature_names[idx], f"{imp:.4f}", bar)
    console.print(table)

# ──────────────────────────────────────────────
# ÉTAPE 5 : Sauvegarder le modèle
# ──────────────────────────────────────────────
def save_model(model, output_dir="models"):
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, "camerphish_model.pkl")
    joblib.dump(model, model_path)
    console.print(f"\n[bold green]💾 Modèle sauvegardé : {model_path}[/]")
    return model_path


def run_pipeline():
    """Lance tout le pipeline d'entraînement."""
    console.print("\n[bold]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
    console.print("[bold cyan]   CamerPhish — Pipeline d'Entraînement ML[/]")
    console.print("[bold]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")

    df            = load_dataset("data/urls_dataset.csv")
    X, y          = extract_features_from_df(df)
    model, *_     = train_model(X, y)
    show_feature_importance(model, get_feature_names())
    save_model(model)

    console.print("\n[bold green]✅ Pipeline terminé avec succès ![/]")
    console.print("[dim]   → Lance maintenant : python api/app.py[/]\n")
    return model


if __name__ == "__main__":
    run_pipeline()
