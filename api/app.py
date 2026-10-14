"""
CamerPhish - Étape 4 : API Flask
==================================
API REST qui reçoit une URL et retourne une analyse de phishing.

Endpoints :
  POST /api/analyze    → analyse une URL
  GET  /api/health     → vérifie que l'API tourne
  GET  /               → sert l'interface web
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import joblib
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from data.feature_extractor import (url_to_feature_vector,
                                     extract_features,
                                     get_feature_names,
                                     PHISHING_TLDS,
                                     SUSPICIOUS_HOSTS)
import re, socket
from urllib.parse import urlparse
import tldextract

_tld_extractor = tldextract.TLDExtract(suffix_list_urls=False)

app = Flask(__name__,
            template_folder="../frontend/templates",
            static_folder="../frontend/static")
CORS(app)

# ── Chargement du modèle ML ──
MODEL_PATH = "models/camerphish_model.pkl"
model = None

def load_model():
    global model
    try:
        model = joblib.load(MODEL_PATH)
        print(f"✅ Modèle chargé : {MODEL_PATH}")
    except FileNotFoundError:
        print(f"⚠️  Modèle non trouvé ({MODEL_PATH})")
        print("   → Lance d'abord : python models/train.py")

# ── Analyse d'une URL ──
def analyze_url(url: str) -> dict:
    """
    Analyse une URL et retourne :
      - score (0-100) : probabilité de phishing
      - label : "phishing" ou "légitime"
      - risk_level : critical / high / medium / low / safe
      - features : détail des 22 features
      - reasons : liste des raisons (pourquoi suspect ?)
      - recommendations : conseils pour l'utilisateur
    """
    # Validation basique
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Extraction des features (offline)
    features_dict = extract_features(url)
    feature_vector = [features_dict.get(n, 0) for n in get_feature_names()]

    # Prédiction ML
    if model is not None:
        proba = model.predict_proba([feature_vector])[0]
        phishing_proba = float(proba[1])
        score = int(phishing_proba * 100)
    else:
        # Fallback heuristique si modèle absent
        score = _heuristic_score(features_dict)
        phishing_proba = score / 100

    # Niveau de risque
    if score >= 80:
        risk_level = "critical"
        label = "phishing"
    elif score >= 60:
        risk_level = "high"
        label = "phishing"
    elif score >= 40:
        risk_level = "medium"
        label = "suspect"
    elif score >= 20:
        risk_level = "low"
        label = "suspect"
    else:
        risk_level = "safe"
        label = "légitime"

    # Génération des raisons
    reasons = _generate_reasons(url, features_dict)

    # Informations sur le domaine
    parsed     = urlparse(url)
    extracted  = _tld_extractor(url)
    domain_info = {
        "full": parsed.netloc,
        "domain": extracted.domain,
        "subdomain": extracted.subdomain,
        "tld": extracted.suffix,
        "scheme": parsed.scheme,
        "path": parsed.path,
    }

    return {
        "url": url,
        "score": score,
        "label": label,
        "risk_level": risk_level,
        "phishing_probability": round(phishing_proba, 4),
        "features": features_dict,
        "reasons": reasons,
        "domain_info": domain_info,
        "recommendations": _get_recommendations(score, features_dict),
        "is_safe": score < 40,
    }


def _heuristic_score(f: dict) -> int:
    """Score heuristique de secours si le modèle ML n'est pas disponible."""
    score = 0
    score += f.get("is_http", 0) * 15
    score += f.get("suspicious_tld", 0) * 25
    score += f.get("free_hosting", 0) * 25
    score += f.get("has_ip_address", 0) * 35
    score += f.get("has_at_symbol", 0) * 30
    score += min(f.get("count_hyphens", 0) * 4, 20)
    score += f.get("has_encoding", 0) * 15
    score += f.get("brand_repetition", 0) * 20
    score += min(f.get("sensitive_keywords", 0) * 5, 20)
    if f.get("url_length", 0) > 100:
        score += 15
    score -= f.get("is_cm_tld", 0) * 20
    return min(max(score, 0), 100)


def _generate_reasons(url: str, f: dict) -> list:
    """Génère une liste de raisons expliquant le score."""
    reasons = []

    if f.get("is_http"):
        reasons.append({
            "icon": "🔓",
            "severity": "warning",
            "text": "Connexion non sécurisée (HTTP)",
            "detail": "Le site utilise HTTP au lieu de HTTPS. Toutes vos données sont transmises en clair."
        })
    if f.get("has_ip_address"):
        reasons.append({
            "icon": "🔢",
            "severity": "danger",
            "text": "Adresse IP directe au lieu d'un nom de domaine",
            "detail": "Les services légitimes utilisent toujours un nom de domaine, jamais une IP directe."
        })
    if f.get("suspicious_tld"):
        reasons.append({
            "icon": "🌍",
            "severity": "danger",
            "text": f"Extension de domaine suspecte (.{tldextract.extract(url).suffix})",
            "detail": "Les extensions .tk, .ml, .ga, .cf sont gratuites et très utilisées pour les arnaques."
        })
    if f.get("free_hosting"):
        reasons.append({
            "icon": "☁️",
            "severity": "danger",
            "text": "Hébergement gratuit suspect",
            "detail": "Ce site est hébergé sur un service gratuit (000webhost, Netlify, Vercel...) souvent utilisé pour des arnaques temporaires."
        })
    if f.get("has_at_symbol"):
        reasons.append({
            "icon": "⚠️",
            "severity": "danger",
            "text": "Symbole @ détecté dans l'URL",
            "detail": "La technique 'URL avec @' est utilisée pour tromper : tout avant le @ est ignoré par le navigateur."
        })
    if f.get("brand_repetition"):
        reasons.append({
            "icon": "🏷️",
            "severity": "warning",
            "text": "Marque camerounaise répétée plusieurs fois",
            "detail": "La répétition d'un nom de marque (MTN, Orange, Afriland...) est caractéristique des faux sites."
        })
    if f.get("count_hyphens", 0) >= 3:
        reasons.append({
            "icon": "➖",
            "severity": "warning",
            "text": f"{f['count_hyphens']} tirets dans l'URL",
            "detail": "Un excès de tirets comme 'mtn-cm-secure-login-verify.tk' est typique des sites de phishing."
        })
    if f.get("has_encoding"):
        reasons.append({
            "icon": "🔤",
            "severity": "warning",
            "text": "Encodage URL suspect (%XX)",
            "detail": "L'encodage de caractères est utilisé pour masquer le vrai nom du domaine aux utilisateurs."
        })
    if f.get("url_length", 0) > 100:
        reasons.append({
            "icon": "📏",
            "severity": "info",
            "text": f"URL très longue ({f['url_length']} caractères)",
            "detail": "Les URLs légitimes sont généralement courtes. Une URL très longue peut indiquer une tentative de dissimulation."
        })
    if f.get("is_cm_tld"):
        reasons.append({
            "icon": "✅",
            "severity": "safe",
            "text": "Utilise le domaine camerounais (.cm)",
            "detail": "L'extension .cm est enregistrée et contrôlée par l'ANTIC Cameroun."
        })
    if not reasons:
        reasons.append({
            "icon": "✅",
            "severity": "safe",
            "text": "Aucun indicateur de phishing majeur détecté",
            "detail": "L'URL ne présente pas les caractéristiques typiques des sites de phishing."
        })
    return reasons


def _get_recommendations(score: int, f: dict) -> list:
    recs = []
    if score >= 60:
        recs.append("❌ N'entrez JAMAIS vos identifiants ou informations bancaires sur ce site.")
        recs.append("📵 Ne téléchargez aucun fichier depuis ce site.")
        recs.append("📢 Signalez ce lien à l'ANTIC Cameroun : www.antic.cm")
    if f.get("is_http"):
        recs.append("🔒 Vérifiez toujours que l'URL commence par HTTPS (cadenas vert).")
    if score >= 40:
        recs.append("🔍 Vérifiez l'URL dans Google : recherchez le nom officiel de l'entreprise.")
        recs.append("📞 Contactez l'entreprise directement via ses canaux officiels.")
    if score < 30:
        recs.append("✅ Ce lien semble sûr. Restez tout de même vigilant.")
    return recs


# ──────────────────────────────────────────────
# ENDPOINTS API
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": model is not None,
        "version": "1.0.0",
        "project": "CamerPhish Detector"
    })

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Paramètre 'url' manquant"}), 400
    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL vide"}), 400
    try:
        result = analyze_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Erreur d'analyse : {str(e)}"}), 500

@app.route("/api/batch", methods=["POST"])
def batch_analyze():
    """Analyse plusieurs URLs d'un coup."""
    data = request.get_json()
    if not data or "urls" not in data:
        return jsonify({"error": "Paramètre 'urls' manquant"}), 400
    results = []
    for url in data["urls"][:20]:  # max 20 URLs par batch
        try:
            results.append(analyze_url(url))
        except Exception as e:
            results.append({"url": url, "error": str(e)})
    return jsonify({"results": results, "count": len(results)})


if __name__ == "__main__":
    load_model()
    print("\n🌍 CamerPhish API démarrée sur http://localhost:5000")
    print("   → Interface web : http://localhost:5000")
    print("   → API health    : http://localhost:5000/api/health\n")
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
