# 🛡️ CamerPhish Detector

> Détecteur de sites de phishing spécialisé pour le Cameroun  
> Projet Cybersécurité | Machine Learning | Flask API | 🇨🇲

---

## 📋 Description

CamerPhish est un outil de détection de phishing entraîné spécifiquement sur les arnaques ciblant le Cameroun : faux sites Mobile Money (MTN MoMo, Orange Money), faux sites bancaires (Afriland, BICEC), et fausses bourses d'études.

Il analyse une URL en extrayant **22 caractéristiques** et utilise un **Random Forest** pour prédire si l'URL est un phishing avec un score de 0 à 100.

---

## 🚀 Installation rapide

```bash
# 1. Cloner / créer le dossier
cd camerphish

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Construire le dataset
python data/build_dataset.py

# 4. Entraîner le modèle ML
python models/train.py

# 5. Lancer l'API + interface web
python api/app.py

# 6. Ouvrir dans le navigateur
# → http://localhost:5000
```

---

## 📁 Structure du projet

```
camerphish/
├── data/
│   ├── build_dataset.py      # Construction du dataset d'URLs
│   ├── feature_extractor.py  # Extraction des 22 features
│   └── urls_dataset.csv      # Dataset généré (430+ URLs)
│
├── models/
│   ├── train.py              # Pipeline d'entraînement ML
│   └── camerphish_model.pkl  # Modèle sauvegardé (après entraînement)
│
├── api/
│   └── app.py                # API Flask REST
│
├── frontend/
│   └── templates/
│       └── index.html        # Interface web complète
│
├── tests/
│   └── test_camerphish.py    # Tests automatisés
│
├── requirements.txt
└── README.md
```

---

## 🔍 Les 22 Features extraites

| # | Feature | Description |
|---|---------|-------------|
| 1 | `url_length` | Longueur totale de l'URL |
| 2 | `domain_length` | Longueur du domaine complet |
| 3 | `is_http` | 1 si HTTP (pas HTTPS) |
| 4 | `count_dots` | Nombre de points dans l'URL |
| 5 | `count_hyphens` | Nombre de tirets (typosquatting) |
| 6 | `count_subdomains` | Nombre de sous-domaines |
| 7 | `has_ip_address` | 1 si IP directe (ex: 41.204.63.12) |
| 8 | `has_at_symbol` | 1 si @ présent dans l'URL |
| 9 | `has_double_slash` | 1 si // dans le chemin |
| 10 | `suspicious_tld` | 1 si TLD gratuit (.tk, .ml, .ga...) |
| 11 | `free_hosting` | 1 si hébergeur gratuit (000webhostapp...) |
| 12 | `sensitive_keywords` | Nombre de mots-clés sensibles |
| 13 | `brand_in_url` | Marques camerounaises présentes |
| 14 | `path_length` | Longueur du chemin |
| 15 | `count_query_params` | Nombre de paramètres GET |
| 16 | `has_encoding` | 1 si encodage % présent |
| 17 | `domain_entropy` | Entropie de Shannon du domaine |
| 18 | `digits_in_domain` | Chiffres dans le domaine |
| 19 | `subdomain_length` | Longueur du sous-domaine |
| 20 | `non_standard_port` | 1 si port non-standard |
| 21 | `brand_repetition` | 1 si marque répétée |
| 22 | `is_cm_tld` | 1 si domaine .cm officiel |

---

## 🌐 API REST

### Analyser une URL
```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://mtn-cm-secure.000webhostapp.com/login"}'
```

**Réponse :**
```json
{
  "url": "http://mtn-cm-secure.000webhostapp.com/login",
  "score": 87,
  "label": "phishing",
  "risk_level": "critical",
  "phishing_probability": 0.8743,
  "reasons": [
    {"icon": "🔓", "severity": "warning", "text": "HTTP non sécurisé", ...},
    {"icon": "☁️", "severity": "danger", "text": "Hébergeur gratuit suspect", ...}
  ],
  "recommendations": ["❌ N'entrez JAMAIS vos identifiants..."]
}
```

### Analyser plusieurs URLs (batch)
```bash
curl -X POST http://localhost:5000/api/batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://www.mtn.cm", "http://mtn-fake.tk/login"]}'
```

---

## 🧪 Lancer les tests

```bash
python tests/test_camerphish.py
```

---

## 📊 Performances du modèle

| Métrique | Valeur |
|----------|--------|
| Précision | 100% (sur dataset synthétique) |
| ROC-AUC | 1.0000 |
| F1-score (cross-val 5-fold) | 1.000 |
| Algorithme | Random Forest (200 arbres) |
| Features | 22 |

> ⚠️ Les performances réelles sur des URLs inconnues seront inférieures.  
> Pour améliorer : ajouter des données réelles de Phishtank et OpenPhish.

---

## 📈 Améliorations possibles (pour le CV)

- [ ] Intégrer l'API Phishtank pour des données réelles
- [ ] Ajouter la vérification WHOIS (ancienneté du domaine)
- [ ] Créer une extension Chrome
- [ ] Déployer sur PythonAnywhere (gratuit)
- [ ] Ajouter un endpoint de signalement à l'ANTIC
- [ ] Dashboard d'analytics des URLs analysées

---

## 👤 Auteur

Projet réalisé dans le cadre du portfolio cybersécurité pour les entreprises camerounaises.

- **Technos** : Python, Flask, scikit-learn, Jinja2
- **Contexte** : Lutte contre le phishing et les arnaques Mobile Money au Cameroun
- **Rapport à l'ANTIC** : [www.antic.cm](https://www.antic.cm)
