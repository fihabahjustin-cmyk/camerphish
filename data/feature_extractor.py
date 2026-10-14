"""
CamerPhish - Étape 2 : Feature Extraction
==========================================
Extraction de 22 caractéristiques (features) à partir d'une URL.
Chaque feature capture un aspect de l'URL qui distingue
les sites légitimes des sites de phishing.

Concepts clés :
  - Une URL comme : http://secure-mtn-cm.000webhostapp.com/login?id=1
    décomposée en : scheme, subdomain, domain, TLD, path, query, params
"""

import re
import math
import tldextract
import ipaddress

# Utiliser le snapshot embarqué — pas besoin de connexion internet
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=False)
from urllib.parse import urlparse, parse_qs


# TLDs et hébergeurs typiquement utilisés pour le phishing en Afrique
PHISHING_TLDS = {".tk", ".ml", ".ga", ".cf", ".xyz", ".top",
                 ".click", ".link", ".gq", ".pw", ".work"}
SUSPICIOUS_HOSTS = {"000webhostapp", "byethost", "netlify", "vercel",
                    "blogspot", "weebly", "wix", "wordpress",
                    "github.io", "glitch.me"}
SENSITIVE_KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "password", "credential", "auth",
    "validation", "reactivate", "unlock", "suspend",
    # Mots-clés spécifiques Cameroun
    "momo", "mobilemoney", "orangemoney", "momoplay",
    "connexion", "espace-client", "verification",
}
LEGIT_BRANDS_CM = {
    "mtn", "orange", "camtel", "afriland", "bicec", "uba",
    "ecobank", "jumia", "antic", "douane", "cameroontribune"
}


def extract_features(url: str) -> dict:
    """
    Extrait 22 features d'une URL.
    Retourne un dict {feature_name: value}.
    """
    features = {}
    url = url.strip()

    # ── PARSING DE L'URL ──
    try:
        parsed = urlparse(url)
        extracted = _tld_extractor(url)
    except Exception:
        return {k: 0 for k in get_feature_names()}

    full_domain = parsed.netloc.lower()
    path        = parsed.path.lower()
    query       = parsed.query.lower()
    scheme      = parsed.scheme.lower()
    subdomain   = extracted.subdomain.lower()
    domain      = extracted.domain.lower()
    suffix      = extracted.suffix.lower()
    full_url    = url.lower()

    # ── 1. LONGUEUR DE L'URL ──────────────────────────
    # Les URLs de phishing sont souvent très longues (>75 chars)
    features["url_length"] = len(url)

    # ── 2. LONGUEUR DU DOMAINE ────────────────────────
    features["domain_length"] = len(full_domain)

    # ── 3. UTILISE HTTP (PAS HTTPS) ───────────────────
    # Les sites légitimes utilisent presque tous HTTPS aujourd'hui
    features["is_http"] = 1 if scheme == "http" else 0

    # ── 4. COMPTE DES POINTS DANS L'URL ──────────────
    # "secure.mtn.cm.account-update.tk" → beaucoup de points = suspect
    features["count_dots"] = url.count(".")

    # ── 5. COMPTE DES TIRETS ─────────────────────────
    # "secure-mtn-cm-verify" → tirets = typosquatting
    features["count_hyphens"] = url.count("-")

    # ── 6. COMPTE DES SOUS-DOMAINES ──────────────────
    features["count_subdomains"] = len(subdomain.split(".")) if subdomain else 0

    # ── 7. PRÉSENCE D'UNE IP DIRECTE ─────────────────
    # "http://41.204.63.12/login" → jamais légitime pour un service grand public
    try:
        ipaddress.ip_address(full_domain.split(":")[0])
        features["has_ip_address"] = 1
    except ValueError:
        features["has_ip_address"] = 0

    # ── 8. PRÉSENCE DU SYMBOLE @ ─────────────────────
    # "http://orange.cm@phishingsite.tk/" trompe les navigateurs naïfs
    features["has_at_symbol"] = 1 if "@" in url else 0

    # ── 9. PRÉSENCE DU SYMBOLE // DANS LE CHEMIN ─────
    # "http://site.cm//redirect?url=phish" → redirection cachée
    features["has_double_slash"] = 1 if "//" in path else 0

    # ── 10. TLD SUSPECT ──────────────────────────────
    features["suspicious_tld"] = 1 if f".{suffix}" in PHISHING_TLDS else 0

    # ── 11. HÉBERGEUR GRATUIT SUSPECT ────────────────
    features["free_hosting"] = 1 if any(h in full_domain for h in SUSPICIOUS_HOSTS) else 0

    # ── 12. MOTS-CLÉS SENSIBLES ──────────────────────
    count_keywords = sum(1 for kw in SENSITIVE_KEYWORDS if kw in full_url)
    features["sensitive_keywords"] = count_keywords

    # ── 13. MARQUE CAMEROUNAISE IMITÉE ───────────────
    # La marque dans un domaine suspect = phishing
    brands_in_url = sum(1 for b in LEGIT_BRANDS_CM if b in full_url)
    features["brand_in_url"] = brands_in_url

    # ── 14. LONGUEUR DU CHEMIN (PATH) ────────────────
    features["path_length"] = len(path)

    # ── 15. NOMBRE DE PARAMÈTRES QUERY ───────────────
    features["count_query_params"] = len(parse_qs(query))

    # ── 16. PRÉSENCE D'ENCODAGE % ────────────────────
    # "mtn%2Ecm" = encodage pour masquer le vrai domaine
    features["has_encoding"] = 1 if "%" in url else 0

    # ── 17. ENTROPIE DE SHANNON DU DOMAINE ───────────
    # Un domaine aléatoire genre "xk4p2m.tk" a une haute entropie
    features["domain_entropy"] = _shannon_entropy(domain)

    # ── 18. NOMBRE DE CHIFFRES DANS LE DOMAINE ───────
    features["digits_in_domain"] = sum(c.isdigit() for c in domain)

    # ── 19. LONGUEUR DU SOUS-DOMAINE ─────────────────
    features["subdomain_length"] = len(subdomain)

    # ── 20. PRÉSENCE D'UN PORT NON-STANDARD ──────────
    port = parsed.port
    features["non_standard_port"] = 1 if (port and port not in {80, 443}) else 0

    # ── 21. RÉPÉTITION DU DOMAINE LÉGITIME ───────────
    # "mtn-cm.compte-mtn.tk" → "mtn" apparaît 2 fois = imitation
    for brand in LEGIT_BRANDS_CM:
        count = full_url.count(brand)
        if count >= 2:
            features["brand_repetition"] = 1
            break
    else:
        features["brand_repetition"] = 0

    # ── 22. UTILISE UN CCLTD CAMEROUNAIS (.cm) ────────
    # Les vrais sites camerounais utilisent .cm ou .gov.cm
    features["is_cm_tld"] = 1 if suffix in {"cm", "gov.cm", "org.cm", "edu.cm"} else 0

    return features


def _shannon_entropy(s: str) -> float:
    """Calcule l'entropie de Shannon d'une chaîne."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def get_feature_names() -> list:
    """Retourne la liste ordonnée des 22 features."""
    return [
        "url_length", "domain_length", "is_http", "count_dots",
        "count_hyphens", "count_subdomains", "has_ip_address",
        "has_at_symbol", "has_double_slash", "suspicious_tld",
        "free_hosting", "sensitive_keywords", "brand_in_url",
        "path_length", "count_query_params", "has_encoding",
        "domain_entropy", "digits_in_domain", "subdomain_length",
        "non_standard_port", "brand_repetition", "is_cm_tld",
    ]


def url_to_feature_vector(url: str) -> list:
    """Retourne un vecteur de features dans l'ordre standard."""
    feats = extract_features(url)
    return [feats.get(name, 0) for name in get_feature_names()]


if __name__ == "__main__":
    # Test sur des exemples concrets
    test_cases = [
        ("https://www.mtn.cm/fr/", 0),
        ("http://mtn-mobilemoney-cm-secure.000webhostapp.com/login", 1),
        ("https://www.afrilandbank.com/espace-client", 0),
        ("http://41.204.63.12/afriland-login", 1),
        ("https://mobilemoney.mtn.cm/", 0),
        ("http://mtn%2Ecm%2Everify.tk/update", 1),
    ]

    print(f"{'URL':<60} {'Prédit':>8} {'Réel':>6}")
    print("─" * 76)
    for url, real_label in test_cases:
        feats = extract_features(url)
        print(f"\n{url[:57]+'...' if len(url)>57 else url}")
        score = (
            feats["is_http"] * 2 +
            feats["suspicious_tld"] * 3 +
            feats["free_hosting"] * 3 +
            feats["has_ip_address"] * 4 +
            feats["has_at_symbol"] * 3 +
            feats["count_hyphens"] * 0.3 +
            feats["domain_entropy"] * 0.5
        )
        prediction = 1 if score > 3 else 0
        status = "✅" if prediction == real_label else "❌"
        print(f"  {status} Phishing={prediction} | Réel={real_label} | Score heuristique={score:.2f}")
        print(f"  Features clés → HTTP:{feats['is_http']} | TLD_suspect:{feats['suspicious_tld']} | "
              f"FreeHost:{feats['free_hosting']} | IP:{feats['has_ip_address']} | "
              f"Tirets:{feats['count_hyphens']} | Entropie:{feats['domain_entropy']}")
