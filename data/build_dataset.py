"""
CamerPhish - Étape 1 : Construction du Dataset
===============================================
Ce script construit un dataset d'URLs légitimes (label=0)
et d'URLs de phishing (label=1) centré sur le contexte camerounais.

Concepts abordés :
  - URLs légitimes : domaines officiels camerounais, banques, télécoms
  - URLs phishing : imitations de ces domaines (typosquatting, sous-domaines suspects, etc.)
"""

import pandas as pd
import random
import re

# ──────────────────────────────────────────────
# 1. URLs LÉGITIMES CAMEROUNAISES (label = 0)
# ──────────────────────────────────────────────
LEGIT_URLS = [
    # Télécoms
    "https://www.mtn.cm/fr/",
    "https://www.orange.cm/",
    "https://mymtn.mtn.cm/",
    "https://selfcare.orange.cm/",
    "https://www.camtel.cm/",
    "https://www.nextelcm.net/",

    # Mobile Money officiels
    "https://mobilemoney.mtn.cm/",
    "https://momo.mtn.cm/",
    "https://orangemoney.orange.cm/",

    # Banques camerounaises
    "https://www.afrilandbank.com/",
    "https://www.bicec.com/",
    "https://www.sgcib.com/",
    "https://www.ecocbank-cameroun.com/",
    "https://www.uba.cm/",
    "https://www.creditcommunautaire.cm/",
    "https://www.cca-bank.cm/",

    # Administrations
    "https://www.spm.gov.cm/",
    "https://www.minfof.cm/",
    "https://www.antic.cm/",
    "https://www.cameroontribune.cm/",
    "https://www.investiraucameroun.com/",
    "https://www.douane.gov.cm/",
    "https://www.drh.gov.cm/",

    # E-commerce & services
    "https://www.jumia.cm/",
    "https://www.kaymu.cm/",
    "https://www.jiji.cm/",
    "https://www.cemac.int/",
    "https://www.beac.int/",

    # Universités
    "https://www.uy1.uninet.cm/",
    "https://www.univ-douala.com/",
    "https://www.univ-yaounde2.cm/",
    "https://www.uy2.uninet.cm/",

    # International légitimes (utilisés au Cameroun)
    "https://www.google.cm/",
    "https://www.facebook.com/",
    "https://www.youtube.com/",
    "https://www.instagram.com/",
    "https://www.whatsapp.com/",
    "https://www.linkedin.com/",
    "https://www.amazon.com/",
    "https://www.microsoft.com/",
    "https://www.apple.com/",
    "https://www.paypal.com/",
    "https://www.visa.com/",
    "https://www.mastercard.com/",
    "https://www.western-union.com/",
    "https://send.moneygram.com/",

    # Médias camerounais
    "https://www.237actu.com/",
    "https://www.crtv.cm/",
    "https://www.mutations.cm/",
    "https://www.voanews.com/",

    # URLs légitimes avec sous-domaines normaux
    "https://mail.orange.cm/",
    "https://api.mtn.cm/",
    "https://secure.afrilandbank.com/",
    "https://accounts.google.com/",
    "https://login.facebook.com/",
]

# ──────────────────────────────────────────────
# 2. URLs DE PHISHING CAMEROUNAISES (label = 1)
# ──────────────────────────────────────────────
PHISHING_URLS = [
    # Typosquatting MTN / Orange
    "http://mtn-cm-mobilemoney.vercel.app/login",
    "http://www.mtn-momopaycm.com/connexion",
    "http://secure-mtn-momo.netlify.app/",
    "http://mtn.cm.account-verify.com/",
    "http://momopay-mtn-cm.000webhostapp.com/",
    "http://mtn-cameroun-mobilemoney.blogspot.com/",
    "http://orange-money-cm-recharge.000webhostapp.com/",
    "http://orangemoney-cm-secure.weebly.com/",
    "http://orange-cm-login.byethost7.com/",
    "http://secure-orange-money.000webhostapp.com/verify",

    # Faux sites bancaires
    "http://afrilandbank-online.tk/login",
    "http://www.afrilandfirstbank-cm.ml/",
    "http://bicec-espace-client-cameroun.000webhostapp.com/",
    "http://uba-cameroon-online.ga/secure",
    "http://www.afrilandbank-cm-login.cf/",
    "http://sgcib-cameroun-securite.tk/",
    "http://creditcommunautaire-online.ml/auth",

    # Faux recrutements / bourses (arnaque étudiants)
    "http://bourse-france-cameroun-2024.blogspot.com/",
    "http://recrutement-onu-cameroun.000webhostapp.com/",
    "http://bourse-canada-cameroun-dossier.weebly.com/",
    "http://emploi-total-cameroun-2024.tk/",
    "http://recrutement-camtel-urgent.blogspot.com/",
    "http://concours-minfof-2024-inscription.000webhostapp.com/",
    "http://bourse-ue-cameroun-apply.tk/",

    # Faux sites gouvernementaux
    "http://spm-gov-cm-verification.000webhostapp.com/",
    "http://douanes-cameroun-paiement.ml/",
    "http://anticm-verification-compte.tk/",
    "http://drh-cameroun-concours-2024.blogspot.com/",

    # Phishing e-commerce
    "http://jumia-cm-promo-50.000webhostapp.com/",
    "http://jumia-cameroun-soldes.tk/",

    # Phishing via sous-domaines longs suspects
    "http://secure.verify-account-mtn-cm.000webhostapp.com/",
    "http://login.update-orange-money-cm.tk/",
    "http://confirm.afrilandbank-verify-cm.ml/",
    "http://account.mtn-mobilemoney-cm-secure.ga/",

    # URLs avec IP directe (jamais légitimes)
    "http://41.204.63.12/mtn-login",
    "http://197.155.12.8/orange-money",
    "http://41.66.31.200/bicec-secure",

    # Phishing avec @ dans l'URL (technique classique)
    "http://www.orange.cm@phishing-site.tk/",
    "http://mtn.cm@194.32.145.2/verify",

    # Domaines très longs (caractéristique phishing)
    "http://mtn-cameroun-mobilemoney-verification-compte-client.tk/",
    "http://orange-money-cm-verification-identite-client-2024.ml/",
    "http://afrilandbank-cameroun-connexion-espace-client-securise.000webhostapp.com/",

    # Encodages et caractères spéciaux
    "http://mtn%2Ecm%2Elogin.tk/verify",
    "http://0range-m0ney.cm.tk/",
    "http://rntn.cm.account-update.tk/",

    # Faux services connus
    "http://paypal-cameroun-paiement.000webhostapp.com/",
    "http://western-union-cm-transfer.ml/",
    "http://moneygram-cameroun-envoi.tk/",
]

# ──────────────────────────────────────────────
# 3. GÉNÉRATION SYNTHÉTIQUE SUPPLÉMENTAIRE
# ──────────────────────────────────────────────

LEGIT_DOMAINS_CM = [
    "mtn.cm", "orange.cm", "camtel.cm", "afrilandbank.com",
    "bicec.com", "uba.cm", "ecobank.cm", "jumia.cm",
    "antic.cm", "spm.gov.cm", "douane.gov.cm"
]

PHISHING_TLDS = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".click"]
PHISHING_HOSTS = ["000webhostapp.com", "byethost7.com", "netlify.app",
                  "vercel.app", "blogspot.com", "weebly.com", "wix.com"]
PHISHING_PREFIXES = ["secure-", "login-", "verify-", "update-",
                     "account-", "espace-", "connexion-", "confirm-"]

def generate_synthetic_phishing(n=200):
    """Génère des URLs de phishing synthétiques réalistes"""
    urls = []
    for _ in range(n):
        domain = random.choice(LEGIT_DOMAINS_CM).replace(".", "-")
        technique = random.randint(1, 5)

        if technique == 1:
            # Typosquatting + TLD gratuit
            tld = random.choice(PHISHING_TLDS)
            url = f"http://www-{domain}{tld}/login"
        elif technique == 2:
            # Faux sous-domaine sur hébergeur gratuit
            host = random.choice(PHISHING_HOSTS)
            prefix = random.choice(PHISHING_PREFIXES)
            url = f"http://{prefix}{domain}.{host}/verify"
        elif technique == 3:
            # URL très longue avec vrai domaine en chemin
            url = f"http://{domain}-verification-compte-client-2024.tk/auth"
        elif technique == 4:
            # IP directe
            ip = f"{random.randint(41,197)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            url = f"http://{ip}/{domain}/login"
        else:
            # Sous-domaine suspect
            prefix = random.choice(PHISHING_PREFIXES)
            tld = random.choice(PHISHING_TLDS)
            url = f"http://{prefix}{domain}-cm{tld}/"

        urls.append(url)
    return urls

def generate_synthetic_legit(n=200):
    """Génère des URLs légitimes synthétiques"""
    urls = []
    legit_paths = ["/", "/fr/", "/en/", "/about", "/contact", "/services",
                   "/espace-client", "/nos-offres", "/actualites", "/faq"]
    subdomains = ["www", "mail", "secure", "api", "m", ""]

    for _ in range(n):
        domain = random.choice(LEGIT_DOMAINS_CM)
        path = random.choice(legit_paths)
        sub = random.choice(subdomains)
        if sub:
            url = f"https://{sub}.{domain}{path}"
        else:
            url = f"https://{domain}{path}"
        urls.append(url)
    return urls


def build_and_save():
    # Combiner URLs manuelles + synthétiques
    all_legit = LEGIT_URLS + generate_synthetic_legit(200)
    all_phish  = PHISHING_URLS + generate_synthetic_phishing(200)

    # Dédoublonner
    all_legit = list(set(all_legit))
    all_phish = list(set(all_phish))

    # Construire DataFrame
    df_legit = pd.DataFrame({"url": all_legit, "label": 0})
    df_phish = pd.DataFrame({"url": all_phish, "label": 1})
    df = pd.concat([df_legit, df_phish], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # Mélanger

    df.to_csv("data/urls_dataset.csv", index=False)
    print(f"✅ Dataset créé : {len(df)} URLs total")
    print(f"   → Légitimes  : {len(df_legit)}")
    print(f"   → Phishing   : {len(df_phish)}")
    print(f"   → Ratio phishing : {len(df_phish)/len(df)*100:.1f}%")
    print(f"   → Fichier : data/urls_dataset.csv")
    return df


if __name__ == "__main__":
    df = build_and_save()
    print("\nAperçu des données :")
    print(df.head(10).to_string())
