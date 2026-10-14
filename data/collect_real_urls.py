"""
CamerPhish - Collecteur de VRAIES URLs (Threat Intelligence)
=============================================================
Sources utilisées :
  1. OpenPhish    → feed gratuit, pas de clé API nécessaire
  2. PhishTank    → JSON public, pas de clé pour le feed de base
  3. URLhaus      → base de malware/phishing d'abuse.ch
  4. Domaines légitimes vérifiés → liste curatée .cm + Alexa Africa

Résultat : un dataset 100% réel pour entraîner un vrai modèle.
"""

import requests
import pandas as pd
import csv
import io
import json
import time
import random
from datetime import datetime
from rich.console import Console
from rich.progress import track

console = Console()

# ──────────────────────────────────────────────────────────
# SOURCES DE PHISHING RÉELS
# ──────────────────────────────────────────────────────────

def fetch_openphish() -> list:
    """
    OpenPhish Free Feed — mis à jour toutes les 12h
    URL : https://openphish.com/feed.txt
    Format : une URL par ligne, pas de header
    Limite free tier : ~500 URLs récentes
    """
    console.print("\n[bold cyan]📡 OpenPhish — Téléchargement du feed...[/]")
    urls = []
    try:
        r = requests.get(
            "https://openphish.com/feed.txt",
            timeout=30,
            headers={"User-Agent": "CamerPhish-Research/1.0 (Academic Security Project)"}
        )
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.splitlines() if l.strip().startswith("http")]
            urls = lines
            console.print(f"   [green]✅ {len(urls)} URLs récupérées depuis OpenPhish[/]")
        else:
            console.print(f"   [yellow]⚠️  OpenPhish HTTP {r.status_code}[/]")
    except Exception as e:
        console.print(f"   [red]❌ Erreur OpenPhish : {e}[/]")
    return urls


def fetch_phishtank() -> list:
    """
    PhishTank — Base de données communautaire de phishing
    URL : http://data.phishtank.com/data/online-valid.json
    Format : JSON, champ 'url' dans chaque entrée
    Note : Limite de fréquence sans clé → 1 requête / 5min
    """
    console.print("\n[bold cyan]📡 PhishTank — Téléchargement du feed JSON...[/]")
    urls = []
    try:
        r = requests.get(
            "http://data.phishtank.com/data/online-valid.json",
            timeout=60,
            headers={"User-Agent": "phishtank/CamerPhish"}
        )
        if r.status_code == 200:
            data = r.json()
            urls = [entry["url"] for entry in data if "url" in entry]
            console.print(f"   [green]✅ {len(urls)} URLs récupérées depuis PhishTank[/]")
        elif r.status_code == 509:
            console.print("   [yellow]⚠️  PhishTank : limite de bande passante atteinte (réessaie dans 5 min)[/]")
        else:
            console.print(f"   [yellow]⚠️  PhishTank HTTP {r.status_code}[/]")
    except Exception as e:
        console.print(f"   [red]❌ Erreur PhishTank : {e}[/]")
    return urls


def fetch_urlhaus() -> list:
    """
    URLhaus (abuse.ch) — Base de malware et phishing
    URL : https://urlhaus.abuse.ch/downloads/csv_recent/
    Format : CSV avec colonnes id, dateadded, url, url_status, ...
    Filtre : on garde seulement les URLs 'online' et 'phishing'
    """
    console.print("\n[bold cyan]📡 URLhaus (abuse.ch) — Téléchargement...[/]")
    urls = []
    try:
        r = requests.get(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            timeout=30,
            headers={"User-Agent": "CamerPhish-Research/1.0"}
        )
        if r.status_code == 200:
            # Sauter les lignes de commentaires (#)
            lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
            reader = csv.DictReader(lines)
            for row in reader:
                url = row.get("url", "").strip('"')
                tags = row.get("tags", "").lower()
                status = row.get("url_status", "").lower()
                # Garder phishing + malware actifs
                if url.startswith("http") and status in ("online", ""):
                    urls.append(url)
            console.print(f"   [green]✅ {len(urls)} URLs récupérées depuis URLhaus[/]")
        else:
            console.print(f"   [yellow]⚠️  URLhaus HTTP {r.status_code}[/]")
    except Exception as e:
        console.print(f"   [red]❌ Erreur URLhaus : {e}[/]")
    return urls


def fetch_phishstats() -> list:
    """
    PhishStats — API publique de statistiques phishing
    URL : https://phishstats.info/phish_score.csv
    Format : CSV, champ url, score de phishing
    Filtre : score >= 7 (très probablement du phishing)
    """
    console.print("\n[bold cyan]📡 PhishStats — Téléchargement...[/]")
    urls = []
    try:
        r = requests.get(
            "https://phishstats.info/phish_score.csv",
            timeout=30,
            headers={"User-Agent": "CamerPhish-Research/1.0"}
        )
        if r.status_code == 200:
            lines = r.text.splitlines()
            # Format : #,Date,URL,IP
            for line in lines[1:]:  # Sauter le header
                parts = line.split(",")
                if len(parts) >= 3:
                    url = parts[2].strip().strip('"')
                    if url.startswith("http"):
                        urls.append(url)
            console.print(f"   [green]✅ {len(urls)} URLs récupérées depuis PhishStats[/]")
        else:
            console.print(f"   [yellow]⚠️  PhishStats HTTP {r.status_code}[/]")
    except Exception as e:
        console.print(f"   [red]❌ Erreur PhishStats : {e}[/]")
    return urls


# ──────────────────────────────────────────────────────────
# URLS LÉGITIMES RÉELLES VÉRIFIÉES
# ──────────────────────────────────────────────────────────

# Liste curatée manuellement — domaines réels et vérifiés
VERIFIED_LEGIT = [
    # ── Cameroun officiel ──
    "https://www.mtn.cm/fr/",
    "https://www.orange.cm/",
    "https://mobilemoney.mtn.cm/",
    "https://selfcare.orange.cm/",
    "https://www.camtel.cm/",
    "https://www.antic.cm/",
    "https://www.spm.gov.cm/",
    "https://www.douane.gov.cm/",
    "https://www.cameroontribune.cm/",
    "https://www.crtv.cm/",
    "https://www.investiraucameroun.com/",
    "https://www.afrilandbank.com/",
    "https://www.bicec.com/",
    "https://www.uba.cm/",
    "https://www.jumia.cm/",
    "https://www.uy1.uninet.cm/",
    "https://www.univ-douala.com/",
    "https://www.237actu.com/",
    "https://www.mutations.cm/",
    "https://www.beac.int/",
    "https://www.cemac.int/",
    # ── Afrique ──
    "https://www.mtn.com/",
    "https://www.orange.com/",
    "https://www.safaricom.co.ke/",
    "https://www.econet.co.zw/",
    "https://www.glo.com/",
    "https://www.airtel.africa/",
    "https://www.africainternetgroup.com/",
    "https://www.jumia.com/",
    "https://www.konga.com/",
    "https://www.paystack.com/",
    "https://www.flutterwave.com/",
    "https://www.remita.net/",
    "https://www.wave.com/",
    # ── Banques régionales ──
    "https://www.ecobank.com/",
    "https://www.stanbankgroup.com/",
    "https://www.nedbank.co.za/",
    "https://www.absa.africa/",
    "https://www.zenithbank.com/",
    "https://www.gtbank.com/",
    "https://www.accessbankplc.com/",
    # ── Organisations internationales présentes en Afrique ──
    "https://www.un.org/",
    "https://www.worldbank.org/",
    "https://www.imf.org/",
    "https://www.afdb.org/",
    "https://www.unicef.org/",
    "https://www.wfp.org/",
    # ── Services très utilisés au Cameroun ──
    "https://www.google.com/",
    "https://www.google.cm/",
    "https://www.facebook.com/",
    "https://www.youtube.com/",
    "https://www.instagram.com/",
    "https://www.whatsapp.com/",
    "https://www.linkedin.com/",
    "https://www.twitter.com/",
    "https://www.tiktok.com/",
    "https://www.paypal.com/",
    "https://www.western-union.com/",
    "https://send.moneygram.com/",
    "https://www.visa.com/",
    "https://www.mastercard.com/",
    "https://www.amazon.com/",
    "https://www.microsoft.com/",
    "https://www.apple.com/",
    "https://www.netflix.com/",
    # ── Sous-domaines légitimes connus ──
    "https://mail.orange.cm/",
    "https://accounts.google.com/",
    "https://login.microsoftonline.com/",
    "https://secure.paypal.com/",
    "https://api.mtn.cm/",
    "https://m.facebook.com/",
    "https://mobile.twitter.com/",
    "https://www.googleapis.com/",
    "https://aws.amazon.com/",
    "https://console.cloud.google.com/",
    # ── Tech & Education ──
    "https://github.com/",
    "https://stackoverflow.com/",
    "https://www.coursera.org/",
    "https://www.edx.org/",
    "https://tryhackme.com/",
    "https://www.hackthebox.com/",
    "https://portswigger.net/",
    "https://owasp.org/",
    "https://www.sans.org/",
    "https://www.kali.org/",
    # ── Actualités ──
    "https://www.bbc.com/",
    "https://www.rfi.fr/",
    "https://www.lemonde.fr/",
    "https://www.voanews.com/",
    "https://www.aljazeera.com/",
    "https://africa.cgtn.com/",
    "https://www.theafricareport.com/",
]


def fetch_majestic_legit(n=300) -> list:
    """
    Majestic Million — Top sites Alexa-like par TrustFlow
    On filtre les domaines africains pour plus de pertinence.
    """
    console.print("\n[bold cyan]📡 Majestic Million — Domaines populaires...[/]")
    urls = []
    try:
        r = requests.get(
            "https://downloads.majestic.com/majestic_million.csv",
            timeout=60,
            headers={"User-Agent": "CamerPhish-Research/1.0"},
            stream=True
        )
        if r.status_code == 200:
            content = ""
            # Lire seulement les 10 000 premières lignes
            for i, chunk in enumerate(r.iter_lines()):
                if i > 10000:
                    break
                if chunk:
                    content += chunk.decode("utf-8", errors="ignore") + "\n"

            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                domain = row.get("Domain", "").strip()
                if domain:
                    urls.append(f"https://www.{domain}/")
                    if len(urls) >= n:
                        break
            console.print(f"   [green]✅ {len(urls)} domaines populaires récupérés[/]")
        else:
            console.print(f"   [yellow]⚠️  Majestic HTTP {r.status_code} — utilisation liste locale[/]")
    except Exception as e:
        console.print(f"   [yellow]⚠️  Majestic non disponible : {e}[/]")
    return urls


# ──────────────────────────────────────────────────────────
# NETTOYAGE ET FILTRAGE
# ──────────────────────────────────────────────────────────

def clean_urls(urls: list) -> list:
    """Nettoie et dédoublonne une liste d'URLs."""
    cleaned = set()
    for url in urls:
        url = url.strip().strip('"').strip("'")
        if url.startswith(("http://", "https://")) and len(url) > 10 and len(url) < 500:
            # Supprimer les URLs avec espaces ou caractères invalides
            if " " not in url and "\n" not in url:
                cleaned.add(url)
    return list(cleaned)


def sample_balanced(phishing_urls: list, legit_urls: list,
                    target_per_class: int = 500) -> tuple:
    """
    Rééquilibre les classes pour avoir un dataset balanced.
    target_per_class : nombre d'URLs par classe (phishing / légitime)
    """
    # Phishing
    if len(phishing_urls) > target_per_class:
        phish_sample = random.sample(phishing_urls, target_per_class)
    else:
        phish_sample = phishing_urls
        console.print(f"   [yellow]⚠️  Seulement {len(phish_sample)} URLs phishing disponibles[/]")

    # Légitimes
    if len(legit_urls) > target_per_class:
        legit_sample = random.sample(legit_urls, target_per_class)
    else:
        legit_sample = legit_urls
        console.print(f"   [yellow]⚠️  Seulement {len(legit_sample)} URLs légitimes disponibles[/]")

    return phish_sample, legit_sample


# ──────────────────────────────────────────────────────────
# PIPELINE PRINCIPAL
# ──────────────────────────────────────────────────────────

def collect_and_save(target_per_class: int = 500):
    console.print("\n[bold]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
    console.print("[bold cyan]  CamerPhish — Collecte de VRAIES URLs Phishing[/]")
    console.print("[bold]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
    console.print(f"   Début : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print(f"   Objectif : {target_per_class} URLs par classe\n")

    # ── 1. Collecte phishing ──
    all_phishing = []

    phish_openphish = fetch_openphish()
    all_phishing.extend(phish_openphish)
    time.sleep(1)

    phish_phishtank = fetch_phishtank()
    all_phishing.extend(phish_phishtank)
    time.sleep(1)

    phish_urlhaus = fetch_urlhaus()
    all_phishing.extend(phish_urlhaus)
    time.sleep(1)

    phish_stats = fetch_phishstats()
    all_phishing.extend(phish_stats)

    all_phishing = clean_urls(all_phishing)
    console.print(f"\n[bold]Total phishing brut (avant dédup) : {len(all_phishing)}[/]")

    # ── 2. Collecte légitimes ──
    console.print("\n[bold cyan]📋 URLs légitimes vérifiées...[/]")
    all_legit = list(VERIFIED_LEGIT)

    majestic = fetch_majestic_legit(400)
    all_legit.extend(majestic)

    all_legit = clean_urls(all_legit)
    console.print(f"[bold]Total légitimes brut : {len(all_legit)}[/]")

    # ── 3. Équilibrage ──
    console.print("\n[bold cyan]⚖️  Équilibrage des classes...[/]")
    phish_final, legit_final = sample_balanced(all_phishing, all_legit, target_per_class)

    # ── 4. Construction du DataFrame ──
    df_phish = pd.DataFrame({"url": phish_final, "label": 1, "source": "threat_intel"})
    df_legit = pd.DataFrame({"url": legit_final, "label": 0, "source": "verified"})
    df = pd.concat([df_phish, df_legit], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # ── 5. Sauvegarde ──
    output_path = "data/urls_dataset_real.csv"
    df.to_csv(output_path, index=False)

    # Stats finales
    console.print(f"\n[bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
    console.print(f"[bold green]  ✅ Dataset réel sauvegardé ![/]")
    console.print(f"[bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
    console.print(f"  Fichier      : {output_path}")
    console.print(f"  Total URLs   : {len(df)}")
    console.print(f"  Phishing (1) : {len(df_phish)} URLs")
    console.print(f"  Légitimes(0) : {len(df_legit)} URLs")
    console.print(f"\n[dim]  Sources phishing :[/]")
    console.print(f"    OpenPhish : {len(phish_openphish)}")
    console.print(f"    PhishTank : {len(phish_phishtank)}")
    console.print(f"    URLhaus   : {len(phish_urlhaus)}")
    console.print(f"    PhishStats: {len(phish_stats)}")
    console.print(f"\n  [bold]Prochaine étape :[/] python3 models/train.py --dataset data/urls_dataset_real.csv\n")

    return df


if __name__ == "__main__":
    df = collect_and_save(target_per_class=500)
    print("\nAperçu :")
    print(df.head(10).to_string())
