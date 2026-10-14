"""
CamerPhish - Tests automatisés
================================
Lance tous les tests avec : python tests/test_camerphish.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data.feature_extractor import extract_features, url_to_feature_vector, get_feature_names
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ─────────────────────────────────────────
# CAS DE TEST : (url, label_attendu, description)
# ─────────────────────────────────────────
TEST_CASES = [
    # ✅ Légitimes camerounais
    ("https://www.mtn.cm/fr/",                         0, "MTN Cameroun officiel"),
    ("https://www.orange.cm/",                          0, "Orange Cameroun officiel"),
    ("https://mobilemoney.mtn.cm/",                    0, "MTN Mobile Money officiel"),
    ("https://www.afrilandbank.com/",                  0, "Afriland First Bank officiel"),
    ("https://www.antic.cm/",                           0, "ANTIC gouvernement"),
    ("https://www.jumia.cm/",                           0, "Jumia Cameroun"),
    # ⚠️ Phishing Mobile Money
    ("http://mtn-mobilemoney-cm-secure.000webhostapp.com/login",  1, "Phishing MTN MoMo (hébergeur gratuit)"),
    ("http://orange-money-cm-recharge.000webhostapp.com/",        1, "Phishing Orange Money"),
    ("http://mtn-cm-secure.tk/verify",                            1, "Phishing MTN (TLD .tk)"),
    ("http://orange-money-cm.ml/login",                           1, "Phishing Orange (.ml)"),
    # ⚠️ Phishing bancaire
    ("http://afrilandbank-online.tk/login",             1, "Phishing Afriland Bank"),
    ("http://bicec-espace-client.000webhostapp.com/",  1, "Phishing BICEC"),
    # ⚠️ IP directe
    ("http://41.204.63.12/mtn-login",                  1, "Phishing IP directe MTN"),
    ("http://197.155.12.8/orange-money",               1, "Phishing IP directe Orange"),
    # ⚠️ @ dans l'URL
    ("http://www.orange.cm@phishing-site.tk/",         1, "Technique URL avec @"),
    # ⚠️ Fausses bourses
    ("http://bourse-france-cameroun-2024.blogspot.com/", 1, "Fausse bourse étudiante"),
    # ⚠️ Encodage
    ("http://mtn%2Ecm%2Everify.tk/update",             1, "URL encodée suspecte"),
]

def simple_heuristic_predict(url: str) -> int:
    """Prédiction heuristique simple pour les tests sans modèle ML."""
    f = extract_features(url)
    score = (
        f.get("is_http", 0) * 15 +
        f.get("suspicious_tld", 0) * 25 +
        f.get("free_hosting", 0) * 25 +
        f.get("has_ip_address", 0) * 35 +
        f.get("has_at_symbol", 0) * 30 +
        f.get("has_encoding", 0) * 15 +
        f.get("brand_repetition", 0) * 20 +
        min(f.get("count_hyphens", 0) * 4, 20) -
        f.get("is_cm_tld", 0) * 30
    )
    return 1 if score > 20 else 0


def run_tests():
    console.print("\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
    console.print("[bold]   CamerPhish — Tests Automatisés[/]")
    console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n")

    # Charger modèle ML si disponible
    model = None
    try:
        import joblib
        model = joblib.load("models/camerphish_model.pkl")
        console.print("[green]✅ Modèle ML chargé[/]\n")
    except Exception:
        console.print("[yellow]⚠️  Modèle absent → utilisation heuristique[/]\n")

    table = Table(box=box.ROUNDED, border_style="cyan")
    table.add_column("URL", max_width=50, style="dim")
    table.add_column("Description", max_width=30)
    table.add_column("Attendu", justify="center")
    table.add_column("Prédit",  justify="center")
    table.add_column("Résultat", justify="center")

    passed = 0
    failed = 0

    for url, expected, desc in TEST_CASES:
        if model:
            vec = url_to_feature_vector(url)
            predicted = int(model.predict([vec])[0])
        else:
            predicted = simple_heuristic_predict(url)

        ok = predicted == expected
        if ok:
            passed += 1
        else:
            failed += 1

        label_str = lambda l: "[red]PHISHING[/]" if l == 1 else "[green]LÉGITIME[/]"
        status = "[bold green]✅ PASS[/]" if ok else "[bold red]❌ FAIL[/]"
        short_url = url[:47] + "..." if len(url) > 50 else url
        table.add_row(short_url, desc, label_str(expected), label_str(predicted), status)

    console.print(table)
    total = passed + failed
    pct = passed / total * 100
    console.print(f"\n[bold]Résultat : {passed}/{total} tests passés ({pct:.0f}%)[/]")
    if failed == 0:
        console.print("[bold green]🎉 Tous les tests passent ![/]")
    else:
        console.print(f"[bold red]❌ {failed} test(s) échoué(s) — vérifiez le modèle.[/]")


def test_features_completeness():
    """Vérifie que les 22 features sont bien extraites pour toute URL."""
    console.print("\n[bold cyan]Test : Complétude des features[/]")
    test_url = "https://www.mtn.cm/fr/"
    features = extract_features(test_url)
    expected_names = set(get_feature_names())
    actual_names   = set(features.keys())
    missing = expected_names - actual_names
    extra   = actual_names - expected_names
    if not missing and not extra:
        console.print(f"   [green]✅ 22 features extraites correctement[/]")
    else:
        if missing:
            console.print(f"   [red]❌ Features manquantes : {missing}[/]")
        if extra:
            console.print(f"   [yellow]⚠️  Features inattendues : {extra}[/]")


if __name__ == "__main__":
    test_features_completeness()
    run_tests()
