# main.py

import time
import re
import requests
import feedparser
import pandas as pd


# =========================
# 1. Configuration
# =========================

URL_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"
URL_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"

FICHIER_BULLETINS = "bulletins_anssi_avec_cves.csv"
FICHIER_ENRICHI = "donnees_anssi_cves_enrichies.csv"
FICHIER_FINAL = "cve_consolide_final.csv"


# =========================
# 2. Extraction RSS
# =========================

def extraire_flux_rss(url, type_bulletin):
    flux = feedparser.parse(url)
    bulletins = []

    for entry in flux.entries:
        bulletins.append({
            "id_anssi": entry.link.rstrip("/").split("/")[-1],
            "titre": entry.title,
            "description": entry.description,
            "date_publication": entry.published,
            "lien": entry.link,
            "type_bulletin": type_bulletin
        })

    return bulletins


# =========================
# 3. Extraction des CVE
# =========================

def extraire_cves_du_bulletin(lien):
    try:
        url_json = lien.rstrip("/") + "/json/"
        response = requests.get(url_json, timeout=10)

        if response.status_code != 200:
            return []

        data = response.json()
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cves = list(set(re.findall(cve_pattern, str(data))))

        return cves

    except Exception:
        return []


# =========================
# 4. Enrichissement MITRE
# =========================

def enrichir_cve_mitre(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    try:
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return {}

        data = response.json()
        cna = data.get("containers", {}).get("cna", {})

        description = "Non disponible"
        descriptions = cna.get("descriptions", [])
        if descriptions:
            description = descriptions[0].get("value", "Non disponible")

        cvss = None
        metrics = cna.get("metrics", [])
        for metric in metrics:
            for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                if key in metric:
                    cvss = metric[key].get("baseScore")
                    break
            if cvss is not None:
                break

        cwe = "Non disponible"
        cwe_description = "Non disponible"
        problem_types = cna.get("problemTypes", [])

        if problem_types:
            descriptions_pt = problem_types[0].get("descriptions", [])
            if descriptions_pt:
                cwe = descriptions_pt[0].get("cweId", "Non disponible")
                cwe_description = descriptions_pt[0].get("description", "Non disponible")

        vendor = "Non disponible"
        produit = "Non disponible"
        versions_affectees = []

        affected = cna.get("affected", [])
        if affected:
            first_product = affected[0]
            vendor = first_product.get("vendor", "Non disponible")
            produit = first_product.get("product", "Non disponible")

            for version in first_product.get("versions", []):
                if version.get("status") == "affected":
                    versions_affectees.append(version.get("version"))

        return {
            "description_cve": description,
            "cvss": cvss,
            "cwe": cwe,
            "cwe_description": cwe_description,
            "vendor": vendor,
            "produit": produit,
            "versions_affectees": ", ".join(versions_affectees)
        }

    except Exception:
        return {}


# =========================
# 5. Enrichissement EPSS
# =========================

def enrichir_epss(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    try:
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return None

        data = response.json()
        epss_data = data.get("data", [])

        if epss_data:
            return float(epss_data[0].get("epss"))

        return None

    except Exception:
        return None


# =========================
# 6. Gravité
# =========================

def calculer_severite(cvss):
    if pd.isna(cvss):
        return "Non disponible"
    elif cvss < 4:
        return "Faible"
    elif cvss < 7:
        return "Moyenne"
    elif cvss < 9:
        return "Élevée"
    else:
        return "Critique"


# =========================
# 7. Programme principal
# =========================

def main():
    print("Extraction des flux RSS...")

    avis = extraire_flux_rss(URL_AVIS, "Avis")
    alertes = extraire_flux_rss(URL_ALERTES, "Alerte")

    df_bulletins = pd.DataFrame(avis + alertes)

    print("Extraction des CVE...")

    df_bulletins["liste_cves"] = df_bulletins["lien"].apply(extraire_cves_du_bulletin)

    df_bulletins.to_csv(FICHIER_BULLETINS, index=False, encoding="utf-8-sig")

    print("Transformation en une ligne par CVE...")

    df_cves = df_bulletins.explode("liste_cves")
    df_cves = df_cves.rename(columns={"liste_cves": "cve"})
    df_cves = df_cves[df_cves["cve"].notna()]
    df_cves = df_cves[df_cves["cve"] != ""]

    print("Enrichissement des CVE...")

    infos_cves = []

    for i, cve in enumerate(df_cves["cve"]):
        print(f"{i+1}/{len(df_cves)} : {cve}")

        infos = enrichir_cve_mitre(cve)
        infos["epss"] = enrichir_epss(cve)

        infos_cves.append(infos)

        time.sleep(1)

    df_infos = pd.DataFrame(infos_cves)

    df_final = pd.concat(
        [
            df_cves.reset_index(drop=True),
            df_infos.reset_index(drop=True)
        ],
        axis=1
    )

    df_final["cvss"] = pd.to_numeric(df_final["cvss"], errors="coerce")
    df_final["epss"] = pd.to_numeric(df_final["epss"], errors="coerce")
    df_final["base_severity"] = df_final["cvss"].apply(calculer_severite)

    colonnes_finales = [
        "id_anssi",
        "titre",
        "type_bulletin",
        "date_publication",
        "cve",
        "cvss",
        "base_severity",
        "cwe",
        "cwe_description",
        "epss",
        "lien",
        "description_cve",
        "vendor",
        "produit",
        "versions_affectees"
    ]

    df_final = df_final[colonnes_finales]

    df_final.to_csv(FICHIER_FINAL, index=False, encoding="utf-8-sig")

    print("Projet terminé.")
    print(f"Fichier généré : {FICHIER_FINAL}")
    print(df_final.head())


if __name__ == "__main__":
    main()