import ast
import os
import time
import smtplib
from email.mime.text import MIMEText
import feedparser
import pandas as pd
import requests


# Configuration

URL_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"
URL_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"

FICHIER_BULLETINS = "bulletins_anssi_avec_cves.csv"
FICHIER_ENRICHI = "donnees_anssi_cves_enrichies.csv"
FICHIER_FINAL = "cve_consolide_final.csv"

# Étape 1 : Extraction RSS ANSSI

def extraire_flux_rss(url, type_bulletin):
    flux = feedparser.parse(url)
    liste_bulletins = []

    for entry in flux.entries:
        liste_bulletins.append({
            "id_anssi": entry.link.strip("/").split("/")[-1],
            "titre": entry.title,
            "description": entry.description,
            "date_publication": entry.published,
            "lien": entry.link,
            "type_bulletin": type_bulletin
        })

    time.sleep(1)
    return liste_bulletins

# Étape 2 : Extraction des CVE

def extraire_cves_du_bulletin(lien_bulletin):
    url_json = f"{lien_bulletin.strip('/')}/json/"

    try:
        response = requests.get(url_json, timeout=10)

        if response.status_code == 200:
            data = response.json()
            return [
                item["name"]
                for item in data.get("cves", [])
                if "name" in item
            ]

        return []

    except Exception as e:
        print(f"Erreur extraction CVE pour {lien_bulletin} : {e}")
        return []


def mettre_a_jour_donnees():
    print("Étape 1 : récupération des flux RSS ANSSI...")

    avis = extraire_flux_rss(URL_AVIS, "Avis")
    alertes = extraire_flux_rss(URL_ALERTES, "Alerte")

    df_flux_actuel = pd.DataFrame(avis + alertes)
    df_flux_actuel["id_anssi"] = df_flux_actuel["id_anssi"].astype(str).str.strip()

    if os.path.exists(FICHIER_BULLETINS):
        print("CSV des bulletins déjà existant, mise à jour...")

        df_existant = pd.read_csv(FICHIER_BULLETINS)
        df_existant["id_anssi"] = df_existant["id_anssi"].astype(str).str.strip()

        mask = ~df_flux_actuel["id_anssi"].isin(df_existant["id_anssi"])
        nouveaux_items = df_flux_actuel[mask].copy()

        if not nouveaux_items.empty:
            print(f"{len(nouveaux_items)} nouveaux bulletins détectés.")
            nouveaux_items["liste_cves"] = nouveaux_items["lien"].apply(extraire_cves_du_bulletin)

            df_final = pd.concat(
                [df_existant, nouveaux_items],
                ignore_index=True
            )

            df_final = df_final.drop_duplicates(subset=["id_anssi"])
            df_final.to_csv(FICHIER_BULLETINS, index=False, encoding="utf-8-sig")
        else:
            print("Aucun nouveau bulletin à ajouter.")
            df_final = df_existant

    else:
        print("Création du CSV des bulletins...")
        df_flux_actuel["liste_cves"] = df_flux_actuel["lien"].apply(extraire_cves_du_bulletin)

        df_final = df_flux_actuel.drop_duplicates(subset=["id_anssi"])
        df_final.to_csv(FICHIER_BULLETINS, index=False, encoding="utf-8-sig")

    print(f"Nombre total de bulletins : {len(df_final)}")
    return df_final

# Étape 3 : Enrichissement MITRE / EPSS

def enrichir_cve_mitre(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    try:
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return None

        data = response.json()

        resultat = {
            "description_cve": None,
            "cvss": None,
            "cwe": None,
            "cwe_description": None,
            "vendor": None,
            "produit": None,
            "versions_affectees": None
        }

        try:
            resultat["description_cve"] = data["containers"]["cna"]["descriptions"][0]["value"]
        except Exception:
            pass

        try:
            metrics = data["containers"]["cna"]["metrics"][0]

            if "cvssV4_0" in metrics:
                resultat["cvss"] = metrics["cvssV4_0"]["baseScore"]
            elif "cvssV3_1" in metrics:
                resultat["cvss"] = metrics["cvssV3_1"]["baseScore"]
            elif "cvssV3_0" in metrics:
                resultat["cvss"] = metrics["cvssV3_0"]["baseScore"]
            elif "cvssV2_0" in metrics:
                resultat["cvss"] = metrics["cvssV2_0"]["baseScore"]
        except Exception:
            pass

        try:
            problem = data["containers"]["cna"]["problemTypes"][0]["descriptions"][0]
            resultat["cwe"] = problem.get("cweId")
            resultat["cwe_description"] = problem.get("description")
        except Exception:
            pass

        try:
            affected = data["containers"]["cna"]["affected"][0]

            resultat["vendor"] = affected.get("vendor")
            resultat["produit"] = affected.get("product")

            versions = [
                v.get("version")
                for v in affected.get("versions", [])
                if v.get("status") == "affected"
            ]

            resultat["versions_affectees"] = ", ".join(versions)
        except Exception:
            pass

        return resultat

    except Exception as e:
        print(f"Erreur MITRE pour {cve_id} : {e}")
        return None


def enrichir_epss(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    try:
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return None

        data = response.json()

        if len(data.get("data", [])) > 0:
            return float(data["data"][0]["epss"])

        return None

    except Exception:
        return None


def enrichir_cve_complete(cve_id):
    mitre = enrichir_cve_mitre(cve_id)

    if mitre is None:
        return {
            "description_cve": None,
            "cvss": None,
            "cwe": None,
            "cwe_description": None,
            "vendor": None,
            "produit": None,
            "versions_affectees": None,
            "epss": None
        }

    mitre["epss"] = enrichir_epss(cve_id)
    return mitre

# Étape 4 : Consolidation

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


def transformer_en_lignes_cve(df_bulletins):
    df = df_bulletins.copy()

    df["liste_cves"] = df["liste_cves"].apply(
        lambda x: ast.literal_eval(x) if isinstance(x, str) else x
    )

    df_cves = df.explode("liste_cves")
    df_cves = df_cves.rename(columns={"liste_cves": "cve"})

    df_cves = df_cves[df_cves["cve"].notna()]
    df_cves = df_cves[df_cves["cve"] != ""]

    return df_cves


def consolider_donnees(df_cves):
    print("Étape 3 : enrichissement des CVE via MITRE et EPSS...")

    liste_infos = []

    for i, cve in enumerate(df_cves["cve"]):
        print(f"{i + 1}/{len(df_cves)} : {cve}")

        infos = enrichir_cve_complete(cve)
        liste_infos.append(infos)

        time.sleep(2)

    df_infos = pd.DataFrame(liste_infos)

    df_consolide = pd.concat(
        [
            df_cves.reset_index(drop=True),
            df_infos.reset_index(drop=True)
        ],
        axis=1
    )

    df_consolide.to_csv(FICHIER_ENRICHI, index=False, encoding="utf-8-sig")

    df_consolide["cvss"] = pd.to_numeric(df_consolide["cvss"], errors="coerce")
    df_consolide["epss"] = pd.to_numeric(df_consolide["epss"], errors="coerce")

    df_consolide["base_severity"] = df_consolide["cvss"].apply(calculer_severite)

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

    df_final = df_consolide[colonnes_finales].copy()

    df_final.to_csv(FICHIER_FINAL, index=False, encoding="utf-8-sig")

    print(f"CSV final créé : {FICHIER_FINAL}")
    print(f"Nombre de lignes : {len(df_final)}")

    return df_final


def charger_ou_creer_donnees_finales():
    if os.path.exists(FICHIER_FINAL):
        print(f"CSV final trouvé : {FICHIER_FINAL}")
        df_final = pd.read_csv(FICHIER_FINAL, encoding="utf-8-sig")

        df_final["cvss"] = pd.to_numeric(df_final["cvss"], errors="coerce")
        df_final["epss"] = pd.to_numeric(df_final["epss"], errors="coerce")
        df_final["date_publication"] = pd.to_datetime(
            df_final["date_publication"],
            errors="coerce"
        )

        print(f"{len(df_final)} lignes chargées.")
        return df_final

    print("CSV final introuvable, lancement du pipeline complet...")

    df_bulletins = mettre_a_jour_donnees()

    print("Étape 2 : transformation en une ligne par CVE...")
    df_cves = transformer_en_lignes_cve(df_bulletins)

    print(f"Nombre de CVE à enrichir : {len(df_cves)}")

    return consolider_donnees(df_cves)

# Étape 7 : Alertes et notifications

def send_email(to_email, subject, body):
    from_email = "votre_email@gmail.com"
    password = "mot_de_passe_application"

    msg = MIMEText(body)
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject

    # Envoi réel désactivé pour éviter l'envoi involontaire.
    # Pour envoyer réellement :
    # server = smtplib.SMTP("smtp.gmail.com", 587)
    # server.starttls()
    # server.login(from_email, password)
    # server.sendmail(from_email, to_email, msg.as_string())
    # server.quit()

    print("\n--- Email simulé ---")
    print(f"À       : {to_email}")
    print(f"Sujet   : {subject}")
    print(f"Message :\n{body}")


def generer_alertes(df):
    print("Étape 4 : génération des alertes...")

    df_critiques = df[
        df["base_severity"].isin(["Critique", "CRITICAL", "Élevée", "HIGH"])
    ].copy()

    print(f"Nombre d'alertes générées : {len(df_critiques)}")

    for _, row in df_critiques.head(10).iterrows():
        sujet = f"Alerte CVE critique : {row['cve']}"

        corps = (
            f"Produit     : {row['produit']} ({row['vendor']})\n"
            f"Gravité     : {row['base_severity']} (CVSS : {row['cvss']})\n"
            f"EPSS        : {row['epss']}\n"
            f"Description : {str(row['description_cve'])[:200]}\n"
            f"Lien ANSSI  : {row['lien']}\n\n"
            f"ACTION : Nous vous recommandons de faire les mises à jour de sécurité dans les plus brefs délais. \n"
        )

        send_email("destinataire@email.com", sujet, corps)


# Programme principal

def main():
    print("======================================")
    print("Projet ANSSI - Analyse des CVE")
    print("======================================")

    df_final = charger_ou_creer_donnees_finales()
    

    print("\nAperçu du fichier final :")
    print(df_final.head())

    print("\nRépartition des niveaux de gravité :")
    print(df_final["base_severity"].value_counts())

    generer_alertes(df_final)

    print("\nFin du projet.")


if __name__ == "__main__":
    main()
