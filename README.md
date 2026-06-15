# Mastercamp_TD_Final_note
Analyse des Avis et Alertes ANSSI avec  Enrichissement des CVE

# Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

## Objectif du projet

Ce projet a pour objectif d'extraire les bulletins de sécurité publiés par l'ANSSI, d'identifier les vulnérabilités (CVE) associées, d'enrichir ces données à l'aide d'API externes, puis de réaliser des analyses et des modèles de Machine Learning.

## Fonctionnalités principales

- Extraction des flux RSS ANSSI
- Identification des CVE dans les bulletins
- Enrichissement des CVE via les API MITRE et EPSS
- Consolidation des données dans un DataFrame Pandas
- Export des données consolidées en CSV
- Analyse et visualisation des vulnérabilités
- Modèles Machine Learning : K-Means et KNN
- Génération d'alertes email simulées

## Fichiers principaux

-`main.py` :  script principal du projet
- `MC_TD_Final.ipynb` : notebook contenant l'ensemble des analyses
- `bulletins_anssi_avec_cves.csv` : bulletins ANSSI avec CVE extraites
- `donnees_anssi_cves_enrichies.csv` : données enrichies
- `cve_consolide_final.csv` : fichier final consolidé final
- `README.md` : documentation du projet




## Installation
Installer les dépendances :

```bash
pip install pandas requests feedparser matplotlib seaborn scikit-learn
```

## Exécution
Lancer le notebook :

```bash
jupyter notebook MC_TD_Final.ipynb
```

Ou lancer le script Python :

```bash
python main.py
```

## Technologies utilisées
- Python
- Pandas
- Requests
- Feedparser
- Matplotlib
- Seaborn
- Scikit-learn

## Sources de données
- Flux RSS ANSSI : https://www.cert.ssi.gouv.fr/avis/feed/
- API MITRE CVE : https://cveawg.mitre.org/api/cve/
- API EPSS FIRST : https://api.first.org/data/v1/epss

## Résultats
Le projet permet d'obtenir un jeu de données enrichi sur les vulnérabilités publiées par l'ANSSI,
de réaliser des analyses statistiques et de mettre en œuvre des modèles de Machine Learning
pour l'étude des vulnérabilités.