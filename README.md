# Mastercamp_TD_Final_note
Analyse des Avis et Alertes ANSSI avec  Enrichissement des CVE

# Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

## Objectif du projet

Ce projet permet d'extraire les bulletins de sécurité publiés par l'ANSSI, d'identifier les CVE associées, d'enrichir ces vulnérabilités avec des informations externes, puis de produire des analyses, visualisations, modèles de Machine Learning et alertes personnalisées.

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

-`main.py` : 
- `MC_TD_Final.ipynb` : notebook principal du projet
- `cve_consolide_final.csv` : fichier final consolidé
- `bulletins_anssi_avec_cves.csv` : bulletins ANSSI avec CVE extraites
- `donnees_anssi_cves_enrichies.csv` : données enrichies
- `README.md` : documentation du projet

## Lancer le projet

Installer les dépendances :

```bash
pip install pandas requests feedparser matplotlib seaborn scikit-learn