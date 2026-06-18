# Projet B3 Cyber — Cartographie du SI CyberCorp avec Neo4j

Modélisation d'un système d'information dans une base de données orientée graphe (Neo4j AuraDB) et analyse des chemins d'attaque depuis une machine compromise.

## Contexte

Le poste `PC-ALICE` a été compromis suite à une attaque par phishing. Le projet utilise Cypher pour identifier les chemins possibles vers les ressources critiques de l'entreprise, repérer les machines vulnérables, analyser les droits à risque et proposer des mesures de sécurisation (segmentation réseau).

## Contenu du graphe

Le script construit un graphe de 54 nœuds répartis en 14 types (User, Machine, Service, Vulnerability, Group, Resource, VLAN, Firewall, ServiceAccount, ADRight, VPNAccess, Internet, PrivilegeLevel, LoginLog) et 89 relations réparties en 21 types.

Il calcule également un score de risque par machine et exécute dix analyses : chemins d'attaque, ressources accessibles, machines vulnérables, utilisateurs à risque, scoring, contrôle de segmentation, exposition Internet, alertes brute-force, chemins d'attaque Active Directory et machines non patchées.

## Prérequis

- Python 3.10 ou supérieur
- Une instance Neo4j AuraDB Free (gratuite) : https://neo4j.com/product/auradb/

## Installation

1. Cloner ou télécharger ce dépôt.

2. Installer les dépendances :

   ```bash
   pip install -r requirements.txt
   ```

3. Copier le fichier d'exemple de configuration :

   ```bash
   cp .env.example .env
   ```

4. Ouvrir le fichier `.env` et renseigner ses propres identifiants AuraDB (URI, utilisateur, mot de passe). Ces informations se trouvent dans la console AuraDB ou dans le fichier `.txt` téléchargé à la création de l'instance.

5. Lancer le script :

   ```bash
   python projetnosql.py
   ```

Le script vide la base, construit le graphe complet, calcule les scores de risque, puis affiche les résultats des analyses dans le terminal.

## Sécurité des identifiants

Les identifiants de connexion ne sont pas stockés dans le code. Ils sont externalisés dans un fichier `.env` exclu du dépôt via `.gitignore`, conformément aux bonnes pratiques de gestion des secrets. Le fichier `.env.example` documente la structure attendue sans révéler aucune valeur réelle.

## Visualisation du graphe

Après exécution, ouvrir AuraDB et lancer dans l'éditeur Query :

```cypher
MATCH (n) RETURN n;
```

Puis basculer sur la vue **Graph** pour visualiser et capturer le graphe.

Pour une capture lisible de la segmentation réseau seule :

```cypher
MATCH p=(:Machine)-[:IN_VLAN]->(:VLAN)<-[:PROTECTS]-(:Firewall) RETURN p;
```

## Structure du dépôt

| Fichier | Rôle |
|---------|------|
| `projetnosql.py` | Script principal de construction et d'analyse du graphe |
| `requirements.txt` | Dépendances Python |
| `.env.example` | Modèle de configuration (à copier en `.env`) |
| `.gitignore` | Exclut le `.env` et les fichiers temporaires |
| `README.md` | Ce fichier |
