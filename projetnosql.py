from neo4j import GraphDatabase


URI = "neo4j+s://815ec735.databases.neo4j.io"  
AUTH = ("815ec735", "E5alzUXFiQgy8gYzTLJPcZ0W6pRzwztDBpyxw6q7Has")            

driver = GraphDatabase.driver(URI, auth=AUTH)

users = [
    {"name": "alice",   "role": "RH"},
    {"name": "bob",     "role": "Developpeur"},
    {"name": "charlie", "role": "Admin Systeme"},
    {"name": "diana",   "role": "RSSI"},
    {"name": "eve",     "role": "Stagiaire"},
]

machines = [
    {"name": "PC-ALICE",   "type": "workstation",       "criticality": "low"},
    {"name": "PC-BOB",     "type": "workstation",       "criticality": "medium"},
    {"name": "SRV-WEB",    "type": "server",            "criticality": "medium"},
    {"name": "SRV-DB",     "type": "database",          "criticality": "high"},
    {"name": "DC-01",      "type": "domain_controller", "criticality": "critical"},
    {"name": "NAS-BACKUP", "type": "backup_server",     "criticality": "critical"},
]

services = [
    {"name": "SSH",     "port": 22},
    {"name": "HTTP",    "port": 80},
    {"name": "HTTPS",   "port": 443},
    {"name": "RDP",     "port": 3389},
    {"name": "SMB",     "port": 445},
    {"name": "MongoDB", "port": 27017},
]

vulnerabilities = [
    {"cve": "CVE-2021-44228", "name": "Log4Shell",            "score": 10.0, "description": "Execution de code a distance via Log4j"},
    {"cve": "CVE-2020-1472",  "name": "Zerologon",            "score": 10.0, "description": "Elevation de privileges sur controleur de domaine"},
    {"cve": "CVE-2019-0708",  "name": "BlueKeep",             "score": 9.8,  "description": "Execution de code a distance via RDP"},
    {"cve": "CVE-2022-22965", "name": "Spring4Shell",         "score": 9.8,  "description": "Execution de code a distance sur application Spring"},
    {"cve": "CVE-2023-0001",  "name": "SMB Misconfiguration", "score": 7.5,  "description": "Mauvaise configuration du partage SMB"},
]

groups = [
    {"name": "RH"},
    {"name": "DEV"},
    {"name": "ADMINS"},
    {"name": "SECURITY"},
]

resources = [
    {"name": "Base clients",        "sensitivity": "high"},
    {"name": "Donnees RH",          "sensitivity": "high"},
    {"name": "Active Directory",    "sensitivity": "critical"},
    {"name": "Sauvegardes",         "sensitivity": "critical"},
    {"name": "Secrets applicatifs", "sensitivity": "critical"},
]


rel_uses = [          
    ("alice", "PC-ALICE"), ("bob", "PC-BOB"), ("charlie", "DC-01"),
    ("diana", "PC-BOB"), ("eve", "PC-ALICE"),
]

rel_member_of = [     
    ("alice", "RH"), ("bob", "DEV"), ("charlie", "ADMINS"),
    ("diana", "SECURITY"), ("eve", "DEV"),
]

rel_admin_of = [     
    ("charlie", "DC-01"), ("charlie", "NAS-BACKUP"), ("charlie", "SRV-DB"),
]

rel_connected_to = [  
    ("PC-ALICE", "SRV-WEB"), ("PC-BOB", "SRV-WEB"), ("SRV-WEB", "SRV-DB"),
    ("SRV-DB", "DC-01"), ("SRV-DB", "NAS-BACKUP"), ("PC-ALICE", "PC-BOB"),
]

rel_exposes = [       
    ("SRV-WEB", "HTTP"), ("SRV-WEB", "HTTPS"), ("SRV-DB", "MongoDB"),
    ("DC-01", "SMB"), ("PC-BOB", "RDP"), ("NAS-BACKUP", "SMB"),
]

rel_has_vuln = [      
    ("SRV-WEB", "CVE-2021-44228"), ("SRV-WEB", "CVE-2022-22965"),
    ("PC-BOB", "CVE-2019-0708"), ("DC-01", "CVE-2020-1472"),
    ("NAS-BACKUP", "CVE-2023-0001"),
]

rel_has_access = [  
    ("RH", "SRV-WEB"), ("DEV", "SRV-DB"),
    ("ADMINS", "DC-01"), ("ADMINS", "NAS-BACKUP"),
]

rel_hosts = [         
    ("SRV-DB", "Base clients"), ("SRV-DB", "Secrets applicatifs"),
    ("DC-01", "Active Directory"), ("NAS-BACKUP", "Sauvegardes"),
    ("SRV-WEB", "Donnees RH"),
]


def reset_db(tx):
    """Vide entierement la base pour repartir propre."""
    tx.run("MATCH (n) DETACH DELETE n")


def create_constraints(tx):
    """Contraintes d'unicite : evite les doublons et accelere les MATCH."""
    tx.run("CREATE CONSTRAINT user_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT machine_name IF NOT EXISTS FOR (m:Machine) REQUIRE m.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT service_name IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT vuln_cve IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve IS UNIQUE")
    tx.run("CREATE CONSTRAINT group_name IF NOT EXISTS FOR (g:Group) REQUIRE g.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT resource_name IF NOT EXISTS FOR (r:Resource) REQUIRE r.name IS UNIQUE")


def create_nodes(tx):
    """Cree tous les noeuds via UNWIND (une requete par type de noeud)."""
    tx.run("UNWIND $rows AS row CREATE (:User {name: row.name, role: row.role})", rows=users)
    tx.run("UNWIND $rows AS row CREATE (:Machine {name: row.name, type: row.type, criticality: row.criticality})", rows=machines)
    tx.run("UNWIND $rows AS row CREATE (:Service {name: row.name, port: row.port})", rows=services)
    tx.run("UNWIND $rows AS row CREATE (:Vulnerability {cve: row.cve, name: row.name, score: row.score, description: row.description})", rows=vulnerabilities)
    tx.run("UNWIND $rows AS row CREATE (:Group {name: row.name})", rows=groups)
    tx.run("UNWIND $rows AS row CREATE (:Resource {name: row.name, sensitivity: row.sensitivity})", rows=resources)


def create_relationships(tx):
    """Cree toutes les relations via UNWIND (une requete par type de relation)."""
   
    def pairs(data):
        return [{"a": a, "b": b} for a, b in data]

    tx.run("""UNWIND $rows AS r
              MATCH (u:User {name:r.a}),(m:Machine {name:r.b})
              CREATE (u)-[:USES]->(m)""", rows=pairs(rel_uses))

    tx.run("""UNWIND $rows AS r
              MATCH (u:User {name:r.a}),(g:Group {name:r.b})
              CREATE (u)-[:MEMBER_OF]->(g)""", rows=pairs(rel_member_of))

    tx.run("""UNWIND $rows AS r
              MATCH (u:User {name:r.a}),(m:Machine {name:r.b})
              CREATE (u)-[:ADMIN_OF]->(m)""", rows=pairs(rel_admin_of))

    tx.run("""UNWIND $rows AS r
              MATCH (a:Machine {name:r.a}),(b:Machine {name:r.b})
              CREATE (a)-[:CONNECTED_TO]->(b)""", rows=pairs(rel_connected_to))

    tx.run("""UNWIND $rows AS r
              MATCH (m:Machine {name:r.a}),(s:Service {name:r.b})
              CREATE (m)-[:EXPOSES]->(s)""", rows=pairs(rel_exposes))

    tx.run("""UNWIND $rows AS r
              MATCH (m:Machine {name:r.a}),(v:Vulnerability {cve:r.b})
              CREATE (m)-[:HAS_VULNERABILITY]->(v)""", rows=pairs(rel_has_vuln))

    tx.run("""UNWIND $rows AS r
              MATCH (g:Group {name:r.a}),(m:Machine {name:r.b})
              CREATE (g)-[:HAS_ACCESS_TO]->(m)""", rows=pairs(rel_has_access))

    tx.run("""UNWIND $rows AS r
              MATCH (m:Machine {name:r.a}),(res:Resource {name:r.b})
              CREATE (m)-[:HOSTS]->(res)""", rows=pairs(rel_hosts))


def compute_risk_scores(tx):
    """BONUS : calcule un score de risque par machine et le stocke."""
    tx.run("""
        MATCH (m:Machine)
        OPTIONAL MATCH (m)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        OPTIONAL MATCH (m)-[:EXPOSES]->(s:Service)
        WITH m,
             CASE m.criticality
               WHEN "critical" THEN 40
               WHEN "high" THEN 30
               WHEN "medium" THEN 15
               ELSE 5
             END AS poids_criticite,
             coalesce(sum(DISTINCT v.score), 0) AS somme_vulns,
             count(DISTINCT s) AS nb_services
        WITH m, poids_criticite + somme_vulns + (nb_services * 3) AS score
        SET m.risk_score = score
    """)


def count_nodes_and_rels(tx):
    nodes = tx.run("MATCH (n) RETURN count(n) AS c").single()["c"]
    rels = tx.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
    return nodes, rels


def paths_to_critical_machines(tx):
    result = tx.run("""
        MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(t:Machine)
        WHERE t.criticality = "critical"
        RETURN t.name AS cible,
               length(path) AS sauts,
               [n IN nodes(path) | n.name] AS chemin
        ORDER BY sauts
    """)
    return [(r["cible"], r["sauts"], r["chemin"]) for r in result]


def reachable_resources(tx):
    result = tx.run("""
        MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HOSTS]->(r:Resource)
        RETURN r.name AS ressource,
               r.sensitivity AS sensibilite,
               m.name AS hebergee_sur,
               [n IN nodes(path) | n.name] AS chemin
        ORDER BY r.sensitivity DESC
    """)
    return [(r["ressource"], r["sensibilite"], r["hebergee_sur"], r["chemin"]) for r in result]


def vulnerable_machines_on_path(tx):
    result = tx.run("""
        MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN DISTINCT m.name AS machine,
               v.cve AS cve,
               v.name AS vulnerabilite,
               v.score AS score
        ORDER BY score DESC
    """)
    return [(r["machine"], r["cve"], r["vulnerabilite"], r["score"]) for r in result]


def risky_users(tx):
    result = tx.run("""
        MATCH (u:User)-[:MEMBER_OF]->(g:Group)-[:HAS_ACCESS_TO]->(m:Machine)
        WHERE m.criticality IN ["high", "critical"]
        RETURN u.name AS utilisateur,
               g.name AS groupe,
               m.name AS machine,
               m.criticality AS criticite
        ORDER BY m.criticality DESC
    """)
    return [(r["utilisateur"], r["groupe"], r["machine"], r["criticite"]) for r in result]


def risk_ranking(tx):
    result = tx.run("""
        MATCH (m:Machine)
        RETURN m.name AS machine, m.criticality AS criticite, m.risk_score AS score
        ORDER BY score DESC
    """)
    return [(r["machine"], r["criticite"], r["score"]) for r in result]


def ligne(titre):
    print("\n" + "=" * 60)
    print(titre)
    print("=" * 60)


with driver.session() as session:
    
    print("Construction du graphe CyberCorp...")
    session.execute_write(reset_db)
    session.execute_write(create_constraints)
    session.execute_write(create_nodes)
    session.execute_write(create_relationships)
    session.execute_write(compute_risk_scores)

    nb_nodes, nb_rels = session.execute_read(count_nodes_and_rels)
    print(f"Graphe construit : {nb_nodes} noeuds, {nb_rels} relations.")

    ligne("CHEMINS D'ATTAQUE VERS LES MACHINES CRITIQUES")
    for cible, sauts, chemin in session.execute_read(paths_to_critical_machines):
        print(f"  -> {cible} ({sauts} sauts) : {' -> '.join(chemin)}")

    ligne("RESSOURCES SENSIBLES ACCESSIBLES DEPUIS PC-ALICE")
    for ressource, sens, machine, chemin in session.execute_read(reachable_resources):
        print(f"  -> {ressource} [{sens}] hebergee sur {machine}")
        print(f"     chemin : {' -> '.join(chemin)}")

    ligne("MACHINES VULNERABLES SUR LE CHEMIN D'ATTAQUE")
    for machine, cve, vuln, score in session.execute_read(vulnerable_machines_on_path):
        print(f"  -> {machine} : {cve} ({vuln}) score {score}")

    ligne("UTILISATEURS / GROUPES A RISQUE")
    for user, groupe, machine, crit in session.execute_read(risky_users):
        print(f"  -> {user} (groupe {groupe}) accede a {machine} [{crit}]")

    ligne("SCORING DE RISQUE PAR MACHINE (BONUS)")
    for machine, crit, score in session.execute_read(risk_ranking):
        print(f"  -> {machine:<12} [{crit:<8}] score de risque = {score}")

driver.close()
print("\nTermine. Ouvre AuraDB et lance  MATCH (n) RETURN n;  pour la capture du graphe.")
