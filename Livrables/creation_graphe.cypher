// ============================================================
// PROJET B3 CYBER - CyberCorp - Livrable 1
// Scripts Cypher de creation (noeuds + relations)
// A coller dans l'editeur Query de Neo4j AuraDB
// ============================================================


// ============================================================
// ETAPE 0 - NETTOYAGE (repartir d'une base vide)
// ============================================================

MATCH (n) DETACH DELETE n;


// ============================================================
// ETAPE 1 - CONTRAINTES D'UNICITE (equivalent cle primaire)
// ============================================================

CREATE CONSTRAINT user_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE;
CREATE CONSTRAINT machine_name IF NOT EXISTS FOR (m:Machine) REQUIRE m.name IS UNIQUE;
CREATE CONSTRAINT service_name IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE;
CREATE CONSTRAINT vuln_cve IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve IS UNIQUE;
CREATE CONSTRAINT group_name IF NOT EXISTS FOR (g:Group) REQUIRE g.name IS UNIQUE;
CREATE CONSTRAINT resource_name IF NOT EXISTS FOR (r:Resource) REQUIRE r.name IS UNIQUE;
CREATE CONSTRAINT vlan_name IF NOT EXISTS FOR (v:VLAN) REQUIRE v.name IS UNIQUE;
CREATE CONSTRAINT firewall_name IF NOT EXISTS FOR (f:Firewall) REQUIRE f.name IS UNIQUE;
CREATE CONSTRAINT svcacct_name IF NOT EXISTS FOR (s:ServiceAccount) REQUIRE s.name IS UNIQUE;
CREATE CONSTRAINT adright_name IF NOT EXISTS FOR (a:ADRight) REQUIRE a.name IS UNIQUE;
CREATE CONSTRAINT vpn_name IF NOT EXISTS FOR (v:VPNAccess) REQUIRE v.name IS UNIQUE;
CREATE CONSTRAINT internet_name IF NOT EXISTS FOR (i:Internet) REQUIRE i.name IS UNIQUE;
CREATE CONSTRAINT priv_name IF NOT EXISTS FOR (p:PrivilegeLevel) REQUIRE p.name IS UNIQUE;
CREATE CONSTRAINT log_id IF NOT EXISTS FOR (l:LoginLog) REQUIRE l.id IS UNIQUE;


// ============================================================
// ETAPE 2 - CREATION DES NOEUDS
// ============================================================

// --- Utilisateurs ---
CREATE (:User {name: "alice",   role: "RH",            privilege: "standard"});
CREATE (:User {name: "bob",     role: "Developpeur",   privilege: "standard"});
CREATE (:User {name: "charlie", role: "Admin Systeme", privilege: "admin"});
CREATE (:User {name: "diana",   role: "RSSI",          privilege: "admin"});
CREATE (:User {name: "eve",     role: "Stagiaire",     privilege: "standard"});

// --- Machines ---
CREATE (:Machine {name: "PC-ALICE",   type: "workstation",       criticality: "low",      last_patch_date: "2025-01-15"});
CREATE (:Machine {name: "PC-BOB",     type: "workstation",       criticality: "medium",   last_patch_date: "2024-11-03"});
CREATE (:Machine {name: "SRV-WEB",    type: "server",            criticality: "medium",   last_patch_date: "2024-08-20"});
CREATE (:Machine {name: "SRV-DB",     type: "database",          criticality: "high",     last_patch_date: "2025-02-10"});
CREATE (:Machine {name: "DC-01",      type: "domain_controller", criticality: "critical", last_patch_date: "2024-06-01"});
CREATE (:Machine {name: "NAS-BACKUP", type: "backup_server",     criticality: "critical", last_patch_date: "2024-09-12"});

// --- Services ---
CREATE (:Service {name: "SSH",     port: 22});
CREATE (:Service {name: "HTTP",    port: 80});
CREATE (:Service {name: "HTTPS",   port: 443});
CREATE (:Service {name: "RDP",     port: 3389});
CREATE (:Service {name: "SMB",     port: 445});
CREATE (:Service {name: "MongoDB", port: 27017});

// --- Vulnerabilites ---
CREATE (:Vulnerability {cve: "CVE-2021-44228", name: "Log4Shell",            score: 10.0, patch_status: "non corrige", description: "Execution de code a distance via Log4j"});
CREATE (:Vulnerability {cve: "CVE-2020-1472",  name: "Zerologon",            score: 10.0, patch_status: "non corrige", description: "Elevation de privileges sur controleur de domaine"});
CREATE (:Vulnerability {cve: "CVE-2019-0708",  name: "BlueKeep",             score: 9.8,  patch_status: "corrige",     description: "Execution de code a distance via RDP"});
CREATE (:Vulnerability {cve: "CVE-2022-22965", name: "Spring4Shell",         score: 9.8,  patch_status: "non corrige", description: "Execution de code a distance sur application Spring"});
CREATE (:Vulnerability {cve: "CVE-2023-0001",  name: "SMB Misconfiguration", score: 7.5,  patch_status: "en cours",    description: "Mauvaise configuration du partage SMB"});

// --- Groupes ---
CREATE (:Group {name: "RH"});
CREATE (:Group {name: "DEV"});
CREATE (:Group {name: "ADMINS"});
CREATE (:Group {name: "SECURITY"});

// --- Ressources ---
CREATE (:Resource {name: "Base clients",        sensitivity: "high"});
CREATE (:Resource {name: "Donnees RH",          sensitivity: "high"});
CREATE (:Resource {name: "Active Directory",    sensitivity: "critical"});
CREATE (:Resource {name: "Sauvegardes",         sensitivity: "critical"});
CREATE (:Resource {name: "Secrets applicatifs", sensitivity: "critical"});

// --- VLAN (segments reseau) ---
CREATE (:VLAN {name: "VLAN-USERS", vlan_id: 10, zone: "utilisateurs"});
CREATE (:VLAN {name: "VLAN-DMZ",   vlan_id: 20, zone: "dmz"});
CREATE (:VLAN {name: "VLAN-DB",    vlan_id: 30, zone: "donnees"});
CREATE (:VLAN {name: "VLAN-ADMIN", vlan_id: 40, zone: "administration"});

// --- Pare-feux ---
CREATE (:Firewall {name: "FW-PERIMETER", type: "perimetre"});
CREATE (:Firewall {name: "FW-INTERNAL",  type: "interne"});

// --- Comptes de service ---
CREATE (:ServiceAccount {name: "svc-web",    description: "compte de service application web"});
CREATE (:ServiceAccount {name: "svc-backup", description: "compte de service sauvegarde"});
CREATE (:ServiceAccount {name: "svc-sql",    description: "compte de service base de donnees"});

// --- Droits Active Directory ---
CREATE (:ADRight {name: "DCSync",        level: "critical", description: "replication des secrets du domaine"});
CREATE (:ADRight {name: "GenericAll",    level: "critical", description: "controle total sur un objet AD"});
CREATE (:ADRight {name: "ResetPassword", level: "high",     description: "reinitialisation de mot de passe"});

// --- Acces VPN ---
CREATE (:VPNAccess {name: "VPN-NOMADE", type: "acces distant collaborateurs"});
CREATE (:VPNAccess {name: "VPN-ADMIN",  type: "acces distant administrateurs"});

// --- Internet (point d'exposition externe) ---
CREATE (:Internet {name: "INTERNET", zone: "externe"});

// --- Niveaux de privilege ---
CREATE (:PrivilegeLevel {name: "standard",     rank: 1});
CREATE (:PrivilegeLevel {name: "admin",        rank: 3});
CREATE (:PrivilegeLevel {name: "domain_admin", rank: 5});

// --- Logs de connexion (les echecs sont une propriete du log) ---
CREATE (:LoginLog {id: "log-001", status: "success", failed_attempts: 0,  timestamp: "2025-06-01T08:12:00"});
CREATE (:LoginLog {id: "log-002", status: "failed",  failed_attempts: 5,  timestamp: "2025-06-01T09:47:00"});
CREATE (:LoginLog {id: "log-003", status: "success", failed_attempts: 0,  timestamp: "2025-06-01T10:03:00"});
CREATE (:LoginLog {id: "log-004", status: "success", failed_attempts: 0,  timestamp: "2025-06-01T11:25:00"});
CREATE (:LoginLog {id: "log-005", status: "failed",  failed_attempts: 12, timestamp: "2025-06-01T23:58:00"});


// ============================================================
// ETAPE 3 - CREATION DES RELATIONS
// ============================================================

// --- USES : un utilisateur utilise une machine ---
MATCH (u:User {name: "alice"}),   (m:Machine {name: "PC-ALICE"}) CREATE (u)-[:USES]->(m);
MATCH (u:User {name: "bob"}),     (m:Machine {name: "PC-BOB"})   CREATE (u)-[:USES]->(m);
MATCH (u:User {name: "charlie"}), (m:Machine {name: "DC-01"})    CREATE (u)-[:USES]->(m);
MATCH (u:User {name: "diana"}),   (m:Machine {name: "PC-BOB"})   CREATE (u)-[:USES]->(m);
MATCH (u:User {name: "eve"}),     (m:Machine {name: "PC-ALICE"}) CREATE (u)-[:USES]->(m);

// --- MEMBER_OF : un utilisateur appartient a un groupe ---
MATCH (u:User {name: "alice"}),   (g:Group {name: "RH"})       CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name: "bob"}),     (g:Group {name: "DEV"})      CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name: "charlie"}), (g:Group {name: "ADMINS"})   CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name: "diana"}),   (g:Group {name: "SECURITY"}) CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name: "eve"}),     (g:Group {name: "DEV"})      CREATE (u)-[:MEMBER_OF]->(g);

// --- ADMIN_OF : droits administrateur sur une machine ---
MATCH (u:User {name: "charlie"}), (m:Machine {name: "DC-01"})      CREATE (u)-[:ADMIN_OF]->(m);
MATCH (u:User {name: "charlie"}), (m:Machine {name: "NAS-BACKUP"}) CREATE (u)-[:ADMIN_OF]->(m);
MATCH (u:User {name: "charlie"}), (m:Machine {name: "SRV-DB"})     CREATE (u)-[:ADMIN_OF]->(m);

// --- CONNECTED_TO : connexions reseau (chemins d'attaque) ---
MATCH (a:Machine {name: "PC-ALICE"}), (b:Machine {name: "SRV-WEB"})    CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "PC-BOB"}),   (b:Machine {name: "SRV-WEB"})    CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "SRV-WEB"}),  (b:Machine {name: "SRV-DB"})     CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "SRV-DB"}),   (b:Machine {name: "DC-01"})      CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "SRV-DB"}),   (b:Machine {name: "NAS-BACKUP"}) CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "PC-ALICE"}), (b:Machine {name: "PC-BOB"})     CREATE (a)-[:CONNECTED_TO]->(b);

// --- EXPOSES : une machine expose un service ---
MATCH (m:Machine {name: "SRV-WEB"}),    (s:Service {name: "HTTP"})    CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "SRV-WEB"}),    (s:Service {name: "HTTPS"})   CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "SRV-DB"}),     (s:Service {name: "MongoDB"}) CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "DC-01"}),      (s:Service {name: "SMB"})     CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "PC-BOB"}),     (s:Service {name: "RDP"})     CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "NAS-BACKUP"}), (s:Service {name: "SMB"})     CREATE (m)-[:EXPOSES]->(s);

// --- HAS_VULNERABILITY : une machine porte une vulnerabilite ---
MATCH (m:Machine {name: "SRV-WEB"}),    (v:Vulnerability {cve: "CVE-2021-44228"}) CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "SRV-WEB"}),    (v:Vulnerability {cve: "CVE-2022-22965"}) CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "PC-BOB"}),     (v:Vulnerability {cve: "CVE-2019-0708"})  CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "DC-01"}),      (v:Vulnerability {cve: "CVE-2020-1472"})  CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "NAS-BACKUP"}), (v:Vulnerability {cve: "CVE-2023-0001"})  CREATE (m)-[:HAS_VULNERABILITY]->(v);

// --- HAS_ACCESS_TO : un groupe a acces a une machine ---
MATCH (g:Group {name: "RH"}),     (m:Machine {name: "SRV-WEB"})    CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "DEV"}),    (m:Machine {name: "SRV-DB"})     CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "ADMINS"}), (m:Machine {name: "DC-01"})      CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "ADMINS"}), (m:Machine {name: "NAS-BACKUP"}) CREATE (g)-[:HAS_ACCESS_TO]->(m);

// --- HOSTS : une machine heberge une ressource ---
MATCH (m:Machine {name: "SRV-DB"}),     (r:Resource {name: "Base clients"})        CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name: "SRV-DB"}),     (r:Resource {name: "Secrets applicatifs"}) CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name: "DC-01"}),      (r:Resource {name: "Active Directory"})    CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name: "NAS-BACKUP"}), (r:Resource {name: "Sauvegardes"})         CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name: "SRV-WEB"}),    (r:Resource {name: "Donnees RH"})          CREATE (m)-[:HOSTS]->(r);

// --- IN_VLAN : une machine appartient a un segment reseau ---
MATCH (m:Machine {name: "PC-ALICE"}),   (v:VLAN {name: "VLAN-USERS"}) CREATE (m)-[:IN_VLAN]->(v);
MATCH (m:Machine {name: "PC-BOB"}),     (v:VLAN {name: "VLAN-USERS"}) CREATE (m)-[:IN_VLAN]->(v);
MATCH (m:Machine {name: "SRV-WEB"}),    (v:VLAN {name: "VLAN-DMZ"})   CREATE (m)-[:IN_VLAN]->(v);
MATCH (m:Machine {name: "SRV-DB"}),     (v:VLAN {name: "VLAN-DB"})    CREATE (m)-[:IN_VLAN]->(v);
MATCH (m:Machine {name: "DC-01"}),      (v:VLAN {name: "VLAN-ADMIN"}) CREATE (m)-[:IN_VLAN]->(v);
MATCH (m:Machine {name: "NAS-BACKUP"}), (v:VLAN {name: "VLAN-ADMIN"}) CREATE (m)-[:IN_VLAN]->(v);

// --- PROTECTS : un pare-feu protege un segment ---
MATCH (f:Firewall {name: "FW-PERIMETER"}), (v:VLAN {name: "VLAN-DMZ"})   CREATE (f)-[:PROTECTS]->(v);
MATCH (f:Firewall {name: "FW-INTERNAL"}),  (v:VLAN {name: "VLAN-USERS"}) CREATE (f)-[:PROTECTS]->(v);
MATCH (f:Firewall {name: "FW-INTERNAL"}),  (v:VLAN {name: "VLAN-DB"})    CREATE (f)-[:PROTECTS]->(v);
MATCH (f:Firewall {name: "FW-INTERNAL"}),  (v:VLAN {name: "VLAN-ADMIN"}) CREATE (f)-[:PROTECTS]->(v);

// --- ALLOWED_TO : flux inter-VLAN autorise par les pare-feux ---
MATCH (a:VLAN {name: "VLAN-USERS"}), (b:VLAN {name: "VLAN-DMZ"})   CREATE (a)-[:ALLOWED_TO]->(b);
MATCH (a:VLAN {name: "VLAN-DMZ"}),   (b:VLAN {name: "VLAN-DB"})    CREATE (a)-[:ALLOWED_TO]->(b);
MATCH (a:VLAN {name: "VLAN-ADMIN"}), (b:VLAN {name: "VLAN-DB"})    CREATE (a)-[:ALLOWED_TO]->(b);
MATCH (a:VLAN {name: "VLAN-ADMIN"}), (b:VLAN {name: "VLAN-ADMIN"}) CREATE (a)-[:ALLOWED_TO]->(b);

// --- RUNS_AS : une machine execute un compte de service ---
MATCH (m:Machine {name: "SRV-WEB"}),    (s:ServiceAccount {name: "svc-web"})    CREATE (m)-[:RUNS_AS]->(s);
MATCH (m:Machine {name: "NAS-BACKUP"}), (s:ServiceAccount {name: "svc-backup"}) CREATE (m)-[:RUNS_AS]->(s);
MATCH (m:Machine {name: "SRV-DB"}),     (s:ServiceAccount {name: "svc-sql"})    CREATE (m)-[:RUNS_AS]->(s);

// --- HAS_AD_RIGHT : un utilisateur ou compte de service detient un droit AD ---
MATCH (n {name: "svc-web"}), (a:ADRight {name: "ResetPassword"}) CREATE (n)-[:HAS_AD_RIGHT]->(a);
MATCH (n {name: "charlie"}), (a:ADRight {name: "DCSync"})        CREATE (n)-[:HAS_AD_RIGHT]->(a);
MATCH (n {name: "charlie"}), (a:ADRight {name: "GenericAll"})    CREATE (n)-[:HAS_AD_RIGHT]->(a);
MATCH (n {name: "eve"}),     (a:ADRight {name: "ResetPassword"}) CREATE (n)-[:HAS_AD_RIGHT]->(a);

// --- AD_RIGHT_ON : un droit AD s'applique a une ressource ---
MATCH (a:ADRight {name: "DCSync"}),        (r:Resource {name: "Active Directory"}) CREATE (a)-[:AD_RIGHT_ON]->(r);
MATCH (a:ADRight {name: "GenericAll"}),    (r:Resource {name: "Active Directory"}) CREATE (a)-[:AD_RIGHT_ON]->(r);
MATCH (a:ADRight {name: "ResetPassword"}), (r:Resource {name: "Active Directory"}) CREATE (a)-[:AD_RIGHT_ON]->(r);

// --- GRANTS_ACCESS_TO : un acces VPN ouvre un segment ---
MATCH (v:VPNAccess {name: "VPN-NOMADE"}), (vl:VLAN {name: "VLAN-USERS"}) CREATE (v)-[:GRANTS_ACCESS_TO]->(vl);
MATCH (v:VPNAccess {name: "VPN-ADMIN"}),  (vl:VLAN {name: "VLAN-ADMIN"}) CREATE (v)-[:GRANTS_ACCESS_TO]->(vl);

// --- USES_VPN : un utilisateur utilise un acces VPN ---
MATCH (u:User {name: "alice"}),   (v:VPNAccess {name: "VPN-NOMADE"}) CREATE (u)-[:USES_VPN]->(v);
MATCH (u:User {name: "eve"}),     (v:VPNAccess {name: "VPN-NOMADE"}) CREATE (u)-[:USES_VPN]->(v);
MATCH (u:User {name: "charlie"}), (v:VPNAccess {name: "VPN-ADMIN"})  CREATE (u)-[:USES_VPN]->(v);
MATCH (u:User {name: "diana"}),   (v:VPNAccess {name: "VPN-ADMIN"})  CREATE (u)-[:USES_VPN]->(v);

// --- EXPOSED_TO_INTERNET : une machine ou un VPN est expose a Internet ---
MATCH (n {name: "SRV-WEB"}),    (i:Internet {name: "INTERNET"}) CREATE (n)-[:EXPOSED_TO_INTERNET]->(i);
MATCH (n {name: "VPN-NOMADE"}), (i:Internet {name: "INTERNET"}) CREATE (n)-[:EXPOSED_TO_INTERNET]->(i);
MATCH (n {name: "VPN-ADMIN"}),  (i:Internet {name: "INTERNET"}) CREATE (n)-[:EXPOSED_TO_INTERNET]->(i);

// --- HAS_PRIVILEGE : un utilisateur possede un niveau de privilege ---
MATCH (u:User {name: "alice"}),   (p:PrivilegeLevel {name: "standard"}) CREATE (u)-[:HAS_PRIVILEGE]->(p);
MATCH (u:User {name: "bob"}),     (p:PrivilegeLevel {name: "standard"}) CREATE (u)-[:HAS_PRIVILEGE]->(p);
MATCH (u:User {name: "eve"}),     (p:PrivilegeLevel {name: "standard"}) CREATE (u)-[:HAS_PRIVILEGE]->(p);
MATCH (u:User {name: "charlie"}), (p:PrivilegeLevel {name: "admin"})    CREATE (u)-[:HAS_PRIVILEGE]->(p);
MATCH (u:User {name: "diana"}),   (p:PrivilegeLevel {name: "admin"})    CREATE (u)-[:HAS_PRIVILEGE]->(p);

// --- DEPENDS_ON : dependance applicative entre machines ---
MATCH (a:Machine {name: "SRV-WEB"}),    (b:Machine {name: "SRV-DB"}) CREATE (a)-[:DEPENDS_ON]->(b);
MATCH (a:Machine {name: "SRV-DB"}),     (b:Machine {name: "DC-01"})  CREATE (a)-[:DEPENDS_ON]->(b);
MATCH (a:Machine {name: "NAS-BACKUP"}), (b:Machine {name: "DC-01"})  CREATE (a)-[:DEPENDS_ON]->(b);

// --- LOGIN_ON : un log de connexion concerne une machine ---
MATCH (l:LoginLog {id: "log-001"}), (m:Machine {name: "PC-ALICE"}) CREATE (l)-[:LOGIN_ON]->(m);
MATCH (l:LoginLog {id: "log-002"}), (m:Machine {name: "PC-ALICE"}) CREATE (l)-[:LOGIN_ON]->(m);
MATCH (l:LoginLog {id: "log-003"}), (m:Machine {name: "SRV-WEB"})  CREATE (l)-[:LOGIN_ON]->(m);
MATCH (l:LoginLog {id: "log-004"}), (m:Machine {name: "DC-01"})    CREATE (l)-[:LOGIN_ON]->(m);
MATCH (l:LoginLog {id: "log-005"}), (m:Machine {name: "DC-01"})    CREATE (l)-[:LOGIN_ON]->(m);

// --- LOGIN_BY : un log de connexion concerne un utilisateur ---
MATCH (l:LoginLog {id: "log-001"}), (u:User {name: "alice"})   CREATE (l)-[:LOGIN_BY]->(u);
MATCH (l:LoginLog {id: "log-002"}), (u:User {name: "eve"})     CREATE (l)-[:LOGIN_BY]->(u);
MATCH (l:LoginLog {id: "log-004"}), (u:User {name: "charlie"}) CREATE (l)-[:LOGIN_BY]->(u);
MATCH (l:LoginLog {id: "log-005"}), (u:User {name: "eve"})     CREATE (l)-[:LOGIN_BY]->(u);


// ============================================================
// ETAPE 4 - VERIFICATION
// ============================================================

// Compter les noeuds par type
MATCH (n) RETURN labels(n)[0] AS type, count(*) AS nombre ORDER BY type;

// Compter les relations par type
MATCH ()-[r]->() RETURN type(r) AS relation, count(*) AS nombre ORDER BY relation;
