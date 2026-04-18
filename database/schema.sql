-- =============================================================
-- APT Watch Intelligence Database — Schema v3
-- Full-coverage threat intelligence database with weighted
-- scoring, lifecycle management, and OSINT feed integration.
-- =============================================================
--
-- Usage (fresh database):
--   sqlite3 apt_intel.db < database/schema.sql
--
-- =============================================================

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- =============================================================
-- IOC TABLES
-- =============================================================

CREATE TABLE IF NOT EXISTS ipv4_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    last_seen TEXT,
    pulse_count INTEGER DEFAULT 1,
    threat_types TEXT,
    source_pulses TEXT,
    infra_type TEXT DEFAULT 'unknown',
    last_validated TEXT,
    validation_count INTEGER DEFAULT 0,
    validation_sources TEXT DEFAULT '{}',
    validation_status TEXT DEFAULT 'unvalidated',
    -- v3: scoring
    composite_score REAL DEFAULT 0.0,
    infrastructure_risk_score REAL DEFAULT 0.0,
    actor_attribution_score REAL DEFAULT 0.0,
    actor_attribution_actor TEXT,
    score_timestamp TEXT,
    provider_risk_level TEXT DEFAULT 'unknown',
    -- v3: lifecycle
    lifecycle_state TEXT DEFAULT 'active',
    decay_multiplier REAL DEFAULT 1.0,
    lifecycle_assessed_at TEXT,
    -- v3: STIX
    stix_id TEXT,
    mitre_techniques TEXT,          -- JSON array: ["T1071", "T1190"]
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ipv4_ip ON ipv4_iocs(ip);
CREATE INDEX IF NOT EXISTS idx_ipv4_infra ON ipv4_iocs(infra_type);
CREATE INDEX IF NOT EXISTS idx_ipv4_validation ON ipv4_iocs(validation_status, last_validated);
CREATE INDEX IF NOT EXISTS idx_ipv4_composite ON ipv4_iocs(composite_score DESC);
CREATE INDEX IF NOT EXISTS idx_ipv4_infra_risk ON ipv4_iocs(infrastructure_risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_ipv4_lifecycle ON ipv4_iocs(lifecycle_state);

CREATE TABLE IF NOT EXISTS ipv6_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    last_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ipv6_ip ON ipv6_iocs(ip);

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_domain ON domains(domain);

CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    host TEXT,
    port INTEGER,
    path TEXT,
    source_file TEXT,
    first_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_url ON urls(url);
CREATE INDEX IF NOT EXISTS idx_url_host ON urls(host);

CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_cve ON cves(cve_id);

CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    domain TEXT,
    source_file TEXT,
    first_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_email ON emails(email);
CREATE INDEX IF NOT EXISTS idx_email_domain ON emails(domain);

CREATE TABLE IF NOT EXISTS cidr_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_cidr_ioc ON cidr_iocs(cidr);

-- =============================================================
-- INFRASTRUCTURE TABLES
-- =============================================================

CREATE TABLE IF NOT EXISTS subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL UNIQUE,
    ioc_count INTEGER DEFAULT 0,
    scanned_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    asn INTEGER,
    asn_org TEXT,
    country TEXT,
    tier TEXT,
    scan_status TEXT DEFAULT 'UNSCANNED',
    first_ioc_date TEXT,
    last_scan_date TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_subnets_cidr ON subnets(cidr);
CREATE INDEX IF NOT EXISTS idx_subnets_tier ON subnets(tier);
CREATE INDEX IF NOT EXISTS idx_subnets_asn ON subnets(asn);

CREATE TABLE IF NOT EXISTS asn_info (
    asn INTEGER PRIMARY KEY,
    org_name TEXT,
    country TEXT,
    subnet_count INTEGER DEFAULT 0,
    ioc_count INTEGER DEFAULT 0,
    scanned_count INTEGER DEFAULT 0,
    risk_level TEXT,
    -- v3: FP suppression
    provider_type TEXT DEFAULT 'unknown',
    fp_risk_score REAL DEFAULT 0.5,
    total_ips_announced INTEGER,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_asn_country ON asn_info(country);
CREATE INDEX IF NOT EXISTS idx_asn_provider ON asn_info(provider_type);

-- =============================================================
-- SCAN RESULTS
-- =============================================================

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    scan_id TEXT,
    scan_date TEXT,
    source_file TEXT,
    risk_score INTEGER DEFAULT 0,
    classification TEXT,
    open_ports TEXT,
    services TEXT,
    vulnerabilities TEXT,
    vuln_count INTEGER DEFAULT 0,
    c2_indicators TEXT,
    lateral_movement TEXT,
    raw_data TEXT,
    verified BOOLEAN DEFAULT 0,
    false_positive BOOLEAN DEFAULT 0,
    c2_confidence TEXT DEFAULT 'unverified',
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scan_ip ON scan_results(ip);
CREATE INDEX IF NOT EXISTS idx_scan_classification ON scan_results(classification);
CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_results(scan_date);
CREATE INDEX IF NOT EXISTS idx_scan_source ON scan_results(source_file);

CREATE TABLE IF NOT EXISTS vulnerability_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_id INTEGER,
    cve TEXT,
    cvss_score REAL,
    risk TEXT,
    host TEXT NOT NULL,
    protocol TEXT,
    port INTEGER,
    plugin_name TEXT,
    synopsis TEXT,
    solution TEXT,
    source_file TEXT,
    scan_date TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_vuln_host ON vulnerability_findings(host);
CREATE INDEX IF NOT EXISTS idx_vuln_risk ON vulnerability_findings(risk);
CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerability_findings(cve);
CREATE INDEX IF NOT EXISTS idx_vuln_plugin ON vulnerability_findings(plugin_id);

-- =============================================================
-- WORKFLOW TABLES
-- =============================================================

CREATE TABLE IF NOT EXISTS scan_campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_name TEXT NOT NULL,
    start_date TEXT,
    end_date TEXT,
    target_count INTEGER,
    completed_count INTEGER DEFAULT 0,
    critical_found INTEGER DEFAULT 0,
    status TEXT DEFAULT 'ACTIVE',
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    priority INTEGER DEFAULT 5,
    reason TEXT,
    campaign_id INTEGER,
    status TEXT DEFAULT 'PENDING',
    added_at TEXT DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,
    FOREIGN KEY (campaign_id) REFERENCES scan_campaigns(id)
);
CREATE INDEX IF NOT EXISTS idx_queue_status ON scan_queue(status);
CREATE INDEX IF NOT EXISTS idx_queue_priority ON scan_queue(priority);

CREATE TABLE IF NOT EXISTS ip_correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip1 TEXT NOT NULL,
    ip2 TEXT NOT NULL,
    correlation_type TEXT,
    confidence REAL DEFAULT 0.0,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_corr_ip1 ON ip_correlations(ip1);
CREATE INDEX IF NOT EXISTS idx_corr_ip2 ON ip_correlations(ip2);

CREATE TABLE IF NOT EXISTS validation_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    priority INTEGER DEFAULT 5,
    status TEXT DEFAULT 'pending',
    sources_requested TEXT,
    sources_completed TEXT DEFAULT '',
    attempts INTEGER DEFAULT 0,
    last_error TEXT,
    queued_at TEXT DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_vqueue_status ON validation_queue(status, priority);

-- =============================================================
-- WEIGHTED IOC SCORING (v3)
-- =============================================================

CREATE TABLE IF NOT EXISTS scoring_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL UNIQUE,
    reliability_weight REAL DEFAULT 0.5,
    category TEXT,                          -- reputation_db, blocklist, behavioral, threat_feed
    description TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO scoring_sources (source, reliability_weight, category, description) VALUES
    ('shodan',            0.30, 'behavioral',    'Shodan InternetDB — open ports, banners, vulns'),
    ('dshield',           0.40, 'reputation_db', 'DShield/SANS ISC — attack reports, threat score'),
    ('threatfox',         0.35, 'threat_feed',   'abuse.ch ThreatFox + Feodo Tracker'),
    ('abuseipdb',         0.25, 'reputation_db', 'AbuseIPDB — community abuse reports'),
    ('otx',               0.20, 'threat_feed',   'AlienVault OTX — pulse intelligence'),
    ('virustotal',        0.25, 'reputation_db', 'VirusTotal — multi-engine analysis'),
    ('censys',            0.20, 'behavioral',    'Censys — service/cert enumeration'),
    ('firehol',           0.15, 'blocklist',     'FireHOL aggregated blocklists'),
    ('stevenblack',       0.10, 'blocklist',     'Steven Black unified hosts'),
    ('c2tracker',         0.30, 'threat_feed',   'C2 Tracker (montysecurity) — Cobalt Strike, Sliver, Brute Ratel C2 IPs'),
    ('tweetfeed',         0.20, 'threat_feed',   'TweetFeed (0xDanielLopez) — crowdsourced IOCs with APT/malware tags'),
    ('ipsum',             0.15, 'blocklist',     'IPsum (stamparm) — meta-blacklist score from 30+ aggregated lists'),
    ('emerging_threats',  0.20, 'blocklist',     'Emerging Threats (Proofpoint) — curated IP blocklist');

CREATE TABLE IF NOT EXISTS source_validations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL DEFAULT 'ipv4',
    ioc_value TEXT NOT NULL,
    source TEXT NOT NULL,
    validated_at TEXT NOT NULL,
    confidence_score REAL DEFAULT 0.0,
    raw_response TEXT,
    UNIQUE(ioc_id, ioc_type, source)
);
CREATE INDEX IF NOT EXISTS idx_srcval_ioc ON source_validations(ioc_id, ioc_type);
CREATE INDEX IF NOT EXISTS idx_srcval_source ON source_validations(source);

-- =============================================================
-- LIFECYCLE & DECAY (v3)
-- =============================================================

CREATE TABLE IF NOT EXISTS lifecycle_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL DEFAULT 'ipv4',
    ioc_value TEXT NOT NULL,
    old_state TEXT,
    new_state TEXT,
    old_score REAL,
    new_score REAL,
    reason TEXT,
    transition_date TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ioc_id) REFERENCES ipv4_iocs(id)
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_ioc ON lifecycle_history(ioc_id);
CREATE INDEX IF NOT EXISTS idx_lifecycle_date ON lifecycle_history(transition_date);

-- =============================================================
-- FALSE-POSITIVE SUPPRESSION (v3)
-- =============================================================

CREATE TABLE IF NOT EXISTS cloud_ip_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    cidr TEXT NOT NULL,
    service_type TEXT,
    last_updated TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider, cidr)
);
CREATE INDEX IF NOT EXISTS idx_cloud_cidr ON cloud_ip_ranges(cidr);
CREATE INDEX IF NOT EXISTS idx_cloud_provider ON cloud_ip_ranges(provider);

-- =============================================================
-- ATTRIBUTION & INTELLIGENCE
-- =============================================================

CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_name TEXT UNIQUE NOT NULL,
    aliases TEXT,
    threat_actor_type TEXT,
    origin_country TEXT,
    first_seen TEXT,
    last_seen TEXT,
    description TEXT,
    objectives TEXT,
    ttps TEXT,
    confidence TEXT DEFAULT 'moderate',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attribution_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    source_org TEXT NOT NULL,
    report_title TEXT,
    publish_date TEXT,
    url TEXT,
    source_type TEXT,
    key_findings TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);
CREATE INDEX IF NOT EXISTS idx_attr_sources_campaign ON attribution_sources(campaign_id);

CREATE TABLE IF NOT EXISTS campaign_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    role TEXT,
    notes TEXT,
    attribution_source_id INTEGER,
    -- v3: per-IOC confidence
    confidence_score REAL DEFAULT 0.5,
    confidence_basis TEXT,
    infrastructure_risk REAL DEFAULT 0.0,
    evidence_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (attribution_source_id) REFERENCES attribution_sources(id)
);
CREATE INDEX IF NOT EXISTS idx_campaign_iocs_campaign ON campaign_iocs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_iocs_value ON campaign_iocs(ioc_value);

CREATE TABLE IF NOT EXISTS ioc_evidence_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_ioc_id INTEGER NOT NULL,
    evidence_type TEXT NOT NULL,
    evidence_detail TEXT NOT NULL,
    confidence_contribution REAL DEFAULT 0.1,
    source_reference TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (campaign_ioc_id) REFERENCES campaign_iocs(id)
);
CREATE INDEX IF NOT EXISTS idx_evidence_cioc ON ioc_evidence_chain(campaign_ioc_id);

CREATE TABLE IF NOT EXISTS threat_actors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    aliases TEXT,
    origin_country TEXT,
    threat_type TEXT,
    description TEXT,
    ttps TEXT,
    first_seen TEXT,
    last_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hosting_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_name TEXT NOT NULL,
    asn TEXT,
    country TEXT,
    ioc_count INTEGER DEFAULT 0,
    classification TEXT,
    sanctions_status TEXT,
    sanctions_date TEXT,
    sanctions_authority TEXT,
    law_enforcement_action TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_hosting_asn ON hosting_providers(asn);

CREATE TABLE IF NOT EXISTS campaign_correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_a_id INTEGER NOT NULL,
    campaign_b_id INTEGER NOT NULL,
    link_type TEXT NOT NULL,
    link_detail TEXT,
    confidence TEXT DEFAULT 'moderate',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (campaign_a_id) REFERENCES campaigns(id),
    FOREIGN KEY (campaign_b_id) REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS cert_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cn_pattern TEXT NOT NULL,
    host_count INTEGER DEFAULT 0,
    assessment TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS takedown_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    priority_id TEXT NOT NULL,
    tier INTEGER NOT NULL,
    target TEXT NOT NULL,
    provider TEXT,
    jurisdiction TEXT,
    action TEXT,
    ioc_count INTEGER DEFAULT 0,
    campaigns_affected TEXT,
    status TEXT DEFAULT 'planned',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_takedown_tier ON takedown_targets(tier);

-- =============================================================
-- STIX 2.1 & MITRE ATT&CK SUPPORT (v3)
-- =============================================================

CREATE TABLE IF NOT EXISTS mitre_mapping (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id INTEGER,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    tactic TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT,
    sub_technique TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mitre_ioc ON mitre_mapping(ioc_id);
CREATE INDEX IF NOT EXISTS idx_mitre_technique ON mitre_mapping(technique_id);

-- =============================================================
-- RECON & ENRICHMENT
-- =============================================================

CREATE TABLE IF NOT EXISTS recon_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    discovery_method TEXT,
    related_to TEXT,
    confidence REAL DEFAULT 0.0,
    risk_score INTEGER DEFAULT 0,
    classification TEXT,
    asn INTEGER,
    asn_org TEXT,
    country TEXT,
    whois_registrar TEXT,
    whois_created TEXT,
    whois_updated TEXT,
    whois_expires TEXT,
    whois_registrant TEXT,
    hosting_provider TEXT,
    reverse_dns TEXT,
    open_ports TEXT,
    services TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(indicator, indicator_type)
);
CREATE INDEX IF NOT EXISTS idx_recon_indicator ON recon_candidates(indicator);
CREATE INDEX IF NOT EXISTS idx_recon_type ON recon_candidates(indicator_type);
CREATE INDEX IF NOT EXISTS idx_recon_class ON recon_candidates(classification);
CREATE INDEX IF NOT EXISTS idx_recon_asn ON recon_candidates(asn);

CREATE TABLE IF NOT EXISTS enrichment_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    source TEXT NOT NULL,
    raw_data TEXT,
    asn INTEGER,
    asn_org TEXT,
    country TEXT,
    city TEXT,
    registrar TEXT,
    created_date TEXT,
    updated_date TEXT,
    abuse_contact TEXT,
    reverse_dns TEXT,
    hosting_provider TEXT,
    queried_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(indicator, source)
);
CREATE INDEX IF NOT EXISTS idx_enrich_indicator ON enrichment_results(indicator);

CREATE TABLE IF NOT EXISTS staging_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    role TEXT,
    confidence REAL DEFAULT 0.0,
    detection_reasons TEXT,
    upstream_ips TEXT,
    downstream_ips TEXT,
    proxy_services TEXT,
    c2_frameworks TEXT,
    open_ports TEXT,
    first_seen TEXT,
    last_seen TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_staging_ip ON staging_servers(ip);
CREATE INDEX IF NOT EXISTS idx_staging_role ON staging_servers(role);

-- =============================================================
-- METADATA
-- =============================================================

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO metadata (key, value) VALUES
    ('schema_version', '3.0'),
    ('created_date', datetime('now')),
    ('last_rebuild', NULL),
    ('last_incremental', NULL),
    ('ipv4_count', '0'),
    ('ipv6_count', '0'),
    ('domain_count', '0'),
    ('url_count', '0'),
    ('cve_count', '0'),
    ('email_count', '0'),
    ('cidr_count', '0'),
    ('scan_result_count', '0'),
    ('vulnerability_finding_count', '0');

-- =============================================================
-- AUXILIARY / RUNTIME TABLES
-- =============================================================
-- These tables are created on-demand by individual scripts
-- (validate.py, harden_db.py, import_data.py). They are defined
-- here as well so that `sqlite3 apt_intel.db < schema.sql` creates
-- a fully-featured database ready for any script to attach to.
-- =============================================================

-- transaction_log: audit trail of every DB write (validate.py)
CREATE TABLE IF NOT EXISTS transaction_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    ip TEXT,
    source TEXT,
    status TEXT,
    detail TEXT,
    run_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_txlog_ts ON transaction_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_txlog_run ON transaction_log(run_id);

-- api_daily_usage: autonomous API quota tracking (validate.py)
CREATE TABLE IF NOT EXISTS api_daily_usage (
    source TEXT NOT NULL,
    date TEXT NOT NULL,
    requests INTEGER DEFAULT 0,
    PRIMARY KEY (source, date)
);

-- audit_log: structured audit trail (harden_db.py)
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL,
    row_id INTEGER,
    old_data TEXT,
    new_data TEXT,
    user_agent TEXT DEFAULT 'system'
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_table ON audit_log(table_name);

-- imported_files: dedup tracker for bulk imports (import_data.py)
CREATE TABLE IF NOT EXISTS imported_files (
    filepath TEXT PRIMARY KEY,
    file_size INTEGER,
    file_mtime TEXT,
    imported_at TEXT,
    record_count INTEGER
);
