-- OTX Russian APT Analytics Database Schema v2
-- Full-coverage threat intelligence database
-- Supports: IPv4, IPv6, domains, URLs, CVEs, emails, CIDRs, vulnerability scans

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- =============================================================
-- IOC TABLES
-- =============================================================

-- IPv4 IOCs (formerly "iocs")
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
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ipv4_ip ON ipv4_iocs(ip);
CREATE INDEX IF NOT EXISTS idx_ipv4_infra ON ipv4_iocs(infra_type);
CREATE INDEX IF NOT EXISTS idx_ipv4_validation ON ipv4_iocs(validation_status, last_validated);

-- IPv6 IOCs
CREATE TABLE IF NOT EXISTS ipv6_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    last_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ipv6_ip ON ipv6_iocs(ip);

-- Domain IOCs
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_domain ON domains(domain);

-- URL IOCs
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

-- CVE references
CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_cve ON cves(cve_id);

-- Email IOCs
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

-- CIDR ranges
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

-- Subnet aggregation (auto-generated from IPv4 IOCs)
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

-- ASN information
CREATE TABLE IF NOT EXISTS asn_info (
    asn INTEGER PRIMARY KEY,
    org_name TEXT,
    country TEXT,
    subnet_count INTEGER DEFAULT 0,
    ioc_count INTEGER DEFAULT 0,
    scanned_count INTEGER DEFAULT 0,
    risk_level TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_asn_country ON asn_info(country);

-- =============================================================
-- SCAN RESULTS
-- =============================================================

-- Scan results (from master reports + APT-TARGETS markdown)
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

-- Vulnerability findings (from scan exports)
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

-- Scan campaigns
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

-- Scan queue
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

-- IP correlations
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

-- =============================================================
-- METADATA
-- =============================================================

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO metadata (key, value) VALUES
    ('schema_version', '2.0'),
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
-- RECON & ENRICHMENT TABLES
-- =============================================================

-- Recon candidates: new IPs/domains discovered through enrichment
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

-- Enrichment results from online lookups
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

-- Staging server analysis
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

-- Validation queue for OSINT API validation
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
-- ATTRIBUTION & INTELLIGENCE TABLES
-- =============================================================

-- Campaigns / Threat Actor profiles
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
    ttps TEXT,                          -- JSON blob of TTPs
    confidence TEXT DEFAULT 'moderate', -- low, moderate, high
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Published attribution sources (reports from security firms, govt advisories)
CREATE TABLE IF NOT EXISTS attribution_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    source_org TEXT NOT NULL,           -- e.g. "Aryaka Threat Labs", "Bitdefender Labs"
    report_title TEXT,
    publish_date TEXT,
    url TEXT,
    source_type TEXT,                   -- primary_research, media_corroboration, vendor_research, government_action, ioc_feed
    key_findings TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);
CREATE INDEX IF NOT EXISTS idx_attr_sources_campaign ON attribution_sources(campaign_id);

-- Campaign-to-IOC linkage
CREATE TABLE IF NOT EXISTS campaign_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL,             -- ipv4, ipv6, domain, hash, filename, url
    ioc_value TEXT NOT NULL,
    role TEXT,                          -- C2 Server, Infrastructure, Malware, etc.
    notes TEXT,
    attribution_source_id INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (attribution_source_id) REFERENCES attribution_sources(id)
);
CREATE INDEX IF NOT EXISTS idx_campaign_iocs_campaign ON campaign_iocs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_iocs_value ON campaign_iocs(ioc_value);

-- Bulletproof hosting provider profiles
CREATE TABLE IF NOT EXISTS hosting_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_name TEXT NOT NULL,
    asn TEXT,
    country TEXT,
    ioc_count INTEGER DEFAULT 0,
    classification TEXT,                -- bulletproof_hosting, abuse_tolerant, commercial_hosting, tor_exit_provider
    sanctions_status TEXT,              -- sanctioned, seized, not_sanctioned
    sanctions_date TEXT,
    sanctions_authority TEXT,
    law_enforcement_action TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_hosting_asn ON hosting_providers(asn);

-- Cross-campaign correlation links
CREATE TABLE IF NOT EXISTS campaign_correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_a_id INTEGER NOT NULL,
    campaign_b_id INTEGER NOT NULL,
    link_type TEXT NOT NULL,            -- shared_hosting, shared_relay, common_targeting, tradecraft_overlap, russian_nexus
    link_detail TEXT,
    confidence TEXT DEFAULT 'moderate',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (campaign_a_id) REFERENCES campaigns(id),
    FOREIGN KEY (campaign_b_id) REFERENCES campaigns(id)
);

-- SSL/TLS certificate patterns across infrastructure
CREATE TABLE IF NOT EXISTS cert_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cn_pattern TEXT NOT NULL,
    host_count INTEGER DEFAULT 0,
    assessment TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Prioritized takedown targets
CREATE TABLE IF NOT EXISTS takedown_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    priority_id TEXT NOT NULL,          -- P1, P2, ... P12
    tier INTEGER NOT NULL,              -- 1=immediate, 2=short-term, 3=strategic
    target TEXT NOT NULL,
    provider TEXT,
    jurisdiction TEXT,
    action TEXT,
    ioc_count INTEGER DEFAULT 0,
    campaigns_affected TEXT,
    status TEXT DEFAULT 'planned',      -- planned, in_progress, completed, blocked
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_takedown_tier ON takedown_targets(tier);
