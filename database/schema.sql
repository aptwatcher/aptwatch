CREATE TABLE ipv4_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    last_seen TEXT,
    pulse_count INTEGER DEFAULT 1,
    threat_types TEXT,
    source_pulses TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
, infra_type TEXT DEFAULT 'unknown', last_validated TEXT, validation_count INTEGER DEFAULT 0, validation_sources TEXT DEFAULT '{}', validation_status TEXT DEFAULT 'unvalidated', composite_score REAL DEFAULT 0.0, infrastructure_risk_score REAL DEFAULT 0.0, actor_attribution_score REAL DEFAULT 0.0, actor_attribution_actor TEXT, score_timestamp TEXT, provider_risk_level TEXT DEFAULT 'unknown', lifecycle_state TEXT DEFAULT 'active', decay_multiplier REAL DEFAULT 1.0, lifecycle_assessed_at TEXT, stix_id TEXT, mitre_techniques TEXT);
CREATE TABLE sqlite_sequence(name,seq);
CREATE INDEX idx_ipv4_ip ON ipv4_iocs(ip);
CREATE TABLE ipv6_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    last_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
, actor_attribution_actor TEXT, actor_attribution_score REAL DEFAULT 0.0);
CREATE INDEX idx_ipv6_ip ON ipv6_iocs(ip);
CREATE TABLE domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
, actor_attribution_actor TEXT, actor_attribution_score REAL DEFAULT 0.0);
CREATE INDEX idx_domain ON domains(domain);
CREATE TABLE urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    host TEXT,
    port INTEGER,
    path TEXT,
    source_file TEXT,
    first_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
, actor_attribution_actor TEXT, actor_attribution_score REAL DEFAULT 0.0);
CREATE INDEX idx_url ON urls(url);
CREATE INDEX idx_url_host ON urls(host);
CREATE TABLE cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
, actor_attribution_actor TEXT, actor_attribution_score REAL DEFAULT 0.0);
CREATE INDEX idx_cve ON cves(cve_id);
CREATE TABLE emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    domain TEXT,
    source_file TEXT,
    first_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
, actor_attribution_actor TEXT, actor_attribution_score REAL DEFAULT 0.0);
CREATE INDEX idx_email ON emails(email);
CREATE INDEX idx_email_domain ON emails(domain);
CREATE TABLE cidr_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL UNIQUE,
    source_file TEXT,
    first_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
, actor_attribution_actor TEXT, actor_attribution_score REAL DEFAULT 0.0);
CREATE INDEX idx_cidr_ioc ON cidr_iocs(cidr);
CREATE TABLE subnets (
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
CREATE INDEX idx_subnets_cidr ON subnets(cidr);
CREATE INDEX idx_subnets_tier ON subnets(tier);
CREATE INDEX idx_subnets_asn ON subnets(asn);
CREATE TABLE asn_info (
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
, provider_type TEXT DEFAULT 'unknown', fp_risk_score REAL DEFAULT 0.5, total_ips_announced INTEGER);
CREATE INDEX idx_asn_country ON asn_info(country);
CREATE TABLE scan_results (
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
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
, c2_confidence TEXT DEFAULT 'unverified');
CREATE INDEX idx_scan_ip ON scan_results(ip);
CREATE INDEX idx_scan_classification ON scan_results(classification);
CREATE INDEX idx_scan_date ON scan_results(scan_date);
CREATE INDEX idx_scan_source ON scan_results(source_file);
CREATE TABLE IF NOT EXISTS "vulnerability_findings" (
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
CREATE TABLE scan_campaigns (
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
CREATE TABLE scan_queue (
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
CREATE INDEX idx_queue_status ON scan_queue(status);
CREATE INDEX idx_queue_priority ON scan_queue(priority);
CREATE TABLE ip_correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip1 TEXT NOT NULL,
    ip2 TEXT NOT NULL,
    correlation_type TEXT,
    confidence REAL DEFAULT 0.0,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_corr_ip1 ON ip_correlations(ip1);
CREATE INDEX idx_corr_ip2 ON ip_correlations(ip2);
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE recon_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,  -- 'ip', 'domain', 'subnet', 'asn'
    discovery_method TEXT,         -- 'asn_expansion', 'whois_pivot', 'subnet_scan', 'passive_dns', 'cert_transparency'
    related_to TEXT,               -- original IOC that led to this discovery
    confidence REAL DEFAULT 0.0,   -- 0.0 to 1.0
    risk_score INTEGER DEFAULT 0,
    classification TEXT,           -- CANDIDATE, CONFIRMED, DISMISSED
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
CREATE INDEX idx_recon_indicator ON recon_candidates(indicator);
CREATE INDEX idx_recon_type ON recon_candidates(indicator_type);
CREATE INDEX idx_recon_class ON recon_candidates(classification);
CREATE INDEX idx_recon_asn ON recon_candidates(asn);
CREATE INDEX idx_recon_confidence ON recon_candidates(confidence);
CREATE TABLE enrichment_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    source TEXT NOT NULL,           -- 'rdap', 'whois', 'bgp_he', 'ipinfo', 'abuseipdb', 'shodan'
    raw_data TEXT,                  -- JSON blob of full response
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
CREATE INDEX idx_enrich_indicator ON enrichment_results(indicator);
CREATE INDEX idx_enrich_source ON enrichment_results(source);
CREATE TABLE staging_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    role TEXT,                      -- 'staging', 'proxy', 'c2_relay', 'drop_server', 'redirector'
    confidence REAL DEFAULT 0.0,
    detection_reasons TEXT,         -- JSON array of reasons
    upstream_ips TEXT,              -- JSON array of suspected upstream C2s
    downstream_ips TEXT,            -- JSON array of downstream targets
    proxy_services TEXT,            -- squid, nginx, socks, etc
    c2_frameworks TEXT,
    open_ports TEXT,
    first_seen TEXT,
    last_seen TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_staging_ip ON staging_servers(ip);
CREATE INDEX idx_staging_role ON staging_servers(role);
CREATE INDEX idx_staging_confidence ON staging_servers(confidence);
CREATE TABLE validation_queue (
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
CREATE INDEX idx_vqueue_status ON validation_queue(status, priority);
CREATE INDEX idx_ipv4_validation ON ipv4_iocs(validation_status, last_validated);
CREATE TABLE transaction_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            ip TEXT,
            source TEXT,
            status TEXT,
            detail TEXT,
            run_id TEXT
        );
CREATE INDEX idx_txlog_ts ON transaction_log(timestamp)
    ;
CREATE INDEX idx_txlog_run ON transaction_log(run_id)
    ;
CREATE TABLE api_daily_usage (
            source TEXT NOT NULL,
            date TEXT NOT NULL,
            requests INTEGER DEFAULT 0,
            PRIMARY KEY (source, date)
        );
CREATE TABLE imported_files (
    filepath TEXT PRIMARY KEY, file_size INTEGER, file_mtime TEXT,
    imported_at TEXT, record_count INTEGER);
CREATE INDEX idx_vuln_host ON vulnerability_findings(host);
CREATE INDEX idx_vuln_risk ON vulnerability_findings(risk);
CREATE INDEX idx_vuln_cve ON vulnerability_findings(cve);
CREATE INDEX idx_vuln_plugin ON vulnerability_findings(plugin_id);
CREATE TABLE campaigns (
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
CREATE TABLE attribution_sources (
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
CREATE TABLE campaign_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    role TEXT,
    notes TEXT,
    attribution_source_id INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP, confidence_score REAL DEFAULT 0.5, confidence_basis TEXT, infrastructure_risk REAL DEFAULT 0.0, evidence_count INTEGER DEFAULT 0,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (attribution_source_id) REFERENCES attribution_sources(id)
);
CREATE TABLE hosting_providers (
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
CREATE TABLE campaign_correlations (
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
CREATE TABLE cert_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cn_pattern TEXT NOT NULL,
    host_count INTEGER DEFAULT 0,
    assessment TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
, actor_attribution_actor TEXT, actor_attribution_score REAL DEFAULT 0.0);
CREATE TABLE takedown_targets (
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
CREATE INDEX idx_campaign_iocs_campaign ON campaign_iocs(campaign_id);
CREATE INDEX idx_campaign_iocs_value ON campaign_iocs(ioc_value);
CREATE INDEX idx_attr_sources_campaign ON attribution_sources(campaign_id);
CREATE INDEX idx_hosting_asn ON hosting_providers(asn);
CREATE INDEX idx_takedown_tier ON takedown_targets(tier);
CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            table_name TEXT NOT NULL,
            operation TEXT NOT NULL,
            row_id INTEGER,
            old_data TEXT,
            new_data TEXT,
            user_agent TEXT DEFAULT 'system'
        );
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_table ON audit_log(table_name);
CREATE TRIGGER audit_delete_ipv4_iocs
            BEFORE DELETE ON ipv4_iocs
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data)
                VALUES ('ipv4_iocs', 'DELETE', OLD.id, OLD.ip);
            END;
CREATE TRIGGER audit_delete_scan_results
            BEFORE DELETE ON scan_results
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data)
                VALUES ('scan_results', 'DELETE', OLD.id, OLD.ip);
            END;
CREATE TRIGGER audit_delete_campaigns
            BEFORE DELETE ON campaigns
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data)
                VALUES ('campaigns', 'DELETE', OLD.id, OLD.campaign_name);
            END;
CREATE TRIGGER audit_delete_campaign_correlations
            BEFORE DELETE ON campaign_correlations
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data)
                VALUES ('campaign_correlations', 'DELETE', OLD.id, OLD.id);
            END;
CREATE TRIGGER audit_delete_attribution_sources
            BEFORE DELETE ON attribution_sources
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data)
                VALUES ('attribution_sources', 'DELETE', OLD.id, OLD.id);
            END;
CREATE TRIGGER audit_delete_hosting_providers
            BEFORE DELETE ON hosting_providers
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data)
                VALUES ('hosting_providers', 'DELETE', OLD.id, OLD.provider_name);
            END;
CREATE TRIGGER audit_delete_takedown_targets
            BEFORE DELETE ON takedown_targets
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data)
                VALUES ('takedown_targets', 'DELETE', OLD.id, OLD.target);
            END;
CREATE TRIGGER audit_delete_subnets
            BEFORE DELETE ON subnets
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data)
                VALUES ('subnets', 'DELETE', OLD.id, OLD.cidr);
            END;
CREATE TRIGGER audit_update_ipv4_iocs
            AFTER UPDATE ON ipv4_iocs
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data, new_data)
                VALUES ('ipv4_iocs', 'UPDATE', NEW.id, OLD.ip, NEW.ip);
            END;
CREATE TRIGGER audit_update_scan_results
            AFTER UPDATE ON scan_results
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data, new_data)
                VALUES ('scan_results', 'UPDATE', NEW.id, OLD.ip, NEW.ip);
            END;
CREATE TRIGGER audit_update_campaigns
            AFTER UPDATE ON campaigns
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data, new_data)
                VALUES ('campaigns', 'UPDATE', NEW.id, OLD.campaign_name, NEW.campaign_name);
            END;
CREATE TRIGGER audit_update_campaign_correlations
            AFTER UPDATE ON campaign_correlations
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data, new_data)
                VALUES ('campaign_correlations', 'UPDATE', NEW.id, OLD.id, NEW.id);
            END;
CREATE TRIGGER audit_update_attribution_sources
            AFTER UPDATE ON attribution_sources
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data, new_data)
                VALUES ('attribution_sources', 'UPDATE', NEW.id, OLD.id, NEW.id);
            END;
CREATE TRIGGER audit_update_hosting_providers
            AFTER UPDATE ON hosting_providers
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data, new_data)
                VALUES ('hosting_providers', 'UPDATE', NEW.id, OLD.provider_name, NEW.provider_name);
            END;
CREATE TRIGGER audit_update_takedown_targets
            AFTER UPDATE ON takedown_targets
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data, new_data)
                VALUES ('takedown_targets', 'UPDATE', NEW.id, OLD.target, NEW.target);
            END;
CREATE TRIGGER audit_update_subnets
            AFTER UPDATE ON subnets
            BEGIN
                INSERT INTO audit_log (table_name, operation, row_id, old_data, new_data)
                VALUES ('subnets', 'UPDATE', NEW.id, OLD.cidr, NEW.cidr);
            END;
CREATE VIEW v_table_counts AS SELECT 'ipv4_iocs' as tbl, COUNT(*) as cnt FROM ipv4_iocs UNION ALL SELECT 'scan_results' as tbl, COUNT(*) as cnt FROM scan_results UNION ALL SELECT 'campaigns' as tbl, COUNT(*) as cnt FROM campaigns UNION ALL SELECT 'campaign_correlations' as tbl, COUNT(*) as cnt FROM campaign_correlations UNION ALL SELECT 'attribution_sources' as tbl, COUNT(*) as cnt FROM attribution_sources UNION ALL SELECT 'hosting_providers' as tbl, COUNT(*) as cnt FROM hosting_providers UNION ALL SELECT 'takedown_targets' as tbl, COUNT(*) as cnt FROM takedown_targets UNION ALL SELECT 'subnets' as tbl, COUNT(*) as cnt FROM subnets
/* v_table_counts(tbl,cnt) */;
CREATE TABLE scoring_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL UNIQUE,
    reliability_weight REAL DEFAULT 0.5,   -- 0.0–1.0
    category TEXT,                          -- reputation_db, blocklist, behavioral, threat_feed
    description TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE source_validations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL DEFAULT 'ipv4',  -- ipv4, domain, url
    ioc_value TEXT NOT NULL,
    source TEXT NOT NULL,
    validated_at TEXT NOT NULL,
    confidence_score REAL DEFAULT 0.0,       -- source-specific confidence 0.0–1.0
    raw_response TEXT,                        -- truncated API response for audit
    UNIQUE(ioc_id, ioc_type, source)
);
CREATE INDEX idx_srcval_ioc ON source_validations(ioc_id, ioc_type);
CREATE INDEX idx_srcval_source ON source_validations(source);
CREATE INDEX idx_ipv4_composite ON ipv4_iocs(composite_score DESC);
CREATE INDEX idx_ipv4_infra_risk ON ipv4_iocs(infrastructure_risk_score DESC);
CREATE INDEX idx_ipv4_lifecycle ON ipv4_iocs(lifecycle_state);
CREATE TABLE lifecycle_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL DEFAULT 'ipv4',
    ioc_value TEXT NOT NULL,
    old_state TEXT,
    new_state TEXT,
    old_score REAL,
    new_score REAL,
    reason TEXT,   -- automatic_decay, reactivation, manual, validation_found
    transition_date TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ioc_id) REFERENCES ipv4_iocs(id)
);
CREATE INDEX idx_lifecycle_ioc ON lifecycle_history(ioc_id);
CREATE INDEX idx_lifecycle_date ON lifecycle_history(transition_date);
CREATE INDEX idx_asn_provider ON asn_info(provider_type);
CREATE TABLE cloud_ip_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    cidr TEXT NOT NULL,
    service_type TEXT,      -- compute, cdn, storage, general
    last_updated TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider, cidr)
);
CREATE INDEX idx_cloud_cidr ON cloud_ip_ranges(cidr);
CREATE INDEX idx_cloud_provider ON cloud_ip_ranges(provider);
CREATE TABLE ioc_evidence_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_ioc_id INTEGER NOT NULL,
    evidence_type TEXT NOT NULL,   -- malware_sample, passive_dns, infrastructure_overlap, cert_pattern, threat_feed, manual_analysis
    evidence_detail TEXT NOT NULL,
    confidence_contribution REAL DEFAULT 0.1,
    source_reference TEXT,         -- URL or report ID
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (campaign_ioc_id) REFERENCES campaign_iocs(id)
);
CREATE INDEX idx_evidence_cioc ON ioc_evidence_chain(campaign_ioc_id);
CREATE TABLE threat_actors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    aliases TEXT,                  -- JSON array
    origin_country TEXT,
    threat_type TEXT,              -- nation_state, cybercrime, hacktivist
    description TEXT,
    ttps TEXT,                     -- JSON
    first_seen TEXT,
    last_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE mitre_mapping (
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
CREATE INDEX idx_mitre_ioc ON mitre_mapping(ioc_id);
CREATE INDEX idx_mitre_technique ON mitre_mapping(technique_id);
CREATE INDEX idx_scan_results_ip ON scan_results(ip);
CREATE INDEX idx_scan_results_class ON scan_results(classification);
CREATE INDEX idx_ip_correlations_ip1 ON ip_correlations(ip1);
CREATE INDEX idx_ip_correlations_ip2 ON ip_correlations(ip2);
CREATE INDEX idx_staging_servers_ip ON staging_servers(ip);
CREATE UNIQUE INDEX ux_campaign_iocs_unique
    ON campaign_iocs (campaign_id, ioc_type, ioc_value);
CREATE UNIQUE INDEX ux_scan_results_ip_scan
    ON scan_results (ip, scan_id);
CREATE TRIGGER tr_scan_results_autofill_scan_id
    AFTER INSERT ON scan_results
    FOR EACH ROW
    WHEN NEW.scan_id IS NULL OR NEW.scan_id = ''
BEGIN
    UPDATE scan_results
       SET scan_id = 'unscoped-' || NEW.id || '-' || strftime('%Y%m%d', 'now')
     WHERE id = NEW.id;
END;
CREATE INDEX idx_domains_actor ON domains(actor_attribution_actor);
CREATE INDEX idx_urls_actor ON urls(actor_attribution_actor);
CREATE INDEX idx_emails_actor ON emails(actor_attribution_actor);
CREATE INDEX idx_cves_actor ON cves(actor_attribution_actor);
CREATE INDEX idx_cidr_actor ON cidr_iocs(actor_attribution_actor);
CREATE INDEX idx_ipv6_actor ON ipv6_iocs(actor_attribution_actor);
CREATE INDEX idx_cert_patterns_actor ON cert_patterns(actor_attribution_actor);
CREATE INDEX idx_ipv4_actor ON ipv4_iocs(actor_attribution_actor);
