// =============================================================
// APTWatch v3 — Scoring, Lifecycle, STIX/Suricata Export, Blocklist Builder
// Requires: db (sql.js instance), q(), qVal(), renderTable(), exportTableCSV()
// =============================================================

// Helper: check if a v3 column exists
function v3Available() {
  try {
    q("SELECT composite_score FROM ipv4_iocs LIMIT 1");
    return true;
  } catch(e) {
    return false;
  }
}

// =============================================================
// SCORING TAB
// =============================================================

function v3LoadScoring() {
  if (!v3Available()) {
    document.getElementById('scoring-loading').textContent = 'v3 scoring columns not found. Load a v3-migrated database.';
    return;
  }
  document.getElementById('scoring-loading').style.display = 'none';
  document.getElementById('scoring-content').style.display = 'block';

  // Score distribution
  const total = qVal("SELECT COUNT(*) FROM ipv4_iocs");
  const critical = qVal("SELECT COUNT(*) FROM ipv4_iocs WHERE composite_score * COALESCE(decay_multiplier,1) >= 0.8");
  const high = qVal("SELECT COUNT(*) FROM ipv4_iocs WHERE composite_score * COALESCE(decay_multiplier,1) >= 0.6 AND composite_score * COALESCE(decay_multiplier,1) < 0.8");
  const medium = qVal("SELECT COUNT(*) FROM ipv4_iocs WHERE composite_score * COALESCE(decay_multiplier,1) >= 0.3 AND composite_score * COALESCE(decay_multiplier,1) < 0.6");
  const low = qVal("SELECT COUNT(*) FROM ipv4_iocs WHERE composite_score * COALESCE(decay_multiplier,1) < 0.3");
  const scored = qVal("SELECT COUNT(*) FROM ipv4_iocs WHERE score_timestamp IS NOT NULL");

  document.getElementById('score-dist-cards').innerHTML =
    `<div class="card info"><div class="label">Total IOCs</div><div class="value">${total.toLocaleString()}</div></div>` +
    `<div class="card purple"><div class="label">Scored</div><div class="value">${scored.toLocaleString()}</div></div>` +
    `<div class="card critical"><div class="label">Critical (0.8+)</div><div class="value">${critical.toLocaleString()}</div></div>` +
    `<div class="card high"><div class="label">High (0.6-0.8)</div><div class="value">${high.toLocaleString()}</div></div>` +
    `<div class="card medium"><div class="label">Medium (0.3-0.6)</div><div class="value">${medium.toLocaleString()}</div></div>` +
    `<div class="card low"><div class="label">Low (<0.3)</div><div class="value">${low.toLocaleString()}</div></div>`;

  // Lifecycle
  const active = qVal("SELECT COUNT(*) FROM ipv4_iocs WHERE lifecycle_state='active'");
  const stale = qVal("SELECT COUNT(*) FROM ipv4_iocs WHERE lifecycle_state='stale'");
  const expired = qVal("SELECT COUNT(*) FROM ipv4_iocs WHERE lifecycle_state='expired'");
  const unassessed = qVal("SELECT COUNT(*) FROM ipv4_iocs WHERE lifecycle_state IS NULL OR lifecycle_state=''");

  document.getElementById('lifecycle-cards').innerHTML =
    `<div class="card critical"><div class="label">Active</div><div class="value">${active.toLocaleString()}</div></div>` +
    `<div class="card medium"><div class="label">Stale</div><div class="value">${stale.toLocaleString()}</div></div>` +
    `<div class="card low"><div class="label">Expired</div><div class="value">${expired.toLocaleString()}</div></div>` +
    `<div class="card info"><div class="label">Unassessed</div><div class="value">${unassessed.toLocaleString()}</div></div>`;

  // Provider risk
  const provR = q("SELECT COALESCE(provider_risk_level,'unknown') as prl, COUNT(*) as cnt FROM ipv4_iocs GROUP BY provider_risk_level ORDER BY cnt DESC");
  let provHtml = '';
  if (provR.length > 0) {
    provR[0].values.forEach(r => {
      const prl = r[0] || 'unknown';
      const cnt = r[1];
      const cls = prl === 'critical' ? 'critical' : prl === 'medium' ? 'medium' : prl === 'low' ? 'low' : 'info';
      provHtml += `<div class="card ${cls}"><div class="label">${prl}</div><div class="value">${cnt.toLocaleString()}</div></div>`;
    });
  }
  document.getElementById('provider-cards').innerHTML = provHtml;
}

function v3QueryIOCs() {
  const lifecycle = document.getElementById('v3-lifecycle-filter').value;
  const provider = document.getElementById('v3-provider-filter').value;
  const minScore = parseFloat(document.getElementById('v3-min-score').value) || 0;
  const search = document.getElementById('v3-ip-search').value.trim().replace(/'/g, '');

  let where = [];
  if (lifecycle) where.push(`lifecycle_state = '${lifecycle}'`);
  if (provider) where.push(`provider_risk_level = '${provider}'`);
  if (minScore > 0) where.push(`(composite_score * COALESCE(decay_multiplier,1)) >= ${minScore}`);
  if (search) where.push(`ip LIKE '%${search}%'`);

  const whereStr = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const sql = `SELECT ip,
    ROUND(composite_score * COALESCE(decay_multiplier,1), 4) as effective_score,
    ROUND(composite_score, 4) as composite_score,
    ROUND(infrastructure_risk_score, 4) as infra_risk,
    lifecycle_state,
    ROUND(decay_multiplier, 2) as decay,
    provider_risk_level,
    validation_count,
    actor_attribution_actor as actor,
    ROUND(actor_attribution_score, 2) as actor_score
    FROM ipv4_iocs ${whereStr}
    ORDER BY composite_score * COALESCE(decay_multiplier,1) DESC
    LIMIT 500`;

  const r = q(sql);
  if (r.length > 0) {
    document.getElementById('v3-ioc-info').textContent = `${r[0].values.length} results (limit 500)`;
    renderTable('v3-ioc-table', r[0].columns, r[0].values, { ipLink: true });
  } else {
    document.getElementById('v3-ioc-info').textContent = '0 results';
    renderTable('v3-ioc-table', [], []);
  }
}

// =============================================================
// EXPORTS TAB — Init
// =============================================================

function v3InitExports() {
  if (!v3Available()) {
    document.getElementById('exports-loading').textContent = 'v3 scoring columns not found. Load a v3-migrated database.';
    return;
  }
  document.getElementById('exports-loading').style.display = 'none';
  document.getElementById('exports-content').style.display = 'block';
}

// =============================================================
// STIX 2.1 EXPORT
// =============================================================

function v3ExportSTIX() {
  const minScore = parseFloat(document.getElementById('stix-min-score').value) || 0;
  const lifecycleStr = document.getElementById('stix-lifecycle').value;
  const limit = parseInt(document.getElementById('stix-limit').value) || 1000;

  let where = [];
  if (minScore > 0) where.push(`(composite_score * COALESCE(decay_multiplier,1)) >= ${minScore}`);
  if (lifecycleStr) {
    const states = lifecycleStr.split(',').map(s => `'${s.trim()}'`).join(',');
    where.push(`lifecycle_state IN (${states})`);
  }

  const whereStr = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const sql = `SELECT ip, composite_score, infrastructure_risk_score, decay_multiplier,
    lifecycle_state, provider_risk_level, actor_attribution_actor, first_seen, last_seen,
    stix_id FROM ipv4_iocs ${whereStr}
    ORDER BY composite_score * COALESCE(decay_multiplier,1) DESC LIMIT ${limit}`;

  const r = q(sql);
  if (!r.length || !r[0].values.length) {
    document.getElementById('stix-info').textContent = 'No IOCs match the criteria.';
    return;
  }

  const now = new Date().toISOString();
  const bundleId = 'bundle--' + crypto.randomUUID();
  const objects = [];

  // Identity
  const identityId = 'identity--' + crypto.randomUUID();
  objects.push({
    type: 'identity', spec_version: '2.1', id: identityId,
    created: now, modified: now,
    name: 'APTWatch', identity_class: 'organization'
  });

  // TLP marking
  const tlpAmber = 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82';

  r[0].values.forEach(row => {
    const [ip, cs, ir, dm, ls, prl, actor, firstSeen, lastSeen, stixId] = row;
    const eff = (cs || 0) * (dm || 1);

    const indicatorId = stixId || ('indicator--' + crypto.randomUUID());
    objects.push({
      type: 'indicator', spec_version: '2.1', id: indicatorId,
      created: now, modified: now,
      name: `Malicious IP: ${ip}`,
      pattern: `[ipv4-addr:value = '${ip}']`,
      pattern_type: 'stix',
      valid_from: firstSeen || now,
      valid_until: ls === 'expired' ? lastSeen : undefined,
      confidence: Math.round(eff * 100),
      object_marking_refs: [tlpAmber],
      created_by_ref: identityId,
      labels: [ls || 'unknown', prl || 'unknown'],
      custom_properties: {
        'x_aptwatch_composite_score': cs,
        'x_aptwatch_infrastructure_risk': ir,
        'x_aptwatch_decay_multiplier': dm,
        'x_aptwatch_lifecycle_state': ls,
        'x_aptwatch_provider_risk_level': prl,
        'x_aptwatch_actor': actor
      }
    });
  });

  const bundle = {
    type: 'bundle', id: bundleId, spec_version: '2.1',
    objects: objects
  };

  const json = JSON.stringify(bundle, null, 2);
  document.getElementById('stix-output').value = json;
  document.getElementById('stix-output').style.display = 'block';
  document.getElementById('stix-download-btn').style.display = 'inline-block';
  document.getElementById('stix-info').textContent = `Generated STIX bundle: ${r[0].values.length} indicators, ${json.length.toLocaleString()} bytes`;
}

function v3DownloadSTIX() {
  const content = document.getElementById('stix-output').value;
  const blob = new Blob([content], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `aptwatch-stix-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// =============================================================
// SURICATA EXPORT
// =============================================================

function v3ExportSuricata() {
  const minScore = parseFloat(document.getElementById('suri-min-score').value) || 0;
  const lifecycleStr = document.getElementById('suri-lifecycle').value;
  const limit = parseInt(document.getElementById('suri-limit').value) || 5000;

  let where = [];
  if (minScore > 0) where.push(`(composite_score * COALESCE(decay_multiplier,1)) >= ${minScore}`);
  if (lifecycleStr) {
    const states = lifecycleStr.split(',').map(s => `'${s.trim()}'`).join(',');
    where.push(`lifecycle_state IN (${states})`);
  }

  const whereStr = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const sql = `SELECT ip, composite_score, decay_multiplier, lifecycle_state, provider_risk_level,
    actor_attribution_actor FROM ipv4_iocs ${whereStr}
    ORDER BY composite_score * COALESCE(decay_multiplier,1) DESC LIMIT ${limit}`;

  const r = q(sql);
  if (!r.length || !r[0].values.length) {
    document.getElementById('suri-info').textContent = 'No IOCs match the criteria.';
    return;
  }

  const now = new Date().toISOString().slice(0, 10);
  let rules = [];
  rules.push(`# APTWatch Suricata Rules — Generated ${now}`);
  rules.push(`# IOCs: ${r[0].values.length} | Min score: ${minScore}`);
  rules.push(`# Lifecycle: ${lifecycleStr || 'all'}`);
  rules.push('');

  let sid = 9100001;
  r[0].values.forEach(row => {
    const [ip, cs, dm, ls, prl, actor] = row;
    const eff = ((cs || 0) * (dm || 1)).toFixed(3);
    const severity = eff >= 0.8 ? 1 : eff >= 0.6 ? 2 : eff >= 0.3 ? 3 : 4;
    const actorTag = actor ? ` actor:${actor.replace(/\s+/g, '_')}` : '';
    const msg = `APTWatch IOC: ${ip} [score:${eff} ${ls||'unknown'} ${prl||'unknown'}${actorTag}]`;

    rules.push(`alert ip ${ip} any -> $HOME_NET any (msg:"${msg}"; classtype:trojan-activity; priority:${severity}; sid:${sid}; rev:1;)`);
    rules.push(`alert ip $HOME_NET any -> ${ip} any (msg:"${msg} (outbound)"; classtype:trojan-activity; priority:${severity}; sid:${sid + 50000}; rev:1;)`);
    sid++;
  });

  const output = rules.join('\n');
  document.getElementById('suri-output').value = output;
  document.getElementById('suri-output').style.display = 'block';
  document.getElementById('suri-download-btn').style.display = 'inline-block';
  document.getElementById('suri-info').textContent = `Generated ${(sid - 9100001) * 2} Suricata rules for ${r[0].values.length} IOCs`;
}

function v3DownloadSuricata() {
  const content = document.getElementById('suri-output').value;
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `aptwatch-${new Date().toISOString().slice(0,10)}.rules`;
  a.click();
  URL.revokeObjectURL(url);
}

// =============================================================
// BLOCKLIST BUILDER
// =============================================================

let _lastBlocklist = '';

function v3BuildBlocklist() {
  const minScore = parseFloat(document.getElementById('bl-min-score').value) || 0;
  const lifecycleStr = document.getElementById('bl-lifecycle').value;
  const providerStr = document.getElementById('bl-provider').value;
  const limit = parseInt(document.getElementById('bl-limit').value) || 10000;

  let where = [];
  if (minScore > 0) where.push(`(composite_score * COALESCE(decay_multiplier,1)) >= ${minScore}`);
  if (lifecycleStr) {
    const states = lifecycleStr.split(',').map(s => `'${s.trim()}'`).join(',');
    where.push(`lifecycle_state IN (${states})`);
  }
  if (providerStr) {
    const provs = providerStr.split(',').map(s => `'${s.trim()}'`).join(',');
    where.push(`provider_risk_level IN (${provs})`);
  }

  const whereStr = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const sql = `SELECT ip FROM ipv4_iocs ${whereStr}
    ORDER BY composite_score * COALESCE(decay_multiplier,1) DESC LIMIT ${limit}`;

  const r = q(sql);
  if (!r.length || !r[0].values.length) {
    document.getElementById('bl-info').textContent = 'No IOCs match the criteria.';
    return;
  }

  const ips = r[0].values.map(row => row[0]);
  const now = new Date().toISOString().slice(0, 10);
  const header = [
    `# APTWatch v3 Blocklist — Generated ${now}`,
    `# IOCs: ${ips.length} | Min effective score: ${minScore}`,
    `# Lifecycle: ${lifecycleStr || 'all'} | Provider: ${providerStr || 'all'}`,
    '#',
  ];

  _lastBlocklist = header.join('\n') + '\n' + ips.join('\n') + '\n';

  document.getElementById('bl-output').value = _lastBlocklist;
  document.getElementById('bl-output').style.display = 'block';
  document.getElementById('bl-download-btn').style.display = 'inline-block';
  document.getElementById('bl-download-hosts-btn').style.display = 'inline-block';
  document.getElementById('bl-copy-btn').style.display = 'inline-block';
  document.getElementById('bl-info').textContent = `Blocklist: ${ips.length} IPs`;
}

function v3DownloadBlocklist(format) {
  let content, filename;
  const now = new Date().toISOString().slice(0, 10);

  if (format === 'hosts') {
    // Convert to hosts format (0.0.0.0 <ip>)
    const lines = _lastBlocklist.split('\n');
    content = lines.map(line => {
      if (line.startsWith('#') || line.trim() === '') return line;
      return '0.0.0.0 ' + line.trim();
    }).join('\n');
    filename = `aptwatch-blocklist-${now}.hosts`;
  } else {
    content = _lastBlocklist;
    filename = `aptwatch-blocklist-${now}.netset`;
  }

  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
