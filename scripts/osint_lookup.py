#!/usr/bin/env python3
# SPDX-License-Identifier: Unlicense
# APT Watch -- https://github.com/aptwatcher/aptwatch -- released into the public domain.
# Part of the APT Watch project (defensive Russian-APT threat intelligence).
"""
osint_lookup.py -- passive OSINT host lookup for APT Watch collaborators.

Query Shodan (free InternetDB or keyed) and Censys (Platform v3) for a set of
IPs / CIDRs, from arguments and/or an input file, and emit a normalized CSV
(+ optional full JSON). Passive: these providers report what they already
scanned, so they see hosts that drop ICMP / refuse direct probing.

NO KEYS ARE STORED IN THIS REPO. Keys are read at runtime:
  1. environment variables  SHODAN_API_KEY / CENSYS_API_TOKEN   (take priority)
  2. an INI config file [api_keys] shodan_api_key / censys_api_token
     (default search: --config, then $APTWATCH_CONFIG, then ./config.ini).
For STTR/private use the keys live in apt-intel/config.ini (never committed).

Examples
--------
  # Free, no key -- which of these hosts does Shodan see, and on what ports?
  python osint_lookup.py 198.51.100.10 198.51.100.20 -p internetdb

  # A whole block from a file, Censys Platform v3, historical snapshot:
  python osint_lookup.py -f targets.txt -p censys --at-time 2026-04-01T00:00:00Z \
      --config ../apt-intel/config.ini --out myblock_apr

  # Shodan keyed CIDR search (needs a Membership plan):
  python osint_lookup.py 192.0.2.0/24 -p shodan --out myblock

Providers
---------
  internetdb : Shodan InternetDB, per-IP, NO key, free. (default)
  shodan     : Shodan keyed -- per-IP host API, or net: search for CIDRs.
  censys     : Censys Platform v3 per-IP asset/host (Bearer token), supports --at-time.
"""
import argparse
import base64
import configparser
import csv
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "APTWatch-osint-lookup/1.0 (+https://github.com/aptwatcher/aptwatch)"


# --------------------------------------------------------------------------- #
# Config / keys
# --------------------------------------------------------------------------- #
def _config_path(explicit):
    for cand in (explicit, os.environ.get("APTWATCH_CONFIG"), "config.ini"):
        if cand and os.path.isfile(cand):
            return cand
    return None


def _decode_key(val, encoding):
    val = (val or "").strip()
    if not val:
        return ""
    if encoding == "base64":
        try:
            return base64.b64decode(val).decode("utf-8").strip()
        except Exception:
            return val
    return val


def load_keys(config_path, encoding):
    """env var first, then [api_keys] in the INI file."""
    cfg = configparser.ConfigParser()
    path = _config_path(config_path)
    if path:
        try:
            cfg.read(path)
        except Exception as e:
            print(f"[warn] could not read config {path}: {e}", file=sys.stderr)

    def from_cfg(key):
        try:
            return cfg.get("api_keys", key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return ""

    shodan = os.environ.get("SHODAN_API_KEY", "") or _decode_key(from_cfg("shodan_api_key"), encoding)
    censys = os.environ.get("CENSYS_API_TOKEN", "") or _decode_key(from_cfg("censys_api_token"), encoding)
    return {"shodan": shodan.strip(), "censys": censys.strip(), "config_used": path}


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #
def read_targets(args_targets, file_path):
    raw = list(args_targets or [])
    if file_path:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    raw.append(line.split()[0])
    # de-dup, preserve order
    seen, out = set(), []
    for t in raw:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def expand_for_per_ip(targets, max_hosts):
    """Expand CIDRs to host IPs for per-IP providers (capped)."""
    ips, cidrs_skipped = [], []
    for t in targets:
        if "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
                hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
                if len(hosts) > max_hosts:
                    print(f"[warn] {t} has {len(hosts)} hosts > --max-hosts {max_hosts}; "
                          f"taking first {max_hosts}", file=sys.stderr)
                    hosts = hosts[:max_hosts]
                ips.extend(hosts)
            except ValueError:
                cidrs_skipped.append(t)
        else:
            ips.append(t)
    # de-dup
    seen, out = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out, cidrs_skipped


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def http_get(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:
        return None, {"_error": str(e)}


# --------------------------------------------------------------------------- #
# Providers -> normalized row {ip, provider, alive, ports, asn, asn_org,
#                              country, hostnames, note} + raw
# --------------------------------------------------------------------------- #
def q_internetdb(ip, delay, **_):
    code, data = http_get(f"https://internetdb.shodan.io/{ip}")
    time.sleep(delay)
    if code == 404:
        return {"ip": ip, "provider": "internetdb", "alive": False, "ports": "",
                "asn": "", "asn_org": "", "country": "", "hostnames": "", "note": "no data"}, None
    if code != 200 or not isinstance(data, dict):
        return {"ip": ip, "provider": "internetdb", "alive": False, "ports": "",
                "asn": "", "asn_org": "", "country": "", "hostnames": "",
                "note": f"http {code}"}, data
    return {
        "ip": ip, "provider": "internetdb", "alive": bool(data.get("ports")),
        "ports": ";".join(str(p) for p in data.get("ports", [])),
        "asn": "", "asn_org": "", "country": "",
        "hostnames": ";".join(data.get("hostnames", [])),
        "note": ";".join(data.get("tags", []) + data.get("vulns", [])[:5]),
    }, data


def q_shodan_host(ip, key, delay, **_):
    code, data = http_get(f"https://api.shodan.io/shodan/host/{ip}?key={key}")
    time.sleep(delay)
    if code == 404:
        return {"ip": ip, "provider": "shodan", "alive": False, "ports": "", "asn": "",
                "asn_org": "", "country": "", "hostnames": "", "note": "no data"}, None
    if code != 200 or not isinstance(data, dict):
        return {"ip": ip, "provider": "shodan", "alive": False, "ports": "", "asn": "",
                "asn_org": "", "country": "", "hostnames": "", "note": f"http {code}"}, data
    return {
        "ip": ip, "provider": "shodan", "alive": bool(data.get("ports")),
        "ports": ";".join(str(p) for p in data.get("ports", [])),
        "asn": str(data.get("asn", "")).replace("AS", ""), "asn_org": data.get("org", ""),
        "country": data.get("country_code", ""),
        "hostnames": ";".join(data.get("hostnames", [])), "note": "",
    }, data


def q_shodan_search(cidr, key, delay, **_):
    q = urllib.parse.quote(f"net:{cidr}")
    code, data = http_get(f"https://api.shodan.io/shodan/host/search?key={key}&query={q}")
    time.sleep(max(delay, 1.0))
    rows, raws = [], data
    if code != 200 or not isinstance(data, dict):
        rows.append({"ip": cidr, "provider": "shodan-search", "alive": False, "ports": "",
                     "asn": "", "asn_org": "", "country": "", "hostnames": "", "note": f"http {code}"})
        return rows, raws
    for m in data.get("matches", []):
        rows.append({
            "ip": m.get("ip_str", ""), "provider": "shodan-search", "alive": True,
            "ports": ";".join(str(p) for p in m.get("ports", []) or [m.get("port")]),
            "asn": str(m.get("asn", "")).replace("AS", ""), "asn_org": m.get("org", ""),
            "country": m.get("location", {}).get("country_code", ""),
            "hostnames": ";".join(m.get("hostnames", [])), "note": f"cidr={cidr}",
        })
    if not rows:
        rows.append({"ip": cidr, "provider": "shodan-search", "alive": False, "ports": "",
                     "asn": "", "asn_org": "", "country": "", "hostnames": "", "note": "0 matches"})
    return rows, raws


def q_censys(ip, token, delay, at_time=None, org_id=None, **_):
    url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
    params = {}
    if at_time:
        params["at_time"] = at_time
    if org_id:
        params["organization_id"] = org_id
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.censys.api.v3.host.v1+json"}
    code, data = http_get(url, headers=headers)
    time.sleep(max(delay, 0.3))
    if code != 200 or not isinstance(data, dict):
        note = "no data" if code == 404 else f"http {code}"
        return {"ip": ip, "provider": "censys", "alive": False, "ports": "", "asn": "",
                "asn_org": "", "country": "", "hostnames": "", "note": note}, data
    res = (data.get("result") or {}).get("resource") or data.get("result") or {}
    svcs = res.get("services") or []
    return {
        "ip": ip, "provider": "censys", "alive": bool(svcs),
        "ports": ";".join(str(s.get("port", "")) for s in svcs),
        "asn": str(res.get("autonomous_system", {}).get("asn", "")),
        "asn_org": res.get("autonomous_system", {}).get("name", ""),
        "country": res.get("location", {}).get("country_code", ""),
        "hostnames": res.get("dns", {}).get("reverse_dns", {}).get("name", ""),
        "note": f"at={at_time}" if at_time else "",
    }, data


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Passive Shodan/Censys host lookup (APT Watch).")
    ap.add_argument("targets", nargs="*", help="IPs and/or CIDRs")
    ap.add_argument("-f", "--file", help="file with IPs/CIDRs (one per line, # comments)")
    ap.add_argument("-p", "--provider", default="internetdb",
                    choices=["internetdb", "shodan", "censys", "all"])
    ap.add_argument("--config", help="path to config.ini (default: $APTWATCH_CONFIG or ./config.ini)")
    ap.add_argument("--key-encoding", default="plain", choices=["plain", "base64"],
                    help="how keys are stored in config.ini (default plain)")
    ap.add_argument("--at-time", help="Censys only: RFC3339 historical timestamp")
    ap.add_argument("--org-id", help="Censys organization_id (optional)")
    ap.add_argument("--out", help="output prefix; writes <prefix>.csv (+ .json with --json)")
    ap.add_argument("--json", action="store_true", help="also write full raw responses to <prefix>.json")
    ap.add_argument("--delay", type=float, default=0.2, help="seconds between calls (politeness)")
    ap.add_argument("--max-hosts", type=int, default=256, help="cap when expanding a CIDR for per-IP providers")
    args = ap.parse_args()

    targets = read_targets(args.targets, args.file)
    if not targets:
        ap.error("no targets (pass IPs/CIDRs and/or --file)")
    keys = load_keys(args.config, args.key_encoding)
    print(f"[*] {len(targets)} target(s); provider={args.provider}; "
          f"config={keys['config_used'] or 'none'}", file=sys.stderr)

    providers = ["internetdb", "shodan", "censys"] if args.provider == "all" else [args.provider]
    rows, raws = [], {}

    for prov in providers:
        if prov == "internetdb":
            ips, _ = expand_for_per_ip(targets, args.max_hosts)
            for ip in ips:
                row, raw = q_internetdb(ip, args.delay)
                rows.append(row)
                if raw is not None:
                    raws.setdefault(ip, {})["internetdb"] = raw
        elif prov == "shodan":
            if not keys["shodan"]:
                print("[error] no Shodan key (SHODAN_API_KEY or [api_keys] shodan_api_key)", file=sys.stderr)
                continue
            for t in targets:
                if "/" in t:
                    r, raw = q_shodan_search(t, keys["shodan"], args.delay)
                    rows.extend(r)
                    raws.setdefault(t, {})["shodan_search"] = raw
                else:
                    row, raw = q_shodan_host(t, keys["shodan"], args.delay)
                    rows.append(row)
                    if raw is not None:
                        raws.setdefault(t, {})["shodan"] = raw
        elif prov == "censys":
            if not keys["censys"]:
                print("[error] no Censys token (CENSYS_API_TOKEN or [api_keys] censys_api_token)", file=sys.stderr)
                continue
            ips, _ = expand_for_per_ip(targets, args.max_hosts)
            for ip in ips:
                row, raw = q_censys(ip, keys["censys"], args.delay,
                                    at_time=args.at_time, org_id=args.org_id)
                rows.append(row)
                if raw is not None:
                    raws.setdefault(ip, {})["censys"] = raw

    # ---- output ----
    cols = ["ip", "provider", "alive", "ports", "asn", "asn_org", "country", "hostnames", "note"]
    if args.out:
        with open(args.out + ".csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
        print(f"[ok] wrote {args.out}.csv ({len(rows)} rows)", file=sys.stderr)
        if args.json:
            with open(args.out + ".json", "w", encoding="utf-8") as f:
                json.dump(raws, f, indent=2)
            print(f"[ok] wrote {args.out}.json", file=sys.stderr)
    else:
        w = csv.DictWriter(sys.stdout, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    alive = sum(1 for r in rows if r["alive"])
    print(f"[*] done: {alive}/{len(rows)} alive", file=sys.stderr)


if __name__ == "__main__":
    main()
