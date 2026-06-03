# APT Watch -- https://github.com/aptwatcher/aptwatch -- SPDX-License-Identifier: Unlicense (public domain)
# Part of the APT Watch project (defensive Russian-APT threat intelligence).
<#
.SYNOPSIS
  Passive OSINT host lookup (Shodan / Censys) for APT Watch collaborators.

.DESCRIPTION
  Native PowerShell twin of tools/osint_lookup.py. Queries Shodan (free
  InternetDB or keyed) and Censys (Platform v3) for IPs/CIDRs from -Target
  and/or -File, and writes a normalized CSV (+ optional full JSON). Passive:
  these providers report what they already scanned, so they see hosts that
  drop ICMP / refuse direct probing.

  NO KEYS IN THIS REPO. Keys are read at runtime:
    1. env vars  $env:SHODAN_API_KEY / $env:CENSYS_API_TOKEN   (priority)
    2. an INI config [api_keys] shodan_api_key / censys_api_token
       (default search: -Config, then $env:APTWATCH_CONFIG, then .\config.ini)
  For STTR/private use the keys live in apt-intel\config.ini (never committed).

.EXAMPLE
  .\osint_lookup.ps1 -Target 198.51.100.10,198.51.100.20 -Provider internetdb

.EXAMPLE
  .\osint_lookup.ps1 -File targets.txt -Provider censys -AtTime 2026-04-01T00:00:00Z `
      -Config ..\apt-intel\config.ini -Out myblock_apr

.EXAMPLE
  .\osint_lookup.ps1 -Target 192.0.2.0/24 -Provider shodan -Out myblock
#>
[CmdletBinding()]
param(
  [string[]]$Target,
  [string]$File,
  [ValidateSet('internetdb','shodan','censys','all')][string]$Provider = 'internetdb',
  [string]$Config,
  [ValidateSet('plain','base64')][string]$KeyEncoding = 'plain',
  [string]$AtTime,
  [string]$OrgId,
  [string]$Out,
  [switch]$Json,
  [double]$Delay = 0.2,
  [int]$MaxHosts = 256
)

function Get-IniValue {
  param($Path,$Section,$Key)
  if (-not (Test-Path $Path)) { return $null }
  $cur = $null
  foreach ($line in Get-Content $Path) {
    $t = $line.Trim()
    if ($t -match '^\[(.+)\]$') { $cur = $Matches[1]; continue }
    if ($cur -eq $Section -and $t -match '^\s*([^#;][^=]*?)\s*=\s*(.*)$' -and $Matches[1].Trim() -eq $Key) {
      return $Matches[2].Trim()
    }
  }
  return $null
}
function Resolve-Key([string]$v,[string]$enc) {
  if (-not $v) { return $v }
  if ($enc -eq 'base64') { try { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($v)).Trim() } catch { return $v } }
  return $v
}
function Resolve-ConfigPath([string]$explicit) {
  foreach ($c in @($explicit, $env:APTWATCH_CONFIG, '.\config.ini')) { if ($c -and (Test-Path $c)) { return $c } }
  return $null
}
function Expand-Cidr {
  param([string]$cidr,[int]$max)
  $a,$p = $cidr.Split('/'); $p = [int]$p
  $bytes = [Net.IPAddress]::Parse($a).GetAddressBytes(); [Array]::Reverse($bytes)
  $base = [uint64][BitConverter]::ToUInt32($bytes,0)
  $size = [uint64][math]::Pow(2, 32 - $p)
  $net  = $base - ($base % $size)
  $first = if ($p -lt 31) { $net + 1 } else { $net }
  $last  = if ($p -lt 31) { $net + $size - 2 } else { $net + $size - 1 }
  $out = New-Object System.Collections.Generic.List[string]; $n = 0
  for ($i = $first; $i -le $last -and $n -lt $max; $i++) {
    $o = [BitConverter]::GetBytes([uint32]$i); [Array]::Reverse($o)
    $out.Add(([Net.IPAddress]::new($o)).ToString()); $n++
  }
  if (($last - $first + 1) -gt $max) { Write-Warning "$cidr truncated to $max hosts" }
  $out
}
function Get-Targets([string[]]$t,[string]$f) {
  $raw = New-Object System.Collections.Generic.List[string]
  if ($t) { $t | ForEach-Object { $raw.Add($_) } }
  if ($f -and (Test-Path $f)) {
    Get-Content $f | ForEach-Object { $l = $_.Trim(); if ($l -and -not $l.StartsWith('#')) { $raw.Add(($l -split '\s+')[0]) } }
  }
  $raw | Select-Object -Unique
}
function Expand-PerIp([string[]]$targets,[int]$max) {
  $ips = New-Object System.Collections.Generic.List[string]
  foreach ($t in $targets) { if ($t -match '/') { Expand-Cidr $t $max | ForEach-Object { $ips.Add($_) } } else { $ips.Add($t) } }
  $ips | Select-Object -Unique
}

$cfgPath = Resolve-ConfigPath $Config
$shodanKey = if ($env:SHODAN_API_KEY) { $env:SHODAN_API_KEY } else { Resolve-Key (Get-IniValue $cfgPath 'api_keys' 'shodan_api_key') $KeyEncoding }
$censysTok = if ($env:CENSYS_API_TOKEN) { $env:CENSYS_API_TOKEN } else { Resolve-Key (Get-IniValue $cfgPath 'api_keys' 'censys_api_token') $KeyEncoding }

$targets = Get-Targets $Target $File
if (-not $targets) { Write-Error "No targets (pass -Target and/or -File)"; exit 1 }
Write-Host "[*] $($targets.Count) target(s); provider=$Provider; config=$([string]::IsNullOrEmpty($cfgPath) ? 'none' : $cfgPath)"

$rows = New-Object System.Collections.Generic.List[object]
$raws = @{}
$delayMs = [int]($Delay * 1000)
$provs = if ($Provider -eq 'all') { @('internetdb','shodan','censys') } else { @($Provider) }

function New-Row($ip,$prov,$alive,$ports,$asn,$org,$country,$hostnames,$note) {
  [pscustomobject]@{ ip=$ip; provider=$prov; alive=$alive; ports=$ports; asn=$asn; asn_org=$org; country=$country; hostnames=$hostnames; note=$note }
}

foreach ($prov in $provs) {
  switch ($prov) {
    'internetdb' {
      foreach ($ip in (Expand-PerIp $targets $MaxHosts)) {
        try {
          $r = Invoke-RestMethod "https://internetdb.shodan.io/$ip" -TimeoutSec 12
          $rows.Add((New-Row $ip 'internetdb' ([bool]$r.ports) (($r.ports) -join ';') '' '' '' (($r.hostnames) -join ';') (($r.tags + ($r.vulns | Select-Object -First 5)) -join ';')))
          $raws[$ip] = @{ internetdb = $r }
        } catch {
          $code = $_.Exception.Response.StatusCode.value__
          $rows.Add((New-Row $ip 'internetdb' $false '' '' '' '' '' ($(if ($code -eq 404){'no data'}else{"http $code"}))))
        }
        Start-Sleep -Milliseconds $delayMs
      }
    }
    'shodan' {
      if (-not $shodanKey) { Write-Error "No Shodan key (SHODAN_API_KEY or [api_keys] shodan_api_key)"; continue }
      foreach ($t in $targets) {
        try {
          if ($t -match '/') {
            $q = [uri]::EscapeDataString("net:$t")
            $r = Invoke-RestMethod "https://api.shodan.io/shodan/host/search?key=$shodanKey&query=$q" -TimeoutSec 25
            foreach ($m in $r.matches) { $rows.Add((New-Row $m.ip_str 'shodan-search' $true (($m.ports) -join ';') ("$($m.asn)" -replace 'AS','') $m.org $m.location.country_code (($m.hostnames) -join ';') "cidr=$t")) }
            if (-not $r.matches) { $rows.Add((New-Row $t 'shodan-search' $false '' '' '' '' '' '0 matches')) }
            Start-Sleep -Milliseconds ([math]::Max($delayMs,1000))
          } else {
            $r = Invoke-RestMethod "https://api.shodan.io/shodan/host/$t`?key=$shodanKey" -TimeoutSec 20
            $rows.Add((New-Row $t 'shodan' ([bool]$r.ports) (($r.ports) -join ';') ("$($r.asn)" -replace 'AS','') $r.org $r.country_code (($r.hostnames) -join ';') ''))
            $raws[$t] = @{ shodan = $r }
            Start-Sleep -Milliseconds $delayMs
          }
        } catch {
          $code = $_.Exception.Response.StatusCode.value__
          $rows.Add((New-Row $t 'shodan' $false '' '' '' '' '' ($(if ($code -eq 404){'no data'}else{"http $code"}))))
        }
      }
    }
    'censys' {
      if (-not $censysTok) { Write-Error "No Censys token (CENSYS_API_TOKEN or [api_keys] censys_api_token)"; continue }
      $h = @{ Authorization = "Bearer $censysTok"; Accept = "application/vnd.censys.api.v3.host.v1+json" }
      foreach ($ip in (Expand-PerIp $targets $MaxHosts)) {
        $u = "https://api.platform.censys.io/v3/global/asset/host/$ip"
        $qp = @(); if ($AtTime) { $qp += "at_time=$AtTime" }; if ($OrgId) { $qp += "organization_id=$OrgId" }
        if ($qp) { $u += "?" + ($qp -join '&') }
        try {
          $res = (Invoke-RestMethod -Uri $u -Headers $h -TimeoutSec 20).result.resource
          $svc = @($res.services)
          $rows.Add((New-Row $ip 'censys' ([bool]$svc.Count) (($svc.port) -join ';') "$($res.autonomous_system.asn)" $res.autonomous_system.name $res.location.country_code $res.dns.reverse_dns.name ($(if($AtTime){"at=$AtTime"}else{''}))))
          $raws[$ip] = @{ censys = $res }
        } catch {
          $code = $_.Exception.Response.StatusCode.value__
          $rows.Add((New-Row $ip 'censys' $false '' '' '' '' '' ($(if ($code -eq 404){'no data'}else{"http $code"}))))
        }
        Start-Sleep -Milliseconds ([math]::Max($delayMs,300))
      }
    }
  }
}

if ($Out) {
  $rows | Export-Csv "$Out.csv" -NoTypeInformation -Encoding UTF8
  Write-Host "[ok] $Out.csv ($($rows.Count) rows)"
  if ($Json) { $raws | ConvertTo-Json -Depth 30 | Set-Content "$Out.json" -Encoding UTF8; Write-Host "[ok] $Out.json" }
} else {
  $rows | Format-Table ip,provider,alive,ports,asn,country,note -Auto
}
$alive = ($rows | Where-Object { $_.alive }).Count
Write-Host "[*] done: $alive/$($rows.Count) alive"
