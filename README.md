# KQL Detection Library

[![CI](https://github.com/CadGoose/kql-detection-library/actions/workflows/ci.yml/badge.svg)](https://github.com/CadGoose/kql-detection-library/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-cadgoose.github.io-9a3412)](https://cadgoose.github.io/kql-detection-library/)
![Detections](https://img.shields.io/badge/detections-25-16181d)
![License](https://img.shields.io/badge/license-MIT-blue)

Detection rules for **Microsoft Sentinel** and **Microsoft Defender XDR**, written the way a SOC actually needs them. Each one is mapped to MITRE ATT&CK, explains *why* the behaviour matters, and ships with false-positive notes and tuning advice.

**Browse the library:** https://cadgoose.github.io/kql-detection-library/ (searchable, with ATT&CK coverage and copy-to-clipboard queries)

## Why this exists

Most public KQL collections are a folder of queries with no context. In a multi-tenant SOC you need more than the query: what normal looks like, what will false-positive on day one, and what to fix so the alert stops firing. Every detection here carries that context, and the repo itself is treated like code: schema-validated, linted and tested in CI, and deployable to Sentinel as an ARM template.

## What's covered

| Area | Examples |
|---|---|
| **Identity (Entra ID)** | legacy-auth success, password spray, MFA fatigue, new-country sign-in, break-glass use, admin portals without CA |
| **Privilege & persistence** | role assigned outside PIM, after-hours PIM activation, MFA method registered from an unknown IP, app credentials added, federation changes |
| **Defense evasion** | Conditional Access weakened, suspicious BEC inbox rules, LOLBin downloads |
| **Email (Exchange / MDO)** | external forwarding, FullAccess/SendAs grants, clicks on phishing later removed by ZAP |
| **Endpoint (MDE)** | encoded PowerShell (decoded inline), LSASS dumping, Office spawning script hosts, local admin added, RDP exposed to the internet |
| **Impact** | shadow copy / backup catalog deletion before ransomware |

Run `kqldl list` for the full table.

## Detection format

Each detection is one YAML file in `detections/<tactic>/`:

```yaml
id: KDL-0003
name: MFA fatigue - repeated MFA denials followed by success
severity: High
platforms: [Sentinel]
data_sources: [SigninLogs]
tactics: [CredentialAccess]
techniques: [T1621]
query_frequency: PT1H
query_period: PT2H
query: |
  SigninLogs
  | where TimeGenerated > ago(2h)
  ...
entity_mappings:
  - { entity: Account, field: FullName, column: UserPrincipalName }
false_positives: [...]
tuning: [...]
references: [...]
```

## Tooling

```bash
pip install -e ".[dev]"

kqldl validate                  # schema + ATT&CK IDs + KQL lint (brackets, strings, time bounds)
kqldl list                      # table of all detections
kqldl export-arm -o rules.json  # Sentinel analytics rules as an ARM template
kqldl build-docs -o site        # the static docs site
```

The validator enforces things that break in production:
- unique IDs, and filenames that match them
- tactics that match the folder
- real ATT&CK technique IDs
- `queryPeriod` of 14 days or less (the Sentinel limit) and never shorter than `queryFrequency`
- entity-mapping columns that actually exist in the query output
- a time filter on every query, so no unbounded scans

### Deploy to Sentinel

```bash
kqldl export-arm -o dist/rules.json --disabled   # deploy disabled first, enable after tuning
az deployment group create -g <resource-group> \
  --template-file dist/rules.json --parameters workspace=<log-analytics-workspace>
```

Rule GUIDs are derived from the detection ID, so redeploying updates rules in place instead of creating duplicates. CI also attaches the generated template as a build artifact on every push.

## Using the queries directly

- **Sentinel:** paste any query into *Logs* or create a scheduled analytics rule.
- **Defender XDR advanced hunting:** detections tagged `DefenderXDR` use native tables (`DeviceProcessEvents`, `EmailEvents`, ...) and `Timestamp`, so they run as-is. Identity detections use `SigninLogs` / `AuditLogs`, which are available in the unified portal when Sentinel is connected.

Placeholder values (domains, break-glass UPNs, business hours) are clearly marked in each query. Replace them with yours or move them to a watchlist.

## Contributing

1. Copy an existing YAML and give it the next free `KDL-` number.
2. Run `kqldl validate && pytest`.
3. Open a PR describing a true positive you have seen (sanitized).

## Author

**George Mkahail**: Cyber Security & Cloud Infrastructure Specialist (Toronto). Security+, CCNA, ISC2 CC.
Portfolio: https://cadgoose.github.io · GitHub: [@CadGoose](https://github.com/CadGoose)

Released under the [MIT License](LICENSE). Test every rule in your own environment before enabling it in production.
