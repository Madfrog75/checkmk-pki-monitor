# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Checkmk 2.3.x compatible plugin for monitoring Microsoft Active Directory Certificate Services (ADCS). It tracks certificate expiration across PKI infrastructure using a PowerShell agent plugin and Python check plugins.

**Version Compatibility:** Checkmk 2.3.0 - 2.3.x only. For Checkmk 2.4+, use the main `pki_monitor` directory.

## Build and Test Commands

```bash
# Build MKP package
./build_mkp.sh

# Verify Python syntax
python3 -m py_compile local/lib/python3/cmk/base/plugins/agent_based/pki_monitor.py
python3 -m py_compile local/lib/python3/cmk/gui/plugins/wato/pki_monitor.py
python3 -m py_compile local/lib/python3/cmk/gui/plugins/metrics/pki_monitor.py

# Test agent plugin on Windows
powershell -ExecutionPolicy Bypass -File "C:\ProgramData\checkmk\agent\plugins\pki_monitor.ps1"

# Test on Checkmk server
cmk -vI --detect-plugins=pki_ca_info,pki_cert_summary,pki_expiring_certs hostname
cmk --detect-plugins=pki_ca_info,pki_cert_summary,pki_expiring_certs -v hostname
```

## Architecture

### Data Flow
1. **PowerShell Agent** (`local/share/check_mk/agents/windows/plugins/pki_monitor.ps1`) runs on Windows hosts with ADCS, queries CA databases via COM objects, outputs semicolon-separated sections
2. **Python Check Plugins** (`local/lib/python3/cmk/base/plugins/agent_based/pki_monitor.py`) parse agent output, evaluate thresholds, yield Results and Metrics
3. **WATO Rulesets** (`local/lib/python3/cmk/gui/plugins/wato/pki_monitor.py`) define GUI configuration for thresholds
4. **Metrics** (`local/lib/python3/cmk/gui/plugins/metrics/pki_monitor.py`) define metric visualization

### Agent Output Sections
The PowerShell agent outputs three sections with `sep(59)` (semicolon separator):

- `<<<pki_ca_info>>>`: `CAName;DNSHostName;ServiceStatus;CACertDaysUntilExpire;TemplateCount`
- `<<<pki_cert_summary>>>`: `CAName;CriticalCount;WarningCount;OKCount;TotalCount`
- `<<<pki_expiring_certs>>>`: `CAName;CommonName;ExpirationDate;DaysUntilExpire;Template;Thumbprint`

### Checkmk Plugin Pattern
Each check follows this pattern:
1. `AgentSection` with `parse_function` transforms raw lines into dicts
2. `discover_*` yields `Service(item=ca_name)` for each CA
3. `check_*` receives `item`, `params`, `section` and yields `Result`/`Metric`
4. `CheckPlugin` wires everything together with `check_ruleset_name` linking to rulesets

### Key APIs (Checkmk 2.3)
- `cmk.agent_based.v2` for check plugins
- `cmk.gui.plugins.wato.utils` with `CheckParameterRulespecWithItem` for WATO rules
- `cmk.gui.valuespec` for form elements (Dictionary, Integer, etc.)
- `cmk.gui.plugins.metrics.utils` with `metric_info`, `graph_info`, `perfometer_info` dicts
- PowerShell uses `CertificateAuthority.View` COM object to query CA database

## Checkmk 2.3 vs 2.4 Differences

| Component | Checkmk 2.3 | Checkmk 2.4+ |
|-----------|-------------|--------------|
| Rulesets | `cmk.gui.plugins.wato.utils` with `CheckParameterRulespecWithItem` | `cmk.rulesets.v1` with `CheckParameters` |
| Valuespec | `cmk.gui.valuespec.Dictionary`, `Integer` | `cmk.rulesets.v1.form_specs.Dictionary`, `Integer` |
| Metrics | `metric_info`, `graph_info`, `perfometer_info` dicts | `cmk.graphing.v1` with `Metric`, `Graph`, `Perfometer` classes |
| MKP Format | Tar archives inside tar.gz | Nested tar archives with `cmk_addons_plugins` structure |
| Plugin Path | `cmk/base/plugins/agent_based/` | `cmk_addons/plugins/<name>/agent_based/` |

## Requirements

- Checkmk 2.3.0 - 2.3.x
- Windows hosts need ADCS role or RSAT-ADCS-Mgmt tools
- PowerShell 5.1+
