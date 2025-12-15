# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Checkmk plugin for monitoring Microsoft Active Directory Certificate Services (ADCS). It tracks certificate expiration across PKI infrastructure using a PowerShell agent plugin and Python check plugins.

## Build and Test Commands

```bash
# Build MKP package
./build_mkp.sh

# Verify Python syntax
python3 -m py_compile local/lib/python3/cmk_addons/plugins/pki_monitor/agent_based/pki_monitor.py

# Run tests (if pytest available)
pytest tests/test_pki_monitor.py -v

# Test agent plugin on Windows
powershell -ExecutionPolicy Bypass -File "C:\ProgramData\checkmk\agent\plugins\pki_monitor.ps1"

# Test on Checkmk server
cmk -vI --detect-plugins=pki_ca_info,pki_cert_summary,pki_expiring_certs hostname
cmk --detect-plugins=pki_ca_info,pki_cert_summary,pki_expiring_certs -v hostname
```

## Architecture

### Data Flow
1. **PowerShell Agent** (`local/share/check_mk/agents/windows/plugins/pki_monitor.ps1`) runs on Windows hosts with ADCS, queries CA databases via COM objects, outputs semicolon-separated sections
2. **Python Check Plugins** (`local/lib/python3/cmk_addons/plugins/pki_monitor/agent_based/pki_monitor.py`) parse agent output, evaluate thresholds, yield Results and Metrics
3. **Rulesets** define WATO configuration for thresholds
4. **Graphing** defines metric visualization

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

### Key APIs
- Uses `cmk.agent_based.v2` for check plugins (Checkmk 2.3+)
- Uses `cmk.rulesets.v1` for WATO rules
- Uses `cmk.graphing.v1` for metrics/perfometers
- PowerShell uses `CertificateAuthority.View` COM object to query CA database

## Requirements
- Checkmk 2.3.0+
- Windows hosts need ADCS role or RSAT-ADCS-Mgmt tools
- PowerShell 5.1+
