# PKI Certificate Monitor - Checkmk 2.3

A Checkmk plugin for monitoring Microsoft Active Directory Certificate Services (ADCS) and tracking certificate expiration across your PKI infrastructure.

**This version is compatible with Checkmk 2.3.x only.** For Checkmk 2.4+, use the `pki_monitor` directory.

## Features

- Monitor Certificate Authority health and service status
- Track CA certificate expiration
- Monitor issued certificate expiration summary
- Individual expiring certificate alerts with details

## Requirements

- Checkmk 2.3.0 - 2.3.x (not compatible with 2.4+)
- Windows hosts with ADCS role or RSAT-ADCS-Mgmt tools
- PowerShell 5.1+

## Installation

### Build the MKP Package

```bash
cd pki_monitor_2.3
./build_mkp.sh
```

This creates `pki_monitor-1.0.0.mkp` in the current directory.

### Install on Checkmk Server

```bash
# Copy to Checkmk container
docker cp pki_monitor-1.0.0.mkp checkmk-monitoring:/tmp/

# Install the package
docker exec -it checkmk-monitoring su - cmk -c 'mkp add /tmp/pki_monitor-1.0.0.mkp'
docker exec -it checkmk-monitoring su - cmk -c 'mkp enable pki_monitor 1.0.0'
docker exec -it checkmk-monitoring su - cmk -c 'cmk -R'
```

### Deploy Windows Agent Plugin

Copy the following files to your Windows hosts with ADCS:

- `pki_monitor.ps1` -> `C:\ProgramData\checkmk\agent\plugins\`
- `pki_monitor.cfg.ps1` -> `C:\ProgramData\checkmk\agent\plugins\` (optional, for configuration)

## Configuration

### Windows Agent Configuration

Edit `pki_monitor.cfg.ps1` to customize:

```powershell
$script:Config = @{
    ExpireWarningDays = 30      # Days before expiration to warn
    ExpireCriticalDays = 14     # Days before expiration to go critical
    MaxCertificates = 1000      # Maximum certificates to retrieve per CA
    IncludeExpired = $false     # Include already expired certificates
    MonitoringPeriodDays = 365  # Monitoring period for certificates
}
```

### Checkmk WATO Rules

Configure thresholds in WATO under **Setup > Services > Service monitoring rules**:

- **PKI Certificate Authority** - CA certificate expiration thresholds
- **PKI Certificate Summary** - (Future expansion)
- **PKI Expiring Certificates** - Individual certificate thresholds and display limits

## Services Created

| Service Name | Description |
|-------------|-------------|
| PKI CA `<name>` | CA health, service status, CA certificate expiration |
| PKI Certificates `<name>` | Certificate expiration summary counts |
| PKI Expiring Certs `<name>` | Individual expiring certificate details |

## Metrics

- `ca_cert_days_remaining` - Days until CA certificate expires
- `ca_template_count` - Number of certificate templates
- `certs_critical` - Certificates expiring critically soon
- `certs_warning` - Certificates expiring soon (warning)
- `certs_ok` - Certificates with OK expiration status
- `certs_total` - Total monitored certificates

## Troubleshooting

### Test Agent Plugin

```powershell
# On Windows host
powershell -ExecutionPolicy Bypass -File "C:\ProgramData\checkmk\agent\plugins\pki_monitor.ps1"
```

### Test Check on Checkmk Server

```bash
# Discover services
cmk -vI --detect-plugins=pki_ca_info,pki_cert_summary,pki_expiring_certs hostname

# Run checks manually
cmk --detect-plugins=pki_ca_info,pki_cert_summary,pki_expiring_certs -v hostname

# View raw agent output
cmk -d hostname | grep -A 50 "<<<pki_"
```

## Directory Structure

```
pki_monitor_2.3/
├── build_mkp.sh                          # Build script for 2.3 MKP format
├── README.md
├── local/
│   ├── lib/python3/cmk/
│   │   ├── base/plugins/agent_based/
│   │   │   └── pki_monitor.py            # Check plugins
│   │   └── gui/plugins/
│   │       ├── wato/
│   │       │   └── pki_monitor.py        # WATO rulesets
│   │       └── metrics/
│   │           └── pki_monitor.py        # Metrics/graphing
│   └── share/check_mk/agents/windows/plugins/
│       ├── pki_monitor.ps1               # Windows agent plugin
│       └── pki_monitor.cfg.ps1           # Agent configuration
└── tests/
    └── (test files)
```

## License

MIT License
