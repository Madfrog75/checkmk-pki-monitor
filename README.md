# PKI Monitor - Checkmk Plugin

A Checkmk plugin for monitoring Microsoft Active Directory Certificate Services (ADCS) and tracking certificate expiration across your PKI infrastructure.

## Features

- **Certificate Authority Monitoring**
  - CA service status (running/stopped)
  - CA certificate expiration tracking
  - Template count reporting

- **Certificate Expiration Tracking**
  - Summary of expiring certificates per CA
  - Individual certificate expiration alerts
  - Configurable warning and critical thresholds

- **Metrics and Visualization**
  - Certificate expiration graphs
  - Perfometers for quick status overview
  - Historical trend data

## Requirements

### Checkmk Server
- Checkmk version 2.3.0 or later
- Checkmk Raw, Enterprise, or Cloud edition

### Monitored Windows Hosts
- Windows Server 2012 R2 or later
- PowerShell 5.1 or later
- One of the following:
  - Active Directory Certificate Services (ADCS) role installed
  - RSAT-ADCS-Mgmt tools installed
- Network connectivity to Certificate Authority servers
- Appropriate permissions to query CA database

## Installation

### Option 1: MKP Package (Recommended)

1. Download the `pki_monitor-1.0.0.mkp` package
2. Upload via Checkmk GUI: Setup → Extension Packages → Upload package
3. Activate the package

### Option 2: Manual Installation

#### Checkmk Server

Copy the following directories to your Checkmk site's `local` directory:

```bash
# As site user (e.g., su - mysite)
cp -r local/lib/python3/cmk_addons/plugins/pki_monitor ~/local/lib/python3/cmk_addons/plugins/
```

#### Windows Agent

1. Copy `pki_monitor.ps1` to the Windows agent plugins directory:
   ```
   C:\ProgramData\checkmk\agent\plugins\pki_monitor.ps1
   ```

2. (Optional) Copy and customize the configuration file:
   ```
   C:\ProgramData\checkmk\agent\plugins\pki_monitor.cfg.ps1
   ```

3. Restart the Checkmk agent service or wait for the next check interval

## Configuration

### Agent Configuration

Edit `pki_monitor.cfg.ps1` on the monitored Windows host:

```powershell
$script:Config = @{
    # Days before expiration to trigger WARNING
    ExpireWarningDays = 30

    # Days before expiration to trigger CRITICAL
    ExpireCriticalDays = 14

    # Maximum certificates to retrieve per CA
    MaxCertificates = 1000

    # Include recently expired certificates
    IncludeExpired = $false

    # Cache results (minutes)
    CacheTimeMinutes = 60
}
```

### Checkmk Rules

Configure monitoring parameters via the Checkmk GUI:

1. **Setup → Services → Service monitoring rules**
2. Search for "PKI" to find available rules:
   - **PKI Certificate Authority**: CA service and certificate thresholds
   - **PKI Certificate Summary**: Summary monitoring settings
   - **PKI Expiring Certificates**: Individual certificate thresholds

## Services Created

The plugin creates the following services on monitored hosts:

| Service Name | Description |
|--------------|-------------|
| PKI CA *[CAName]* | Certificate Authority health and status |
| PKI Certificates *[CAName]* | Summary of certificate expiration counts |
| PKI Expiring Certs *[CAName]* | Details of individual expiring certificates |

## Metrics

| Metric | Description |
|--------|-------------|
| `ca_cert_days_remaining` | Days until CA certificate expires |
| `ca_template_count` | Number of certificate templates |
| `certs_critical` | Certificates expiring critically soon |
| `certs_warning` | Certificates with warning-level expiration |
| `certs_ok` | Certificates with OK status |
| `certs_total` | Total certificates monitored |

## Troubleshooting

### Agent Output

Test the agent plugin manually on the Windows host:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\ProgramData\checkmk\agent\plugins\pki_monitor.ps1"
```

Expected output format:
```
<<<pki_ca_info:sep(59)>>>
MyCA;ca.domain.com;Running;365;15
<<<pki_cert_summary:sep(59)>>>
MyCA;0;5;100;105
<<<pki_expiring_certs:sep(59)>>>
MyCA;webserver.domain.com;2024-03-15 12:00:00;14;WebServer;ABC123
```

### Common Issues

1. **No CAs found**
   - Verify ADCS role or RSAT tools are installed
   - Check domain connectivity
   - Ensure the service account has permissions

2. **Permission errors**
   - The Checkmk agent service account needs read access to CA database
   - Consider running the agent as a domain account with CA read permissions

3. **Service discovery not working**
   - Run discovery on the host: `cmk -vI hostname`
   - Check agent output: `cmk -d hostname`

## Development

### Project Structure

```
pki_monitor/
├── local/
│   ├── lib/python3/cmk_addons/plugins/pki_monitor/
│   │   ├── agent_based/
│   │   │   └── pki_monitor.py      # Check plugins
│   │   ├── rulesets/
│   │   │   └── pki_monitor.py      # WATO rules
│   │   └── graphing/
│   │       └── pki_monitor.py      # Metrics/graphs
│   └── share/check_mk/agents/windows/plugins/
│       ├── pki_monitor.ps1         # Agent plugin
│       └── pki_monitor.cfg.ps1     # Configuration
├── tests/
│   └── test_pki_monitor.py
├── package_info.json
└── README.md
```

### Testing

Run the check plugin tests:

```bash
pytest tests/test_pki_monitor.py -v
```

Test on Checkmk server:

```bash
# Discover services
cmk -vI --detect-plugins=pki_ca_info,pki_cert_summary,pki_expiring_certs hostname

# Run checks
cmk --detect-plugins=pki_ca_info,pki_cert_summary,pki_expiring_certs -v hostname
```

## Credits

- Based on [PKITools](https://github.com/BladeFireLight/PKITools) by BladeFireLight
- Plugin structure inspired by [kpc_windows_updates](https://github.com/matthias1232/kpc_windows_updates)
- Checkmk documentation: [Developing agent-based check plugins](https://docs.checkmk.com/latest/en/devel_check_plugins.html)

## License

MIT License - See LICENSE file for details.

## Support

For issues and feature requests, please open an issue in the repository.
