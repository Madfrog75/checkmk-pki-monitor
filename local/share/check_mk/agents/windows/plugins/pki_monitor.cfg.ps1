<#
.SYNOPSIS
    Configuration file for PKI Monitor Checkmk Agent Plugin
.DESCRIPTION
    Modify these settings to customize the plugin behavior.
    Place this file alongside pki_monitor.ps1 or in the same directory.
#>

# Override default configuration
$script:Config = @{
    # Number of days before expiration to trigger WARNING state
    ExpireWarningDays = 30

    # Number of days before expiration to trigger CRITICAL state
    ExpireCriticalDays = 14

    # Maximum number of certificates to retrieve per CA
    # Set lower if you have many certificates and performance is an issue
    MaxCertificates = 1000

    # Include certificates that have already expired (last 30 days)
    IncludeExpired = $false

    # Cache results for this many minutes (reduces CA load)
    # Note: Checkmk agent typically runs every minute, caching prevents overload
    CacheTimeMinutes = 60

    # Monitoring period in days - certificates expiring within this period are
    # included in the summary total. Certificates expiring beyond this are not monitored.
    # Set to a higher value (e.g., 3650 for ~10 years) to monitor more certificates.
    MonitoringPeriodDays = 365
}

# Optional: Specify specific CAs to monitor (leave empty to auto-discover all)
# $script:MonitorCAs = @("MyCA1", "MyCA2")

# Optional: Exclude specific certificate templates from monitoring
# $script:ExcludeTemplates = @("ShortLivedCert", "AutoEnrollTemplate")
