<#
.SYNOPSIS
    Checkmk Agent Plugin for PKI Certificate Monitoring
.DESCRIPTION
    This plugin queries local Certificate Authorities for issued certificates
    and reports on certificate status, expiration, and CA health.
    Based on PKITools by BladeFireLight (https://github.com/BladeFireLight/PKITools)
.NOTES
    Author: Checkmk PKI Monitor Plugin
    Version: 1.0.0
    Requires: Windows Server with ADCS role or RSAT-ADCS tools
#>

#Requires -Version 5.1

# Configuration - can be overridden via config file
$script:Config = @{
    ExpireWarningDays = 30      # Days before expiration to warn
    ExpireCriticalDays = 14     # Days before expiration to go critical
    MaxCertificates = 1000      # Maximum certificates to retrieve per CA
    IncludeExpired = $false     # Include already expired certificates
    CacheTimeMinutes = 60       # Cache results for this many minutes
}

# Load config file if exists
$ConfigPath = Join-Path $PSScriptRoot "pki_monitor.cfg.ps1"
if (Test-Path $ConfigPath) {
    . $ConfigPath
}

# Validate configuration values
function Test-ConfigurationValid {
    $Errors = @()

    if ($script:Config.ExpireCriticalDays -le 0) {
        $Errors += "ExpireCriticalDays must be greater than 0 (current: $($script:Config.ExpireCriticalDays))"
    }
    if ($script:Config.ExpireWarningDays -le 0) {
        $Errors += "ExpireWarningDays must be greater than 0 (current: $($script:Config.ExpireWarningDays))"
    }
    if ($script:Config.ExpireWarningDays -le $script:Config.ExpireCriticalDays) {
        $Errors += "ExpireWarningDays ($($script:Config.ExpireWarningDays)) must be greater than ExpireCriticalDays ($($script:Config.ExpireCriticalDays))"
    }
    if ($script:Config.MaxCertificates -le 0) {
        $Errors += "MaxCertificates must be greater than 0 (current: $($script:Config.MaxCertificates))"
    }

    $MonitoringPeriodDays = if ($null -ne $script:Config.MonitoringPeriodDays) { $script:Config.MonitoringPeriodDays } else { 365 }
    if ($MonitoringPeriodDays -le 0) {
        $Errors += "MonitoringPeriodDays must be greater than 0 (current: $MonitoringPeriodDays)"
    }
    if ($MonitoringPeriodDays -lt $script:Config.ExpireWarningDays) {
        $Errors += "MonitoringPeriodDays ($MonitoringPeriodDays) should be greater than or equal to ExpireWarningDays ($($script:Config.ExpireWarningDays))"
    }

    return $Errors
}

#region Helper Functions

function Get-Domain {
    <#
    .SYNOPSIS
        Get the current Active Directory domain
    #>
    [CmdletBinding()]
    param()
    try {
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
    catch {
        Write-Error "Failed to get current domain: $_"
        return $null
    }
}

function Get-ADPKIEnrollmentServers {
    <#
    .SYNOPSIS
        Query AD for Certificate Authority enrollment servers
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.ActiveDirectory.Domain]$Domain
    )

    try {
        $ConfigNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
        $EnrollmentServersPath = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
        $EnrollmentServers = [ADSI]$EnrollmentServersPath

        if (-not $EnrollmentServers.Children) {
            return $null
        }

        return $EnrollmentServers.Children
    }
    catch {
        Write-Error "Failed to query enrollment servers: $_"
        return $null
    }
}

function Get-CertificateAuthority {
    <#
    .SYNOPSIS
        Get Certificate Authority information from Active Directory
    #>
    [CmdletBinding()]
    param(
        [string[]]$CAName,
        [string[]]$ComputerName
    )

    try {
        $Domain = Get-Domain
        if (-not $Domain) { return $null }

        $EnrollmentServers = Get-ADPKIEnrollmentServers -Domain $Domain
        if (-not $EnrollmentServers) { return $null }

        $CAs = @()
        foreach ($CA in $EnrollmentServers) {
            $CAInfo = @{
                Name = $CA.cn.ToString()
                DNSHostName = $CA.dNSHostName.ToString()
                DisplayName = $CA.displayName.ToString()
                CertificateTemplates = @($CA.certificateTemplates)
                LocationString = "$($CA.dNSHostName)\$($CA.cn)"
            }

            # Apply filters
            if ($CAName -and $CAInfo.Name -notin $CAName) { continue }
            if ($ComputerName -and $CAInfo.DNSHostName -notin $ComputerName) { continue }

            $CAs += [PSCustomObject]$CAInfo
        }

        return $CAs
    }
    catch {
        Write-Error "Failed to get Certificate Authorities: $_"
        return $null
    }
}

function Get-CALocationString {
    <#
    .SYNOPSIS
        Get CA location strings in format "ComputerName\CAName"
    #>
    [CmdletBinding()]
    param(
        [string[]]$CAName,
        [string[]]$ComputerName
    )

    $CAs = Get-CertificateAuthority -CAName $CAName -ComputerName $ComputerName
    if ($CAs) {
        return $CAs | ForEach-Object { $_.LocationString }
    }
    return $null
}

function Get-IssuedCertificate {
    <#
    .SYNOPSIS
        Get certificates issued by a Certificate Authority
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CALocation,

        [int]$ExpireInDays = 365,

        [string]$CommonName,

        [string]$TemplateOID,

        [int]$MaxResults = 1000,

        [switch]$IncludeExpired
    )

    # Initialize COM object to null for proper cleanup
    $CaView = $null

    try {
        # Create CA View COM object
        $CaView = New-Object -ComObject CertificateAuthority.View
        $CaView.OpenConnection($CALocation)

        # Define columns to retrieve
        $Columns = @(
            "Issued Common Name",
            "Certificate Expiration Date",
            "Certificate Effective Date",
            "Certificate Hash",
            "Certificate Template",
            "Request Disposition",
            "Requester Name",
            "Serial Number"
        )

        # Set up columns
        $CaView.SetResultColumnCount($Columns.Count)
        foreach ($Col in $Columns) {
            $ColIndex = $CaView.GetColumnIndex($false, $Col)
            $CaView.SetResultColumn($ColIndex)
        }

        # Set restriction for issued certificates only (disposition = 20)
        $CVR_SEEK_EQ = 1
        $CVR_SORT_NONE = 0
        $CV_COLUMN_QUEUE_DEFAULT = -1

        $DispositionIndex = $CaView.GetColumnIndex($false, "Request Disposition")
        $CaView.SetRestriction($DispositionIndex, $CVR_SEEK_EQ, $CVR_SORT_NONE, 20)

        # Set expiration date restriction
        $ExpirationIndex = $CaView.GetColumnIndex($false, "Certificate Expiration Date")

        if (-not $IncludeExpired) {
            # Only get non-expired certificates
            $CVR_SEEK_GE = 4
            $CaView.SetRestriction($ExpirationIndex, $CVR_SEEK_GE, $CVR_SORT_NONE, (Get-Date))
        }

        if ($ExpireInDays -gt 0) {
            # Set upper bound for expiration
            $CVR_SEEK_LE = 2
            $MaxDate = (Get-Date).AddDays($ExpireInDays)
            $CaView.SetRestriction($ExpirationIndex, $CVR_SEEK_LE, $CVR_SORT_NONE, $MaxDate)
        }

        # Common Name filter
        if ($CommonName) {
            $CNIndex = $CaView.GetColumnIndex($false, "Issued Common Name")
            $CaView.SetRestriction($CNIndex, $CVR_SEEK_EQ, $CVR_SORT_NONE, $CommonName)
        }

        # Template OID filter
        if ($TemplateOID) {
            $TemplateIndex = $CaView.GetColumnIndex($false, "Certificate Template")
            $CaView.SetRestriction($TemplateIndex, $CVR_SEEK_EQ, $CVR_SORT_NONE, $TemplateOID)
        }

        # Open view and iterate results
        $RowEnum = $CaView.OpenView()
        $Certificates = @()
        $Count = 0

        while ($RowEnum.Next() -ne -1 -and $Count -lt $MaxResults) {
            $ColEnum = $RowEnum.EnumCertViewColumn()
            $CertData = @{}

            while ($ColEnum.Next() -ne -1) {
                $ColName = $ColEnum.GetName()
                $ColValue = $ColEnum.GetValue(1)  # CV_OUT_BASE64HEADER
                $CertData[$ColName] = $ColValue
            }

            # Calculate days until expiration
            if ($CertData["Certificate Expiration Date"]) {
                $ExpDate = [DateTime]$CertData["Certificate Expiration Date"]
                $DaysUntilExpire = ($ExpDate - (Get-Date)).Days
                $CertData["DaysUntilExpiration"] = $DaysUntilExpire
            }

            $Certificates += [PSCustomObject]$CertData
            $Count++
        }

        return $Certificates
    }
    catch {
        Write-Error "Failed to query certificates from $CALocation : $_"
        return $null
    }
    finally {
        if ($null -ne $CaView) {
            try {
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($CaView)
            }
            catch {
                # Silently ignore cleanup errors
            }
        }
    }
}

function Get-CAServiceStatus {
    <#
    .SYNOPSIS
        Check the status of Certificate Authority service
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    # Try multiple approaches to query service status
    $Service = $null
    $Errors = @()

    # First try with full FQDN
    try {
        $Service = Get-Service -Name "CertSvc" -ComputerName $ComputerName -ErrorAction Stop
    }
    catch {
        $Errors += "FQDN ($ComputerName): $($_.Exception.Message)"

        # Try with short hostname if FQDN failed
        $ShortName = $ComputerName.Split('.')[0]
        try {
            $Service = Get-Service -Name "CertSvc" -ComputerName $ShortName -ErrorAction Stop
        }
        catch {
            $Errors += "ShortName ($ShortName): $($_.Exception.Message)"

            # Try localhost if this is the local machine
            $LocalHostname = [System.Net.Dns]::GetHostName()
            if ($ComputerName -like "$LocalHostname*" -or $ShortName -eq $LocalHostname) {
                try {
                    $Service = Get-Service -Name "CertSvc" -ErrorAction Stop
                }
                catch {
                    $Errors += "Localhost: $($_.Exception.Message)"
                }
            }
        }
    }

    if ($Service) {
        return @{
            ComputerName = $ComputerName
            ServiceName = $Service.Name
            Status = $Service.Status.ToString()
            StartType = $Service.StartType.ToString()
        }
    }
    else {
        return @{
            ComputerName = $ComputerName
            ServiceName = "CertSvc"
            Status = "Unknown"
            StartType = "Unknown"
            Error = ($Errors -join "; ")
        }
    }
}

function Get-CACertificateInfo {
    <#
    .SYNOPSIS
        Get the CA's own certificate information
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CALocation
    )

    $CertAdmin = $null
    try {
        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin

        # Get CA certificate state
        $CACertState = $CertAdmin.GetCAProperty($CALocation, 0x0000000B, 0, 3, 0)  # CR_PROP_CACERTSTATE

        # Get CA cert expiration
        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $CertProp = $CertAdmin.GetCAProperty($CALocation, 0x0000000C, 0, 3, 0)  # CR_PROP_CACERT
        $Cert.Import([Convert]::FromBase64String($CertProp))

        return @{
            CALocation = $CALocation
            Subject = $Cert.Subject
            Issuer = $Cert.Issuer
            NotBefore = $Cert.NotBefore
            NotAfter = $Cert.NotAfter
            Thumbprint = $Cert.Thumbprint
            DaysUntilExpiration = ($Cert.NotAfter - (Get-Date)).Days
            SerialNumber = $Cert.SerialNumber
        }
    }
    catch {
        return @{
            CALocation = $CALocation
            Error = $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $CertAdmin) {
            try {
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($CertAdmin)
            }
            catch {
                # Silently ignore cleanup errors
            }
        }
    }
}

#endregion

#region Main Execution

function Write-PKIMonitorOutput {
    <#
    .SYNOPSIS
        Main function to output PKI monitoring data in Checkmk format
    #>

    # Validate configuration first
    $ConfigErrors = Test-ConfigurationValid
    if ($ConfigErrors.Count -gt 0) {
        Write-Output "<<<pki_ca_info:sep(59)>>>"
        Write-Output "CONFIG_ERROR;$($ConfigErrors -join ' | ' -replace ';', '_');-1;-1;0"
        Write-Output "<<<pki_cert_summary:sep(59)>>>"
        Write-Output "<<<pki_expiring_certs:sep(59)>>>"
        return
    }

    # Output section header for CA information
    Write-Output "<<<pki_ca_info:sep(59)>>>"

    $CAs = Get-CertificateAuthority
    if (-not $CAs) {
        Write-Output "ERROR;No Certificate Authorities found;-1;-1;0"
        # Output empty sections for summary and expiring certs to avoid stale data
        Write-Output "<<<pki_cert_summary:sep(59)>>>"
        Write-Output "<<<pki_expiring_certs:sep(59)>>>"
        return
    }

    # Store certificate data per CA to avoid duplicate queries
    $CACertificateData = @{}
    $MonitoringPeriodDays = if ($null -ne $script:Config.MonitoringPeriodDays) { $script:Config.MonitoringPeriodDays } else { 365 }

    foreach ($CA in $CAs) {
        try {
            # Get service status (pass full FQDN, function will try fallbacks)
            $ServiceStatus = Get-CAServiceStatus -ComputerName $CA.DNSHostName

            # Get CA certificate info
            $CACertInfo = Get-CACertificateInfo -CALocation $CA.LocationString

            # Output: Name;DNSHostName;ServiceStatus;CACertDaysUntilExpire;TemplateCount
            $DaysExpire = if ($CACertInfo.DaysUntilExpiration) { $CACertInfo.DaysUntilExpiration } else { -1 }
            $TemplateCount = $CA.CertificateTemplates.Count

            Write-Output "$($CA.Name);$($CA.DNSHostName);$($ServiceStatus.Status);$DaysExpire;$TemplateCount"

            # Query certificates ONCE for this CA (within monitoring period)
            # This data will be reused for both summary and individual cert sections
            $AllCerts = @(Get-IssuedCertificate -CALocation $CA.LocationString -ExpireInDays $MonitoringPeriodDays -MaxResults $script:Config.MaxCertificates)
            $CACertificateData[$CA.Name] = @{
                Certificates = $AllCerts
                MaxResultsReached = ($AllCerts.Count -eq $script:Config.MaxCertificates)
                Error = $null
            }
        }
        catch {
            # Per-CA error isolation - output error for this CA but continue with others
            Write-Output "$($CA.Name);$($CA.DNSHostName);Error;-1;0"
            $CACertificateData[$CA.Name] = @{
                Certificates = @()
                MaxResultsReached = $false
                Error = $_.Exception.Message
            }
        }
    }

    # Output section header for issued certificates summary
    Write-Output "<<<pki_cert_summary:sep(59)>>>"

    foreach ($CA in $CAs) {
        $CAData = $CACertificateData[$CA.Name]

        if ($CAData.Error) {
            Write-Output "$($CA.Name);-1;-1;-1;-1;ERROR:$($CAData.Error -replace ';', '_')"
            continue
        }

        $AllCerts = $CAData.Certificates

        # Filter certificates by expiration threshold from the single query result
        $CriticalCount = @($AllCerts | Where-Object { $_.DaysUntilExpiration -le $script:Config.ExpireCriticalDays }).Count
        $WarningCount = @($AllCerts | Where-Object {
            $_.DaysUntilExpiration -gt $script:Config.ExpireCriticalDays -and
            $_.DaysUntilExpiration -le $script:Config.ExpireWarningDays
        }).Count
        $OKCount = @($AllCerts | Where-Object { $_.DaysUntilExpiration -gt $script:Config.ExpireWarningDays }).Count
        $TotalCount = $AllCerts.Count

        # Add indicator if MaxResults was reached (data may be incomplete)
        $MaxResultsFlag = if ($CAData.MaxResultsReached) { ";TRUNCATED" } else { "" }

        # Output: CAName;CriticalCount;WarningCount;OKCount;TotalCount[;TRUNCATED]
        Write-Output "$($CA.Name);$CriticalCount;$WarningCount;$OKCount;$TotalCount$MaxResultsFlag"
    }

    # Output section header for individual expiring certificates
    Write-Output "<<<pki_expiring_certs:sep(59)>>>"

    foreach ($CA in $CAs) {
        $CAData = $CACertificateData[$CA.Name]

        if ($CAData.Error) {
            Write-Output "$($CA.Name);ERROR;$($CAData.Error -replace ';', '_');-1;;;"
            continue
        }

        # Filter to only certificates expiring within warning threshold
        $ExpiringCerts = $CAData.Certificates | Where-Object {
            $_.DaysUntilExpiration -le $script:Config.ExpireWarningDays
        }

        foreach ($Cert in $ExpiringCerts) {
            # Output: CAName;CommonName;ExpirationDate;DaysUntilExpire;Template;Thumbprint
            $ExpDate = if ($Cert."Certificate Expiration Date") {
                ([DateTime]$Cert."Certificate Expiration Date").ToString("yyyy-MM-dd HH:mm:ss")
            } else { "Unknown" }

            $CommonName = $Cert."Issued Common Name" -replace ';', '_'  # Escape separator
            $Template = $Cert."Certificate Template" -replace ';', '_'
            $Hash = $Cert."Certificate Hash" -replace ' ', ''

            Write-Output "$($CA.Name);$CommonName;$ExpDate;$($Cert.DaysUntilExpiration);$Template;$Hash"
        }
    }

    # Output section for expired certificates (if configured)
    if ($script:Config.IncludeExpired) {
        Write-Output "<<<pki_expired_certs:sep(59)>>>"

        foreach ($CA in $CAs) {
            try {
                $ExpiredCerts = Get-IssuedCertificate -CALocation $CA.LocationString -ExpireInDays 0 -IncludeExpired -MaxResults 100
                $RecentlyExpired = $ExpiredCerts | Where-Object { $_.DaysUntilExpiration -lt 0 -and $_.DaysUntilExpiration -gt -30 }

                foreach ($Cert in $RecentlyExpired) {
                    $CommonName = $Cert."Issued Common Name" -replace ';', '_'
                    $ExpDate = ([DateTime]$Cert."Certificate Expiration Date").ToString("yyyy-MM-dd HH:mm:ss")

                    Write-Output "$($CA.Name);$CommonName;$ExpDate;$($Cert.DaysUntilExpiration)"
                }
            }
            catch {
                # Output error but continue
                Write-Output "$($CA.Name);ERROR;$($_.Exception.Message -replace ';', '_');-1"
            }
        }
    }
}

# Execute main function
try {
    Write-PKIMonitorOutput
}
catch {
    Write-Output "<<<pki_ca_info:sep(59)>>>"
    Write-Output "CRITICAL_ERROR;$($_.Exception.Message -replace ';', '_');-1;-1;-1"
    Write-Output "<<<pki_cert_summary:sep(59)>>>"
    Write-Output "<<<pki_expiring_certs:sep(59)>>>"
}

#endregion
