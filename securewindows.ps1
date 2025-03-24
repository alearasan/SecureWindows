param (
    [switch]$Verbose = $false,
    [switch]$DetailedReport = $false,
    [switch]$ExportCSV = $false
)

# Global Configuration
$ErrorActionPreference = 'Stop'
$VerbosePreference = if ($Verbose) { 'Continue' } else { 'SilentlyContinue' }
$scriptRoot = $PSScriptRoot
$htmlPath = "$scriptRoot\comprehensive_security_report.html"
$logPath = "$scriptRoot\security_scan_comprehensive_log.txt"
$chartPath = "$scriptRoot\security_charts.png"
$csvPath = "$scriptRoot\security_details.csv"
$fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$global:score = 0
$global:maxScore = 0
$global:securityResults = @{}
$global:detailedFindings = @()

# Calcular el puntaje máximo teórico
$maxScores = @{
    "Antivirus" = @{
        "Defender Status" = 5
        "Antivirus Enabled" = 10
        "Real-time Protection" = 15
        "Signature Freshness" = 15
        "Third-party AV" = 10
    }
    "Updates" = @{
        "System Updates" = 20
    }
    "Firewall" = @{
        "Firewall Domain" = 10
        "Firewall Private" = 10
        "Firewall Public" = 10
    }
    "Network" = @{
        "Risky Ports" = 15
        "Network Interface" = 2
        "DNS Servers" = 2
    }
    "Hardening" = @{
        "Tamper Protection" = 15
        "UAC Status" = 10
        "PowerShell Policy" = 10
        "Admin Accounts" = 10
        "SMBv1" = 10
    }
    "User Security" = @{
        "Password Expiration" = 10
        "Password Change" = 10
        "Blank Passwords" = 15
    }
}

$global:maxScore = 0
foreach ($category in $maxScores.Keys) {
    foreach ($check in $maxScores[$category].Keys) {
        $global:maxScore += $maxScores[$category][$check]
    }
}

# Get the actual number of active network interfaces
$activeInterfaces = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

# Add points based on the actual number of interfaces
$global:maxScore += ($activeInterfaces.Count * $maxScores["Network"]["Network Interface"])

# Similarly, for DNS servers, get the actual number of interfaces with DNS servers configured
$dnsInterfaces = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -ne $null }

# Add points for DNS server configuration based on the actual number of DNS interfaces
$global:maxScore += ($dnsInterfaces.Count * $maxScores["Network"]["DNS Servers"])

# Enhanced Logging Function
function Write-SecurityLog {
    param (
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $logEntry = "[$Level] $fecha - $Message"
    Add-Content -Path $logPath -Value $logEntry
    if ($Verbose) {
        $color = switch($Level) {
            'ERROR' { 'Red' }
            'WARN' { 'Yellow' }
            'INFO' { 'Cyan' }
            default { 'White' }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
}

# Advanced Result Tracking with Evidence Collection
function Add-Result {
    param (
        [string]$Category,
        [string]$CheckName,
        [string]$Estado, 
        [string]$Mensaje, 
        [int]$Puntos,
        [string]$Recomendacion = "",
        [object]$Evidence = $null
    )
    $global:score += $Puntos
    
    if (-not $global:securityResults.ContainsKey($Category)) {
        $global:securityResults[$Category] = @{
            Total = 0
            MaxPossible = 0 
            Scored = 0
            Results = @()
        }
    }
    
    $global:securityResults[$Category].Scored += $Puntos
    
    if ($maxScores[$Category][$CheckName]) {
        $global:securityResults[$Category].MaxPossible += $maxScores[$Category][$CheckName]
    } else {
        $global:securityResults[$Category].MaxPossible += $Puntos
    }
    
    $result = @{
        Category = $Category
        CheckName = $CheckName
        Estado = $Estado
        Mensaje = $Mensaje
        Puntos = $Puntos
        Recomendacion = $Recomendacion
        Evidence = $Evidence
    }
    $global:securityResults[$Category].Results += $result
    $global:detailedFindings += $result

    Write-SecurityLog -Message "$Category - $CheckName : $Mensaje ($Estado)" -Level $Estado
}

function Test-AdvancedSecurityFeatures {
    # Comprehensive Antivirus Check
    try {
        $defender = Get-MpComputerStatus
        $updateDays = (Get-Date) - $defender.AntivirusSignatureLastUpdated
        
        Add-Result -Category "Antivirus" -CheckName "Defender Status" -Estado "ok" -Mensaje "Windows Defender is installed" -Puntos 5 -Evidence $defender
        
        if ($defender.AntivirusEnabled) {
            Add-Result -Category "Antivirus" -CheckName "Antivirus Enabled" -Estado "ok" -Mensaje "Antivirus protection is enabled" -Puntos 10 -Evidence $defender.AntivirusEnabled
        } else {
            Add-Result -Category "Antivirus" -CheckName "Antivirus Enabled" -Estado "fail" -Mensaje "Antivirus protection is disabled" -Puntos 0 -Recomendacion "Enable Windows Defender Antivirus" -Evidence $defender.AntivirusEnabled
        }

        if ($defender.RealTimeProtectionEnabled) {
            Add-Result -Category "Antivirus" -CheckName "Real-time Protection" -Estado "ok" -Mensaje "Real-time protection is active" -Puntos 15 -Evidence $defender.RealTimeProtectionEnabled
        } else {
            Add-Result -Category "Antivirus" -CheckName "Real-time Protection" -Estado "fail" -Mensaje "Real-time protection is disabled" -Puntos 0 -Recomendacion "Enable real-time protection immediately" -Evidence $defender.RealTimeProtectionEnabled
        }
        
        if ($updateDays.Days -le 3) {
            Add-Result -Category "Antivirus" -CheckName "Signature Freshness" -Estado "ok" -Mensaje "Virus signatures updated $($updateDays.Days) days ago" -Puntos 15 -Evidence $updateDays
        } else {
            Add-Result -Category "Antivirus" -CheckName "Signature Freshness" -Estado "warn" -Mensaje "Virus signatures outdated ($($updateDays.Days) days old)" -Puntos 5 -Recomendacion "Update antivirus signatures immediately" -Evidence $updateDays
        }

        # Check for other security products
        $securityProducts = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct
        $thirdPartyAV = $securityProducts | Where-Object { $_.displayName -notmatch "Windows Defender" }
        if ($thirdPartyAV) {
            Add-Result -Category "Antivirus" -CheckName "Third-party AV" -Estado "ok" -Mensaje "Third-party antivirus detected: $($thirdPartyAV.displayName -join ', ')" -Puntos 10 -Evidence $thirdPartyAV
        } else {
            Add-Result -Category "Antivirus" -CheckName "Third-party AV" -Estado "info" -Mensaje "No third-party antivirus detected" -Puntos 5 -Evidence $securityProducts
        }
    } catch {
        Add-Result -Category "Antivirus" -CheckName "Defender Status" -Estado "error" -Mensaje "Failed to check Windows Defender status: $_" -Puntos 0 -Evidence $_
    }

    # Check for Windows updates
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $updatesNeeded = $updateSearcher.Search("IsInstalled=0").Updates.Count
        
        if ($updatesNeeded -eq 0) {
            Add-Result -Category "Updates" -CheckName "System Updates" -Estado "ok" -Mensaje "No pending Windows updates found" -Puntos 20 -Evidence $updatesNeeded
        } else {
            Add-Result -Category "Updates" -CheckName "System Updates" -Estado "warn" -Mensaje "$updatesNeeded Windows updates pending" -Puntos 5 -Recomendacion "Install pending Windows updates" -Evidence $updatesNeeded
        }
    } catch {
        Add-Result -Category "Updates" -CheckName "System Updates" -Estado "error" -Mensaje "Failed to check Windows updates: $_" -Puntos 0 -Evidence $_
    }
}

function Test-NetworkAndFirewallSecurity {
    # Enhanced Network Security Analysis
    try {
        $firewallProfiles = Get-NetFirewallProfile
        foreach ($profile in $firewallProfiles) {
            if ($profile.Enabled) {
                Add-Result -Category "Firewall" -CheckName "Firewall $($profile.Name)" -Estado "ok" -Mensaje "Firewall enabled for $($profile.Name) profile" -Puntos 10 -Evidence $profile
            } else {
                Add-Result -Category "Firewall" -CheckName "Firewall $($profile.Name)" -Estado "warn" -Mensaje "Firewall disabled for $($profile.Name) profile" -Puntos 2 -Recomendacion "Enable firewall for $($profile.Name) profile" -Evidence $profile
            }
        }

        # Check for open ports
        $openPorts = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
        $riskyPorts = $openPorts | Where-Object { $_.LocalPort -in @(21, 23, 80, 135, 139, 445, 3389) }
        
        if ($riskyPorts) {
            Add-Result -Category "Network" -CheckName "Risky Ports" -Estado "warn" -Mensaje "Potentially risky ports open: $($riskyPorts.LocalPort -join ', ')" -Puntos 5 -Recomendacion "Close unnecessary ports" -Evidence $riskyPorts
        } else {
            Add-Result -Category "Network" -CheckName "Risky Ports" -Estado "ok" -Mensaje "No risky ports detected in listening state" -Puntos 15 -Evidence $openPorts
        }

        # Check network interfaces
        $interfaces = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        foreach ($interface in $interfaces) {
            Add-Result -Category "Network" -CheckName "Network Interface" -Estado "info" -Mensaje "Active interface: $($interface.Name) ($($interface.InterfaceDescription))" -Puntos 2 -Evidence $interface
        }

        # Check DNS settings
        $dnsClients = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -ne $null }
        foreach ($dnsClient in $dnsClients) {
            Add-Result -Category "Network" -CheckName "DNS Servers" -Estado "info" -Mensaje "DNS servers for $($dnsClient.InterfaceAlias): $($dnsClient.ServerAddresses -join ', ')" -Puntos 2 -Evidence $dnsClient
        }
    } catch {
        Add-Result -Category "Network" -CheckName "Network Check" -Estado "error" -Mensaje "Failed to perform network checks: $_" -Puntos 0 -Evidence $_
    }
}

function Test-SystemHardening {
    # Windows Defender Exploit Protection
    try {
        $exploitProtection = Get-MpComputerStatus

        if ($exploitProtection.IsTamperProtectionEnabled) {
            Add-Result -Category "Hardening" -CheckName "Tamper Protection" -Estado "ok" -Mensaje "Windows Defender Tamper Protection Enabled" -Puntos 15 -Evidence $exploitProtection
        } else {
            Add-Result -Category "Hardening" -CheckName "Tamper Protection" -Estado "warn" -Mensaje "Tamper Protection Disabled" -Puntos 5 -Recomendacion "Enable Tamper Protection in Windows Security" -Evidence $exploitProtection
        }

        # Check UAC status
        $uac = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
        if ($uac.EnableLUA -eq 1) {
            Add-Result -Category "Hardening" -CheckName "UAC Status" -Estado "ok" -Mensaje "User Account Control (UAC) is enabled" -Puntos 10 -Evidence $uac
        } else {
            Add-Result -Category "Hardening" -CheckName "UAC Status" -Estado "fail" -Mensaje "User Account Control (UAC) is disabled" -Puntos 0 -Recomendacion "Enable UAC for better security" -Evidence $uac
        }

        # PowerShell and Script Execution Policy
        $executionPolicy = Get-ExecutionPolicy
        if ($executionPolicy -eq 'RemoteSigned' -or $executionPolicy -eq 'Restricted') {
            Add-Result -Category "Hardening" -CheckName "PowerShell Policy" -Estado "ok" -Mensaje "PowerShell Execution Policy is $executionPolicy" -Puntos 10 -Evidence $executionPolicy
        } else {
            Add-Result -Category "Hardening" -CheckName "PowerShell Policy" -Estado "warn" -Mensaje "Lenient PowerShell Execution Policy ($executionPolicy)" -Puntos 5 -Recomendacion "Set PowerShell Execution Policy to RemoteSigned" -Evidence $executionPolicy
        }

        # Check for admin accounts
        $adminAccounts = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.ObjectClass -eq "User" }
        if ($adminAccounts.Count -eq 1) {
            Add-Result -Category "Hardening" -CheckName "Admin Accounts" -Estado "ok" -Mensaje "Only one admin account detected" -Puntos 10 -Evidence $adminAccounts
        } else {
            Add-Result -Category "Hardening" -CheckName "Admin Accounts" -Estado "warn" -Mensaje "Multiple admin accounts detected ($($adminAccounts.Count))" -Puntos 5 -Recomendacion "Minimize number of admin accounts" -Evidence $adminAccounts
        }

        # Check SMB settings
        $smb1Enabled = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Where-Object { $_.State -eq "Enabled" }
        if ($smb1Enabled) {
            Add-Result -Category "Hardening" -CheckName "SMBv1" -Estado "fail" -Mensaje "SMBv1 protocol is enabled (security risk)" -Puntos 0 -Recomendacion "Disable SMBv1 protocol immediately" -Evidence $smb1Enabled
        } else {
            Add-Result -Category "Hardening" -CheckName "SMBv1" -Estado "ok" -Mensaje "SMBv1 protocol is disabled" -Puntos 10 -Evidence $smb1Enabled
        }
    } catch {
        Add-Result -Category "Hardening" -CheckName "System Hardening" -Estado "error" -Mensaje "Failed to perform system hardening checks: $_" -Puntos 0 -Evidence $_
    }
}

function Test-UserSecurity {
    # Check password policies
    try {
        $passwordPolicy = Get-LocalUser | Select-Object Name, PasswordExpires, PasswordNeverExpires, UserMayChangePassword
        $neverExpireCount = ($passwordPolicy | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
        $cannotChangeCount = ($passwordPolicy | Where-Object { $_.UserMayChangePassword -eq $false }).Count
        
        if ($neverExpireCount -gt 0) {
            Add-Result -Category "User Security" -CheckName "Password Expiration" -Estado "warn" -Mensaje "$neverExpireCount accounts with passwords that never expire" -Puntos 5 -Recomendacion "Set password expiration policies" -Evidence $passwordPolicy
        } else {
            Add-Result -Category "User Security" -CheckName "Password Expiration" -Estado "ok" -Mensaje "All accounts have password expiration" -Puntos 10 -Evidence $passwordPolicy
        }

        if ($cannotChangeCount -gt 0) {
            Add-Result -Category "User Security" -CheckName "Password Change" -Estado "warn" -Mensaje "$cannotChangeCount accounts cannot change their passwords" -Puntos 5 -Recomendacion "Allow users to change their passwords" -Evidence $passwordPolicy
        } else {
            Add-Result -Category "User Security" -CheckName "Password Change" -Estado "ok" -Mensaje "All accounts can change their passwords" -Puntos 10 -Evidence $passwordPolicy
        }

        # Check for blank passwords
        $blankPasswordAccounts = Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false }
        if ($blankPasswordAccounts) {
            Add-Result -Category "User Security" -CheckName "Blank Passwords" -Estado "fail" -Mensaje "$($blankPasswordAccounts.Count) accounts with blank passwords" -Puntos 0 -Recomendacion "Require passwords for all accounts" -Evidence $blankPasswordAccounts
        } else {
            Add-Result -Category "User Security" -CheckName "Blank Passwords" -Estado "ok" -Mensaje "No accounts with blank passwords" -Puntos 15 -Evidence $blankPasswordAccounts
        }
    } catch {
        Add-Result -Category "User Security" -CheckName "User Security" -Estado "error" -Mensaje "Failed to check user security settings: $_" -Puntos 0 -Evidence $_
    }
}

function Export-SecurityCharts {
    try {
        Add-Type -AssemblyName System.Windows.Forms.DataVisualization

        $chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
        $chart.Width = 1000
        $chart.Height = 800

        $chartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
        $chart.ChartAreas.Add($chartArea)

        # Pie chart for categories
        $seriesPie = New-Object System.Windows.Forms.DataVisualization.Charting.Series
        $seriesPie.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Pie
        $seriesPie.Name = "Categories"
        $seriesPie["PieLabelStyle"] = "Outside"
        $seriesPie["PieLineColor"] = "Black"
        $seriesPie["PieDrawingStyle"] = "Concave"

        $categories = $global:securityResults.Keys
        foreach ($category in $categories) {
            $seriesPie.Points.AddXY($category, $global:securityResults[$category].Scored)
        }
        $chart.Series.Add($seriesPie)

        # Bar chart for individual checks
        $chartArea2 = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
        $chartArea2.AxisX.Title = "Checks"
        $chartArea2.AxisY.Title = "Points"
        $chartArea2.Position = New-Object System.Windows.Forms.DataVisualization.Charting.ElementPosition(55, 40, 40, 50)
        $chart.ChartAreas.Add($chartArea2)

        $seriesBar = New-Object System.Windows.Forms.DataVisualization.Charting.Series
        $seriesBar.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Bar
        $seriesBar.Name = "Checks"
        $seriesBar.ChartArea = $chartArea2.Name

        foreach ($finding in $global:detailedFindings | Sort-Object Puntos -Descending | Select-Object -First 20) {
            $seriesBar.Points.AddXY($finding.CheckName, $finding.Puntos)
        }
        $chart.Series.Add($seriesBar)

        $chart.Titles.Add("Security Score by Category")
        $chart.SaveImage($chartPath, "Png")
    } catch {
        Write-SecurityLog -Message "Failed to generate security charts: $_" -Level "ERROR"
    }
}

function Generate-ComprehensiveReport {
    Write-Host "Starting Advanced Security Scan..." -ForegroundColor Cyan

    # Run All Security Tests
    Test-AdvancedSecurityFeatures
    Test-NetworkAndFirewallSecurity
    Test-SystemHardening
    Test-UserSecurity

    # Calculate percentage score
    $percentageScore = [math]::Round(($global:score/$global:maxScore)*100)
    
    # Generate HTML Report with improved design
    $reportHtml = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>Windows Security Assessment Report</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --info-color: #3498db;
            --light-color: #ecf0f1;
            --dark-color: #2c3e50;
            --white: #ffffff;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f9f9f9;
            margin: 0;
            padding: 0;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: var(--white);
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        
        header {
            background-color: var(--primary-color);
            color: var(--white);
            padding: 20px;
            border-radius: 5px 5px 0 0;
            margin-bottom: 30px;
        }
        
        h1, h2, h3 {
            color: var(--primary-color);
            margin-top: 0;
        }
        
        h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        h2 {
            font-size: 22px;
            border-bottom: 2px solid var(--light-color);
            padding-bottom: 10px;
            margin-top: 30px;
        }
        
        .report-meta {
            display: flex;
            justify-content: space-between;
            margin-bottom: 20px;
            font-size: 14px;
            color: #666;
        }
        
        .chart-container {
            background-color: var(--white);
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        
        .chart {
            max-width: 100%;
            height: auto;
            display: block;
            margin: 0 auto;
        }
        
        .score-card {
            background: linear-gradient(135deg, var(--primary-color), var(--dark-color));
            color: var(--white);
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            margin: 20px 0;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .score-value {
            font-size: 48px;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .score-label {
            font-size: 18px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .progress-container {
            height: 20px;
            background-color: var(--light-color);
            border-radius: 10px;
            margin: 15px 0;
            overflow: hidden;
        }
        
        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--secondary-color), var(--info-color));
            transition: width 0.5s ease;
        }
        
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 14px;
        }
        
        .findings-table th {
            background-color: var(--primary-color);
            color: var(--white);
            padding: 12px;
            text-align: left;
        }
        
        .findings-table td {
            padding: 12px;
            border-bottom: 1px solid #ddd;
            vertical-align: top;
        }
        
        .findings-table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        
        .findings-table tr:hover {
            background-color: #f1f1f1;
        }
        
        .status {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 12px;
            text-transform: uppercase;
        }
        
        .status-ok {
            background-color: var(--success-color);
            color: var(--white);
        }
        
        .status-warn {
            background-color: var(--warning-color);
            color: var(--white);
        }
        
        .status-fail {
            background-color: var(--danger-color);
            color: var(--white);
        }
        
        .status-info {
            background-color: var(--info-color);
            color: var(--white);
        }
        
        .status-error {
            background-color: var(--danger-color);
            color: var(--white);
        }
        
        .category-card {
            background-color: var(--white);
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            border-left: 4px solid var(--secondary-color);
        }
        
        .category-title {
            font-size: 18px;
            margin-top: 0;
            color: var(--primary-color);
        }
        
        .category-score {
            float: right;
            font-weight: bold;
            background-color: var(--light-color);
            padding: 3px 8px;
            border-radius: 3px;
        }
        
        .recommendation {
            font-style: italic;
            color: #666;
            margin-top: 5px;
            font-size: 13px;
        }
        
        footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 12px;
            border-top: 1px solid #ddd;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .findings-table {
                font-size: 12px;
            }
            
            .findings-table th, 
            .findings-table td {
                padding: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Windows Security Assessment Report</h1>
            <div class="report-meta">
                <span>Generated on: $fecha</span>
                <span>Computer: $env:COMPUTERNAME</span>
            </div>
        </header>
        
        <div class="score-card">
            <div class="score-label">Overall Security Score</div>
            <div class="score-value">$percentageScore%</div>
            <div class="progress-container">
                <div class="progress-bar" style="width: $percentageScore%"></div>
            </div>
            <div>
                $global:score / $global:maxScore points
            </div>
        </div>
        
        <div class="chart-container">
            <h2>Security Score Distribution</h2>
            <img src="$chartPath" alt="Security Score Chart" class="chart">
        </div>
        
        <h2>Detailed Findings</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Points</th>
                    <th>Details</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                $(
                    foreach ($finding in $global:detailedFindings) {
                        $statusClass = "status-" + $finding.Estado.ToLower()
                        @"
                        <tr>
                            <td>$($finding.Category)</td>
                            <td>$($finding.CheckName)</td>
                            <td><span class="status $statusClass">$($finding.Estado.ToUpper())</span></td>
                            <td>$($finding.Puntos)</td>
                            <td>$($finding.Mensaje)</td>
                            <td>$($finding.Recomendacion)</td>
                        </tr>
"@
                    }
                )
            </tbody>
        </table>
        
        <h2>Results by Category</h2>
       $(
    foreach ($category in $global:securityResults.Keys) {
        $categoryScore = $global:securityResults[$category].Scored
        $categoryMax = $global:securityResults[$category].MaxPossible
        $categoryPercentage = [math]::Round(($categoryScore/$categoryMax)*100)
        
        @"
        <div class="category-card">
            <h3 class="category-title">$category Security 
                <span class="category-score">$categoryScore/$categoryMax points ($categoryPercentage%)</span>
            </h3>
            <div class="progress-container">
                <div class="progress-bar" style="width: $categoryPercentage%"></div>
            </div>
            $(
                foreach ($result in $global:securityResults[$category].Results) {
                    $statusClass = "status-" + $result.Estado.ToLower()
                    @"
                    <div style="margin: 10px 0;">
                        <strong>$($result.CheckName)</strong> 
                        <span class="status $statusClass">$($result.Estado.ToUpper())</span>
                        <div>$($result.Mensaje) - <strong>$($result.Puntos) points</strong></div>
                        $(if($result.Recomendacion) { "<div class='recommendation'>Recommendation: $($result.Recomendacion)</div>" })
                    </div>
"@
                }
            )
        </div>
"@
    }
)
        
        <footer>
            <p>Report generated by Windows Security Scanner | $(Get-Date -Format "yyyy")</p>
        </footer>
    </div>
</body>
</html>
"@

    # Export Results
    $reportHtml | Out-File -Encoding UTF8 -FilePath $htmlPath
    Export-SecurityCharts

    if ($ExportCSV) {
        $global:detailedFindings | Select-Object Category, CheckName, Estado, Puntos, Mensaje, Recomendacion | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    }

    Write-Host "`nComprehensive Report Generated: $htmlPath" -ForegroundColor Green
    Write-Host "Security Log: $logPath" -ForegroundColor Green
    Write-Host "Security Charts: $chartPath" -ForegroundColor Green
    if ($ExportCSV) {
        Write-Host "Detailed CSV Report: $csvPath" -ForegroundColor Green
    }

    if ($DetailedReport) {
        Start-Process $htmlPath
        Start-Process $chartPath
        if ($ExportCSV) {
            Start-Process $csvPath
        }
    }
}

# Main Execution
try {
    Generate-ComprehensiveReport
} catch {
    Write-Host "Error during security scan: $_" -ForegroundColor Red
    Write-SecurityLog -Message "Scan Error: $_" -Level 'ERROR'
}