
# Windows Security Assessment Script - README

This PowerShell script performs a comprehensive security scan on a Windows machine, analyzing antivirus, firewall, network security, system hardening, and user security. It generates an HTML report and exports data to CSV.

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Usage](#usage)
4. [Configuration](#configuration)
5. [Features](#features)
6. [Export Options](#export-options)
7. [Sample Output](#sample-output)
8. [Troubleshooting](#troubleshooting)
9. [Contributing](#contributing)

## Introduction

This script assesses Windows security, covering:
- Antivirus protection
- Windows updates
- Network security
- Firewall settings
- System hardening (e.g., UAC, PowerShell policy)
- User security (e.g., password policies)

It generates a security score and provides improvement recommendations.

## Prerequisites

- **PowerShell**: v5.1 or later.
- **Administrator privileges**.
- **Internet access** for Windows updates and third-party antivirus checks.

## Usage

Run the script using the following command:

```powershell
.\SecurityAssessment.ps1
```

### Switches

- `-Verbose`: Outputs detailed logs.
- `-DetailedReport`: Generates and opens the HTML report.
- `-ExportCSV`: Exports findings to CSV.

Example:

```powershell
.\SecurityAssessment.ps1 -Verbose -ExportCSV
```

## Configuration

Global variables define paths for the HTML report, log, security charts, and CSV file.

## Features

### Key Checks:
- **Antivirus**: Status of Windows Defender and third-party AV.
- **Updates**: Pending Windows updates.
- **Firewall**: Status of firewall for different profiles.
- **Network**: Open ports, network interfaces, and DNS servers.
- **Hardening**: UAC, PowerShell policies, and SMBv1 settings.
- **User Security**: Password policies, blank passwords, etc.

## Export Options

- **HTML Report**: Includes a security score, charts, findings, and recommendations.
- **CSV Export**: Contains findings with categories, checks, status, and recommendations.
- **Security Charts**: Pie and bar charts showing score distributions.

## Sample Output

The HTML report includes:
- Overall security score.
- Detailed findings table.
- Security charts.

The CSV file contains:
- Category, Check, Status, Points, Details, and Recommendations.

## Troubleshooting

- **Permissions**: Run with administrator privileges.
- **Internet**: Some checks require internet access.

## Contributing

To contribute:
1. Fork the repo.
2. Create a branch.
3. Commit and push.
4. Submit a pull request.
