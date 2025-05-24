# PowerShell for Azure Intune Management

A comprehensive collection of PowerShell scripts for managing Microsoft Azure and Intune environments, including device management, policy deployment, and administrative automation.

## Overview

This repository contains organized PowerShell scripts and tools for Azure and Intune administration, covering authentication, device management, policy configuration, and administrative reporting.

## Repository Structure

```
PowerShell-for-Azure-Intune-Management/
├── Azure Authentication/     # Azure authentication and connection scripts
├── Azure Visualizations/     # Reporting and visualization tools
├── Intune/                  # Intune device and policy management
├── Mapping Out/             # Network and infrastructure mapping
└── Windows Image Creation/   # Windows image preparation and deployment
```

## Features

- **Azure Authentication** - Secure connection and authentication methods
- **Intune Management** - Device enrollment, policy deployment, and compliance
- **Azure Visualizations** - Reporting and dashboard creation
- **Infrastructure Mapping** - Network and resource discovery
- **Image Management** - Windows image creation and deployment automation

## Prerequisites

- PowerShell 5.1 or later
- Azure PowerShell module
- Microsoft.Graph.Intune module
- Appropriate Azure and Intune administrative permissions

## Installation

```powershell
# Clone the repository
git clone https://github.com/wesellis/PowerShell-for-Azure-Intune-Management.git
cd PowerShell-for-Azure-Intune-Management

# Install required modules
Install-Module Az -Force -AllowClobber
Install-Module Microsoft.Graph.Intune -Force
Install-Module MSOnline -Force
```

## Usage Examples

### Azure Authentication
```powershell
# Connect to Azure with enhanced authentication
.\Azure Authentication\Connect-AzureEnvironment.ps1
```

### Intune Device Management
```powershell
# Get device compliance status
.\Intune\Get-DeviceCompliance.ps1

# Deploy configuration policies
.\Intune\Deploy-ConfigurationPolicy.ps1
```

### Azure Visualizations
```powershell
# Generate Azure resource reports
.\Azure Visualizations\Generate-AzureReport.ps1
```

## Script Categories

### Azure Authentication
- Secure authentication methods
- Multi-tenant support
- Service principal automation
- Credential management

### Intune Management
- Device enrollment automation
- Policy deployment and management
- Compliance reporting
- Application deployment

### Azure Visualizations
- Resource utilization reports
- Cost analysis dashboards
- Performance monitoring
- Security assessments

### Infrastructure Mapping
- Network topology discovery
- Resource dependency mapping
- Architecture documentation
- Capacity planning

### Windows Image Creation
- Automated image preparation
- Driver integration
- Application packaging
- Deployment automation

## Contributing

Contributions are welcome! Please read our contribution guidelines before submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions and support:
- Create an issue in this repository
- Contact Wesley Ellis at wes@wesellis.com

## Acknowledgments

- Microsoft Azure and Intune teams for comprehensive APIs
- PowerShell community for tools and best practices
- Contributors who help improve these scripts