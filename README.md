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
│   ├── Device-Management/   # Device configuration and security scripts
│   └── Task-Management/     # Scheduled task management tools
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

# Create LAPS user account for device management
.\Intune\Device-Management\Add-LAPSuser.ps1

# Disable Windows Fast Startup for compatibility
.\Intune\Device-Management\Disable-FastStartup.ps1

# Enable full context menu in Windows 11
.\Intune\Device-Management\EnableFullContextMenu.ps1

# Remove OneStart.ai malware/unwanted software
.\Intune\Device-Management\Remove-OneStart.ps1

# Manage scheduled tasks
.\Intune\Task-Management\Remove-ScheduledTask.ps1
.\Intune\Task-Management\ScheduledTaskTemplate.ps1
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
- **Device Configuration** - LAPS users, system settings, security configurations
- **Malware Removal** - Automated removal of unwanted software
- **Task Management** - Scheduled task creation and removal
- **Windows Optimization** - Performance and compatibility enhancements

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

## New Script Documentation

### Intune Device Management Scripts

#### Device-Management Folder

**Add-LAPSuser.ps1**
- Creates a local user account with randomly generated password for LAPS (Local Administrator Password Solution)
- Designed for Intune deployment as a Platform script
- Includes comprehensive logging and error handling
- Automatically adds user to local Administrators group
- Checks for existing accounts to prevent duplicates

**Disable-FastStartup.ps1**
- Disables Windows Fast Startup feature by modifying registry
- Improves compatibility with dual boot setups and network configurations
- Includes proper error handling and logging
- Designed for system context or administrator execution

**EnableFullContextMenu.ps1**
- Restores full context menu in Windows 11
- Creates necessary registry keys to bypass simplified context menu
- Quick registry modification for improved user experience
- Requires computer restart to take effect

**Remove-OneStart.ps1**
- Comprehensive removal tool for OneStart.ai malware/unwanted software
- Removes processes, files, registry entries, scheduled tasks, and browser extensions
- Supports multiple browsers (Chrome, Edge, Firefox)
- Extensive logging and error reporting
- Statistics tracking for removal operations
- Safe removal with cleanup verification

#### Task-Management Folder

**Remove-ScheduledTask.ps1**
- Template script for removing scheduled tasks
- Includes administrator privilege verification
- Comprehensive logging and error handling
- Customizable task name parameter

**ScheduledTaskTemplate.ps1**
- Template for creating scheduled tasks from XML definitions
- Includes task replacement logic (removes existing before creating new)
- Comprehensive error handling and logging
- Easily customizable XML task definition

### Usage in Enterprise Environments

These scripts are specifically designed for:
- **Microsoft Intune deployment** as Platform scripts
- **Enterprise device management** with centralized logging
- **Security and compliance** operations
- **Automated remediation** of common issues
- **Malware removal** and system optimization

### Deployment Recommendations

1. **Test thoroughly** in a lab environment before production deployment
2. **Review and customize** script parameters for your environment
3. **Deploy via Intune** as Platform scripts with appropriate targeting
4. **Monitor logs** in the %TEMP% directory for execution results
5. **Verify results** using Intune compliance policies where applicable

All scripts include professional headers with author information, comprehensive error handling, and detailed logging for enterprise deployment scenarios.