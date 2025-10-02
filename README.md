# Azure Intune Management Scripts

A collection of PowerShell scripts for managing Azure Intune devices and policies.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

---

## What is This?

This is a personal collection of PowerShell scripts I've created and gathered for working with Microsoft Intune and Azure device management. The scripts help automate common tasks like device management, policy deployment, and reporting.

## What's Included

### Azure Authentication
- Single sign-on checking

### Azure Visualizations
- Resource group visualization tools
- Export tools for mapping Azure resources

### Intune Management
- **Device Management**: Scripts for device configuration and management
- **Application Management**: App deployment and category management
- **Task Management**: Scheduled task automation
- **Policy Reporting**: Generate reports on policies and assignments

### Windows Image Creation
- Hyper-V and WDS installation scripts

## Prerequisites

- PowerShell 5.1 or higher
- Azure AD PowerShell module
- Microsoft Graph Intune module (for some scripts)
- Appropriate permissions in your Azure/Intune tenant

## Installation

```powershell
# Install required modules
Install-Module -Name Microsoft.Graph.Intune
Install-Module -Name AzureAD

# Clone this repository
git clone https://github.com/wesellis/TECH-Azure-Intune-Management-PowerShell-Device-Policy-Enterprise
```

## Usage

Each script is standalone and can be run individually. Review the script contents before running to understand what it does and ensure it fits your needs.

```powershell
# Example: Run a device management script
.\Intune\Device-Management\Intune.GraphAPI.Modern.ps1
```

**Important**: Always test scripts in a non-production environment first.

## Project Structure

```
.
├── Azure Authentication/     # Azure auth-related scripts
├── Azure Visualizations/     # Resource visualization tools
├── Intune/                   # Intune management scripts
│   ├── Device-Management/    # Device-specific scripts
│   ├── PowerShell-Scripts/   # Various management scripts
│   └── Task-Management/      # Task automation
└── Windows Image Creation/   # Image creation utilities
```

## Contributing

This is a personal collection, but suggestions and improvements are welcome. Feel free to open an issue or submit a pull request.

## Disclaimer

These scripts are provided as-is. Always review and test scripts before using them in production environments. Make sure you understand what each script does and have appropriate backups before making changes to your Intune/Azure environment.

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- Microsoft for the Graph API and Intune platform
- PowerShell community for modules and examples

---

**Author:** Wesley Ellis
**Note:** These scripts are for educational and administrative purposes. Use at your own risk.

