# Device Management Scripts

This folder contains PowerShell scripts for device configuration, security, and system optimization specifically designed for Microsoft Intune deployment.

## Scripts Overview

### Security & Access Management
- **Add-LAPSuser.ps1** - Creates LAPS (Local Administrator Password Solution) user accounts with random passwords
- **Remove-OneStart.ps1** - Comprehensive malware removal tool for OneStart.ai and similar unwanted software

### System Configuration & Optimization
- **Disable-FastStartup.ps1** - Disables Windows Fast Startup for improved compatibility
- **EnableFullContextMenu.ps1** - Restores full context menu functionality in Windows 11

## Deployment Guidelines

### Intune Deployment
All scripts are designed for deployment via Microsoft Intune as Platform scripts:

1. **Upload to Intune** → Devices → Scripts → Platform scripts
2. **Run in system context** for administrative privileges
3. **Target appropriate device groups** based on requirements
4. **Monitor execution** via Intune reporting and temp logs

### Prerequisites
- Administrative privileges (system context recommended)
- PowerShell execution policy configured appropriately
- Target devices enrolled in Intune/Azure AD

### Logging
All scripts create detailed logs in the `%TEMP%` directory with timestamps for troubleshooting and compliance reporting.

## Security Considerations

- Scripts follow security best practices with input validation
- Comprehensive error handling prevents system instability
- Logging provides audit trails for compliance requirements
- Password generation uses cryptographically secure methods

---
**Author**: Wesley Ellis | **Email**: wes@wesellis.com | **Website**: wesellis.com
