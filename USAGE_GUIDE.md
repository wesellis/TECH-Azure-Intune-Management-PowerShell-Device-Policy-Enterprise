# 📱 Azure Intune Management - Administrator Usage Guide

## Overview

This comprehensive guide provides administrators with step-by-step instructions for using the Azure Intune Management PowerShell tools to manage devices, deploy policies, and automate administrative tasks.

---

## 🚀 Getting Started

### Prerequisites

1. **PowerShell Requirements**
   - Windows PowerShell 5.1 or PowerShell 7+
   - Administrative privileges on your workstation
   - Script execution policy set to RemoteSigned or Bypass

2. **Azure/Intune Requirements**
   - Azure AD Global Administrator or Intune Administrator role
   - Valid Microsoft 365/Intune subscription
   - Modern authentication enabled

3. **Required Modules**
   ```powershell
   # Install required modules
   Install-Module -Name Az -Force -AllowClobber
   Install-Module -Name Microsoft.Graph -Force
   Install-Module -Name Microsoft.Graph.Intune -Force
   Install-Module -Name MSOnline -Force
   ```

### Initial Setup

1. **Clone the Repository**
   ```powershell
   git clone https://github.com/yourusername/azure-intune-management.git
   cd azure-intune-management
   ```

2. **Connect to Azure/Intune**
   ```powershell
   # Connect to Azure
   Connect-AzAccount
   
   # Connect to Microsoft Graph
   Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All"
   
   # Connect to Intune
   Connect-MSGraph
   ```

---

## 📋 Common Administrative Tasks

### Device Management

#### 1. Add LAPS User Account
Creates a local administrator account for LAPS (Local Administrator Password Solution).

```powershell
# Deploy via Intune as Platform Script
.\Intune\Device-Management\Add-LAPSuser.ps1

# Or run locally with admin privileges
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\Intune\Device-Management\Add-LAPSuser.ps1
```

**Features:**
- Random password generation
- Automatic administrator group membership
- Duplicate account prevention
- Comprehensive logging to `%TEMP%\LAPS_User_Creation.log`

#### 2. Disable Fast Startup
Improves compatibility and reduces boot issues.

```powershell
# Deploy via Intune
.\Intune\Device-Management\Disable-FastStartup.ps1

# Check current status
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled"
```

#### 3. Enable Full Context Menu (Windows 11)
Restores the classic right-click context menu.

```powershell
# Deploy to restore full context menu
.\Intune\Device-Management\EnableFullContextMenu.ps1

# Note: Requires restart to take effect
```

#### 4. Remove Unwanted Software
Comprehensive removal of OneStart.ai and similar unwanted applications.

```powershell
# Remove OneStart.ai completely
.\Intune\Device-Management\Remove-OneStart.ps1

# View removal log
Get-Content "$env:TEMP\OneStart_Removal.log"
```

### Task Management

#### 1. Create Scheduled Tasks
Deploy custom scheduled tasks across your environment.

```powershell
# Customize the XML in the script first
.\Intune\Task-Management\ScheduledTaskTemplate.ps1

# Deploy via Intune for multiple devices
```

#### 2. Remove Scheduled Tasks
Clean up unwanted or malicious scheduled tasks.

```powershell
# Remove specific task
.\Intune\Task-Management\Remove-ScheduledTask.ps1 -TaskName "UnwantedTask"

# Check logs
Get-Content "$env:TEMP\RemoveScheduledTask.log"
```

### Reporting and Visualization

#### 1. Generate Intune Policy Report
Creates comprehensive reports of all Intune policies and assignments.

```powershell
# Generate full policy report
.\Intune\IntunePoliciesAndAssignmentsReport.ps1

# Output will be saved to specified location
```

#### 2. Azure Resource Visualization
Export visual maps of your Azure resources.

```powershell
# Single resource group
.\Azure Visualizations\Export-AzResourceGroupVisualMapSingle.ps1 -ResourceGroupName "RG-Production"

# All resource groups
.\Azure Visualizations\Export-AzResourceGroupVisualMap.ps1
```

#### 3. Network Security Group Analysis
Export NSG rules and configurations.

```powershell
# Export NSG details to CSV
.\Mapping Out\Export-AzNSGDetailsToCsv.ps1 -OutputPath "C:\Reports\NSG_Report.csv"
```

---

## 🛠️ Deployment Best Practices

### Intune Script Deployment

1. **Platform Scripts**
   - Use for system-level changes
   - Deploy in System context
   - Enable 64-bit PowerShell execution

2. **PowerShell Scripts**
   - Use for user-specific settings
   - Deploy in User context
   - Consider execution policies

3. **Remediation Scripts**
   - Use for compliance enforcement
   - Pair detection and remediation scripts
   - Schedule regular evaluations

### Script Configuration in Intune

```powershell
# Example deployment settings
$scriptSettings = @{
    DisplayName = "Remove Unwanted Software"
    Description = "Removes OneStart.ai and related components"
    ScriptContent = Get-Content ".\Remove-OneStart.ps1" -Raw
    RunAsAccount = "System"
    EnforceSignatureCheck = $false
    RunAs32Bit = $false
}
```

### Assignment Best Practices

1. **Test Groups First**
   - Create pilot groups
   - Monitor execution results
   - Review logs before broad deployment

2. **Phased Rollout**
   ```powershell
   # Phase 1: IT Department
   # Phase 2: Pilot Users (10%)
   # Phase 3: Production (50%)
   # Phase 4: All Users
   ```

3. **Exclusions**
   - Exclude critical servers
   - Exclude VIP users during initial rollout
   - Create break-glass admin accounts

---

## 📊 Monitoring and Troubleshooting

### Log Locations

| Script Type | Log Location |
|------------|--------------|
| LAPS User Creation | `%TEMP%\LAPS_User_Creation.log` |
| Fast Startup | `%TEMP%\DisableFastStartup.log` |
| OneStart Removal | `%TEMP%\OneStart_Removal.log` |
| Scheduled Tasks | `%TEMP%\RemoveScheduledTask.log` |

### Common Issues and Solutions

#### Script Execution Failures

```powershell
# Check execution policy
Get-ExecutionPolicy -List

# Check for errors in Intune
Get-IntuneDeviceConfigurationPolicy | Where-Object {$_.displayName -like "*YourScript*"}
```

#### Permission Issues

```powershell
# Verify admin rights
[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent().IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Check Intune permissions
Get-MgContext
```

#### Debugging Scripts

```powershell
# Enable verbose logging
$VerbosePreference = "Continue"
$DebugPreference = "Continue"

# Test script locally first
.\YourScript.ps1 -WhatIf
```

---

## 🔐 Security Considerations

### Script Signing

```powershell
# Sign scripts for production
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
Set-AuthenticodeSignature -FilePath ".\Script.ps1" -Certificate $cert
```

### Least Privilege

1. Use dedicated service accounts
2. Grant minimum required permissions
3. Implement conditional access policies
4. Enable MFA for admin accounts

### Audit and Compliance

```powershell
# Export audit logs
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -Operations "IntuneScriptExecution"
```

---

## 📈 Advanced Scenarios

### Bulk Operations

```powershell
# Process multiple devices
$devices = Get-IntuneManagedDevice
foreach ($device in $devices) {
    # Apply configuration
    Invoke-IntuneManagedDeviceAction -managedDeviceId $device.id -actionName "RemoveOEM"
}
```

### Automation with Azure Functions

```powershell
# Webhook for automated remediation
$webhook = @{
    Uri = "https://yourfunction.azurewebsites.net/api/RemediateDevice"
    Method = "POST"
    Body = @{
        DeviceId = $deviceId
        Issue = "UnwantedSoftware"
    } | ConvertTo-Json
}
Invoke-RestMethod @webhook
```

### Integration with Logic Apps

1. Create Logic App triggers
2. Call PowerShell scripts
3. Send notifications
4. Update ServiceNow tickets

---

## 📞 Support and Resources

### Getting Help

- **Documentation**: Review script headers for detailed information
- **Logs**: Check `%TEMP%` directory for execution logs
- **Issues**: Submit GitHub issues with log excerpts
- **Email**: intune-support@yourcompany.com

### Useful Commands

```powershell
# Get all Intune commands
Get-Command -Module Microsoft.Graph.Intune

# Get help for specific cmdlet
Get-Help Get-IntuneManagedDevice -Full

# Find examples
Get-Help Set-IntuneDeviceConfigurationPolicy -Examples
```

### Additional Resources

- [Microsoft Intune Documentation](https://docs.microsoft.com/en-us/mem/intune/)
- [Microsoft Graph API Reference](https://docs.microsoft.com/en-us/graph/api/overview)
- [PowerShell Gallery Modules](https://www.powershellgallery.com/)

---

## 🚀 Quick Reference Card

### Essential Commands

```powershell
# Connect to services
Connect-MgGraph
Connect-MSGraph
Connect-AzAccount

# Get devices
Get-IntuneManagedDevice
Get-MgDevice

# Deploy script
New-IntuneDeviceConfigurationPolicyScript

# Check compliance
Get-IntuneDeviceCompliancePolicyDeviceStatus

# Export reports
Export-IntunePolicyReport
```

### Emergency Procedures

1. **Rollback Script**
   ```powershell
   # Disable problematic script
   Set-IntuneDeviceConfigurationPolicy -Id $policyId -Enabled $false
   ```

2. **Force Sync**
   ```powershell
   # Force device sync
   Invoke-IntuneManagedDeviceAction -Id $deviceId -ActionName syncDevice
   ```

3. **Emergency Exclusion**
   ```powershell
   # Add to exclusion group
   Add-AzureADGroupMember -ObjectId $exclusionGroupId -RefObjectId $deviceId
   ```

---

*Last Updated: June 2025*
*Version: 1.0*