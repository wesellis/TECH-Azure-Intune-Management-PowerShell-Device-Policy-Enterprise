<#
.SYNOPSIS
    Mrtbone Set Mgazureautomationaccountpermissions

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules
#>

<#
.SYNOPSIS
    We Enhanced Mrtbone Set Mgazureautomationaccountpermissions

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


<#PSScriptInfo


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
    Script for setting permissions on Azure Automation Accounts 
 
.DESCRIPTION
    This script will assign specified permissions on an Azure Automation Account
        
.EXAMPLE
   .\Set-MgAzureAutomationAccountPermissions.ps1
    will assign specified permissions on an Azure Automation Account with settings in the modifyable region. 

.NOTES
    Written by Mr-Tbone (Tbone Granheden) Coligo AB
    torbjorn.granheden@coligo.se

.VERSION
    1.0

.RELEASENOTES
    1.0 2024-01-04 Initial Build

.AUTHOR
    Tbone Granheden 
    @MrTbone_se

.COMPANYNAME 
    Coligo AB

.GUID 
    00000000-0000-0000-0000-000000000000

.COPYRIGHT
    Feel free to use this, But would be grateful if My name is mentioned in Notes 

.CHANGELOG
    1.0.2401.1 - Initial Version







$WETenantID = " d6f19297-08a2-4ade-9a68-0db7586d80ad"
$WEManagedIdentity = " Tbone-IntuneAutomation"
    $WEPermissions = @(
    " DeviceManagementManagedDevices.ReadWrite.All"
    " AuditLog.Read.All"
    " User.Read.All"
)



    $WEGraphAppId = " 00000003-0000-0000-c000-000000000000" # Don't change this.
    $WEAdminPermissions = @(" Application.Read.All" ," AppRoleAssignment.ReadWrite.All" )   # To be able to set persmissions on the Managed Identity



import-module Microsoft.Graph.Authentication
import-module Microsoft.Graph.Applications





Connect-MgGraph -TenantId $WETenantId -Scopes $WEAdminPermissions
$WEIdentityServicePrincipal = Get-MgServicePrincipal -Filter " DisplayName eq '$managedidentity'"
$WEGraphServicePrincipal = Get-MgServicePrincipal -Filter " appId eq '$WEGraphAppId'"; 
$WEAppRoles = $WEGraphServicePrincipal.AppRoles | Where-Object {$_.Value -in $WEPermissions -and $_.AllowedMemberTypes -contains " Application" }
    
foreach($WEAppRole in $WEAppRoles)
 {
 ;  $WEAppRoleAssignment = @{
      " PrincipalId" = $WEIdentityServicePrincipal.Id
      " ResourceId" = $WEGraphServicePrincipal.Id
      " AppRoleId" = $WEAppRole.Id
    }
  New-MgServicePrincipalAppRoleAssignment -ErrorAction Stop `
      -ServicePrincipalId $WEAppRoleAssignment.PrincipalId `
      -BodyParameter $WEAppRoleAssignment `
      -Verbose
  }
disconnect-mggraph


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================