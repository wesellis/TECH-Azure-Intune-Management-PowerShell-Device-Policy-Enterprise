<#
.SYNOPSIS
    Intunepoliciesandassignmentsreport

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
    We Enhanced Intunepoliciesandassignmentsreport

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Intune)) {
    Install-Module -Name Microsoft.Graph.Intune
}

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.SDK)) {
    Install-Module -Name Microsoft.Graph.SDK
}


Connect-MSGraph


Write-WELog " ---- App Assignments ----" " INFO"
$apps = Get-IntuneManagedApplication


foreach ($app in $apps) {
    Write-WELog " App Name: $($app.displayName)" " INFO"
    Write-WELog " App ID: $($app.id)" " INFO"
    Write-WELog " App Assignments:" " INFO"

    $assignments = Get-IntuneManagedApplicationAssignment -ManagedAppId $app.id

    if ($assignments) {
        foreach ($assignment in $assignments) {
            Write-WELog " ---------------------------------------------" " INFO"
            Write-WELog " Assignment ID: $($assignment.id)" " INFO"
            Write-WELog " Assignment Group ID: $($assignment.target.groupId)" " INFO"
            Write-WELog " Assignment Intent: $($assignment.intent)" " INFO"
            Write-WELog " Assignment Settings: $($assignment.settings)" " INFO"
            Write-WELog " ---------------------------------------------" " INFO"
        }
    } else {
        Write-WELog " No assignments found for this app." " INFO"
    }
    Write-WELog "" " INFO"
}


Write-WELog " ---- Compliance Policies ----" " INFO"
$compliancePolicies = Get-IntuneDeviceCompliancePolicy
foreach ($policy in $compliancePolicies) {
    Write-WELog " Policy Name: $($policy.displayName)" " INFO"
    Write-WELog " Policy ID: $($policy.id)" " INFO"
    Write-WELog " ---------------------------------------------" " INFO"
}


Write-WELog " ---- Configuration Profiles ----" " INFO"; 
$configProfiles = Get-IntuneDeviceConfigurationPolicy
foreach ($profile in $configProfiles) {
    Write-WELog " Profile Name: $($profile.displayName)" " INFO"
    Write-WELog " Profile ID: $($profile.id)" " INFO"
    Write-WELog " ---------------------------------------------" " INFO"
}


Write-WELog " ---- Conditional Access Policies ----" " INFO" ; 
$conditionalAccessPolicies = Get-MSGraphPolicy -PolicyType " ConditionalAccessPolicy"
foreach ($policy in $conditionalAccessPolicies) {
    Write-WELog " Policy Name: $($policy.displayName)" " INFO"
    Write-WELog " Policy ID: $($policy.id)" " INFO"
    Write-WELog " ---------------------------------------------" " INFO"
}


Disconnect-MSGraph



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================