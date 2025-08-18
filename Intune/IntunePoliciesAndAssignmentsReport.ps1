# Install required modules if not already installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Intune)) {
    Install-Module -Name Microsoft.Graph.Intune
}

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.SDK)) {
    Install-Module -Name Microsoft.Graph.SDK
}

# Authenticate and connect to Microsoft Graph
Connect-MSGraph

# Get all applications
Write-Host "---- App Assignments ----"
$apps = Get-IntuneManagedApplication

# Loop through each application and get assignments
foreach ($app in $apps) {
    Write-Host "App Name: $($app.displayName)"
    Write-Host "App ID: $($app.id)"
    Write-Host "App Assignments:"

    $assignments = Get-IntuneManagedApplicationAssignment -ManagedAppId $app.id

    if ($assignments) {
        foreach ($assignment in $assignments) {
            Write-Host "---------------------------------------------"
            Write-Host "Assignment ID: $($assignment.id)"
            Write-Host "Assignment Group ID: $($assignment.target.groupId)"
            Write-Host "Assignment Intent: $($assignment.intent)"
            Write-Host "Assignment Settings: $($assignment.settings)"
            Write-Host "---------------------------------------------"
        }
    } else {
        Write-Host "No assignments found for this app."
    }
    Write-Host ""
}

# Get Compliance Policies
Write-Host "---- Compliance Policies ----"
$compliancePolicies = Get-IntuneDeviceCompliancePolicy
foreach ($policy in $compliancePolicies) {
    Write-Host "Policy Name: $($policy.displayName)"
    Write-Host "Policy ID: $($policy.id)"
    Write-Host "---------------------------------------------"
}

# Get Configuration Profiles
Write-Host "---- Configuration Profiles ----"
$configProfiles = Get-IntuneDeviceConfigurationPolicy
foreach ($profile in $configProfiles) {
    Write-Host "Profile Name: $($profile.displayName)"
    Write-Host "Profile ID: $($profile.id)"
    Write-Host "---------------------------------------------"
}

# Get Conditional Access Policies
Write-Host "---- Conditional Access Policies ----"
$conditionalAccessPolicies = Get-MSGraphPolicy -PolicyType "ConditionalAccessPolicy"
foreach ($policy in $conditionalAccessPolicies) {
    Write-Host "Policy Name: $($policy.displayName)"
    Write-Host "Policy ID: $($policy.id)"
    Write-Host "---------------------------------------------"
}

# Disconnect from Microsoft Graph
Disconnect-MSGraph
