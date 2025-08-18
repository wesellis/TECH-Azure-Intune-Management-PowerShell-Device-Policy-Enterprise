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
Write-Information "---- App Assignments ----"
$apps = Get-IntuneManagedApplication -ErrorAction Stop

# Loop through each application and get assignments
foreach ($app in $apps) {
    Write-Information "App Name: $($app.displayName)"
    Write-Information "App ID: $($app.id)"
    Write-Information "App Assignments:"

    $assignments = Get-IntuneManagedApplicationAssignment -ManagedAppId $app.id

    if ($assignments) {
        foreach ($assignment in $assignments) {
            Write-Information "---------------------------------------------"
            Write-Information "Assignment ID: $($assignment.id)"
            Write-Information "Assignment Group ID: $($assignment.target.groupId)"
            Write-Information "Assignment Intent: $($assignment.intent)"
            Write-Information "Assignment Settings: $($assignment.settings)"
            Write-Information "---------------------------------------------"
        }
    } else {
        Write-Information "No assignments found for this app."
    }
    Write-Information ""
}

# Get Compliance Policies
Write-Information "---- Compliance Policies ----"
$compliancePolicies = Get-IntuneDeviceCompliancePolicy -ErrorAction Stop
foreach ($policy in $compliancePolicies) {
    Write-Information "Policy Name: $($policy.displayName)"
    Write-Information "Policy ID: $($policy.id)"
    Write-Information "---------------------------------------------"
}

# Get Configuration Profiles
Write-Information "---- Configuration Profiles ----"
$configProfiles = Get-IntuneDeviceConfigurationPolicy -ErrorAction Stop
foreach ($profile in $configProfiles) {
    Write-Information "Profile Name: $($profile.displayName)"
    Write-Information "Profile ID: $($profile.id)"
    Write-Information "---------------------------------------------"
}

# Get Conditional Access Policies
Write-Information "---- Conditional Access Policies ----"
$conditionalAccessPolicies = Get-MSGraphPolicy -PolicyType "ConditionalAccessPolicy"
foreach ($policy in $conditionalAccessPolicies) {
    Write-Information "Policy Name: $($policy.displayName)"
    Write-Information "Policy ID: $($policy.id)"
    Write-Information "---------------------------------------------"
}

# Disconnect from Microsoft Graph
Disconnect-MSGraph
