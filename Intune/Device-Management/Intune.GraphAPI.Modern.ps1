#Requires -Version 7.0
#Requires -Modules Microsoft.Graph

<#
.SYNOPSIS
    Modern Microsoft Graph API integration for Intune Device Management
.DESCRIPTION
    Comprehensive Intune management using Microsoft Graph API v1.0 and beta endpoints
.VERSION
    2.0.0
.AUTHOR
    Azure Intune Management Toolkit
#>

# Module configuration
$script:GraphVersion = "v1.0"
$script:GraphBetaVersion = "beta"
$script:RequiredScopes = @(
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementApps.ReadWrite.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementConfiguration.ReadWrite.All"
)

#region Authentication

function Connect-IntuneGraph {
    <#
    .SYNOPSIS
        Connect to Microsoft Graph for Intune management
    .DESCRIPTION
        Establishes connection with proper scopes for Intune operations
    .PARAMETER TenantId
        Azure AD Tenant ID
    .PARAMETER ClientId
        Application Client ID (optional)
    .PARAMETER UseDeviceCode
        Use device code flow for interactive auth
    .EXAMPLE
        Connect-IntuneGraph -TenantId "contoso.onmicrosoft.com" -UseDeviceCode
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,
        
        [string]$ClientId,
        
        [switch]$UseDeviceCode
    )
    
    try {
        $connectParams = @{
            TenantId = $TenantId
            Scopes = $script:RequiredScopes
        }
        
        if ($ClientId) {
            $connectParams.ClientId = $ClientId
        }
        
        if ($UseDeviceCode) {
            $connectParams.UseDeviceCode = $true
        }
        
        Connect-MgGraph @connectParams
        
        $context = Get-MgContext
        Write-Information "Connected to tenant: $($context.TenantId)" -InformationAction Continue
        Write-Information "Scopes: $($context.Scopes -join ', ')" -InformationAction Continue
        
        return $context
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
    }
}

#endregion

#region Device Management

function Get-IntuneManagedDevices {
    <#
    .SYNOPSIS
        Get all Intune managed devices with advanced filtering
    .DESCRIPTION
        Retrieves managed devices with support for filtering, sorting, and exporting
    .PARAMETER Platform
        Filter by platform (Windows, iOS, Android, macOS)
    .PARAMETER ComplianceState
        Filter by compliance state
    .PARAMETER LastSyncDays
        Filter devices by last sync time
    .PARAMETER ExportPath
        Export results to CSV
    .EXAMPLE
        Get-IntuneManagedDevices -Platform "Windows" -ComplianceState "Compliant" -ExportPath ".\devices.csv"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'All')]
        [string]$Platform = 'All',
        
        [ValidateSet('Compliant', 'NonCompliant', 'All')]
        [string]$ComplianceState = 'All',
        
        [int]$LastSyncDays,
        
        [string]$ExportPath
    )
    
    $uri = "https://graph.microsoft.com/$script:GraphVersion/deviceManagement/managedDevices"
    $filter = @()
    
    # Build filter
    if ($Platform -ne 'All') {
        $platformFilter = switch ($Platform) {
            'Windows' { "operatingSystem eq 'Windows'" }
            'iOS' { "operatingSystem eq 'iOS'" }
            'Android' { "operatingSystem eq 'Android'" }
            'macOS' { "operatingSystem eq 'macOS'" }
        }
        $filter += $platformFilter
    }
    
    if ($ComplianceState -ne 'All') {
        $complianceFilter = if ($ComplianceState -eq 'Compliant') {
            "complianceState eq 'compliant'"
        } else {
            "complianceState ne 'compliant'"
        }
        $filter += $complianceFilter
    }
    
    if ($LastSyncDays) {
        $syncDate = (Get-Date).AddDays(-$LastSyncDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $filter += "lastSyncDateTime ge $syncDate"
    }
    
    # Build query
    $query = @{
        '$select' = 'id,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,userPrincipalName,model,manufacturer'
        '$orderby' = 'deviceName'
        '$top' = 999
    }
    
    if ($filter) {
        $query['$filter'] = $filter -join ' and '
    }
    
    # Get devices
    $devices = @()
    $nextLink = $uri
    
    while ($nextLink) {
        $response = Invoke-MgGraphRequest -Uri $nextLink -Method GET -Body $query
        $devices += $response.value
        $nextLink = $response.'@odata.nextLink'
        
        # Clear query for subsequent requests
        $query = @{}
    }
    
    # Export if requested
    if ($ExportPath) {
        $devices | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Information "Exported $($devices.Count) devices to: $ExportPath" -InformationAction Continue
    }
    
    return $devices
}

function Invoke-IntuneSyncDevice {
    <#
    .SYNOPSIS
        Trigger sync for Intune managed devices
    .DESCRIPTION
        Forces device sync for one or more managed devices
    .PARAMETER DeviceId
        Device ID(s) to sync
    .PARAMETER All
        Sync all devices
    .PARAMETER Platform
        Sync all devices of specific platform
    .EXAMPLE
        Get-IntuneManagedDevices -Platform "Windows" | Invoke-IntuneSyncDevice
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [string[]]$DeviceId,
        
        [switch]$All,
        
        [ValidateSet('Windows', 'iOS', 'Android', 'macOS')]
        [string]$Platform
    )
    
    process {
        if ($All -or $Platform) {
            $devices = Get-IntuneManagedDevices -Platform ($Platform ?? 'All')
            $DeviceId = $devices.id
        }
        
        foreach ($id in $DeviceId) {
            if ($PSCmdlet.ShouldProcess($id, "Sync device")) {
                try {
                    $uri = "https://graph.microsoft.com/$script:GraphVersion/deviceManagement/managedDevices/$id/syncDevice"
                    Invoke-MgGraphRequest -Uri $uri -Method POST
                    Write-Information "Sync triggered for device: $id" -InformationAction Continue
                }
                catch {
                    Write-Error "Failed to sync device $id: $_"
                }
            }
        }
    }
}

function Set-IntuneDeviceCompliance {
    <#
    .SYNOPSIS
        Manage device compliance actions
    .DESCRIPTION
        Perform compliance-related actions on devices
    .PARAMETER DeviceId
        Device ID
    .PARAMETER Action
        Compliance action to perform
    .EXAMPLE
        Set-IntuneDeviceCompliance -DeviceId $device.id -Action "Retire"
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)]
        [string]$DeviceId,
        
        [Parameter(Mandatory)]
        [ValidateSet('Retire', 'Wipe', 'Delete', 'RemoveCompanyData', 'DisableLostMode')]
        [string]$Action
    )
    
    $actionMap = @{
        'Retire' = 'retire'
        'Wipe' = 'wipe'
        'Delete' = 'delete'
        'RemoveCompanyData' = 'removeCompanyData'
        'DisableLostMode' = 'disableLostMode'
    }
    
    if ($PSCmdlet.ShouldProcess($DeviceId, $Action)) {
        try {
            $uri = "https://graph.microsoft.com/$script:GraphVersion/deviceManagement/managedDevices/$DeviceId/$($actionMap[$Action])"
            Invoke-MgGraphRequest -Uri $uri -Method POST
            Write-Information "$Action action completed for device: $DeviceId" -InformationAction Continue
        }
        catch {
            Write-Error "Failed to perform $Action on device $DeviceId: $_"
        }
    }
}

#endregion

#region Application Management

function Get-IntuneApps {
    <#
    .SYNOPSIS
        Get Intune mobile apps
    .DESCRIPTION
        Retrieves all mobile apps with detailed information
    .PARAMETER AppType
        Filter by app type
    .PARAMETER IncludeAssignments
        Include app assignments
    .EXAMPLE
        Get-IntuneApps -AppType "Microsoft" -IncludeAssignments
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('All', 'Microsoft', 'iOS', 'Android', 'Windows', 'WebApp', 'Office365')]
        [string]$AppType = 'All',
        
        [switch]$IncludeAssignments
    )
    
    $uri = "https://graph.microsoft.com/$script:GraphVersion/deviceAppManagement/mobileApps"
    
    # Get apps
    $apps = (Invoke-MgGraphRequest -Uri $uri -Method GET).value
    
    # Filter by type
    if ($AppType -ne 'All') {
        $apps = switch ($AppType) {
            'Microsoft' { $apps | Where-Object { $_.'@odata.type' -match 'microsoft' } }
            'iOS' { $apps | Where-Object { $_.'@odata.type' -match 'ios' } }
            'Android' { $apps | Where-Object { $_.'@odata.type' -match 'android' } }
            'Windows' { $apps | Where-Object { $_.'@odata.type' -match 'windows' } }
            'WebApp' { $apps | Where-Object { $_.'@odata.type' -match 'webApp' } }
            'Office365' { $apps | Where-Object { $_.'@odata.type' -match 'officeSuite' } }
        }
    }
    
    # Get assignments if requested
    if ($IncludeAssignments) {
        foreach ($app in $apps) {
            $assignmentUri = "https://graph.microsoft.com/$script:GraphVersion/deviceAppManagement/mobileApps/$($app.id)/assignments"
            $app | Add-Member -NotePropertyName 'assignments' -NotePropertyValue (Invoke-MgGraphRequest -Uri $assignmentUri -Method GET).value
        }
    }
    
    return $apps
}

function New-IntuneAppAssignment {
    <#
    .SYNOPSIS
        Create app assignment
    .DESCRIPTION
        Assigns an app to groups with install intent
    .PARAMETER AppId
        Mobile app ID
    .PARAMETER GroupId
        Target group ID
    .PARAMETER Intent
        Installation intent
    .EXAMPLE
        New-IntuneAppAssignment -AppId $app.id -GroupId $group.id -Intent "Required"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$AppId,
        
        [Parameter(Mandatory)]
        [string]$GroupId,
        
        [Parameter(Mandatory)]
        [ValidateSet('Required', 'Available', 'Uninstall')]
        [string]$Intent
    )
    
    if ($PSCmdlet.ShouldProcess("$AppId to $GroupId", "Assign app")) {
        try {
            $uri = "https://graph.microsoft.com/$script:GraphVersion/deviceAppManagement/mobileApps/$AppId/assignments"
            
            $assignment = @{
                '@odata.type' = '#microsoft.graph.mobileAppAssignment'
                target = @{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId = $GroupId
                }
                intent = $Intent.ToLower()
            }
            
            $body = @{
                mobileAppAssignments = @($assignment)
            }
            
            Invoke-MgGraphRequest -Uri $uri -Method POST -Body ($body | ConvertTo-Json -Depth 10)
            Write-Information "App assigned successfully" -InformationAction Continue
        }
        catch {
            Write-Error "Failed to assign app: $_"
        }
    }
}

#endregion

#region Policy Management

function Get-IntuneDeviceConfigurations {
    <#
    .SYNOPSIS
        Get device configuration profiles
    .DESCRIPTION
        Retrieves all device configuration profiles with assignments
    .PARAMETER Platform
        Filter by platform
    .PARAMETER IncludeAssignments
        Include profile assignments
    .EXAMPLE
        Get-IntuneDeviceConfigurations -Platform "Windows10" -IncludeAssignments
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('All', 'Windows10', 'iOS', 'Android', 'macOS')]
        [string]$Platform = 'All',
        
        [switch]$IncludeAssignments
    )
    
    $uri = "https://graph.microsoft.com/$script:GraphVersion/deviceManagement/deviceConfigurations"
    $configurations = (Invoke-MgGraphRequest -Uri $uri -Method GET).value
    
    # Filter by platform
    if ($Platform -ne 'All') {
        $configurations = $configurations | Where-Object { $_.'@odata.type' -match $Platform }
    }
    
    # Get assignments
    if ($IncludeAssignments) {
        foreach ($config in $configurations) {
            $assignmentUri = "https://graph.microsoft.com/$script:GraphVersion/deviceManagement/deviceConfigurations/$($config.id)/assignments"
            $config | Add-Member -NotePropertyName 'assignments' -NotePropertyValue (Invoke-MgGraphRequest -Uri $assignmentUri -Method GET).value
        }
    }
    
    return $configurations
}

function New-IntuneDeviceConfiguration {
    <#
    .SYNOPSIS
        Create device configuration profile
    .DESCRIPTION
        Creates a new device configuration profile from template
    .PARAMETER Name
        Profile name
    .PARAMETER Description
        Profile description
    .PARAMETER Template
        Configuration template
    .PARAMETER Platform
        Target platform
    .EXAMPLE
        New-IntuneDeviceConfiguration -Name "Windows Security Baseline" -Template $template -Platform "Windows10"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [string]$Description,
        
        [Parameter(Mandatory)]
        [hashtable]$Template,
        
        [Parameter(Mandatory)]
        [ValidateSet('Windows10', 'iOS', 'Android', 'macOS')]
        [string]$Platform
    )
    
    if ($PSCmdlet.ShouldProcess($Name, "Create configuration profile")) {
        try {
            $uri = "https://graph.microsoft.com/$script:GraphVersion/deviceManagement/deviceConfigurations"
            
            # Add metadata
            $Template['displayName'] = $Name
            $Template['description'] = $Description
            
            # Set OData type based on platform
            if (-not $Template.ContainsKey('@odata.type')) {
                $Template['@odata.type'] = switch ($Platform) {
                    'Windows10' { '#microsoft.graph.windows10GeneralConfiguration' }
                    'iOS' { '#microsoft.graph.iosGeneralDeviceConfiguration' }
                    'Android' { '#microsoft.graph.androidGeneralDeviceConfiguration' }
                    'macOS' { '#microsoft.graph.macOSGeneralDeviceConfiguration' }
                }
            }
            
            $response = Invoke-MgGraphRequest -Uri $uri -Method POST -Body ($Template | ConvertTo-Json -Depth 10)
            Write-Information "Configuration profile created: $($response.id)" -InformationAction Continue
            return $response
        }
        catch {
            Write-Error "Failed to create configuration profile: $_"
        }
    }
}

#endregion

#region Compliance Reporting

function Get-IntuneComplianceReport {
    <#
    .SYNOPSIS
        Generate comprehensive compliance report
    .DESCRIPTION
        Creates detailed compliance report for all devices
    .PARAMETER ExportPath
        Path to export report
    .PARAMETER IncludeNonCompliantDetails
        Include detailed non-compliance reasons
    .EXAMPLE
        Get-IntuneComplianceReport -ExportPath ".\compliance-report.html" -IncludeNonCompliantDetails
    #>
    [CmdletBinding()]
    param(
        [string]$ExportPath,
        
        [switch]$IncludeNonCompliantDetails
    )
    
    # Get all devices
    $devices = Get-IntuneManagedDevices
    
    # Get compliance policies
    $uri = "https://graph.microsoft.com/$script:GraphVersion/deviceManagement/deviceCompliancePolicies"
    $policies = (Invoke-MgGraphRequest -Uri $uri -Method GET).value
    
    # Build report data
    $reportData = @{
        GeneratedOn = Get-Date
        TotalDevices = $devices.Count
        CompliantDevices = ($devices | Where-Object { $_.complianceState -eq 'compliant' }).Count
        NonCompliantDevices = ($devices | Where-Object { $_.complianceState -ne 'compliant' }).Count
        Policies = $policies.Count
        DeviceBreakdown = @{
            Windows = ($devices | Where-Object { $_.operatingSystem -eq 'Windows' }).Count
            iOS = ($devices | Where-Object { $_.operatingSystem -eq 'iOS' }).Count
            Android = ($devices | Where-Object { $_.operatingSystem -eq 'Android' }).Count
            macOS = ($devices | Where-Object { $_.operatingSystem -eq 'macOS' }).Count
        }
    }
    
    # Get non-compliant details
    if ($IncludeNonCompliantDetails) {
        $nonCompliant = $devices | Where-Object { $_.complianceState -ne 'compliant' }
        $reportData.NonCompliantDetails = @()
        
        foreach ($device in $nonCompliant) {
            $uri = "https://graph.microsoft.com/$script:GraphVersion/deviceManagement/managedDevices/$($device.id)/deviceCompliancePolicyStates"
            $states = (Invoke-MgGraphRequest -Uri $uri -Method GET).value
            
            $reportData.NonCompliantDetails += @{
                DeviceName = $device.deviceName
                User = $device.userPrincipalName
                Platform = $device.operatingSystem
                LastSync = $device.lastSyncDateTime
                NonCompliantPolicies = $states | Where-Object { $_.state -ne 'compliant' } | Select-Object displayName, state
            }
        }
    }
    
    # Export report
    if ($ExportPath) {
        if ($ExportPath -match '\.html$') {
            # Generate HTML report
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Intune Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f0f0f0; padding: 20px; border-radius: 8px; }
        .metric { display: inline-block; margin: 10px; padding: 10px; background: white; border-radius: 4px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #0078d4; color: white; }
        .compliant { color: green; }
        .non-compliant { color: red; }
    </style>
</head>
<body>
    <h1>Intune Compliance Report</h1>
    <p>Generated: $($reportData.GeneratedOn)</p>
    
    <div class="summary">
        <div class="metric">
            <h3>Total Devices</h3>
            <p style="font-size: 24px;">$($reportData.TotalDevices)</p>
        </div>
        <div class="metric">
            <h3>Compliant</h3>
            <p style="font-size: 24px;" class="compliant">$($reportData.CompliantDevices)</p>
        </div>
        <div class="metric">
            <h3>Non-Compliant</h3>
            <p style="font-size: 24px;" class="non-compliant">$($reportData.NonCompliantDevices)</p>
        </div>
    </div>
    
    <h2>Device Breakdown</h2>
    <table>
        <tr>
            <th>Platform</th>
            <th>Count</th>
        </tr>
        <tr><td>Windows</td><td>$($reportData.DeviceBreakdown.Windows)</td></tr>
        <tr><td>iOS</td><td>$($reportData.DeviceBreakdown.iOS)</td></tr>
        <tr><td>Android</td><td>$($reportData.DeviceBreakdown.Android)</td></tr>
        <tr><td>macOS</td><td>$($reportData.DeviceBreakdown.macOS)</td></tr>
    </table>
</body>
</html>
"@
            $html | Out-File $ExportPath
        }
        else {
            $reportData | ConvertTo-Json -Depth 10 | Out-File $ExportPath
        }
        
        Write-Information "Report exported to: $ExportPath" -InformationAction Continue
    }
    
    return $reportData
}

#endregion

#region Windows Autopilot

function Get-AutopilotDevices {
    <#
    .SYNOPSIS
        Get Windows Autopilot devices
    .DESCRIPTION
        Retrieves all Autopilot registered devices
    .PARAMETER GroupTag
        Filter by group tag
    .PARAMETER ExportPath
        Export to CSV
    .EXAMPLE
        Get-AutopilotDevices -GroupTag "Marketing" -ExportPath ".\autopilot-devices.csv"
    #>
    [CmdletBinding()]
    param(
        [string]$GroupTag,
        
        [string]$ExportPath
    )
    
    $uri = "https://graph.microsoft.com/$script:GraphBetaVersion/deviceManagement/windowsAutopilotDeviceIdentities"
    
    $query = @{
        '$select' = 'id,serialNumber,model,manufacturer,groupTag,purchaseOrderIdentifier,enrollmentState,lastContactedDateTime'
        '$orderby' = 'serialNumber'
    }
    
    if ($GroupTag) {
        $query['$filter'] = "groupTag eq '$GroupTag'"
    }
    
    $devices = @()
    $response = Invoke-MgGraphRequest -Uri $uri -Method GET -Body $query
    $devices += $response.value
    
    while ($response.'@odata.nextLink') {
        $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET
        $devices += $response.value
    }
    
    if ($ExportPath) {
        $devices | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Information "Exported $($devices.Count) Autopilot devices" -InformationAction Continue
    }
    
    return $devices
}

function Import-AutopilotDevice {
    <#
    .SYNOPSIS
        Import device to Windows Autopilot
    .DESCRIPTION
        Registers a device with Windows Autopilot
    .PARAMETER SerialNumber
        Device serial number
    .PARAMETER HardwareHash
        Hardware identifier
    .PARAMETER GroupTag
        Group tag for dynamic grouping
    .PARAMETER AssignedUser
        Pre-assign user
    .EXAMPLE
        Import-AutopilotDevice -SerialNumber "1234567890" -HardwareHash $hash -GroupTag "Marketing"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SerialNumber,
        
        [Parameter(Mandatory)]
        [string]$HardwareHash,
        
        [string]$GroupTag,
        
        [string]$AssignedUser
    )
    
    if ($PSCmdlet.ShouldProcess($SerialNumber, "Import to Autopilot")) {
        try {
            $uri = "https://graph.microsoft.com/$script:GraphBetaVersion/deviceManagement/importedWindowsAutopilotDeviceIdentities"
            
            $body = @{
                '@odata.type' = '#microsoft.graph.importedWindowsAutopilotDeviceIdentity'
                serialNumber = $SerialNumber
                hardwareIdentifier = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($HardwareHash))
                state = @{
                    '@odata.type' = 'microsoft.graph.importedWindowsAutopilotDeviceIdentityState'
                    deviceImportStatus = 'pending'
                    deviceRegistrationId = ''
                }
            }
            
            if ($GroupTag) {
                $body.groupTag = $GroupTag
            }
            
            if ($AssignedUser) {
                $body.assignedUserPrincipalName = $AssignedUser
            }
            
            $response = Invoke-MgGraphRequest -Uri $uri -Method POST -Body ($body | ConvertTo-Json -Depth 10)
            
            Write-Information "Device imported successfully. Import ID: $($response.id)" -InformationAction Continue
            Write-Information "Monitor import status using Get-AutopilotImportStatus" -InformationAction Continue
            
            return $response
        }
        catch {
            Write-Error "Failed to import device: $_"
        }
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Connect-IntuneGraph'
    'Get-IntuneManagedDevices'
    'Invoke-IntuneSyncDevice'
    'Set-IntuneDeviceCompliance'
    'Get-IntuneApps'
    'New-IntuneAppAssignment'
    'Get-IntuneDeviceConfigurations'
    'New-IntuneDeviceConfiguration'
    'Get-IntuneComplianceReport'
    'Get-AutopilotDevices'
    'Import-AutopilotDevice'
)