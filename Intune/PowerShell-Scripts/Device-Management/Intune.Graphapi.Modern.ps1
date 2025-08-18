<#
.SYNOPSIS
    Intune.Graphapi.Modern

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
    We Enhanced Intune.Graphapi.Modern

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


<#


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
    Modern Microsoft Graph API integration for Intune Device Management
.DESCRIPTION
    Comprehensive Intune management using Microsoft Graph API v1.0 and beta endpoints
.VERSION
    2.0.0
.AUTHOR
    Azure Intune Management Toolkit



$script:GraphVersion = " v1.0"
$script:GraphBetaVersion = " beta"
$script:RequiredScopes = @(
    " DeviceManagementManagedDevices.Read.All" ,
    " DeviceManagementManagedDevices.ReadWrite.All" ,
    " DeviceManagementApps.Read.All" ,
    " DeviceManagementApps.ReadWrite.All" ,
    " DeviceManagementConfiguration.Read.All" ,
    " DeviceManagementConfiguration.ReadWrite.All"
)



function WE-Connect-IntuneGraph {
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
        Connect-IntuneGraph -TenantId " contoso.onmicrosoft.com" -UseDeviceCode
    #>
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
    param(
        [Parameter(Mandatory)]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WETenantId,
        
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEClientId,
        
        [switch]$WEUseDeviceCode
    )
    
    try {
        $connectParams = @{
            TenantId = $WETenantId
            Scopes = $script:RequiredScopes
        }
        
        if ($WEClientId) {
            $connectParams.ClientId = $WEClientId
        }
        
        if ($WEUseDeviceCode) {
            $connectParams.UseDeviceCode = $true
        }
        
        Connect-MgGraph @connectParams
        
        $context = Get-MgContext
        Write-Information " Connected to tenant: $($context.TenantId)" -InformationAction Continue
        Write-Information " Scopes: $($context.Scopes -join ', ')" -InformationAction Continue
        
        return $context
    }
    catch {
        Write-Error " Failed to connect to Microsoft Graph: $_"
    }
}





function WE-Get-IntuneManagedDevices {
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
        Get-IntuneManagedDevices -Platform " Windows" -ComplianceState " Compliant" -ExportPath " .\devices.csv"
    #>
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
    param(
        [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'All')]
        [string]$WEPlatform = 'All',
        
        [ValidateSet('Compliant', 'NonCompliant', 'All')]
        [string]$WEComplianceState = 'All',
        
        [int]$WELastSyncDays,
        
        [string]$WEExportPath
    )
    
    $uri = " https://graph.microsoft.com/$script:GraphVersion/deviceManagement/managedDevices"
    $filter = @()
    
    # Build filter
    if ($WEPlatform -ne 'All') {
        $platformFilter = switch ($WEPlatform) {
            'Windows' { " operatingSystem eq 'Windows'" }
            'iOS' { " operatingSystem eq 'iOS'" }
            'Android' { " operatingSystem eq 'Android'" }
            'macOS' { " operatingSystem eq 'macOS'" }
        }
        $filter = $filter + $platformFilter
    }
    
    if ($WEComplianceState -ne 'All') {
        $complianceFilter = if ($WEComplianceState -eq 'Compliant') {
            " complianceState eq 'compliant'"
        } else {
            " complianceState ne 'compliant'"
        }
        $filter = $filter + $complianceFilter
    }
    
    if ($WELastSyncDays) {
        $syncDate = (Get-Date).AddDays(-$WELastSyncDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $filter = $filter + " lastSyncDateTime ge $syncDate"
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
        $devices = $devices + $response.value
        $nextLink = $response.'@odata.nextLink'
        
        # Clear query for subsequent requests
        $query = @{}
    }
    
    # Export if requested
    if ($WEExportPath) {
        $devices | Export-Csv -Path $WEExportPath -NoTypeInformation
        Write-Information " Exported $($devices.Count) devices to: $WEExportPath" -InformationAction Continue
    }
    
    return $devices
}

function WE-Invoke-IntuneSyncDevice {
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
        Get-IntuneManagedDevices -Platform " Windows" | Invoke-IntuneSyncDevice
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [string[]]$WEDeviceId,
        
        [switch]$WEAll,
        
        [ValidateSet('Windows', 'iOS', 'Android', 'macOS')]
        [string]$WEPlatform
    )
    
    process {
        if ($WEAll -or $WEPlatform) {
            $devices = Get-IntuneManagedDevices -Platform ($WEPlatform ?? 'All')
            $WEDeviceId = $devices.id
        }
        
        foreach ($id in $WEDeviceId) {
            if ($WEPSCmdlet.ShouldProcess($id, " Sync device" )) {
                try {
                    $uri = " https://graph.microsoft.com/$script:GraphVersion/deviceManagement/managedDevices/$id/syncDevice"
                    Invoke-MgGraphRequest -Uri $uri -Method POST
                    Write-Information " Sync triggered for device: $id" -InformationAction Continue
                }
                catch {
                    Write-Error " Failed to sync device $id: $_"
                }
            }
        }
    }
}

function WE-Set-IntuneDeviceCompliance {
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
        Set-IntuneDeviceCompliance -DeviceId $device.id -Action " Retire"
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEDeviceId,
        
        [Parameter(Mandatory)]
        [ValidateSet('Retire', 'Wipe', 'Delete', 'RemoveCompanyData', 'DisableLostMode')]
        [string]$WEAction
    )
    
    $actionMap = @{
        'Retire' = 'retire'
        'Wipe' = 'wipe'
        'Delete' = 'delete'
        'RemoveCompanyData' = 'removeCompanyData'
        'DisableLostMode' = 'disableLostMode'
    }
    
    if ($WEPSCmdlet.ShouldProcess($WEDeviceId, $WEAction)) {
        try {
            $uri = " https://graph.microsoft.com/$script:GraphVersion/deviceManagement/managedDevices/$WEDeviceId/$($actionMap[$WEAction])"
            Invoke-MgGraphRequest -Uri $uri -Method POST
            Write-Information " $WEAction action completed for device: $WEDeviceId" -InformationAction Continue
        }
        catch {
            Write-Error " Failed to perform $WEAction on device $WEDeviceId: $_"
        }
    }
}





function WE-Get-IntuneApps {
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
        Get-IntuneApps -AppType " Microsoft" -IncludeAssignments
    #>
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
    param(
        [ValidateSet('All', 'Microsoft', 'iOS', 'Android', 'Windows', 'WebApp', 'Office365')]
        [string]$WEAppType = 'All',
        
        [switch]$WEIncludeAssignments
    )
    
    $uri = " https://graph.microsoft.com/$script:GraphVersion/deviceAppManagement/mobileApps"
    
    # Get apps
    $apps = (Invoke-MgGraphRequest -Uri $uri -Method GET).value
    
    # Filter by type
    if ($WEAppType -ne 'All') {
        $apps = switch ($WEAppType) {
            'Microsoft' { $apps | Where-Object { $_.'@odata.type' -match 'microsoft' } }
            'iOS' { $apps | Where-Object { $_.'@odata.type' -match 'ios' } }
            'Android' { $apps | Where-Object { $_.'@odata.type' -match 'android' } }
            'Windows' { $apps | Where-Object { $_.'@odata.type' -match 'windows' } }
            'WebApp' { $apps | Where-Object { $_.'@odata.type' -match 'webApp' } }
            'Office365' { $apps | Where-Object { $_.'@odata.type' -match 'officeSuite' } }
        }
    }
    
    # Get assignments if requested
    if ($WEIncludeAssignments) {
        foreach ($app in $apps) {
            $assignmentUri = " https://graph.microsoft.com/$script:GraphVersion/deviceAppManagement/mobileApps/$($app.id)/assignments"
            $app | Add-Member -NotePropertyName 'assignments' -NotePropertyValue (Invoke-MgGraphRequest -Uri $assignmentUri -Method GET).value
        }
    }
    
    return $apps
}

function WE-New-IntuneAppAssignment {
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
        New-IntuneAppAssignment -AppId $app.id -GroupId $group.id -Intent " Required"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAppId,
        
        [Parameter(Mandatory)]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEGroupId,
        
        [Parameter(Mandatory)]
        [ValidateSet('Required', 'Available', 'Uninstall')]
        [string]$WEIntent
    )
    
    if ($WEPSCmdlet.ShouldProcess(" $WEAppId to $WEGroupId" , " Assign app" )) {
        try {
            $uri = " https://graph.microsoft.com/$script:GraphVersion/deviceAppManagement/mobileApps/$WEAppId/assignments"
            
            $assignment = @{
                '@odata.type' = '#microsoft.graph.mobileAppAssignment'
                target = @{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId = $WEGroupId
                }
                intent = $WEIntent.ToLower()
            }
            
            $body = @{
                mobileAppAssignments = @($assignment)
            }
            
            Invoke-MgGraphRequest -Uri $uri -Method POST -Body ($body | ConvertTo-Json -Depth 10)
            Write-Information " App assigned successfully" -InformationAction Continue
        }
        catch {
            Write-Error " Failed to assign app: $_"
        }
    }
}





function WE-Get-IntuneDeviceConfigurations {
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
        Get-IntuneDeviceConfigurations -Platform " Windows10" -IncludeAssignments
    #>
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
    param(
        [ValidateSet('All', 'Windows10', 'iOS', 'Android', 'macOS')]
        [string]$WEPlatform = 'All',
        
        [switch]$WEIncludeAssignments
    )
    
    $uri = " https://graph.microsoft.com/$script:GraphVersion/deviceManagement/deviceConfigurations"
    $configurations = (Invoke-MgGraphRequest -Uri $uri -Method GET).value
    
    # Filter by platform
    if ($WEPlatform -ne 'All') {
        $configurations = $configurations | Where-Object { $_.'@odata.type' -match $WEPlatform }
    }
    
    # Get assignments
    if ($WEIncludeAssignments) {
        foreach ($config in $configurations) {
            $assignmentUri = " https://graph.microsoft.com/$script:GraphVersion/deviceManagement/deviceConfigurations/$($config.id)/assignments"
            $config | Add-Member -NotePropertyName 'assignments' -NotePropertyValue (Invoke-MgGraphRequest -Uri $assignmentUri -Method GET).value
        }
    }
    
    return $configurations
}

function WE-New-IntuneDeviceConfiguration {
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
        New-IntuneDeviceConfiguration -Name " Windows Security Baseline" -Template $template -Platform " Windows10"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEName,
        
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEDescription,
        
        [Parameter(Mandatory)]
        [hashtable]$WETemplate,
        
        [Parameter(Mandatory)]
        [ValidateSet('Windows10', 'iOS', 'Android', 'macOS')]
        [string]$WEPlatform
    )
    
    if ($WEPSCmdlet.ShouldProcess($WEName, " Create configuration profile" )) {
        try {
            $uri = " https://graph.microsoft.com/$script:GraphVersion/deviceManagement/deviceConfigurations"
            
            # Add metadata
            $WETemplate['displayName'] = $WEName
            $WETemplate['description'] = $WEDescription
            
            # Set OData type based on platform
            if (-not $WETemplate.ContainsKey('@odata.type')) {
                $WETemplate['@odata.type'] = switch ($WEPlatform) {
                    'Windows10' { '#microsoft.graph.windows10GeneralConfiguration' }
                    'iOS' { '#microsoft.graph.iosGeneralDeviceConfiguration' }
                    'Android' { '#microsoft.graph.androidGeneralDeviceConfiguration' }
                    'macOS' { '#microsoft.graph.macOSGeneralDeviceConfiguration' }
                }
            }
            
            $response = Invoke-MgGraphRequest -Uri $uri -Method POST -Body ($WETemplate | ConvertTo-Json -Depth 10)
            Write-Information " Configuration profile created: $($response.id)" -InformationAction Continue
            return $response
        }
        catch {
            Write-Error " Failed to create configuration profile: $_"
        }
    }
}





function WE-Get-IntuneComplianceReport {
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
        Get-IntuneComplianceReport -ExportPath " .\compliance-report.html" -IncludeNonCompliantDetails
    #>
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
    param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEExportPath,
        
        [switch]$WEIncludeNonCompliantDetails
    )
    
    # Get all devices
    $devices = Get-IntuneManagedDevices
    
    # Get compliance policies
    $uri = " https://graph.microsoft.com/$script:GraphVersion/deviceManagement/deviceCompliancePolicies"
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
    if ($WEIncludeNonCompliantDetails) {
        $nonCompliant = $devices | Where-Object { $_.complianceState -ne 'compliant' }
        $reportData.NonCompliantDetails = @()
        
        foreach ($device in $nonCompliant) {
            $uri = " https://graph.microsoft.com/$script:GraphVersion/deviceManagement/managedDevices/$($device.id)/deviceCompliancePolicyStates"
           ;  $states = (Invoke-MgGraphRequest -Uri $uri -Method GET).value
            
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
    if ($WEExportPath) {
        if ($WEExportPath -match '\.html$') {
            # Generate HTML report
           ;  $html = @"
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
    
    <div class=" summary" >
        <div class=" metric" >
            <h3>Total Devices</h3>
            <p style=" font-size: 24px;" >$($reportData.TotalDevices)</p>
        </div>
        <div class=" metric" >
            <h3>Compliant</h3>
            <p style=" font-size: 24px;" class=" compliant" >$($reportData.CompliantDevices)</p>
        </div>
        <div class=" metric" >
            <h3>Non-Compliant</h3>
            <p style=" font-size: 24px;" class=" non-compliant" >$($reportData.NonCompliantDevices)</p>
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
" @
            $html | Out-File $WEExportPath
        }
        else {
            $reportData | ConvertTo-Json -Depth 10 | Out-File $WEExportPath
        }
        
        Write-Information " Report exported to: $WEExportPath" -InformationAction Continue
    }
    
    return $reportData
}





function WE-Get-AutopilotDevices {
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
        Get-AutopilotDevices -GroupTag " Marketing" -ExportPath " .\autopilot-devices.csv"
    #>
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
    param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEGroupTag,
        
        [string]$WEExportPath
    )
    
    $uri = " https://graph.microsoft.com/$script:GraphBetaVersion/deviceManagement/windowsAutopilotDeviceIdentities"
    
    $query = @{
        '$select' = 'id,serialNumber,model,manufacturer,groupTag,purchaseOrderIdentifier,enrollmentState,lastContactedDateTime'
        '$orderby' = 'serialNumber'
    }
    
    if ($WEGroupTag) {
        $query['$filter'] = " groupTag eq '$WEGroupTag'"
    }
    
    $devices = @()
    $response = Invoke-MgGraphRequest -Uri $uri -Method GET -Body $query
    $devices = $devices + $response.value
    
    while ($response.'@odata.nextLink') {
        $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET
        $devices = $devices + $response.value
    }
    
    if ($WEExportPath) {
        $devices | Export-Csv -Path $WEExportPath -NoTypeInformation
        Write-Information " Exported $($devices.Count) Autopilot devices" -InformationAction Continue
    }
    
    return $devices
}

function WE-Import-AutopilotDevice {
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
        Import-AutopilotDevice -SerialNumber " 1234567890" -HardwareHash $hash -GroupTag " Marketing"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESerialNumber,
        
        [Parameter(Mandatory)]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEHardwareHash,
        
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEGroupTag,
        
        [string]$WEAssignedUser
    )
    
    if ($WEPSCmdlet.ShouldProcess($WESerialNumber, " Import to Autopilot" )) {
        try {
            $uri = " https://graph.microsoft.com/$script:GraphBetaVersion/deviceManagement/importedWindowsAutopilotDeviceIdentities"
            
           ;  $body = @{
                '@odata.type' = '#microsoft.graph.importedWindowsAutopilotDeviceIdentity'
                serialNumber = $WESerialNumber
                hardwareIdentifier = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($WEHardwareHash))
                state = @{
                    '@odata.type' = 'microsoft.graph.importedWindowsAutopilotDeviceIdentityState'
                    deviceImportStatus = 'pending'
                    deviceRegistrationId = ''
                }
            }
            
            if ($WEGroupTag) {
                $body.groupTag = $WEGroupTag
            }
            
            if ($WEAssignedUser) {
                $body.assignedUserPrincipalName = $WEAssignedUser
            }
            
           ;  $response = Invoke-MgGraphRequest -Uri $uri -Method POST -Body ($body | ConvertTo-Json -Depth 10)
            
            Write-Information " Device imported successfully. Import ID: $($response.id)" -InformationAction Continue
            Write-Information " Monitor import status using Get-AutopilotImportStatus" -InformationAction Continue
            
            return $response
        }
        catch {
            Write-Error " Failed to import device: $_"
        }
    }
}




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


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================