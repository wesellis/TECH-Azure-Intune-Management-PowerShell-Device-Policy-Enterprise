<#
.SYNOPSIS
    Toastappstatus

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
    We Enhanced Toastappstatus

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
Display Window to keep users informed of apps and policy being applied from Intune.

.DESCRIPTION
This script is designed to be run as a scheduled task after Autopilot provisioning to keep users informed of apps and policy being applied from Intune. The script will check for assigned applications and display a pop up Window showing status.

.PARAMETER message
Microsoft Graph API client ID, client secret, and tenant name.
The message to display in the toast notification.

.EXAMPLE
IntuneToast.ps1 -clientId " 12345678-1234-1234-1234-123456789012" -clientSecret " client_secret" -tenantName " tenantName"

.NOTES
File Name      : IntuneToast.ps1
Author         : Justin Rice, Steve Weiner
Prerequisite   : PowerShell V5
Copyright 2025 - Rubix, LLC. All rights reserved.



[CmdletBinding()]
function log {
    param(
        [string]$message
    )
    $time = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
    $message = " $time - $message"
    Write-Output $message
}


function msGraphAuthenticate()
{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
    param(
        [string]$clientId = " <client_id>" ,
        [string]$clientSecret = " <client_secret>" ,
        [string]$tenantName = " <tenant_name>"
    )
    $headers = New-Object -ErrorAction Stop " System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add(" Content-Type" , " application/x-www-form-urlencoded" )
    $body = " grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
    $body = $body + -join (" &client_id=" , $clientId, " &client_secret=" , $clientSecret)
    $response = Invoke-RestMethod " https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body
    # Get token from OAuth response

    $token = -join (" Bearer " , $response.access_token)

    # Reinstantiate headers
    $headers = New-Object -ErrorAction Stop " System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add(" Authorization" , $token)
    $headers.Add(" Content-Type" , " application/json" )
    $headers = @{'Authorization'=" $($token)" }
    return $headers
}


$WEHeaders = msGraphAuthenticate


$WEGraphAPIBase = " https://graph.microsoft.com/beta"



[string]$WEWin32RegPath = " HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
[string]$WEGraphAPIBase = " https://graph.microsoft.com/beta"
    

$WEAppStatusList = @()

if(Test-Path $WEWin32RegPath)
{
    # Pattern matching for validation
# Pattern matching for validation
$WEAppGUIDs = Get-ChildItem -Path $WEWin32RegPath | Select-Object -ExpandProperty PSChildName | Where-Object { $_ -match " ^[0-9a-fA-F\-]{36}$" }

    foreach ($WEAppGUID in $WEAPPGUIDs)
    {
        $WEAppGUIDPath = " $($WEWin32RegPath)\$($WEAppGUID)"

        if(Test-Path $WEAppGUIDPath)
        {
            $WEParentSubKeys = Get-ChildItem -Path $WEAppGUIDPath | Select-Object -ExpandProperty PSChildName -ErrorAction SilentlyContinue

            if($WEParentSubKeys)
            {
                $WESubKeys = $WEParentSubKeys | Where-Object { $_ -match " ^[0-9a-fA-F\-]{36}" }

                if ($WESubKeys)
                {
                    foreach($WESubKey in $WESubKeys)
                    {
                        if($WESubKey -match " ^(.*)_1$" )
                        {
                            $WESubKey = $matches[1]
                        }
                        else
                        {
                            $WESubKey = $WESubKey
                        }
                        $WERegPath = " $($WEAppGUIDPath)\$($WESubKey)_1\EnforcementStateMessage"
                        $WERegValue = " EnforcementStateMessage"

                        if(Test-Path $WERegPath)
                        {
                            try
                            {
                                $WEEnforcementStateMessage = Get-ItemProperty -Path $WERegPath -Name $WERegValue | Select-Object -ExpandProperty $WERegValue
                                $WEEnforcementStateMessage = $WEEnforcementStateMessage.Trim()

                                if($WEEnforcementStateMessage -match " ^\{" )
                                {
                                    try
                                    {
                                        $WEEnforcementStateObject = $WEEnforcementStateMessage | ConvertFrom-Json
                                        $WEEnforcementState = $WEEnforcementStateObject.EnforcementState                                            
                                        
                                    }
                                    catch
                                    {
                                        log " Error parsing JSON: $_"
                                    }
                                }
                                else
                                {
                                    log " Error: EnforcementStateMessage is not in JSON format"
                                }


                               ;  $WEGraphUri = " $($WEGraphAPIBase)/deviceAppManagement/mobileApps/$($WESubKey)"
                               ;  $WEAppDisplayName = (Invoke-RestMethod -Method Get -Uri $WEGraphUri -Headers $WEHeaders).DisplayName

                               ;  $WEAppStatusList = $WEAppStatusList + [PSCustomObject]@{
                                    DisplayName = $WEAppDisplayName
                                    AppId = $WESubKey
                                    EnforcementState = $WEEnforcementState
                                }
                            }
                            catch
                            {
                                log " Error retrieving EnforcementState for App GUID: $($WESubKey) - $_"
                            }
                        }
                        else
                        {
                            log " Registry key not found: $WERegPath"
                        }
                    }
                }
                else
                {
                    log " No valid subkeys found under: $WEAppGUIDPath"
                }
            }
            else
            {
                log " No subkeys found for App GUID: $WEAppGUID"
            }
        }
        else
        {
            log " Registry path does not exist: $WEAppGUIDPath"
        }
    }
    
}
else
{
    log " Registry path not found: $WEWin32RegPath"
}



if($null -eq $WEAppStatusList)
{
    log " No applications found.  Exiting..."
    # Kill task
    Exit 0
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================