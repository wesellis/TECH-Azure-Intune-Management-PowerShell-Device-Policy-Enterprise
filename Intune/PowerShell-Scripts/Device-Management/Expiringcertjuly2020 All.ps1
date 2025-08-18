<#
.SYNOPSIS
    Expiringcertjuly2020 All

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
    We Enhanced Expiringcertjuly2020 All

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

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.



[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory = $true, HelpMessage = " File path and name for output of expiring devices" )]
    $WEOutputFile

)



function WE-Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
    [Parameter(Mandatory=$true)]
    $WEUser
)

$userUpn = New-Object " System.Net.Mail.MailAddress" -ArgumentList $WEUser

$tenant = $userUpn.Host

Write-WELog " Checking for AzureAD module..." " INFO"

    $WEAadModule = Get-Module -Name " AzureAD" -ListAvailable

    if ($WEAadModule -eq $null) {

        Write-WELog " AzureAD PowerShell module not found, looking for AzureADPreview" " INFO"
        $WEAadModule = Get-Module -Name " AzureADPreview" -ListAvailable

    }

    if ($WEAadModule -eq $null) {
        write-host
        write-host " AzureAD Powershell module not installed..." -f Red
        write-host " Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host " Script can't continue..." -f Red
        write-host
        exit
    }



    if($WEAadModule.count -gt 1){

        $WELatest_Version = ($WEAadModule | select version | Sort-Object)[-1]

        $aadModule = $WEAadModule | ? { $_.version -eq $WELatest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($WEAadModule.count -gt 1){

            $aadModule = $WEAadModule | select -Unique

            }

        $adal = Join-Path $WEAadModule.ModuleBase " Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $WEAadModule.ModuleBase " Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $WEAadModule.ModuleBase " Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $WEAadModule.ModuleBase " Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null



$clientId = " <replace with your clientID>"

$redirectUri = " urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = " https://graph.microsoft.com"

$authority = " https://login.microsoftonline.com/$WETenant"

    try {

    $authContext = New-Object " Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object " Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList " Auto"

    $userId = New-Object " Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($WEUser, " OptionalDisplayableId" )

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'=" Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-WELog " Authorization Access Token is null, please re-run authentication..." " INFO" -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}



function WE-Get-MsGraphCollection {

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory = $true)]
    $WEUri,
        
    [Parameter(Mandatory = $true)]
    $WEAuthHeader
)

    $WECollection = @()
    $WENextLink = $WEUri
    $WECertExpiration = [datetime]'2020-07-12 12:00:00'  #(Get-Date -Year 2019 -Month 4 -Day 21 -Hour 14 -Minute 48)

    do {

        try {

            Write-WELog " GET $WENextLink" " INFO"
            $WEResult = Invoke-RestMethod -Method Get -Uri $WENextLink -Headers $WEAuthHeader

            foreach ($d in $WEResult.value)
            {
                if ([datetime]($d.managementCertificateExpirationDate) -le $WECertExpiration)
                {
                    $WECollection = $WECollection + $d
                }
            }
            $WENextLink = $WEResult.'@odata.nextLink'
        } 

        catch {

            $WEResponseStream = $_.Exception.Response.GetResponseStream()
            $WEResponseReader = New-Object System.IO.StreamReader $WEResponseStream
            $WEResponseContent = $WEResponseReader.ReadToEnd()
            Write-WELog " Request Failed: $($_.Exception.Message)`n$($_.ErrorDetails)" " INFO"
            Write-WELog " Request URL: $WENextLink" " INFO"
            Write-WELog " Response Content:`n$WEResponseContent" " INFO"
            break

        }

    } while ($WENextLink -ne $null)

    return $WECollection
}





write-host


if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $WEDateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes

        if($WETokenExpires -le 0){

        write-host " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($WEUser -eq $null -or $WEUser -eq "" ){

            $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $WEUser

        }
}



else {

    if($WEUser -eq $null -or $WEUser -eq "" ){

    $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
    Write-Host

    }


$global:authToken = Get-AuthToken -User $WEUser

}




; 
$uri = " https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=((managementAgent%20eq%20%27mdm%27%20or%20managementAgent%20eq%20%27easmdm%27%20or%20managementAgent%20eq%20%27configurationmanagerclientmdm%27%20or%20managementAgent%20eq%20%27configurationmanagerclientmdmeas%27)%20and%20managementState%20eq%20%27managed%27)"
; 
$devices = Get-MsGraphCollection -Uri $uri -AuthHeader $authToken

Write-Host
Write-WELog " Found" " INFO" $devices.Count " devices:"
Write-WELog " Writing results to" " INFO" $WEOutputFile -ForegroundColor Cyan

($devices | Select-Object Id, DeviceName, DeviceType, IMEI, UserPrincipalName, SerialNumber, LastSyncDateTime, ManagementCertificateExpirationDate) | Export-Csv -Path $WEOutputFile -NoTypeInformation 

$devices | Select-Object Id, DeviceName, DeviceType, IMEI, UserPrincipalName, SerialNumber, LastSyncDateTime, ManagementCertificateExpirationDate

Write-WELog " Results written to" " INFO" $WEOutputFile -ForegroundColor Yellow



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================