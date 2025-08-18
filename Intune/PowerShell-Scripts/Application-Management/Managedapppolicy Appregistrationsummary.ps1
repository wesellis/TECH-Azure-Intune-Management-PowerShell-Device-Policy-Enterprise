<#
.SYNOPSIS
    Managedapppolicy Appregistrationsummary

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
    We Enhanced Managedapppolicy Appregistrationsummary

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
    #>
    
        [cmdletbinding()]
    
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [Parameter(Mandatory = $true)]
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
    
        # Getting path to ActiveDirectory Assemblies
        # If the module count is greater than 1 find the latest version
    
        if ($WEAadModule.count -gt 1) {
    
            $WELatest_Version = ($WEAadModule | select version | Sort-Object)[-1]
    
            $aadModule = $WEAadModule | ? { $_.version -eq $WELatest_Version.version }
    
            # Checking if there are multiple versions of the same module found
    
            if ($WEAadModule.count -gt 1) {
    
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
    
        # Using this authentication method requires a clientID.  Register a new app in the Entra ID admin center to obtain a clientID.  More information
        # on app registration and clientID is available here: https://learn.microsoft.com/entra/identity-platform/quickstart-register-app 

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
    
            $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
    
            # If the accesstoken is valid then create the authentication header
    
            if ($authResult.AccessToken) {
    
                # Creating header for Authorization token
    
                $authHeader = @{
                    'Content-Type'  = 'application/json'
                    'Authorization' = " Bearer " + $authResult.AccessToken
                    'ExpiresOn'     = $authResult.ExpiresOn
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
    
    ####################################################
    
    Function Get-ManagedAppPolicyRegistrationSummary() {
    
    <#
    .SYNOPSIS
    This function is used to download App Protection Report for iOS and Android.
    .DESCRIPTION
    The function connects to the Graph API Interface and gets the ManagedAppRegistrationSummary
    .EXAMPLE
    Get-ManagedAppPolicyRegistrationSummary -ReportType Android_iOS
    Returns any managed app policies configured in Intune
    .NOTES
    NAME: Get-ManagedAppPolicyRegistrationSummary
    #>
    
        [cmdletbinding()]
    
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [ValidateSet(" Android_iOS" , " WIP_WE" , " WIP_MDM" )]
            $WEReportType,
            $WENextPage
        )
    
        $graphApiVersion = " Beta"
        $WEStoploop = $false
        [int]$WERetrycount = " 0"
        do{
        try {
        
            if ($WEReportType -eq "" -or $WEReportType -eq $null) {
                $WEReportType = " Android_iOS"
        
            }
            elseif ($WEReportType -eq " Android_iOS" ) {
        
                $WEResource = " /deviceAppManagement/managedAppStatuses('appregistrationsummary')?fetch=6000&policyMode=0&columns=DisplayName,UserEmail,ApplicationName,ApplicationInstanceId,ApplicationVersion,DeviceName,DeviceType,DeviceManufacturer,DeviceModel,AndroidPatchVersion,AzureADDeviceId,MDMDeviceID,Platform,PlatformVersion,ManagementLevel,PolicyName,LastCheckInDate"
                if ($WENextPage -ne "" -and $WENextPage -ne $null) {
                    $WEResource = $WEResource + " &seek=$WENextPage"
                }
                $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
        
            }
    
            elseif ($WEReportType -eq " WIP_WE" ) {
        
                $WEResource = " deviceAppManagement/managedAppStatuses('windowsprotectionreport')"
                if ($WENextPage -ne "" -and $WENextPage -ne $null) {
                    $WEResource = $WEResource + " &seek=$WENextPage"
                }
                $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
        
            }
    
            elseif ($WEReportType -eq " WIP_MDM" ) {
        
                $WEResource = " deviceAppManagement/mdmWindowsInformationProtectionPolicies"
        
                $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
            }
            $WEStoploop = $true
        }
    
        catch {
    
            $ex = $_.Exception
    
            # Retry 4 times if 503 service time out
            if($ex.Response.StatusCode.value__ -eq " 503" ) {
                $WERetrycount = $WERetrycount + 1
                $WEStoploop = $WERetrycount -gt 3
                if($WEStoploop -eq $false) {
                    Start-Sleep -Seconds 5
                    continue
                }
            }
            $errorResponse = $ex.Response.GetResponseStream()
           ;  $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
           ;  $responseBody = $reader.ReadToEnd();
            Write-WELog " Response content:`n$responseBody" " INFO" -f Red
            Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            $WEStoploop = $true
            break
        }
    }
    while ($WEStoploop -eq $false)
    
    }
    
    ####################################################
    
    Function Test-AuthToken(){
    
        # Checking if authToken exists before running authentication
        if ($global:authToken) {
    
            # Setting DateTime to Universal time to work in all timezones
            $WEDateTime = (Get-Date).ToUniversalTime()
    
            # If the authToken exists checking when it expires
            $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes
    
            if ($WETokenExpires -le 0) {
    
                write-host " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
                write-host
    
                # Defining User Principal Name if not present
    
                if ($WEUser -eq $null -or $WEUser -eq "" ) {
    
                    $global:User = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
                    Write-Host
    
                }
    
                $global:authToken = Get-AuthToken -User $WEUser
    
            }
        }
    
        # Authentication doesn't exist, calling Get-AuthToken function
    
        else {
    
            if ($WEUser -eq $null -or $WEUser -eq "" ) {
    
                $global:User = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
                Write-Host
    
            }
    
            # Getting the authorization token
            $global:authToken = Get-AuthToken -User $WEUser
    
        }
    }
    
    ####################################################
    
    Test-AuthToken
    
    ####################################################
    
    Write-Host
    
    $WEExportPath = Read-Host -Prompt " Please specify a path to export the policy data to e.g. C:\IntuneOutput"
    
    # If the directory path doesn't exist prompt user to create the directory
    
    if (!(Test-Path " $WEExportPath" )) {
    
        Write-Host
        Write-WELog " Path '$WEExportPath' doesn't exist, do you want to create this directory? Y or N?" " INFO" -ForegroundColor Yellow
    
        $WEConfirm = read-host
    
        if ($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ) {
    
            new-item -ItemType Directory -Path " $WEExportPath" | Out-Null
            Write-Host
    
        }
    
        else {
    
            Write-WELog " Creation of directory path was cancelled..." " INFO" -ForegroundColor Red
            Write-Host
            break
    
        }
    
    }
    
    Write-Host
    
    ####################################################
    
    $WEAppType = Read-Host -Prompt " Please specify the type of report [Android_iOS, WIP_WE, WIP_MDM]"
    
    if($WEAppType -eq " Android_iOS" -or $WEAppType -eq " WIP_WE" -or $WEAppType -eq " WIP_MDM" ) {
                
        Write-Host
        write-host " Running query against Microsoft Graph to download App Protection Report for '$WEAppType'.." -f Yellow
    
        $ofs = ','
        $stream = [System.IO.StreamWriter]::new(" $WEExportPath\AppRegistrationSummary_$WEAppType.csv" , $false, [System.Text.Encoding]::UTF8)
        $WEManagedAppPolicies = Get-ManagedAppPolicyRegistrationSummary -ReportType $WEAppType
        $stream.WriteLine([string]($WEManagedAppPolicies.content.header | % {$_.columnName } ))
    
        do {
            Test-AuthToken
    
            write-host " Your data is being downloaded for '$WEAppType'..."
           ;  $WEMoreItem = $WEManagedAppPolicies.content.skipToken -ne "" -and $WEManagedAppPolicies.content.skipToken -ne $null
            
            foreach ($WESummaryItem in $WEManagedAppPolicies.content.body) {
    
                $stream.WriteLine([string]($WESummaryItem.values -replace " ," ," ." ))
            }
            
            if ($WEMoreItem){
    
               ;  $WEManagedAppPolicies = Get-ManagedAppPolicyRegistrationSummary -ReportType $WEAppType -NextPage ($WEManagedAppPolicies.content.skipToken)
            }
    
        } while ($WEMoreItem)
        
        $stream.close()
        
        write-host
        
    }
        
    else {
        
        Write-WELog " AppType isn't a valid option..." " INFO" -ForegroundColor Red
        Write-Host
        
    }



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================