<#
.SYNOPSIS
    Endpointsecuritypolicy Export

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
    We Enhanced Endpointsecuritypolicy Export

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
function WE-Get-AuthToken -ErrorAction Stop {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken -ErrorAction Stop
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    $WEUser
)

$userUpn = New-Object -ErrorAction Stop " System.Net.Mail.MailAddress" -ArgumentList $WEUser

$tenant = $userUpn.Host

Write-WELog " Checking for AzureAD module..." " INFO"

    $WEAadModule = Get-Module -Name " AzureAD" -ListAvailable

    if ($null -eq $WEAadModule) {

        Write-WELog " AzureAD PowerShell module not found, looking for AzureADPreview" " INFO"
        $WEAadModule = Get-Module -Name " AzureADPreview" -ListAvailable

    }

    if ($null -eq $WEAadModule) {
        Write-Information write-host " AzureAD Powershell module not installed..." -f Red
        Write-Information " Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        Write-Information " Script can't continue..." -f Red
        Write-Information exit
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

    $authContext = New-Object -ErrorAction Stop " Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object -ErrorAction Stop " Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList " Auto"

    $userId = New-Object -ErrorAction Stop " Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($WEUser, " OptionalDisplayableId" )

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

        Write-Information Write-WELog " Authorization Access Token is null, please re-run authentication..." " INFO"
        Write-Information break

        }

    }

    catch {

    Write-Information $_.Exception.Message -f Red
    Write-Information $_.Exception.ItemName -f Red
    Write-Information break

    }

}



Function Get-EndpointSecurityTemplate(){

<#
.SYNOPSIS
This function is used to get all Endpoint Security templates using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all Endpoint Security templates
.EXAMPLE
Get-EndpointSecurityTemplate -ErrorAction Stop 
Gets all Endpoint Security Templates in Endpoint Manager
.NOTES
NAME: Get-EndpointSecurityTemplate -ErrorAction Stop



$graphApiVersion = " Beta"
$WEESP_resource = " deviceManagement/templates?`$filter=(isof(%27microsoft.graph.securityBaselineTemplate%27))"

    try {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEESP_resource)"
        (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    Write-Information break

    }

}



Function Get-EndpointSecurityPolicy(){

<#
.SYNOPSIS
This function is used to get all Endpoint Security policies using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all Endpoint Security templates
.EXAMPLE
Get-EndpointSecurityPolicy -ErrorAction Stop
Gets all Endpoint Security Policies in Endpoint Manager
.NOTES
NAME: Get-EndpointSecurityPolicy -ErrorAction Stop



$graphApiVersion = " Beta"
$WEESP_resource = " deviceManagement/intents"

    try {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEESP_resource)"
        (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    Write-Information break

    }

}



Function Get-EndpointSecurityTemplateCategory(){

<#
.SYNOPSIS
This function is used to get all Endpoint Security categories from a specific template using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all template categories
.EXAMPLE
Get-EndpointSecurityTemplateCategory -TemplateId $templateId
Gets an Endpoint Security Categories from a specific template in Endpoint Manager
.NOTES
NAME: Get-EndpointSecurityTemplateCategory -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $WETemplateId
)

$graphApiVersion = " Beta"
$WEESP_resource = " deviceManagement/templates/$WETemplateId/categories"

    try {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEESP_resource)"
        (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    Write-Information break

    }

}



Function Get-EndpointSecurityCategorySetting(){

<#
.SYNOPSIS
This function is used to get an Endpoint Security category setting from a specific policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a policy category setting
.EXAMPLE
Get-EndpointSecurityCategorySetting -PolicyId $policyId -categoryId $categoryId
Gets an Endpoint Security Categories from a specific template in Endpoint Manager
.NOTES
NAME: Get-EndpointSecurityCategory -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $WEPolicyId,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $categoryId
)

$graphApiVersion = " Beta"
$WEESP_resource = " deviceManagement/intents/$policyId/categories/$categoryId/settings?`$expand=Microsoft.Graph.DeviceManagementComplexSettingInstance/Value"

    try {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEESP_resource)"
        (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    Write-Information break

    }

}



Function Export-JSONData(){

<#
.SYNOPSIS
This function is used to export JSON data returned from Graph
.DESCRIPTION
This function is used to export JSON data returned from Graph
.EXAMPLE
Export-JSONData -JSON $WEJSON
Export the JSON inputted on the function
.NOTES
NAME: Export-JSONData




[CmdletBinding()]
function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$Message,
        [ValidateSet(" INFO" , " WARN" , " ERROR" , " SUCCESS" )]
        [string]$Level = " INFO"
    )
    
   ;  $timestamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
   ;  $colorMap = @{
        " INFO" = " Cyan" ; " WARN" = " Yellow" ; " ERROR" = " Red" ; " SUCCESS" = " Green"
    }
    
    $logEntry = " $timestamp [WE-Enhanced] [$Level] $Message"
    Write-Information $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
$WEJSON,
$WEExportPath

)

    try {

        if($WEJSON -eq "" -or $null -eq $WEJSON){

        Write-Information " No JSON specified, please specify valid JSON..." -f Red

        }

        elseif(!$WEExportPath){

        Write-Information " No export path parameter set, please provide a path to export the file" -f Red

        }

        elseif(!(Test-Path $WEExportPath)){

        Write-Information " $WEExportPath doesn't exist, can't export JSON Data" -f Red

        }

        else {

        $WEJSON1 = ConvertTo-Json $WEJSON -Depth 5

        $WEJSON_Convert = $WEJSON1 | ConvertFrom-Json

        $displayName = $WEJSON_Convert.displayName

        # Updating display name to follow file naming conventions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
        $WEDisplayName = $WEDisplayName -replace '\<|\>|:|" |/|\\|\||\?|\*', " _"

            # Added milliseconds to date format due to duplicate policy name
            $WEFileName_JSON = " $WEDisplayName" + " _" + $(get-date -f dd-MM-yyyy-H-mm-ss.fff) + " .json"

            Write-Information " Export Path:" " $WEExportPath"

            $WEJSON1 | Set-Content -LiteralPath " $WEExportPath\$WEFileName_JSON"
            Write-Information " JSON created in $WEExportPath\$WEFileName_JSON..." -f cyan
            
        }

    }

    catch {

    $_.Exception

    }

}





Write-Information if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $WEDateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes

        if($WETokenExpires -le 0){

        Write-Information " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
        Write-Information # Defining User Principal Name if not present

            if($null -eq $WEUser -or $WEUser -eq "" ){

            $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
            Write-Information }

        $script:authToken = Get-AuthToken -User $WEUser

        }
}



else {

    if($null -eq $WEUser -or $WEUser -eq "" ){

    $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
    Write-Information }


$script:authToken = Get-AuthToken -User $WEUser

}







$WEExportPath = Read-Host -Prompt " Please specify a path to export the policy data to e.g. C:\IntuneOutput"

    # If the directory path doesn't exist prompt user to create the directory
    $WEExportPath = $WEExportPath.replace('" ','')

    if(!(Test-Path " $WEExportPath" )){

    Write-Information Write-WELog " Path '$WEExportPath' doesn't exist, do you want to create this directory? Y or N?" " INFO"

    $WEConfirm = read-host

        if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

        new-item -ItemType Directory -Path " $WEExportPath" | Out-Null
        Write-Information }

        else {

        Write-WELog " Creation of directory path was cancelled..." " INFO" -ForegroundColor Red
        Write-Information break

        }

    }

Write-Information $WETemplates = Get-EndpointSecurityTemplate -ErrorAction Stop




$WEESPolicies = Get-EndpointSecurityPolicy -ErrorAction Stop | Sort-Object displayName




foreach($policy in $WEESPolicies){

    Write-WELog " Endpoint Security Policy:" " INFO" $policy.displayName -ForegroundColor Yellow
    $WEPolicyName = $policy.displayName
    $WEPolicyDescription = $policy.description
    $policyId = $policy.id
    $WETemplateId = $policy.templateId
    $roleScopeTagIds = $policy.roleScopeTagIds

    $WEES_Template = $WETemplates | ?  { $_.id -eq $policy.templateId }

    $WETemplateDisplayName = $WEES_Template.displayName
    $WETemplateId = $WEES_Template.id
    $versionInfo = $WEES_Template.versionInfo

    if($WETemplateDisplayName -eq " Endpoint detection and response" ){

        Write-WELog " Export of 'Endpoint detection and response' policy not included in sample script..." " INFO" -ForegroundColor Magenta
        Write-Information }

    else {

        ####################################################

        # Creating object for JSON output
        $WEJSON = New-Object -TypeName PSObject

        Add-Member -InputObject $WEJSON -MemberType 'NoteProperty' -Name 'displayName' -Value " $WEPolicyName"
        Add-Member -InputObject $WEJSON -MemberType 'NoteProperty' -Name 'description' -Value " $WEPolicyDescription"
        Add-Member -InputObject $WEJSON -MemberType 'NoteProperty' -Name 'roleScopeTagIds' -Value $roleScopeTagIds
        Add-Member -InputObject $WEJSON -MemberType 'NoteProperty' -Name 'TemplateDisplayName' -Value " $WETemplateDisplayName"
        Add-Member -InputObject $WEJSON -MemberType 'NoteProperty' -Name 'TemplateId' -Value " $WETemplateId"
        Add-Member -InputObject $WEJSON -MemberType 'NoteProperty' -Name 'versionInfo' -Value " $versionInfo"

        ####################################################

        # Getting all categories in specified Endpoint Security Template
       ;  $WECategories = Get-EndpointSecurityTemplateCategory -TemplateId $WETemplateId

        # Looping through all categories within the Template

        foreach($category in $WECategories){

           ;  $categoryId = $category.id

           ;  $WESettings = $WESettings + Get-EndpointSecurityCategorySetting -PolicyId $policyId -categoryId $categoryId
        
        }

        # Adding All settings to settingsDelta ready for JSON export
        Add-Member -InputObject $WEJSON -MemberType 'NoteProperty' -Name 'settingsDelta' -Value @($WESettings)

        ####################################################

        Export-JSONData -JSON $WEJSON -ExportPath " $WEExportPath"

        Write-Information # Clearing up variables so previous data isn't exported in each policy
        Clear-Variable JSON
        Clear-Variable Settings

    }

}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================