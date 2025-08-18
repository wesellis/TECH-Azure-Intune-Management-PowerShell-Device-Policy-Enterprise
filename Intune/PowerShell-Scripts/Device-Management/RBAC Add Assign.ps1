<#
.SYNOPSIS
    Rbac Add Assign

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
    We Enhanced Rbac Add Assign

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



Function Test-JSON(){

<#
.SYNOPSIS
This function is used to test if the JSON passed to a REST Post request is valid
.DESCRIPTION
The function tests if the JSON passed to the REST Post is valid
.EXAMPLE
Test-JSON -JSON $WEJSON
Test if the JSON is valid before calling the Graph REST interface
.NOTES
NAME: Test-JSON




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
$WEJSON

)

    try {

    $WETestJSON = ConvertFrom-Json $WEJSON -ErrorAction Stop
    $validJson = $true

    }

    catch {

    $validJson = $false
    $_.Exception

    }

    if (!$validJson){
    
    Write-WELog " Provided JSON isn't in valid JSON format" " INFO" -f Red
    break

    }

}



Function Get-AADGroup(){

<#
.SYNOPSIS
This function is used to get AAD Groups from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Groups registered with AAD
.EXAMPLE
Get-AADGroup -ErrorAction Stop
Returns all users registered with Azure AD
.NOTES
NAME: Get-AADGroup -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEGroupName,
    $id,
    [switch]$WEMembers
)


$graphApiVersion = " v1.0"
$WEGroup_resource = " groups"
    
    try {

        if($id){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)?`$filter=id eq '$id'"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }
        
        elseif($WEGroupName -eq "" -or $null -eq $WEGroupName){
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        
        }

        else {
            
            if(!$WEMembers){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)?`$filter=displayname eq '$WEGroupName'"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
            }
            
            elseif($WEMembers){
            
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)?`$filter=displayname eq '$WEGroupName'"
            $WEGroup = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
                if($WEGroup){

                $WEGID = $WEGroup.id

                $WEGroup.displayName
                Write-Information $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)/$WEGID/Members"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                }

            }
        
        }

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



Function Add-RBACRole(){

<#
.SYNOPSIS
This function is used to add an RBAC Role Definitions from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an RBAC Role Definitions
.EXAMPLE
Add-RBACRole -JSON $WEJSON
.NOTES
NAME: Add-RBACRole


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEJSON
)

$graphApiVersion = " Beta"
$WEResource = " deviceManagement/roleDefinitions"
    
    try {

        if(!$WEJSON){

        Write-Information " No JSON was passed to the function, provide a JSON variable" -f Red
        break

        }

        Test-JSON -JSON $WEJSON
    
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJson -ContentType " application/json"
    
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



Function Assign-RBACRole(){

<#
.SYNOPSIS
This function is used to set an assignment for an RBAC Role using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and sets and assignment for an RBAC Role
.EXAMPLE
Assign-RBACRole -Id $WEIntuneRoleID -DisplayName " Assignment" -MemberGroupId $WEMemberGroupId -TargetGroupId $WETargetGroupId
Creates and Assigns and Intune Role assignment to an Intune Role in Intune
.NOTES
NAME: Assign-RBACRole


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEId,
    $WEDisplayName,
    $WEMemberGroupId,
    $WETargetGroupId
)

$graphApiVersion = " Beta"
$WEResource = " deviceManagement/roleAssignments"
    
    try {

        if(!$WEId){

        Write-Information " No Policy Id specified, specify a valid Application Id" -f Red
        break

        }

        if(!$WEDisplayName){

        Write-Information " No Display Name specified, specify a Display Name" -f Red
        break

        }

        if(!$WEMemberGroupId){

        Write-Information " No Member Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

        if(!$WETargetGroupId){

        Write-Information " No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }


$WEJSON = @"

    {
    " id" :"" ,
    " description" :"" ,
    " displayName" :" $WEDisplayName" ,
    " members" :[" $WEMemberGroupId" ],
    " scopeMembers" :[" $WETargetGroupId" ],
    " roleDefinition@odata.bind" :" https://graph.microsoft.com/beta/deviceManagement/roleDefinitions('$WEID')"
    }

" @

    $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJSON -ContentType " application/json"
    
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







$WEMemberAADGroup = Read-Host -Prompt " Enter the Azure AD Group name for Intune Role Members"

$WEMemberGroupId = (get-AADGroup -GroupName " $WEMemberAADGroup" ).id

    if($null -eq $WEMemberGroupId -or $WEMemberGroupId -eq "" ){

    Write-WELog " AAD Group - '$WEMemberAADGroup' doesn't exist, please specify a valid AAD Group..." " INFO" -ForegroundColor Red
    Write-Information exit

    }

Write-Information $WEAADGroup = Read-Host -Prompt " Enter the Azure AD Group name for Intune Role Scope"

$WETargetGroupId = (get-AADGroup -GroupName " $WEAADGroup" ).id

    if($null -eq $WETargetGroupId -or $WETargetGroupId -eq "" ){

    Write-WELog " AAD Group - '$WEAADGroup' doesn't exist, please specify a valid AAD Group..." " INFO" -ForegroundColor Red
    Write-Information exit

    }

Write-Information $WEJSON = @"

{
  " @odata.type" : " #microsoft.graph.roleDefinition" ,
  " displayName" : " Graph RBAC Role Assigned" ,
  " description" : " New RBAC Role Description" ,
  " permissions" : [
    {
      " actions" : [
        " Microsoft.Intune/MobileApps/Read" ,
        " Microsoft.Intune/TermsAndConditions/Read" ,
        " Microsoft.Intune/ManagedApps/Read" ,
        " Microsoft.Intune/ManagedDevices/Read" ,
        " Microsoft.Intune/DeviceConfigurations/Read" ,
        " Microsoft.Intune/TelecomExpenses/Read" ,
        " Microsoft.Intune/Organization/Read" ,
        " Microsoft.Intune/RemoteTasks/RebootNow" ,
        " Microsoft.Intune/RemoteTasks/RemoteLock"
      ]
    }
  ],
  " isBuiltInRoleDefinition" : false
}

" @



Write-WELog " Adding Intune Role from JSON..." " INFO" -ForegroundColor Yellow
Write-WELog " Creating Intune Role via Graph" " INFO"
$WECreateResult = Add-RBACRole -JSON $WEJSON
Write-Information " Intune Role created with id" $WECreateResult.id
; 
$WEIntuneRoleID = $WECreateResult.id

Write-Information Write-WELog " Creating Intune Role Assignment..." " INFO"
Write-WELog " Creating Intune Role Assignment via Graph" " INFO"
; 
$WEAssignmentIntuneRole = Assign-RBACRole -Id $WEIntuneRoleID -DisplayName " Assignment" -MemberGroupId $WEMemberGroupId -TargetGroupId $WETargetGroupId
Write-Information " Intune Role Assigment created with id" $WEAssignmentIntuneRole.id

Write-Information # Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================