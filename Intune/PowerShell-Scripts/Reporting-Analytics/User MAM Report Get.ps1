<#
.SYNOPSIS
    User Mam Report Get

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
    We Enhanced User Mam Report Get

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



Function Get-AADUser(){

<#
.SYNOPSIS
This function is used to get AAD Users from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any users registered with AAD
.EXAMPLE
Get-AADUser -ErrorAction Stop
Returns all users registered with Azure AD
.EXAMPLE
Get-AADUser -userPrincipleName user@domain.com
Returns specific user by UserPrincipalName registered with Azure AD
.NOTES
NAME: Get-AADUser -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $userPrincipalName,
    $WEProperty
)


$graphApiVersion = " v1.0"
$WEUser_resource = " users"
    
    try {
        
        if($userPrincipalName -eq "" -or $null -eq $userPrincipalName){
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEUser_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        
        }

        else {
            
            if($WEProperty -eq "" -or $null -eq $WEProperty){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEUser_resource)/$userPrincipalName"
            Write-Verbose $uri
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

            }

            else {

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEUser_resource)/$userPrincipalName/$WEProperty"
            Write-Verbose $uri
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

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



Function Get-ManagedAppPolicy(){

<#
.SYNOPSIS
This function is used to get managed app policies (AppConfig) from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any managed app policies
.EXAMPLE
Get-ManagedAppPolicy -ErrorAction Stop
Returns any managed app policies configured in Intune
.NOTES
NAME: Get-ManagedAppPolicy -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/managedAppPolicies"

    try {

    
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains(" ManagedAppProtection" ) -or ($_.'@odata.type').contains(" InformationProtectionPolicy" ) }
    
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



Function Get-ManagedAppProtection(){

<#
.SYNOPSIS
This function is used to get managed app protection configuration from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any managed app protection policy
.EXAMPLE
Get-ManagedAppProtection -id $id -OS " Android"
Returns a managed app protection policy for Android configured in Intune
Get-ManagedAppProtection -id $id -OS " iOS"
Returns a managed app protection policy for iOS configured in Intune
Get-ManagedAppProtection -id $id -OS " WIP_WE"
Returns a managed app protection policy for Windows 10 without enrollment configured in Intune
.NOTES
NAME: Get-ManagedAppProtection -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $id,
    $WEOS    
)

$graphApiVersion = " Beta"

    try {
    
        if($id -eq "" -or $null -eq $id){
    
        Write-Information " No Managed App Policy id specified, please provide a policy id..." -f Red
        break
    
        }
    
        else {
    
            if($WEOS -eq "" -or $null -eq $WEOS){
    
            Write-Information " No OS parameter specified, please provide an OS. Supported values are Android,iOS, and Windows..." -f Red
            Write-Information break
    
            }
    
            elseif($WEOS -eq " Android" ){
    
            $WEResource = " deviceAppManagement/androidManagedAppProtections('$id')/?`$expand=deploymentSummary,apps,assignments"
    
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
            }
    
            elseif($WEOS -eq " iOS" ){
    
            $WEResource = " deviceAppManagement/iosManagedAppProtections('$id')/?`$expand=deploymentSummary,apps,assignments"
    
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
            }

            elseif($WEOS -eq " Windows" ){
    
            $WEResource = " deviceAppManagement/windowsInformationProtectionPolicies('$id')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
    
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
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



Function Get-ApplicationAssignment(){

<#
.SYNOPSIS
This function is used to get an application assignment from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets an application assignment
.EXAMPLE
Get-ApplicationAssignment -ErrorAction Stop
Returns an Application Assignment configured in Intune
.NOTES
NAME: Get-ApplicationAssignment -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEApplicationId
)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/mobileApps/$WEApplicationId/assignments"

    try {

        if(!$WEApplicationId){

        Write-Information " No Application Id specified, specify a valid Application Id" -f Red
        break

        }

        else {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

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



Function Get-MobileAppConfigurations(){
    
<#
.SYNOPSIS
This function is used to get all Mobile App Configuration Policies (managed device) using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all Mobile App Configuration Policies from the itunes store
.EXAMPLE
Get-MobileAppConfigurations -ErrorAction Stop
Gets all Mobile App Configuration Policies configured in the Intune Service
.NOTES
NAME: Get-MobileAppConfigurations -ErrorAction Stop


[cmdletbinding()]
    
$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/mobileAppConfigurations?`$expand=assignments"
        
    try {

    $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"

    (Invoke-RestMethod -Uri $uri -Method Get -Headers $authToken).value


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



Function Get-TargetedManagedAppConfigurations(){
    
<#
.SYNOPSIS
This function is used to get all Targeted Managed App Configuration Policies using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all Targeted Managed App Configuration Policies from the itunes store
.EXAMPLE
Get-TargetedManagedAppConfigurations -ErrorAction Stop
Gets all Targeted Managed App Configuration Policies configured in the Intune Service
.NOTES
NAME: Get-TargetedManagedAppConfigurations -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$false)]
    $WEPolicyId
)
    
$graphApiVersion = " Beta"
        
    try {

        if($WEPolicyId){

            $WEResource = " deviceAppManagement/targetedManagedAppConfigurations('$WEPolicyId')?`$expand=apps,assignments"
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            (Invoke-RestMethod -Uri $uri -Method Get -Headers $authToken)

        }

        else {

            $WEResource = " deviceAppManagement/targetedManagedAppConfigurations"
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            (Invoke-RestMethod -Uri $uri -Method Get -Headers $authToken).value

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



Function Get-IntuneApplication(){

<#
.SYNOPSIS
This function is used to get applications from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any applications added
.EXAMPLE
Get-IntuneApplication -ErrorAction Stop
Returns any applications configured in Intune
.NOTES
NAME: Get-IntuneApplication -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $id,
    $WEName
)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/mobileApps"

    try {

        if($id){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)/$id"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)

        }
        
        
        elseif($WEName){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains(" $WEName" ) -and (!($_.'@odata.type').Contains(" managed" )) }

        }

        else {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { (!($_.'@odata.type').Contains(" managed" )) }

        }

    }

    catch {

    $ex = $_.Exception
    Write-WELog " Request to $WEUri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)" " INFO" -f Red
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



Function Get-IntuneMAMApplication(){

<#
.SYNOPSIS
This function is used to get MAM applications from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any MAM applications
.EXAMPLE
Get-IntuneMAMApplication -ErrorAction Stop
Returns any MAM applications configured in Intune
.NOTES
NAME: Get-IntuneMAMApplication -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
$packageid,
$bundleid
)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/mobileApps"

    try {

        if($packageid){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { ($_.'@odata.type').Contains(" managed" ) -and ($_.'appAvailability' -eq " Global" ) -and ($_.'packageid' -eq " $packageid" ) }

        }

        elseif($bundleid){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { ($_.'@odata.type').Contains(" managed" ) -and ($_.'appAvailability' -eq " Global" ) -and ($_.'bundleid' -eq " $bundleid" ) }

        }

        else {

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { ($_.'@odata.type').Contains(" managed" ) -and ($_.'appAvailability' -eq " Global" ) }

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





Write-Information if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $WEDateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes

        if($WETokenExpires -le 0){

        Write-Information " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
        Write-Information # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

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





Write-Information " This script outputs the Intune app protection policies and application configuration policies assigned to a user."
Write-Information Write-Warning " This script doesn't support configurations applied to nested group members"

Write-Information write-host " Enter the UPN:" -f Yellow
$WEUPN = Read-Host

if($null -eq $WEUPN -or $WEUPN -eq "" ){

    Write-Information " User Principal Name is Null..."
    Write-WELog " Script can't continue..." " INFO" -ForegroundColor Red
    Write-Information break

}

$WEUser = Get-AADUser -userPrincipalName $WEUPN

if(!$WEUser){ break }

$WEUserID = $WEUser.id

Write-Information Write-Information " -------------------------------------------------------------------"
Write-Information Write-Information " Display Name:" $WEUser.displayName
Write-Information " User Principal Name:" $WEUser.userPrincipalName
Write-Information Write-Information " -------------------------------------------------------------------"
Write-Information $WEOSChoices = " Android" ," iOS"


; 
$WEOSChoicesCount = " 2"

   ;  $menu = @{}

    for ($i=1;$i -le $WEOSChoices.count; $i++) 
    { Write-WELog " $i. $($WEOSChoices[$i-1])" " INFO" 
    $menu.Add($i,($WEOSChoices[$i-1]))}

    Write-Information $ans = Read-Host 'Choose an OS (numerical value)'

    if($ans -eq "" -or $null -eq $ans){

    Write-WELog " OS choice can't be null, please specify a valid OS..." " INFO" -ForegroundColor Red
    Write-Information break

    }

    elseif(($ans -match " ^[\d\.]+$" ) -eq $true){

    $selection = $menu.Item([int]$ans)

        if($selection){

            $WEOS = $WEOSChoices | ? { $_ -eq " $WESelection" }

        }

        else {

            Write-WELog " OS choice selection invalid, please specify a valid OS..." " INFO" -ForegroundColor Red
            Write-Information break

        }

    }

    else {

        Write-WELog " OS choice not an integer, please specify a valid OS..." " INFO" -ForegroundColor Red
        Write-Information break

    }

    Write-Information $WEMemberOf = Get-AADUser -userPrincipalName $WEUPN -Property MemberOf

$WEAADGroups = $WEMemberOf | ? { $_.'@odata.type' -eq " #microsoft.graph.group" }





Write-Information " -------------------------------------------------------------------"
Write-Information Write-WELog " App Protection Policies: $WEOS" " INFO"
Write-Information Write-Information " -------------------------------------------------------------------"
Write-Information $WEManagedAppPolicies = Get-ManagedAppPolicy -ErrorAction Stop | ? {$_.'@odata.type' -like " *$os*" }

if($WEManagedAppPolicies){

$WEAssignmentCount = 0

    foreach($WEManagedAppPolicy in $WEManagedAppPolicies){

        # If Android Managed App Policy
    
        if($WEManagedAppPolicy.'@odata.type' -eq " #microsoft.graph.androidManagedAppProtection" ){

            $WEAndroidManagedAppProtection = Get-ManagedAppProtection -id $WEManagedAppPolicy.id -OS " Android"
            
            $WEMAMApps = $WEAndroidManagedAppProtection.apps

            $WEAndroidAssignments = ($WEAndroidManagedAppProtection | select assignments).assignments
    
            if($WEAndroidAssignments){
    
                foreach($WEGroup in $WEAndroidAssignments.target){

                    if($WEAADGroups.id -contains $WEGroup.groupId){

                    $WEAssignmentCount++

                    $WEGroupID = $WEGroup.GroupId
                   ;  $WEGroupTargetType = $WEGroup.'@odata.type'.split(" ." )[-1]

                   ;  $targetedAppManagementLevels = $WEAndroidManagedAppProtection.targetedAppManagementLevels

                        switch ($targetedAppManagementLevels){

                            " unspecified" {$WEManagementType = " All app types" ;break}
                            " mdm" {$WEManagementType = " Apps on managed devices" ;break}
                            " unmanaged" {$WEManagementType = " Apps on unmanaged devices" ;break}

                            }

                    Write-Information " Policy name: " -NoNewline
                    Write-Information $WEAndroidManagedAppProtection.displayname -ForegroundColor Green
                    Write-Information " Group assigned: " -NoNewline
                    Write-Information (get-aadgroup -id $WEGroupID).displayname

                    if($WEGroupTargetType -eq " exclusionGroupAssignmentTarget" ){
                    
                        Write-WELog " Group Target: " " INFO" -NoNewline
                        Write-WELog " Excluded" " INFO" -ForegroundColor Red
                    
                    }

                    elseif($WEGroupTargetType -eq " GroupAssignmentTarget" ){
                    
                        Write-WELog " Group Target: " " INFO" -NoNewline
                        Write-WELog " Included" " INFO" -ForegroundColor Green
                    
                    }

                    Write-Information Write-WELog " Targeted Apps:" " INFO"

                    foreach($WEMAMApp in $WEMAMApps){

                        $WEAppName = (Get-IntuneMAMApplication -packageId $WEMAMApp.mobileAppIdentifier.packageId).displayName

                        if($WEAppName){ $WEAppName }
                        else { $WEMAMApp.mobileAppIdentifier.packageId }

                    }

                    Write-Information Write-WELog " Configuration Settings:" " INFO"
                    Write-WELog " Targeted management type: $WEManagementType" " INFO"
                    Write-WELog " Jailbroken/rooted devices blocked: $($WEAndroidManagedAppProtection.deviceComplianceRequired)" " INFO"
                    Write-WELog " Min OS version: $($WEAndroidManagedAppProtection.minimumRequiredOsVersion)" " INFO"
                    Write-WELog " Min patch version: $($WEAndroidManagedAppProtection.minimumRequiredPatchVersion)" " INFO"
                    Write-WELog " Allowed device manufacturer(s): $($WEAndroidManagedAppProtection.allowedAndroidDeviceManufacturers)" " INFO"
                    Write-Information " Require managed browser: $($WEAndroidManagedAppProtection.managedBrowserToOpenLinksRequired)"
                    Write-WELog " Contact sync blocked: $($WEAndroidManagedAppProtection.contactSyncBlocked)" " INFO"
                    Write-WELog " Printing blocked: $($WEAndroidManagedAppProtection.printblocked)" " INFO"
                    Write-Information Write-Information " -------------------------------------------------------------------"
                    Write-Information }
                
                }

            }
            
        }     

        # If iOS Managed App Policy
    
        elseif($WEManagedAppPolicy.'@odata.type' -eq " #microsoft.graph.iosManagedAppProtection" ){
    
            $iOSManagedAppProtection = Get-ManagedAppProtection -id $WEManagedAppPolicy.id -OS " iOS"

            $WEMAMApps = $iOSManagedAppProtection.apps
    
            $iOSAssignments = ($iOSManagedAppProtection | select assignments).assignments
    
            if($iOSAssignments){
    
                foreach($WEGroup in $iOSAssignments.target){
    
                    if($WEAADGroups.id -contains $WEGroup.groupId){

                    $WEAssignmentCount++

                    $WEGroupID = $WEGroup.GroupId
                   ;  $WEGroupTargetType = $WEGroup.'@odata.type'.split(" ." )[-1]

                   ;  $targetedAppManagementLevels = $iOSManagedAppProtection.targetedAppManagementLevels

                        switch ($targetedAppManagementLevels){

                            " unspecified" {$WEManagementType = " All app types" ;break}
                            " mdm" {$WEManagementType = " Apps on managed devices" ;break}
                            " unmanaged" {$WEManagementType = " Apps on unmanaged devices" ;break}

                            }

                    Write-Information " Policy name: " -NoNewline
                    Write-Information $iOSManagedAppProtection.displayname -ForegroundColor Green
                    Write-Information " Group assigned: " -NoNewline
                    Write-Information (get-aadgroup -id $WEGroupID).displayname

                    if($WEGroupTargetType -eq " exclusionGroupAssignmentTarget" ){
                    
                        Write-WELog " Group Target: " " INFO" -NoNewline
                        Write-WELog " Excluded" " INFO" -ForegroundColor Red
                    
                    }

                    elseif($WEGroupTargetType -eq " GroupAssignmentTarget" ){
                    
                        Write-WELog " Group Target: " " INFO" -NoNewline
                        Write-WELog " Included" " INFO" -ForegroundColor Green
                    
                    }

                    Write-Information Write-WELog " Targeted Apps:" " INFO"

                    foreach($WEMAMApp in $WEMAMApps){

                        $WEAppName = (Get-IntuneMAMApplication -bundleid $WEMAMApp.mobileAppIdentifier.bundleId).displayName

                        if($WEAppName){ $WEAppName }
                        else { $WEMAMApp.mobileAppIdentifier.bundleId }

                    }

                    Write-Information Write-WELog " Configuration Settings:" " INFO"
                    Write-WELog " Targeted management type: $WEManagementType" " INFO"
                    Write-WELog " Jailbroken/rooted devices blocked: $($iOSManagedAppProtection.deviceComplianceRequired)" " INFO"
                    Write-WELog " Min OS version: $($iOSManagedAppProtection.minimumRequiredOsVersion)" " INFO"
                    Write-WELog " Allowed device model(s): $($iOSManagedAppProtection.allowedIosDeviceModels)" " INFO"
                    Write-Information " Require managed browser: $($iOSManagedAppProtection.managedBrowserToOpenLinksRequired)"
                    Write-WELog " Contact sync blocked: $($iOSManagedAppProtection.contactSyncBlocked)" " INFO"
                    Write-WELog " FaceId blocked: $($iOSManagedAppProtection.faceIdBlocked)" " INFO"
                    Write-WELog " Printing blocked: $($iOSManagedAppProtection.printblocked)" " INFO"
                    Write-Information Write-Information " -------------------------------------------------------------------"
                    Write-Information }

                }

            }
    
        }

    }

    if($WEAssignmentCount -eq 0){

        Write-WELog " No $WEOS App Protection Policies Assigned..." " INFO"
        Write-Information Write-Information " -------------------------------------------------------------------"
        Write-Information }

}

else {

    Write-WELog " No $WEOS App Protection Policies Exist..." " INFO"
    Write-Information Write-Information " -------------------------------------------------------------------"
    Write-Information }







Write-WELog " App Configuration Policies: Managed Apps" " INFO" -ForegroundColor Cyan
Write-Information Write-Information " -------------------------------------------------------------------"
Write-Information $WETargetedManagedAppConfigurations = Get-TargetedManagedAppConfigurations -ErrorAction Stop

$WETMACAssignmentCount = 0

if($WETargetedManagedAppConfigurations){

$WETMACCount = @($WETargetedManagedAppConfigurations).count

    foreach($WETargetedManagedAppConfiguration in $WETargetedManagedAppConfigurations){

    $WEPolicyId = $WETargetedManagedAppConfiguration.id

    $WEManagedAppConfiguration = Get-TargetedManagedAppConfigurations -PolicyId $WEPolicyId

    $WEMAMApps = $WEManagedAppConfiguration.apps

        if($WEManagedAppConfiguration.assignments){

            foreach($group in $WEManagedAppConfiguration.assignments){

                if($WEAADGroups.id -contains $WEGroup.target.GroupId){

                $WETMACAssignmentCount++

                $WEGroupID = $WEGroup.target.GroupId
                $WEGroupTargetType = $WEGroup.target.'@odata.type'.split(" ." )[-1]

                Write-Information " Policy name: " -NoNewline
                Write-Information $WEManagedAppConfiguration.displayname -ForegroundColor Green
                Write-Information " Group assigned: " -NoNewline
                Write-Information (get-aadgroup -id $WEGroupID).displayname

                if($WEGroupTargetType -eq " exclusionGroupAssignmentTarget" ){
                    
                    Write-WELog " Group Target: " " INFO" -NoNewline
                    Write-WELog " Excluded" " INFO" -ForegroundColor Red
                    
                }

                elseif($WEGroupTargetType -eq " GroupAssignmentTarget" ){
                    
                    Write-WELog " Group Target: " " INFO" -NoNewline
                    Write-WELog " Included" " INFO" -ForegroundColor Green
                    
                }

                Write-Information Write-WELog " Targeted Apps:" " INFO"

                foreach($WEMAMApp in $WEMAMApps){

                    if($WEMAMApp.mobileAppIdentifier.'@odata.type' -eq " #microsoft.graph.androidMobileAppIdentifier" ){
                    
                        $WEAppName = (Get-IntuneMAMApplication -packageId $WEMAMApp.mobileAppIdentifier.packageId)
                        
                        if($WEAppName.'@odata.type' -like " *$WEOS*" ){

                            Write-Information $WEAppName.displayName " -" $WEAppName.'@odata.type' -ForegroundColor Green
                        
                        }
                        
                        else {
                        
                            Write-Information $WEAppName.displayName " -" $WEAppName.'@odata.type'
                        
                        }

                    }
                    
                    elseif($WEMAMApp.mobileAppIdentifier.'@odata.type' -eq " #microsoft.graph.iosMobileAppIdentifier" ){
                    
                        $WEAppName = (Get-IntuneMAMApplication -bundleId $WEMAMApp.mobileAppIdentifier.bundleId)
                        
                        if($WEAppName.'@odata.type' -like " *$WEOS*" ){

                            Write-Information $WEAppName.displayName " -" $WEAppName.'@odata.type' -ForegroundColor Green
                        
                        }
                        
                        else {
                        
                            Write-Information $WEAppName.displayName " -" $WEAppName.'@odata.type'
                        
                        }
                    
                    }

                }

                Write-Information Write-WELog " Configuration Settings:" " INFO"

                $WEExcludeGroup = $WEGroup.target.'@odata.type'
                
                $WEAppConfigNames = $WEManagedAppConfiguration.customsettings

                    foreach($WEConfig in $WEAppConfigNames){

                        $searchName = $config.name

                        if ($WEConfig.name -like " *.*" ) {
                            
                        $WEName = ($config.name).split(" ." )[-1]
                        

                        }

                        elseif ($WEConfig.name -like " *_*" ){
                            
                        $_appConfigName = ($config.name).replace(" _" ," " )
                        $WEName = (Get-Culture).TextInfo.ToTitleCase($_appConfigName.tolower())

                        }

                        else {
                            
                        $WEName = $config.name
                                                       
                        }

                        $WEValue = ($WETargetedManagedAppConfiguration.customSettings | ? { $_.Name -eq " $searchName" } | select value).value

                        if ($name -like " *ListURLs*" ){
                                
                            $value = $WEValue.replace(" |" ," , " )

                            Write-Information Write-WELog " $($WEName):" " INFO"
                            Write-Information $($WEValue)
                                
                        }

                        else {
                                
                        Write-WELog " $($WEName): $($WEValue)" " INFO"
                                
                        }

                    }

                Write-Information Write-Information " -------------------------------------------------------------------"
                Write-Information }   

            }

        }

    }

    if($WETMACAssignmentCount -eq 0){

        Write-WELog " No $WEOS App Configuration Policies: Managed Apps Assigned..." " INFO"
        Write-Information Write-Information " -------------------------------------------------------------------"
        Write-Information }

}

else {

    Write-WELog " No $WEOS App Configuration Policies: Managed Apps Exist..." " INFO"
    Write-Information Write-Information " -------------------------------------------------------------------"
    Write-Information }







Write-WELog " App Configuration Policies: Managed Devices" " INFO" -ForegroundColor Cyan
Write-Information Write-Information " -------------------------------------------------------------------"
Write-Information $WEAppConfigurations = Get-MobileAppConfigurations -ErrorAction Stop | ? { $_.'@odata.type' -like " *$WEOS*" }

$WEMACAssignmentCount = 0

if($WEAppConfigurations){

    foreach($WEAppConfiguration in $WEAppConfigurations){

        if($WEAppConfiguration.assignments){

            foreach($group in $WEAppConfiguration.assignments){

                if($WEAADGroups.id -contains $WEGroup.target.GroupId){

                $WEMACAssignmentCount++

                $WEGroupID = $WEGroup.target.GroupId
                $WEGroupTargetType = $WEGroup.target.'@odata.type'.split(" ." )[-1]

                Write-Information " Policy name: " -NoNewline
                Write-Information $WEAppConfiguration.displayname -ForegroundColor Green
                Write-Information " Group assigned: " -NoNewline
                Write-Information (get-aadgroup -id $WEGroupID).displayname

                if($WEGroupTargetType -eq " exclusionGroupAssignmentTarget" ){
                    
                    Write-WELog " Group Target: " " INFO" -NoNewline
                    Write-WELog " Excluded" " INFO" -ForegroundColor Red
                    
                }

                elseif($WEGroupTargetType -eq " GroupAssignmentTarget" ){
                    
                    Write-WELog " Group Target: " " INFO" -NoNewline
                    Write-WELog " Included" " INFO" -ForegroundColor Green
                    
                }

                $WETargetedApp = Get-IntuneApplication -id $WEAppConfiguration.targetedMobileApps
                Write-Information Write-WELog " Targeted Mobile App:" " INFO"
                Write-Information $WETargetedApp.displayName " -" $WETargetedApp.'@odata.type'
                Write-Information Write-WELog " Configuration Settings:" " INFO"

                $WEExcludeGroup = $WEGroup.target.'@odata.type'

                $WEType = ($WEAppConfiguration.'@odata.type'.split(" ." )[2] -creplace '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim()

                if($WEAppConfiguration.settings){

                    $WEAppConfigNames = $WEAppConfiguration.settings

                    foreach($WEConfig in $WEAppConfigNames){

                        if ($WEConfig.appConfigKey -like " *.*" ) {
                            
                            if($config.appConfigKey -like " *userChangeAllowed*" ){
                        
                            $appConfigKey = ($config.appConfigKey).split(" ." )[-2,-1]
                            $appConfigKey = $($appConfigKey)[-2] + " - " + $($appConfigKey)[-1]
                            
                            }

                            else {
                        
                            $appConfigKey = ($config.appConfigKey).split(" ." )[-1]
                        
                            }

                        }

                        elseif ($WEConfig.appConfigKey -like " *_*" ){
                            
                        $appConfigKey = ($config.appConfigKey).replace(" _" ," " )

                        }
 
                        else {
                        
                        $appConfigKey = ($config.appConfigKey)
                        
                        }

                        Write-WELog " $($appConfigKey): $($config.appConfigKeyValue)" " INFO"

                    }

                }

                elseif($WEAppConfiguration.payloadJson){

                    $WEJSON = $WEAppConfiguration.payloadJson

                    $WEConfigs = ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(" $WEJSON" )) | ConvertFrom-Json | select managedproperty).managedproperty

                    foreach($WEConfig in $WEConfigs){

                        if ($WEConfig.key -like " *.*" ) {
                            
                        $appConfigKey = ($config.key).split(" ." )[-1]
                            
                        }

                        elseif ($WEConfig.key -like " *_*" ){
                            
                       ;  $_appConfigKey = ($config.key).replace(" _" ," " )
                       ;  $appConfigKey = (Get-Culture).TextInfo.ToTitleCase($_appConfigKey.tolower())

                        }

                        Write-WELog " $($appConfigKey): $($WEConfig.valueString)$($WEConfig.valueBool)" " INFO"

                    }

                }

                Write-Information Write-Information " -------------------------------------------------------------------"
                Write-Information }

            }            
     
       }

    }

    if($WEMACAssignmentCount -eq 0){

        Write-WELog " No $WEOS App Configuration Policies: Managed Devices Assigned..." " INFO"
        Write-Information Write-Information " -------------------------------------------------------------------"
        Write-Information }

}

else {

    Write-WELog " No $WEOS App Configuration Policies: Managed Devices Exist..." " INFO" 
    Write-Information }





Write-WELog " Evaluation complete..." " INFO" -ForegroundColor Green
Write-Information Write-Information " -------------------------------------------------------------------"
Write-Information # Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================