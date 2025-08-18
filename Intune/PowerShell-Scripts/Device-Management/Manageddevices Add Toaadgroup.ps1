<#
.SYNOPSIS
    Manageddevices Add Toaadgroup

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
    We Enhanced Manageddevices Add Toaadgroup

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



Function Get-AADDevice(){

<#
.SYNOPSIS
This function is used to get an AAD Device from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets an AAD Device registered with AAD
.EXAMPLE
Get-AADDevice -DeviceID $WEDeviceID
Returns an AAD Device from Azure AD
.NOTES
NAME: Get-AADDevice -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEDeviceID
)


$graphApiVersion = " v1.0"
$WEResource = " devices"
    
    try {

    $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)?`$filter=deviceId eq '$WEDeviceID'"

    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value 

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



Function Add-AADGroupMember(){

<#
.SYNOPSIS
This function is used to add an member to an AAD Group from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a member to an AAD Group registered with AAD
.EXAMPLE
Add-AADGroupMember -GroupId $WEGroupId -AADMemberID $WEAADMemberID
Returns all users registered with Azure AD
.NOTES
NAME: Add-AADGroupMember


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEGroupId,
    $WEAADMemberId
)


$graphApiVersion = " v1.0"
$WEResource = " groups"
    
    try {

    $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource/$WEGroupId/members/`$ref"

$WEJSON = @"

{
    " @odata.id" : " https://graph.microsoft.com/v1.0/directoryObjects/$WEAADMemberId"
}

" @

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



Function Get-ManagedDevices(){

<#
.SYNOPSIS
This function is used to get Intune Managed Devices from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Intune Managed Device
.EXAMPLE
Get-ManagedDevices -ErrorAction Stop
Returns all managed devices but excludes EAS devices registered within the Intune Service
.EXAMPLE
Get-ManagedDevices -IncludeEAS
Returns all managed devices including EAS devices registered within the Intune Service
.NOTES
NAME: Get-ManagedDevices -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [switch]$WEIncludeEAS,
    [switch]$WEExcludeMDM
)


$graphApiVersion = " beta"
$WEResource = " deviceManagement/managedDevices"

try {

    $WECount_Params = 0

    if($WEIncludeEAS.IsPresent){ $WECount_Params++ }
    if($WEExcludeMDM.IsPresent){ $WECount_Params++ }
        
        if($WECount_Params -gt 1){

        write-warning " Multiple parameters set, specify a single parameter -IncludeEAS, -ExcludeMDM or no parameter against the function"
        Write-Information break

        }
        
        elseif($WEIncludeEAS){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource"

        }

        elseif($WEExcludeMDM){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource`?`$filter=managementAgent eq 'eas'"

        }
        
        else {
    
        $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource`?`$filter=managementAgent eq 'mdm' and managementAgent eq 'easmdm'"
        Write-Warning " EAS Devices are excluded by default, please use -IncludeEAS if you want to include those devices"
        Write-Information }

        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
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









$WEAADGroup = Read-Host -Prompt " Enter the Azure AD device group name where devices will be assigned as members" 

$WEGroupId = (get-AADGroup -GroupName " $WEAADGroup" ).id

    if($null -eq $WEGroupId -or $WEGroupId -eq "" ){

    Write-WELog " AAD Group - '$WEAADGroup' doesn't exist, please specify a valid AAD Group..." " INFO" -ForegroundColor Red
    Write-Information exit

    }

    else {

    $WEGroupMembers = Get-AADGroup -GroupName " $WEAADGroup" -Members

    }









$WEFilterName = Read-Host -Prompt " Specify the Azure AD display name search string" 

    if($WEFilterName -eq "" -or $null -eq $WEFilterName){

    Write-Information Write-WELog " A string is required to identify the set of users." " INFO"
    Write-Information break

    }



$count = 0



$countAdded = 0





Write-Information Write-WELog " Checking if any Managed Devices are registered with Intune..." " INFO"
Write-Information $WEDevices = Get-ManagedDevices -ErrorAction Stop

if($WEDevices){

    Write-WELog " Intune Managed Devices found..." " INFO" -ForegroundColor Yellow
    Write-Information foreach($WEDevice in $WEDevices){

    $WEDeviceID = $WEDevice.id
    $WEAAD_DeviceID = $WEDevice.azureActiveDirectoryDeviceId
    $WELSD = $WEDevice.lastSyncDateTime
    $userId = $WEDevice.userPrincipalName

    # Getting User information from AAD to get the users displayName

    $WEUser = Get-AADUser -userPrincipalName $userId

        # Filtering on the display Name to add users device to a specific group

        if(($WEUser.displayName).contains(" $WEFilterName" )){

        Write-WELog " ----------------------------------------------------" " INFO"
        Write-Information Write-Information " Device Name:" $WEDevice.deviceName -f Green
        Write-Information " Management State:" $WEDevice.managementState
        Write-Information " Operating System:" $WEDevice.operatingSystem
        Write-Information " Device Type:" $WEDevice.deviceType
        Write-Information " Last Sync Date Time:" $WEDevice.lastSyncDateTime
        Write-Information " Jail Broken:" $WEDevice.jailBroken
        Write-Information " Compliance State:" $WEDevice.complianceState
        Write-Information " Enrollment Type:" $WEDevice.enrollmentType
        Write-Information " AAD Registered:" $WEDevice.aadRegistered
        Write-WELog " UPN:" " INFO" $WEDevice.userPrincipalName
        Write-Information write-host " User Details:" -f Green
        Write-Information " User Display Name:" $WEUser.displayName

        Write-WELog " Adding user device" " INFO" $WEDevice.deviceName " to AAD Group $WEAADGroup..." -ForegroundColor Yellow

        # Getting Device information from Azure AD Devices

       ;  $WEAAD_Device = Get-AADDevice -DeviceID $WEAAD_DeviceID       

       ;  $WEAAD_Id = $WEAAD_Device.id

            if($WEGroupMembers.id -contains $WEAAD_Id){

            Write-WELog " Device already exists in AAD Group..." " INFO" -ForegroundColor Red

            $countAdded++

            }

            else {

            Write-WELog " Adding Device to AAD Group..." " INFO" -ForegroundColor Yellow

            Add-AADGroupMember -GroupId $WEGroupId -AADMemberId $WEAAD_Id

            $count++

            }

        Write-Information }

    }
    
    Write-WELog " ----------------------------------------------------" " INFO"
    Write-Information Write-WELog " $count devices added to AAD Group '$WEAADGroup' with filter '$filterName'..." " INFO"
    Write-WELog " $countAdded devices already in AAD Group '$WEAADGroup' with filter '$filterName'..." " INFO" -ForegroundColor Yellow
    Write-Information }

else {

Write-Information " No Intune Managed Devices found..." -f green
Write-Information }



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================