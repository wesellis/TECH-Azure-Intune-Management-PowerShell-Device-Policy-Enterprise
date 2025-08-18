<#
.SYNOPSIS
    Application Ios Add Assign

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
    We Enhanced Application Ios Add Assign

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


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
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



Function Get-itunesApplication(){

    <#
    .SYNOPSIS
    This function is used to get an iOS application from the itunes store using the Apple REST API interface
    .DESCRIPTION
    The function connects to the Apple REST API Interface and returns applications from the itunes store
    .EXAMPLE
    Get-itunesApplication -SearchString " Microsoft Corporation"
    Gets an iOS application from itunes store
    .EXAMPLE
    Get-itunesApplication -SearchString " Microsoft Corporation" -Limit 10
    Gets an iOS application from itunes store with a limit of 10 results
    .NOTES
    NAME: Get-itunesApplication
    https://affiliate.itunes.apple.com/resources/documentation/itunes-store-web-service-search-api/
    #>
    
    [cmdletbinding()]
    
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$true)]
        $WESearchString,
        [int]$WELimit
    )
    
        try{
    
        Write-Verbose $WESearchString
    
        # Testing if string contains a space and replacing it with %20
        $WESearchString = $WESearchString.replace(" " ," %20" )
    
        Write-Verbose " SearchString variable converted if there is a space in the name $WESearchString"
    
            if($WELimit){
    
            $iTunesUrl = " https://itunes.apple.com/search?country=us&media=software&entity=software,iPadSoftware&term=$WESearchString&limit=$limit"
            
            }
    
            else {
    
            $iTunesUrl = " https://itunes.apple.com/search?country=us&entity=software&term=$WESearchString&attribute=softwareDeveloper"
    
            }
    
        write-verbose $iTunesUrl
    
        $apps = Invoke-RestMethod -Uri $iTunesUrl -Method Get
    
        # Putting sleep in so that no more than 20 API calls to itunes REST API
        # https://affiliate.itunes.apple.com/resources/documentation/itunes-store-web-service-search-api/
        Start-Sleep 3
    
        return $apps
    
        }
    
        catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-verbose $_.Exception
        write-host
        break
    
        }
    
    }



Function Add-iOSApplication(){
    
    <#
    .SYNOPSIS
    This function is used to add an iOS application using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds an iOS application from the itunes store
    .EXAMPLE
    Add-iOSApplication -AuthHeader $WEAuthHeader
    Adds an iOS application into Intune from itunes store
    .NOTES
    NAME: Add-iOSApplication
    #>
    
    [cmdletbinding()]
    
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        $itunesApp
    )
    
    $graphApiVersion = " Beta"
    $WEResource = " deviceAppManagement/mobileApps"
        
        try {
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            
        $app = $itunesApp
    
        Write-Verbose $app
                
        Write-WELog " Publishing $($app.trackName)" " INFO" -f Yellow
    
        # Step 1 - Downloading the icon for the application
        $iconUrl = $app.artworkUrl60
    
            if ($iconUrl -eq $null){
    
            Write-WELog " 60x60 icon not found, using 100x100 icon" " INFO"
            $iconUrl = $app.artworkUrl100
            
            }
            
            if ($iconUrl -eq $null){
            
            Write-WELog " 60x60 icon not found, using 512x512 icon" " INFO"
            $iconUrl = $app.artworkUrl512
            
            }
    
        $iconResponse = Invoke-WebRequest $iconUrl
        $base64icon = [System.Convert]::ToBase64String($iconResponse.Content)
        $iconType = $iconResponse.Headers[" Content-Type" ]
    
            if(($app.minimumOsVersion.Split(" ." )).Count -gt 2){
    
            $WESplit = $app.minimumOsVersion.Split(" ." )
    
            $WEMOV = $WESplit[0] + " ." + $WESplit[1]
    
            $osVersion = [Convert]::ToDouble($WEMOV)
    
            }
    
            else {
    
            $osVersion = [Convert]::ToDouble($app.minimumOsVersion)
    
            }
    
        # Setting support Operating System Devices
        if($app.supportedDevices -match " iPadMini" ){ $iPad = $true } else { $iPad = $false }
        if($app.supportedDevices -match " iPhone6" ){ $iPhone = $true } else { $iPhone = $false }
    
        # Step 2 - Create the Hashtable Object of the application
       ;  $description = $app.description -replace " [^\x00-\x7F]+" ,""
    
       ;  $graphApp = @{
            " @odata.type" =" #microsoft.graph.iosStoreApp" ;
            displayName=$app.trackName;
            publisher=$app.artistName;
            description=$description;
            largeIcon= @{
                type=$iconType;
                value=$base64icon;
            };
            isFeatured=$false;
            appStoreUrl=$app.trackViewUrl;
            applicableDeviceType=@{
                iPad=$iPad;
                iPhoneAndIPod=$iPhone;
            };
            minimumSupportedOperatingSystem=@{       
                v8_0=$osVersion -lt 9.0;
                v9_0=$osVersion.ToString().StartsWith(9)
                v10_0=$osVersion.ToString().StartsWith(10)
                v11_0=$osVersion.ToString().StartsWith(11)
                v12_0=$osVersion.ToString().StartsWith(12)
                v13_0=$osVersion.ToString().StartsWith(13)
            };
        };
    
        # Step 3 - Publish the application to Graph
        Write-WELog " Creating application via Graph" " INFO"
        $createResult = Invoke-RestMethod -Uri $uri -Method Post -ContentType " application/json" -Body (ConvertTo-Json $graphApp) -Headers $authToken
        Write-WELog " Application created as $uri/$($createResult.id)" " INFO"
        write-host
        
        }
        
        catch {
    
        $ex = $_.Exception
        Write-WELog " Request to $WEUri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)" " INFO" -f Red
    
        $errorResponse = $ex.Response.GetResponseStream()
        
        $ex.Response.GetResponseStream()
    
       ;  $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
       ;  $responseBody = $reader.ReadToEnd();
        Write-WELog " Response content:`n$responseBody" " INFO" -f Red
        Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
        }
    
    }



Function Add-ApplicationAssignment(){

<#
.SYNOPSIS
This function is used to add an application assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a application assignment
.EXAMPLE
Add-ApplicationAssignment -ApplicationId $WEApplicationId -TargetGroupId $WETargetGroupId -InstallIntent $WEInstallIntent
Adds an application assignment in Intune
.NOTES
NAME: Add-ApplicationAssignment


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEApplicationId,
    $WETargetGroupId,
    $WEInstallIntent
)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/mobileApps/$WEApplicationId/assign"
    
    try {

        if(!$WEApplicationId){

        write-host " No Application Id specified, specify a valid Application Id" -f Red
        break

        }

        if(!$WETargetGroupId){

        write-host " No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

        
        if(!$WEInstallIntent){

        write-host " No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment" -f Red
        break

        }

$WEJSON = @"

{
    " mobileAppAssignments" : [
    {
        " @odata.type" : " #microsoft.graph.mobileAppAssignment" ,
        " target" : {
        " @odata.type" : " #microsoft.graph.groupAssignmentTarget" ,
        " groupId" : " $WETargetGroupId"
        },
        " intent" : " $WEInstallIntent"
    }
    ]
}

" @

    $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJSON -ContentType " application/json"

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
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
Get-AADGroup
Returns all users registered with Azure AD
.NOTES
NAME: Get-AADGroup


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
        
        elseif($WEGroupName -eq "" -or $WEGroupName -eq $null){
        
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
                write-host

                $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)/$WEGID/Members"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                }

            }
        
        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

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







Write-Host
Write-Warning " This script adds all your iOS Store Apps as 'available' assignments for the Azure AD group you specify."
Write-Host
$WEAADGroup = Read-Host -Prompt " Enter the Azure AD Group name where applications will be assigned"

$WETargetGroupId = (get-AADGroup -GroupName " $WEAADGroup" ).id

    if($WETargetGroupId -eq $null -or $WETargetGroupId -eq "" ){

    Write-WELog " AAD Group - '$WEAADGroup' doesn't exist, please specify a valid AAD Group..." " INFO" -ForegroundColor Red
    Write-Host
    exit

    }

Write-Host




$culture = " EN-US"


$WEOldCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
$WEOldUICulture = [System.Threading.Thread]::CurrentThread.CurrentUICulture



[System.Threading.Thread]::CurrentThread.CurrentCulture = $culture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture



$itunesApps = Get-itunesApplication -SearchString " Microsoft Corporation" -Limit 50


$WEApplications = 'Microsoft Outlook','Microsoft Excel','OneDrive'



if($WEApplications) {
    
    # Looping through applications list
    foreach($WEApplication in $WEApplications){

    $itunesApp = $itunesApps.results | ? { ($_.trackName).contains(" $WEApplication" ) }

        # if single application count is greater than 1 loop through names
        if($itunesApp.count -gt 1){

        $itunesApp.count
        write-host " More than 1 application was found in the itunes store" -f Cyan

            foreach($iapp in $itunesApp){

            $WECreate_App = Add-iOSApplication -itunesApp $iApp

            $WEApplicationId = $WECreate_App.id

            $WEAssign_App = Add-ApplicationAssignment -ApplicationId $WEApplicationId -TargetGroupId $WETargetGroupId -InstallIntent " available"
            Write-WELog " Assigned '$WEAADGroup' to $($WECreate_App.displayName)/$($create_App.id) with" " INFO" $WEAssign_App.InstallIntent " install Intent"

            Write-Host

            }

        }
        
        # Single application found, adding application
        elseif($itunesApp){

        $WECreate_App = Add-iOSApplication -itunesApp $itunesApp

        $WEApplicationId = $WECreate_App.id

        $WEAssign_App = Add-ApplicationAssignment -ApplicationId $WEApplicationId -TargetGroupId $WETargetGroupId -InstallIntent " available"
        Write-WELog " Assigned '$WEAADGroup' to $($WECreate_App.displayName)/$($create_App.id) with" " INFO" $WEAssign_App.InstallIntent " install Intent"

        Write-Host
    
        }

        # if application isn't found in itunes returning doesn't exist
        else {

        write-host
        write-host " Application '$WEApplication' doesn't exist" -f Red
        write-host

        }

    }

}


else {
    
    # if there are results returned from itunes query
    if($itunesApps.results){

    write-host
    write-host " Number of iOS applications to add:" $itunesApps.results.count -f Yellow
    Write-Host
        
        # Looping through applications returned from itunes
        foreach($itunesApp in $itunesApps.results){

        $WECreate_App = Add-iOSApplication -itunesApp $itunesApp

       ;  $WEApplicationId = $WECreate_App.id

       ;  $WEAssign_App = Add-ApplicationAssignment -ApplicationId $WEApplicationId -TargetGroupId $WETargetGroupId -InstallIntent " available"
        Write-WELog " Assigned '$WEAADGroup' to $($WECreate_App.displayName)/$($create_App.id) with" " INFO" $WEAssign_App.InstallIntent " install Intent"

        Write-Host

        }

    }

    # No applications returned from itunes
    else {

    write-host
    write-host " No applications found..." -f Red
    write-host

    }

}

[System.Threading.Thread]::CurrentThread.CurrentCulture = $WEOldCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $WEOldUICulture



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================