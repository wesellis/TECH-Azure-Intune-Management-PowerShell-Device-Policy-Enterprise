<#
.SYNOPSIS
    Rbac Userstatus

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
    We Enhanced Rbac Userstatus

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
    #>
    
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
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
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
    
    # Using this authentication method requires a clientID.  Register a new app in the Entra ID admin center to obtain a clientID.  More information
    # on app registration and clientID is available here: https://learn.microsoft.com/entra/identity-platform/quickstart-register-app 

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
    
    ####################################################
    
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
    #>
    
    [cmdletbinding()]
    
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        $userPrincipalName,
        $WEProperty
    )
    
    # Defining Variables
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
    
    ####################################################
    
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
    #>
    
    [cmdletbinding()]
    
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        $WEGroupName,
        $id,
        [switch]$WEMembers
    )
    
    # Defining Variables
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
    
    ####################################################
    
    Function Get-RBACRole(){
    
    <#
    .SYNOPSIS
    This function is used to get RBAC Role Definitions from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any RBAC Role Definitions
    .EXAMPLE
    Get-RBACRole -ErrorAction Stop
    Returns any RBAC Role Definitions configured in Intune
    .NOTES
    NAME: Get-RBACRole -ErrorAction Stop
    #>
    
    $graphApiVersion = " Beta"
    $WEResource = " deviceManagement/roleDefinitions"
        
        try {
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
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
    
    ####################################################
    
    Function Get-RBACRoleDefinition(){
    
    <#
    .SYNOPSIS
    This function is used to get an RBAC Role Definition from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any RBAC Role Definition
    .EXAMPLE
    Get-RBACRoleDefinition -id $id
    Returns an RBAC Role Definitions configured in Intune
    .NOTES
    NAME: Get-RBACRoleDefinition -ErrorAction Stop
    #>
    
    [cmdletbinding()]
    
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        $id
    )
    
    $graphApiVersion = " Beta"
    $WEResource = " deviceManagement/roleDefinitions('$id')?`$expand=roleassignments"
        
        try {
    
            if(!$id){
    
            Write-Information " No Role ID was passed to the function, provide an ID variable" -f Red
            break
    
            }
        
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).roleAssignments
        
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
    
    ####################################################
    
    Function Get-RBACRoleAssignment(){
    
    <#
    .SYNOPSIS
    This function is used to get an RBAC Role Assignment from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any RBAC Role Assignment
    .EXAMPLE
    Get-RBACRoleAssignment -id $id
    Returns an RBAC Role Assignment configured in Intune
    .NOTES
    NAME: Get-RBACRoleAssignment -ErrorAction Stop
    #>
    
    [cmdletbinding()]
    
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        $id
    )
    
    $graphApiVersion = " Beta"
    $WEResource = " deviceManagement/roleAssignments('$id')?`$expand=microsoft.graph.deviceAndAppManagementRoleAssignment/roleScopeTags"
        
        try {
    
            if(!$id){
    
            Write-Information " No Role Assignment ID was passed to the function, provide an ID variable" -f Red
            break
    
            }
        
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        
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
    
    ####################################################
    
    #region Authentication
    
    Write-Information # Checking if authToken exists before running authentication
    if($global:authToken){
    
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
    
    # Authentication doesn't exist, calling Get-AuthToken -ErrorAction Stop [CmdletBinding()]
function
    
    else {
    
        if($null -eq $WEUser -or $WEUser -eq "" ){
    
        $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
        Write-Information }
    
    # Getting the authorization token
    $script:authToken = Get-AuthToken -User $WEUser
    
    }
    
    #endregion
    
    ####################################################
    
    Write-Information write-host " Please specify the User Principal Name you want to query:" -f Yellow
    $WEUPN = Read-Host
    
        if($null -eq $WEUPN -or $WEUPN -eq "" ){
    
        Write-WELog " Valid UPN not specified, script can't continue..." " INFO" -f Red
        Write-Information break
    
        }
    
    $WEUser = Get-AADUser -userPrincipalName $WEUPN
    
    $WEUserID = $WEUser.id
    $WEUserDN = $WEUser.displayName
    $WEUserPN = $WEUser.userPrincipalName
    
    Write-Information Write-Information " -------------------------------------------------------------------"
    Write-Information Write-Information " Display Name:" $WEUser.displayName
    Write-Information " User ID:" $WEUser.id
    Write-Information " User Principal Name:" $WEUser.userPrincipalName
    Write-Information ####################################################
    
    $WEMemberOf = Get-AADUser -userPrincipalName $WEUPN -Property MemberOf
    
    $WEDirectoryRole = $WEMemberOf | ? { $_.'@odata.type' -eq " #microsoft.graph.directoryRole" }
    
        if($WEDirectoryRole){
    
        $WEDirRole = $WEDirectoryRole.displayName
    
        Write-Information " Directory Role:" -f Yellow
        $WEDirectoryRole.displayName
        Write-Information }
    
        else {
    
        Write-Information " Directory Role:" -f Yellow
        Write-WELog " User" " INFO"
        Write-Information }
    
    ####################################################
    
    $WEAADGroups = $WEMemberOf | ? { $_.'@odata.type' -eq " #microsoft.graph.group" } | sort displayName
    
        if($WEAADGroups){
    
        Write-Information " AAD Group Membership:" -f Yellow
            
            foreach($WEAADGroup in $WEAADGroups){
            
            $WEGroupDN = (Get-AADGroup -id $WEAADGroup.id).displayName
    
            $WEGroupDN
    
            }
    
        Write-Information }
    
        else {
    
        Write-Information " AAD Group Membership:" -f Yellow
        Write-Information " No Group Membership in AAD Groups"
        Write-Information }
    
    ####################################################
    
    Write-Information " -------------------------------------------------------------------"
    
    # Getting all Intune Roles defined
    $WERBAC_Roles = Get-RBACRole -ErrorAction Stop
    
    $WEUserRoleCount = 0
    
    $WEPermissions = @()
    
    # Looping through all Intune Roles defined
    foreach($WERBAC_Role in $WERBAC_Roles){
    
    $WERBAC_id = $WERBAC_Role.id
    
    $WERoleAssignments = Get-RBACRoleDefinition -id $WERBAC_id
        
        # If an Intune Role has an Assignment check if the user is a member of members group
        if($WERoleAssignments){
    
            $WERoleAssignments | foreach {
    
            $WERBAC_Role_Assignments = $_.id
    
            $WEAssignment = Get-RBACRoleAssignment -id $WERBAC_Role_Assignments
    
            $WERA_Names = @()
    
            $WEMembers = $WEAssignment.members
            $WEScopeMembers = $WEAssignment.scopeMembers
            $WEScopeTags = $WEAssignment.roleScopeTags
    
                $WEMembers | foreach {
    
                    if($WEAADGroups.id -contains $_){
    
                    $WERA_Names = $WERA_Names + (Get-AADGroup -id $_).displayName
    
                    }
    
                }
    
                if($WERA_Names){
    
                $WEUserRoleCount++
    
                Write-Information Write-Information " RBAC Role Assigned: " $WERBAC_Role.displayName
                $WEPermissions = $WEPermissions + $WERBAC_Role.permissions.actions
                Write-Information Write-Information " Assignment Display Name:" $WEAssignment.displayName
                Write-Information Write-WELog " Assignment - Members:" " INFO" -f Yellow 
                $WERA_Names
    
                Write-Information Write-WELog " Assignment - Scope (Groups):" " INFO" -f Yellow
                
                    if($WEAssignment.scopeType -eq " resourceScope" ){
                    
                        $WEScopeMembers | foreach {
    
                        (Get-AADGroup -id $_).displayName
    
                        }
    
                    }
    
                    else {
    
                        Write-Information ($WEAssignment.ScopeType -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim()
    
                    }
    
                Write-Information Write-WELog " Assignment - Scope Tags:" " INFO" -f Yellow
                    
                    if($WEScopeTags){
    
                        $WEAllScopeTags = $WEAllScopeTags + $WEScopeTags 
    
                        $WEScopeTags | foreach {
    
                            $_.displayName
    
                        }
    
                    }
    
                    else {
    
                        Write-WELog " No Scope Tag Assigned to the Role Assignment..." " INFO" -f Red
    
                    }
    
                Write-Information Write-WELog " Assignment - Permissions:" " INFO" -f Yellow
                
                $WERolePermissions = $WERBAC_Role.permissions.actions | foreach { $_.replace(" Microsoft.Intune_" ,"" ) }
                
                $WERolePermissions | sort
    
               ;  $WEScopeTagPermissions = $WEScopeTagPermissions + $WERolePermissions | foreach { $_.split(" _" )[0] } | select -Unique | sort
    
                Write-Information Write-Information " -------------------------------------------------------------------"
    
                }
    
            }
    
        }
    
    }
    
    ####################################################
    
    if($WEPermissions){
    
    Write-Information Write-Information " Effective Permissions for user:"
    
   ;  $WEPermissions = $WEPermissions | foreach { $_.replace(" Microsoft.Intune_" ,"" ) }
    
    $WEPermissions | select -Unique | sort
    
    }
    
    else {
    
    Write-Information Write-Information " User isn't part of any Intune Roles..."
    
    }
    
    Write-Information ####################################################
    



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================