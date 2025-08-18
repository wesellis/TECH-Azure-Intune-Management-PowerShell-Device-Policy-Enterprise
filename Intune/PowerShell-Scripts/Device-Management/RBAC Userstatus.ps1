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
    
    ####################################################
    
    Function Get-AADUser(){
    
    <#
    .SYNOPSIS
    This function is used to get AAD Users from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any users registered with AAD
    .EXAMPLE
    Get-AADUser
    Returns all users registered with Azure AD
    .EXAMPLE
    Get-AADUser -userPrincipleName user@domain.com
    Returns specific user by UserPrincipalName registered with Azure AD
    .NOTES
    NAME: Get-AADUser
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
            
            if($userPrincipalName -eq "" -or $userPrincipalName -eq $null){
            
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEUser_resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
            }
    
            else {
                
                if($WEProperty -eq "" -or $WEProperty -eq $null){
    
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
    
    ####################################################
    
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
    
    ####################################################
    
    Function Get-RBACRole(){
    
    <#
    .SYNOPSIS
    This function is used to get RBAC Role Definitions from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any RBAC Role Definitions
    .EXAMPLE
    Get-RBACRole
    Returns any RBAC Role Definitions configured in Intune
    .NOTES
    NAME: Get-RBACRole
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
    NAME: Get-RBACRoleDefinition
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
    
            write-host " No Role ID was passed to the function, provide an ID variable" -f Red
            break
    
            }
        
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).roleAssignments
        
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
    NAME: Get-RBACRoleAssignment
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
    
            write-host " No Role Assignment ID was passed to the function, provide an ID variable" -f Red
            break
    
            }
        
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        
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
    
    ####################################################
    
    #region Authentication
    
    write-host
    
    # Checking if authToken exists before running authentication
    if($global:authToken){
    
        # Setting DateTime to Universal time to work in all timezones
        $WEDateTime = (Get-Date).ToUniversalTime()
    
        # If the authToken exists checking when it expires
        $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes
    
            if($WETokenExpires -le 0){
    
            write-host " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
            write-host
    
                # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)
    
                if($WEUser -eq $null -or $WEUser -eq "" ){
    
                $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
                Write-Host
    
                }
    
            $global:authToken = Get-AuthToken -User $WEUser
    
            }
    }
    
    # Authentication doesn't exist, calling Get-AuthToken function
    
    else {
    
        if($WEUser -eq $null -or $WEUser -eq "" ){
    
        $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
        Write-Host
    
        }
    
    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $WEUser
    
    }
    
    #endregion
    
    ####################################################
    
    write-host
    write-host " Please specify the User Principal Name you want to query:" -f Yellow
    $WEUPN = Read-Host
    
        if($WEUPN -eq $null -or $WEUPN -eq "" ){
    
        Write-WELog " Valid UPN not specified, script can't continue..." " INFO" -f Red
        Write-Host
        break
    
        }
    
    $WEUser = Get-AADUser -userPrincipalName $WEUPN
    
    $WEUserID = $WEUser.id
    $WEUserDN = $WEUser.displayName
    $WEUserPN = $WEUser.userPrincipalName
    
    Write-Host
    write-host " -------------------------------------------------------------------"
    write-host
    write-host " Display Name:" $WEUser.displayName
    write-host " User ID:" $WEUser.id
    write-host " User Principal Name:" $WEUser.userPrincipalName
    write-host
    
    ####################################################
    
    $WEMemberOf = Get-AADUser -userPrincipalName $WEUPN -Property MemberOf
    
    $WEDirectoryRole = $WEMemberOf | ? { $_.'@odata.type' -eq " #microsoft.graph.directoryRole" }
    
        if($WEDirectoryRole){
    
        $WEDirRole = $WEDirectoryRole.displayName
    
        write-host " Directory Role:" -f Yellow
        $WEDirectoryRole.displayName
        write-host
    
        }
    
        else {
    
        write-host " Directory Role:" -f Yellow
        Write-WELog " User" " INFO"
        write-host
    
        }
    
    ####################################################
    
    $WEAADGroups = $WEMemberOf | ? { $_.'@odata.type' -eq " #microsoft.graph.group" } | sort displayName
    
        if($WEAADGroups){
    
        write-host " AAD Group Membership:" -f Yellow
            
            foreach($WEAADGroup in $WEAADGroups){
            
            $WEGroupDN = (Get-AADGroup -id $WEAADGroup.id).displayName
    
            $WEGroupDN
    
            }
    
        write-host
    
        }
    
        else {
    
        write-host " AAD Group Membership:" -f Yellow
        write-host " No Group Membership in AAD Groups"
        Write-Host
    
        }
    
    ####################################################
    
    write-host " -------------------------------------------------------------------"
    
    # Getting all Intune Roles defined
    $WERBAC_Roles = Get-RBACRole
    
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
    
                Write-Host
                write-host " RBAC Role Assigned: " $WERBAC_Role.displayName -ForegroundColor Cyan
                $WEPermissions = $WEPermissions + $WERBAC_Role.permissions.actions
                Write-Host
    
                write-host " Assignment Display Name:" $WEAssignment.displayName -ForegroundColor Yellow
                Write-Host
    
                Write-WELog " Assignment - Members:" " INFO" -f Yellow 
                $WERA_Names
    
                Write-Host
                Write-WELog " Assignment - Scope (Groups):" " INFO" -f Yellow
                
                    if($WEAssignment.scopeType -eq " resourceScope" ){
                    
                        $WEScopeMembers | foreach {
    
                        (Get-AADGroup -id $_).displayName
    
                        }
    
                    }
    
                    else {
    
                        Write-Host ($WEAssignment.ScopeType -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim()
    
                    }
    
                Write-Host
                Write-WELog " Assignment - Scope Tags:" " INFO" -f Yellow
                    
                    if($WEScopeTags){
    
                        $WEAllScopeTags = $WEAllScopeTags + $WEScopeTags 
    
                        $WEScopeTags | foreach {
    
                            $_.displayName
    
                        }
    
                    }
    
                    else {
    
                        Write-WELog " No Scope Tag Assigned to the Role Assignment..." " INFO" -f Red
    
                    }
    
                Write-Host
                Write-WELog " Assignment - Permissions:" " INFO" -f Yellow
                
                $WERolePermissions = $WERBAC_Role.permissions.actions | foreach { $_.replace(" Microsoft.Intune_" ,"" ) }
                
                $WERolePermissions | sort
    
               ;  $WEScopeTagPermissions = $WEScopeTagPermissions + $WERolePermissions | foreach { $_.split(" _" )[0] } | select -Unique | sort
    
                Write-Host
                write-host " -------------------------------------------------------------------"
    
                }
    
            }
    
        }
    
    }
    
    ####################################################
    
    if($WEPermissions){
    
    Write-Host
    write-host " Effective Permissions for user:" -ForegroundColor Yellow
    
   ;  $WEPermissions = $WEPermissions | foreach { $_.replace(" Microsoft.Intune_" ,"" ) }
    
    $WEPermissions | select -Unique | sort
    
    }
    
    else {
    
    Write-Host
    write-host " User isn't part of any Intune Roles..." -ForegroundColor Yellow
    
    }
    
    Write-Host
    
    
    ####################################################
    



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================