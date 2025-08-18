<#
.SYNOPSIS
    Configure Mdatpintunesecadminrole

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
    We Enhanced Configure Mdatpintunesecadminrole

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
  Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software" ), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED " AS IS" , WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


<#



$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
  Name: Configure-MDATPIntuneSecAdminRole.ps1
  Configures MDATP Intune environment by creating a custom role and assignment with permissions to read security baseline data and machine onboarding data.

.DESCRIPTION
  Configures MDATP Intune environment by creating a custom role and assignment with permissions to read security baseline data and machine onboarding data.
  Populates the role assignment with security groups provided by the SecurityGroupList parameter. 
  Any users or groups added to the new role assignment will inherit the permissions of the role and gain read access to security baseline data and machine onboarding data.
  Use an elevated command prompt (run as local admin) from a machine with access to your Microsoft Defender ATP environment. 
  The script needs to run as local admin to install the Azure AD PowerShell module if not already present.

.PARAMETER AdminUser
  User with global admin privileges in your Intune environment  

.PARAMETER SecAdminGroup
  Security group name - Security group that contains SecAdmin users. Supports only one group. Create a group first if needed. Specify SecAdminGroup param or SecurityGroupList param, but not both.

.PARAMETER SecurityGroupList
  Path to txt file containing list of ObjectIds for security groups to add to Intune role. One ObjectId per line. Specify SecAdminGroup param or SecurityGroupList param, but not both.

.EXAMPLE
  Configure-MDATPIntuneSecAdminRole.ps1 -AdminUser admin@tenant.onmicrosoft.com -SecAdminGroup MySecAdminGroup
  Connects to Azure Active Directory environment myMDATP.mydomain.com, creates a custom role with permission to read security baseline data, and populates it with the specified SecAdmin security group

.EXAMPLE
  Configure-MDATPIntuneSecAdminRole.ps1 -AdminUser admin@tenant.onmicrosoft.com -SecurityGroupList .\SecurityGroupList.txt
  Connects to Azure Active Directory environment myMDATP.mydomain.com, creates a custom role with permission to read security baseline data, and populates it with security groups from SecurityGroupList.txt
  SecurityGroupList txt file must contain list of ObjectIds for security groups to add to Intune role. One ObjectId per line.

.NOTES
  This script uses functions provided by Microsoft Graph team:
  Microsoft Graph API's for Intune: https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview
  Sample PowerShell Scripts: https://github.com/microsoftgraph/powershell-intune-samples
  https://github.com/microsoftgraph/powershell-intune-samples/tree/master/RBAC



[CmdletBinding()]
$ErrorActionPreference = " Stop"

param(
    [Parameter(Mandatory=$true, HelpMessage=" AdminUser@myenvironment.onmicrosoft.com" )]
    $WEAdminUser,

    [Parameter(Mandatory=$false, HelpMessage=" MySecAdminGroup" )]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESecAdminGroup,

    [Parameter(Mandatory=$false, HelpMessage=" c:\mylist.txt" )]
    $WESecurityGroupList

)



if ($WESecurityGroupList){

    $WESecurityGroupList = Get-Content -ErrorAction Stop " $WESecurityGroupList"

}

$WEAADEnvironment = (New-Object -ErrorAction Stop " System.Net.Mail.MailAddress" -ArgumentList $WEAdminUser).Host

$WERBACRoleName    = " MDATP SecAdmin"  
$WESecurityGroup   = " MDATP SecAdmin SG"  
$WEUser = $WEAdminUser



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
          Write-Information Write-WELog " AzureAD Powershell module not installed..." " INFO" -f Red
          Write-WELog " Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" " INFO" -f Yellow
          Write-WELog " Script can't continue..." " INFO" -f Red
          Write-Information exit
      }
  
  # Getting path to ActiveDirectory Assemblies
  # If the module count is greater than 1 find the latest version
  
      if($WEAadModule.count -gt 1){
  
          $WELatest_Version = ($WEAadModule | Select-Object version | Sort-Object)[-1]
  
          $aadModule = $WEAadModule | Where-Object { $_.version -eq $WELatest_Version.version }
  
              # Checking if there are multiple versions of the same module found
  
              if($WEAadModule.count -gt 1){
  
              $aadModule = $WEAadModule | Select-Object -Unique
  
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
  #>
  
  [cmdletbinding()]
  
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

param(
    $WEJSON
)

$graphApiVersion = " Beta"
$WEResource = " deviceManagement/roleDefinitions"

    try {

        if(!$WEJSON){

        Write-WELog " No JSON was passed to the function, provide a JSON variable" " INFO" -f Red
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
  
  [cmdletbinding()]
  
  param(
      $WEName
  )
  
  $graphApiVersion = " v1.0"
  $WEResource = " deviceManagement/roleDefinitions"
  
      try {
  
        if($WEName){
          $WEQueryString = " ?`$filter=contains(displayName, '$WEName')"
          $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)$($WEQueryString)"
          $rbacRoles = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
          $customRbacRoles = $rbacRoles | Where-Object { $_isBuiltInRoleDefinition -eq $false }
          return $customRbacRoles
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

        Write-WELog " No Policy Id specified, specify a valid Application Id" " INFO" -f Red
        break

        }

        if(!$WEDisplayName){

        Write-WELog " No Display Name specified, specify a Display Name" " INFO" -f Red
        break

        }

        if(!$WEMemberGroupId){

        Write-WELog " No Member Group Id specified, specify a valid Target Group Id" " INFO" -f Red
        break

        }

        if(!$WETargetGroupId){

        Write-WELog " No Target Group Id specified, specify a valid Target Group Id" " INFO" -f Red
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
  
        Write-WELog " Authentication Token expired" " INFO" $WETokenExpires " minutes ago" -ForegroundColor Yellow
        Write-Information # Defining User Principal Name if not present
  
            if($null -eq $WEUser -or $WEUser -eq "" ){
  
            $WEUser = Read-Host -Prompt " Please specify your Global Admin user for Azure Authentication (e.g. globaladmin@myenvironment.onmicrosoft.com):"
            Write-Information }
  
        $script:authToken = Get-AuthToken -User $WEUser
  
        }
}
  

  
else {
  
    if($null -eq $WEUser -or $WEUser -eq "" ){
  
    $WEUser = Read-Host -Prompt " Please specify your Global Admin user for Azure Authentication (e.g. globaladmin@myenvironment.onmicrosoft.com):"
    Write-Information }
  

$script:authToken = Get-AuthToken -User $WEUser
  
}
  

  


$WEJSON = @"
{
  " @odata.type" : " #microsoft.graph.roleDefinition" ,
  " displayName" : " $WERBACRoleName" ,
  " description" : " Role with access to modify Intune SecuriyBaselines and DeviceConfigurations" ,
  " permissions" : [
    {
      " actions" : [
        " Microsoft.Intune_Organization_Read" ,
        " Microsoft.Intune/SecurityBaselines/Assign" ,
        " Microsoft.Intune/SecurityBaselines/Create" ,
        " Microsoft.Intune/SecurityBaselines/Delete" ,
        " Microsoft.Intune/SecurityBaselines/Read" ,
        " Microsoft.Intune/SecurityBaselines/Update" ,
        " Microsoft.Intune/DeviceConfigurations/Assign" ,
        " Microsoft.Intune/DeviceConfigurations/Create" ,
        " Microsoft.Intune/DeviceConfigurations/Delete" ,
        " Microsoft.Intune/DeviceConfigurations/Read" ,
        " Microsoft.Intune/DeviceConfigurations/Update"
      ]
    }
  ],
  " isBuiltInRoleDefinition" : false
}
" @
  


Write-WELog " Configuring MDATP Intune SecAdmin Role..." " INFO" -ForegroundColor Cyan
Write-Information Write-WELog " Connecting to Azure AD environment: $WEAADEnvironment..." " INFO"
Write-Information $WERBAC_Roles = Get-RBACRole -ErrorAction Stop


if($WERBAC_Roles | Where-Object { $_.displayName -eq " $WERBACRoleName" }){

    Write-WELog " Intune Role already exists with name '$WERBACRoleName'..." " INFO" -ForegroundColor Red
    Write-WELog " Script can't continue..." " INFO" -ForegroundColor Red
    Write-Information break

}


Write-WELog " Adding new RBAC Role: $WERBACRoleName..." " INFO" -ForegroundColor Yellow
Write-WELog " JSON:" " INFO"
Write-Information $WEJSON
Write-Information $WENewRBACRole = Add-RBACRole -JSON $WEJSON
$WENewRBACRoleID = $WENewRBACRole.id


Write-WELog " Getting Id for new role..." " INFO" -ForegroundColor Yellow
$WEUpdated_RBAC_Roles = Get-RBACRole -ErrorAction Stop

$WENewRBACRoleID = ($WEUpdated_RBAC_Roles | Where-Object {$_.displayName -eq " $WERBACRoleName" }).id

Write-WELog " $WENewRBACRoleID" " INFO"
Write-Information if($WESecAdminGroup){

  # Verify group exists
  Write-WELog " Verifying group '$WESecAdminGroup' exists..." " INFO" -ForegroundColor Yellow

  Connect-AzureAD -AzureEnvironmentName AzureCloud -AccountId $WEAdminUser | Out-Null
  $WEValidatedSecAdminGroup = (Get-AzureADGroup -SearchString $WESecAdminGroup).ObjectId

  if ($WEValidatedSecAdminGroup){

    Write-WELog " AAD Group '$WESecAdminGroup' exists" " INFO" -ForegroundColor Green
    Write-WELog "" " INFO"
    Write-WELog " Adding AAD group $WESecAdminGroup - $WEValidatedSecAdminGroup to MDATP Role..." " INFO" -ForegroundColor Yellow
    
    # Verify security group list only contains valid GUIDs
    try {

      [System.Guid]::Parse($WEValidatedSecAdminGroup) | Out-Null
      Write-WELog " ObjectId: $WEValidatedSecAdminGroup" " INFO" -ForegroundColor Green
      Write-Information }
    
    catch {
    
        Write-WELog " ObjectId: $WEValidatedSecAdminGroup is not a valid ObjectId" " INFO" -ForegroundColor Red
        Write-WELog " Verify that your security group list only contains valid ObjectIds and try again." " INFO" -ForegroundColor Cyan
        exit -1
    
    }

  Write-WELog " Adding security group to RBAC role $WERBACRoleName ..." " INFO" -ForegroundColor Yellow

  Assign-RBACRole -Id $WENewRBACRoleID -DisplayName 'MDATP RBAC Assignment' -MemberGroupId $WEValidatedSecAdminGroup -TargetGroupId " default"
  # NOTE: TargetGroupID = Scope Group

  }
  
  else {

    Write-WELog " Group '$WESecAdminGroup' does not exist. Please run script again and specify a valid group." " INFO" -ForegroundColor Red
    Write-Information break
  
  }

}



if($WESecurityGroupList){

  Write-WELog " Validating Security Groups to add to Intune Role:" " INFO" -ForegroundColor Yellow

  foreach ($WESecurityGroup in $WESecurityGroupList) {
    
    # Verify security group list only contains valid GUIDs
    try {

      [System.Guid]::Parse($WESecurityGroup) | Out-Null
      Write-WELog " ObjectId: $WESecurityGroup" " INFO" -ForegroundColor Green
    
    }
    
    catch {

        Write-WELog " ObjectId: $WESecurityGroup is not a valid ObjectId" " INFO" -ForegroundColor Red
        Write-WELog " Verify that your security group list only contains valid ObjectIds and try again." " INFO" -ForegroundColor Cyan
        exit -1
    
    }

  }

  # Format list for Assign-RBACRole function
 ;  $WEValidatedSecurityGroupList = $WESecurityGroupList -join " `" ,`""

  $WESecurityGroupList
  $WEValidatedSecurityGroupList

  Write-WELog "" " INFO"
  Write-WELog " Adding security groups to RBAC role '$WERBACRoleName'..." " INFO" -ForegroundColor Yellow

  Assign-RBACRole -Id $WENewRBACRoleID -DisplayName 'MDATP RBAC Assignment' -MemberGroupId $WEValidatedSecurityGroupList -TargetGroupId " default"
  # NOTE: TargetGroupID = Scope Group

}



Write-WELog " Retrieving permissions for new role: $WERBACRoleName..." " INFO" -ForegroundColor Yellow
Write-Information ; 
$WERBAC_Role = Get-RBACRole -ErrorAction Stop | Where-Object { $_.displayName -eq " $WERBACRoleName" }

Write-Information $WERBAC_Role.displayName -ForegroundColor Green
Write-Information $WERBAC_Role.id -ForegroundColor Cyan
$WERBAC_Role.RolePermissions.resourceActions.allowedResourceActions
Write-Information Write-WELog " Members of RBAC Role '$WERBACRoleName' should now have access to Security Baseline and" " INFO"
Write-Information " Onboarded machines tiles in Microsoft Defender Security Center."
Write-Information Write-WELog " https://securitycenter.windows.com/configuration-management" " INFO"
Write-Information Write-WELog " Add users and groups to the new role assignment 'MDATP RBAC Assignment' as needed." " INFO"

Write-Information Write-WELog " Configuration of MDATP Intune SecAdmin Role complete..." " INFO"
Write-Information # Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================