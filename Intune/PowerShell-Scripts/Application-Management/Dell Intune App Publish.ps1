<#
.SYNOPSIS
    Dell Intune App Publish

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
    We Enhanced Dell Intune App Publish

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


$WEErrorActionPreference = "Stop" ; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

_author_ = Poluka, Muni Sekhar <muni.poluka@dell.com>
_version_ = 1.1


<#
/********************************************************************************

/* DELL PROPRIETARY INFORMATION

*
* This software contains the intellectual property of Dell Inc. Use of this software and the intellectual property
* contained therein is expressly limited to the terms and conditions of the License Agreement under which it is
* provided by or on behalf of Dell Inc. or its subsidiaries.

*

* Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.

*

*  DELL INC. MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF THE SOFTWARE, EITHER
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  DELL SHALL NOT BE LIABLE FOR ANY DAMAGES
* SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS
* DERIVATIVES.

Licensed under the Apache License, Version 2.0 (the " License" );
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an " AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/


<#
.Synopsis
    This script helps Dell Customers to Publish Dell Applications to the respective Intune Tenant.

.Description
     This file when invoked will do the below tasks
        1. show the UI to user to select required application
        2. Download the application that is posted for admin portal production to customer system
        3. Extract the contents and read the CreateAPPConfig.json file
        4. create win32_Lob App in intune
        5. Get APP file version
        6. Upload and commit intunewin file to Azure Storage Blob
        7. Update the file version in the Intune application



[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory = $WEFalse, Position = 0, ValueFromPipeline = $false)] [System.String] $WEClientId,
    [Parameter(Mandatory = $WEFalse, Position = 0, ValueFromPipeline = $false)] [System.String] $WETenantId,
    [Parameter(Mandatory = $WEFalse, Position = 0, ValueFromPipeline = $false)] [System.String] $WEClientSecret,
    [Parameter(Mandatory = $WEFalse, Position = 0, ValueFromPipeline = $false)] [System.String] $WECertThumbprint,
    [Parameter(Mandatory = $WEFalse, Position = 0, ValueFromPipeline = $false)] [System.String] $WEAppName,
    [Parameter(Mandatory = $WEFalse, Position = 0, ValueFromPipeline = $false)] [System.String] $WECabPath,
    [Parameter(Mandatory = $WEFalse, Position = 0, ValueFromPipeline = $false)] [System.String] $proxy,
    [Parameter(Mandatory = $WEFalse, Position = 0, ValueFromPipeline = $false)] [switch] $help,
    [Parameter(Mandatory = $WEFalse, Position = 0, ValueFromPipeline = $false)] [switch] $supportedapps,
    [Parameter(Mandatory = $WEFalse, Position = 0, ValueFromPipeline = $false)] [switch] $logpath
)
; 
$error_code_mapping = @{" Success" = 0; " Invalid_App_Name" = 1; " Invalid_Parameters_passed_to_script" = 2; " File_Download_Failure" = 3; " Content_Extraction_Failure" = 4; " json_file_parsing_failure" = 5; " MSAL_Token_Generation_error" = 6; " Win32_LOB_App_creation_error" = 7; " Win32_file_version_creation_error" = 8; " Win32_Lob_App_Place_holder_ID_creation_error" = 9; " Azure_Storage_URI_creation_error" = 10; " file_chunk_calculating_uploading_error" = 11; " upload_chunks_failure" = 12; " committing_file_upload_error" = 13; " Win32_App_file_version_updation_error" = 14; " Sig_verification_failure" = 15; " Prerequisite_check_failure" = 16; " Admin_Privilege_Required" = 17; " Directory_path_not_Exist" = 18; " dependency_update_failure" = 19; " Certificate_Not_Found" = 20;" SectionName_Not_present" = 21; " Unsupported_File_Extension" = 22; " Hash_Verification_Failure" = 23; " commit_upload_status_fetching_error" = 24}

$WEGlobal:intune_config_file_download_url = " https://dellupdater.dell.com/non_du/ClientService/endpointmgmt/Intune_Config.cab"

function secure_dir_file_creation {
    # The below statements are to define global variables
    $timestamp = Get-Date -Format " yyyy-MM-dd_HH_mm_ss"
    $basedir1 = Join-Path -Path $env:ProgramData -ChildPath " Dell" 
    $basedir2 = Join-Path -Path $env:ProgramData -ChildPath " Dell\Intune_App_Publish_Script"
    $WEGLobal:logdir = Join-Path -Path $env:ProgramData -ChildPath " Dell\Intune_App_Publish_Script\Log" 
    $WEGlobal:downloads_dir = Join-Path -Path $env:ProgramData -ChildPath " Dell\Intune_App_Publish_Script\Downloads"
    
    $dirs_list = @($basedir2, $WEGlobal:logdir, $WEGlobal:downloads_dir)
    if (Test-Path -Path $WEGlobal:logdir) {
            $WEGlobal:log_file_path = Join-Path -Path $WEGlobal:logdir -ChildPath " Intune_App_Publish_log_$timestamp.txt"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Path $WEGlobal:logdir exists and hence not creating and re-applying ACL's"
            
        }   
    if (Test-Path -Path $basedir1) {
        $WEGlobal:log_file_path = Join-Path -Path $WEGlobal:logdir -ChildPath " Intune_App_Publish_log_$timestamp.txt"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Path $basedir1 exists and hence not creating and re-applying ACL's"
    }
    else {
        New-Item -Path $basedir1 -ItemType Directory
        $WEGlobal:log_file_path = Join-Path -Path $WEGlobal:logdir -ChildPath " Intune_App_Publish_log_$timestamp.txt"
    }
    foreach ($dir in $dirs_list) {
        if ((-Not (Test-Path $dir))) {
            New-Item -Path $dir -ItemType Directory
            Set-CustomAcl -Path $dir
        }
        else {
            Set-CustomAcl -Path $dir 
                
        }
    }
    $WEGlobal:log_file_path = Join-Path -Path $WEGLobal:logdir -ChildPath " Intune_App_Publish_log_$timestamp.txt"
    
}


function WE-Set-CustomAcl {
    

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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [string]$WEPath
    )
    # Check if the provided path exists
    if (-Not (Test-Path $WEPath)) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The specified path does not exist: $WEPath"
    }
    # Determine if the path is a directory or a file
    $isDirectory = (Get-Item $WEPath).PSIsContainer
    # Get the parent directory and item name
    $parentDir = (Get-Item $WEPath).PSParentPath -replace 'Microsoft.PowerShell.Core\\FileSystem::', ''
    $itemName = (Get-Item $WEPath).Name
    # Handle symlinks and existing items
    if ((Get-Item $WEPath).Attributes -match " ReparsePoint" ) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Removing Symlink: $WEPath"
        Remove-Item -LiteralPath $WEPath -Force -Recurse -Confirm:$false
        $newPath = Join-Path -Path $parentDir -ChildPath $itemName
        if ($isDirectory) {
            # If it's a directory, recreate the directory
            $null = New-Item -Path $newPath -ItemType Directory -Force
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Recreating directory: $newPath"
        }
        else {
            # If it's a file, recreate the file
            $null = New-Item -Path $newPath -ItemType File -Force
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Recreating file: $newPath"
        }
        $WEPath = $newPath
    } 

    # Get the ACL for the newly created directory or file
    $WEACL = Get-Acl -Path $WEPath 
    # Remove inheritance and strip all existing permissions
    $WEACL.SetAccessRuleProtection($true, $false) # Enable protection but do not preserve inherited rules
    $WEACL.Access | ForEach-Object { $WEACL.RemoveAccessRule($_) } > $null  
    # Add the specified access rules
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        " NT AUTHORITY\SYSTEM" ,
        " FullControl" ,
        " ContainerInherit, ObjectInherit" ,
        " None" ,
        " Allow"
    )
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        " BUILTIN\Administrators" ,
        " FullControl" ,
        " ContainerInherit, ObjectInherit" ,
        " None" ,
        " Allow"
    )
    $WEUserRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        " BUILTIN\Users" ,
        " ReadAndExecute" ,
        " ContainerInherit, ObjectInherit" ,
        " None" ,
        " Allow"
    )
    $WEUserRule1 = New-Object System.Security.AccessControl.FileSystemAccessRule(
        " BUILTIN\Users" ,
        " Write" ,
        " ContainerInherit, ObjectInherit" ,
        " None" ,
        " Allow"
    )

    $WEACL.AddAccessRule($systemRule)
    $WEACL.AddAccessRule($adminRule)
    $WEACL.AddAccessRule($WEUserRule)
    $WEACL.AddAccessRule($WEUserRule1)

    # Apply the modified ACL back to the directory or file
    Set-Acl -Path $WEPath -AclObject $WEACL
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Permissions updated for: $WEPath"
}


function WE-Write-Log {
    
    Add-Content -Path $WEGlobal:log_file_path -Value $WEGlobal:logMessages
}


function verify_admin_privileges {
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] " Administrator" )) {
        Write-Error " You do not have Administrator rights to run this script. Please re-run this script as an Administrator." , $error_code_mapping.Admin_Privilege_Required
        Exit $error_code_mapping.Admin_Privilege_Required
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script is running with admin privileges"
    }
}

function prerequisite_verification {
    # The below check is for checking if MSAL library is installed or not
    if (Get-Module -ListAvailable -Name " MSAL.PS" ) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - MSAL.PS PowerShell module exists"
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - MSAL.PS does not exist on system, please install and try again"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Exeution terminated with return code " , $error_code_mapping.Prerequisite_check_failure
        Write-Log
        Exit $error_code_mapping.Prerequisite_check_failure
    }
}


function hash_verification {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEFilePath,
        [Parameter(Mandatory = $false)] [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESHA512,
        [Parameter(Mandatory = $false)] [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAppConfigSHA512,
        [Parameter(Mandatory = $false)] [string]$intunewinSHA512
    )

    if ($WESHA512) {
        $file_hash = Get-FileHash -Algorithm SHA512 -LiteralPath $WEFilePath
        if ($file_hash.Hash -eq $WESHA512) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The hash values of $WEFilePath match"
        }
    }
    elseif ($WEAppConfigSHA512) {
        $file_hash = Get-FileHash -Algorithm SHA512 -LiteralPath $WEFilePath
        if ($file_hash.Hash -eq $WEAppConfigSHA512) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The hash values of $WEFilePath match"
        }
    }
    elseif ($intunewinSHA512) {
        $file_hash = Get-FileHash -Algorithm SHA512 -LiteralPath $WEFilePath
        if ($file_hash.Hash -eq $intunewinSHA512) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The hash values of $WEFilePath match"
        }
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The hash values of $WEFilePath do not match"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Exeution terminated with return code " , $error_code_mapping.Hash_Verification_Failure
        write-log
        Exit $error_code_mapping.Hash_Verification_Failure
    }
}


function sig_verification {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string]$WEFilePath
    )
    
    $file_extension = [IO.Path]::GetExtension($WEFilePath).ToLower()
    if ($file_extension -eq " .cab" ) {
        $signature = Get-AuthenticodeSignature -FilePath $WEFilePath

        if ($signature.Status -eq " Valid" ) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The digital signature of $WEFilePath is valid."
        }
        else {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Digital Signature check Failed for $WEFilePath"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Exeution terminated with return code " , $error_code_mapping.Sig_verification_failure
            Write-Log
            Exit $error_code_mapping.Sig_verification_failure
        }
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - File extension is not .cab"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Exeution terminated with return code "
    }
}


function input_processing {
    

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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $WEAppName
    )
    # The below code is to download the config json cabinet file
    $download_files_response = download_files -downloadurl $WEGlobal:intune_config_file_download_url -downloadPath $WEGlobal:downloads_dir -proxy $proxy
    $json_downloadPath = $download_files_response.downloadPath
    $json_filename = $download_files_response.filename

    # The below code is to call extract function based on the file type that is downloaded.
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Downloaded file full path from main function is : $json_downloadPath"
    $full_package_path = Join-Path -Path $json_downloadPath -ChildPath $json_filename
    $file_extension = [System.IO.Path]::GetExtension($full_package_path).ToLower()
    if ($file_extension -eq " .cab" ) {
        
        $WEExtract_file_path = Extract_CabinetFile -downloadPath $json_downloadPath -filename $json_filename    
    }
    elseif ($file_extension -eq " .zip" ) {
        
        $WEExtract_file_path = Extract_Archive -downloadPath $json_downloadPath -filename $json_filename
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Unsupported file type $file_extension"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Exeution terminated with return code " , $error_code_mapping.Unsupported_file_type
        Write-Log
        Exit $error_code_mapping.Unsupported_file_type
    }

    # The below code is to read the specific app section from the config json file based on user entred app name
    $intune_config_json_data = read_json_section -json_file_path $WEExtract_file_path -SectionName $WEAppName

    # The below is to pasre and read the version and download URL from the config json file
    $intune_config_json_data = $intune_config_json_data | ConvertFrom-Json
    $WEDependentApp_Version = $null
    $WEDependentAppdownloadurl = $null
    $WEDependentApp_displayname = $null
    $dependentAppSHA512 = $null
    $dependentAppAppConfigJsonSHA512 = $null
    $dependentAppIntunePackageSHA512 = $null
    foreach ($item1 in $intune_config_json_data) {
        $dependencyAppDisplayname = $null
        $dependencyAppversion = $null
        $dependencyAppOperator = $null
        if ($null -eq $WEDependentApp_Version) {
            $WEDependentApp_displayname = $item1.displayname
            $WEDependentApp_Version = $item1.version
            $WEDependentAppdownloadurl = $item1.downloadurl
            $WEDependentAppCryptography = $item1.cryptography
            foreach ($cryptokeys in $WEDependentAppCryptography) {
                $dependentAppSHA512 = $cryptokeys.SHA512
                $dependentAppAppConfigJsonSHA512 = $cryptokeys.appConfigJsonSHA512
                $dependentAppIntunePackageSHA512 = $cryptokeys.intunePackageSHA512             
            }
        }
        elseif ($item1.version -gt $WEDependentApp_Version) {
            $WEDependentApp_displayname = $item1.displayname
            $WEDependentApp_Version = $item1.version
            $WEDependentAppdownloadurl = $item1.downloadurl
            $WEDependentAppCryptography = $item1.cryptography
            foreach ($cryptokeys in $WEDependentAppCryptography) {
                $dependentAppSHA512 = $cryptokeys.SHA512
                $dependentAppAppConfigJsonSHA512 = $cryptokeys.appConfigJsonSHA512
                $dependentAppIntunePackageSHA512 = $cryptokeys.intunePackageSHA512             
            }
        }
        
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Displayname and version from config json file is " , $WEDependentApp_displayname, $WEDependentApp_Version
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Download URL from config json file is " , $WEDependentAppdownloadurl

        if ($item1.dependencyApp) {
            # The below code is to fetch the dependency app name, version, operator from the config json file
            $parsedData = $item1.dependencyApp | ForEach-Object {
                if ($_ -match " @{(.+)}" ) {
                   ;  $obj = @{}
                    $_ -match " @{(.+)}" | Out-Null
                   ;  $pairs = $matches[1] -split " ; "
                    foreach ($pair in $pairs) {
                        $key, $value = $pair -split " ="
                        $obj[$key.Trim()] = $value.Trim()
                    }
                    [PSCustomObject]$obj
                } else {
                    $_
                }
            }
            $dependencyAppDisplayname = $parsedData[0].name
            $dependencyAppversion = $parsedData[0].version
            $dependencyAppOperator = $parsedData[0].operator
        }
    }
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependency App name and version from config json file is " , $dependencyAppDisplayname, $dependencyAppversion
    if ($null -eq $dependencyAppDisplayname) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - No dependency app found in config json file"
    }
    else {
        $final_dependency_App_download_url = $null
        $final_dependencyAppSHA512 = $null
        $final_dependencyAppAppConfigJsonSHA512 = $null
        $final_dependencyAppIntunePackageSHA512 = $null
        # The below code is to read the specific app section from the config json file based on user entred app name
        $WEDependency_App_intune_config_json_data = read_json_section -json_file_path $WEExtract_Cabinet_path -SectionName $dependencyAppDisplayname

        foreach ($item2 in $WEDependency_App_intune_config_json_data) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Displayname and version from dependency app config json file is " , $item2.displayname, $item2.version
            $item2 = $item2 | ConvertFrom-Json
            if ($dependencyAppOperator.ToLower() -eq " equal" ) {
                if ($item2.version -eq $dependencyAppversion) {
                    $final_dependency_App_Version = $item2.version
                    $final_dependency_App_download_url = $item2.downloadurl
                    $WEDependencyAppCryptography = $item1.cryptography
                    foreach ($cryptokeys in $WEDependencyAppCryptography) {
                        $final_dependencyAppSHA512 = $cryptokeys.SHA512
                        $final_dependencyAppAppConfigJsonSHA512 = $cryptokeys.appConfigJsonSHA512
                        $final_dependencyAppIntunePackageSHA512 = $cryptokeys.intunePackageSHA512             
                    }
                }
            }
            elseif ($dependencyAppOperator.ToLower() -eq " greaterthan" ) {
                if ($item2.version -gt $dependencyAppversion) {
                    if ($null -eq $final_dependency_App_Version) {
                        $final_dependency_App_Version = $item2.version
                        $final_dependency_App_download_url = $item2.downloadurl
                        $WEDependencyAppCryptography = $item1.cryptography
                        foreach ($cryptokeys in $WEDependencyAppCryptography) {
                            $final_dependencyAppSHA512 = $cryptokeys.SHA512
                            $final_dependencyAppAppConfigJsonSHA512 = $cryptokeys.appConfigJsonSHA512
                            $final_dependencyAppIntunePackageSHA512 = $cryptokeys.intunePackageSHA512             
                        }
                    }
                    elseif ($item2.version -gt $final_dependency_App_Version) {
                        $final_dependency_App_Version = $item2.version
                        $final_dependency_App_download_url = $item2.downloadurl
                        $WEDependencyAppCryptography = $item1.cryptography
                        foreach ($cryptokeys in $WEDependencyAppCryptography) {
                            $final_dependencyAppSHA512 = $cryptokeys.SHA512
                            $final_dependencyAppAppConfigJsonSHA512 = $cryptokeys.appConfigJsonSHA512
                            $final_dependencyAppIntunePackageSHA512 = $cryptokeys.intunePackageSHA512             
                        }
                    }
                }
            }

            elseif ($dependencyAppOperator.ToLower() -eq " greaterthanequal" ) {
                if ($item2.version -ge $dependencyAppversion) {
                    if ($null -eq $final_dependency_App_Version) {
                        $final_dependency_App_Version = $item2.version
                        $final_dependency_App_download_url = $item2.downloadurl
                        $WEDependencyAppCryptography = $item1.cryptography
                        foreach ($cryptokeys in $WEDependencyAppCryptography) {
                            $final_dependencyAppSHA512 = $cryptokeys.SHA512
                            $final_dependencyAppAppConfigJsonSHA512 = $cryptokeys.appConfigJsonSHA512
                            $final_dependencyAppIntunePackageSHA512 = $cryptokeys.intunePackageSHA512             
                        }
                    }
                    elseif ($item2.version -ge $final_dependency_App_Version) {
                        $final_dependency_App_Version = $item2.version
                        $final_dependency_App_download_url = $item2.downloadurl
                        $WEDependencyAppCryptography = $item1.cryptography
                        foreach ($cryptokeys in $WEDependencyAppCryptography) {
                            $final_dependencyAppSHA512 = $cryptokeys.SHA512
                            $final_dependencyAppAppConfigJsonSHA512 = $cryptokeys.appConfigJsonSHA512
                           ;  $final_dependencyAppIntunePackageSHA512 = $cryptokeys.intunePackageSHA512             
                        }
                    }
                }
            }
        }
    }
   ;  $download_url_responses = @{
        " dependantAppURL"  = $WEDependentAppdownloadurl;
        " dependencyAppURL" = $final_dependency_App_download_url
        " dependentAppSHA512"  = $dependentAppSHA512;
        " dependentAppConfigJsonSHA512" = $dependentAppAppConfigJsonSHA512;
        " dependentAppIntunePackageSHA512" = $dependentAppIntunePackageSHA512;
        " dependencyAppSHA512" = $final_dependencyAppSHA512;
        " dependencyAppAppConfigJsonSHA512" = $final_dependencyAppAppConfigJsonSHA512;
        " dependencyAppIntunePackageSHA512" = $final_dependencyAppIntunePackageSHA512
    }
    return $download_url_responses
    
}


function download_files {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $downloadurl,
        [Parameter(Mandatory = $true)] [string] $downloadPath,
        [Parameter(Mandatory = $false)] [string] $proxy
    )
    try {
        $filename = ($downloadurl -split " /" )[-1]
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Filename from downlod files function is " , $filename
        $downloadPath1 = Join-Path -Path $downloadPath -ChildPath ($filename.Replace(" .cab" , "" ))
        $null=New-item -ItemType Directory -Path $downloadPath1 -Force
        Get-ChildItem -Path $downloadPath1 -Include *.* -File -Recurse | ForEach-Object { $_.Delete() }
       ;  $download_full_path = Join-Path -Path $downloadPath1 -ChildPath $filename
       ;  $userAgent = 'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
        if ($proxy -ne "" ) {
            Invoke-WebRequest -Uri $downloadurl -OutFile $download_full_path -UserAgent $userAgent -Proxy $proxy 
        }
        else {
            $download_status = Invoke-WebRequest -Uri $downloadurl -OutFile $download_full_path -UserAgent $userAgent -PassThru 
        }
        if ($?) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Downloaded the file successfully in location " , $downloadPath
            if ([System.IO.File]::Exists($download_full_path)) {
                sig_verification -FilePath $download_full_path
               
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - File exists in the location " , $download_full_path
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Download path without filename, inside download files function " , $downloadPath1
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Filename inside download files function " , $filename
               ;  $downloaad_files_response = @{
                    " downloadPath" = $downloadPath1;
                    " filename"     = $filename
                }
                return $downloaad_files_response
            }
            else {
                
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - File does not exists in the location " , $download_full_path
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Exeution terminated with return code " , $error_code_mapping.File_Download_Failure
                Write-Log
                Exit $error_code_mapping.File_Download_Failure
            }
        }
        else {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to download the file"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Exeution terminated with return code " , $error_code_mapping.File_Download_Failure
            Write-Log
            Exit $error_code_mapping.File_Download_Failure
        }
    }
    catch {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Exception during file download process " , $_.Exception.Message
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Exeution terminated with return code " , $error_code_mapping.File_Download_Failure
        Write-Log
        Exit $error_code_mapping.File_Download_Failure
    }
}


function WE-Extract_Archive {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $downloadPath,
        [Parameter(Mandatory = $true)] [string] $filename
    )
    $intunewinzipfilePath = Join-Path -Path $downloadPath -ChildPath $filename
    Expand-Archive -LiteralPath $intunewinzipfilePath -DestinationPath $downloadPath -Force
    if ($?) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Extracted the contents successfully in location $downloadPath"
        $intunewinfilepath = Join-Path -Path $downloadPath -ChildPath " IntunePackage.intunewin"
        $WECreateAPPConfigPath = Join-Path -Path $downloadPath -ChildPath " AppConfig.json"
        $intune_config_file = Join-Path -Path $downloadPath -ChildPath " Intune_Config.json"
        if ((Test-Path $intunewinfilepath) -and (Test-Path $WECreateAPPConfigPath)) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Extracted the contents successfully in location $downloadPath"
            return $intunewinfilepath, $WECreateAPPConfigPath
        }
        elseif (Test-Path $intune_config_file) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Extracted the cabinet file contents successfully in location $downloadPath"
            return $intune_config_file
            
        }        
        else {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Extracted the contents successfully in location $downloadPath"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with return code " , $error_code_mapping.Content_Extraction_Failure
            Write-Log
            Exit $error_code_mapping.Content_Extraction_Failure
        }
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to extract the Archive contents"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with return code " , $error_code_mapping.Content_Extraction_Failure
        Write-Log
        Exit $error_code_mapping.Content_Extraction_Failure
    }
}


function WE-Extract_CabinetFile {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $downloadPath,
        [Parameter(Mandatory = $true)] [string] $filename
    )
    
    $intunewincabfilePath = Join-Path -Path $downloadPath -ChildPath $filename
    $cabFile = New-Object -ComObject Shell.Application
    $cabFile.Namespace($downloadPath).CopyHere($cabFile.Namespace($intunewincabfilePath).Items())
    if ($?) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Extracted the cabinet file contents successfully in location $downloadPath"
        $intunewinfilepath = Join-Path -Path $downloadPath -ChildPath " IntunePackage.intunewin"
        $WECreateAPPConfigPath = Join-Path -Path $downloadPath -ChildPath " AppConfig.json"
        $intune_config_file = Join-Path -Path $downloadPath -ChildPath " Intune_Config.json"
        if ((Test-Path $intunewinfilepath) -and (Test-Path $WECreateAPPConfigPath)) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Extracted the cabinet file contents successfully in location $downloadPath"
            return $intunewinfilepath, $WECreateAPPConfigPath
        }
        elseif (Test-Path $intune_config_file) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Extracted the cabinet file contents successfully in location $downloadPath"
            return $intune_config_file
            
        }
        else {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Extraction of cabinet file contents is unsuccessful $downloadPath"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with return code " , $error_code_mapping.Content_Extraction_Failure
            Write-Log
            Exit $error_code_mapping.Content_Extraction_Failure
        }
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to extract the Cabinet file contents"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with return code " , $error_code_mapping.Content_Extraction_Failure
        Write-Log
        Exit $error_code_mapping.Content_Extraction_Failure
    }
}


function read_json_section {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $json_file_path,
        [Parameter(Mandatory = $true)] [string] $WESectionName
    )
    $json_data = Get-Content -Path $json_file_path | ConvertFrom-Json
    if ($?) {
        if (-not $json_data.PSObject.Properties[$sectionName]) {
            Write-Log
            Exit $error_code_mapping.SectionName_Not_present
        }
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Read the CreateAPPConfig.json file successfully"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Display Name that is being read is : $($json_data.$sectionName)"
        $section_data = $json_data.$sectionName | ConvertTo-Json
        return $section_data
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to read the CreateAPPConfig.json file"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution terminated with return code " , $error_code_mapping.json_file_parsing_failure
        Write-Log
        Exit $error_code_mapping.json_file_parsing_failure
    }
}


function generate_access_token_using_Client_Secret {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]; 
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $WEClientId,
        [Parameter(Mandatory = $true)] [string] $WETenantId,
        [Parameter(Mandatory = $true)] [string] $WEClientSecret
    )
    # Create the Connection details
    $WEGlobal:connectionDetails = @{
        'TenantId'     = $WETenantId;
        'ClientId'     = $WEClientId;
        'ClientSecret' = $WEClientSecret | ConvertTo-SecureString -AsPlainText -Force
    }
    try{
        $token = Get-MsalToken @Global:connectionDetails
    }
    catch{
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to generate the Access token"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with return code " , $error_code_mapping.MSAL_Token_Generation_error
        Write-Log
        Exit $error_code_mapping.MSAL_Token_Generation_error
    }
    if ($?) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Generated the Access token successfully"
        $tokenauthorizationheader = $token.CreateAuthorizationHeader()
        return $tokenauthorizationheader
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to generate the Access token"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with return code " , $error_code_mapping.MSAL_Token_Generation_error
        Write-Log
        Exit $error_code_mapping.MSAL_Token_Generation_error
    }  
}


function generate_access_token_using_Client_Cert_Thumbprint {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $WEClientId,
        [Parameter(Mandatory = $true)] [string] $WETenantId,
        [Parameter(Mandatory = $true)] [string] $WECertThumbprint
    )

    $clientCertificate = Get-Item " Cert:\CurrentUser\My\$WECertThumbprint" -ErrorAction SilentlyContinue
    if ($clientCertificate) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Certificate found with thumbprint under current user cert store "

    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Certificate not found with thumbprint under current user cert store "
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with return code " , $error_code_mapping.Certificate_Not_Found
        Write-Log
        Exit $error_code_mapping.Certificate_Not_Found
        
    }
    $token = Get-MsalToken -ClientId $WEClientId -TenantId $WETenantId -ClientCertificate $clientCertificate
    if ($?) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Generated the Access token successfully"
        $tokenauthorizationheader = $token.CreateAuthorizationHeader()
        return $tokenauthorizationheader
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to generate the Access token"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with return code " , $error_code_mapping.MSAL_Token_Generation_error
        Write-Log
        Exit $error_code_mapping.MSAL_Token_Generation_error
    }
    
}


function win32_LobApp_creation {
    
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $tokenauthorizationheader,
        [Parameter(Mandatory = $true)] [string] $createAppConfig_createApp
    )
        $authHeader = @{
            'Authorization' = $tokenauthorizationheader
        }
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - inside win32_LobApp_creation"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Createapp content is:" , $createAppConfig_createApp
        
        $win32LobUrl = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps'
        $win32LobApp = Invoke-RestMethod -Uri $win32LobUrl -Body $createAppConfig_createApp -Headers $authHeader -Method " POST" -ContentType 'application/json'
        if ($?) {
            $win32LobAppId = $win32LobApp.id
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Created the win32_Lob App successfully and the win32LobAppId is " , $win32LobAppId
            return $win32LobAppId

        }
        else {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to create the win32_Lob App"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.Win32_LOB_App_creation_error
            Write-Log
            Exit $error_code_mapping.Win32_LOB_App_creation_error
        }
}


function win32_LobApp_file_version {

    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $tokenauthorizationheader,
        [Parameter(Mandatory = $true)] [string] $win32LobAppId
    )
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Inside win32_LobApp_file_version"
    $authHeader = @{
        'Authorization' = $tokenauthorizationheader
    }
    $WEWin32LobVersionUrl = " https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{0}/microsoft.graph.win32LobApp/contentVersions" -f $win32LobAppId
    $win32LobAppVersionRequest = Invoke-RestMethod -Uri $WEWin32LobVersionUrl -Method " POST" -Body " {}" -Headers $authHeader -ContentType 'application/json'
    if ($?) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - APP file version request successful"
        $win32LobAppVersion = $win32LobAppVersionRequest.id
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - APP file version is" , $win32LobAppVersion
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Got the APP file version successfully"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Got the APP file version successfully"
        return  $win32LobAppVersion
        
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to get the APP file version"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.Win32_file_version_creation_error
        Write-Log
        Exit $error_code_mapping.Win32_file_version_creation_error
    }    
}


function win32LobApp_placeholder {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $tokenauthorizationheader,
        [Parameter(Mandatory = $true)] [string] $createAppConfig_createFile,
        [Parameter(Mandatory = $true)] [string] $win32LobAppId,
        [Parameter(Mandatory = $true)] [string] $win32LobAppVersionId
    )
    $authHeader = @{
        'Authorization' = $tokenauthorizationheader
    }

    $WEWin32LobFileUrl = " https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{0}/microsoft.graph.win32LobApp/contentVersions/{1}/files" -f $win32LobAppId, $win32LobAppVersionId
    
    $WEWin32LobPlaceHolder = Invoke-RestMethod -Uri $WEWin32LobFileUrl -Method " POST" -Body $createAppConfig_createFile -Headers $authHeader -ContentType 'application/json'
    if ($?) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Created the place holder for intune file version successfully"
        $WEWin32LobPlaceHolderId = $WEWin32LobPlaceHolder.id
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Win32placeholderId:" , $WEWin32LobPlaceHolderId
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Created the place holder for intune file version successfully"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - **********************: " , $WEWin32LobPlaceHolder.size
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - **********************: " , $WEWin32LobPlaceHolder.sizeEncrypted
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Created the place holder for intune file version successfully"
        return $WEWin32LobPlaceHolderId
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to create the place holder for intune file version"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.Win32_Lob_App_Place_holder_ID_creation_error
        Write-Log
        Exit $error_code_mapping.Win32_Lob_App_Place_holder_ID_creation_error
    }
}


function  check_win32LobApp_placeholder_status {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $tokenauthorizationheader,
        [Parameter(Mandatory = $true)] [string] $win32LobAppId,
        [Parameter(Mandatory = $true)] [string] $win32LobAppVersionId,
        [parameter(Mandatory = $true)] [string] $WEWin32LobPlaceHolderId
    )
    $authHeader = @{
        'Authorization' = $tokenauthorizationheader
    }
    $azure_upload_state = ""
    while ($azure_upload_state -ne " azureStorageUriRequestSuccess" ) {
        $storageCheckUrl = " https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{0}/microsoft.graph.win32LobApp/contentVersions/{1}/files/{2}" -f $win32LobAppId, $win32LobAppVersionId, $WEWin32LobPlaceHolderId
        $storageCheck = Invoke-RestMethod -Uri $storageCheckUrl -Method " GET" -Headers $authHeader
        if ($?) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Checked the status of the place holder for intune file version successfully"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The status of the place holder for intune file version is " , $storageCheck
            $azure_upload_state = $storageCheck.uploadState
            $azureStorageUri = $storageCheck.azureStorageUri
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The azure storage URI is " , $azureStorageUri
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Checked the status of the place holder for intune file version successfully"
            if ($storageCheck.uploadState -eq " azureStorageUriRequestSuccess" ) {
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Azure storage status is success"
                return $azureStorageUri
            }
            
        }
        else {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to check the status of the place holder for intune file version"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.Azure_Storage_URI_creation_error
            Write-Log
            Exit $error_code_mapping.Azure_Storage_URI_creation_error
        }
    }
}






function calculate_create_upload_chunks {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $intunewinfilepath,
        [Parameter(Mandatory = $true)] [string] $azureStorageUri,
        [Parameter(Mandatory = $true)] [string] $tokenauthorizationheader
    )
   ;  $authHeader = @{
        'Authorization' = $tokenauthorizationheader
    }
    # Calculate the chunk size
   ;  $WEChunkSizeInBytes = 1024l * 1024l * 6l;
    $WESASRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $WEFileSize = (Get-Item -Path $intunewinfilepath).Length
    $WEChunkCount = [System.Math]::Ceiling($WEFileSize / $WEChunkSizeInBytes)
   ;  $WEBinaryReader = New-Object -TypeName System.IO.BinaryReader([System.IO.File]::Open($intunewinfilepath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite))

    # create and upload the chunks
   ;  $WEChunkIDs = @()
    for ($WEChunk = 0; $WEChunk -lt $WEChunkCount; $WEChunk++) {
        $WEChunkID = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($WEChunk.ToString(" 0000" )))
        $WEChunkIDs = $WEChunkIDs + $WEChunkID
        $WEStart = $WEChunk * $WEChunkSizeInBytes
        $WELength = [System.Math]::Min($WEChunkSizeInBytes, $WEFileSize - $WEStart)
        $WEBytes = $WEBinaryReader.ReadBytes($WELength)
        $WECurrentChunk = $WEChunk + 1

        $WEUri = " {0}&comp=block&blockid={1}" -f $azureStorageUri, $WEChunkID
        $WEISOEncoding = [System.Text.Encoding]::GetEncoding(" iso-8859-1" )
        $WEEncodedBytes = $WEISOEncoding.GetString($WEBytes)
        $WEHeaders = @{
            " x-ms-blob-type" = " BlockBlob"
        }
        $WEUploadResponse = Invoke-WebRequest $WEUri -Method " Put" -Headers $WEHeaders -Body $WEEncodedBytes
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - upload response from calculate_create_upload_chunks function is : " , $WEUploadResponse.StatusCode
        if ($WEUploadResponse.StatusCode -eq 201) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Uploaded the chunk $WECurrentChunk of $WEChunkCount"
        }
        else {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to upload the chunk $WECurrentChunk of $WEChunkCount"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.file_chunk_calculating_uploading_error
            $WEBinaryReader.Close()
            $WEBinaryReader.Dispose()
            Write-Log
            Exit $error_code_mapping.file_chunk_calculating_uploading_error
        }
    }

    # finalise the chunk list and send XML list to the storage location
    $finalChunkUri = " {0}&comp=blocklist" -f $azureStorageUri
    $WEXML = '<?xml version=" 1.0" encoding=" utf-8" ?><BlockList>'
    foreach ($WEChunk in $WEChunkIDs) {
        $WEXML = $WEXML + " <Latest>$($WEChunk)</Latest>"
    }
    $WEXML = $WEXML + '</BlockList>'
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - XML file content is : $WEXML"

    $uploadresponse1 = Invoke-WebRequest -Uri $finalChunkUri -Method " Put" -Body $WEXML
    if ($?) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Uploaded the chunks successfully"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The upload status is " , $uploadresponse1.StatusCode
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Response from calculate_create_upload_chunks function for finalise chunk list and send xml storage location is : " , $uploadresponse1.statusCode
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Uploaded the chunks successfully"
        if ($uploadresponse1.StatusCode -eq 201) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Uploaded the chunks successfully"
            $WEBinaryReader.Close()
            $WEBinaryReader.Dispose()
            return $WEChunkIDs
        }
        else {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to upload the chunks"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.upload_chunks_failure
            $WEBinaryReader.Close()
            $WEBinaryReader.Dispose()
            Write-Log
            Exit $error_code_mapping.upload_chunks_failure
        }
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to upload the chunks"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.upload_chunks_failure
        $WEBinaryReader.Close()
        $WEBinaryReader.Dispose()
        Write-Log
        Exit $error_code_mapping.upload_chunks_failure
    }
    
}


function commit_upload_status {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $tokenauthorizationheader,
        [Parameter(Mandatory = $true)] [string] $createAppConfig_commitFile,
        [Parameter(Mandatory = $true)] [string] $win32LobAppId,
        [Parameter(Mandatory = $true)] [string] $win32LobAppVersionId,
        [Parameter(Mandatory = $true)] [string] $WEWin32LobPlaceHolderId
    )
    $authHeader = @{
        'Authorization' = $tokenauthorizationheader
    }

    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - createAppConfig_commitFile from commit_upload_status function is - $createAppConfig_commitFile"
    # The below code is to commit the commit the upload
    $storageCheckUrl = " https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{0}/microsoft.graph.win32LobApp/contentVersions/{1}/files/{2}" -f $win32LobAppId, $win32LobAppVersionId, $WEWin32LobPlaceHolderId

    $WECommitResourceUri = " {0}/commit" -f $storageCheckUrl

    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - CommitResourceUri is - " , $WECommitResourceUri
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - tokenauthorizationheader is - " , $tokenauthorizationheader

    $commit_upload_status_respnse = Invoke-RestMethod -uri $WECommitResourceUri -Method " POST" -Body $createAppConfig_commitFile -Headers $authHeader -ContentType 'application/json'
    if ($?) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The commit status is " , $commit_upload_status_respnse
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Committed the upload successfully"
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to commit the upload"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.commit_upload_status_fetching_error
        Write-Log
        Exit $error_code_mapping.commit_upload_status_fetching_error
    }
    # The below code is to check the commit status
    $commit_status_upload_state = ""
    $i = 0
    while ($commit_status_upload_state -ne " commitFileSuccess" ) {
        $WECommitStatus = Invoke-RestMethod -uri $storageCheckUrl  -Method " GET" -Headers $authHeader
        if ($?) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The upload is committed successfully"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The commit status is $WECommitStatus"
            $commit_status_upload_state = $WECommitStatus.uploadState
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The commit status from commit_upload_status function is $commit_status_upload_state"
            
            Start-Sleep -Milliseconds 5000
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - $i seconds elapsed"
            $i = $i + 1
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The value of i is $i"
            if ($i -eq 30) {
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The upload is not committed successfully"
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.commit_upload_status_fetching_error
                Write-Log
                Exit $error_code_mapping.commit_upload_status_fetching_error
            }
        }
        else {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to get the commit status"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.commit_upload_status_fetching_error
            Write-Log
            Exit $error_code_mapping.commit_upload_status_fetching_error
        }
    }
    return $commit_status_upload_state
}


function update_file_version {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $tokenauthorizationheader,
        [Parameter(Mandatory = $true)] [string] $win32LobAppId,
        [Parameter(Mandatory = $true)] [string] $win32LobAppVersionId
    )
    $authHeader = @{
        'Authorization' = $tokenauthorizationheader
    }
    $WEWin32AppCommitBody = [ordered]@{
        " @odata.type"             = " #microsoft.graph.win32LobApp"
        " committedContentVersion" = $win32LobAppVersionId
    } | ConvertTo-Json
    $win32LobUrl = " https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
    $WEWin32AppUrl = " {0}/{1}" -f $win32LobUrl, $win32LobAppId
    $j = 0
    while ($j -lt 30) {
        $update_file_version_response = Invoke-WebRequest -uri $WEWin32AppUrl -Method " PATCH" -Body $WEWin32AppCommitBody -Headers $authHeader -ContentType 'application/json'
        
        if ($update_file_version_response.StatusCode -eq 204) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Updated the file version in the Intune application successfully"
            $WEGlobal:logMessages += $update_file_version_response.uploadState
            Start-Sleep -Milliseconds 5000 
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - $i seconds elapsed"
            $j = $j + 1
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The value of i is $j"
            $update_file_version_published_state = Invoke-WebRequest -uri $WEWin32AppUrl -Method " GET" -Headers $authHeader -ContentType 'application/json'
            $update_file_version_published_state_response = $update_file_version_published_state.Content | ConvertFrom-Json
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The file version is updated successfully"
            if ($update_file_version_published_state.StatusCode -eq 200 -And $update_file_version_published_state_response.publishingState -eq " published" ) {
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The file version is updated successfully"
                return $update_file_version_published_state_response.publishingState
            }
            
            if ($j -eq 30) {
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The upload is not committed successfully"
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.Win32_App_file_version_updation_error
                Write-Log
                Exit $error_code_mapping.Win32_App_file_version_updation_error
            }
        }
        else {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to update the file version in the Intune application"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.Win32_App_file_version_updation_error
            Write-Log
            Exit $error_code_mapping.Win32_App_file_version_updation_error
        }
    }
    if ($update_file_version_published_state_response.publishingState -ne " published" ) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - The file version is not updated successfully"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution Terminated with error code " , $error_code_mapping.Win32_App_file_version_updation_error
        Write-Log
        Exit $error_code_mapping.Win32_App_file_version_updation_error
    }
}

function WE-Intune_App_Publish {

    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $tokenauthorizationheader,
        [Parameter(Mandatory = $true)] [string] $WECreateAPPConfigfilePath,
        [Parameter(Mandatory = $true)] [string] $intunewinfilepath
    )

    # The below function call is to read the create App section of the JSON file
    $createAppConfig_createApp = read_json_section -json_file_path $WECreateAPPConfigfilePath -SectionName " createApp"
        
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - ***********************"
    
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Create App section data from createappconfig file from main function is : $createAppConfig_createApp"

    # The below function call is to create the win32_Lob App in intune
    $win32LobAppId = win32_LobApp_creation -tokenauthorizationheader $tokenauthorizationheader -createAppConfig_createApp $createAppConfig_createApp
    
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Win32LobAppId for the intune instance from main function is : $win32LobAppId"
    
    # The below function call is to get win32_LobApp file version
    $win32LobAppVersionId = win32_LobApp_file_version -tokenauthorizationheader $tokenauthorizationheader -win32LobAppId $win32LobAppId

    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Win32LobAppVersionID from main function is : $win32LobAppVersionId"
    
    # The below fucntion call is to fetch the createFile data from the createAppConfig.json file
    $createAppConfig_createFile = read_json_section -json_file_path $WECreateAPPConfigfilePath -SectionName " createFile"
    
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Succesfully read the createappconfig json file createfile section from main fucntion is : $createAppConfig_createFile"

    # The below function call is to create place holder for intune file version
    $WEWin32LobPlaceHolderId = win32LobApp_placeholder -tokenauthorizationheader $tokenauthorizationheader -createAppConfig_createFile $createAppConfig_createFile -win32LobAppId $win32LobAppId -win32LobAppVersionId $win32LobAppVersionId
    
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Win32LobPlaceHolderId from main function is : $WEWin32LobPlaceHolderId"

    # The below fucntion call is to check if the above function for creating the place holder is handled properly or not.
    $azureStorageUri = check_win32LobApp_placeholder_status -tokenauthorizationheader $tokenauthorizationheader -win32LobAppId $win32LobAppId -win32LobAppVersionId $win32LobAppVersionId -Win32LobPlaceHolderId $WEWin32LobPlaceHolderId
    
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Azure Storage URI from main function is : $azureStorageUri"
    
    # 2., 3. The below function call is to calculate , create and upload chunks of the intunewin file
    calculate_create_upload_chunks -intunewinfilepath $intunewinfilepath -azureStorageUri $azureStorageUri -tokenauthorizationheader $tokenauthorizationheader
    
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Successfully uploaded the chunks of the intunewin file from main function"

    # The below function call is to fetch the commitFile section data from the createAppConfig.json file
    $createAppConfig_commitFile = read_json_section -json_file_path $WECreateAPPConfigfilePath -SectionName " commitFile"
    
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - CommitFile section data from createappconfig json file from main function is : $createAppConfig_commitFile"

    # 4. The below function call is to commit the upload and check commit status
    $commit_status_upload_state = commit_upload_status -tokenauthorizationheader $tokenauthorizationheader -createAppConfig_commitFile $createAppConfig_commitFile -win32LobAppId $win32LobAppId -win32LobAppVersionId $win32LobAppVersionId -Win32LobPlaceHolderId $WEWin32LobPlaceHolderId
    
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Commit status upload state from main function is : $commit_status_upload_state"

    # 5. The below function call is to update the file version in the Intune application
    $upload_file_version_upload_state = update_file_version -tokenauthorizationheader $tokenauthorizationheader -win32LobAppId $win32LobAppId -win32LobAppVersionId $win32LobAppVersionId

    # The below function is check if win32 app has been successfully published or not
    return $win32LobAppId
}

function check_win32_App_Existenece_in_Intune {
    

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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $tokenauthorizationheader,
        [Parameter(Mandatory = $true)] [string] $dependencyAppConfigfilepath
    )

    $authHeader = @{
        'Authorization' = $tokenauthorizationheader
    }
    $createAppConfig_createApp = read_json_section -json_file_path $dependencyAppConfigfilepath -SectionName " createApp"
    # Ftech the detection rules key from the createApp section
    
    $detectionRuletype = $createAppConfig_createApp | ConvertFrom-Json
    $detectionRuleInfo = $detectionRuletype.detectionRules
    $detectionRuletype = $detectionRuletype.detectionRules." @odata.type"
    $win32_App_Publisher_Filter = " https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$filter=contains(publisher,'Dell')"
    $win32Apps_response_intune = Invoke-RestMethod -Uri $win32_App_Publisher_Filter -Method " GET" -Headers $authHeader -ContentType 'application/json'
    $win32Apps_response_intune1 = Invoke-WebRequest -Uri $win32_App_Publisher_Filter -Method " GET" -Headers $authHeader -ContentType 'application/json'
    if ($win32Apps_response_intune1.StatusCode -eq 200) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Win32 app found in Intune"
        
        $win32Apps_data_intune = $win32Apps_response_intune.value
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Total Win32 apps found in Intune : " , $win32Apps_data_intune.count
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Win32 apps found in Intune : " , $win32Apps_data_intune

        if ($win32Apps_data_intune.count -ge 1) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Win32 app found in Intune"
            foreach ($appdata_intune in $win32Apps_data_intune) {
                $global:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Win32 app found in Intune"

                $win32app_id_intune = $appdata_intune.id
                $publishingState_intune = $appdata_intune.publishingState
                $detectionRules_intune = $appdata_intune.detectionRules
                $WEGlobal:logMessages += $detectionRules_intune
        
                foreach ($detectionRule_intune in $detectionRules_intune) {
                    $WEGlobal:logMessages += $detectionRule_intune." @odata.type"
                    if ($detectionRuletype -eq $detectionRule_intune." @odata.type" ) {
                        if ($detectionRuletype -eq " #microsoft.graph.win32LobAppRegistryDetection" ) {
                            
                            if ($detectionRuleInfo.keyPath -eq $detectionRule_intune.keyPath) {
                                if ($publishingState_intune -eq " Published" ) {
                                    return $win32app_id_intune
                                }
                            }
                        }
                        elseif ($detectionRuletype -eq " #microsoft.graph.win32LobAppPowerShellScriptDetection" ) {
                            if ($detectionRuleInfo.scriptContent -eq $detectionRule_intune.scriptContent) {
                                if ($publishingState_intune -eq " Published" ) {
                                    return $win32app_id_intune
                                }
                            }
                        }
                        elseif ($detectionRuletype -eq " #microsoft.graph.win32LobAppProductCodeDetection" ) {
                            if ($detectionRuleInfo.productCode -eq $detectionRule_intune.productCode) {
                                if ($publishingState_intune -eq " Published" ) {
                                    return $win32app_id_intune
                                }   
                            } 
                        }
                    }        
                }
            }
        }
        else {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Win32 app not found in Intune"
        }
        
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Unable to fetch win32 apps from Intune through graph API"
        return $WEFalse
    }
    
}

function WE-Win32_App_Dependency_Update {
    

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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $tokenauthorizationheader,
        [Parameter(Mandatory = $true)] [string] $dependencyAppID,
        [Parameter(Mandatory = $true)] [string] $dependentAppID
    )
    $authHeader = @{
        'Authorization' = $tokenauthorizationheader
    }
    $dependency_update_url = " https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{0}/UpdateRelationships" -f $dependentAppID
    $body = @{
        relationships = @(
            [PSCustomObject]@{
                targetId       = $dependencyAppID
                dependencyType = " autoInstall"
                " @odata.type"  = " #microsoft.graph.mobileAppDependency"
            }
        )
    }

    # Convert to JSON with proper depth
    $dependency_update_body = $body | ConvertTo-Json -Depth 10 -Compress    
    $dependency_update = Invoke-RestMethod -Uri $dependency_update_url -Method " POST" -Body $dependency_update_body -Headers $authHeader -ContentType 'application/json'
    if ($?) {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependency updated successfully"
        $global:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependency ID is : " , $dependency_update.id
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependency update failed"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script execution terminated with error code " , $error_code_mapping.dependency_update_failure
        Write-Log
        Exit $error_code_mapping.dependency_update_failure
    }

}

function WE-Show-Help {
    @"
    Usage:
    --> powershell.exe -file " Dell_Intune_App_Publish_V1.0.ps1" -ClientId " 12345678-1234-1234-1234-123456789012" -TenantId " d66b5b8b-8b60-4b0f-8b60-123456789012" -ClientSecret " z98b5b8b8b604b0f8b60123456789012" -AppName " dcu" -proxy " http://proxy.local:80"
    --> powershell.exe -file " Dell_Intune_App_Publish_V1.0.ps1" -ClientId " 12345678-1234-1234-1234-123456789012" -TenantId " d66b5b8b-8b60-4b0f-8b60-123456789012" -CertificateThumbprint " z98b5b8b8b604b0f8b60123456789012" -AppName " dcu" -proxy " http://proxy.local:80"
    --> powershell.exe -file " Dell_Intune_App_Publish_V1.0.ps1" -ClientId " 12345678-1234-1234-1234-123456789012" -TenantId " d66b5b8b-8b60-4b0f-8b60-123456789012" -ClientSecret " z98b5b8b8b604b0f8b60123456789012" -CabPath " C:\temp\dcu.cab" -proxy " http://proxy.local:80"
    --> powershell.exe -file " Dell_Intune_App_Publish_V1.0.ps1" -ClientId " 12345678-1234-1234-1234-123456789012" -TenantId " d66b5b8b-8b60-4b0f-8b60-123456789012" -CertificateThumbprint " z98b5b8b8b604b0f8b60123456789012" -CabPath " C:\temp\dcu.cab" -proxy " http://proxy.local:80"
    --> powershell.exe -file " Dell_Intune_App_Publish_V1.0.ps1" -help
    --> powershell.exe -file " Dell_Intune_App_Publish_V1.0.ps1" -supportedapps
    --> powershell.exe -file " Dell_Intune_App_Publish_V1.0.ps1" -supportedapps -Proxy " http://proxy.local:80"

    Description:
        This script helps Dell Customers to Publish Dell Applications to the respective Intune Tenant.

    Parameters:
        -help                      : displays this help content
        -supportedapps             : List the application names, supported versions and its AppName that needs to be passed to script
        -ClientId                  : Microsoft Intune Client identification string that needs to be passed to the script
        -TenantId                  : Microsoft Intune Tenant identification string that needs to be passed to the script
        -ClientSecret              : Microsoft Intune Client Secret string that needs to be passed to the script
        -CertificateThumbprint     : Microsoft Intune Certificate Thumbprint string that needs to be passed to the script
        -CabPath                   : Path of the cab file that needs to be published to Microsoft Intune
        -AppName                   : Application Name that needs to be published to Microsoft Intune
        -proxy                     : Proxy URL that needs to be passed to the script for downloading the files
        -logpath                   : FolderPath To store log Files.

" @ | Write-Host
}


function WE-Draw-AsciiTable {
    

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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [array]$WEData
    )
 
    $WEColumns = @(" Supported Application Name" , " Version" , " AppName" )
    $colWidths = @{
        " Supported Application Name" = [Math]::Max(30, ($WEData | ForEach-Object { $_.DisplayName.Length } | Measure-Object -Maximum).Maximum)
        " Version" = [Math]::Max(10, ($WEData | ForEach-Object { $_.Version.Length } | Measure-Object -Maximum).Maximum)
        " AppName" = [Math]::Max(15, ($WEData | ForEach-Object { $_.AppName.Length } | Measure-Object -Maximum).Maximum)
    }
 
    function WE-Build-Line {
        $line = " +"
        foreach ($col in $WEColumns) {
            $line = $line + (" -" * ($colWidths[$col] + 2)) + " +"
        }
        return $line
    }
 
    function WE-Print-Line {
        Write-Host (Build-Line) -ForegroundColor Green
    }
 
    function WE-Print-Header {
        $line = ""
        foreach ($col in $WEColumns) {
            $line = $line + " | " + $col.PadRight($colWidths[$col]) + " "
        }
        $line = $line + " |"
 
        $parts = $line -split '(\|)'
        foreach ($part in $parts) {
            if ($part -eq " |" ) {
                Write-Host -NoNewline $part -ForegroundColor Green
            } else {
                Write-Host -NoNewline $part -ForegroundColor Yellow
            }
        }
        Write-Host
    }
 
    function WE-Print-Rows {
        foreach ($row in $WEData) {
            $line = ""
            $line = $line + " | " + $row.DisplayName.PadRight($colWidths[" Supported Application Name" ]) + " "
            $line = $line + " | " + $row.Version.PadRight($colWidths[" Version" ]) + " "
            $line = $line + " | " + $row.AppName.PadRight($colWidths[" AppName" ]) + " |"
 
            $parts = $line -split '(\|)'
            foreach ($part in $parts) {
                if ($part -eq " |" ) {
                    Write-Host -NoNewline $part -ForegroundColor Green
                } else {
                    Write-Host -NoNewline $part -ForegroundColor White
                }
            }
            Write-Host
            Print-Line
        }
    }
 
    Print-Line
    Print-Header
    Print-Line
    Print-Rows
}
function WE-Show-SupportedApps {
    @"
Supported applications and its AppName that needs to be passed to script are as below:  
" @ | Write-Host
    # The below code is to download the config json cabinet file
    if ($proxy) {
        $download_files_response = download_files -downloadurl $WEGlobal:intune_config_file_download_url -downloadPath $WEGlobal:downloads_dir -proxy $proxy
    }
    else {
        $download_files_response = download_files -downloadurl $WEGlobal:intune_config_file_download_url -downloadPath $WEGlobal:downloads_dir
    }
   
    $json_downloadPath = $download_files_response.downloadPath
    $json_filename = $download_files_response.filename
   
    # The below code is to extract the config json cabinet file
    $WEIntune_Config_File_Path = Extract_CabinetFile -downloadPath $json_downloadPath -filename $json_filename
   
    # The below code is to read the JSON data in a loop to display the supported Application Name, Version and App Name
    $json_data = Get-Content -Path $WEIntune_Config_File_Path | ConvertFrom-Json
    $displayData = @()
    if ($?) {
        # Loop through the parsed data and print displayname and version
        foreach ($key in $json_data.PSObject.Properties.Name) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Key Name that is being read is : $key"
            foreach ($app in $json_data.$key) {
                foreach ($appdetails in $app) {
                    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Display Name that is being read is : $($appdetails.displayname)"
                    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Version that is being read is : $($appdetails.version)"
                   
                    # Collect the data
                    $displayData = $displayData + [PSCustomObject]@{
                        DisplayName = $appdetails.displayname
                        Version     = $appdetails.version
                        AppName     = $key
                    }
                }
            }
        }
    Draw-AsciiTable -Data $displayData
    Write-Log
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to read the Intune Config.json file"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Execution terminated with return code " , $error_code_mapping.json_file_parsing_failure
        Write-Log
        Exit $error_code_mapping.json_file_parsing_failure
    }
}


function WE-File_download_Extract {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)] [string] $WEAppdownloadurl,
        [Parameter(Mandatory = $true)] [string] $WESHA512,
        [Parameter(Mandatory = $true)] [string] $WEAppconfigSHA512,
        [Parameter(Mandatory = $true)] [string] $intunewinSHA512
    )

    # The below function call is to download the Application from the URL
    $download_files_response = download_files -downloadurl $WEAppdownloadurl -downloadPath $WEGlobal:downloads_dir -proxy $proxy

    $downloadPath1 = $download_files_response.downloadPath
    $filename1 = $download_files_response.filename
    
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Downloaded file full path from main function is : $downloadPath1"
    
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Downloaded the file successfully and the filename from main fucntion is : $filename1"

    $WEApp_File_path = Join-Path -Path $downloadPath1 -ChildPath $filename1
    
    hash_verification -FilePath $WEApp_File_path -SHA512 $WESHA512

    $WEAppFileExtension = [System.IO.Path]::GetExtension($WEApp_File_path).ToLower()
    if ($WEAppFileExtension -eq " .cab" ) {
        # The below function call is to extract the CAB contents on the end-user system in downloads_temp folder under CWD
        $intunewinfilepath, $WECreateAPPConfigfilePath = Extract_CabinetFile -downloadPath $downloadPath1 -filename $filename1
    }
    elseif ($WEAppFileExtension -eq " .zip" ) {
        # The below function call is to extract the ZIP contents on the end-user system in downloads_temp folder under CWD
        $intunewinfilepath, $WECreateAPPConfigfilePath = Extract_Archive -downloadPath $downloadPath1 -filename $filename1
    }
    else {
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Unsupported file extension : $WEAppFileExtension"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Exeution terminated with return code " , $error_code_mapping.Unsupported_file_extension
        Write-Log
        Exit $error_code_mapping.Unsupported_file_extension
    }
    
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - intunewin file path is : $intunewinfilepath"

    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - CreateAPPConfig file path is : $WECreateAPPConfigfilePath"

    hash_verification -FilePath $WECreateAPPConfigfilePath -AppConfigSHA512 $WEAppconfigSHA512

    hash_verification -FilePath $intunewinfilepath -intunewinSHA512 $intunewinSHA512

    $extracted_file_paths = @{
        intunewinfilepath       = $intunewinfilepath
        CreateAPPConfigfilePath = $WECreateAPPConfigfilePath

    }
    return $extracted_file_paths
    
}




function main {

    secure_dir_file_creation
    $WEGlobal:logMessages = " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Started and inside main function"
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - **************************************************"
    if ((($WEClientId) -and ($WETenantId) -and ($WEClientSecret) -and ($WEAppName)) -or (($WEClientId) -and ($WETenantId) -and ($WECertThumbprint) -and ($WEAppName)) -or (($WEClientId) -and ($WETenantId) -and ($WEClientSecret) -and ($WECabPath)) -or (($WEClientId) -and ($WETenantId) -and ($WECertThumbprint) -and ($WECabPath))) {

        # Pre-requesites check
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Checking Prerequisites"
        prerequisite_verification

        if ($WEAppName) {
            # intialization
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Current working directory is : $WEGlobal:downloads_dir"
            
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Log Path location is : $WEGlobal:log_file_path"
            
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Application Name is : $WEAppName"
            
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Proxy is : $proxy"
        
            # The below fucntion call is to get the respective application intune zip file URL based on User entered data
            
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Application Name is $appName.ToUpper()"
            $WEAppdownloadurl = input_processing -AppName $WEAppName

            $dependentAppDownloadURL = $WEAppdownloadurl.dependantAppURL
            $dependencyAppDownloadURL = $WEAppdownloadurl.dependencyAppURL
            
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependent App Download URL for the user selected application is : $dependentAppDownloadURL"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependency App Download URL for the user selected application is : $dependencyAppDownloadURL"

            if ($WEClientSecret) {
                # The below function call is to create the Access token by using the client id, tenant id and client secret that is passed by user
                $tokenauthorizationheader = generate_access_token_using_Client_Secret -ClientId $WEClientId -TenantId $WETenantId -ClientSecret $WEClientSecret
            }
            elseif ($WECertThumbprint) {
                # The below function call is to create the Access token by using the client id, tenant id and client certificate that is passed by user
                $tokenauthorizationheader = generate_access_token_using_Client_Cert_Thumbprint -ClientId $WEClientId -TenantId $WETenantId -CertThumbprint $WECertThumbprint
            }
            
            $dependencywin32lobappID = ""
            $dependentwin32lobappID = ""

            if ($null -ne $dependencyAppDownloadURL) {
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependency App Download URL is available for the user selected application"
                $dependencyAppExtractPaths = File_download_Extract -Appdownloadurl $dependencyAppDownloadURL -SHA512 $WEAppdownloadurl.dependencyAppSHA512 -AppconfigSHA512 $WEAppdownloadurl.dependencyAppAppConfigJsonSHA512 -intunewinSHA512 $WEAppdownloadurl.dependencyAppIntunePackageSHA512
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependency App Intune win file path is : $dependencyAppExtractPaths.intunewinfilepath"
                
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependency App CreateAPPConfig file path is : $dependencyAppExtractPaths.CreateAPPConfigfilePath"

                # The below code is to check if the dependency app exists in intune or not
                $dependencywin32lobappID = check_win32_App_Existenece_in_Intune -tokenauthorizationheader $tokenauthorizationheader -dependencyAppConfigfilepath $dependencyAppExtractPaths.CreateAPPConfigfilePath
                
                $dependencywin32lobappID = $dependencywin32lobappID -split " "
                $dependencywin32lobappID = $dependencywin32lobappID[-1]
                if ($dependencywin32lobappID -ne "" ) {
                    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependency App exists in Intune, hence skipping the intune app publish"
                }
                else {
                    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependency App does not exists in Intune, hence going ahead with intune app publish"

                    $dependencywin32lobappID = Intune_App_Publish -tokenauthorizationheader $tokenauthorizationheader -CreateAPPConfigfilePath $dependencyAppExtractPaths.CreateAPPConfigfilePath -intunewinfilepath $dependencyAppExtractPaths.intunewinfilepath
                    $dependencywin32lobappID = $dependencywin32lobappID -split " "

                    # Get the last element
                    $dependencywin32lobappID = $dependencywin32lobappID[-1]
                    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependency App ID is : $dependencywin32lobappID"
                }
                
            }
            else {
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - No dependency app found for the user selected application"
            }

            if ($dependentAppDownloadURL -ne "" ) {
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependent App Download URL is available for the user selected application"
                $dependentAppExtractPaths = File_download_Extract -Appdownloadurl $dependentAppDownloadURL -SHA512 $WEAppdownloadurl.dependentAppSHA512 -AppconfigSHA512 $WEAppdownloadurl.dependentAppConfigJsonSHA512 -intunewinSHA512 $WEAppdownloadurl.dependentAppIntunePackageSHA512
                
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependent App Intune win file path is : $dependentAppExtractPaths.intunewinfilepath"
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependent App CreateAPPConfig file path is : $dependentAppExtractPaths.CreateAPPConfigfilePath"
                
                $dependentwin32lobappID = Intune_App_Publish -tokenauthorizationheader $tokenauthorizationheader -CreateAPPConfigfilePath $dependentAppExtractPaths.CreateAPPConfigfilePath -intunewinfilepath $dependentAppExtractPaths.intunewinfilepath
                $dependentwin32lobappID = $dependentwin32lobappID -split " "

                    # Get the last element
                $dependentwin32lobappID = $dependentwin32lobappID[-1]
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependent App win32lobappID is : $dependentwin32lobappID"

            }
            
            # The below code is to update the app dependency in Intune.
            if ($dependencywin32lobappID -ne "" ) {
                Win32_App_Dependency_Update -tokenauthorizationheader $tokenauthorizationheader -dependencyAppID $dependencywin32lobappID -dependentAppID $dependentwin32lobappID
                if($?){
                    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Dependency updated successfully"
                    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script execution completed successfully" , $error_code_mapping.success
                    Write-Log
                    Exit $error_code_mapping.success

                }
                else{
                    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Failed to update the dependency in Intune"
                    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script execution terminated with error code " , $error_code_mapping.dependency_update_failure
                    Write-Log
                    Exit $error_code_mapping.dependency_update_failure
                }
            }    

        }
        elseif ($WECabPath) {
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - CAB path provided by user is : $WECabPath"
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - For Local CAB Path Flow, App Dependecies wont be published to Intune"

            if (!(Test-Path $WECabPath)) {
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - CAB path provided by user is not valid"
                Write-Log
                Exit $error_code_mapping.Directory_path_not_Exist
            }
            else {

                $filename1 = $WECabPath.Split(" \" )[-1]

                $downloadPath1 = $WECabPath.Replace(" \" + $filename1, "" )
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Downloaded file full path from main function is : $downloadPath1"
            
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Downloaded the file successfully and the filename from main fucntion is : $filename1"

                $WEApp_File_path = Join-Path -Path $downloadPath1 -ChildPath $filename1
                $WEAppFileExtension = [System.IO.Path]::GetExtension($WEApp_File_path).ToLower()
                if ($WEAppFileExtension -eq " .cab" ) {
                    # The below function call is to extract the CAB contents on the end-user system in downloads_temp folder under CWD
                    $intunewinfilepath, $WECreateAPPConfigfilePath = Extract_CabinetFile -downloadPath $downloadPath1 -filename $filename1
                }
                elseif ($WEAppFileExtension -eq " .zip" ) {
                    # The below function call is to extract the ZIP contents on the end-user system in downloads_temp folder under CWD
                    $intunewinfilepath, $WECreateAPPConfigfilePath = Extract_Archive -downloadPath $downloadPath1 -filename $filename1
                }
                else {
                    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - App file extension is not valid"
                    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script execution terminated with error code " , $error_code_mapping.Unsupported_File_Extension
                    Write-Log
                    Exit $error_code_mapping.Unsupported_File_Extension
                }
            
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - intunewin file path is : $intunewinfilepath"
            
                $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - CreateAPPConfig file path is : $WECreateAPPConfigfilePath"
                
            }    
        
            if ($WEClientSecret) {
                # The below function call is to create the Access token by using the client id, tenant id and client secret that is passed by user
                $tokenauthorizationheader = generate_access_token_using_Client_Secret -ClientId $WEClientId -TenantId $WETenantId -ClientSecret $WEClientSecret
            }
            elseif ($WECertThumbprint) {
                # The below function call is to create the Access token by using the client id, tenant id and client certificate that is passed by user
               ;  $tokenauthorizationheader = generate_access_token_using_Client_Cert_Thumbprint -ClientId $WEClientId -TenantId $WETenantId -CertThumbprint $WECertThumbprint
            }
            
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - --------------------------------"
            
            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Intune token authorization header generated successfully"
            
            #$WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Intune token authorization header from main function is : $tokenauthorizationheader"

            # The below function call is to publish the app to Intune
           ;  $win32LobAppId = Intune_App_Publish -tokenauthorizationheader $tokenauthorizationheader -CreateAPPConfigfilePath $WECreateAPPConfigfilePath -intunewinfilepath $intunewinfilepath

            $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Win32LobAppId from main function for local CAB path publishing is : $win32LobAppId"
        }
    }
    elseif ($help) {
        Show-Help
    }
    elseif ($supportedapps) {
        # The below code is to create the secure directory and files for downloading and logging purposes
        
        Show-SupportedApps
    }
    else {
        # The below code is to create the secure directory and files for downloading and logging purposes
        # secure_dir_file_creation

        Write-WELog " Invalid parameters passed. Please pass the correct parameters" " INFO"
        Write-WELog " For more details on script usage, Please run the script with -help parameter as below" " INFO"
        Write-Host 'powershell.exe -file Dell_Intune_App_Publish_V1.0.ps1 -help'
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Invalid parameters passed. Please pass the correct parameters"
        $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - For more details on script usage, Please run the script with -help parameter as below"
        $WEGlobal:logMessages += " $(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - powershell.exe -file Dell_Intune_App_Publish_V1.0.ps1 -help"
        Write-Log
        Exit $error_code_mapping.Invalid_Parameters_passed_to_script
    }
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - **************************************************"
    $WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Ended"
    Write-Log
}


verify_admin_privileges

$WEGlobal:logMessages += " `n$timestamp - Logging Started"
$WEGlobal:logMessages += " `n$(Get-Date -Format " yyyy-MM-dd HH:mm:ss" ) - Script Started"

main












# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================