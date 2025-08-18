<#
.SYNOPSIS
    Import Entradynamicusergroup

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
    We Enhanced Import Entradynamicusergroup

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
    .SYNOPSIS
        Creates Azure AD dynamic Microsoft 365 groups from definitions listed in an external CSV file.
        Requires external authentication to the tenant before executing the script.

        Authenticate to the target tenant with:

        $WEScopes = "Group.ReadWrite.All" , " Directory.ReadWrite.All"
        Connect-MgGraph -Scopes $WEScopes

    .NOTES
        Author: Aaron Parker
        Twitter: @stealthpuppy

    .LINK
        https://stealthpuppy.com



$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(ValueFromPipeline, Mandatory = $false, Position = 0, HelpMessage = " Path to the CSV document describing the Dynamic Groups." )]
    [ValidateNotNullOrEmpty()]
    [ValidateScript( {
            if ( -not (Test-Path -Path $_)) { throw " $_ does not exist." }
            if ( -not ($_ | Test-Path -PathType Leaf) ) { throw " The Path argument must be a file. Folder paths are not allowed." }
            if ($_ -notmatch " (\.csv)" ) { throw " The file specified in the path argument must be either of type CSV." }
            return $true
        })]
    [System.IO.FileInfo] $WEPath = (Join-Path -Path $WEPSScriptRoot -ChildPath " DynamicUserGroups.csv" )
)

begin {}
process {

    # Import CSV
    $csvGroups = Import-Csv $WEPath -ErrorAction " Stop"

    # Get the existing dynamic groups from Azure AD
    $WEExistingGroups = Get-MgGroup -All:$true | Where-Object { $_.GroupTypes -eq " DynamicMembership" } -ErrorAction " Stop"
    if ($WEExistingGroups) { Write-Verbose -Message " Found $($WEExistingGroups.Count) existing dynamic groups." }

    # Step through each group from the CSV file
    foreach ($group in $csvGroups) {

        # Match any existing group with the same display name membership rule. This means that we can run this against any tenant
        # Update to match against $_.Id if you want to ensure
        $matchingGroup = $WEExistingGroups | Where-Object { $_.DisplayName -eq $group.DisplayName -and $_.MembershipRule -eq $group.MembershipRule }
        if ($matchingGroup) {
            Write-Warning -Message " Skipping import - Membership rule for $($group.DisplayName) matches existing group $($matchingGroup.DisplayName)."

            # if the description needs updating on the group, update to match that listed in the CSV file
            if ($matchingGroup.Description -ne $group.Description) {
                if ($WEPSCmdlet.ShouldProcess($group.DisplayName , " Update description: '$($group.Description)'." )) {
                    $params = @{
                        Id          = $matchingGroup.Id
                        Description = $group.Description
                        ErrorAction = " Stop"
                    }
                    Update-MgGroup @params
                }
            }
        }
        else {
            # Create the new group
            if ($WEPSCmdlet.ShouldProcess($group.DisplayName , " Create group." )) {
                Write-Verbose -Message " Created group '$($group.DisplayName)' with membership rule '$($group.MembershipRule)'."

                # Construct the parameters for New-MgGroup -ErrorAction Stop
                $params = @{
                    DisplayName                   = $group.DisplayName
                    Description                   = $group.Description
                    GroupTypes                    = " DynamicMembership" , " Unified"
                    MembershipRule                = $group.MembershipRule
                    MembershipRuleProcessingState = " On"
                    SecurityEnabled               = $true
                    MailEnabled                   = $true
                    IsAssignableToRole            = $false
                    MailNickname                  = (New-Guid)
                    ErrorAction                   = " Stop"
                }
               ;  $WENewGroup = New-MgGroup -ErrorAction Stop @params
                Write-Output -InputObject $WENewGroup

                # Add a photo to the group
                if (-not([System.String]::IsNullOrEmpty($group.PhotoUrl))) {
                   ;  $WEProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                    Invoke-WebRequest -Uri $group.PhotoUrl -OutFile " $WEPSScriptRoot\$(Split-Path -Path $group.PhotoUrl -Leaf)" -ErrorAction " Stop"
                    Set-MgGroupPhotoContent -GroupId $WENewGroup.Id -InFile " $WEPSScriptRoot\$(Split-Path -Path $group.PhotoUrl -Leaf)" -ErrorAction " Stop"
                    Remove-Item -Path " $WEPSScriptRoot\$(Split-Path -Path $group.PhotoUrl -Leaf)" -Force
                }
            }
        }
    }
}




} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
