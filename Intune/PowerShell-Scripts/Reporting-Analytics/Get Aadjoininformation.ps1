<#
.SYNOPSIS
    Get Aadjoininformation

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
    We Enhanced Get Aadjoininformation

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


Add-Type -TypeDefinition @'



$WEErrorActionPreference = "Stop" ; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public enum DSREG_JOIN_TYPE {
    DSREG_UNKNOWN_JOIN = 0,
    DSREG_DEVICE_JOIN = 1,
    DSREG_WORKPLACE_JOIN = 2
}

[StructLayout(LayoutKind.Sequential)]
public struct DSREG_USER_INFO {
    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszUserEmail;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszUserKeyId;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszUserKeyName;
}

[StructLayout(LayoutKind.Sequential)]
public struct DSREG_JOIN_INFO {
    public DSREG_JOIN_TYPE joinType;
    public IntPtr pJoinCertificate;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszDeviceId;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszIdpDomain;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszTenantId;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszJoinUserEmail;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszTenantDisplayName;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszMdmEnrollmentUrl;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszMdmTermsOfUseUrl;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszMdmComplianceUrl;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszUserSettingSyncUrl;

    public IntPtr pUserInfo;
}

public class dsreg {
    [DllImport(" netapi32.dll" , CharSet = CharSet.Unicode)]
    public static extern int NetGetAadJoinInformation(
        [MarshalAs(UnmanagedType.LPWStr)] string pcszTenantId,
        out IntPtr ppJoinInfo
    );

    [DllImport(" netapi32.dll" , CharSet = CharSet.Unicode)]
    public static extern void NetFreeAadJoinInformation(IntPtr pJoinInfo);
}
'@

[CmdletBinding()]
function WE-Get-AadJoinInformation -ErrorAction Stop {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$WETenantId
    )

    $ppJoinInfo = [IntPtr]::Zero

    $result = [dsreg]::NetGetAadJoinInformation($WETenantId, [ref]$ppJoinInfo)
    if ($result -eq 0) {
        # Marshal the IntPtr to DSREG_JOIN_INFO structure
        $joinInfoStruct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ppJoinInfo, [type][DSREG_JOIN_INFO])

        # Convert pJoinCertificate to X509Certificate2
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($joinInfoStruct.pJoinCertificate)

        # Manually marshal pUserInfo to DSREG_USER_INFO if not IntPtr.Zero
        $userInfoStruct = $null
        if ($joinInfoStruct.pUserInfo -ne [IntPtr]::Zero) {
           ;  $userInfoStruct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($joinInfoStruct.pUserInfo, [type][DSREG_USER_INFO])
        }

        # Free the memory using NetFreeAadJoinInformation
        [dsreg]::NetFreeAadJoinInformation($ppJoinInfo)

        # Create a PSObject with friendly names
       ;  $resultObject = [PSCustomObject]@{
            JoinType           = $joinInfoStruct.joinType
            Certificate         = $certificate
            DeviceId           = $joinInfoStruct.pszDeviceId
            IdpDomain          = $joinInfoStruct.pszIdpDomain
            TenantId           = $joinInfoStruct.pszTenantId
            JoinUserEmail      = $joinInfoStruct.pszJoinUserEmail
            TenantDisplayName  = $joinInfoStruct.pszTenantDisplayName
            MdmEnrollmentUrl   = $joinInfoStruct.pszMdmEnrollmentUrl
            MdmTermsOfUseUrl   = $joinInfoStruct.pszMdmTermsOfUseUrl
            MdmComplianceUrl   = $joinInfoStruct.pszMdmComplianceUrl
            UserSettingSyncUrl = $joinInfoStruct.pszUserSettingSyncUrl
            UserEmail          = $userInfoStruct.pszUserEmail
            UserKeyId          = $userInfoStruct.pszUserKeyId
            UserKeyName        = $userInfoStruct.pszUserKeyName
        }

        return $resultObject
    }
    else {
        # If failed to get AAD join information, return $null
        return $null
    }
}







} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
