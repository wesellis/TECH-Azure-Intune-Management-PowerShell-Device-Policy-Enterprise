<#
.SYNOPSIS
    Taskbar Template

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
    We Enhanced Taskbar Template

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start=" http://schemas.microsoft.com/Start/2014/StartLayout" Version=" 1" xmlns=" http://schemas.microsoft.com/Start/2014/LayoutModification" xmlns:taskbar=" https://schemas.microsoft.com/Start/2014/TaskbarLayout" >
  
  <CustomTaskbarLayoutCollection PinListPlacement=" Replace" >
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
        <taskbar:DesktopApp DesktopApplicationLinkPath=" %APPDATA%\Microsoft\Windows\Start Menu\Programs\File Explorer.lnk" />
        <taskbar:DesktopApp DesktopApplicationLinkPath=" %APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk" />
        <taskbar:DesktopApp DesktopApplicationLinkPath=" %ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" />
        <taskbar:DesktopApp DesktopApplicationLinkPath=" %ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\GitHub, Inc\Github Desktop.lnk" />
        <taskbar:DesktopApp DesktopApplicationLinkPath=" %ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Visual Studio Code\Visual Studio Code.lnk" />
        <taskbar:UWA AppUserModelID=" Microsoft.WindowsNotepad_8wekyb3d8bbwe!App" />
        <taskbar:UWA AppUserModelID=" {6D809377-6AF0-444B-8957-A3773F02200E}\Notepad++\notepad++.exe" />
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================