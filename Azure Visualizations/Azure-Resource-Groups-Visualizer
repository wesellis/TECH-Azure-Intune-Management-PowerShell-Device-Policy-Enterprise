<#
.SYNOPSIS
This PowerShell script creates a visual map of multiple Azure resource groups.

.DESCRIPTION
This script generates a visual representation of the resources in one or more Azure resource groups, including their dependencies and relationships.

.NOTES
Author: Wes Ellis
Date: April 6, 2023
Version: 1.0

.LINK
GitHub Repository: https://github.com/yourusername/yourrepositoryname

.PARAMETER ResourceGroups
Specifies one or more Azure resource groups to visualize. You can specify multiple resource groups by separating them with a comma. For example:

.\ResourceGroupVisualMap.ps1 -ResourceGroups "myresourcegroup1, myresourcegroup2"

#>

# Your PowerShell script goes here


# chocolatey packages Graphviz for Windows
choco install graphviz

# alternatively using windows package manager
winget install graphviz

# install from powershell gallery
Install-Module -Name AzViz -Scope CurrentUser -Repository PSGallery -Force

# import the module
Import-Module AzViz -Verbose

# login to azure, this is required for module to work
Connect-AzAccount

# Visualizing multiple resource groups
Export-AzViz -ResourceGroup demo-2, demo-3 -LabelVerbosity 1 -CategoryDepth 1 -Theme light -Show -OutputFormat png
