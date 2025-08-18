<#
.SYNOPSIS
This PowerShell script creates a visual map of a single Azure resource group.

.DESCRIPTION
This script generates a visual representation of the resources in an Azure resource group, including their dependencies and relationships.

.NOTES
Author: Wes Ellis
Date: April 6, 2023
Version: 1.0

.LINK
GitHub Repository: Azure Visualizations/Azure_Visual_Map.ps1

#>

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

#Change Demo-1, Demo-2, Demo-3 to resource groups

# Visualizing a single resource group
Export-AzViz -ResourceGroup demo-2 -Theme Neon -OutputFormat png -Show
