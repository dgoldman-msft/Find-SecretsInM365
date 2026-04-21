# Dot-source internal helper functions
. (Join-Path $PSScriptRoot "internal\functions\Get-TimeStamp.ps1")
. (Join-Path $PSScriptRoot "internal\functions\Write-ToLogFile.ps1")

# Dot-source public functions
. (Join-Path $PSScriptRoot "functions\Find-SecretsInM365.ps1")

# Export public functions and aliases
Export-ModuleMember -Function Find-SecretsInM365 -Alias FSiM365
