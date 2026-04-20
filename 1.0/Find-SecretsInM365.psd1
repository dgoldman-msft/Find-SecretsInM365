@{
    # Module identity
    RootModule        = 'Find-SecretsInM365.psm1'
    ModuleVersion     = '1.0'
    GUID              = 'a7c2e4f1-83b6-4d9e-bc05-d73f1a229e41'
    Author            = 'Dave Goldman'
    CompanyName       = ' '
    Copyright         = '(c) Dave Goldman. All rights reserved.'

    # Description
    Description       = 'Audits Microsoft 365 SharePoint Online for secrets accidentally stored using Microsoft Purview Content Explorer. Implements a Purview-native false-positive reduction model to reduce pattern-match noise from 2M+ signals to an actionable remediation queue. Supports optional automated remediation via PnP PowerShell.'

    # Minimum PowerShell version required
    PowerShellVersion = '7.1'

    # Required modules — ExchangeOnlineManagement is checked/installed at runtime
    RequiredModules   = @()

    # Format file
    FormatsToProcess  = @('.\xml\Find-Secrets.Format.ps1xml')

    # Exports
    FunctionsToExport = @(
        'Find-SecretsInM365',
        'Invoke-SecretRemediation'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @('FSiM365', 'Find-Secrets')

    # Private data
    PrivateData       = @{
        PSData = @{
            Tags         = @('Purview', 'Secrets', 'SharePoint', 'Compliance', 'ContentExplorer', 'MicrosoftPurview', 'SIT', 'FalsePositive', 'Remediation', 'PnP', 'Security')
            LicenseUri   = 'https://github.com/dgoldman-msft/Find-SecretsInM365/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/dgoldman-msft/Find-SecretsInM365'
            ReleaseNotes = 'Initial release.'
        }
    }
}
