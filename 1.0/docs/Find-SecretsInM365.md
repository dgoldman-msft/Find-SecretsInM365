---
external help file: Find-SecretsInM365-help.xml
Module Name: Find-SecretsInM365
online version: https://learn.microsoft.com/en-us/microsoft-365/compliance/sit-sensitive-information-type-learn-about
schema: 2.0.0
---

# Find-SecretsInM365

## SYNOPSIS
A PowerShell module that audits secrets accidentally stored in Microsoft 365 using Microsoft Purview Sensitive Information Types (SITs).

## SYNTAX

```
Find-SecretsInM365 [[-TagType] <String>] [[-SitNames] <String[]>] [[-SiteUrls] <String[]>]
 [[-Workloads] <String[]>] [[-MinConfidence] <String>] [[-PageSize] <Int32>] [-ExportResults] [-UseAggregate]
 [-ConnectIPPS] [[-IncludeFileTypes] <String[]>] [[-ExcludeFileTypes] <String[]>]
 [[-ExcludePathPattern] <String>] [[-MinMatchCount] <Int32>] [[-LogDirectory] <String>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Uses Export-ContentExplorerData (Security & Compliance PowerShell) to enumerate Sensitive
Information Type (SIT) matches in SharePoint Online (and optionally OneDrive for Business).

The function implements a Purview-native false-positive reduction model:
  - Filters by MinConfidence threshold (High/Medium/Low) to cut pattern-match noise
  - Optionally restricts to a named set of SITs rather than scanning all 300+
  - Optionally restricts to specific site URLs via -SiteUrls
  - -IncludeFileTypes / -ExcludeFileTypes filter by file extension (e.g.
include only
    Office docs; exclude .log/.tmp/.bak noise)
  - -ExcludePathPattern drops records whose path matches a regex (e.g.
backup folders)
  - -MinMatchCount requires N or more SIT instances in a file before it is reported
    (raises the bar for broad/generic SITs like 'General password')
  - Emits a SecretAuditResult object per match with enough metadata for triage and remediation

Why pattern counts explode (the large result set problem):
  Built-in SITs are intentionally broad-regex classifiers.
Without confidence filtering and SIT
  scoping, every number, GUID-like string, or token in code dumps registers as a hit.
  Setting -MinConfidence High and scoping via -SitNames reduces the queue by orders of magnitude
  without disabling detection.

## EXAMPLES

### EXAMPLE 1
```
Find-SecretsInM365 -ConnectIPPS -MinConfidence High -ExportResults
```

Connects to IPPS, scans all SITs at High confidence across SPO, exports results to CSV.

### EXAMPLE 2
```
$credSITs = @(
    'Azure DevOps personal access token',
    'Azure DevOps app secret',
    'Azure storage account key',
    'Azure storage account access key',
    'Azure Storage account shared access signature',
    'Azure Storage account shared access signature for high risk resources',
    'Azure SAS',
    'Azure service bus connection string',
    'Azure Cosmos DB account access key',
    'Azure SQL connection string',
    'Azure IAAS database connection string and Azure SQL connection string',
    'Azure IoT connection string',
    'Azure Function Master / API key',
    'Azure Cognitive Search API key',
    'Azure Container Registry access key',
    'Azure Databricks personal access token',
    'Azure Redis cache connection string',
    'Azure Bot Framework secret key',
    'Azure Shared Access key / Web Hook token',
    'Azure App Service deployment password',
    'Microsoft Entra client access token',
    'Microsoft Entra client secret',
    'Microsoft Entra user Credentials',
    'GitHub Personal Access Token',
    'Amazon S3 Client Secret Access Key',
    'Google API key',
    'Slack access token',
    'General password',
    'General Symmetric key',
    'Client secret / API key',
    'User login credentials',
    'Http authorization header',
    'SQL Server connection string',
    'X.509 certificate private key'
)
Find-SecretsInM365 -SitNames $credSITs -MinConfidence High -Workloads SPO,ODB -ExportResults
```

Scans only credential-type SITs at High confidence across both SharePoint Online and OneDrive.

### EXAMPLE 3
```
Find-SecretsInM365 -SiteUrls 'https://contoso.sharepoint.com/sites/ITOps' -MinConfidence Medium
```

Scopes scan to a single site at Medium confidence - useful for targeted investigation.

## PARAMETERS

### -TagType
The Content Explorer classification category to query.
Maps directly to the filter views in
the Purview Content Explorer UI (Data classification → Content explorer → filter dropdown):
  SensitiveInformationType - Sensitive info types    (default)
  Sensitivity              - Sensitivity labels
  Retention                - Retention labels
  TrainableClassifier      - Trainable classifiers
Defaults to 'SensitiveInformationType'.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: SensitiveInformationType
Accept pipeline input: False
Accept wildcard characters: False
```

### -SitNames
Array of tag names to scan for, scoped to the selected -TagType.
For SensitiveInformationType: Sensitive Information Type display names.
For Sensitivity / Retention: label names.
For TrainableClassifier: classifier names.
Defaults to a built-in credential-focused SIT list covering Azure, Microsoft Entra,
GitHub, AWS, Google, Slack, and generic credential patterns.
Override by passing your
own array.
Use 'All credentials' as a single umbrella tag, or list individual types such as:
  # Microsoft / Azure
  'Azure DevOps personal access token', 'Azure DevOps app secret',
  'Azure storage account key', 'Azure storage account access key',
  'Azure Storage account key (generic)',
  'Azure Storage account shared access signature',
  'Azure Storage account shared access signature for high risk resources',
  'Azure SAS', 'Azure service bus connection string',
  'Azure service bus shared access signature',
  'Azure Cosmos DB account access key', 'Azure DocumentDB auth key',
  'Azure Redis cache connection string', 'Azure Redis cache connection string password',
  'Azure SQL connection string',
  'Azure IAAS database connection string and Azure SQL connection string',
  'Azure IoT connection string', 'Azure IoT shared access key',
  'Azure Function Master / API key', 'Azure Cognitive Search API key',
  'Azure Cognitive Service key', 'Azure Container Registry access key',
  'Azure Databricks personal access token', 'Azure EventGrid access key',
  'Azure Logic app shared access signature', 'Azure Machine Learning web service API key',
  'Azure Maps subscription key', 'Azure Batch shared access key',
  'Azure Bot Framework secret key', 'Azure Bot service app secret',
  'Azure Shared Access key / Web Hook token', 'Azure SignalR access key',
  'Azure App Service deployment password', 'Azure publish setting password',
  'Azure subscription management certificate',
  'Microsoft Entra client access token', 'Microsoft Entra client secret',
  'Microsoft Entra user Credentials', 'Microsoft Bing maps key',
  'ASP.NET machine Key',
  # Third-party
  'GitHub Personal Access Token', 'Amazon S3 Client Secret Access Key',
  'Google API key', 'Slack access token',
  # Generic / cross-platform
  'General password', 'General Symmetric key', 'Client secret / API key',
  'User login credentials', 'Http authorization header',
  'SQL Server connection string', 'X.509 certificate private key'

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: @(
            # Azure / Microsoft
            'Azure DevOps personal access token',
            'Azure DevOps app secret',
            'Azure storage account key',
            'Azure storage account access key',
            'Azure Storage account shared access signature',
            'Azure SAS',
            'Azure service bus connection string',
            'Azure Cosmos DB account access key',
            'Azure SQL connection string',
            'Azure IAAS database connection string and Azure SQL connection string',
            'Azure IoT connection string',
            'Azure Function Master / API key',
            'Azure Container Registry access key',
            'Azure Databricks personal access token',
            'Azure Redis cache connection string',
            'Azure Bot Framework secret key',
            'Azure App Service deployment password',
            'Microsoft Entra client access token',
            'Microsoft Entra client secret',
            'ASP.NET machine Key',
            # Third-party
            'GitHub Personal Access Token',
            'Amazon S3 Client Secret Access Key',
            'Google API key',
            'Slack access token',
            # Generic
            'General password',
            'Client secret / API key',
            'Http authorization header',
            'SQL Server connection string',
            'X.509 certificate private key'
        )
Accept pipeline input: False
Accept wildcard characters: False
```

### -SiteUrls
Array of SharePoint Online site URLs to restrict results to.
When specified, only records whose SiteUrl field matches one of the supplied URLs are returned.
If omitted, results are returned for all sites.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Workloads
Which M365 workloads to query.
Accepts 'SPO' (SharePoint Online), 'ODB' (OneDrive for Business),
'EXO' (Exchange Online), and 'Teams'.
Multiple workloads are scanned sequentially.
Defaults to @('SPO', 'ODB', 'EXO', 'Teams') - all workloads.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: @('SPO', 'ODB', 'EXO', 'Teams')
Accept pipeline input: False
Accept wildcard characters: False
```

### -MinConfidence
Minimum Purview SIT confidence level to include.
  High   - fewest false positives; best for remediation queues        (recommended)
  Medium - moderate noise; useful for broad discovery
  Low    - maximum recall; expect very high false-positive rates
Defaults to 'High'.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: High
Accept pipeline input: False
Accept wildcard characters: False
```

### -PageSize
Records to retrieve per API page from Content Explorer.
Range: 1-10000.
Defaults to 1000.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: 1000
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportResults
When specified, exports the audit report to a CSV file per workload inside -LogDirectory.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -UseAggregate
When specified, performs a two-phase scan for SPO and ODB workloads:
  Phase 1 - calls Export-ContentExplorerData with -Aggregate to retrieve only the list of
            sites containing matches at the requested confidence level (no item records).
  Phase 2 - scopes each subsequent paging call to a single site via -SiteUrl, downloading
            only item records from sites confirmed to have hits.
This dramatically reduces data transfer when most sites have no matches at -MinConfidence High.
Note: -Aggregate is currently in private preview and may not be available in all tenants.
Falls back to a full workload scan automatically if the aggregate call fails.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ConnectIPPS
When specified, attempts to import ExchangeOnlineManagement and call Connect-IPPSSession
if no active IPPS session is detected.
The session is automatically disconnected via
Disconnect-ExchangeOnline when the function completes, preventing orphaned connections.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -IncludeFileTypes
Allowlist of file extensions to include.
Records whose FileType is not in this list are
dropped before being returned.
Use this to restrict results to file types that are
realistically expected to contain credentials and dramatically reduce false positives from
log files, binaries, and other noisy sources.
Extensions are matched case-insensitively without a leading dot.
Example: @('docx', 'xlsx', 'pdf', 'txt', 'csv', 'ps1', 'py', 'json', 'xml', 'config')

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludeFileTypes
Blocklist of file extensions to suppress.
Records whose FileType matches any extension in
this list are dropped.
Use this to eliminate known noisy sources without restricting by
allowlist.
Extensions are matched case-insensitively without a leading dot.
Example: @('log', 'tmp', 'bak', 'etl', 'evtx', 'blg')

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 8
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludePathPattern
A regular expression applied to each record's Path field.
Records whose path matches are
dropped.
Use this to suppress backup directories, archive paths, test data locations, or
any known false-positive subtrees.
Example: '(?i)(backup|archive|test|temp|recycle)'

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 9
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MinMatchCount
Minimum number of SIT pattern instances a record must contain to be returned.
When the API returns a per-record match count (SensitiveInfoTypeCount / MatchCount), records
below this threshold are dropped.
Raising this value (e.g.
2 or 3) eliminates one-off
pattern hits in large documents that are unlikely to be intentional credential storage.
Defaults to 1 (all records returned regardless of match count).
Note: when the API does not return a match count the filter is skipped automatically.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 10
Default value: 1
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogDirectory
Directory for Logging.txt and any CSV exports.
Defaults to a 'Find-Secrets' subfolder inside $env:TEMP.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 11
Default value: (Join-Path $env:TEMP 'Find-Secrets')
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
{{ Fill ProgressAction Description }}

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### SecretAuditResult - one object per match with properties:
###   SIT, Workload, SiteUrl, FileName, FileType, Confidence, MatchCount, ContainerName, Path, RawRecord
## NOTES
Requires an active Security & Compliance PowerShell session (Connect-IPPSSession) and the
Content Explorer List Viewer or Content Explorer Content Viewer role in Microsoft Purview.

## RELATED LINKS

[https://learn.microsoft.com/en-us/microsoft-365/compliance/sit-sensitive-information-type-learn-about](https://learn.microsoft.com/en-us/microsoft-365/compliance/sit-sensitive-information-type-learn-about)

