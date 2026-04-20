function Find-SecretsInM365 {
    <#
    .SYNOPSIS
        A PowerShell module that audits secrets accidentally stored in Microsoft 365 using Microsoft Purview Sensitive Information Types (SITs).

    .DESCRIPTION
        Uses Export-ContentExplorerData (Security & Compliance PowerShell) to enumerate
        Sensitive Information Type (SIT) matches in M365 workloads to find credentials.

        The function implements a Purview-native false-positive reduction model:
          - Filters by MinConfidence threshold (High/Medium/Low) to cut pattern-match noise
          - Optionally restricts to a named set of SITs rather than scanning all 300+
          - Optionally restricts to specific site URLs via -SiteUrls
          - -IncludeFileTypes / -ExcludeFileTypes filter by file extension (e.g. include only
            Office docs; exclude .log/.tmp/.bak noise)
          - -ExcludePathPattern drops records whose path matches a regex (e.g. backup folders)
          - -MinMatchCount requires N or more SIT instances in a file before it is reported
            (raises the bar for broad/generic SITs like 'General password')
          - Emits a SecretAuditResult object per match with enough metadata for triage and remediation

        Why pattern counts explode (the large result set problem):
          Built-in SITs are intentionally broad-regex classifiers. Without confidence filtering and SIT
          scoping, every number, GUID-like string, or token in code dumps registers as a hit.
          Setting -MinConfidence High and scoping via -SitNames reduces the queue by orders of magnitude
          without disabling detection.

    .PARAMETER TagType
        The Content Explorer classification category to query. Maps directly to the filter views in
        the Purview Content Explorer UI (Data classification → Content explorer → filter dropdown):
          SensitiveInformationType — Sensitive info types    (default)
          Sensitivity              — Sensitivity labels
          Retention                — Retention labels
          TrainableClassifier      — Trainable classifiers
        Defaults to 'SensitiveInformationType'.

    .PARAMETER SitNames
        Array of tag names to scan for, scoped to the selected -TagType.
        For SensitiveInformationType: Sensitive Information Type display names.
        For Sensitivity / Retention: label names.
        For TrainableClassifier: classifier names.
        Defaults to a built-in credential-focused SIT list covering Azure, Microsoft Entra,
        GitHub, AWS, Google, Slack, and generic credential patterns. Override by passing your
        own array. Use 'All credentials' as a single umbrella tag, or list individual types such as:
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

    .PARAMETER SiteUrls
        Array of SharePoint Online site URLs to restrict results to.
        When specified, only records whose SiteUrl field matches one of the supplied URLs are returned.
        If omitted, results are returned for all sites.

    .PARAMETER Workloads
        Which M365 workloads to query. Accepts 'SPO' (SharePoint Online), 'ODB' (OneDrive for Business),
        'EXO' (Exchange Online), and 'Teams'. Multiple workloads are scanned sequentially.
        Defaults to @('SPO', 'ODB', 'EXO', 'Teams') — all workloads.

    .PARAMETER MinConfidence
        Minimum Purview SIT confidence level to include.
          High   — fewest false positives; best for remediation queues        (recommended)
          Medium — moderate noise; useful for broad discovery
          Low    — maximum recall; expect very high false-positive rates
        Defaults to 'High'.

    .PARAMETER PageSize
        Records to retrieve per API page from Content Explorer. Range: 1–10000.
        Defaults to 1000.

    .PARAMETER ExportResults
        When specified, exports the audit report to a CSV file per workload inside -LogDirectory.

    .PARAMETER UseAggregate
        When specified, performs a two-phase scan for SPO and ODB workloads:
          Phase 1 — calls Export-ContentExplorerData with -Aggregate to retrieve only the list of
                    sites containing matches at the requested confidence level (no item records).
          Phase 2 — scopes each subsequent paging call to a single site via -SiteUrl, downloading
                    only item records from sites confirmed to have hits.
        This dramatically reduces data transfer when most sites have no matches at -MinConfidence High.
        Note: -Aggregate is currently in private preview and may not be available in all tenants.
        Falls back to a full workload scan automatically if the aggregate call fails.

    .PARAMETER ConnectIPPS
        When specified, attempts to import ExchangeOnlineManagement and call Connect-IPPSSession
        if no active IPPS session is detected. The session is automatically disconnected via
        Disconnect-ExchangeOnline when the function completes, preventing orphaned connections.

    .PARAMETER IncludeFileTypes
        Allowlist of file extensions to include. Records whose FileType is not in this list are
        dropped before being returned. Use this to restrict results to file types that are
        realistically expected to contain credentials and dramatically reduce false positives from
        log files, binaries, and other noisy sources.
        Extensions are matched case-insensitively without a leading dot.
        Example: @('docx', 'xlsx', 'pdf', 'txt', 'csv', 'ps1', 'py', 'json', 'xml', 'config')

    .PARAMETER ExcludeFileTypes
        Blocklist of file extensions to suppress. Records whose FileType matches any extension in
        this list are dropped. Use this to eliminate known noisy sources without restricting by
        allowlist.
        Extensions are matched case-insensitively without a leading dot.
        Example: @('log', 'tmp', 'bak', 'etl', 'evtx', 'blg')

    .PARAMETER ExcludePathPattern
        A regular expression applied to each record's Path field. Records whose path matches are
        dropped. Use this to suppress backup directories, archive paths, test data locations, or
        any known false-positive subtrees.
        Example: '(?i)(backup|archive|test|temp|recycle)'

    .PARAMETER MinMatchCount
        Minimum number of SIT pattern instances a record must contain to be returned.
        When the API returns a per-record match count (SensitiveInfoTypeCount / MatchCount), records
        below this threshold are dropped. Raising this value (e.g. 2 or 3) eliminates one-off
        pattern hits in large documents that are unlikely to be intentional credential storage.
        Defaults to 1 (all records returned regardless of match count).
        Note: when the API does not return a match count the filter is skipped automatically.

    .PARAMETER LogDirectory
        Directory for Logging.txt and any CSV exports.
        Defaults to a 'Find-Secrets' subfolder inside $env:TEMP.

    .EXAMPLE
        Find-SecretsInM365 -ConnectIPPS -MinConfidence High -ExportResults

        Connects to IPPS, scans all SITs at High confidence across SPO, exports results to CSV.

    .EXAMPLE
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

        Scans only credential-type SITs at High confidence across both SharePoint Online and OneDrive.

    .EXAMPLE
        Find-SecretsInM365 -SiteUrls 'https://contoso.sharepoint.com/sites/ITOps' -MinConfidence Medium

        Scopes scan to a single site at Medium confidence — useful for targeted investigation.

    .OUTPUTS
        SecretAuditResult — one object per match with properties:
          SIT, Workload, SiteUrl, FileName, FileType, Confidence, MatchCount, ContainerName, Path, RawRecord

    .NOTES
        Requires an active Security & Compliance PowerShell session (Connect-IPPSSession) and the
        Content Explorer List Viewer or Content Explorer Content Viewer role in Microsoft Purview.

    .LINK
        https://learn.microsoft.com/en-us/microsoft-365/compliance/sit-sensitive-information-type-learn-about
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [Alias('FSiM365', 'Find-Secrets')]
    param(
        [Parameter()]
        [ValidateSet('SensitiveInformationType', 'Sensitivity', 'Retention', 'TrainableClassifier')]
        [string]$TagType = 'SensitiveInformationType',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$SitNames = @(
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
        ),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$SiteUrls,

        [Parameter()]
        [ValidateSet('SPO', 'ODB', 'EXO', 'Teams')]
        [string[]]$Workloads = @('SPO', 'ODB', 'EXO', 'Teams'),

        [Parameter()]
        [ValidateSet('High', 'Medium', 'Low')]
        [string]$MinConfidence = 'High',

        [Parameter()]
        [ValidateRange(1, 10000)]
        [int]$PageSize = 1000,

        [Parameter()]
        [switch]$ExportResults,

        [Parameter()]
        [switch]$UseAggregate,

        [Parameter()]
        [switch]$ConnectIPPS,

        # --- False-positive reduction filters ---------------------------------------------------

        [Parameter()]
        [string[]]$IncludeFileTypes,

        [Parameter()]
        [string[]]$ExcludeFileTypes,

        [Parameter()]
        [string]$ExcludePathPattern,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$MinMatchCount = 1,

        [Parameter()]
        [string]$LogDirectory = (Join-Path $env:TEMP 'Find-Secrets')
    )

    begin {
        # Confidence rank: used to filter records below threshold
        $confidenceRank = @{ Low = 1; Medium = 2; High = 3 }
        $minRank = $confidenceRank[$MinConfidence]

        # Ensure log directory
        if (-not (Test-Path -Path $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }

        $separator = "$(Get-TimeStamp) " + ("-" * 80)
        Write-ToLogFile -StringObject $separator -LogDirectory $LogDirectory
        Write-Verbose "Starting Find-SecretsInM365"
        Write-ToLogFile -StringObject "$(Get-TimeStamp) Starting Find-SecretsInM365" -LogDirectory $LogDirectory
        Write-ToLogFile -StringObject "$(Get-TimeStamp) TagType        : $TagType" -LogDirectory $LogDirectory
        Write-ToLogFile -StringObject "$(Get-TimeStamp) MinConfidence  : $MinConfidence" -LogDirectory $LogDirectory
        Write-ToLogFile -StringObject "$(Get-TimeStamp) Workloads      : $($Workloads -join ', ')" -LogDirectory $LogDirectory
        Write-ToLogFile -StringObject "$(Get-TimeStamp) UseAggregate   : $UseAggregate" -LogDirectory $LogDirectory
        if ($IncludeFileTypes)    { Write-ToLogFile -StringObject "$(Get-TimeStamp) IncludeFileTypes : $($IncludeFileTypes -join ', ')" -LogDirectory $LogDirectory }
        if ($ExcludeFileTypes)    { Write-ToLogFile -StringObject "$(Get-TimeStamp) ExcludeFileTypes : $($ExcludeFileTypes -join ', ')" -LogDirectory $LogDirectory }
        if ($ExcludePathPattern)  { Write-ToLogFile -StringObject "$(Get-TimeStamp) ExcludePathPattern : $ExcludePathPattern" -LogDirectory $LogDirectory }
        if ($MinMatchCount -gt 1) { Write-ToLogFile -StringObject "$(Get-TimeStamp) MinMatchCount    : $MinMatchCount" -LogDirectory $LogDirectory }

        # Optional auto-connect
        if ($ConnectIPPS) {
            Write-Verbose "Auto-connecting to IPPS session"
            Write-ToLogFile -StringObject "$(Get-TimeStamp) Checking for ExchangeOnlineManagement module" -LogDirectory $LogDirectory
            try {
                if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
                    Write-ToLogFile -StringObject "$(Get-TimeStamp) ExchangeOnlineManagement not found. Installing from PSGallery..." -LogDirectory $LogDirectory
                    Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                    Write-ToLogFile -StringObject "$(Get-TimeStamp) ExchangeOnlineManagement installed successfully" -LogDirectory $LogDirectory
                }
                else {
                    Write-ToLogFile -StringObject "$(Get-TimeStamp) ExchangeOnlineManagement module found" -LogDirectory $LogDirectory
                }
                Import-Module ExchangeOnlineManagement -ErrorAction Stop
                Write-ToLogFile -StringObject "$(Get-TimeStamp) ExchangeOnlineManagement imported" -LogDirectory $LogDirectory
                Connect-IPPSSession -ErrorAction Stop
                Write-Verbose "Successfully connected to IPPS session"
                Write-ToLogFile -StringObject "$(Get-TimeStamp) Successfully connected to IPPS session" -LogDirectory $LogDirectory
            }
            catch {
                Write-ToLogFile -StringObject "$(Get-TimeStamp) ERROR: Failed to connect to IPPS session: $($_.Exception.Message)" -LogDirectory $LogDirectory
                Write-Host "ERROR: Could not connect to the Security and Compliance PowerShell session." -ForegroundColor Red
                Write-Host "  Action required: Ensure you have the ExchangeOnlineManagement module installed and that your account" -ForegroundColor Yellow
                Write-Host "  has the 'Compliance Administrator' or 'Global Administrator' role, then retry with -ConnectIPPS." -ForegroundColor Yellow
                return
            }
        }

        # Validate that the required IPPS cmdlets are available regardless of how the session was established
        Write-Verbose "Validating IPPS session..."
        if (-not (Get-Command -Name 'Export-ContentExplorerData' -ErrorAction SilentlyContinue)) {
            Write-ToLogFile -StringObject "$(Get-TimeStamp) ERROR: Export-ContentExplorerData cmdlet not found. No active IPPS session detected." -LogDirectory $LogDirectory
            Write-Host "ERROR: No active Security and Compliance PowerShell session was found." -ForegroundColor Red
            Write-Host "  Action required: Run 'Connect-IPPSSession' before calling this function, or re-run with the -ConnectIPPS switch." -ForegroundColor Yellow
            return
        }
        Write-Verbose "IPPS session validated successfully"
        Write-ToLogFile -StringObject "$(Get-TimeStamp) IPPS session validated" -LogDirectory $LogDirectory

        # Resolve tag list into $resolvedTags (separate from the parameter to avoid re-validation)
        [string[]]$resolvedTags = $null
        if (-not $SitNames) {
            Write-ToLogFile -StringObject "$(Get-TimeStamp) No -SitNames specified — scanning all tags of type '$TagType'. This may return a very large result set." -LogDirectory $LogDirectory -ForegroundColor Yellow
            Write-Warning "No -SitNames specified. Scanning all '$TagType' tags may return millions of results. Consider scoping with -SitNames or -MinConfidence High."

            # For SensitiveInformationType we can enumerate known names; other TagTypes fall through
            # and let Export-ContentExplorerData return all tags when TagName is omitted.
            if ($TagType -eq 'SensitiveInformationType') {
                try {
                    $resolvedTags = (Get-DlpSensitiveInformationType -ErrorAction Stop).Name
                    Write-ToLogFile -StringObject "$(Get-TimeStamp) Retrieved $($resolvedTags.Count) SIT(s) from tenant" -LogDirectory $LogDirectory
                }
                catch {
                    Write-ToLogFile -StringObject "$(Get-TimeStamp) WARNING: Could not retrieve SIT list. Continuing with 'All': $($_.Exception.Message)" -LogDirectory $LogDirectory -ForegroundColor Yellow
                    $resolvedTags = @($null)
                }
            }
            else {
                # For Sensitivity / Retention / TrainableClassifier, omit TagName and let the API return all
                $resolvedTags = @($null)
            }
        }
        else {
            Write-ToLogFile -StringObject "$(Get-TimeStamp) Tag scope ($TagType): $($SitNames -join ', ')" -LogDirectory $LogDirectory
            $resolvedTags = $SitNames

            # Validate supplied names against known SITs only (no tenant enumeration for other TagTypes)
            if ($TagType -eq 'SensitiveInformationType') {
                try {
                    $knownSITs = (Get-DlpSensitiveInformationType -ErrorAction Stop).Name
                    $badNames  = $resolvedTags | Where-Object { $_ -and $_ -notin $knownSITs }
                    if ($badNames) {
                        Write-Warning "The following -SitNames were not found in the tenant and will return no results: $($badNames -join ', ')"
                        Write-ToLogFile -StringObject "$(Get-TimeStamp) WARNING: Unrecognised SIT name(s): $($badNames -join ', ')" -LogDirectory $LogDirectory -ForegroundColor Yellow
                        Write-Host "  Tip: Run (Get-DlpSensitiveInformationType).Name to list valid names." -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-ToLogFile -StringObject "$(Get-TimeStamp) INFO: Could not validate SIT names (Get-DlpSensitiveInformationType unavailable): $($_.Exception.Message)" -LogDirectory $LogDirectory
                }
            }
        }

        if ($SiteUrls) {
            Write-ToLogFile -StringObject "$(Get-TimeStamp) Site filter   : $($SiteUrls -join ', ')" -LogDirectory $LogDirectory
        }
    }

    process {
        $hits = [System.Collections.Generic.List[object]]::new()

        foreach ($workload in $Workloads) {
            Write-ToLogFile -StringObject "$(Get-TimeStamp) *** Starting scan of workload: $workload ***" -LogDirectory $LogDirectory -ForegroundColor Cyan

            foreach ($sit in $resolvedTags) {
                $sitLabel = if ($sit) { $sit } else { '(all tags)' }
                Write-Verbose "Scanning SIT '$sitLabel' in workload '$workload'"
                Write-ToLogFile -StringObject "$(Get-TimeStamp) Scanning SIT: '$sitLabel' | Workload: $workload" -LogDirectory $LogDirectory

                # --- Phase 1: optional aggregate pass to identify affected sites ------
                # Aggregate (SPO/ODB only) returns the list of sites with matches at the
                # requested confidence level without downloading any item records.
                # Phase 2 then scopes every paging call to a single site via -SiteUrl,
                # dramatically reducing data transfer when most sites have zero matches.
                $isSiteBased = $workload -in @('SPO', 'SharePoint', 'ODB', 'OneDrive')
                $sitesToScan = @($null)   # $null = no SiteUrl scope; scan the whole workload

                if ($UseAggregate -and $isSiteBased) {
                    Write-ToLogFile -StringObject "$(Get-TimeStamp) Aggregate pass: SIT '$sitLabel' | Workload $workload" -LogDirectory $LogDirectory
                    try {
                        $aggParams = @{
                            TagType         = $TagType
                            Workload        = $workload
                            ConfidenceLevel = $MinConfidence.ToLower()   # API requires lowercase: high/medium/low
                            Aggregate       = $true
                            ErrorAction     = 'Stop'
                        }
                        if ($sit) { $aggParams['TagName'] = $sit }

                        $aggResp    = Export-ContentExplorerData @aggParams 3>$null
                        $aggMeta    = $aggResp[0]
                        $aggRecords = if ($aggResp.Count -gt 1) { $aggResp[1..($aggResp.Count - 1)] } else { @() }

                        $aggTotal = if ($aggMeta.PSObject.Properties['TotalCount']) { $aggMeta.TotalCount } else { '?' }
                        Write-ToLogFile -StringObject "$(Get-TimeStamp) Aggregate response: TotalCount=$aggTotal | SiteRecords=$($aggRecords.Count)" -LogDirectory $LogDirectory

                        # Collect site URLs for sites that reported at least one match
                        $aggSites = $aggRecords | ForEach-Object {
                            $cnt = if ($_.PSObject.Properties['TotalCount']) { [int]$_.TotalCount }
                                   elseif ($_.PSObject.Properties['Count'])  { [int]$_.Count }
                                   else { 1 }
                            if ($cnt -gt 0) {
                                if ($_.PSObject.Properties['SiteUrl'])     { $_.SiteUrl }
                                elseif ($_.PSObject.Properties['SiteURL']) { $_.SiteURL }
                            }
                        } | Where-Object { $_ }

                        # If the aggregate returned records but we couldn't parse any SiteUrl,
                        # the response schema is unexpected — fall back to a full workload scan
                        # rather than silently skipping.
                        if ($aggRecords.Count -gt 0 -and $aggSites.Count -eq 0) {
                            $sampleProps = ($aggRecords[0].PSObject.Properties.Name) -join ', '
                            Write-Warning "Aggregate returned $($aggRecords.Count) record(s) for '$sitLabel' but could not parse SiteUrl. Available properties: $sampleProps. Falling back to full workload scan."
                            Write-ToLogFile -StringObject "$(Get-TimeStamp) WARNING: Aggregate SiteUrl parse failed. Properties: $sampleProps. Falling back to full scan." -LogDirectory $LogDirectory -ForegroundColor Yellow
                            $sitesToScan = if ($SiteUrls -and $isSiteBased) { @($SiteUrls) } else { @($null) }
                        }
                        else {
                            # Intersect with -SiteUrls when specified
                            if ($SiteUrls) {
                                $aggSites = $aggSites | Where-Object {
                                    $s = $_; $SiteUrls | Where-Object { $s -like "*$_*" }
                                }
                            }

                            $sitesToScan = @($aggSites)
                            Write-ToLogFile -StringObject "$(Get-TimeStamp) Aggregate: $($sitesToScan.Count) site(s) to scan for '$sitLabel'" -LogDirectory $LogDirectory -ForegroundColor Cyan

                            if ($sitesToScan.Count -eq 0) {
                                $hint = if ($aggTotal -eq 0 -or $aggTotal -eq '0') {
                                    ' SIT name may be incorrect or content has not yet been scanned by Purview.'
                                } else { '' }
                                Write-Verbose "  Aggregate returned 0 sites for '$sitLabel' — skipping item scan"
                                Write-ToLogFile -StringObject "$(Get-TimeStamp) Aggregate: 0 sites for '$sitLabel' — skipping.$hint" -LogDirectory $LogDirectory
                                continue
                            }
                        }
                    }
                    catch {
                        Write-Warning "Aggregate pass failed for '$sitLabel': $($_.Exception.Message). Falling back to full scan."
                        Write-ToLogFile -StringObject "$(Get-TimeStamp) WARNING: Aggregate pass failed, falling back: $($_.Exception.Message)" -LogDirectory $LogDirectory
                        $sitesToScan = if ($SiteUrls -and $isSiteBased) { @($SiteUrls) } else { @($null) }
                    }
                }
                elseif ($SiteUrls -and $isSiteBased) {
                    # No aggregate but user supplied specific sites — scope each API call
                    # directly so filtering happens server-side, not in memory
                    $sitesToScan = @($SiteUrls)
                }

                # --- Phase 2: item-level paging — per site when scoped, else full workload ---
                foreach ($siteScope in $sitesToScan) {
                    $pageCookie = $null
                    $morePages  = $true
                    $pageCount  = 0
                    $scopeLabel = if ($siteScope) { "site '$siteScope'" } else { 'all sites' }

                    while ($morePages) {
                        $pageCount++
                        Write-Verbose "  Page $pageCount | SIT '$sitLabel' | $scopeLabel"

                        try {
                            $exportParams = @{
                                TagType         = $TagType
                                Workload        = $workload
                                PageSize        = $PageSize
                                ConfidenceLevel = $MinConfidence.ToLower()   # API requires lowercase: high/medium/low
                                ErrorAction     = 'Stop'
                            }
                            if ($pageCookie) { $exportParams['PageCookie'] = $pageCookie }  # omit on first page
                            if ($sit)        { $exportParams['TagName']    = $sit }
                            if ($siteScope)  { $exportParams['SiteUrl']    = $siteScope }

                            $resp = Export-ContentExplorerData @exportParams 3>$null
                        }
                        catch {
                            Write-Warning "Error on page $pageCount | SIT '$sitLabel' | $scopeLabel : $($_.Exception.Message)"
                            Write-ToLogFile -StringObject "$(Get-TimeStamp) ERROR: SIT '$sitLabel' | $scopeLabel | Page $pageCount : $($_.Exception.Message)" -LogDirectory $LogDirectory
                            break
                        }

                        # Item 0 = metadata, items 1..n = records
                        $meta    = $resp[0]
                        $records = if ($resp.Count -gt 1) { $resp[1..($resp.Count - 1)] } else { @() }

                        Write-Verbose "  Page $pageCount returned $($records.Count) record(s)"

                        # On the first page of the first SIT, dump property names in Verbose mode
                        # so it's easy to diagnose what the API is actually returning.
                        if ($pageCount -eq 1 -and $records.Count -gt 0) {
                            $propNames = ($records[0].PSObject.Properties.Name) -join ', '
                            Write-Verbose "  Record properties for '$sitLabel': $propNames"
                            Write-ToLogFile -StringObject "$(Get-TimeStamp) Record properties for '$sitLabel': $propNames" -LogDirectory $LogDirectory
                        }

                        foreach ($r in $records) {
                            # --- Confidence safety-net filter -------------------------------------------
                            # ConfidenceLevel is now passed to the API so the vast majority of
                            # low-confidence records are filtered server-side before being returned.
                            # This guard catches any edge-case records with an unexpected confidence value.
                            $rawConf  = if ($r.PSObject.Properties['Confidence'])          { $r.Confidence }
                                        elseif ($r.PSObject.Properties['ConfidenceLevel']) { $r.ConfidenceLevel }
                                        else { $MinConfidence }  # No confidence property — trust server-side ConfidenceLevel filtering

                            # Normalise to 'High','Medium','Low'
                            $confNorm = switch -Wildcard ($rawConf.ToString()) {
                                '*High*'   { 'High'   }
                                '*Medium*' { 'Medium' }
                                default    { 'Low'    }
                            }

                            if ($confidenceRank[$confNorm] -lt $minRank) {
                                Write-Verbose "    Safety-net: dropping record (confidence '$confNorm' < '$MinConfidence')"
                                continue
                            }

                            # --- Resolve site URL -------------------------------------------------------
                            $recordSiteUrl = if ($r.PSObject.Properties['SiteUrl'])     { $r.SiteUrl }
                                             elseif ($r.PSObject.Properties['SiteURL']) { $r.SiteURL }
                                             else { $siteScope ?? '' }

                            # Post-filter against SiteUrls only when the API call was not already scoped
                            if ($SiteUrls -and -not $siteScope) {
                                $siteMatch = $SiteUrls | Where-Object { $recordSiteUrl -like "*$_*" }
                                if (-not $siteMatch) { continue }
                            }

                            # --- Build result object ----------------------------------------------------
                            $result = [pscustomobject]@{
                                PSTypeName    = 'SecretAuditResult'
                                SIT           = $sitLabel
                                Workload      = $workload
                                Confidence    = $confNorm
                                SiteUrl       = $recordSiteUrl
                                FileName      = if ($r.PSObject.Properties['ObjectName'])  { $r.ObjectName }
                                                elseif ($r.PSObject.Properties['FileName']) { $r.FileName }
                                                else { '' }
                                FileType      = if ($r.PSObject.Properties['FileType'])    { $r.FileType }
                                                elseif ($r.PSObject.Properties['Extension']) { $r.Extension }
                                                else { '' }
                                ContainerName = if ($r.PSObject.Properties['ContainerName']) { $r.ContainerName } else { '' }
                                Path          = if ($r.PSObject.Properties['Path'])          { $r.Path }
                                                elseif ($r.PSObject.Properties['URL'])        { $r.URL }
                                                else { '' }
                                MatchCount    = if ($r.PSObject.Properties['SensitiveInfoTypeCount']) { [int]$r.SensitiveInfoTypeCount }
                                                elseif ($r.PSObject.Properties['MatchCount'])          { [int]$r.MatchCount }
                                                elseif ($r.PSObject.Properties['Count'])               { [int]$r.Count }
                                                else { $null }
                                RawRecord     = $r
                            }

                            # --- False-positive reduction filters -----------------------------------
                            # IncludeFileTypes: allowlist — drop records not in the list
                            if ($IncludeFileTypes -and $result.FileType) {
                                $ext = $result.FileType.TrimStart('.')
                                if ($ext -notin $IncludeFileTypes) {
                                    Write-Verbose "    FP-filter: dropping '$($result.FileName)' — FileType '$ext' not in -IncludeFileTypes"
                                    continue
                                }
                            }

                            # ExcludeFileTypes: blocklist — drop records in the list
                            if ($ExcludeFileTypes -and $result.FileType) {
                                $ext = $result.FileType.TrimStart('.')
                                if ($ext -in $ExcludeFileTypes) {
                                    Write-Verbose "    FP-filter: dropping '$($result.FileName)' — FileType '$ext' in -ExcludeFileTypes"
                                    continue
                                }
                            }

                            # ExcludePathPattern: regex on Path — drop matching records
                            if ($ExcludePathPattern -and $result.Path -match $ExcludePathPattern) {
                                Write-Verbose "    FP-filter: dropping '$($result.FileName)' — Path matches -ExcludePathPattern"
                                continue
                            }

                            # MinMatchCount: only keep records that meet the instance count threshold
                            if ($result.MatchCount -ne $null -and $result.MatchCount -lt $MinMatchCount) {
                                Write-Verbose "    FP-filter: dropping '$($result.FileName)' — MatchCount $($result.MatchCount) < MinMatchCount $MinMatchCount"
                                continue
                            }

                            $hits.Add($result)
                            Write-Verbose "    Match: '$($result.FileName)' | SIT: '$sitLabel' | Confidence: $confNorm"
                            Write-ToLogFile -StringObject "$(Get-TimeStamp) MATCH: File='$($result.FileName)' | SIT='$sitLabel' | Confidence=$confNorm | Site='$recordSiteUrl'" -LogDirectory $LogDirectory
                        }

                        $pageCookie = $meta.PageCookie
                        $morePages  = [bool]$meta.MorePagesAvailable
                    }
                }
            }

            $wlCount = ($hits | Where-Object { $_.Workload -eq $workload }).Count
            Write-ToLogFile -StringObject "$(Get-TimeStamp) *** Completed workload: $workload | Matches: $wlCount ***" -LogDirectory $LogDirectory -ForegroundColor Green

            # CSV export per workload
            if ($ExportResults -and $wlCount -gt 0) {
                $csvPath = Join-Path $LogDirectory "${workload}_Secrets_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                $hits | Where-Object { $_.Workload -eq $workload } |
                    Select-Object SIT, Workload, Confidence, SiteUrl, FileName, FileType, MatchCount, ContainerName, Path |
                    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-ToLogFile -StringObject "$(Get-TimeStamp) [$workload] CSV exported to: $csvPath" -LogDirectory $LogDirectory -ForegroundColor Green
                Write-Host "  [$workload] CSV report : $csvPath" -ForegroundColor Green
            }
        }

        # --- Deduplicate: same file + same SIT can surface from multiple scope passes -----
        # Key includes Workload, SiteUrl, FileName, and Path so that records with an empty
        # or missing Path are not incorrectly collapsed together.
        $uniqueHits = $hits |
            Group-Object -Property SIT, Workload, SiteUrl, FileName, Path |
            ForEach-Object { $_.Group | Sort-Object { $confidenceRank[$_.Confidence] } -Descending | Select-Object -First 1 }

        Write-ToLogFile -StringObject "$(Get-TimeStamp) Scan complete. Raw hits: $($hits.Count) | After dedup: $($uniqueHits.Count)" -LogDirectory $LogDirectory
        Write-Host ""
        Write-Host "Scan complete. Unique findings: $($uniqueHits.Count)" -ForegroundColor Cyan
        Write-Host "Log file : $(Join-Path $LogDirectory 'Logging.txt')" -ForegroundColor Cyan

        $uniqueHits | ForEach-Object { $_ }
    }

    end {
        # Disconnect the IPPS / Exchange Online session if this function established it,
        # so we do not leave orphaned remote sessions open.
        if ($ConnectIPPS) {
            try {
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
                Write-Verbose "Disconnected from Exchange Online / IPPS session"
                Write-ToLogFile -StringObject "$(Get-TimeStamp) Disconnected from Exchange Online / IPPS session" -LogDirectory $LogDirectory
            }
            catch {
                Write-ToLogFile -StringObject "$(Get-TimeStamp) WARNING: Could not disconnect from Exchange Online: $($_.Exception.Message)" -LogDirectory $LogDirectory
            }
        }
    }
}
