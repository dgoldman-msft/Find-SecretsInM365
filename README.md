# Find-SecretsInM365

A PowerShell module that audits secrets accidentally stored in Microsoft 365 using Microsoft Purview Sensitive Information Types (SITs).

---

## Overview

### How Microsoft Purview classifies content

Microsoft Purview continuously scans your Microsoft 365 tenant — SharePoint Online, OneDrive for Business, Exchange Online, and Teams — and stamps every file with any Sensitive Information Type (SIT) pattern that matches its content. A SIT is essentially a regex-based classifier: Purview ships with over 300 built-in types covering credentials, identifiers, financial data, health information, and more.

Purview deliberately errs on the side of recall. Its built-in SITs are intentionally broad so that a genuine secret is never missed. The trade-off is that patterns broad enough to catch every AWS access key or GitHub token will also match strings that *look like* secrets but aren't — sequential numbers, GUIDs in application logs, version strings, auto-generated identifiers, and so on. Every match at every confidence level is recorded in Content Explorer regardless of how noisy it is.

This is by design: Purview's job is classification at scale. It surfaces everything so that downstream tools — DLP policies, Information Protection labels, and scripts like this one — can act on the subset that matters.

### The gap this module fills

The raw Content Explorer data, without any filtering, is too large to be actionable for a remediation team. Most organizations find that when they query all SITs at all confidence levels across all workloads, they are looking at a volume of signals that is orders of magnitude larger than the number of real secrets in their environment.

**Find-Secrets** sits between Purview's broad classification pass and your remediation workflow. It applies a layered filtering strategy to the same `Export-ContentExplorerData` API that Content Explorer uses, so that what reaches your team is a focused, high-confidence queue rather than a raw signal dump.

> **False-positive reduction guide:** [Reduce false positives by using SITs and advanced classifiers](https://learn.microsoft.com/en-us/purview/deploymentmodels/depmod-reduce-false-positives)

> **Microsoft Learn:** [Data classification overview](https://learn.microsoft.com/en-us/purview/data-classification-overview) · [Learn about sensitive information types](https://learn.microsoft.com/en-us/purview/sensitive-information-type-learn-about) · [Get started with Content Explorer](https://learn.microsoft.com/en-us/purview/data-classification-content-explorer)

---

## How false-positive reduction works

The module attacks the noise problem at five distinct layers:

### Layer 1 — SIT scoping

Purview scans all 300+ SITs by default. The vast majority of those types — names, addresses, phone numbers, generic numbers — are not credential signals. By supplying `-SitNames`, you restrict every API call to the specific SIT types that represent real secrets. A typical credential-focused list looks like:

```
Azure DevOps Personal Access Token
GitHub Personal Access Token
AWS Access Key
Azure Storage Account Key
Azure SAS Token
Generic Password
API Key
```

This alone eliminates a large proportion of total signals before any API call is made, because those calls simply never happen for non-credential SIT types.

> **Important:** SITs detect credentials by scanning **raw file content** using regex patterns and corroborating keyword/checksum evidence. Files do **not** need a sensitivity label applied — SITs are the detectors that run on unlabelled content. Labels are an *output* of classification, not a prerequisite for it.

> **Microsoft Learn:** [Sensitive information type entity definitions](https://learn.microsoft.com/en-us/purview/sit-sensitive-information-type-entity-definitions) · [All credentials sensitive information types](https://learn.microsoft.com/en-us/purview/sit-defn-all-creds)

### Layer 2 — Server-side confidence filtering

Every Purview SIT match is scored with a confidence level: **High**, **Medium**, or **Low**.

| Level | What it means | Typical false-positive rate |
|---|---|---|
| High (≥85) | Strong pattern plus corroborating keyword or checksum validation | Low — suitable for automated remediation |
| Medium (≥75) | Pattern matched but supporting evidence is weaker | Moderate — warrants human review |
| Low (≥65) | Pattern matched on structure alone with no corroborating signal | High — useful only for broad discovery |

The `-MinConfidence` parameter is passed directly to `Export-ContentExplorerData` as the `-ConfidenceLevel` argument. This means Purview filters the results **server-side** before any data is returned to the script. At `High` confidence, you receive only the records where Purview's classifier has the strongest conviction — not everything that could conceivably match.

> **Microsoft Learn:** [More on confidence levels](https://learn.microsoft.com/en-us/purview/sensitive-information-type-learn-about#more-on-confidence-levels) · [Export-ContentExplorerData — -ConfidenceLevel](https://learn.microsoft.com/en-us/powershell/module/exchange/export-contentexplorerdata#-confidencelevel)

### Layer 3 — Two-phase aggregate scanning (`-UseAggregate`)

For SharePoint Online and OneDrive workloads, `Export-ContentExplorerData` supports an `-Aggregate` mode. In aggregate mode, the API returns only a **count per site** — no file records are transferred at all.

When `-UseAggregate` is specified:

**Phase 1 — Discovery:** The function calls the API with `-Aggregate` to retrieve the list of sites that have at least one match at the requested confidence level. Sites with zero matches are immediately excluded.

**Phase 2 — Targeted retrieval:** The function loops through only the confirmed sites and calls the API with `-SiteUrl` scoped to each one. Item-level records are only downloaded for sites that were confirmed to have matches in Phase 1.

In a large tenant where most sites contain no high-confidence credential matches, this approach can reduce the number of API pages the script has to process dramatically. If `-Aggregate` is not available in your tenant (it is currently in private preview), the function falls back to a full workload scan automatically.

> **Microsoft Learn:** [Export-ContentExplorerData — -Aggregate parameter](https://learn.microsoft.com/en-us/powershell/module/exchange/export-contentexplorerdata#-aggregate) (confirmed in private preview in the cmdlet reference)

### Layer 4 — In-memory safety net and deduplication

After records are received from the API, a final client-side confidence check catches any records that have an unexpected or malformed confidence value before they reach the output.

When per-site scoping is active, the same file can theoretically surface from multiple scope passes. Before results are emitted to the pipeline, the function groups records by `SIT + workload + site URL + file name + path` and retains only the highest-confidence record per unique document, removing duplicates.

### Layer 5 — Client-side false-positive filters

Four additional parameters give you fine-grained control over what survives to the output after the API has already applied confidence-level filtering. These are the primary levers for tuning a scan against a specific tenant's noise profile.

#### `-IncludeFileTypes` — extension allowlist

Only returns records whose file extension is in the list you supply. This is the most powerful noise-reduction filter available for credential hunting: files that could not possibly contain a credential in text form (binaries, images, compiled artefacts, telemetry logs) are dropped before they reach you.

```powershell
# Only look inside Office docs, PDFs, scripts, config files, and plain text
Find-SecretsInM365 -SitNames 'General password' -MinConfidence High `
    -IncludeFileTypes @('docx','xlsx','pdf','txt','csv','ps1','py','json','xml','config','env','yaml','yml')
```

#### `-ExcludeFileTypes` — extension blocklist

Drops records whose file extension appears in this list. Use when you want to keep most file types but suppress known noisy ones:

```powershell
Find-SecretsInM365 -SitNames 'General password' -MinConfidence High `
    -ExcludeFileTypes @('log','tmp','bak','etl','evtx','blg','vhd','zip')
```

#### `-ExcludePathPattern` — path regex

Drops records whose `Path` field matches a regular expression. Use this to suppress entire subtrees — backup libraries, archive document libraries, test sites, recycle bin — without having to enumerate each one:

```powershell
Find-SecretsInM365 -SitNames 'General password' -MinConfidence High `
    -ExcludePathPattern '(?i)(backup|archive|test|temp|\/forms\/responses)'
```

#### `-MinMatchCount` — instance count threshold

Purview records how many times a SIT pattern matched inside a file. A broad SIT like *General password* with a single hit in a 500-page document is far more likely to be coincidental than the same SIT with five hits in a small config file. Raising this threshold eliminates one-off matches:

```powershell
# Require at least 2 General password instances before reporting the file
Find-SecretsInM365 -SitNames 'General password' -MinConfidence High -MinMatchCount 2
```

> **Note:** `MatchCount` is populated from the `SensitiveInfoTypeCount`, `MatchCount`, or `Count` property of each API record (whichever is present). If none of those properties exists in the API response for your tenant, the `-MinMatchCount` filter is silently skipped so results are never suppressed due to missing data.

> **Microsoft Learn:** [Configure pattern-based sensitive data detection — Step 1](https://learn.microsoft.com/en-us/purview/deploymentmodels/depmod-reduce-false-positives-step1) — covers confidence levels, proximity, exclusions, and instance count thresholds.

---

## How credentials are found — no labels required

This is the most common source of confusion when working with Purview.

### The classification pipeline

```
File lands in SharePoint / OneDrive / Exchange / Teams
        ↓
Purview scans the raw content automatically (no action needed)
        ↓
Sensitive Information Types match patterns in the text
  e.g. a string matching the Azure SAS token regex + "sig=" keyword
        ↓
Match is recorded in Content Explorer with a confidence level
        ↓
This module queries that data via Export-ContentExplorerData
```

At no point in this pipeline does a sensitivity label need to exist on the file. SITs are pure content classifiers — they look at what is *inside* the file (text, key-value pairs, patterns), not at any metadata tag on the file.

### What `-TagType` controls

Content Explorer supports four classification views, controlled by the `-TagType` parameter:

| `-TagType` value | Content Explorer view | Requires labels? | Use for credential hunting? |
|---|---|---|---|
| `SensitiveInformationType` *(default)* | Sensitive info types | **No** — scans raw content | **Yes — this is the right choice** |
| `Sensitivity` | Sensitivity labels | Yes — label must be applied | No (labels come *after* detection) |
| `Retention` | Retention labels | Yes — label must be applied | No |
| `TrainableClassifier` | Trainable classifiers | Requires trained model | No (for general credential detection) |

**Always use the default `SensitiveInformationType`** when hunting for credentials. The other TagTypes are useful for label-based compliance reporting but will return zero results for files that have never had a label applied — which is exactly the population you're trying to find.

> **Microsoft Learn:** [Export-ContentExplorerData — -TagType parameter](https://learn.microsoft.com/en-us/powershell/module/exchange/export-contentexplorerdata#-tagtype) · [Learn about sensitivity labels](https://learn.microsoft.com/en-us/purview/sensitivity-labels) · [Learn about retention policies and retention labels](https://learn.microsoft.com/en-us/purview/retention) · [Learn about trainable classifiers](https://learn.microsoft.com/en-us/purview/trainable-classifiers-learn-about)

### Why you may see zero results with other TagTypes

- `Sensitivity` / `Retention`: returns only files that already have a label stamped on them. Unlabelled files containing credentials are invisible to this view.
- `TrainableClassifier`: requires a custom or built-in trainable classifier model to have produced a classification. Not applicable to most credential patterns.

### The right command to find credentials across all workloads

```powershell
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
    'ASP.NET machine Key',
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

Find-SecretsInM365 `
    -ConnectIPPS `
    -SitNames      $credSITs `
    -Workloads     SPO, ODB, EXO, Teams `
    -MinConfidence High `
    -UseAggregate `
    -ExportResults
```

Leave `-TagType` at its default — `SensitiveInformationType` is already set for you.

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | 7.1 or later |
| ExchangeOnlineManagement | Required for `Connect-IPPSSession` and `Export-ContentExplorerData` |
| Purview role | **Content Explorer List Viewer** — required to call `Export-ContentExplorerData`. **Content Explorer Content Viewer** — also required to return file names (file names are considered sensitive data per Microsoft docs). Assign both. |
| M365 licence | **E5 (or equivalent)** is required for all credential scanning SITs |

### What you get at each permission level

| Roles assigned | Module behaviour |
|---|---|
| Neither role | `Export-ContentExplorerData` returns an API error or zero results — no output |
| **List Viewer** only | Results are returned but `FileName` is blank/empty on every row |
| **List Viewer + Content Viewer** | Full output — all properties including `FileName` are populated |

> Per the Microsoft documentation: *"The data classification content viewer role is also required to view the name of items in list view, which might contain sensitive data."*

> **Microsoft Learn:** [Content Explorer permissions](https://learn.microsoft.com/en-us/purview/data-classification-content-explorer#permissions) · [E5 licensing for credential scanning SITs](https://learn.microsoft.com/en-us/purview/sensitive-information-type-learn-about#licensing) · [Security & Compliance PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/scc-powershell)

---

## Installation

```powershell
# Clone or download the repository, then import the module
Import-Module .\Find-Secrets\1.0\Find-Secrets.psd1
```

---

## Usage

### Audit — Find-SecretsInM365

#### Connect and scan with recommended defaults

```powershell
$credSITs = @(
    'Azure DevOps Personal Access Token',
    'GitHub Personal Access Token',
    'AWS Access Key',
    'Azure Storage Account Key',
    'Generic Password'
)

Find-SecretsInM365 `
    -ConnectIPPS `
    -SitNames $credSITs `
    -MinConfidence High `
    -UseAggregate `
    -ExportResults
```

`-ConnectIPPS` handles the session automatically. `-UseAggregate` runs the two-phase scan. `-ExportResults` writes a CSV to `$env:TEMP\Find-Secrets\` for each workload.

> **Running without `-SitNames`?** If you call `Find-SecretsInM365 -ConnectIPPS` with no other arguments, the function uses its built-in default SIT list — 29 credential-focused types covering Azure, Microsoft Entra, GitHub, AWS, Google, Slack, and generic patterns — across all four workloads (SPO, ODB, EXO, Teams) at High confidence. This is the recommended starting point.
>
> Be aware that a full scan across all workloads can take significant time depending on tenant size and how many SIT matches Purview has indexed. Each SIT is queried per workload separately and results are paged in batches of up to 1000 records. For large tenants, consider using `-UseAggregate` (reduces data transfer for SPO/ODB by only fetching item records from sites confirmed to have matches) and allowing **up to 14 days** after first deployment for the Content Explorer index to fully populate — you may see more results on subsequent runs as Purview completes its initial crawl.

#### Scan SharePoint and OneDrive

```powershell
Find-SecretsInM365 `
    -ConnectIPPS `
    -SitNames $credSITs `
    -Workloads SPO, ODB `
    -MinConfidence High `
    -UseAggregate `
    -ExportResults
```

#### Target a specific site

```powershell
Find-SecretsInM365 `
    -SiteUrls 'https://contoso.sharepoint.com/sites/Engineering' `
    -SitNames $credSITs `
    -MinConfidence Medium
```

#### Broader discovery pass (expect more noise)

```powershell
Find-SecretsInM365 `
    -ConnectIPPS `
    -SitNames $credSITs `
    -MinConfidence Medium `
    -ExportResults
```

#### Save results to a variable for pipeline use

```powershell
$findings = Find-SecretsInM365 `
    -ConnectIPPS `
    -SitNames $credSITs `
    -MinConfidence High `
    -UseAggregate

$findings | Format-Table SIT, Confidence, MatchCount, FileName, SiteUrl -AutoSize
```

#### Reduce false positives — restrict to credential-bearing file types

```powershell
Find-SecretsInM365 `
    -ConnectIPPS `
    -SitNames $credSITs `
    -Workloads SPO, ODB `
    -MinConfidence High `
    -IncludeFileTypes @('docx','xlsx','pptx','pdf','txt','csv','ps1','psm1','py','js','ts','json','xml','config','env','yaml','yml','ini') `
    -ExportResults
```

#### Reduce false positives — suppress known noisy paths and file types

```powershell
Find-SecretsInM365 `
    -ConnectIPPS `
    -SitNames $credSITs `
    -Workloads SPO, ODB `
    -MinConfidence High `
    -ExcludeFileTypes    @('log','tmp','bak','etl','evtx','blg') `
    -ExcludePathPattern  '(?i)(backup|archive|test|temp|recycle)' `
    -ExportResults
```

#### Reduce false positives — raise instance count for broad SITs

Broad SITs like *General password* or *Http authorization header* will produce single-hit matches in large documents that are almost always false positives. Requiring at least 2 matches per file is a reliable noise reducer:

```powershell
Find-SecretsInM365 `
    -ConnectIPPS `
    -SitNames @('General password', 'Http authorization header', 'User login credentials') `
    -Workloads SPO, ODB `
    -MinConfidence High `
    -MinMatchCount 2 `
    -ExportResults
```

#### Combine all FP filters for a highly targeted scan

```powershell
Find-SecretsInM365 `
    -ConnectIPPS `
    -SitNames $credSITs `
    -Workloads SPO, ODB `
    -MinConfidence High `
    -UseAggregate `
    -IncludeFileTypes   @('docx','xlsx','pdf','csv','txt','ps1','py','json','xml','config','env','yaml','yml') `
    -ExcludePathPattern '(?i)(backup|archive|test|temp|recycle)' `
    -MinMatchCount 2 `
    -ExportResults
```

---

## Output objects

### SecretAuditResult (from Find-SecretsInM365)

| Property | Description |
|---|---|
| `SIT` | The Sensitive Information Type name |
| `Workload` | SPO, ODB, EXO, or Teams |
| `Confidence` | High, Medium, or Low |
| `SiteUrl` | SharePoint site URL |
| `FileName` | Document name |
| `FileType` | File extension |
| `MatchCount` | Number of SIT pattern instances found in the file. `$null` when the API does not return a count. |
| `ContainerName` | Document library name |
| `Path` | Full URL to the file |
| `RawRecord` | Unmodified record from the Content Explorer API |

---

## Parameters reference

### Find-SecretsInM365

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-TagType` | `string` | `SensitiveInformationType` | Content Explorer classification view to query. Use the default for credential hunting — see [How credentials are found](#how-credentials-are-found--no-labels-required). |
| `-SitNames` | `string[]` | Built-in credential SIT list (29 types) | Tag names to scan, scoped to `-TagType`. Override to narrow or broaden the SIT scope. |
| `-SiteUrls` | `string[]` | (all sites) | Restrict scan to specific SharePoint site URLs. |
| `-Workloads` | `string[]` | `SPO, ODB, EXO, Teams` | Workloads to scan. Defaults to all four workloads. |
| `-MinConfidence` | `string` | `High` | Minimum confidence level passed server-side to the API: `High`, `Medium`, or `Low`. |
| `-PageSize` | `int` | `1000` | Records per API page (1–10000). |
| `-ExportResults` | `switch` | off | Export results to CSV in `-LogDirectory`. Columns include `MatchCount`. |
| `-UseAggregate` | `switch` | off | Use two-phase aggregate scan to scope API calls to sites with matches only. |
| `-ConnectIPPS` | `switch` | off | Auto-connect to Security & Compliance PowerShell. Automatically disconnects when the function completes. |
| `-IncludeFileTypes` | `string[]` | (all types) | **FP filter.** Extension allowlist — only return records whose `FileType` is in this list. Case-insensitive, no leading dot. Example: `@('docx','xlsx','json','ps1','config')` |
| `-ExcludeFileTypes` | `string[]` | (none) | **FP filter.** Extension blocklist — drop records in this list. Example: `@('log','tmp','bak','etl')` |
| `-ExcludePathPattern` | `string` | (none) | **FP filter.** Regex matched against each record's `Path`. Records whose path matches are dropped. Example: `'(?i)(backup\|archive\|test)'` |
| `-MinMatchCount` | `int` | `1` | **FP filter.** Minimum SIT instance count per file. Records with a lower count (when available from the API) are dropped. Raise to 2–3 for broad SITs like *General password*. |
| `-LogDirectory` | `string` | `$env:TEMP\Find-Secrets` | Directory for logs and CSV exports. |

---

## NOTE: What this module does NOT give you

Understanding these limitations is important before acting on results.

### Content Explorer returns metadata only — not the secret itself

`Export-ContentExplorerData` returns the **location** of a file that matched a SIT pattern — the site URL, file name, path, SIT type, and confidence level. It does **not** return the matched text or the secret value itself.

To view the actual content of a flagged file you need the **Content Explorer Content Viewer** role in Microsoft Purview, and you would open the file directly from the Content Explorer UI or via the file URL in the results.

> **Microsoft Learn:** [Required permissions to access items in Content Explorer](https://learn.microsoft.com/en-us/purview/data-classification-content-explorer#required-permissions-to-access-items-in-content-explorer)

### Results are not real-time — counts update within 7 days, SharePoint files within 14

Content Explorer is a classification **index**, not a real-time query of file content. According to Microsoft documentation: *“It can take up to seven days for counts to update in content explorer and 14 days for files that are in SharePoint.”* This means:

- A file uploaded today may not appear in results for up to 14 days (SharePoint) or 7 days (other workloads).
- A file that was already deleted may still appear in results until the index catches up.
- Re-running the scan after several days may surface additional findings that weren’t present in the first run.

For an initial tenant deployment, allow up to **7 days** for Content Explorer counts to fully populate after a new SIT or DLP policy is enabled.

> **Microsoft Learn:** [Content Explorer — Export timing note](https://learn.microsoft.com/en-us/purview/data-classification-content-explorer#export)

### Confidence levels — all three exist in Content Explorer

Without filtering, Content Explorer returns **Low, Medium, and High** confidence matches for every SIT. This is the source of the millions-of-results problem: Purview's built-in SITs are intentionally broad, so nearly every number, GUID, or token in a document registers as a Low-confidence hit.

This module passes `-ConfidenceLevel` directly to the API so Purview filters **server-side** before returning any records. The default `-MinConfidence High` means only records where Purview's classifier has the strongest conviction — a regex match *plus* corroborating keywords or checksum validation — are returned.

| Confidence | What it means | Typical use |
|---|---|---|
| High (≥85) | Pattern + corroborating evidence | Automated remediation queues |
| Medium (≥75) | Pattern matched, weaker evidence | Human review / broader discovery |
| Low (≥65) | Pattern match only, no supporting signal | Maximum recall; expect high noise |

> **Microsoft Learn:** [More on confidence levels](https://learn.microsoft.com/en-us/purview/sensitive-information-type-learn-about#more-on-confidence-levels) (confirms discrete values of 65, 75, and 85; high confidence returns only high matches, low confidence returns all)

### Files Purview could not read are never in the index

The following file types will never appear in Content Explorer results regardless of their content:

- **Encrypted files** (e.g. files encrypted with sensitivity labels, BitLocker, or third-party encryption)
- **Password-protected Office documents**
- **Unsupported file formats** — Purview maintains a list of supported file types; binary formats, proprietary formats, and very large files may be excluded
- **Files in unsupported locations** — personal OneDrive folders that haven't been licensed for Purview, Teams messages in tenants without the appropriate licence

> **Microsoft Learn:** [Enable sensitivity labels for files in SharePoint and OneDrive](https://learn.microsoft.com/en-us/purview/sensitivity-labels-sharepoint-onedrive-files) (encrypted sensitivity labels do not surface in Content Explorer for SharePoint and OneDrive) · [Trainable classifiers — encryption limitation](https://learn.microsoft.com/en-us/purview/trainable-classifiers-learn-about#trainable-classifiers) (classifiers only work with items that aren't encrypted)

---

## Recommended workflow

1. **Baseline scan — understand the volume** with all workloads and default SIT list:
   ```powershell
   Find-SecretsInM365 -ConnectIPPS -MinConfidence High -UseAggregate -ExportResults
   ```

2. **Review the CSV** in `$env:TEMP\Find-Secrets\`. Look at the `FileType`, `Path`, and `MatchCount` columns to identify patterns in the noise.

3. **Tune the filters** based on what you see. Common first steps:
   - Add `-IncludeFileTypes` to skip binaries and log files.
   - Add `-ExcludePathPattern` to suppress backup/archive libraries.
   - Add `-MinMatchCount 2` for broad SITs like *General password*.

4. **Re-run with filters applied** to get a cleaner queue:
   ```powershell
   Find-SecretsInM365 -ConnectIPPS -SitNames $credSITs -MinConfidence High -UseAggregate `
       -IncludeFileTypes @('docx','xlsx','pdf','txt','csv','ps1','py','json','xml','config','env','yaml') `
       -ExcludePathPattern '(?i)(backup|archive|test|temp|recycle)' `
       -MinMatchCount 2 `
       -ExportResults
   ```

5. **Re-run the audit** after a Purview re-scan cycle to confirm findings have been resolved. Allow up to 14 days for SharePoint re-indexing to complete.

---

## Aliases

| Alias | Resolves to |
|---|---|
| `FSiM365` | `Find-SecretsInM365` |
| `Find-Secrets` | `Find-SecretsInM365` |

---

## License

MIT License — Copyright (c) 2026 Dave Goldman. See [LICENSE](1.0/LICENSE) for full terms.
