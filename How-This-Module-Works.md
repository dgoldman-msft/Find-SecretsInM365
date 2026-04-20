# How This Module Works

## The Content Explorer found everything problem

Content Explorer records **every** SIT match at **every** confidence level across **every** file in your tenant. Purview ships with a large number of built-in Sensitive Information Type (SIT) classifiers covering credentials, identities, financial data, health information, and more — the full list is published at [Sensitive information type entity definitions](https://learn.microsoft.com/en-us/purview/sit-sensitive-information-type-entity-definitions). Its detector is deliberately tuned to avoid false negatives — a high-confidence match returns fewer false positives but may miss some items, while a low-confidence match maximises recall at the cost of more false positives. The result is that the following types of content generate hits — these examples are illustrative of common noise patterns, not direct quotes from Microsoft documentation:

- A GUID-like string in a SharePoint page can match a certificate or key SIT at Low confidence
- A formatted number like `4111-1111-1111-1111` in a log file can match *Credit Card Number* at Low confidence
- A key-value string like `password=abc123` in a config file can trigger *General password*, *User login credentials*, *Http authorization header*, and *Client secret / API key* simultaneously — four separate SIT hits for the same string
- A Teams message containing a password-reset phrase can match *General password* at Low confidence

None of those are secrets that need remediation. But all of those records are sitting in Content Explorer waiting for someone to look at them.

**This is by design.** Purview's job is classification at scale. It surfaces everything so that downstream tools — DLP policies, Information Protection labels, and scripts like this one — can act on the subset that matters.

**Find-SecretsInM365** sits between Purview's broad classification pass and your remediation workflow. It applies a five-layer filtering strategy to the same `Export-ContentExplorerData` API that Content Explorer uses, so that what reaches your team is a focused, high-confidence queue rather than a raw signal dump.

---

## The five filtering layers

The reduction happens in a specific sequence. Each layer cuts before the next one runs.

---

### Layer 1 — SIT scoping

**The problem:** Purview's built-in SITs include types that are irrelevant to credential hunting — *All Full Names*, *All Medical Terms and Conditions*, *EU Passport Number*, *IP Address*, *All Physical Addresses*, and many more. The full catalogue is listed at [Sensitive information type entity definitions](https://learn.microsoft.com/en-us/purview/sit-sensitive-information-type-entity-definitions). If you query all of them, you get large volumes of hits from names, physical addresses, IP addresses, phone numbers, and identifiers that are not credentials.

**What the module does:** The default `-SitNames` list contains exactly 29 credential-focused SIT types — Azure tokens, GitHub PATs, AWS keys, connection strings, generic passwords, and API keys. When you call the module, it only makes API calls for those 29 types. All 270+ other SITs are simply **never queried**. The API calls for *All Full Names*, *Credit Card Number*, and *EU Passport Number* never happen.

**How to control it:** Pass `-SitNames` to override the default list. Narrow it to a smaller set to reduce runtime, or broaden it by adding types relevant to your environment.

**Expected reduction:** Typically 80–95% of Content Explorer's total count is from non-credential SITs. Scoping to 29 credential types alone may bring extremely large amounts of items down to tens of thousands.

---

### Layer 2 — Server-side confidence filtering

**The problem:** Even within credential SITs, Purview records matches at three confidence levels. Low-confidence matches are pattern-only: the regex matched a string that *looks like* a token but there is little to no corroborating keyword, checksum, or supporting evidence in proximity. These are the largest source of noise within credential SITs.

These are the three discrete confidence levels as defined by Microsoft on the [Sensitive information type entity definitions](https://learn.microsoft.com/en-us/purview/sit-sensitive-information-type-entity-definitions) page:

> *"Mapping of confidence level (high/medium/low) with accuracy number (numeric value of 1 to 100): Low confidence: 65 or below · Medium confidence: 75 · High confidence: 85"*

| Level | Numeric value | What it means | Approximate share of all hits\* |
|---|---|---|---|
| Low | 65 or below | Pattern matched with little to no supporting evidence in proximity | ~70–80% |
| Medium | 75 | Pattern matched, supporting evidence present but weaker | ~15–25% |
| High | 85 | Pattern matched with strong corroborating keyword or checksum validation | ~5–10% |

\* *Percentage estimates are illustrative based on typical enterprise tenant observations. Microsoft does not publish exact distribution figures.*

> **Microsoft Learn:** [Sensitive information type entity definitions — confidence level mapping](https://learn.microsoft.com/en-us/purview/sit-sensitive-information-type-entity-definitions) · [More on confidence levels](https://learn.microsoft.com/en-us/purview/sensitive-information-type-learn-about#more-on-confidence-levels)

**What the module does:** It passes `ConfidenceLevel = 'high'` directly to `Export-ContentExplorerData`. This filter runs **in Purview's backend** before any record is returned to the script. You never download the Low or Medium records — they are excluded at the source. This also means the API call itself is faster and uses less bandwidth.

**How to control it:** Set `-MinConfidence` to `High` (default), `Medium`, or `Low`. Start with `High` for a remediation queue. Use `Medium` for a broader discovery pass when you want to understand the full scope before tightening.

**Expected reduction:** With `High` confidence only, you typically keep 5–10% of the records that would have come back at all confidence levels. A credential SIT with 50,000 Low+Medium+High hits may produce 2,500–5,000 at High only.

> **Microsoft Learn:** [More on confidence levels](https://learn.microsoft.com/en-us/purview/sensitive-information-type-learn-about#more-on-confidence-levels)

> **Microsoft recommendation:** *"You should use high confidence level patterns with low counts, say five to ten, and low confidence patterns with higher counts, say 20 or more."* This directly informs the `-MinMatchCount` guidance in Layer 5.

---

### Layer 3 — Two-phase aggregate scanning (`-UseAggregate`)

**The problem:** SharePoint tenants with thousands of sites would require the script to page through every site sequentially even when 95% of sites have zero high-confidence credential matches.

**What the module does:** With `-UseAggregate`, it makes one fast API call using the `-Aggregate` flag that returns only a **count per site** — no file records, no content, just a site URL and a number. Sites with zero matches are immediately discarded. The script then makes item-level API calls scoped only to the confirmed sites.

**Example:** If 50 of your 5,000 SharePoint sites have high-confidence *General password* matches, the module makes 51 API calls (1 aggregate + 50 scoped) instead of paging through the full 5,000-site index. This does not reduce the record count in your results, but it dramatically reduces runtime and API load.

**Fallback:** If `-Aggregate` is not yet available in your tenant (it is currently in private preview), the function automatically falls back to a full workload scan without failing.

> **Microsoft Learn:** [Export-ContentExplorerData — -Aggregate parameter](https://learn.microsoft.com/en-us/powershell/module/exchange/export-contentexplorerdata#-aggregate)

---

### Layer 4 — Client-side deduplication

**The problem:** When site-scoped calls are active, the same file can surface from multiple scope passes. For example, a file at a site confirmed by the aggregate pass that also matches a `-SiteUrls` filter may be returned twice.

**What the module does:** After all API calls complete, records are grouped by `SIT + Workload + SiteUrl + FileName + Path`. Only the highest-confidence copy of each unique combination is kept. This collapses accidental duplicates without collapsing genuinely distinct matches (different SITs on the same file are kept separately; different files with the same name in different sites are kept separately).

---

### Layer 5 — Client-side false-positive filters

These run after the API has returned records but before anything reaches your pipeline. They are the tools you use to tune against *your specific tenant's noise profile* based on what you see in the first scan.

The `MatchCount` property in every result object tells you how many times the SIT pattern matched inside the file — this is the key diagnostic column for deciding how to set these filters.

#### `-IncludeFileTypes` — extension allowlist

The most impactful single filter. After the first scan, look at the `FileType` column. You will typically find a large proportion of matches in:

- `.log` — application and system log files (timestamps, session tokens, diagnostic output)
- `.etl`, `.evtx` — event trace and Windows event logs
- `.tmp`, `.bak` — temporary and backup files
- Binary formats — compiled DLLs, images, database files matched on binary coincidences

None of these realistically contain credentials that need remediation. By specifying:

```powershell
-IncludeFileTypes @('docx','xlsx','pdf','txt','csv','ps1','psm1','py','js','json','xml','config','env','yaml','yml','ini')
```

Everything not in that list is dropped before it reaches you. A credential hit in a `.log` file is an application runtime artefact, not a secret someone intentionally stored.

#### `-ExcludeFileTypes` — extension blocklist

A softer alternative when you want to keep most file types but suppress specific known-noisy ones:

```powershell
-ExcludeFileTypes @('log','tmp','bak','etl','evtx','blg')
```

#### `-ExcludePathPattern` — suppress known-safe subtrees

After the first scan, look at the `Path` column. You will typically find patterns like:

- `/sites/IT-Archive/` — decommissioned content
- `/sites/Backup/` — backup document libraries
- `/personal/leaver@contoso.com/` — former employee OneDrive accounts

These are real matches but not actionable. A regex drops them without affecting other paths:

```powershell
-ExcludePathPattern '(?i)(archive|backup|leaver|offboarded|test|temp|recycle)'
```

#### `-MinMatchCount` — instance count threshold

Purview records how many times a SIT pattern matched inside a file. A document that contains the word "password" once in a 200-page policy document is almost certainly not a credential store. A file where the *General password* SIT matched 8 times is very likely to actually contain credentials.

```powershell
-MinMatchCount 2   # require at least 2 instances before reporting the file
```

This is the module's implementation of the Microsoft Purview guidance to *"adjust the instance count to reduce false positives."*

Microsoft's own SIT documentation explicitly recommends: *"You should use high confidence level patterns with low counts, say five to ten, and low confidence patterns with higher counts, say 20 or more."*

> **Note:** `MatchCount` is read from the `SensitiveInfoTypeCount`, `MatchCount`, or `Count` property of each API record (whichever is present). If the API does not return a count for your tenant, `-MinMatchCount` is silently skipped and all records are kept — results are never suppressed due to missing data.

> **Microsoft Learn:** [Optimize DLP policy configuration — instance count](https://learn.microsoft.com/en-us/purview/deploymentmodels/depmod-reduce-false-positives#optimize-dlp-policy-configuration)

---

## What to expect against extremely large record sets

A realistic progression for a typical tenant:

| Run | Parameters active | Expected result count |
|---|---|---|
| Content Explorer raw (all SITs, all confidence) | — | **Millions+** |
| SIT scoping to 29 credential types | `-SitNames $credSITs` | ~50,000–200,000 |
| + High confidence (server-side) | `-MinConfidence High` | ~5,000–20,000 |
| + File type restriction | `-IncludeFileTypes @(...)` | ~1,000–5,000 |
| + Path exclusion | `-ExcludePathPattern '...'` | ~500–2,000 |
| + Instance threshold | `-MinMatchCount 2` | **~100–500** |

The final number is a **high-confidence, actionable queue** — not every SIT hit in your tenant, but the ones where Purview's own classifier is most confident, in file types that can realistically contain intentional secrets, in paths that are not archive or backup subtrees, with enough pattern instances that the match is unlikely to be coincidental.

---

## Two important things this module does NOT do

### It returns file locations, not the secret itself

`Export-ContentExplorerData` returns the **location** of a file that matched a SIT pattern — the site URL, file name, path, SIT type, and confidence level. It does **NOT** return the matched text or the secret value itself.

To view the actual content of a flagged file you need the **Content Explorer Content Viewer** role in Microsoft Purview, and you would open the file directly from the Content Explorer UI or via the `Path` URL in the results.

### Results are not real-time

Content Explorer is a classification **index**, not a live query. According to Microsoft documentation:

> *"It can take up to seven days for counts to update in content explorer and 14 days for files that are in SharePoint."*

This means:

- A file uploaded today may not appear in results for up to 14 days.
- A file that was deleted may still appear in results until the index catches up.
- Re-running the scan after several days may surface additional findings not present in the first run.

> **Microsoft Learn:** [Content Explorer — Export](https://learn.microsoft.com/en-us/purview/data-classification-content-explorer#export)

### SIT definition updates do not reclassify existing files

This is a critical limitation to understand when interpreting results:

> *"When you update a Sensitive Information Type (SIT) definition, the classification of existing files doesn't change unless you alter those files. This behavior means that the new SIT definition doesn't automatically reclassify the existing files; only the files that you modify are reevaluated and classified based on the updated SIT criteria. However, any new file you create after modifying the SIT definition is evaluated according to the latest SIT definition."*

In practice this means: if Microsoft updated a SIT's detection patterns after a file was last modified, that file's Content Explorer classification still reflects the old patterns. Results from this module are bounded by when each file was last crawled by Purview.

> **Microsoft Learn:** [Content Explorer — Provide match or not a match accuracy feedback](https://learn.microsoft.com/en-us/purview/data-classification-content-explorer#provide-match-or-not-a-match-accuracy-feedback-in-content-explorer)

---

## Recommended scan sequence

### Step 1 — Baseline scan

Understand the volume before applying filters. Use all default settings with High confidence:

```powershell
Find-SecretsInM365 -ConnectIPPS -MinConfidence High -UseAggregate -ExportResults
```

Open the CSV in `$env:TEMP\Find-Secrets\`. Look at the **FileType**, **Path**, and **MatchCount** columns. Identify the patterns in the noise that are specific to your tenant.

---

### Step 2 — Tuned scan

Apply filters based on what you observed in step 1:

```powershell
$credSITs = @(
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
    'GitHub Personal Access Token',
    'Amazon S3 Client Secret Access Key',
    'Google API key',
    'Slack access token',
    'General password',
    'Client secret / API key',
    'Http authorization header',
    'SQL Server connection string',
    'X.509 certificate private key'
)

Find-SecretsInM365 `
    -ConnectIPPS `
    -SitNames           $credSITs `
    -Workloads          SPO, ODB `
    -MinConfidence      High `
    -UseAggregate `
    -IncludeFileTypes   @('docx','xlsx','pdf','txt','csv','ps1','psm1','py','js','json','xml','config','env','yaml','yml','ini') `
    -ExcludePathPattern '(?i)(archive|backup|test|temp|recycle)' `
    -MinMatchCount      2 `
    -ExportResults
```

---

### Targeting a single SIT

You can pass a single string directly to `-SitNames` at any point — no array syntax required. This is useful when you want to investigate one specific SIT in isolation, validate a finding, or diagnose why a particular type is producing noise.

#### Investigate a single SIT across all workloads

```powershell
Find-SecretsInM365 -SitNames 'General password' -MinConfidence High -ExportResults
```

#### Investigate a single SIT on SharePoint only

```powershell
Find-SecretsInM365 -SitNames 'General password' -Workloads SPO -MinConfidence High
```

#### Investigate a single SIT with all FP filters applied

```powershell
Find-SecretsInM365 `
    -SitNames           'General password' `
    -Workloads          SPO, ODB `
    -MinConfidence      High `
    -IncludeFileTypes   @('docx','xlsx','pdf','txt','csv','ps1','py','json','xml','config','env','yaml') `
    -ExcludePathPattern '(?i)(archive|backup|test|temp|recycle)' `
    -MinMatchCount      2 `
    -ExportResults
```

#### Investigate a single SIT on a specific site

```powershell
Find-SecretsInM365 `
    -SitNames   'GitHub Personal Access Token' `
    -SiteUrls   'https://contoso.sharepoint.com/sites/Engineering' `
    -Workloads  SPO `
    -MinConfidence High
```

#### Compare noise levels across confidence levels for one SIT

A common use case is understanding how much noise a broad SIT like *General password* produces at each confidence level before committing to a full scan:

```powershell
foreach ($level in @('High', 'Medium', 'Low')) {
    $count = (Find-SecretsInM365 -SitNames 'General password' -Workloads SPO -MinConfidence $level).Count
    [pscustomobject]@{ Confidence = $level; Matches = $count }
}
```

This gives you a quick signal-to-noise profile for that SIT in your tenant before you run a broader scan.

> **Tip:** Use `-Verbose` when targeting a single SIT to see the raw property names the API is returning for your tenant. This is useful when diagnosing why `MatchCount`, `FileName`, or `Path` may be empty in your results.

```powershell
Find-SecretsInM365 -SitNames 'General password' -Workloads SPO -MinConfidence High -Verbose
```

---

### Step 3 — Review and triage

```powershell
$findings = Find-SecretsInM365 -ConnectIPPS -SitNames $credSITs -MinConfidence High -UseAggregate

# See the distribution by SIT and confidence
$findings | Group-Object SIT | Sort-Object Count -Descending | Format-Table Name, Count

# See the distribution by file type
$findings | Group-Object FileType | Sort-Object Count -Descending | Format-Table Name, Count

# See files with the most matches (most likely to be genuine credential stores)
$findings | Sort-Object MatchCount -Descending | Select-Object -First 20 |
    Format-Table SIT, MatchCount, Confidence, FileName, SiteUrl -AutoSize

# Filter to only items with a known high-risk SIT
$findings | Where-Object { $_.SIT -like '*Personal Access Token*' -or $_.SIT -like '*secret*' } |
    Format-Table SIT, Confidence, FileName, SiteUrl -AutoSize
```

---

### Step 4 — Verify remediation

After files identified in step 2 have been remediated (secrets rotated, files deleted or relabelled), re-run the same command. Allow up to **14 days** for SharePoint re-indexing to confirm the file no longer appears in results.

---

## Required permissions

| Role | Effect |
|---|---|
| Neither role | API returns an error or zero results |
| **Content Explorer List Viewer** | Results returned but `FileName` is blank on every row |
| **List Viewer + Content Explorer Content Viewer** | Full output — all properties including `FileName` populated |

Assign both roles in the Microsoft Purview compliance portal under **Roles & Scopes → Role groups**.

> **Microsoft Learn:** [Content Explorer permissions](https://learn.microsoft.com/en-us/purview/data-classification-content-explorer#permissions)
