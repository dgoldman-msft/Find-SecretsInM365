# Comparison: Content Explorer UI vs Find-SecretsInM365 Module

Both the Microsoft Purview Content Explorer UI and this module query the same underlying classification index via the same `Export-ContentExplorerData` API. The difference is in how much of that API's capability is exposed and how much can be automated.

> **Microsoft Learn reference:** [Get started with Content Explorer](https://learn.microsoft.com/en-us/purview/data-classification-content-explorer)

---

## How to reach Content Explorer in the UI

[purview.microsoft.com](https://purview.microsoft.com) → **Solutions** → **Data Lifecycle Management** → **Explorers** → **Content explorer**

---

## Step-by-step equivalence

### 1. Scope to credential SITs — equivalent to `-SitNames`

**In the UI:**
In the left panel, expand **Sensitive info types** and check each SIT you want to examine — for example, *Azure DevOps personal access token*, *GitHub Personal Access Token*, *Amazon S3 Client Secret Access Key*, etc. Only items matching the checked types appear in the main pane.

**What you cannot do in the UI:**
There is no confidence level filter in the left panel filter tree. The item count shown against each SIT is the **total across Low + Medium + High** combined — there is no way to restrict to High-confidence matches only before you start browsing. This is the single most significant practical difference between the UI and the module.

---

### 2. Scope to a workload — equivalent to `-Workloads`

**In the UI:**
Under **All locations** in the main pane, select one of:

| UI label | Module value |
|---|---|
| SharePoint sites | `SPO` |
| OneDrive accounts | `ODB` |
| Exchange mailboxes | `EXO` |
| Teams messages | `Teams` |

To see multiple workloads you must switch between them manually, one at a time.

**In the module:**
`-Workloads SPO, ODB, EXO, Teams` scans all four in a single run sequentially.

---

### 3. Drill into a specific site — equivalent to `-SiteUrls`

**In the UI:**
After selecting **SharePoint sites**, use the **Filter** tool (appears when you drill into a location) and search by:

| Search type | Example |
|---|---|
| Full site URL | `https://contoso.sharepoint.com/sites/Engineering` |
| File name | `deploy-config.txt` |
| Text at start of file name | `deploy` |
| Text after an underscore in file name | `config` |
| File extension | `txt` |

**In the module:**
`-SiteUrls 'https://contoso.sharepoint.com/sites/Engineering'` passes the URL directly to the API, so filtering happens server-side before any records are returned.

---

### 4. Export results — equivalent to `-ExportResults`

**In the UI:**
Use the **Export** button in the top-right of the pane. It downloads a `.csv` of whatever is currently in focus in the main pane — one SIT, one workload, one location at a time. Each export is a separate manual action.

> **Microsoft documentation note:** *"It can take up to seven days for counts to update in content explorer and 14 days for files that are in SharePoint."*
> Source: [Content Explorer — Export](https://learn.microsoft.com/en-us/purview/data-classification-content-explorer#export)

**In the module:**
`-ExportResults` automatically exports one CSV per workload to `-LogDirectory` (`$env:TEMP\Find-Secrets\` by default) at the end of each workload scan. The file path is printed to the console on completion.

---

### 5. Save a custom view — equivalent to running the module repeatedly

**In the UI:**
Use **Save views** to create a named view with your chosen SITs, labels, or classifiers pre-selected. A saved view can be set as the default so it loads automatically the next time Content Explorer is opened. This is the UI's closest equivalent to re-running the module on a schedule.

**In the module:**
Store your parameter set in a script and re-run it on demand or via a scheduled task. Results are structured objects that can be compared, diffed, or fed into downstream tooling.

---

### 6. View actual file content — not available in this module

**In the UI:**
Double-click any item in Content Explorer to open it natively and view its contents — this requires the **Content Explorer Content Viewer** role. This is the only way to confirm whether a flagged match is a genuine secret or a false positive without opening the file from its source location.

**In the module:**
The module returns only **metadata** (file location, SIT name, confidence, path). It intentionally does not expose file content. To inspect flagged files, use the `Path` property in the output to navigate directly to the file, or open Content Explorer with the Content Viewer role.

> **Microsoft Learn:** [Required permissions to access items in Content Explorer](https://learn.microsoft.com/en-us/purview/data-classification-content-explorer#required-permissions-to-access-items-in-content-explorer)

---

## Capability comparison

| Capability | Content Explorer UI | Find-SecretsInM365 module |
|---|---|---|
| Filter by confidence level (High / Medium / Low) | No — all levels shown combined, no pre-filter | Yes — server-side via `-MinConfidence` |
| Bulk scan across all credential SITs in one operation | No — one SIT checked at a time, manual | Yes — default SIT list of 29 credential types |
| Cross-workload scan in one run | No — must switch workload manually | Yes — `-Workloads SPO, ODB, EXO, Teams` |
| Scope to specific sites server-side | Partial — filter after drilling in | Yes — `-SiteUrls` passed to API directly |
| Two-phase aggregate scan (skip empty sites) | No | Yes — `-UseAggregate` (SPO/ODB only) |
| Deduplication across scope passes | No | Yes — deduped by `SIT + Path`, highest confidence retained |
| Structured output for downstream processing | No — CSV only, one location at a time | Yes — `SecretAuditResult` objects in the PowerShell pipeline |
| Automated / scheduled / scripted runs | No | Yes |
| View actual file content | Yes — with Content Viewer role | No — metadata only |
| All confidence levels visible | Yes — always | Optional — use `-MinConfidence Low` |
| Save named views for repeat use | Yes — Save views feature | Yes — save as a `.ps1` script |

---

## When to use each

### Use Content Explorer UI when:
- Investigating a **single specific file** or site after the module has flagged it
- You need to **read the file content** to confirm whether a match is genuine
- You want a **quick visual browse** without writing any code
- You are verifying that Purview has finished indexing content before running a full scan

### Use the module when:
- Running a **tenant-wide audit** across all workloads
- You need results **scoped to High confidence only** (the UI cannot do this)
- You want a **CSV report** generated automatically across all SITs and workloads
- You need **repeatable, scheduled, or scripted** scanning
- You are feeding results into a downstream workflow or ticketing system

---

## Required roles (both UI and module)

| Role | Required for |
|---|---|
| **Content Explorer List Viewer** | Access the Content Explorer tab and use `Export-ContentExplorerData` via PowerShell |
| **Content Explorer Content Viewer** | View **file names** in list view (file names may contain sensitive data per Microsoft docs) and open file contents in the UI |

Both roles are relevant to this module. The **List Viewer** role is the minimum to call `Export-ContentExplorerData`. The **Content Viewer** role is additionally required if you need the `FileName` property in results to be populated — because per the Microsoft documentation, file names are considered potentially sensitive and require the Content Viewer role to be returned. Assign both roles to ensure complete output from the module.

> **Microsoft Learn:** [Content Explorer permissions](https://learn.microsoft.com/en-us/purview/data-classification-content-explorer#permissions) — *"The data classification content viewer role is also required to view the name of items in list view, which might contain sensitive data."*
> **Licensing note:** An **E5 licence** (or equivalent add-on) is required for all credential scanning SITs.
> Source: [E5 licensing for credential scanning SITs](https://learn.microsoft.com/en-us/purview/sensitive-information-type-learn-about#licensing)
