# Yuzu TAR Roadmap — Create GitHub Issues (PowerShell)
# Can be run from any directory.

param(
    [string]$Repo = "OWNER/REPO"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Creating TAR issues in repo: $Repo"
Write-Host ""

Write-Host "[1/9] Implement core TAR abstraction and read-only query layer"
gh issue create --repo "$Repo" `
  --title "Implement core TAR abstraction and read-only query layer" `
  --body @'
## Summary
Implement the core 1E Client Activity Record (TAR) abstraction in Yuzu as a read-only, system-managed persistent data layer.

## Scope
- Add a read-only TAR layer
- Treat TAR as system-managed persistent storage, not user-managed tables
- Model TAR around Live, Hourly, Daily, and Monthly table classes where applicable
- Enforce SELECT-only access semantics
- Prevent create, update, and delete operations from user workflows

## Acceptance criteria
- TAR data can be queried via SELECT
- TAR tables cannot be created, modified, or deleted through Yuzu workflows
- The abstraction supports Live, Hourly, Daily, and Monthly table classes where applicable
- Internal interfaces clearly separate TAR from normal user-managed tables

## Notes
This is the foundation for all subsequent TAR work.
'@

Write-Host "[2/9] Implement TAR source registry and schema metadata"
gh issue create --repo "$Repo" `
  --title "Implement TAR source registry and schema metadata" `
  --body @'
## Summary
Create the source registry and schema model for all supported TAR sources and table variants.

## Scope
- Add support for TAR sources including:
  - ARP cache entries
  - Boot performance
  - Device interaction
  - Device performance
  - Device resource demand
  - DNS resolutions
  - Operating System performance
  - Performance event
  - Process executions
  - Process stabilizations
  - Process usage
  - Sensitive processes
  - Software installations
  - Software interaction
  - Software performance
  - TCP outbound connections
  - User usage
- Build a source registry mapping source to supported table variants
- Add schema metadata showing:
  - fields common to all table variants
  - fields present in Live only
  - fields present in aggregated tables only

## Acceptance criteria
- All documented TAR sources exist in the registry
- Registry identifies which table granularities each source supports
- Schema metadata is available programmatically for query validation and tooling
- Registry and schema definitions are covered by tests
'@

Write-Host "[3/9] Implement table granularity rules and source-specific exceptions"
gh issue create --repo "$Repo" `
  --title "Implement table granularity rules and source-specific exceptions" `
  --body @'
## Summary
Encode all documented exceptions where a TAR source does not expose the standard Live, Hourly, Daily, Monthly table set.

## Scope
- Handle sources that do not expose all four table types
- Explicitly support:
  - Boot performance as Live-only
  - Process usage as Daily-only
  - User usage as Daily-only
  - SoftwarePerformance.DiskUsage roll-up into $SoftwarePerformance
  - SoftwarePerformance.ProcessNetworkUsage roll-up into $SoftwarePerformance
- Ensure table discovery and query generation respect these exceptions

## Acceptance criteria
- Unsupported table variants are not exposed
- Query-builder and validators reject invalid source/table combinations
- Software performance roll-up inputs are represented correctly
- Tests cover all documented exceptions
'@

Write-Host "[4/9] Implement aggregation and retention behavior for TAR tables"
gh issue create --repo "$Repo" `
  --title "Implement aggregation and retention behavior for TAR tables" `
  --body @'
## Summary
Implement TAR aggregation flow and retention policy handling.

## Scope
- Make aggregation configurable through client configuration settings
- Reflect default aggregation on a 60-second cycle
- Ensure Hourly, Daily, and Monthly tables aggregate from Live data, not from one another
- Support independent retention policies for Live, Hourly, Daily, and Monthly tables

## Acceptance criteria
- Aggregation scheduling is configurable
- Default aggregation cycle is 60 seconds
- Aggregated tables are derived from Live data only
- Retention can be configured independently per granularity
- Tests verify roll-up behavior and retention independence
'@

Write-Host "[5/9] Implement timestamp handling and query helper functions"
gh issue create --repo "$Repo" `
  --title "Implement timestamp handling and query helper functions" `
  --body @'
## Summary
Standardize TAR timestamp handling and add helper utilities for query-time conversions.

## Scope
- Store and expose TS as Unix epoch seconds in UTC
- Provide helper functions or examples equivalent to EPOCHTOJSON
- Truncate timestamps appropriately in aggregated tables
- Document UTC epoch handling expectations for downstream consumers

## Acceptance criteria
- TS is consistently represented as UTC epoch seconds
- Aggregated table timestamps are truncated at the correct granularity
- Query helper utilities or examples exist for timestamp conversion
- Tests verify timestamp correctness across Live and aggregated tables
'@

Write-Host "[6/9] Implement schema-aware query validation and case-sensitive query behavior"
gh issue create --repo "$Repo" `
  --title "Implement schema-aware query validation and case-sensitive query behavior" `
  --body @'
## Summary
Prevent invalid TAR queries by enforcing schema-aware field availability and documented case-sensitivity behavior.

## Scope
- Prevent invalid query generation for fields that exist only in Live or only in aggregated tables
- Add validation for known patterns such as:
  - ProcessId in $TCP_Live
  - ConnectionCount in aggregated TCP tables
  - Live-only interaction second fields
  - Aggregated interaction minute/count fields
- Ensure TAR string comparisons are treated as case-sensitive unless explicitly compensated for
- Add helper/query-builder behavior to prefer LIKE where appropriate, such as ProcessName

## Acceptance criteria
- Invalid field/table combinations are rejected before execution
- Case-sensitive behavior is documented and reflected in query generation
- LIKE-based helpers exist for process-name lookups
- Tests cover validation and case-sensitivity edge cases
'@

Write-Host "[7/9] Implement TAR source-specific behaviors and edge cases"
gh issue create --repo "$Repo" `
  --title "Implement TAR source-specific behaviors and edge cases" `
  --body @'
## Summary
Implement documented source-specific semantics that require custom handling beyond the generic TAR model.

## Scope
### TCP outbound connections
- Capture TCP only, not UDP
- Handle startup initial connection scan behavior
- Document and test possible double-counting across client restarts
- Preserve distinction between attempted and successfully established connections
- Support documented IPv6 caveat on Windows

### User usage
- Implement $UserUsage_Daily semantics only
- Model LastSeen, Duration, midnight rollover, and cross-day carry-over behavior
- Group by SID and Username
- Exclude system and service accounts

### Process stabilizations
- Support Live-only ProcessId and StabilizationTimeMs
- Support aggregated ExecutionCount and TotalStabilizationTimeMs
- Preserve lower-case aggregation behavior for UserName and ExecutableName

### Software installations
- Support Live-only IsUninstall
- Support aggregated InstallCount and UninstallCount

### Software performance
- Implement parent $SoftwarePerformance source and roll-up behavior
- Support Windows/macOS schema parity, including nullable metrics on macOS

## Acceptance criteria
- Each listed source behavior is implemented exactly as documented
- Edge-case semantics are covered by tests
- Query results match expected behavior for restart, rollover, and aggregation scenarios
'@

Write-Host "[8/9] Implement OS compatibility mapping and capture configuration surface"
gh issue create --repo "$Repo" `
  --title "Implement OS compatibility mapping and capture configuration surface" `
  --body @'
## Summary
Add platform support metadata and configuration controls for TAR capture behavior.

## Scope
- Add per-source OS support metadata for Windows, macOS, and Linux
- Encode source-specific capture methods such as ETW vs polling where relevant
- Mark constrained or unsupported legacy Windows versions in the compatibility matrix
- Expose configuration for capture-source enablement/disablement where documented
- Support polling instead of ETW for Windows sources where applicable
- Add configuration support for monitored process stabilization lists
- Document performance and scale trade-offs for monitored process stabilization

## Acceptance criteria
- OS support metadata is available per TAR source
- Capture configuration options are exposed where documented
- ETW vs polling behavior is configurable where applicable
- Compatibility matrix reflects supported and constrained platforms
- Tests cover configuration handling and platform mapping
'@

Write-Host "[9/9] Add TAR query examples, test coverage, and implementer documentation"
gh issue create --repo "$Repo" `
  --title "Add TAR query examples, test coverage, and implementer documentation" `
  --body @'
## Summary
Complete the TAR implementation with developer-facing examples, comprehensive tests, and implementation documentation.

## Scope
- Ship example queries for:
  - daily aggregation queries
  - timestamp conversion
  - case-sensitive process-name querying
- Include examples similar to:
  - SELECT ... FROM $TCP_Daily
  - LIKE "chrome.exe"
  - EPOCHTOJSON(TS)
- Add unit and integration coverage for:
  - every source/table combination
  - live-to-aggregate rollups
  - retention independence across granularities
  - restart behavior and double-capture caveats for TCP
  - midnight rollover and carry-over logic for User Usage
  - schema validation for granularity-specific fields
- Add implementer documentation covering:
  - TAR as forensics/inventory capability
  - compressed, encrypted local persistence
  - persistence across client upgrade, uninstall, and reinstall unless deleted
  - startup detection behavior for events that occurred while the client was not running
  - device impact expectations

## Acceptance criteria
- Example queries are available to developers
- Test coverage exists for all critical TAR behaviors
- Implementer documentation is complete and internally consistent
- The TAR implementation is supportable without relying on the original upstream page
'@

Write-Host ""
Write-Host "Done! All 9 TAR issues created."
