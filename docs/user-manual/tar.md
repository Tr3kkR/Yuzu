# Timeline Activity Record (TAR)

The TAR plugin continuously captures system state snapshots and records changes as timestamped events in a local SQLite database on each endpoint. It enables retrospective investigation of "what happened on this machine" without requiring pre-configured logging or SIEM integration.

## What TAR captures

TAR monitors four categories of system activity:

| Category | Collection interval | Events detected |
|----------|-------------------|-----------------|
| **Processes** | 60 seconds (fast) | Process started, process stopped |
| **Network connections** | 60 seconds (fast) | Connection opened, connection closed |
| **Services** | 300 seconds (slow) | Service started, stopped, state changed |
| **User sessions** | 300 seconds (slow) | User login, user logout |

Each collection cycle takes a snapshot of the current state, compares it to the previous snapshot, and records only the differences as events. This keeps the database compact while providing full visibility into system changes.

## Querying TAR data

### From the Yuzu dashboard

Use the **TAR Query** instruction to search events by time range and type.

### From the REST API

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "query",
  "parameters": {
    "from": "1711000000",
    "to": "1711100000",
    "type": "process",
    "limit": "500"
  }
}
```

### Query parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `from` | No | 0 | Start of time range (Unix epoch seconds) |
| `to` | No | now | End of time range (Unix epoch seconds) |
| `type` | No | all | Filter: `process`, `network`, `service`, or `user` |
| `limit` | No | 1000 | Maximum results (max 10000) |

### Output format

Each event is output as a pipe-delimited line:

```
timestamp|event_type|event_action|snapshot_id|detail_json
```

Example:

```
1711050123|process|started|1711050123001|{"pid":1234,"ppid":1,"name":"nginx","cmdline":"nginx -g daemon off;","user":"www-data"}
1711050123|network|connected|1711050123001|{"proto":"tcp","local_addr":"0.0.0.0","local_port":80,"remote_addr":"10.0.0.5","remote_port":54321,"state":"ESTABLISHED","pid":1234}
1711050423|service|state_changed|1711050423002|{"name":"sshd","display_name":"OpenSSH","status":"stopped","prev_status":"running","startup_type":"automatic","prev_startup_type":"automatic"}
1711050423|user|login|1711050423002|{"user":"admin","domain":"CORP","logon_type":"remote","session_id":"pts/0"}
```

### JSON export

Use the `export` action for JSON output suitable for integration with Splunk, ClickHouse, or ELK:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "export",
  "parameters": { "type": "process", "limit": "100" }
}
```

## Configuration

Use the `configure` action to adjust TAR behavior.

| Setting | Valid range | Default | Description |
|---------|-----------|---------|-------------|
| `retention_days` | 1-365 | 7 | Days to keep events before automatic purge |
| `fast_interval` | 10-3600 | 60 | Seconds between process/network collections |
| `slow_interval` | 30-7200 | 300 | Seconds between service/user collections |
| `redaction_patterns` | JSON array | See below | Patterns for command-line redaction (case-insensitive) |

**Validation rules:**

- When both `fast_interval` and `slow_interval` are provided, `fast_interval` must be less than `slow_interval`.
- `redaction_patterns` must be a JSON array of non-empty strings.

Example:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "configure",
  "parameters": {
    "retention_days": "14",
    "fast_interval": "30"
  }
}
```

## Security: command-line redaction

TAR automatically redacts sensitive command-line arguments before storing process events. Any command line matching a redaction pattern has its `cmdline` field replaced with `[REDACTED by TAR]`.

Default redaction patterns:

```json
["*password*", "*secret*", "*token*", "*api_key*", "*credential*"]
```

Patterns use case-insensitive substring matching. The `*` characters at the start and end indicate substring semantics (e.g., `*password*` matches any command line containing "password" in any case).

To customize:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "configure",
  "parameters": {
    "redaction_patterns": "[\"*password*\",\"*secret*\",\"*token*\",\"*private_key*\"]"
  }
}
```

## Checking TAR status

The `status` action returns database health information:

```
record_count|15234
oldest_timestamp|1710950000
newest_timestamp|1711050423
db_size_bytes|2097152
retention_days|7
```

## Forcing an immediate snapshot

The `snapshot` action triggers an immediate full collection of all four categories, useful before a maintenance window or at the start of an investigation:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "snapshot"
}
```

## Performance impact

TAR is designed for minimal performance overhead:

- **Fast collection** (processes + network): typically completes in under 100ms
- **Slow collection** (services + users): typically completes in under 200ms
- **Database size**: varies by system activity; a typical endpoint generates 1-5 MB per day
- **CPU**: negligible between collection cycles; brief spike during snapshot + diff
- **Automatic purge**: old events are removed hourly based on the retention setting
- **WAL mode**: SQLite Write-Ahead Logging ensures reads never block writes

## Warehouse Query System

TAR includes a typed data warehouse that replaces the legacy flat `tar_events` table with structured, tiered tables optimized for different query time horizons.

### Warehouse tables

Table names use `$`-prefixed identifiers (e.g., `$Process_Live`) which the agent translates to real SQLite table names at execution time. There are four capture sources, each with multiple granularity tiers:

| Source | Live | Hourly | Daily | Monthly |
|--------|:----:|:------:|:-----:|:-------:|
| **Process** | `$Process_Live` (5000 rows) | `$Process_Hourly` (24h) | `$Process_Daily` (31d) | `$Process_Monthly` (12mo) |
| **TCP** | `$TCP_Live` (5000 rows) | `$TCP_Hourly` (24h) | `$TCP_Daily` (31d) | `$TCP_Monthly` (12mo) |
| **Service** | `$Service_Live` (5000 rows) | `$Service_Hourly` (24h) | -- | -- |
| **User** | `$User_Live` (5000 rows) | -- | `$User_Daily` (31d) | -- |

- **Live** tables hold the most recent raw events with a 5000-row cap (oldest rows are evicted).
- **Hourly** tables aggregate counts and summaries per hour, retained for 24 hours.
- **Daily** tables aggregate per day, retained for 31 days.
- **Monthly** tables aggregate per month, retained for 12 months.
- Service only has live and hourly tiers. User only has live and daily tiers.

### Key columns by table type

**Process tables:** `ts`, `name`, `pid`, `ppid`, `cmdline`, `user`, `action` (started/stopped). Aggregated tiers add `start_count`, `stop_count`.

**TCP tables:** `ts`, `process_name`, `pid`, `remote_addr`, `remote_port`, `local_port`, `proto`, `state`. Aggregated tiers add `connect_count`.

**Service tables:** `ts`, `name`, `status`, `prev_status`, `action` (started/stopped/state_changed). Hourly tier adds `change_count`.

**User tables:** `ts`, `user`, `domain`, `logon_type`, `action` (login/logout). Daily tier adds `login_count`.

### Querying with SQL

Use the `tar.sql` action to execute SELECT queries against warehouse tables:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "sql",
  "parameters": {
    "sql": "SELECT name, pid, cmdline FROM $Process_Live ORDER BY ts DESC LIMIT 50"
  }
}
```

Pre-built queries are available in `content/definitions/tar_warehouse.yaml`, covering common use cases like recent processes, TCP connections by process, listening ports, hourly summaries, service state changes, user sessions, and process trees.

### Rollup aggregation

The warehouse automatically runs a rollup aggregation cycle every 15 minutes. Each cycle:

1. Aggregates live-tier data into hourly summaries
2. Aggregates hourly data into daily summaries
3. Aggregates daily data into monthly summaries
4. Enforces retention limits on each tier

To force an immediate rollup, use the `tar.rollup` action.

### Safety controls

SQL queries are validated at multiple levels:

- **Server-side:** Only SELECT statements are permitted. A keyword blocklist rejects INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, ATTACH, DETACH, PRAGMA, VACUUM, and REINDEX.
- **Agent-side:** Table names must use the `$`-prefixed whitelist (`$Process_Live`, `$TCP_Hourly`, etc.). Only a single SQL statement is allowed. Queries exceeding 4KB are rejected.

## Data storage

TAR events are stored in `{data_dir}/tar.db` (SQLite), where `data_dir` is the agent's configured data directory. The database uses:

- WAL journal mode for concurrent performance
- `busy_timeout=5000` for thread safety
- `secure_delete=ON` to zero deleted data
- Indexes on `timestamp`, `(event_type, timestamp)`, and `snapshot_id`
