# ClickHouse Setup for Yuzu Analytics

## Prerequisites

- ClickHouse 23.3+ (for `DateTime64` and `LowCardinality` support)
- Network connectivity from Yuzu server to ClickHouse HTTP interface (default port 8123)

## Database and Table DDL

```sql
CREATE DATABASE IF NOT EXISTS yuzu;

CREATE TABLE yuzu.yuzu_events (
    tenant_id       LowCardinality(String)  DEFAULT 'default',
    agent_id        String                  DEFAULT '',
    session_id      String                  DEFAULT '',
    event_type      LowCardinality(String),
    event_time      DateTime64(3, 'UTC'),
    ingest_time     DateTime64(3, 'UTC')    DEFAULT now64(3),
    plugin          LowCardinality(String)  DEFAULT '',
    capability      LowCardinality(String)  DEFAULT '',
    correlation_id  String                  DEFAULT '',
    severity        Enum8('debug'=0,'info'=1,'warn'=2,'error'=3,'critical'=4) DEFAULT 'info',
    source          LowCardinality(String)  DEFAULT 'server',
    hostname        String                  DEFAULT '',
    os              LowCardinality(String)  DEFAULT '',
    arch            LowCardinality(String)  DEFAULT '',
    agent_version   LowCardinality(String)  DEFAULT '',
    principal       String                  DEFAULT '',
    principal_role  LowCardinality(String)  DEFAULT '',
    attributes      String                  DEFAULT '{}',
    payload         String                  DEFAULT '{}',
    schema_version  UInt8                   DEFAULT 1
) ENGINE = MergeTree()
  PARTITION BY toYYYYMM(event_time)
  ORDER BY (tenant_id, event_type, event_time, agent_id)
  TTL event_time + INTERVAL 365 DAY;
```

## Indexes

```sql
ALTER TABLE yuzu.yuzu_events ADD INDEX idx_agent_id agent_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE yuzu.yuzu_events ADD INDEX idx_correlation_id correlation_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE yuzu.yuzu_events ADD INDEX idx_hostname hostname TYPE bloom_filter GRANULARITY 4;
```

## Materialized Views

### Command Duration Percentiles (Hourly)

```sql
CREATE MATERIALIZED VIEW yuzu.mv_command_duration_hourly
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, plugin, hour)
AS
SELECT
    tenant_id,
    plugin,
    toStartOfHour(event_time) AS hour,
    quantileState(0.5)(JSONExtractFloat(payload, 'duration_ms'))  AS p50,
    quantileState(0.95)(JSONExtractFloat(payload, 'duration_ms')) AS p95,
    quantileState(0.99)(JSONExtractFloat(payload, 'duration_ms')) AS p99,
    countState() AS total
FROM yuzu.yuzu_events
WHERE event_type = 'command.completed'
GROUP BY tenant_id, plugin, hour;
```

### Agent Activity Heatmap (Daily)

```sql
CREATE MATERIALIZED VIEW yuzu.mv_agent_activity_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, agent_id, day, event_type)
AS
SELECT
    tenant_id,
    agent_id,
    toDate(event_time) AS day,
    event_type,
    count() AS event_count
FROM yuzu.yuzu_events
GROUP BY tenant_id, agent_id, day, event_type;
```

## Yuzu Server Configuration

```bash
yuzu-server \
    --clickhouse-url http://clickhouse.internal:8123 \
    --clickhouse-database yuzu \
    --clickhouse-table yuzu_events \
    --clickhouse-user default \
    --clickhouse-password '' \
    --analytics-drain-interval 10 \
    --analytics-batch-size 100
```

## Useful Queries

### Events per type (last 24h)

```sql
SELECT event_type, count() AS cnt
FROM yuzu.yuzu_events
WHERE event_time > now() - INTERVAL 1 DAY
GROUP BY event_type
ORDER BY cnt DESC;
```

### Active agents (last hour)

```sql
SELECT DISTINCT agent_id
FROM yuzu.yuzu_events
WHERE event_type = 'agent.connected'
  AND event_time > now() - INTERVAL 1 HOUR;
```

### Failed commands by plugin

```sql
SELECT plugin, count() AS failures
FROM yuzu.yuzu_events
WHERE event_type = 'command.completed'
  AND JSONExtractString(payload, 'status') = 'error'
  AND event_time > now() - INTERVAL 7 DAY
GROUP BY plugin
ORDER BY failures DESC;
```

### Login attempts by IP

```sql
SELECT
    JSONExtractString(attributes, 'source_ip') AS ip,
    event_type,
    count() AS cnt
FROM yuzu.yuzu_events
WHERE event_type IN ('auth.login', 'auth.login_failed')
  AND event_time > now() - INTERVAL 1 DAY
GROUP BY ip, event_type
ORDER BY cnt DESC;
```
