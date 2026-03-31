-- Yuzu ClickHouse schema — auto-applied on first container start
-- See docs/clickhouse-setup.md for full documentation

CREATE DATABASE IF NOT EXISTS yuzu;

CREATE TABLE IF NOT EXISTS yuzu.yuzu_events (
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
  TTL toDate(event_time) + INTERVAL 365 DAY;

-- Bloom filter indexes for fast agent/correlation lookups
ALTER TABLE yuzu.yuzu_events ADD INDEX IF NOT EXISTS idx_agent_id agent_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE yuzu.yuzu_events ADD INDEX IF NOT EXISTS idx_correlation_id correlation_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE yuzu.yuzu_events ADD INDEX IF NOT EXISTS idx_hostname hostname TYPE bloom_filter GRANULARITY 4;

-- Materialized view: command duration percentiles (hourly rollup)
CREATE MATERIALIZED VIEW IF NOT EXISTS yuzu.mv_command_duration_hourly
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

-- Materialized view: agent activity heatmap (daily rollup)
CREATE MATERIALIZED VIEW IF NOT EXISTS yuzu.mv_agent_activity_daily
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
