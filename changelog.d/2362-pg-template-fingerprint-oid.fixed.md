- **`PgTestTemplate` shared-key verification no longer fails spuriously on PostgreSQL
  before 18 (#2362).** The structural fingerprint included `information_schema`
  constraint names, and on PG < 18 a `NOT NULL` is surfaced as an auto-named `CHECK`
  constraint whose name embeds the table/attribute OIDs — so two databases built by
  identical setups fingerprinted differently and every cross-file shared-key replay
  check failed. Nullability now rides on the column arm's `is_nullable` and the
  auto-named `NOT NULL` checks are excluded, keeping divergence detectable while making
  the fingerprint OID-independent on every supported server version. CI (PG 18) was
  unaffected; a local PG 16 cluster failed ~46 `[pg]` cases before this fix.
