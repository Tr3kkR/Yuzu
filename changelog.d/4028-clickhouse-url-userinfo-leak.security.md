- **Settings analytics view no longer leaks ClickHouse URL credentials.** The Settings →
  Analytics dashboard fragment (and its new `GET /api/v1/settings/analytics` REST twin) rendered
  the configured ClickHouse URL verbatim, masking only the separate `clickhouse_password` field —
  a URL carrying embedded userinfo credentials (`clickhouse://user:pass@host:9000/db`) leaked the
  credential regardless of that masking. The URL is now stripped of embedded userinfo
  unconditionally before either surface renders it, and the raw password is never read into a
  response at all (only whether it is set).
