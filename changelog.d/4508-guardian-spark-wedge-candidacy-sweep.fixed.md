- **Guardian spark (lands dormant: `prefer_spark_` stays false, so no production
  arm or disarm takes the new path until the flip): wedge withdrawal tracks
  pending claims directly.** Derive late-arm adoption candidacy from retained
  claims, preserve committed generations during publication failures, and
  sweep candidacy before rule withdrawal and full-sync teardown (#4508).
