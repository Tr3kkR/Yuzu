- **Guardian agents no longer re-send audit records the server already has.** (Dormant with the
  rest of the Guardian journal machinery until the Spark detection path becomes authoritative.)
  A delivered batch leaves the agent's in-memory send window as soon as it ships, and window
  membership was the only test for "already delivered" - so on the next replay pass the batch
  looked new again, and was re-read, re-placed and re-sent, for as long as retention kept it.
  Nothing was lost and the server de-duplicated the copies, but each agent spent its whole
  replay budget re-delivering records that had already arrived, and across a fleet that is a
  permanent floor of redundant traffic and ingest that grows with the number of endpoints.
  Delivery is already recorded durably on disk; that record simply was not consulted when
  choosing what to replay. It is now, and an already-delivered batch is re-offered only after a
  restart or a reconnect - the points at which a send genuinely may have been lost in flight -
  so the safety net is kept where it can pay and dropped where it cannot.
