-- Indexes for retention pruning.
--
-- The three history tables grew without limit. Nothing ever deleted from them,
-- so a Cogwheel that had been running for a year held every classifier verdict
-- and every configuration change it had ever seen. That is a disk problem on a
-- small appliance disk, and -- more to the point for a thing that exists to
-- stop tracking -- it is a permanent, unasked-for record of a household's
-- browsing sitting on a box in the hall.
--
-- Pruning is `DELETE ... WHERE created_at < ?`, and created_at is stored as an
-- RFC 3339 string, which sorts lexicographically in the same order as time for
-- any fixed offset. Without these indexes that delete is a full table scan on
-- exactly the tables that have grown largest, on the slowest storage the
-- product targets.
--
-- IF NOT EXISTS on every statement: migrations are re-applied on upgrade paths
-- that have already seen them, and an index that already exists is not an
-- error worth failing an upgrade over.
CREATE INDEX IF NOT EXISTS idx_security_events_created_at
  ON security_events (created_at);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
  ON audit_events (created_at);
