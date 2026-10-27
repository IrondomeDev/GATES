-- Apply after 001, in the same trusted schema using the host migration runner.
-- Coordinate/stop all old Gate writers before upgrading: V1 has no tombstone check.
ALTER TABLE irondome_gate_identity ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0);

CREATE TABLE irondome_gate_revoked (
  tenant_id text COLLATE "C" NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  user_id text COLLATE "C" NOT NULL CHECK (octet_length(user_id) BETWEEN 1 AND 512),
  revoked_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, user_id)
);
COMMENT ON TABLE irondome_gate_revoked IS
  'Terminal user revocations fence delayed callbacks. User IDs cannot be reused. No email retained.';
