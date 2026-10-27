-- Optional Better Auth lifecycle metadata. Apply in the same trusted schema after 001/002.
-- Tokens are provider-signed and remain with the mail transport; only their fingerprints persist.
CREATE TABLE irondome_gate_better_auth_change (
  tenant_id text COLLATE "C" NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  user_id text COLLATE "C" NOT NULL CHECK (octet_length(user_id) BETWEEN 1 AND 512),
  token_hash text COLLATE "C" NOT NULL CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  purpose text NOT NULL CHECK (purpose IN ('verify-email','change-email')),
  previous_delivery_email text COLLATE "C" NOT NULL CHECK (octet_length(previous_delivery_email) BETWEEN 1 AND 254),
  next_delivery_email text COLLATE "C" NOT NULL CHECK (octet_length(next_delivery_email) BETWEEN 1 AND 254),
  expected_revision bigint NOT NULL CHECK (expected_revision > 0),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, token_hash)
);
CREATE INDEX irondome_gate_better_auth_change_expiry ON irondome_gate_better_auth_change (expires_at);
CREATE INDEX irondome_gate_better_auth_change_user ON irondome_gate_better_auth_change (tenant_id, user_id);
COMMENT ON TABLE irondome_gate_better_auth_change IS
  'PII: exact delivery addresses and revision bound to a hashed Better Auth change token; purge expired records.';
