-- Apply with the application's normal migration runner, inside a transaction.
-- No pending/unverified identities belong in this table.
-- policy_version is metadata, deliberately NOT part of either uniqueness key.
CREATE TABLE irondome_gate_identity (
  tenant_id text COLLATE "C" NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  user_id text COLLATE "C" NOT NULL CHECK (octet_length(user_id) BETWEEN 1 AND 512),
  canonical_email text COLLATE "C" NOT NULL CHECK (octet_length(canonical_email) BETWEEN 1 AND 254),
  policy_version text COLLATE "C" NOT NULL CHECK (octet_length(policy_version) BETWEEN 1 AND 128),
  claimed_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT irondome_gate_identity_pkey PRIMARY KEY (tenant_id, canonical_email),
  CONSTRAINT irondome_gate_identity_user_key UNIQUE (tenant_id, user_id)
);

COMMENT ON TABLE irondome_gate_identity IS
  'Verified canonical identity ownership only; never a source of authentication or account linking.';
COMMENT ON COLUMN irondome_gate_identity.policy_version IS
  'Rule version used at claim time; not a uniqueness namespace. Rule changes require collision review.';
