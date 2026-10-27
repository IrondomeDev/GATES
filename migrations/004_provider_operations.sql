-- Optional durable Auth0/Supabase lifecycle operations; apply after 001 and 002.
CREATE TABLE irondome_gate_provider_operation (
  namespace text COLLATE "C" NOT NULL CHECK (octet_length(namespace) BETWEEN 1 AND 512),
  tenant_id text COLLATE "C" NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  user_id text COLLATE "C" NOT NULL CHECK (octet_length(user_id) BETWEEN 1 AND 512),
  operation_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('email-change','delete')),
  generation text NOT NULL CHECK (octet_length(generation) BETWEEN 1 AND 256),
  previous_email text CHECK (octet_length(previous_email) BETWEEN 1 AND 254),
  next_email text CHECK (octet_length(next_email) BETWEEN 1 AND 254),
  expected_revision bigint CHECK (expected_revision > 0),
  status text NOT NULL CHECK (status IN ('pending','complete','deleting','deleted')),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (namespace, tenant_id, user_id),
  CHECK ((kind='email-change' AND previous_email IS NOT NULL AND next_email IS NOT NULL AND expected_revision IS NOT NULL AND status IN ('pending','complete')) OR
    (kind='delete' AND previous_email IS NULL AND next_email IS NULL AND expected_revision IS NULL AND status IN ('deleting','deleted')))
);
COMMENT ON TABLE irondome_gate_provider_operation IS
  'PII: current provider operation and immutable generation; deletes retain no email. Keep terminal delete intents for recovery.';
