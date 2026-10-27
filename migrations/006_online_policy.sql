-- Online dual-epoch ownership backend. Apply in the same trusted schema as
-- migrations 001, 002, and 005. It creates parallel tables without rewriting
-- existing identities. Installing row triggers briefly takes SHARE ROW
-- EXCLUSIVE locks on the legacy tables until the migration transaction ends.

CREATE TABLE irondome_gate_online_policy (
  policy_version text COLLATE "C" PRIMARY KEY
    CHECK (octet_length(policy_version) BETWEEN 1 AND 128),
  rules jsonb NOT NULL CHECK (pg_catalog.jsonb_typeof(rules) = 'object')
);

CREATE TABLE irondome_gate_online_tenant (
  tenant_id text COLLATE "C" PRIMARY KEY
    CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  active_epoch uuid NOT NULL,
  active_version text COLLATE "C" NOT NULL
    REFERENCES irondome_gate_online_policy (policy_version),
  pending_epoch uuid,
  pending_version text COLLATE "C"
    REFERENCES irondome_gate_online_policy (policy_version),
  cursor_user text COLLATE "C"
    CHECK (cursor_user IS NULL OR octet_length(cursor_user) BETWEEN 1 AND 512),
  scan_done boolean NOT NULL DEFAULT false,
  legacy_mode boolean NOT NULL DEFAULT false,
  protocol_enforced boolean NOT NULL DEFAULT false,
  CONSTRAINT irondome_gate_online_tenant_pending_pair_check
    CHECK ((pending_epoch IS NULL) = (pending_version IS NULL)),
  CONSTRAINT irondome_gate_online_tenant_pending_epoch_check
    CHECK (pending_epoch IS NULL OR pending_epoch <> active_epoch)
);

CREATE TABLE irondome_gate_online_owner (
  tenant_id text COLLATE "C" NOT NULL
    REFERENCES irondome_gate_online_tenant (tenant_id) ON DELETE CASCADE,
  user_id text COLLATE "C" NOT NULL CHECK (octet_length(user_id) BETWEEN 1 AND 512),
  -- Exact last provider-verified delivery address. Canonical keys are stored
  -- separately and may change by epoch; this source must remain exact.
  delivery_email text COLLATE "C" NOT NULL CHECK (octet_length(delivery_email) BETWEEN 1 AND 254),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  claimed_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT irondome_gate_online_owner_pkey PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE irondome_gate_online_key (
  tenant_id text COLLATE "C" NOT NULL,
  epoch uuid NOT NULL,
  canonical_email text COLLATE "C" NOT NULL CHECK (octet_length(canonical_email) BETWEEN 1 AND 254),
  user_id text COLLATE "C" NOT NULL CHECK (octet_length(user_id) BETWEEN 1 AND 512),
  CONSTRAINT irondome_gate_online_key_pkey PRIMARY KEY (tenant_id, epoch, canonical_email),
  CONSTRAINT irondome_gate_online_key_epoch_user_key UNIQUE (tenant_id, epoch, user_id),
  CONSTRAINT irondome_gate_online_key_owner_fkey
    FOREIGN KEY (tenant_id, user_id)
    REFERENCES irondome_gate_online_owner (tenant_id, user_id) ON DELETE CASCADE
);

-- Supports owner deletion cascades; the uniqueness index above places epoch
-- between tenant_id and user_id and therefore cannot serve this lookup.
CREATE INDEX irondome_gate_online_key_owner_idx
  ON irondome_gate_online_key (tenant_id, user_id);

CREATE TABLE irondome_gate_online_gap (
  tenant_id text COLLATE "C" NOT NULL
    REFERENCES irondome_gate_online_tenant (tenant_id) ON DELETE CASCADE,
  epoch uuid NOT NULL,
  user_id text COLLATE "C" NOT NULL CHECK (octet_length(user_id) BETWEEN 1 AND 512),
  reason text COLLATE "C" NOT NULL
    CHECK (reason IN ('source-required', 'invalid-source', 'invalid-target', 'collision')),
  PRIMARY KEY (tenant_id, epoch, user_id)
);

-- Fence legacy identity/policy writes after the tenant protocol is enabled.
-- Every legacy write first takes the same shared tenant advisory lock as the
-- online writer. The protocol-enforcement update therefore drains in-flight
-- legacy writes before committing, and later legacy writes observe the fence.
DO $definition$
BEGIN
  EXECUTE pg_catalog.format($sql$
CREATE FUNCTION %1$I.irondome_gate_online_legacy_write_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $body$
DECLARE
  target_tenant text;
  protocol_on boolean;
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'tenant identity is immutable';
  END IF;
  IF TG_OP = 'DELETE' THEN
    target_tenant := OLD.tenant_id;
  ELSE
    target_tenant := NEW.tenant_id;
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock_shared(
    pg_catalog.hashtextextended(
      'irondome-gate-online-v1|' || %2$L || '|tenant|' || target_tenant, 0));

  IF pg_catalog.current_setting('irondome_gate.online_write', true) = 'on' THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
  END IF;

  SELECT tenant.protocol_enforced INTO protocol_on
    FROM %1$I.irondome_gate_online_tenant AS tenant
    WHERE tenant.tenant_id = target_tenant
    FOR SHARE;
  IF protocol_on IS TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'online Gate write protocol required';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END
$body$;
$sql$, pg_catalog.current_schema(), pg_catalog.current_schema());
END
$definition$;

DO $definition$
BEGIN
  EXECUTE pg_catalog.format($sql$
CREATE FUNCTION %1$I.irondome_gate_online_policy_immutable()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $body$
BEGIN
  IF OLD.policy_version IS DISTINCT FROM NEW.policy_version OR OLD.rules IS DISTINCT FROM NEW.rules THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'online Gate policy catalog is immutable';
  END IF;
  RETURN NEW;
END
$body$;

CREATE TRIGGER irondome_gate_online_policy_immutable_update
BEFORE UPDATE ON %1$I.irondome_gate_online_policy
FOR EACH ROW EXECUTE FUNCTION %1$I.irondome_gate_online_policy_immutable();

CREATE TRIGGER irondome_gate_online_protocol_guard_identity
BEFORE INSERT OR UPDATE OR DELETE ON %1$I.irondome_gate_identity
FOR EACH ROW EXECUTE FUNCTION %1$I.irondome_gate_online_legacy_write_guard();

CREATE TRIGGER irondome_gate_online_protocol_guard_policy
BEFORE INSERT OR UPDATE OR DELETE ON %1$I.irondome_gate_tenant_policy
FOR EACH ROW EXECUTE FUNCTION %1$I.irondome_gate_online_legacy_write_guard();

CREATE TRIGGER irondome_gate_online_protocol_guard_revoked
BEFORE INSERT OR UPDATE OR DELETE ON %1$I.irondome_gate_revoked
FOR EACH ROW EXECUTE FUNCTION %1$I.irondome_gate_online_legacy_write_guard();
$sql$, pg_catalog.current_schema());
END
$definition$;

COMMENT ON TABLE irondome_gate_online_policy IS
  'Immutable canonical policy catalog used by the online dual-epoch backend.';
COMMENT ON TABLE irondome_gate_online_tenant IS
  'Per-tenant active and pending policy epochs; a policy flip does not change user revisions.';
COMMENT ON TABLE irondome_gate_online_owner IS
  'Stable provider principal and exact last verified delivery address for online policy migration.';
COMMENT ON TABLE irondome_gate_online_key IS
  'Unique canonical mailbox keys, isolated by tenant and policy epoch.';
COMMENT ON TABLE irondome_gate_online_gap IS
  'Per-owner reason an online target epoch key is not yet safely present; no email values are stored.';
