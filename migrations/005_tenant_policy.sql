-- Apply after 001_identity.sql and 002_lifecycle.sql in the same trusted schema.
-- Coordinate a freeze of every Gate writer before applying this migration or
-- running the audited policy migrator. The migrator performs an exclusive lock.

DO $migration$
BEGIN
  IF EXISTS (
    SELECT tenant_id
    FROM irondome_gate_identity
    GROUP BY tenant_id
    HAVING pg_catalog.count(DISTINCT policy_version) > 1
  ) THEN
    RAISE EXCEPTION 'Gate policy migration found tenants with mixed policy versions';
  END IF;
END
$migration$;

CREATE TABLE irondome_gate_tenant_policy (
  tenant_id text COLLATE "C" PRIMARY KEY
    CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  policy_version text COLLATE "C" NOT NULL
    CHECK (octet_length(policy_version) BETWEEN 1 AND 128),
  CONSTRAINT irondome_gate_tenant_policy_tenant_version_key UNIQUE (tenant_id, policy_version)
);

INSERT INTO irondome_gate_tenant_policy (tenant_id, policy_version)
SELECT tenant_id, min(policy_version COLLATE "C")
FROM irondome_gate_identity
GROUP BY tenant_id;

ALTER TABLE irondome_gate_identity
  ADD CONSTRAINT irondome_gate_identity_policy_fkey
  FOREIGN KEY (tenant_id, policy_version)
  REFERENCES irondome_gate_tenant_policy (tenant_id, policy_version)
  DEFERRABLE INITIALLY IMMEDIATE;

-- Bind the schema once at installation so PostgreSQL can cache the seed plan.
-- No SQL formatting or replanning is needed on each identity insertion.
DO $definition$
BEGIN
  EXECUTE pg_catalog.format($sql$
CREATE FUNCTION %1$I.irondome_gate_seed_tenant_policy()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $body$
BEGIN
  INSERT INTO %1$I.irondome_gate_tenant_policy (tenant_id, policy_version)
  VALUES (NEW.tenant_id, NEW.policy_version) ON CONFLICT (tenant_id) DO NOTHING;
  RETURN NEW;
END
$body$;
$sql$, pg_catalog.current_schema());
END
$definition$;

CREATE TRIGGER irondome_gate_identity_seed_tenant_policy
BEFORE INSERT ON irondome_gate_identity
FOR EACH ROW
EXECUTE FUNCTION irondome_gate_seed_tenant_policy();

COMMENT ON TABLE irondome_gate_tenant_policy IS
  'One canonicalization policy per tenant; retained after its last identity is revoked.';
