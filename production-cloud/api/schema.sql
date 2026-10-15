CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS organizations(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE NOT NULL,
  display_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS memberships(
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  org_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  role text NOT NULL CHECK(role IN ('owner','admin','asset_manager','auditor','approver','viewer')),
  PRIMARY KEY(user_id,org_id)
);

CREATE TABLE IF NOT EXISTS locations(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  parent_id uuid,
  location_type text NOT NULL CHECK(location_type IN ('site','building','floor','area','room','department')),
  name text NOT NULL,
  code text,
  address text,
  description text,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT locations_parent_fk FOREIGN KEY(parent_id) REFERENCES locations(id) ON DELETE RESTRICT,
  CONSTRAINT locations_no_self_parent CHECK(parent_id IS NULL OR parent_id <> id),
  UNIQUE(org_id,id)
);

CREATE INDEX IF NOT EXISTS locations_org_parent ON locations(org_id,parent_id);
CREATE INDEX IF NOT EXISTS locations_org_type ON locations(org_id,location_type);
CREATE UNIQUE INDEX IF NOT EXISTS locations_org_parent_name
  ON locations(org_id,COALESCE(parent_id,'00000000-0000-0000-0000-000000000000'::uuid),lower(name));

CREATE TABLE IF NOT EXISTS custodians(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL,
  email text,
  department text,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vendors(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL,
  contact_name text,
  email text,
  phone text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS asset_categories(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  parent_id uuid,
  code text NOT NULL,
  name text NOT NULL,
  description text,
  is_system boolean NOT NULL DEFAULT false,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT asset_categories_parent_fk FOREIGN KEY(parent_id) REFERENCES asset_categories(id) ON DELETE RESTRICT,
  CONSTRAINT asset_categories_no_self_parent CHECK(parent_id IS NULL OR parent_id <> id),
  UNIQUE(org_id,code)
);
CREATE INDEX IF NOT EXISTS asset_categories_org_parent ON asset_categories(org_id,parent_id);
CREATE UNIQUE INDEX IF NOT EXISTS asset_categories_system_code ON asset_categories(code) WHERE org_id IS NULL;

INSERT INTO asset_categories(org_id,code,name,is_system) VALUES
(NULL,'IT','IT Equipment',true),(NULL,'CCTV-ELV','CCTV / ELV',true),(NULL,'ELEC','Electronics',true),
(NULL,'APP','Appliances',true),(NULL,'FURN','Furniture',true),(NULL,'MACH','Machinery',true),
(NULL,'TOOLS','Tools',true),(NULL,'VEH','Vehicles',true),(NULL,'OTHER','Other',true)
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS assets(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  location_id uuid,
  custodian_id uuid,
  vendor_id uuid,
  tag text NOT NULL,
  serial text,
  asset_name text NOT NULL,
  category text,
  category_id uuid,
  brand text,
  model text,
  cost numeric(18,2) NOT NULL DEFAULT 0,
  useful_life_years numeric(8,2) NOT NULL DEFAULT 5,
  salvage_value numeric(18,2) NOT NULL DEFAULT 0,
  depreciation_method text NOT NULL DEFAULT 'straight_line',
  purchase_date date,
  condition text NOT NULL DEFAULT 'Good' CHECK(condition IN ('Excellent','Good','Fair','Poor','Damaged')),
  status text NOT NULL DEFAULT 'Active',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(org_id,tag),
  CONSTRAINT assets_category_fk FOREIGN KEY(category_id) REFERENCES asset_categories(id) ON DELETE SET NULL,
  CONSTRAINT assets_location_fk FOREIGN KEY(location_id) REFERENCES locations(id) ON DELETE RESTRICT,
  CONSTRAINT assets_custodian_fk FOREIGN KEY(custodian_id) REFERENCES custodians(id) ON DELETE SET NULL,
  CONSTRAINT assets_vendor_fk FOREIGN KEY(vendor_id) REFERENCES vendors(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS assets_org_location ON assets(org_id,location_id);

CREATE TABLE IF NOT EXISTS asset_transfers(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  from_location_id uuid REFERENCES locations(id) ON DELETE RESTRICT,
  to_location_id uuid NOT NULL REFERENCES locations(id) ON DELETE RESTRICT,
  requested_by uuid REFERENCES users(id),
  approved_by uuid REFERENCES users(id),
  transferred_at timestamptz,
  reason text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS approvals(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  entity text NOT NULL,
  entity_id uuid NOT NULL,
  status text NOT NULL CHECK(status IN ('pending','approved','rejected')),
  requested_by uuid REFERENCES users(id),
  reviewed_by uuid REFERENCES users(id),
  comments text,
  created_at timestamptz NOT NULL DEFAULT now(),
  reviewed_at timestamptz
);

CREATE TABLE IF NOT EXISTS service_records(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  service_date date NOT NULL,
  service_type text NOT NULL,
  vendor_id uuid REFERENCES vendors(id) ON DELETE SET NULL,
  cost numeric(18,2) NOT NULL DEFAULT 0,
  notes text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events(
  sequence bigserial PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_id uuid,
  action text NOT NULL,
  entity text NOT NULL,
  entity_id text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}',
  previous_hash text NOT NULL,
  hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_org_sequence ON audit_events(org_id,sequence);

CREATE TABLE IF NOT EXISTS attachments(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_id uuid REFERENCES assets(id) ON DELETE CASCADE,
  object_key text NOT NULL,
  content_type text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notifications(
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  title text NOT NULL,
  body text NOT NULL,
  read_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- All organization-owned records are linked through org_id. Application authorization
-- must verify membership before every read/write; database RLS can be enabled when
-- the deployment's connection-role/session-variable strategy is finalized.


-- Standard subcategories
INSERT INTO asset_categories(org_id,parent_id,code,name,is_system)
SELECT NULL,p.id,v.code,v.name,true
FROM asset_categories p
JOIN (VALUES
('IT','IT-LAP','Laptop'),('IT','IT-DESK','Desktop'),('IT','IT-MON','Monitor'),('IT','IT-SRV','Server'),('IT','IT-PRN','Printer'),('IT','IT-UPS','UPS'),('IT','IT-SW','Network switch'),('IT','IT-RT','Router'),
('CCTV-ELV','CCTV-CAM','Camera'),('CCTV-ELV','CCTV-NVR','NVR/DVR'),('CCTV-ELV','CCTV-ACC','Access control'),('CCTV-ELV','CCTV-INT','Intercom'),('CCTV-ELV','CCTV-FIRE','Fire alarm'),('CCTV-ELV','CCTV-RACK','Rack'),
('ELEC','ELEC-TV','TV'),('ELEC','ELEC-PROJ','Projector'),('ELEC','ELEC-DISP','Display'),('ELEC','ELEC-SOUND','Sound system'),
('APP','APP-FRIDGE','Refrigerator'),('APP','APP-AC','Air conditioner'),('APP','APP-MICRO','Microwave'),('APP','APP-WASH','Washing machine')
) AS v(parent_code,code,name) ON p.code=v.parent_code AND p.org_id IS NULL
ON CONFLICT DO NOTHING;