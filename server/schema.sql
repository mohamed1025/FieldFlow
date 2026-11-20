CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  industry TEXT NOT NULL DEFAULT 'صيانة عامة',
  phone TEXT,
  email TEXT,
  address TEXT,
  logo_url TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  plan_code TEXT NOT NULL DEFAULT 'trial',
  subscription_status TEXT NOT NULL DEFAULT 'trial' CHECK (subscription_status IN ('trial','active','past_due','cancelled','expired')),
  billing_cycle TEXT DEFAULT 'monthly',
  trial_ends_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '14 days'),
  subscription_ends_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner','manager','technician','platform_admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS users_tenant_idx ON users(tenant_id);

CREATE TABLE IF NOT EXISTS customers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  address TEXT,
  site_name TEXT,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS customers_tenant_idx ON customers(tenant_id);

CREATE TABLE IF NOT EXISTS work_orders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  customer_id UUID NOT NULL REFERENCES customers(id),
  code TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  category TEXT NOT NULL DEFAULT 'صيانة عامة',
  priority TEXT NOT NULL DEFAULT 'normal' CHECK (priority IN ('low','normal','high','urgent')),
  status TEXT NOT NULL DEFAULT 'new',
  assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
  scheduled_at TIMESTAMPTZ,
  address TEXT,
  country_code VARCHAR(2) NOT NULL DEFAULT 'EG',
  city TEXT,
  timezone TEXT NOT NULL DEFAULT 'Africa/Cairo',
  expected_duration_minutes INTEGER,
  site_contact_name TEXT,
  site_contact_phone TEXT,
  task_instructions TEXT,
  access_instructions TEXT,
  required_materials TEXT,
  safety_notes TEXT,
  task_checklist TEXT,
  task_checklist_progress JSONB NOT NULL DEFAULT '[]'::jsonb,
  service_price NUMERIC(12,2) NOT NULL DEFAULT 0,
  currency VARCHAR(3) NOT NULL DEFAULT 'EGP',
  price_includes_tax BOOLEAN NOT NULL DEFAULT TRUE,
  payment_method TEXT NOT NULL DEFAULT 'cash',
  payment_account_holder TEXT,
  payment_bank_name TEXT,
  payment_bank_swift VARCHAR(20),
  payment_bank_country VARCHAR(2),
  payment_account_number TEXT,
  payment_instructions TEXT,
  payment_link TEXT,
  payment_status TEXT NOT NULL DEFAULT 'unpaid',
  paid_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
  collected_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
  payment_reference TEXT,
  payment_recorded_at TIMESTAMPTZ,
  payment_recorded_by UUID REFERENCES users(id) ON DELETE SET NULL,
  payment_verified_at TIMESTAMPTZ,
  payment_verified_by UUID REFERENCES users(id) ON DELETE SET NULL,
  started_at TIMESTAMPTZ,
  waiting_parts_at TIMESTAMPTZ,
  technician_completed_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, code)
);
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS country_code VARCHAR(2) NOT NULL DEFAULT 'EG';
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS city TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT 'Africa/Cairo';
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS expected_duration_minutes INTEGER;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS site_contact_name TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS site_contact_phone TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS task_instructions TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS access_instructions TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS required_materials TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS safety_notes TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS task_checklist TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS task_checklist_progress JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS service_price NUMERIC(12,2) NOT NULL DEFAULT 0;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS currency VARCHAR(3) NOT NULL DEFAULT 'EGP';
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS price_includes_tax BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_method TEXT NOT NULL DEFAULT 'cash';
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_account_holder TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_bank_name TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_bank_swift VARCHAR(20);
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_bank_country VARCHAR(2);
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_account_number TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_instructions TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_link TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_status TEXT NOT NULL DEFAULT 'unpaid';
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS paid_amount NUMERIC(12,2) NOT NULL DEFAULT 0;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS collected_amount NUMERIC(12,2) NOT NULL DEFAULT 0;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_reference TEXT;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_recorded_at TIMESTAMPTZ;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_recorded_by UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_verified_at TIMESTAMPTZ;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS payment_verified_by UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS waiting_parts_at TIMESTAMPTZ;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS technician_completed_at TIMESTAMPTZ;
ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;
ALTER TABLE work_orders DROP CONSTRAINT IF EXISTS work_orders_status_check;
ALTER TABLE work_orders DROP CONSTRAINT IF EXISTS work_orders_status_check_v2;
ALTER TABLE work_orders ADD CONSTRAINT work_orders_status_check_v2 CHECK (status IN ('new','assigned','in_progress','waiting_parts','awaiting_review','completed','cancelled'));
ALTER TABLE work_orders DROP CONSTRAINT IF EXISTS work_orders_payment_method_check;
ALTER TABLE work_orders ADD CONSTRAINT work_orders_payment_method_check CHECK (payment_method IN ('cash','bank_transfer','card','online','on_account','not_required'));
ALTER TABLE work_orders DROP CONSTRAINT IF EXISTS work_orders_payment_status_check;
ALTER TABLE work_orders ADD CONSTRAINT work_orders_payment_status_check CHECK (payment_status IN ('unpaid','pending_verification','partial','paid','waived'));
ALTER TABLE work_orders DROP CONSTRAINT IF EXISTS work_orders_country_code_check;
ALTER TABLE work_orders ADD CONSTRAINT work_orders_country_code_check CHECK (BTRIM(country_code) ~ '^[A-Z]{2}$');
ALTER TABLE work_orders DROP CONSTRAINT IF EXISTS work_orders_currency_check;
ALTER TABLE work_orders ADD CONSTRAINT work_orders_currency_check CHECK (BTRIM(currency) ~ '^[A-Z]{3}$');
ALTER TABLE work_orders DROP CONSTRAINT IF EXISTS work_orders_price_nonnegative_check;
ALTER TABLE work_orders ADD CONSTRAINT work_orders_price_nonnegative_check CHECK (service_price >= 0 AND paid_amount >= 0 AND collected_amount >= 0);
CREATE INDEX IF NOT EXISTS orders_tenant_status_idx ON work_orders(tenant_id,status,created_at DESC);
CREATE INDEX IF NOT EXISTS orders_tenant_schedule_idx ON work_orders(tenant_id,scheduled_at);

CREATE TABLE IF NOT EXISTS visits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  work_order_id UUID NOT NULL REFERENCES work_orders(id) ON DELETE CASCADE,
  technician_id UUID REFERENCES users(id) ON DELETE SET NULL,
  check_in_at TIMESTAMPTZ DEFAULT NOW(),
  check_out_at TIMESTAMPTZ,
  technician_notes TEXT,
  audio_path TEXT,
  audio_mime TEXT,
  transcript TEXT,
  extracted_data JSONB NOT NULL DEFAULT '{}'::jsonb,
  photos JSONB NOT NULL DEFAULT '[]'::jsonb,
  report_body TEXT,
  missing_information JSONB NOT NULL DEFAULT '[]'::jsonb,
  latitude NUMERIC(10,7),
  longitude NUMERIC(10,7),
  report_status TEXT NOT NULL DEFAULT 'draft' CHECK (report_status IN ('draft','pending','approved','rejected')),
  manager_notes TEXT,
  public_token UUID UNIQUE,
  approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
  approved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS visits_tenant_idx ON visits(tenant_id, created_at DESC);
ALTER TABLE visits ADD COLUMN IF NOT EXISTS latitude NUMERIC(10,7);
ALTER TABLE visits ADD COLUMN IF NOT EXISTS longitude NUMERIC(10,7);
ALTER TABLE visits ADD COLUMN IF NOT EXISTS technician_name_snapshot TEXT;
UPDATE visits v SET technician_name_snapshot=u.name FROM users u WHERE v.technician_id=u.id AND v.technician_name_snapshot IS NULL;

CREATE TABLE IF NOT EXISTS quotations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  customer_id UUID NOT NULL REFERENCES customers(id),
  work_order_id UUID REFERENCES work_orders(id) ON DELETE SET NULL,
  code TEXT NOT NULL,
  title TEXT NOT NULL,
  items JSONB NOT NULL DEFAULT '[]'::jsonb,
  subtotal NUMERIC(12,2) NOT NULL DEFAULT 0,
  tax NUMERIC(12,2) NOT NULL DEFAULT 0,
  total NUMERIC(12,2) NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','sent','accepted','rejected','expired')),
  valid_until DATE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, code)
);

CREATE TABLE IF NOT EXISTS invoices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  customer_id UUID NOT NULL REFERENCES customers(id),
  work_order_id UUID REFERENCES work_orders(id) ON DELETE SET NULL,
  code TEXT NOT NULL,
  title TEXT NOT NULL,
  items JSONB NOT NULL DEFAULT '[]'::jsonb,
  subtotal NUMERIC(12,2) NOT NULL DEFAULT 0,
  tax NUMERIC(12,2) NOT NULL DEFAULT 0,
  total NUMERIC(12,2) NOT NULL DEFAULT 0,
  paid_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'unpaid' CHECK (status IN ('unpaid','partial','paid','overdue','cancelled')),
  due_date DATE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, code)
);

CREATE TABLE IF NOT EXISTS contracts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  customer_id UUID NOT NULL REFERENCES customers(id),
  title TEXT NOT NULL,
  service_description TEXT,
  frequency TEXT NOT NULL DEFAULT 'every_6_months',
  starts_on DATE NOT NULL,
  ends_on DATE,
  next_visit_on DATE,
  amount NUMERIC(12,2) DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','ended')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reminders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
  work_order_id UUID REFERENCES work_orders(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT,
  due_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','done','cancelled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS payment_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  plan_code TEXT NOT NULL,
  billing_cycle TEXT NOT NULL CHECK (billing_cycle IN ('monthly','yearly')),
  amount NUMERIC(12,2) NOT NULL,
  method TEXT NOT NULL CHECK (method IN ('vodafone_cash','instapay','gateway')),
  transaction_reference TEXT,
  payer_phone TEXT,
  proof_path TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  admin_note TEXT,
  reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS payments_pending_idx ON payment_requests(status,created_at DESC);

CREATE TABLE IF NOT EXISTS platform_settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
  actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id UUID,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
