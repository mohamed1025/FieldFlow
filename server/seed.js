require('dotenv').config();
const bcrypt = require('bcryptjs');
const { pool, initDatabase } = require('./db');

async function seed() {
  await initDatabase();
  const production = process.env.NODE_ENV === 'production';
  const bootstrap = {
    admin: process.env.PLATFORM_ADMIN_PASSWORD || (production ? '' : 'ChangeMe123!'),
    owner: process.env.DEMO_OWNER_PASSWORD || (production ? '' : 'Demo123!'),
    technician: process.env.DEMO_TECH_PASSWORD || (production ? '' : 'Demo123!'),
  };
  if (production && Object.entries(bootstrap).some(([, value]) => value.length < 16)) {
    throw new Error('Production bootstrap passwords are missing or too short. Set PLATFORM_ADMIN_PASSWORD, DEMO_OWNER_PASSWORD, and DEMO_TECH_PASSWORD to values of at least 16 characters.');
  }
  const adminPassword = await bcrypt.hash(bootstrap.admin, 12);
  const ownerPassword = await bcrypt.hash(bootstrap.owner, 12);
  const techPassword = await bcrypt.hash(bootstrap.technician, 12);

  await pool.query(`INSERT INTO users (name,email,password_hash,role) VALUES ('مدير المنصة','admin@serviceops.local',$1,'platform_admin') ON CONFLICT(email) DO NOTHING`, [adminPassword]);
  const tenant = await pool.query(`INSERT INTO tenants (name,slug,industry,phone,email,plan_code,subscription_status) VALUES ('شركة الصيانة التجريبية','demo-maintenance','تكييف وتبريد','01000000000','demo@serviceops.local','growth','active') ON CONFLICT(slug) DO UPDATE SET name=EXCLUDED.name RETURNING id`);
  const tenantId = tenant.rows[0].id;
  const owner = await pool.query(`INSERT INTO users (tenant_id,name,email,phone,password_hash,role) VALUES ($1,'مدير الشركة','owner@demo.local','01000000000',$2,'owner') ON CONFLICT(email) DO UPDATE SET tenant_id=EXCLUDED.tenant_id RETURNING id`, [tenantId, ownerPassword]);
  const tech = await pool.query(`INSERT INTO users (tenant_id,name,email,phone,password_hash,role) VALUES ($1,'أحمد الفني','tech@demo.local','01111111111',$2,'technician') ON CONFLICT(email) DO UPDATE SET tenant_id=EXCLUDED.tenant_id RETURNING id`, [tenantId, techPassword]);
  const customer = await pool.query(`INSERT INTO customers (tenant_id,name,phone,email,address,site_name,notes) SELECT $1,'شركة النور','01222222222','client@example.com','مدينة نصر - القاهرة','مقر الإدارة','عميل تجريبي' WHERE NOT EXISTS (SELECT 1 FROM customers WHERE tenant_id=$1 AND phone='01222222222') RETURNING id`, [tenantId]);
  let customerId = customer.rows[0]?.id;
  if (!customerId) customerId = (await pool.query(`SELECT id FROM customers WHERE tenant_id=$1 AND phone='01222222222'`, [tenantId])).rows[0].id;
  await pool.query(`INSERT INTO work_orders (tenant_id,customer_id,code,title,description,category,priority,status,assigned_to,scheduled_at,address,created_by) SELECT $1,$2,'SO-1001','صيانة تكييف مركزي','ضعف تبريد في الوحدة الرئيسية','تكييف وتبريد','high','assigned',$3,NOW()+INTERVAL '2 hours','مدينة نصر - القاهرة',$4 WHERE NOT EXISTS (SELECT 1 FROM work_orders WHERE tenant_id=$1 AND code='SO-1001')`, [tenantId, customerId, tech.rows[0].id, owner.rows[0].id]);
  await pool.query(`INSERT INTO platform_settings (key,value) VALUES ('payment_methods', $1::jsonb) ON CONFLICT(key) DO NOTHING`, [JSON.stringify({ vodafone_cash_number: '', instapay_address: '', instapay_qr_url: '', payment_instructions: 'ارسل التحويل ثم ارفع صورة الإيصال ورقم العملية. يتم تفعيل الاشتراك بعد المراجعة.', checkout_url: process.env.PAYMENT_CHECKOUT_URL || '' })]);
  console.log('Seed completed.');
  await pool.end();
}
seed().catch(err => { console.error(err); process.exit(1); });
