require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { z } = require('zod');
const { pool, initDatabase } = require('./db');
const { initOptimizationSchema, registerOptimizationRoutes } = require('./optimization');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
if (process.env.NODE_ENV === 'production' && (!JWT_SECRET || JWT_SECRET.length < 32)) {
  throw new Error('Set JWT_SECRET to a random value of at least 32 characters before production.');
}
if (!JWT_SECRET || JWT_SECRET.length < 32) console.warn('WARNING: Set JWT_SECRET to a random value of at least 32 characters before production.');
const secret = JWT_SECRET || 'development-only-secret-change-before-production-000000';
const storageDir = path.resolve(__dirname, '..', 'storage');
fs.mkdirSync(storageDir, { recursive: true });

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 50, standardHeaders: true, legacyHeaders: false }));

const PLANS = {
  starter: { code: 'starter', name: 'البداية', monthly: 499, yearly: 4990, maxTechnicians: 5, features: ['customers','work_orders','voice_reports','photos'] },
  growth: { code: 'growth', name: 'النمو', monthly: 899, yearly: 8990, maxTechnicians: 15, features: ['customers','work_orders','voice_reports','photos','quotations','invoices','reminders'] },
  pro: { code: 'pro', name: 'احترافي', monthly: 1499, yearly: 14990, maxTechnicians: 999, features: ['customers','work_orders','voice_reports','photos','quotations','invoices','reminders','contracts','advanced_reports','priority_support'] },
};
const ROLE_LABELS = { owner: 'مالك الشركة', manager: 'مدير', technician: 'فني', platform_admin: 'مدير المنصة' };

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, storageDir),
    filename: (_req, file, cb) => cb(null, `${Date.now()}-${crypto.randomUUID()}${path.extname(file.originalname).slice(0, 12)}`),
  }),
  limits: { fileSize: 25 * 1024 * 1024, files: 9 },
  fileFilter: (_req, file, cb) => {
    const ok = /^(image\/(jpeg|png|webp|heic|heif)|audio\/(webm|ogg|mpeg|mp4|wav|x-wav|aac|m4a|x-m4a))(;.*)?$/i.test(file.mimetype);
    cb(ok ? null : new Error('نوع الملف غير مسموح. ارفع صورة أو تسجيل صوتي مدعوم.'), ok);
  },
});

function asyncRoute(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }
function signToken(user) {
  return jwt.sign({ sub: user.id, tenantId: user.tenant_id, role: user.role, name: user.name, email: user.email }, secret, { expiresIn: '7d', issuer: 'syntrix-serviceops' });
}
const auth = asyncRoute(async (req, res, next) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'سجّل الدخول للمتابعة.' });
  try {
    const payload = jwt.verify(token, secret, { issuer: 'syntrix-serviceops' });
    const result = await pool.query(`SELECT u.id,u.tenant_id,u.name,u.email,u.phone,u.role,u.status,t.name AS company_name,t.slug AS company_slug,t.status AS company_status,t.plan_code,t.subscription_status,t.trial_ends_at,t.subscription_ends_at FROM users u LEFT JOIN tenants t ON t.id=u.tenant_id WHERE u.id=$1`, [payload.sub]);
    if (!result.rowCount || result.rows[0].status !== 'active') return res.status(401).json({ error: 'الحساب غير متاح.' });
    const user = result.rows[0];
    if (user.role !== 'platform_admin' && user.company_status !== 'active') return res.status(403).json({ error: 'حساب الشركة موقوف. تواصل مع إدارة المنصة.' });
    req.user = user;
    next();
  } catch (_err) { return res.status(401).json({ error: 'انتهت جلسة الدخول. سجّل الدخول مرة أخرى.' }); }
});
function allow(...roles) { return (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'ليس لديك صلاحية لتنفيذ هذا الإجراء.' }); }
function tenant(req) { return req.user.tenant_id; }
function audit(req, action, type, id, details = {}) {
  return pool.query(`INSERT INTO audit_logs (tenant_id,actor_id,action,entity_type,entity_id,details) VALUES ($1,$2,$3,$4,$5,$6)`, [tenant(req), req.user.id, action, type, id || null, JSON.stringify(details)]).catch(() => {});
}
function requireTenant(req, res) { if (!req.user.tenant_id) { res.status(400).json({ error: 'هذا الإجراء خاص بحساب شركة.' }); return false; } return true; }
function planFor(code) { return PLANS[code] || PLANS.starter; }
function subscriptionIsValid(req) {
  const now=Date.now();
  if(req.user.subscription_status==='trial') return !!req.user.trial_ends_at && new Date(req.user.trial_ends_at).getTime()>now;
  if(req.user.subscription_status==='active') return !req.user.subscription_ends_at || new Date(req.user.subscription_ends_at).getTime()>now;
  return false;
}
// Subscription enforcement is paused in this release. Keep the DB fields for future billing activation.
function subscriptionWriteGate(req,res,next) { return next(); }
function hasFeature(_req, _feature) { return true; }
function featureGate(_feature) { return (_req, _res, next) => next(); }
function publicUser(user) { const { password_hash, ...safe } = user; return safe; }
function technicianSafeVisit(visit) { if (!visit) return visit; const { manager_notes, public_token, approved_by, ...safe } = visit; return safe; }
function makeCode(prefix) { return `${prefix}-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`; }

// Operations Research endpoints are registered separately and remain tenant-scoped.
registerOptimizationRoutes(app, { pool, auth, allow, tenant, asyncRoute, z, crypto, audit });

app.get('/api/health', (_req, res) => res.json({
  ok: true,
  app: 'FieldFlow',
  version: '1.3.0',
  voiceTranscription: process.env.GROQ_API_KEY?.trim() ? 'groq' : 'disabled',
}));
app.get('/api/plans', (_req, res) => res.json({ plans: Object.values(PLANS) }));

// Authentication and onboarding
app.post('/api/auth/register', asyncRoute(async (req, res) => {
  const schema = z.object({ companyName: z.string().min(2).max(120), industry: z.string().min(2).max(80), name: z.string().min(2).max(100), email: z.string().email().max(160), phone: z.string().min(7).max(30), password: z.string().min(8).max(100) });
  const input = schema.parse(req.body);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const exists = await client.query('SELECT id FROM users WHERE email=$1', [input.email.toLowerCase()]);
    if (exists.rowCount) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'البريد الإلكتروني مستخدم بالفعل.' }); }
    const baseSlug = input.companyName.toLowerCase().replace(/[^a-z0-9\u0600-\u06ff]+/g, '-').replace(/^-|-$/g, '').slice(0, 45) || 'company';
    const slug = `${baseSlug}-${crypto.randomBytes(3).toString('hex')}`;
    const t = await client.query(`INSERT INTO tenants (name,slug,industry,phone,email,plan_code,subscription_status) VALUES ($1,$2,$3,$4,$5,'pro','trial') RETURNING *`, [input.companyName, slug, input.industry, input.phone, input.email.toLowerCase()]);
    const hash = await bcrypt.hash(input.password, 12);
    const u = await client.query(`INSERT INTO users (tenant_id,name,email,phone,password_hash,role) VALUES ($1,$2,$3,$4,$5,'owner') RETURNING id,tenant_id,name,email,phone,role`, [t.rows[0].id, input.name, input.email.toLowerCase(), input.phone, hash]);
    await client.query('COMMIT');
    const user = { ...u.rows[0], company_name: t.rows[0].name, company_slug: slug, plan_code: 'pro', subscription_status: 'trial', trial_ends_at: t.rows[0].trial_ends_at };
    res.status(201).json({ token: signToken(user), user, message: 'تم إنشاء حسابك التجريبي لمدة 14 يوم.' });
  } catch (err) { await client.query('ROLLBACK'); throw err; } finally { client.release(); }
}));
app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const input = z.object({ email: z.string().email(), password: z.string().min(1) }).parse(req.body);
  const result = await pool.query(`SELECT u.*,t.name AS company_name,t.slug AS company_slug,t.status AS company_status,t.plan_code,t.subscription_status,t.trial_ends_at,t.subscription_ends_at FROM users u LEFT JOIN tenants t ON t.id=u.tenant_id WHERE LOWER(u.email)=LOWER($1)`, [input.email]);
  const user = result.rows[0];
  if (!user || user.status !== 'active' || !(await bcrypt.compare(input.password, user.password_hash))) return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة.' });
  if (user.role !== 'platform_admin' && user.company_status !== 'active') return res.status(403).json({ error: 'حساب الشركة موقوف.' });
  res.json({ token: signToken(user), user: publicUser(user) });
}));
app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user), roleLabel: ROLE_LABELS[req.user.role] }));
app.post('/api/auth/change-password',auth,asyncRoute(async(req,res)=>{const x=z.object({currentPassword:z.string().min(1),newPassword:z.string().min(10).max(100)}).parse(req.body);const r=await pool.query('SELECT password_hash FROM users WHERE id=$1',[req.user.id]);if(!r.rowCount||!(await bcrypt.compare(x.currentPassword,r.rows[0].password_hash)))return res.status(400).json({error:'كلمة المرور الحالية غير صحيحة.'});const hash=await bcrypt.hash(x.newPassword,12);await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2',[hash,req.user.id]);res.json({ok:true,message:'تم تغيير كلمة المرور.'});}));

// Dashboard
app.get('/api/dashboard', auth, allow('owner','manager'), asyncRoute(async (req, res) => {
  if (!requireTenant(req, res)) return;
  const tid = tenant(req);
  const [orders, customers, team, pending, invoices, reminders, recent] = await Promise.all([
    pool.query(`SELECT COUNT(*)::int AS total,COUNT(*) FILTER (WHERE status='new')::int AS new,COUNT(*) FILTER (WHERE status='in_progress')::int AS in_progress,COUNT(*) FILTER (WHERE status='completed')::int AS completed,COUNT(*) FILTER (WHERE priority='urgent' AND status NOT IN ('completed','cancelled'))::int AS urgent FROM work_orders WHERE tenant_id=$1`, [tid]),
    pool.query('SELECT COUNT(*)::int AS total FROM customers WHERE tenant_id=$1', [tid]),
    pool.query("SELECT COUNT(*)::int AS total,COUNT(*) FILTER (WHERE role='technician')::int AS technicians FROM users WHERE tenant_id=$1 AND status='active'", [tid]),
    pool.query("SELECT COUNT(*)::int AS total FROM visits WHERE tenant_id=$1 AND report_status='pending'", [tid]),
    pool.query("SELECT COALESCE(SUM(total-paid_amount),0)::numeric(12,2) AS outstanding FROM invoices WHERE tenant_id=$1 AND status IN ('unpaid','partial','overdue')", [tid]),
    pool.query("SELECT COUNT(*)::int AS total FROM reminders WHERE tenant_id=$1 AND status='open' AND due_at<=NOW()+INTERVAL '7 days'", [tid]),
    pool.query(`SELECT w.id,w.code,w.title,w.status,w.priority,w.scheduled_at,c.name AS customer_name,u.name AS technician_name FROM work_orders w JOIN customers c ON c.id=w.customer_id LEFT JOIN users u ON u.id=w.assigned_to WHERE w.tenant_id=$1 ORDER BY w.created_at DESC LIMIT 7`, [tid]),
  ]);
  res.json({ stats: { ...orders.rows[0], customers: customers.rows[0].total, team: team.rows[0].total, technicians: team.rows[0].technicians, pending_reports: pending.rows[0].total, outstanding: invoices.rows[0].outstanding, due_reminders: reminders.rows[0].total }, recent: recent.rows, plan: planFor(req.user.plan_code), subscription: { status: req.user.subscription_status, trialEndsAt: req.user.trial_ends_at, endsAt: req.user.subscription_ends_at } });
}));

// Company profile
app.get('/api/company',auth,allow('owner','manager'),asyncRoute(async(req,res)=>{if(!requireTenant(req,res))return;const r=await pool.query('SELECT id,name,slug,industry,phone,email,address,logo_url,created_at FROM tenants WHERE id=$1',[tenant(req)]);res.json({company:r.rows[0]});}));
app.patch('/api/company',auth,allow('owner','manager'),asyncRoute(async(req,res)=>{if(!requireTenant(req,res))return;const x=z.object({name:z.string().min(2).max(120),industry:z.string().min(2).max(80),phone:z.string().max(30).optional(),email:z.string().email().optional().or(z.literal('')),address:z.string().max(300).optional(),logo_url:z.string().url().max(500).optional().or(z.literal(''))}).parse(req.body);const r=await pool.query('UPDATE tenants SET name=$1,industry=$2,phone=$3,email=$4,address=$5,logo_url=$6 WHERE id=$7 RETURNING id,name,slug,industry,phone,email,address,logo_url',[x.name,x.industry,x.phone||null,x.email||null,x.address||null,x.logo_url||null,tenant(req)]);res.json({company:r.rows[0]});}));

// Customers
app.get('/api/customers', auth, allow('owner','manager'), asyncRoute(async (req, res) => {
  if (!requireTenant(req, res)) return;
  const q = `%${String(req.query.q || '').slice(0, 80)}%`;
  const result = await pool.query(`SELECT c.*,COUNT(w.id)::int AS work_orders_count FROM customers c LEFT JOIN work_orders w ON w.customer_id=c.id WHERE c.tenant_id=$1 AND (c.name ILIKE $2 OR COALESCE(c.phone,'') ILIKE $2 OR COALESCE(c.site_name,'') ILIKE $2) GROUP BY c.id ORDER BY c.created_at DESC LIMIT 250`, [tenant(req), q]);
  res.json({ customers: result.rows });
}));
app.post('/api/customers', auth, allow('owner','manager'), subscriptionWriteGate, asyncRoute(async (req, res) => {
  if (!requireTenant(req, res)) return;
  const x = z.object({ name: z.string().min(2).max(140), phone: z.string().max(30).optional(), email: z.string().email().optional().or(z.literal('')), address: z.string().max(300).optional(), site_name: z.string().max(140).optional(), notes: z.string().max(2000).optional() }).parse(req.body);
  const r = await pool.query(`INSERT INTO customers (tenant_id,name,phone,email,address,site_name,notes) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`, [tenant(req), x.name, x.phone || null, x.email || null, x.address || null, x.site_name || null, x.notes || null]);
  audit(req, 'customer.created', 'customer', r.rows[0].id);
  res.status(201).json({ customer: r.rows[0] });
}));
app.patch('/api/customers/:id', auth, allow('owner','manager'), subscriptionWriteGate, asyncRoute(async (req, res) => {
  const x = z.object({ name: z.string().min(2).max(140).optional(), phone: z.string().max(30).optional(), email: z.string().max(160).optional(), address: z.string().max(300).optional(), site_name: z.string().max(140).optional(), notes: z.string().max(2000).optional() }).parse(req.body);
  const keys = Object.keys(x); if (!keys.length) return res.status(400).json({ error: 'مفيش بيانات للتعديل.' });
  const sets = keys.map((k,i)=>`"${k}"=$${i+3}`).join(',');
  const vals = keys.map(k=>x[k]);
  const r = await pool.query(`UPDATE customers SET ${sets} WHERE id=$1 AND tenant_id=$2 RETURNING *`, [req.params.id,tenant(req),...vals]);
  if (!r.rowCount) return res.status(404).json({ error: 'العميل غير موجود.' });
  res.json({ customer: r.rows[0] });
}));
app.delete('/api/customers/:id', auth, allow('owner','manager'), subscriptionWriteGate, asyncRoute(async (req,res)=>{
  const r=await pool.query('DELETE FROM customers WHERE id=$1 AND tenant_id=$2 AND NOT EXISTS (SELECT 1 FROM work_orders WHERE customer_id=$1) RETURNING id',[req.params.id,tenant(req)]);
  if(!r.rowCount) return res.status(409).json({error:'لا يمكن حذف العميل لوجود طلبات صيانة مرتبطة به.'}); res.json({ok:true});
}));

// Team
app.get('/api/team', auth, allow('owner','manager'), asyncRoute(async (req,res)=>{
  if(!requireTenant(req,res)) return;
  const r=await pool.query(`SELECT id,name,email,phone,role,status,created_at FROM users WHERE tenant_id=$1 ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'manager' THEN 1 ELSE 2 END,name`,[tenant(req)]);
  res.json({team:r.rows});
}));
app.post('/api/team', auth, allow('owner','manager'), subscriptionWriteGate, asyncRoute(async (req,res)=>{
  if(!requireTenant(req,res)) return;
  const x=z.object({name:z.string().min(2).max(100),email:z.string().email(),phone:z.string().max(30).optional(),role:z.enum(['manager','technician']),password:z.string().min(8).max(100)}).parse(req.body);
  const hash=await bcrypt.hash(x.password,12);
  try { const r=await pool.query(`INSERT INTO users (tenant_id,name,email,phone,password_hash,role) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,name,email,phone,role,status`,[tenant(req),x.name,x.email.toLowerCase(),x.phone||null,hash,x.role]); res.status(201).json({member:r.rows[0]}); }
  catch(e){ if(e.code==='23505') return res.status(409).json({error:'البريد الإلكتروني مستخدم بالفعل.'}); throw e; }
}));
app.patch('/api/team/:id/status', auth, allow('owner','manager'), subscriptionWriteGate, asyncRoute(async(req,res)=>{
  const x=z.object({status:z.enum(['active','disabled'])}).parse(req.body);
  if(req.params.id===req.user.id) return res.status(400).json({error:'لا يمكنك إيقاف حسابك الحالي.'});
  const r=await pool.query(`UPDATE users SET status=$1 WHERE id=$2 AND tenant_id=$3 AND role<>'owner' RETURNING id,name,status`,[x.status,req.params.id,tenant(req)]);
  if(!r.rowCount) return res.status(404).json({error:'المستخدم غير موجود.'}); res.json({member:r.rows[0]});
}));
app.patch('/api/team/:id', auth, allow('owner','manager'), asyncRoute(async(req,res)=>{
  const x=z.object({name:z.string().min(2).max(100).optional(),email:z.string().email().max(160).optional(),phone:z.string().max(30).nullable().optional(),role:z.enum(['manager','technician']).optional()}).strict().parse(req.body);
  if(!Object.keys(x).length) return res.status(400).json({error:'مفيش بيانات للتعديل.'});
  if(req.params.id===req.user.id && x.role) return res.status(400).json({error:'لا يمكنك تغيير دور حسابك الحالي.'});
  const current=await pool.query('SELECT id,role FROM users WHERE id=$1 AND tenant_id=$2',[req.params.id,tenant(req)]);
  if(!current.rowCount || current.rows[0].role==='owner') return res.status(404).json({error:'المستخدم غير موجود أو لا يمكن تعديل حساب المالك.'});
  const keys=Object.keys(x); const sets=keys.map((k,i)=>`\"${k}\"=$${i+3}`).join(',');
  try { const r=await pool.query(`UPDATE users SET ${sets} WHERE id=$1 AND tenant_id=$2 RETURNING id,name,email,phone,role,status,created_at`,[req.params.id,tenant(req),...keys.map(k=>k==='email'?x[k].toLowerCase():x[k])]); audit(req,'team.updated','user',req.params.id,x); res.json({member:r.rows[0]}); }
  catch(e){if(e.code==='23505') return res.status(409).json({error:'البريد الإلكتروني مستخدم بالفعل.'}); throw e;}
}));
app.delete('/api/team/:id', auth, allow('owner','manager'), asyncRoute(async(req,res)=>{
  if(req.params.id===req.user.id) return res.status(400).json({error:'لا يمكنك حذف حسابك الحالي.'});
  const current=await pool.query('SELECT id,role FROM users WHERE id=$1 AND tenant_id=$2',[req.params.id,tenant(req)]);
  if(!current.rowCount || current.rows[0].role==='owner') return res.status(404).json({error:'المستخدم غير موجود أو لا يمكن حذف حساب المالك.'});
  await pool.query('INSERT INTO audit_logs (tenant_id,actor_id,action,entity_type,entity_id,details) VALUES ($1,$2,$3,$4,$5,$6)',[tenant(req),req.user.id,'team.deleted','user',req.params.id,JSON.stringify({role:current.rows[0].role})]);
  await pool.query('DELETE FROM users WHERE id=$1 AND tenant_id=$2',[req.params.id,tenant(req)]);
  res.json({ok:true,message:'تم حذف المستخدم. ستظل التقارير والطلبات القديمة محفوظة.'});
}));

// Work orders: full task brief, assignment, international pricing and payment tracking.
app.get('/api/orders', auth, asyncRoute(async(req,res)=>{
  if(!requireTenant(req,res)) return;
  const params=[tenant(req)]; let where='w.tenant_id=$1';
  if(req.query.status){params.push(String(req.query.status));where+=` AND w.status=$${params.length}`;}
  if(req.user.role==='technician'){params.push(req.user.id);where+=` AND w.assigned_to=$${params.length}`;}
  const r=await pool.query(`SELECT w.*,c.name AS customer_name,c.phone AS customer_phone,c.email AS customer_email,c.site_name AS customer_site_name,u.name AS technician_name,
    EXISTS(SELECT 1 FROM visits v WHERE v.work_order_id=w.id AND v.tenant_id=w.tenant_id AND v.id=(SELECT v2.id FROM visits v2 WHERE v2.work_order_id=w.id AND v2.tenant_id=w.tenant_id ORDER BY v2.created_at DESC LIMIT 1) AND v.technician_id=w.assigned_to AND v.report_status IN ('pending','approved') AND v.report_body IS NOT NULL AND BTRIM(v.report_body)<>'') AS has_report,
    (SELECT v.report_status FROM visits v WHERE v.work_order_id=w.id AND v.tenant_id=w.tenant_id ORDER BY v.created_at DESC LIMIT 1) AS latest_report_status,
    CASE WHEN w.started_at IS NOT NULL AND w.technician_completed_at IS NOT NULL THEN GREATEST(0,EXTRACT(EPOCH FROM (w.technician_completed_at-w.started_at))/60)::int ELSE NULL END AS actual_duration_minutes
    FROM work_orders w JOIN customers c ON c.id=w.customer_id LEFT JOIN users u ON u.id=w.assigned_to WHERE ${where} ORDER BY w.scheduled_at ASC NULLS LAST,w.created_at DESC LIMIT 300`,params);
  res.json({orders:r.rows});
}));
const workOrderFields = {
  customer_id:z.string().uuid(), title:z.string().min(3).max(180), description:z.string().max(3000).nullable().optional(),
  category:z.string().min(2).max(100), priority:z.enum(['low','normal','high','urgent']).default('normal'),
  assigned_to:z.string().uuid().nullable().optional(), scheduled_at:z.string().datetime().nullable().optional(), address:z.string().max(500).nullable().optional(),
  country_code:z.string().regex(/^[A-Za-z]{2}$/).default('EG'), city:z.string().max(120).nullable().optional(), timezone:z.string().min(3).max(80).default('Africa/Cairo'),
  expected_duration_minutes:z.coerce.number().int().min(1).max(10080).nullable().optional(), site_contact_name:z.string().max(120).nullable().optional(), site_contact_phone:z.string().max(40).nullable().optional(),
  task_instructions:z.string().max(5000).nullable().optional(), access_instructions:z.string().max(3000).nullable().optional(), required_materials:z.string().max(3000).nullable().optional(), safety_notes:z.string().max(3000).nullable().optional(), task_checklist:z.string().max(5000).nullable().optional().refine(v=>!v||v.split(/\r?\n/).filter(line=>line.trim()).length<=30,'حد أقصى 30 خطوة لقائمة التحقق.'),
  service_price:z.coerce.number().min(0).max(999999999).default(0), currency:z.string().regex(/^[A-Za-z]{3}$/).default('EGP'), price_includes_tax:z.boolean().default(true),
  payment_method:z.enum(['cash','bank_transfer','card','online','on_account','not_required']).default('cash'),
  payment_account_holder:z.string().max(160).nullable().optional(), payment_bank_name:z.string().max(120).nullable().optional(), payment_bank_swift:z.string().max(20).nullable().optional(), payment_bank_country:z.string().max(2).refine(v=>!v||/^[A-Za-z]{2}$/.test(v),'رمز دولة البنك يجب أن يكون حرفين.').nullable().optional(), payment_account_number:z.string().max(160).nullable().optional(),
  payment_instructions:z.string().max(2000).nullable().optional(), payment_link:z.string().max(500).nullable().optional().refine(v=>!v||/^https:\/\//i.test(v),'رابط الدفع لازم يبدأ بـ https://')
};
const workOrderCreateSchema=z.object(workOrderFields).strict();
app.post('/api/orders', auth, allow('owner','manager'), subscriptionWriteGate, asyncRoute(async(req,res)=>{
  if(!requireTenant(req,res)) return;
  const x=workOrderCreateSchema.parse(req.body);
  const c=await pool.query('SELECT id,address FROM customers WHERE id=$1 AND tenant_id=$2',[x.customer_id,tenant(req)]); if(!c.rowCount) return res.status(400).json({error:'اختار عميل تابع لشركتك.'});
  if(x.assigned_to){const u=await pool.query("SELECT id FROM users WHERE id=$1 AND tenant_id=$2 AND role='technician' AND status='active'",[x.assigned_to,tenant(req)]); if(!u.rowCount)return res.status(400).json({error:'الفني المختار غير صالح.'});}
  x.country_code=x.country_code.toUpperCase();x.currency=x.currency.toUpperCase();
  const columns=['tenant_id','customer_id','code','title','description','category','priority','status','assigned_to','scheduled_at','address','country_code','city','timezone','expected_duration_minutes','site_contact_name','site_contact_phone','task_instructions','access_instructions','required_materials','safety_notes','task_checklist','service_price','currency','price_includes_tax','payment_method','payment_status','payment_account_holder','payment_bank_name','payment_bank_swift','payment_bank_country','payment_account_number','payment_instructions','payment_link','created_by'];
  const values=[tenant(req),x.customer_id,makeCode('SO'),x.title,x.description||null,x.category,x.priority,x.assigned_to?'assigned':'new',x.assigned_to||null,x.scheduled_at||null,x.address||c.rows[0].address||null,x.country_code,x.city||null,x.timezone,x.expected_duration_minutes||null,x.site_contact_name||null,x.site_contact_phone||null,x.task_instructions||null,x.access_instructions||null,x.required_materials||null,x.safety_notes||null,x.task_checklist||null,x.service_price,x.currency,x.price_includes_tax,x.payment_method,x.payment_method==='not_required'?'waived':'unpaid',x.payment_account_holder||null,x.payment_bank_name||null,x.payment_bank_swift||null,x.payment_bank_country?x.payment_bank_country.toUpperCase():null,x.payment_account_number||null,x.payment_instructions||null,x.payment_link||null,req.user.id];
  const placeholders=values.map((_,i)=>`$${i+1}`).join(',');
  const r=await pool.query(`INSERT INTO work_orders (${columns.join(',')}) VALUES (${placeholders}) RETURNING *`,values);
  audit(req,'work_order.created','work_order',r.rows[0].id,{code:r.rows[0].code,assigned_to:x.assigned_to||null,service_price:x.service_price,currency:x.currency});
  res.status(201).json({order:r.rows[0]});
}));
app.patch('/api/orders/:id', auth, allow('owner','manager','technician'), subscriptionWriteGate, asyncRoute(async(req,res)=>{
  if(req.user.role==='technician'){
    const x=z.object({status:z.enum(['in_progress','waiting_parts'])}).strict().parse(req.body);
    const r=await pool.query(`UPDATE work_orders SET status=$1,started_at=CASE WHEN $1='in_progress' THEN COALESCE(started_at,NOW()) ELSE started_at END,waiting_parts_at=CASE WHEN $1='waiting_parts' THEN NOW() ELSE waiting_parts_at END,updated_at=NOW() WHERE id=$2 AND tenant_id=$3 AND assigned_to=$4 AND status NOT IN ('completed','cancelled','awaiting_review') RETURNING *`,[x.status,req.params.id,tenant(req),req.user.id]);
    if(!r.rowCount)return res.status(404).json({error:'المهمة غير موجودة أو لم تعد متاحة.'});
    audit(req,'work_order.status_changed','work_order',req.params.id,{status:x.status});res.json({order:r.rows[0]});return;
  }
  const schema=z.object({
    title:z.string().min(3).max(180).optional(),description:z.string().max(3000).nullable().optional(),category:z.string().min(2).max(100).optional(),priority:z.enum(['low','normal','high','urgent']).optional(),
    status:z.enum(['new','assigned','in_progress','waiting_parts','awaiting_review','completed','cancelled']).optional(),assigned_to:z.string().uuid().nullable().optional(),scheduled_at:z.string().datetime().nullable().optional(),address:z.string().max(500).nullable().optional(),
    country_code:z.string().regex(/^[A-Za-z]{2}$/).optional(),city:z.string().max(120).nullable().optional(),timezone:z.string().min(3).max(80).optional(),expected_duration_minutes:z.coerce.number().int().min(1).max(10080).nullable().optional(),
    site_contact_name:z.string().max(120).nullable().optional(),site_contact_phone:z.string().max(40).nullable().optional(),task_instructions:z.string().max(5000).nullable().optional(),access_instructions:z.string().max(3000).nullable().optional(),required_materials:z.string().max(3000).nullable().optional(),safety_notes:z.string().max(3000).nullable().optional(),task_checklist:z.string().max(5000).nullable().optional().refine(v=>!v||v.split(/\r?\n/).filter(line=>line.trim()).length<=30,'حد أقصى 30 خطوة لقائمة التحقق.'),
    service_price:z.coerce.number().min(0).max(999999999).optional(),currency:z.string().regex(/^[A-Za-z]{3}$/).optional(),price_includes_tax:z.boolean().optional(),payment_method:z.enum(['cash','bank_transfer','card','online','on_account','not_required']).optional(),
    payment_account_holder:z.string().max(160).nullable().optional(),payment_bank_name:z.string().max(120).nullable().optional(),payment_bank_swift:z.string().max(20).nullable().optional(),payment_bank_country:z.string().max(2).refine(v=>!v||/^[A-Za-z]{2}$/.test(v),'رمز دولة البنك يجب أن يكون حرفين.').nullable().optional(),payment_account_number:z.string().max(160).nullable().optional(),payment_instructions:z.string().max(2000).nullable().optional(),payment_link:z.string().max(500).nullable().optional().refine(v=>!v||/^https:\/\//i.test(v),'رابط الدفع لازم يبدأ بـ https://')
  }).strict();
  const x=schema.parse(req.body);if(x.country_code)x.country_code=x.country_code.toUpperCase();if(x.currency)x.currency=x.currency.toUpperCase();if(x.payment_bank_country)x.payment_bank_country=x.payment_bank_country.toUpperCase();
  const keys=Object.keys(x);if(!keys.length)return res.status(400).json({error:'مفيش بيانات للتعديل.'});
  if(x.assigned_to){const u=await pool.query("SELECT id FROM users WHERE id=$1 AND tenant_id=$2 AND role='technician' AND status='active'",[x.assigned_to,tenant(req)]);if(!u.rowCount)return res.status(400).json({error:'الفني المختار غير صالح.'});}
  let sets=keys.map((k,i)=>`"${k}"=$${i+3}`).join(',');const values=keys.map(k=>x[k]);
  if(Object.prototype.hasOwnProperty.call(x,'assigned_to')&&!Object.prototype.hasOwnProperty.call(x,'status')){values.push(x.assigned_to||null);sets+=`,status=CASE WHEN $${values.length+2}::uuid IS NULL THEN 'new' WHEN status='new' THEN 'assigned' ELSE status END`;}
  if(Object.prototype.hasOwnProperty.call(x,'task_checklist'))sets+=`,task_checklist_progress='[]'::jsonb`;
  if(x.payment_method==='not_required')sets+=`,payment_status='waived'`;else if(x.payment_method)sets+=`,payment_status=CASE WHEN payment_status='waived' THEN 'unpaid' ELSE payment_status END`;
  if(x.status==='in_progress') sets+=',started_at=COALESCE(started_at,NOW())';
  if(x.status==='waiting_parts') sets+=',waiting_parts_at=NOW()';
  if(x.status==='completed') sets+=',completed_at=COALESCE(completed_at,NOW())';
  const r=await pool.query(`UPDATE work_orders SET ${sets},updated_at=NOW() WHERE id=$1 AND tenant_id=$2 RETURNING *`,[req.params.id,tenant(req),...values]);
  if(!r.rowCount)return res.status(404).json({error:'الطلب غير موجود.'});audit(req,'work_order.updated','work_order',r.rows[0].id,x);res.json({order:r.rows[0]});
}));
app.patch('/api/orders/:id/checklist',auth,allow('technician'),asyncRoute(async(req,res)=>{
  const x=z.object({completed_items:z.array(z.number().int().min(0).max(29)).max(30)}).strict().parse(req.body);
  const current=await pool.query(`SELECT task_checklist FROM work_orders WHERE id=$1 AND tenant_id=$2 AND assigned_to=$3 AND status NOT IN ('completed','cancelled','awaiting_review')`,[req.params.id,tenant(req),req.user.id]);
  if(!current.rowCount)return res.status(404).json({error:'المهمة غير متاحة.'});
  const stepCount=String(current.rows[0].task_checklist||'').split(/\r?\n/).map(v=>v.trim()).filter(Boolean).length;
  if(x.completed_items.some(i=>i>=stepCount))return res.status(400).json({error:'قائمة التحقق تغيرت. حدّث الصفحة وحاول مرة أخرى.'});
  const r=await pool.query(`UPDATE work_orders SET task_checklist_progress=$1::jsonb,updated_at=NOW() WHERE id=$2 AND tenant_id=$3 AND assigned_to=$4 AND status NOT IN ('completed','cancelled','awaiting_review') RETURNING task_checklist_progress`,[JSON.stringify([...new Set(x.completed_items)]),req.params.id,tenant(req),req.user.id]);
  if(!r.rowCount)return res.status(409).json({error:'لم تعد المهمة متاحة للتعديل.'});
  audit(req,'work_order.checklist_updated','work_order',req.params.id,{completed_items:x.completed_items});
  res.json({completed_items:r.rows[0].task_checklist_progress});
}));

app.post('/api/orders/:id/complete',auth,allow('technician'),asyncRoute(async(req,res)=>{
  const existing=await pool.query(`SELECT w.id,w.status,w.assigned_to,
    (SELECT v.report_status FROM visits v WHERE v.work_order_id=w.id AND v.tenant_id=w.tenant_id ORDER BY v.created_at DESC LIMIT 1) AS latest_report_status,
    w.task_checklist,w.task_checklist_progress,
    EXISTS(SELECT 1 FROM visits v WHERE v.work_order_id=w.id AND v.tenant_id=w.tenant_id AND v.technician_id=$3 AND v.id=(SELECT v2.id FROM visits v2 WHERE v2.work_order_id=w.id AND v2.tenant_id=w.tenant_id ORDER BY v2.created_at DESC LIMIT 1) AND v.report_status IN ('pending','approved') AND v.report_body IS NOT NULL AND BTRIM(v.report_body)<>'') AS has_report
    FROM work_orders w WHERE w.id=$1 AND w.tenant_id=$2 AND w.assigned_to=$3`,[req.params.id,tenant(req),req.user.id]);
  if(!existing.rowCount)return res.status(404).json({error:'المهمة غير موجودة أو غير مسندة إليك.'});
  if(['completed','cancelled','awaiting_review'].includes(existing.rows[0].status))return res.status(409).json({error:'المهمة تم إغلاقها أو إرسالها للمراجعة بالفعل.'});
  if(['new','assigned'].includes(existing.rows[0].status))return res.status(409).json({error:'ابدأ تنفيذ المهمة أولًا، وبعدها سجّل التقرير واطلب الإغلاق.'});
  if(!existing.rows[0].has_report)return res.status(400).json({error:'قبل إغلاق المهمة، سجّل تقرير الزيارة بالصوت أو الكتابة وأرسله للمدير.'});
  const checklist=String(existing.rows[0].task_checklist||'').split(/\r?\n/).map(v=>v.trim()).filter(Boolean);const checked=Array.isArray(existing.rows[0].task_checklist_progress)?existing.rows[0].task_checklist_progress:[];
  if(checklist.some((_,i)=>!checked.includes(i)))return res.status(400).json({error:'أكمل كل خطوات قائمة التحقق قبل إغلاق المهمة.'});
  const nextStatus=existing.rows[0].latest_report_status==='approved'?'completed':'awaiting_review';
  const r=await pool.query(`UPDATE work_orders SET status=$1,technician_completed_at=NOW(),completed_at=CASE WHEN $1='completed' THEN COALESCE(completed_at,NOW()) ELSE completed_at END,updated_at=NOW() WHERE id=$2 AND tenant_id=$3 AND assigned_to=$4 RETURNING *`,[nextStatus,req.params.id,tenant(req),req.user.id]);
  audit(req,'work_order.technician_completed','work_order',req.params.id,{status:nextStatus});res.json({order:r.rows[0],message:nextStatus==='completed'?'تم إنهاء المهمة وإغلاقها.':'تم إنهاء المهمة وإرسالها للمدير للمراجعة.'});
}));
app.post('/api/orders/:id/payment',auth,allow('technician'),asyncRoute(async(req,res)=>{
  const x=z.object({collected_amount:z.coerce.number().positive().max(999999999),payment_reference:z.string().max(160).optional()}).strict().parse(req.body);
  const order=await pool.query('SELECT id,service_price,paid_amount,payment_status,payment_method,status FROM work_orders WHERE id=$1 AND tenant_id=$2 AND assigned_to=$3',[req.params.id,tenant(req),req.user.id]);
  if(!order.rowCount)return res.status(404).json({error:'المهمة غير موجودة أو غير مسندة إليك.'});
  if(['cancelled','completed'].includes(order.rows[0].status))return res.status(409).json({error:'المهمة مغلقة.'});
  if(order.rows[0].payment_status==='pending_verification')return res.status(409).json({error:'يوجد تحصيل بانتظار مراجعة المدير بالفعل.'});
  const remaining=Number(order.rows[0].service_price)-Number(order.rows[0].paid_amount||0);
  if(x.collected_amount>remaining)return res.status(400).json({error:`المبلغ أكبر من المتبقي (${remaining}).`});
  const r=await pool.query(`UPDATE work_orders SET collected_amount=$1,payment_reference=$2,payment_recorded_at=NOW(),payment_recorded_by=$3,payment_status='pending_verification',updated_at=NOW() WHERE id=$4 AND tenant_id=$5 RETURNING id,collected_amount,payment_reference,payment_status,currency`,[x.collected_amount,x.payment_reference||null,req.user.id,req.params.id,tenant(req)]);
  audit(req,'work_order.payment_reported','work_order',req.params.id,{collected_amount:x.collected_amount,payment_reference:x.payment_reference||null});res.json({payment:r.rows[0],message:'تم تسجيل التحصيل وإرساله للمدير للتأكيد.'});
}));
app.patch('/api/orders/:id/payment',auth,allow('owner','manager'),asyncRoute(async(req,res)=>{
  const x=z.object({action:z.enum(['confirm','reject','record']),paid_amount:z.coerce.number().nonnegative().max(999999999).optional(),collected_amount:z.coerce.number().positive().max(999999999).optional(),payment_reference:z.string().max(160).optional()}).strict().parse(req.body);
  const current=await pool.query('SELECT id,service_price,paid_amount,collected_amount,currency,payment_status FROM work_orders WHERE id=$1 AND tenant_id=$2',[req.params.id,tenant(req)]);
  if(!current.rowCount)return res.status(404).json({error:'طلب الصيانة غير موجود.'});
  if(x.action==='record'){
    if(current.rows[0].payment_status==='pending_verification')return res.status(409).json({error:'راجع التحصيل المسجل من الفني أولًا.'});
    if(!x.collected_amount)return res.status(400).json({error:'أدخل المبلغ الذي استلمته.'});
    const amount=Number(current.rows[0].paid_amount||0)+x.collected_amount;
    if(amount>Number(current.rows[0].service_price))return res.status(400).json({error:'المبلغ الجديد أكبر من المتبقي على العميل.'});
    const status=amount>=Number(current.rows[0].service_price)?'paid':amount>0?'partial':'unpaid';
    const r=await pool.query(`UPDATE work_orders SET paid_amount=$1,collected_amount=0,payment_reference=$2,payment_recorded_at=NOW(),payment_recorded_by=$3,payment_verified_at=NOW(),payment_verified_by=$3,payment_status=$4,updated_at=NOW() WHERE id=$5 AND tenant_id=$6 RETURNING *`,[amount,x.payment_reference||null,req.user.id,status,req.params.id,tenant(req)]);
    audit(req,'work_order.payment_recorded_by_manager','work_order',req.params.id,{collected_amount:x.collected_amount,paid_amount:amount,payment_reference:x.payment_reference||null});
    return res.json({order:r.rows[0],message:'تم تسجيل السداد واعتماده.'});
  }
  if(current.rows[0].payment_status!=='pending_verification')return res.status(409).json({error:'لا يوجد تحصيل بانتظار المراجعة لهذا الطلب.'});
  if(x.action==='confirm'){
    const amount=x.paid_amount??(Number(current.rows[0].paid_amount||0)+Number(current.rows[0].collected_amount||0));
    if(amount<Number(current.rows[0].paid_amount||0))return res.status(400).json({error:'إجمالي المدفوع لا يمكن أن يقل عن الدفعات المؤكدة السابقة.'});
    if(amount>Number(current.rows[0].service_price))return res.status(400).json({error:'المبلغ المحصل أكبر من سعر الخدمة.'});
    const status=amount>=Number(current.rows[0].service_price)?'paid':amount>0?'partial':'unpaid';
    const r=await pool.query(`UPDATE work_orders SET paid_amount=$1,payment_status=$2,payment_verified_at=NOW(),payment_verified_by=$3,updated_at=NOW() WHERE id=$4 AND tenant_id=$5 RETURNING *`,[amount,status,req.user.id,req.params.id,tenant(req)]);
    audit(req,'work_order.payment_verified','work_order',req.params.id,{paid_amount:amount,payment_status:status});res.json({order:r.rows[0],message:'تم تأكيد التحصيل.'});
  }else{
    const r=await pool.query(`UPDATE work_orders SET payment_status=CASE WHEN paid_amount>0 THEN 'partial' ELSE 'unpaid' END,collected_amount=0,payment_reference=NULL,payment_recorded_at=NULL,payment_recorded_by=NULL,payment_verified_at=NOW(),payment_verified_by=$1,updated_at=NOW() WHERE id=$2 AND tenant_id=$3 RETURNING *`,[req.user.id,req.params.id,tenant(req)]);
    audit(req,'work_order.payment_rejected','work_order',req.params.id);res.json({order:r.rows[0],message:'تم رفض تسجيل التحصيل.'});
  }
}));
app.delete('/api/orders/:id', auth, allow('owner','manager'), asyncRoute(async(req,res)=>{
  const existing=await pool.query('SELECT id FROM work_orders WHERE id=$1 AND tenant_id=$2',[req.params.id,tenant(req)]);
  if(!existing.rowCount) return res.status(404).json({error:'طلب الصيانة غير موجود.'});
  const visits=await pool.query('SELECT COUNT(*)::int AS n FROM visits WHERE work_order_id=$1',[req.params.id]);
  if(visits.rows[0].n) return res.status(409).json({error:'لا يمكن حذف الطلب لوجود تقارير زيارات مرتبطة به. احذف التقارير أولاً أو اترك الطلب في السجل.'});
  await pool.query('DELETE FROM work_orders WHERE id=$1 AND tenant_id=$2',[req.params.id,tenant(req)]);
  audit(req,'work_order.deleted','work_order',req.params.id); res.json({ok:true});
}));

// Visits, audio preservation, AI transcription, report approval
app.get('/api/visits', auth, asyncRoute(async(req,res)=>{
  if(!requireTenant(req,res))return;
  const params=[tenant(req)];let where='v.tenant_id=$1';
  if(req.query.status){params.push(String(req.query.status));where+=` AND v.report_status=$${params.length}`;}
  else if(req.user.role!=='technician'){where+=` AND v.report_status<>'draft'`;}
  if(req.user.role==='technician'){params.push(req.user.id);where+=` AND v.technician_id=$${params.length}`;}
  const r=await pool.query(`SELECT v.*,w.code,w.title AS order_title,w.category,c.name AS customer_name,COALESCE(v.technician_name_snapshot,u.name) AS technician_name FROM visits v JOIN work_orders w ON w.id=v.work_order_id JOIN customers c ON c.id=w.customer_id LEFT JOIN users u ON u.id=v.technician_id WHERE ${where} ORDER BY v.created_at DESC LIMIT 250`,params);
  const visits=req.user.role==='technician'?r.rows.map(technicianSafeVisit):r.rows;
  res.json({visits});
}));
app.post('/api/visits', auth, allow('owner','manager','technician'), subscriptionWriteGate, upload.fields([{name:'audio',maxCount:1},{name:'photos',maxCount:8}]), asyncRoute(async(req,res)=>{
  if(!requireTenant(req,res))return;
  const x=z.object({work_order_id:z.string().uuid(),technician_notes:z.string().max(6000).optional(),report_body:z.string().max(12000).optional(),latitude:z.coerce.number().min(-90).max(90).optional(),longitude:z.coerce.number().min(-180).max(180).optional()}).parse(req.body);
  const order=await pool.query('SELECT w.id,w.status,w.assigned_to,u.name AS assigned_technician_name FROM work_orders w LEFT JOIN users u ON u.id=w.assigned_to WHERE w.id=$1 AND w.tenant_id=$2',[x.work_order_id,tenant(req)]);
  if(!order.rowCount)return res.status(404).json({error:'طلب الصيانة غير موجود.'});
  if(order.rows[0].status==='cancelled')return res.status(409).json({error:'لا يمكن تسجيل زيارة على طلب ملغي.'});
  if(req.user.role==='technician'&&order.rows[0].status==='completed')return res.status(409).json({error:'الطلب مكتمل بالفعل. تواصل مع المدير إذا كنت تحتاج زيارة إضافية.'});
  const technicianId=req.user.role==='technician'?req.user.id:(order.rows[0].assigned_to||null);
  const technicianName=req.user.role==='technician'?req.user.name:(order.rows[0].assigned_technician_name||null);
  if(req.user.role==='technician' && order.rows[0].assigned_to!==req.user.id)return res.status(403).json({error:'المهمة غير مسندة إليك.'});
  const audio=req.files?.audio?.[0]; if(!audio&&!String(x.report_body||'').trim()&&!String(x.technician_notes||'').trim())return res.status(400).json({error:'سجّل صوتك أو اكتب ملخص الزيارة قبل الحفظ.'}); const photos=(req.files?.photos||[]).map(f=>({url:`/api/media/${f.filename}`,name:f.originalname,mime:f.mimetype}));
  const r=await pool.query(`INSERT INTO visits (tenant_id,work_order_id,technician_id,technician_name_snapshot,technician_notes,audio_path,audio_mime,photos,report_body,latitude,longitude,report_status,check_out_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW()) RETURNING *`,[tenant(req),x.work_order_id,technicianId,technicianName,x.technician_notes||null,audio?`/api/media/${audio.filename}`:null,audio?.mimetype||null,JSON.stringify(photos),x.report_body||'',x.latitude??null,x.longitude??null,audio?'draft':'pending']);
  // Keep the service order open until a manager reviews the report and updates its status.
  audit(req,'visit.created','visit',r.rows[0].id);const visit=req.user.role==='technician'?technicianSafeVisit(r.rows[0]):r.rows[0];res.status(201).json({visit,message:'تم حفظ الزيارة وإرسال التقرير للمراجعة.'});
}));
app.post('/api/visits/:id/transcribe', auth, allow('owner','manager','technician'), subscriptionWriteGate, asyncRoute(async(req,res)=>{
  const r=await pool.query('SELECT * FROM visits WHERE id=$1 AND tenant_id=$2',[req.params.id,tenant(req)]);
  if(!r.rowCount)return res.status(404).json({error:'الزيارة غير موجودة.'});
  const visit=r.rows[0];
  if(req.user.role==='technician'&&visit.technician_id!==req.user.id)return res.status(403).json({error:'غير مسموح.'});
  if(visit.report_status==='approved') return res.status(409).json({error:'التقرير المعتمد لا يمكن إعادة تحويله.'});
  if(!visit.audio_path)return res.status(400).json({error:'مفيش تسجيل صوتي مرفوع للزيارة.'});

  // Cloud voice processing uses Groq only. No OpenAI key or local model is required.
  const apiKey=String(process.env.GROQ_API_KEY||'').trim();
  if(!apiKey)return res.status(503).json({error:'خدمة تحويل الصوت عبر Groq غير مفعّلة. أضف GROQ_API_KEY إلى ملف .env في جذر المشروع ثم أعد تشغيل الخادم.'});
  const provider='groq';
  const apiBase='https://api.groq.com/openai/v1';
  const audioFile=path.join(storageDir,path.basename(visit.audio_path));
  if(!fs.existsSync(audioFile))return res.status(404).json({error:'ملف التسجيل غير موجود على الخادم. أعد رفع التسجيل من جهاز الفني.'});

  const audioBuffer=await fs.promises.readFile(audioFile);
  const form=new FormData();
  form.append('file',new Blob([audioBuffer],{type:visit.audio_mime||'audio/webm'}),path.basename(audioFile));
  const transcriptionModel=process.env.GROQ_TRANSCRIBE_MODEL||'whisper-large-v3-turbo';
  form.append('model',transcriptionModel);
  form.append('language','ar');
  form.append('prompt','تسجيل فني صيانة يتحدث باللهجة المصرية عن عطل وإجراءات فحص وإصلاح. احتفظ بالأرقام والقياسات وأسماء قطع الغيار كما قيلت ولا تصححها بالتخمين.');

  const transcriptionResponse=await fetch(`${apiBase}/audio/transcriptions`,{
    method:'POST',
    headers:{Authorization:`Bearer ${apiKey}`},
    body:form,
    signal:AbortSignal.timeout(120000),
  });
  const transcriptionText=await transcriptionResponse.text();
  let transcriptionData={};
  try{transcriptionData=JSON.parse(transcriptionText)}catch{transcriptionData={error:{message:transcriptionText.slice(0,500)}}}
  if(!transcriptionResponse.ok){
    if(transcriptionResponse.status===429){
      const wait=transcriptionResponse.headers.get('retry-after');
      return res.status(429).json({error:wait?`وصلنا للحد المجاني مؤقتًا. جرّب بعد ${wait} ثانية.`:'وصلنا للحد المجاني لخدمة تحويل الصوت. جرّب بعد قليل أو راجع حدود الاستخدام.'});
    }
    console.error('Voice transcription provider error:',provider,transcriptionResponse.status,transcriptionData.error?.message||'Unknown provider error');
    return res.status(transcriptionResponse.status>=400&&transcriptionResponse.status<500?transcriptionResponse.status:502)
      .json({error:transcriptionData.error?.message||'تعذر تحويل التسجيل الصوتي من الخدمة السحابية.'});
  }
  const transcript=String(transcriptionData.text||'').trim();
  if(!transcript)return res.status(422).json({error:'لم نتمكن من استخراج كلام واضح من التسجيل. جرّب تسجيلًا أوضح.'});

  const reportModel=process.env.GROQ_REPORT_MODEL||'openai/gpt-oss-20b';
  const reportPrompt='أنت مساعد متخصص في تحرير تقارير الصيانة الداخلية. حوّل كلام الفني باللهجة المصرية إلى عربية واضحة ومهنية ومنظمة، مع الحفاظ على المعنى والأرقام كما قيلت. استخرج فقط المعلومات المذكورة صراحة؛ ممنوع اختراع قياسات أو قطع غيار أو سبب عطل أو نتيجة اختبار. إذا لم تُذكر معلومة ضعها null وأضف سؤالاً محدداً عنها في missing_information. أعد JSON فقط بالمفاتيح: problem, inspection, actions, parts, readings, result, recommendations, missing_information, report_body. اجعل report_body تقريراً نظيفاً بعناوين مناسبة مثل وصف المشكلة، الفحص والمعاينة، الأعمال المنفذة، قطع الغيار، القراءات، النتيجة والتوصيات. احذف أي عنوان لا توجد له معلومة، ولا تعرض null في التقرير النهائي.';
  let aiResponse=null;
  let aiData={};
  try{
    aiResponse=await fetch(`${apiBase}/chat/completions`,{
      method:'POST',
      headers:{Authorization:`Bearer ${apiKey}`,'Content-Type':'application/json'},
      body:JSON.stringify({
        model:reportModel,
        response_format:{type:'json_object'},
        messages:[
          {role:'system',content:reportPrompt},
          {role:'user',content:`ملاحظات الفني: ${visit.technician_notes||'لا يوجد'}\nالتفريغ الصوتي: ${transcript}`},
        ],
      }),
      signal:AbortSignal.timeout(120000),
    });
    const aiText=await aiResponse.text();
    try{aiData=JSON.parse(aiText)}catch{aiData={error:{message:aiText.slice(0,500)}}}
  }catch(err){
    console.warn('Report formatting request failed; keeping transcript as editable draft:',err.message);
    aiData={error:{message:err.message}};
  }
  let extracted={};
  if(aiResponse?.ok){
    try{extracted=JSON.parse(aiData.choices?.[0]?.message?.content||'{}')}catch{}
  }else{
    console.warn('Report formatting unavailable; keeping transcript as editable draft:',provider,aiResponse?.status||'network error',aiData.error?.message||'Unknown provider error');
    extracted={missing_information:['تم تفريغ التسجيل، لكن تعذر تنسيق التقرير آليًا الآن. راجع النص ورتّبه يدويًا قبل الاعتماد.']};
  }
  const report=String(extracted.report_body||`ملخص الزيارة\n${transcript}`);
  const updated=await pool.query(
    `UPDATE visits SET transcript=$1,extracted_data=$2::jsonb,report_body=$3,missing_information=$4::jsonb,report_status=$5 WHERE id=$6 AND tenant_id=$7 RETURNING *`,
    [transcript,JSON.stringify(extracted),report,JSON.stringify(extracted.missing_information||[]),req.user.role==='technician'?'draft':'pending',req.params.id,tenant(req)]
  );
  const responseVisit=req.user.role==='technician'?technicianSafeVisit(updated.rows[0]):updated.rows[0];
  res.json({visit:responseVisit,provider,transcription_model:transcriptionModel,report_model:reportModel,report_formatted:!!aiResponse?.ok});
}));
app.patch('/api/visits/:id', auth, allow('owner','manager','technician'), subscriptionWriteGate, asyncRoute(async(req,res)=>{
  const x=z.object({technician_notes:z.string().max(6000).optional(),report_body:z.string().max(12000).optional(),report_status:z.enum(['draft','pending','rejected']).optional(),manager_notes:z.string().max(3000).optional()}).strict().parse(req.body);
  const old=await pool.query('SELECT * FROM visits WHERE id=$1 AND tenant_id=$2',[req.params.id,tenant(req)]);if(!old.rowCount)return res.status(404).json({error:'الزيارة غير موجودة.'});
  if(req.user.role==='technician'&&old.rows[0].technician_id!==req.user.id)return res.status(403).json({error:'غير مسموح.'});
  if(old.rows[0].report_status==='approved') return res.status(409).json({error:'التقرير المعتمد لا يمكن تعديله.'});
  if(req.user.role==='technician' && (Object.prototype.hasOwnProperty.call(x,'manager_notes') || (x.report_status && !['draft','pending'].includes(x.report_status)))) return res.status(403).json({error:'الفني يقدر يعدل تقريره ويرسله للمراجعة فقط.'});
  const keys=Object.keys(x);if(!keys.length)return res.status(400).json({error:'مفيش بيانات للتعديل.'});
  const sets=keys.map((k,i)=>`"${k}"=$${i+3}`).join(',');const values=keys.map(k=>x[k]);
  const r=await pool.query(`UPDATE visits SET ${sets} WHERE id=$1 AND tenant_id=$2 RETURNING *`,[req.params.id,tenant(req),...values]);
  if(req.user.role!=='technician'&&x.report_status==='rejected')await pool.query(`UPDATE work_orders SET status='in_progress',updated_at=NOW() WHERE id=$1 AND tenant_id=$2 AND status='awaiting_review'`,[r.rows[0].work_order_id,tenant(req)]);
  const visit=req.user.role==='technician'?technicianSafeVisit(r.rows[0]):r.rows[0];res.json({visit});
}));
app.delete('/api/visits/:id', auth, allow('owner','manager'), asyncRoute(async(req,res)=>{
  const found=await pool.query('SELECT work_order_id,audio_path,photos FROM visits WHERE id=$1 AND tenant_id=$2',[req.params.id,tenant(req)]);
  if(!found.rowCount) return res.status(404).json({error:'التقرير غير موجود.'});
  await pool.query('DELETE FROM visits WHERE id=$1 AND tenant_id=$2',[req.params.id,tenant(req)]);
  await pool.query(`UPDATE work_orders SET status='in_progress',updated_at=NOW() WHERE id=$1 AND tenant_id=$2 AND status='awaiting_review'`,[found.rows[0].work_order_id,tenant(req)]);
  const media=[found.rows[0].audio_path,...(Array.isArray(found.rows[0].photos)?found.rows[0].photos.map(p=>p.url):[])].filter(Boolean);
  for(const item of media){const file=path.join(storageDir,path.basename(item));try{await fs.promises.unlink(file);}catch(e){if(e.code!=='ENOENT') console.warn('Could not remove report file:',e.message);}}
  audit(req,'visit.deleted','visit',req.params.id); res.json({ok:true});
}));
app.post('/api/visits/:id/approve', auth, allow('owner','manager'), subscriptionWriteGate, asyncRoute(async(req,res)=>{
  const x=z.object({manager_notes:z.string().max(3000).optional()}).parse(req.body||{});
  const current=await pool.query('SELECT report_body FROM visits WHERE id=$1 AND tenant_id=$2',[req.params.id,tenant(req)]);if(!current.rowCount)return res.status(404).json({error:'التقرير غير موجود.'});if(!String(current.rows[0].report_body||'').trim())return res.status(400).json({error:'اكتب أو أنشئ محتوى التقرير قبل الاعتماد.'});
  const r=await pool.query(`UPDATE visits SET report_status='approved',approved_by=$1,approved_at=NOW(),public_token=NULL,manager_notes=$2 WHERE id=$3 AND tenant_id=$4 AND report_status<>'approved' RETURNING *`,[req.user.id,x.manager_notes||null,req.params.id,tenant(req)]);
  if(!r.rowCount)return res.status(404).json({error:'التقرير غير موجود أو تم اعتماده مسبقًا.'});
  await pool.query(`UPDATE work_orders SET status='completed',completed_at=COALESCE(completed_at,NOW()),updated_at=NOW() WHERE id=$1 AND tenant_id=$2 AND status='awaiting_review' AND NOT EXISTS (SELECT 1 FROM visits newer WHERE newer.work_order_id=work_orders.id AND newer.tenant_id=work_orders.tenant_id AND newer.created_at>$3)`,[r.rows[0].work_order_id,tenant(req),r.rows[0].created_at]);
  audit(req,'visit.approved','visit',req.params.id);
  res.json({visit:r.rows[0],message:'تم اعتماد التقرير داخل الشركة.'});
}));
app.get('/api/media/:filename',auth,asyncRoute(async(req,res)=>{
  if(!requireTenant(req,res))return; const filename=path.basename(req.params.filename);
  const params=[tenant(req),`/api/media/${filename}`,JSON.stringify([{url:`/api/media/${filename}`}])];
  let ownerFilter='';if(req.user.role==='technician'){params.push(req.user.id);ownerFilter=` AND technician_id=$${params.length}`;}
  const r=await pool.query(`SELECT id FROM visits WHERE tenant_id=$1 AND (audio_path=$2 OR photos @> $3::jsonb)${ownerFilter} LIMIT 1`,params);
  if(!r.rowCount)return res.status(404).json({error:'الملف غير موجود.'}); const f=path.join(storageDir,filename);if(!fs.existsSync(f))return res.status(404).json({error:'الملف غير موجود.'});res.setHeader('X-Content-Type-Options','nosniff');res.sendFile(f);
}));
app.get('/api/platform/payments/:id/proof',auth,allow('platform_admin'),asyncRoute(async(req,res)=>{const r=await pool.query('SELECT proof_path FROM payment_requests WHERE id=$1',[req.params.id]);if(!r.rowCount||!r.rows[0].proof_path)return res.status(404).json({error:'الإيصال غير موجود.'});const f=path.join(storageDir,path.basename(r.rows[0].proof_path));if(!fs.existsSync(f))return res.status(404).json({error:'الملف غير موجود.'});res.setHeader('X-Content-Type-Options','nosniff');res.sendFile(f);}));
// Quotations and invoices
async function listFinancial(req,res,table) { if(!requireTenant(req,res))return; const r=await pool.query(`SELECT x.*,c.name AS customer_name FROM ${table} x JOIN customers c ON c.id=x.customer_id WHERE x.tenant_id=$1 ORDER BY x.created_at DESC LIMIT 250`,[tenant(req)]);res.json({items:r.rows}); }
async function createFinancial(req,res,table,prefix) {
  if(!requireTenant(req,res))return;
  const x=z.object({customer_id:z.string().uuid(),work_order_id:z.string().uuid().nullable().optional(),title:z.string().min(2).max(180),items:z.array(z.object({description:z.string().min(1).max(160),quantity:z.number().positive(),unit_price:z.number().nonnegative()})).min(1).max(50),tax:z.number().nonnegative().default(0),due_date:z.string().optional(),valid_until:z.string().optional()}).parse(req.body);
  const customer=await pool.query('SELECT id FROM customers WHERE id=$1 AND tenant_id=$2',[x.customer_id,tenant(req)]);if(!customer.rowCount)return res.status(400).json({error:'العميل غير صالح.'});
  if(x.work_order_id){const order=await pool.query('SELECT id FROM work_orders WHERE id=$1 AND tenant_id=$2',[x.work_order_id,tenant(req)]);if(!order.rowCount)return res.status(400).json({error:'طلب الصيانة غير صالح.'});}
  const subtotal=x.items.reduce((sum,i)=>sum+i.quantity*i.unit_price,0);const total=subtotal+x.tax;const code=makeCode(prefix);
  const r=await pool.query(`INSERT INTO ${table} (tenant_id,customer_id,work_order_id,code,title,items,subtotal,tax,total,${table==='invoices'?'due_date':'valid_until'}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,[tenant(req),x.customer_id,x.work_order_id||null,code,x.title,JSON.stringify(x.items),subtotal,x.tax||0,total,x[table==='invoices'?'due_date':'valid_until']||null]);
  res.status(201).json({item:r.rows[0]});
}
app.get('/api/quotations',auth,allow('owner','manager'),featureGate('quotations'),asyncRoute((req,res)=>listFinancial(req,res,'quotations')));
app.post('/api/quotations',auth,allow('owner','manager'),featureGate('quotations'),asyncRoute((req,res)=>createFinancial(req,res,'quotations','QT')));
app.patch('/api/quotations/:id/status',auth,allow('owner','manager'),featureGate('quotations'),asyncRoute(async(req,res)=>{const x=z.object({status:z.enum(['draft','sent','accepted','rejected','expired'])}).parse(req.body);const r=await pool.query('UPDATE quotations SET status=$1 WHERE id=$2 AND tenant_id=$3 RETURNING *',[x.status,req.params.id,tenant(req)]);if(!r.rowCount)return res.status(404).json({error:'عرض السعر غير موجود.'});res.json({item:r.rows[0]});}));
app.get('/api/invoices',auth,allow('owner','manager'),featureGate('invoices'),asyncRoute((req,res)=>listFinancial(req,res,'invoices')));
app.post('/api/invoices',auth,allow('owner','manager'),featureGate('invoices'),asyncRoute((req,res)=>createFinancial(req,res,'invoices','INV')));
app.patch('/api/invoices/:id/payment',auth,allow('owner','manager'),featureGate('invoices'),asyncRoute(async(req,res)=>{const x=z.object({paid_amount:z.number().nonnegative()}).parse(req.body);const r=await pool.query(`UPDATE invoices SET paid_amount=LEAST(total,$1),status=CASE WHEN LEAST(total,$1)>=total THEN 'paid' WHEN LEAST(total,$1)>0 THEN 'partial' ELSE 'unpaid' END WHERE id=$2 AND tenant_id=$3 RETURNING *`,[x.paid_amount,req.params.id,tenant(req)]);if(!r.rowCount)return res.status(404).json({error:'الفاتورة غير موجودة.'});res.json({item:r.rows[0]});}));

// Contracts and reminders
app.get('/api/contracts',auth,allow('owner','manager'),featureGate('contracts'),asyncRoute(async(req,res)=>{const r=await pool.query(`SELECT c.*,cu.name AS customer_name FROM contracts c JOIN customers cu ON cu.id=c.customer_id WHERE c.tenant_id=$1 ORDER BY c.next_visit_on NULLS LAST`,[tenant(req)]);res.json({items:r.rows});}));
app.post('/api/contracts',auth,allow('owner','manager'),featureGate('contracts'),asyncRoute(async(req,res)=>{const x=z.object({customer_id:z.string().uuid(),title:z.string().min(2),service_description:z.string().optional(),frequency:z.enum(['monthly','every_3_months','every_6_months','yearly']),starts_on:z.string(),ends_on:z.string().optional(),next_visit_on:z.string(),amount:z.number().nonnegative().default(0)}).parse(req.body);const r=await pool.query(`INSERT INTO contracts (tenant_id,customer_id,title,service_description,frequency,starts_on,ends_on,next_visit_on,amount) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,[tenant(req),x.customer_id,x.title,x.service_description||null,x.frequency,x.starts_on,x.ends_on||null,x.next_visit_on,x.amount]);await pool.query(`INSERT INTO reminders (tenant_id,customer_id,title,body,due_at) VALUES ($1,$2,$3,$4,$5::date::timestamp + INTERVAL '9 hours')`,[tenant(req),x.customer_id,`موعد الصيانة الدوري: ${x.title}`,'موعد الزيارة القادمة حسب عقد الصيانة.',x.next_visit_on]);res.status(201).json({item:r.rows[0]});}));
app.get('/api/reminders',auth,allow('owner','manager'),featureGate('reminders'),asyncRoute(async(req,res)=>{const r=await pool.query(`SELECT r.*,c.name AS customer_name FROM reminders r LEFT JOIN customers c ON c.id=r.customer_id WHERE r.tenant_id=$1 ORDER BY r.due_at ASC LIMIT 250`,[tenant(req)]);res.json({items:r.rows});}));
app.post('/api/reminders',auth,allow('owner','manager'),featureGate('reminders'),asyncRoute(async(req,res)=>{const x=z.object({customer_id:z.string().uuid().nullable().optional(),work_order_id:z.string().uuid().nullable().optional(),title:z.string().min(2).max(180),body:z.string().max(1000).optional(),due_at:z.string().datetime()}).parse(req.body);const r=await pool.query(`INSERT INTO reminders (tenant_id,customer_id,work_order_id,title,body,due_at) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,[tenant(req),x.customer_id||null,x.work_order_id||null,x.title,x.body||null,x.due_at]);res.status(201).json({item:r.rows[0]});}));
app.patch('/api/reminders/:id',auth,allow('owner','manager'),featureGate('reminders'),asyncRoute(async(req,res)=>{const x=z.object({status:z.enum(['open','done','cancelled'])}).parse(req.body);const r=await pool.query('UPDATE reminders SET status=$1 WHERE id=$2 AND tenant_id=$3 RETURNING *',[x.status,req.params.id,tenant(req)]);if(!r.rowCount)return res.status(404).json({error:'التذكير غير موجود.'});res.json({item:r.rows[0]});}));

// Subscription plans & payments. Transfer proof is reviewed by platform staff; never activate on upload alone.
app.get('/api/billing',auth,allow('owner','manager'),asyncRoute(async(req,res)=>{
  if(!requireTenant(req,res))return;
  const [requests,settings]=await Promise.all([pool.query('SELECT id,plan_code,billing_cycle,amount,method,transaction_reference,payer_phone,status,admin_note,created_at FROM payment_requests WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 20',[tenant(req)]),pool.query("SELECT value FROM platform_settings WHERE key='payment_methods'")]);
  const count=await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE tenant_id=$1 AND role='technician' AND status='active'",[tenant(req)]);
  res.json({plans:Object.values(PLANS),current:{plan_code:req.user.plan_code,subscription_status:req.user.subscription_status,billing_cycle:req.user.billing_cycle,trial_ends_at:req.user.trial_ends_at,subscription_ends_at:req.user.subscription_ends_at,technicians:count.rows[0].n},payments:requests.rows,paymentMethods:settings.rows[0]?.value||{}});
}));
app.post('/api/billing/request',auth,allow('owner','manager'),upload.single('proof'),asyncRoute(async(req,res)=>{
  if(!requireTenant(req,res))return;
  const x=z.object({plan_code:z.enum(['starter','growth','pro']),billing_cycle:z.enum(['monthly','yearly']),method:z.enum(['vodafone_cash','instapay']),transaction_reference:z.string().max(120).optional(),payer_phone:z.string().max(30).optional()}).parse(req.body);
  const plan=PLANS[x.plan_code];const amount=x.billing_cycle==='yearly'?plan.yearly:plan.monthly;
  if(!x.transaction_reference&&!req.file)return res.status(400).json({error:'اكتب رقم العملية وارفع صورة إثبات الدفع.'});
  const r=await pool.query(`INSERT INTO payment_requests (tenant_id,plan_code,billing_cycle,amount,method,transaction_reference,payer_phone,proof_path) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,status,amount,method,created_at`,[tenant(req),x.plan_code,x.billing_cycle,amount,x.method,x.transaction_reference||null,x.payer_phone||null,req.file?req.file.filename:null]);
  res.status(201).json({payment:r.rows[0],message:'تم استلام طلب الدفع. الاشتراك هيتفعل بعد تأكيد العملية من الإدارة.'});
}));

// Platform administration
app.get('/api/platform/overview',auth,allow('platform_admin'),asyncRoute(async(req,res)=>{
  const [tenants,users,payments,revenue,recent]=await Promise.all([
    pool.query('SELECT COUNT(*)::int AS total,COUNT(*) FILTER (WHERE subscription_status=\'active\')::int AS active,COUNT(*) FILTER (WHERE subscription_status=\'trial\')::int AS trial,COUNT(*) FILTER (WHERE status=\'suspended\')::int AS suspended FROM tenants'),
    pool.query('SELECT COUNT(*)::int AS total FROM users'),
    pool.query("SELECT COUNT(*)::int AS pending FROM payment_requests WHERE status='pending'"),
    pool.query("SELECT COALESCE(SUM(amount),0)::numeric(12,2) AS total FROM payment_requests WHERE status='approved'"),
    pool.query(`SELECT t.id,t.name,t.slug,t.industry,t.created_at,COUNT(u.id)::int AS users FROM tenants t LEFT JOIN users u ON u.tenant_id=t.id GROUP BY t.id ORDER BY t.created_at DESC LIMIT 12`),
  ]);
  res.json({stats:{...tenants.rows[0],users:users.rows[0].total,pending_payments:payments.rows[0].pending,approved_payments:revenue.rows[0].total},recent:recent.rows});
}));
app.get('/api/platform/tenants',auth,allow('platform_admin'),asyncRoute(async(req,res)=>{const r=await pool.query(`SELECT t.*,COUNT(u.id)::int AS users FROM tenants t LEFT JOIN users u ON u.tenant_id=t.id GROUP BY t.id ORDER BY t.created_at DESC`);res.json({tenants:r.rows});}));
app.patch('/api/platform/tenants/:id',auth,allow('platform_admin'),asyncRoute(async(req,res)=>{const x=z.object({status:z.enum(['active','suspended']).optional(),subscription_status:z.enum(['trial','active','past_due','cancelled','expired']).optional(),plan_code:z.enum(['starter','growth','pro']).optional(),subscription_ends_at:z.string().datetime().nullable().optional()}).parse(req.body);const keys=Object.keys(x);if(!keys.length)return res.status(400).json({error:'مفيش بيانات.'});const sets=keys.map((k,i)=>`"${k}"=$${i+2}`).join(',');const r=await pool.query(`UPDATE tenants SET ${sets} WHERE id=$1 RETURNING *`,[req.params.id,...keys.map(k=>x[k])]);if(!r.rowCount)return res.status(404).json({error:'الشركة غير موجودة.'});res.json({tenant:r.rows[0]});}));
app.get('/api/platform/payments',auth,allow('platform_admin'),asyncRoute(async(req,res)=>{const r=await pool.query(`SELECT p.*,t.name AS company_name,t.email AS company_email FROM payment_requests p JOIN tenants t ON t.id=p.tenant_id ORDER BY CASE p.status WHEN 'pending' THEN 0 ELSE 1 END,p.created_at DESC LIMIT 300`);res.json({payments:r.rows});}));
app.patch('/api/platform/payments/:id/review',auth,allow('platform_admin'),asyncRoute(async(req,res)=>{
  const x=z.object({decision:z.enum(['approved','rejected']),admin_note:z.string().max(1000).optional()}).parse(req.body);
  const client=await pool.connect();try{await client.query('BEGIN');const p=await client.query('SELECT * FROM payment_requests WHERE id=$1 FOR UPDATE',[req.params.id]);if(!p.rowCount){await client.query('ROLLBACK');return res.status(404).json({error:'طلب الدفع غير موجود.'});}if(p.rows[0].status!=='pending'){await client.query('ROLLBACK');return res.status(409).json({error:'تمت مراجعة الطلب بالفعل.'});}
    await client.query(`UPDATE payment_requests SET status=$1,admin_note=$2,reviewed_by=$3,reviewed_at=NOW() WHERE id=$4`,[x.decision,x.admin_note||null,req.user.id,req.params.id]);
    if(x.decision==='approved'){const pmt=p.rows[0];await client.query(`UPDATE tenants SET plan_code=$1,subscription_status='active',billing_cycle=$2,subscription_ends_at=CASE WHEN subscription_ends_at>NOW() THEN subscription_ends_at + CASE WHEN $2='yearly' THEN INTERVAL '1 year' ELSE INTERVAL '1 month' END ELSE NOW() + CASE WHEN $2='yearly' THEN INTERVAL '1 year' ELSE INTERVAL '1 month' END END WHERE id=$3`,[pmt.plan_code,pmt.billing_cycle,pmt.tenant_id]);}
    await client.query('COMMIT');res.json({ok:true,message:x.decision==='approved'?'تم اعتماد الدفع وتفعيل الاشتراك.':'تم رفض طلب الدفع.'});
  }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
}));
app.get('/api/platform/settings',auth,allow('platform_admin'),asyncRoute(async(req,res)=>{const r=await pool.query("SELECT value FROM platform_settings WHERE key='payment_methods'");res.json({settings:r.rows[0]?.value||{vodafone_cash_number:'',instapay_address:'',instapay_qr_url:'',payment_instructions:'',checkout_url:''}});}));
app.put('/api/platform/settings',auth,allow('platform_admin'),asyncRoute(async(req,res)=>{const x=z.object({vodafone_cash_number:z.string().max(50).optional(),instapay_address:z.string().max(120).optional(),instapay_qr_url:z.string().max(500).optional(),payment_instructions:z.string().max(1500).optional(),checkout_url:z.string().max(500).optional()}).parse(req.body);await pool.query(`INSERT INTO platform_settings(key,value) VALUES ('payment_methods',$1::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()`,[JSON.stringify(x)]);res.json({settings:x});}));

// Error and static app handling
app.use((err,req,res,_next)=>{
  console.error(`[${new Date().toISOString()}]`,err.stack||err.message||err);
  if(err instanceof z.ZodError)return res.status(400).json({error:'راجع البيانات المدخلة.',details:err.issues.map(i=>({field:i.path.join('.'),message:i.message}))});
  if(err instanceof multer.MulterError)return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'الملف أكبر من 25 ميجابايت.':'تعذر رفع الملف.'});
  if(err.message?.includes('نوع الملف غير مسموح'))return res.status(415).json({error:err.message});
  const status=err.status&&Number.isInteger(err.status)?err.status:500;
  res.status(status).json({error:status===500?'حصل خطأ غير متوقع في السيرفر.':err.message});
});

const dist=path.resolve(__dirname,'..','client','dist');
if(fs.existsSync(dist)){
  app.use(express.static(dist,{index:false}));
  app.get('*',(req,res)=>{if(req.path.startsWith('/api/'))return res.status(404).json({error:'المسار غير موجود.'});res.sendFile(path.join(dist,'index.html'));});
}

(async()=>{
  await initDatabase();
  await initOptimizationSchema(pool);
  app.listen(PORT,'0.0.0.0',()=>{
    console.log(`FieldFlow listening on :${PORT}`);
    console.log(`Voice AI provider: ${process.env.GROQ_API_KEY?.trim()?'Groq Cloud':'DISABLED - add GROQ_API_KEY to .env'}`);
    console.log('API version: 1.3.0');
  });
})().catch(err=>{console.error('Startup failed:',err);process.exit(1);});
