// FieldFlow Operations Research module.
// All records are tenant-scoped. Recommendations are simulated first;
// work orders change only after an owner/manager explicitly applies a run.
const PRIORITY_WEIGHT = { urgent: 4, high: 3, normal: 2, low: 1 };
const DEFAULT_TRAVEL_SPEED_KMH = 25;

async function initOptimizationSchema(pool) {
  const statements = [
    `CREATE TABLE IF NOT EXISTS fieldflow_or_technician_profiles (
      id uuid PRIMARY KEY,
      tenant_id uuid NOT NULL,
      technician_id uuid NOT NULL,
      skills jsonb NOT NULL DEFAULT '[]'::jsonb,
      base_city varchar(120),
      base_latitude double precision,
      base_longitude double precision,
      shift_start time NOT NULL DEFAULT '09:00',
      shift_end time NOT NULL DEFAULT '17:00',
      daily_capacity_minutes integer NOT NULL DEFAULT 480,
      hourly_cost numeric(14,2) NOT NULL DEFAULT 0,
      travel_cost_per_km numeric(14,2) NOT NULL DEFAULT 0,
      cost_currency varchar(3) NOT NULL DEFAULT 'EGP',
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, technician_id)
    )`,
    `CREATE INDEX IF NOT EXISTS fieldflow_or_technician_profiles_tenant_idx ON fieldflow_or_technician_profiles(tenant_id)`,
    `CREATE TABLE IF NOT EXISTS fieldflow_or_job_profiles (
      id uuid PRIMARY KEY,
      tenant_id uuid NOT NULL,
      work_order_id uuid NOT NULL,
      required_skills jsonb NOT NULL DEFAULT '[]'::jsonb,
      latitude double precision,
      longitude double precision,
      estimated_duration_minutes integer,
      service_window_start time,
      service_window_end time,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, work_order_id)
    )`,
    `CREATE INDEX IF NOT EXISTS fieldflow_or_job_profiles_tenant_idx ON fieldflow_or_job_profiles(tenant_id)`,
    `CREATE TABLE IF NOT EXISTS fieldflow_or_inventory_items (
      id uuid PRIMARY KEY,
      tenant_id uuid NOT NULL,
      name varchar(180) NOT NULL,
      sku varchar(80),
      unit varchar(30) NOT NULL DEFAULT 'قطعة',
      quantity_on_hand numeric(14,2) NOT NULL DEFAULT 0,
      average_daily_usage numeric(14,4) NOT NULL DEFAULT 0,
      lead_time_days integer NOT NULL DEFAULT 7,
      safety_stock_days integer NOT NULL DEFAULT 3,
      unit_cost numeric(14,2) NOT NULL DEFAULT 0,
      cost_currency varchar(3) NOT NULL DEFAULT 'EGP',
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, sku)
    )`,
    `CREATE INDEX IF NOT EXISTS fieldflow_or_inventory_tenant_idx ON fieldflow_or_inventory_items(tenant_id)`,
    `CREATE TABLE IF NOT EXISTS fieldflow_or_runs (
      id uuid PRIMARY KEY,
      tenant_id uuid NOT NULL,
      created_by uuid NOT NULL,
      title varchar(180) NOT NULL,
      inputs jsonb NOT NULL DEFAULT '{}'::jsonb,
      result jsonb NOT NULL DEFAULT '{}'::jsonb,
      applied_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now()
    )`,
    `CREATE INDEX IF NOT EXISTS fieldflow_or_runs_tenant_created_idx ON fieldflow_or_runs(tenant_id, created_at DESC)`,
  ];
  for (const sql of statements) await pool.query(sql);
}

function asArray(value) { return Array.isArray(value) ? value : []; }
function normalizeWords(values) {
  return asArray(values).map(value => String(value || '').trim().toLocaleLowerCase()).filter(Boolean);
}
function minutesFromTime(value, fallback = 9 * 60) {
  const match = String(value || '').match(/^(\d{1,2}):(\d{2})/);
  return match ? Number(match[1]) * 60 + Number(match[2]) : fallback;
}
function timeLabel(minutes) {
  const safe = Math.max(0, Math.min(24 * 60 - 1, Math.round(minutes)));
  return `${String(Math.floor(safe / 60)).padStart(2, '0')}:${String(safe % 60).padStart(2, '0')}`;
}
function hasCoordinate(value) { return value !== null && value !== undefined && value !== '' && Number.isFinite(Number(value)); }
function distanceKm(a, b) {
  if (!a || !b || !hasCoordinate(a.latitude) || !hasCoordinate(a.longitude) || !hasCoordinate(b.latitude) || !hasCoordinate(b.longitude)) return null;
  const rad = value => Number(value) * Math.PI / 180;
  const dLat = rad(Number(b.latitude) - Number(a.latitude));
  const dLon = rad(Number(b.longitude) - Number(a.longitude));
  const x = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.latitude)) * Math.cos(rad(b.latitude)) * Math.sin(dLon / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(x), Math.sqrt(1 - x));
}
function profileMap(rows, key) { return new Map(rows.map(row => [row[key], row])); }
function inventoryAdvice(item) {
  const daily = Number(item.average_daily_usage || 0);
  const lead = Number(item.lead_time_days || 0);
  const safety = Number(item.safety_stock_days || 0);
  const reorderPoint = daily * (lead + safety);
  const current = Number(item.quantity_on_hand || 0);
  return {
    ...item,
    reorder_point: Number(reorderPoint.toFixed(2)),
    suggested_order_quantity: Number(Math.max(0, Math.ceil(reorderPoint - current)).toFixed(2)),
    needs_reorder: current < reorderPoint,
  };
}

function registerOptimizationRoutes(app, deps) {
  const { pool, auth, allow, tenant, asyncRoute, z, crypto } = deps;
  const manager = [auth, allow('owner', 'manager')];

  app.get('/api/optimization/data', ...manager, asyncRoute(async (req, res) => {
    const tid = tenant(req);
    const [ordersR, techniciansR, techProfilesR, jobProfilesR, inventoryR, forecastR, runsR] = await Promise.all([
      pool.query(`SELECT id,code,title,category,priority,status,assigned_to,scheduled_at,address,city,
        expected_duration_minutes,service_price,currency,created_at
        FROM work_orders WHERE tenant_id=$1 AND status NOT IN ('completed','cancelled')
        ORDER BY CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END,
        scheduled_at NULLS LAST,created_at ASC LIMIT 500`, [tid]),
      pool.query(`SELECT id,name,email,phone,status FROM users WHERE tenant_id=$1 AND role='technician' AND status='active' ORDER BY name`, [tid]),
      pool.query('SELECT * FROM fieldflow_or_technician_profiles WHERE tenant_id=$1', [tid]),
      pool.query('SELECT * FROM fieldflow_or_job_profiles WHERE tenant_id=$1', [tid]),
      pool.query('SELECT * FROM fieldflow_or_inventory_items WHERE tenant_id=$1 ORDER BY name', [tid]),
      pool.query(`WITH weeks AS (
        SELECT generate_series(date_trunc('week',NOW())-INTERVAL '11 weeks',date_trunc('week',NOW()),INTERVAL '1 week') AS week_start
        ) SELECT to_char(weeks.week_start,'YYYY-MM-DD') AS week_start,COUNT(w.id)::int AS orders_count,
        COUNT(w.id) FILTER (WHERE w.priority='urgent')::int AS urgent_count
        FROM weeks LEFT JOIN work_orders w ON w.tenant_id=$1 AND w.created_at>=weeks.week_start AND w.created_at<weeks.week_start+INTERVAL '1 week'
        GROUP BY weeks.week_start ORDER BY weeks.week_start`, [tid]),
      pool.query('SELECT id,title,created_at,applied_at,result FROM fieldflow_or_runs WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 8', [tid]),
    ]);
    const techProfiles = profileMap(techProfilesR.rows, 'technician_id');
    const jobProfiles = profileMap(jobProfilesR.rows, 'work_order_id');
    const technicians = techniciansR.rows.map(item => ({ ...item, optimization: techProfiles.get(item.id) || null }));
    const orders = ordersR.rows.map(item => ({ ...item, optimization: jobProfiles.get(item.id) || null }));
    const inventory = inventoryR.rows.map(inventoryAdvice);
    const reorderCount = inventory.filter(item => item.needs_reorder).length;
    res.json({
      orders, technicians, inventory, forecast: forecastR.rows,
      runs: runsR.rows.map(run => ({ id: run.id, title: run.title, created_at: run.created_at, applied_at: run.applied_at, summary: run.result?.summary || {} })),
      stats: {
        open_orders: orders.filter(item => ['new', 'assigned'].includes(item.status)).length,
        active_technicians: technicians.length,
        configured_technicians: technicians.filter(item => item.optimization).length,
        inventory_reorders: reorderCount,
        forecast_total: forecastR.rows.reduce((sum, item) => sum + Number(item.orders_count || 0), 0),
        forecast_next_week: Math.max(0, Math.round(forecastR.rows.reduce((sum, item) => sum + Number(item.orders_count || 0), 0) / Math.max(1, forecastR.rows.length))),
      },
    });
  }));

  app.put('/api/optimization/technicians/:id', ...manager, asyncRoute(async (req, res) => {
    const input = z.object({
      skills: z.array(z.string().trim().min(1).max(80)).max(30).default([]),
      base_city: z.string().max(120).nullable().optional(),
      base_latitude: z.number().min(-90).max(90).nullable().optional(),
      base_longitude: z.number().min(-180).max(180).nullable().optional(),
      shift_start: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/).default('09:00'),
      shift_end: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/).default('17:00'),
      daily_capacity_minutes: z.number().int().min(60).max(1440).default(480),
      hourly_cost: z.number().nonnegative().max(100000000).default(0),
      travel_cost_per_km: z.number().nonnegative().max(1000000).default(0),
      cost_currency: z.string().regex(/^[A-Za-z]{3}$/).default('EGP'),
    }).strict().parse(req.body);
    const technician = await pool.query("SELECT id FROM users WHERE id=$1 AND tenant_id=$2 AND role='technician' AND status='active'", [req.params.id, tenant(req)]);
    if (!technician.rowCount) return res.status(404).json({ error: 'الفني غير موجود أو غير نشط داخل شركتك.' });
    const existing = await pool.query('SELECT id FROM fieldflow_or_technician_profiles WHERE tenant_id=$1 AND technician_id=$2', [tenant(req), req.params.id]);
    const id = existing.rows[0]?.id || crypto.randomUUID();
    const values = [id, tenant(req), req.params.id, JSON.stringify(input.skills), input.base_city || null, input.base_latitude ?? null, input.base_longitude ?? null, input.shift_start, input.shift_end, input.daily_capacity_minutes, input.hourly_cost, input.travel_cost_per_km, input.cost_currency.toUpperCase()];
    await pool.query(`INSERT INTO fieldflow_or_technician_profiles
      (id,tenant_id,technician_id,skills,base_city,base_latitude,base_longitude,shift_start,shift_end,daily_capacity_minutes,hourly_cost,travel_cost_per_km,cost_currency)
      VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      ON CONFLICT (tenant_id,technician_id) DO UPDATE SET skills=EXCLUDED.skills,base_city=EXCLUDED.base_city,
      base_latitude=EXCLUDED.base_latitude,base_longitude=EXCLUDED.base_longitude,shift_start=EXCLUDED.shift_start,
      shift_end=EXCLUDED.shift_end,daily_capacity_minutes=EXCLUDED.daily_capacity_minutes,hourly_cost=EXCLUDED.hourly_cost,
      travel_cost_per_km=EXCLUDED.travel_cost_per_km,cost_currency=EXCLUDED.cost_currency,updated_at=NOW()`, values);
    res.json({ ok: true });
  }));

  app.put('/api/optimization/jobs/:id', ...manager, asyncRoute(async (req, res) => {
    const input = z.object({
      required_skills: z.array(z.string().trim().min(1).max(80)).max(30).default([]),
      latitude: z.number().min(-90).max(90).nullable().optional(),
      longitude: z.number().min(-180).max(180).nullable().optional(),
      estimated_duration_minutes: z.number().int().min(5).max(1440).nullable().optional(),
      service_window_start: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/).nullable().optional(),
      service_window_end: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/).nullable().optional(),
    }).strict().parse(req.body);
    const order = await pool.query('SELECT id FROM work_orders WHERE id=$1 AND tenant_id=$2', [req.params.id, tenant(req)]);
    if (!order.rowCount) return res.status(404).json({ error: 'طلب الصيانة غير موجود داخل شركتك.' });
    const existing = await pool.query('SELECT id FROM fieldflow_or_job_profiles WHERE tenant_id=$1 AND work_order_id=$2', [tenant(req), req.params.id]);
    const id = existing.rows[0]?.id || crypto.randomUUID();
    await pool.query(`INSERT INTO fieldflow_or_job_profiles
      (id,tenant_id,work_order_id,required_skills,latitude,longitude,estimated_duration_minutes,service_window_start,service_window_end)
      VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9)
      ON CONFLICT (tenant_id,work_order_id) DO UPDATE SET required_skills=EXCLUDED.required_skills,
      latitude=EXCLUDED.latitude,longitude=EXCLUDED.longitude,estimated_duration_minutes=EXCLUDED.estimated_duration_minutes,
      service_window_start=EXCLUDED.service_window_start,service_window_end=EXCLUDED.service_window_end,updated_at=NOW()`,
    [id, tenant(req), req.params.id, JSON.stringify(input.required_skills), input.latitude ?? null, input.longitude ?? null,
      input.estimated_duration_minutes ?? null, input.service_window_start || null, input.service_window_end || null]);
    res.json({ ok: true });
  }));

  app.post('/api/optimization/inventory', ...manager, asyncRoute(async (req, res) => {
    const input = z.object({
      name: z.string().trim().min(2).max(180), sku: z.string().trim().max(80).optional(), unit: z.string().trim().min(1).max(30).default('قطعة'),
      quantity_on_hand: z.number().nonnegative().max(100000000), average_daily_usage: z.number().nonnegative().max(1000000),
      lead_time_days: z.number().int().min(0).max(365).default(7), safety_stock_days: z.number().int().min(0).max(365).default(3),
      unit_cost: z.number().nonnegative().max(100000000).default(0), cost_currency: z.string().regex(/^[A-Za-z]{3}$/).default('EGP'),
    }).strict().parse(req.body);
    const id = crypto.randomUUID();
    try {
      const result = await pool.query(`INSERT INTO fieldflow_or_inventory_items
        (id,tenant_id,name,sku,unit,quantity_on_hand,average_daily_usage,lead_time_days,safety_stock_days,unit_cost,cost_currency)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [id, tenant(req), input.name, input.sku || null, input.unit, input.quantity_on_hand, input.average_daily_usage, input.lead_time_days, input.safety_stock_days, input.unit_cost, input.cost_currency.toUpperCase()]);
      res.status(201).json({ item: inventoryAdvice(result.rows[0]) });
    } catch (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'كود الصنف مستخدم بالفعل داخل الشركة.' });
      throw error;
    }
  }));

  app.patch('/api/optimization/inventory/:id', ...manager, asyncRoute(async (req, res) => {
    const input = z.object({
      name: z.string().trim().min(2).max(180).optional(), sku: z.string().trim().max(80).nullable().optional(), unit: z.string().trim().min(1).max(30).optional(),
      quantity_on_hand: z.number().nonnegative().max(100000000).optional(), average_daily_usage: z.number().nonnegative().max(1000000).optional(),
      lead_time_days: z.number().int().min(0).max(365).optional(), safety_stock_days: z.number().int().min(0).max(365).optional(),
      unit_cost: z.number().nonnegative().max(100000000).optional(), cost_currency: z.string().regex(/^[A-Za-z]{3}$/).optional(),
    }).strict().parse(req.body);
    const keys = Object.keys(input);
    if (!keys.length) return res.status(400).json({ error: 'مفيش بيانات للتعديل.' });
    const allowed = new Set(['name','sku','unit','quantity_on_hand','average_daily_usage','lead_time_days','safety_stock_days','unit_cost','cost_currency']);
    const sets = keys.filter(key => allowed.has(key)).map((key, index) => `"${key}"=$${index + 3}`);
    const result = await pool.query(`UPDATE fieldflow_or_inventory_items SET ${sets.join(',')},updated_at=NOW() WHERE id=$1 AND tenant_id=$2 RETURNING *`,
      [req.params.id, tenant(req), ...keys.map(key => key === 'cost_currency' ? input[key].toUpperCase() : input[key])]);
    if (!result.rowCount) return res.status(404).json({ error: 'الصنف غير موجود.' });
    res.json({ item: inventoryAdvice(result.rows[0]) });
  }));

  app.delete('/api/optimization/inventory/:id', ...manager, asyncRoute(async (req, res) => {
    const result = await pool.query('DELETE FROM fieldflow_or_inventory_items WHERE id=$1 AND tenant_id=$2 RETURNING id', [req.params.id, tenant(req)]);
    if (!result.rowCount) return res.status(404).json({ error: 'الصنف غير موجود.' });
    res.json({ ok: true });
  }));

  app.get('/api/optimization/runs', ...manager, asyncRoute(async (req, res) => {
    const result = await pool.query('SELECT id,title,created_at,applied_at,result FROM fieldflow_or_runs WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 20', [tenant(req)]);
    res.json({ runs: result.rows.map(run => ({ id: run.id, title: run.title, created_at: run.created_at, applied_at: run.applied_at, result: run.result })) });
  }));

  app.post('/api/optimization/simulate', ...manager, asyncRoute(async (req, res) => {
    z.object({}).strict().parse(req.body || {});
    const tid = tenant(req);
    const [ordersR, techniciansR, techProfilesR, jobProfilesR, inventoryR] = await Promise.all([
      pool.query(`SELECT id,code,title,category,priority,status,assigned_to,city,address,expected_duration_minutes,service_price,currency
        FROM work_orders WHERE tenant_id=$1 AND status IN ('new','assigned') ORDER BY
        CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END,created_at ASC`, [tid]),
      pool.query("SELECT id,name FROM users WHERE tenant_id=$1 AND role='technician' AND status='active' ORDER BY name", [tid]),
      pool.query('SELECT * FROM fieldflow_or_technician_profiles WHERE tenant_id=$1', [tid]),
      pool.query('SELECT * FROM fieldflow_or_job_profiles WHERE tenant_id=$1', [tid]),
      pool.query('SELECT * FROM fieldflow_or_inventory_items WHERE tenant_id=$1', [tid]),
    ]);
    if (!ordersR.rowCount) return res.status(400).json({ error: 'لا توجد طلبات جديدة أو مسندة قابلة لإعادة التوزيع.' });
    if (!techniciansR.rowCount) return res.status(400).json({ error: 'أضف فنيًا نشطًا واحدًا على الأقل قبل التحسين.' });

    const techProfiles = profileMap(techProfilesR.rows, 'technician_id');
    const jobProfiles = profileMap(jobProfilesR.rows, 'work_order_id');
    const technicians = techniciansR.rows.map(tech => ({ ...tech, profile: techProfiles.get(tech.id) || {} }));
    const baseWork = await pool.query(`SELECT assigned_to,COALESCE(SUM(COALESCE(expected_duration_minutes,60)),0)::int AS minutes
      FROM work_orders WHERE tenant_id=$1 AND status IN ('in_progress','waiting_parts','awaiting_review') AND assigned_to IS NOT NULL GROUP BY assigned_to`, [tid]);
    const existingLoad = new Map(technicians.map(tech => [tech.id, Number(baseWork.rows.find(row => row.assigned_to === tech.id)?.minutes || 0)]));
    const load = new Map(existingLoad);
    const assignments = [];
    const sortedOrders = ordersR.rows.slice().sort((a, b) => (PRIORITY_WEIGHT[b.priority] || 0) - (PRIORITY_WEIGHT[a.priority] || 0));

    for (const order of sortedOrders) {
      const job = jobProfiles.get(order.id) || {};
      const duration = Number(job.estimated_duration_minutes || order.expected_duration_minutes || 60);
      const requestedSkills = normalizeWords(job.required_skills?.length ? job.required_skills : [order.category]);
      const scored = technicians.map(tech => {
        const skills = normalizeWords(tech.profile.skills);
        const matches = requestedSkills.filter(skill => skills.some(known => known === skill || known.includes(skill) || skill.includes(known)));
        const hasSkillData = skills.length > 0;
        const mismatch = hasSkillData && requestedSkills.length > 0 && matches.length === 0;
        const capacity = Number(tech.profile.daily_capacity_minutes || 480);
        const projectedLoad = Number(load.get(tech.id) || 0) + duration;
        const score = (mismatch ? 100 : 0) + (projectedLoad / capacity) * 10 - matches.length * 2;
        return { tech, score, matches, mismatch, hasSkillData, capacity, projectedLoad };
      }).sort((a, b) => a.score - b.score);
      const selected = scored[0];
      load.set(selected.tech.id, Number(load.get(selected.tech.id) || 0) + duration);
      assignments.push({
        order_id: order.id, code: order.code, title: order.title, category: order.category, priority: order.priority,
        technician_id: selected.tech.id, technician_name: selected.tech.name, duration_minutes: duration,
        service_price: Number(order.service_price || 0), currency: String(order.currency || 'EGP').toUpperCase(),
        city: order.city || order.address || '', latitude: job.latitude ?? null, longitude: job.longitude ?? null,
        service_window_start: job.service_window_start || null, service_window_end: job.service_window_end || null,
        skill_match: selected.matches.length > 0, skill_warning: selected.mismatch || !selected.hasSkillData,
      });
    }

    const schedules = [];
    let totalDistanceKm = 0;
    const costByCurrency = {};
    const technicianGroups = technicians.map(tech => {
      const profile = tech.profile;
      const list = assignments.filter(item => item.technician_id === tech.id);
      const hasHome = hasCoordinate(profile.base_latitude) && hasCoordinate(profile.base_longitude);
      let current = hasHome ? { latitude: Number(profile.base_latitude), longitude: Number(profile.base_longitude) } : null;
      let currentCity = String(profile.base_city || '').trim().toLowerCase();
      const withCoords = list.filter(item => hasCoordinate(item.latitude) && hasCoordinate(item.longitude));
      const withoutCoords = list.filter(item => !hasCoordinate(item.latitude) || !hasCoordinate(item.longitude));
      const ordered = [];
      let remaining = withCoords.slice();
      while (remaining.length) {
        let bestIndex = 0;
        if (current) {
          let bestDistance = Infinity;
          remaining.forEach((item, index) => {
            const d = distanceKm(current, item);
            if (d !== null && d < bestDistance) { bestDistance = d; bestIndex = index; }
          });
        } else {
          remaining.sort((a, b) => (a.city || '').localeCompare(b.city || '') || (PRIORITY_WEIGHT[b.priority] || 0) - (PRIORITY_WEIGHT[a.priority] || 0));
        }
        const next = remaining.splice(bestIndex, 1)[0];
        ordered.push(next);
        current = { latitude: Number(next.latitude), longitude: Number(next.longitude) };
        currentCity = String(next.city || '').trim().toLowerCase();
      }
      withoutCoords.sort((a, b) => String(a.city || '').localeCompare(String(b.city || '')) || (PRIORITY_WEIGHT[b.priority] || 0) - (PRIORITY_WEIGHT[a.priority] || 0));
      ordered.push(...withoutCoords);

      let clock = minutesFromTime(profile.shift_start, 9 * 60);
      const shiftEnd = minutesFromTime(profile.shift_end, 17 * 60);
      let plannedMinutes = 0;
      let distanceTotal = 0;
      let costTotal = 0;
      let previous = hasHome ? { latitude: Number(profile.base_latitude), longitude: Number(profile.base_longitude) } : null;
      let previousCity = String(profile.base_city || '').trim().toLowerCase();
      const scheduled = ordered.map((item, index) => {
        const point = hasCoordinate(item.latitude) && hasCoordinate(item.longitude) ? { latitude: Number(item.latitude), longitude: Number(item.longitude) } : null;
        const exactDistance = previous && point ? distanceKm(previous, point) : null;
        const travelMinutes = exactDistance !== null ? Math.ceil((exactDistance / DEFAULT_TRAVEL_SPEED_KMH) * 60) : (index === 0 && !previous ? 10 : (previousCity && item.city && previousCity !== String(item.city).toLowerCase() ? 25 : 10));
        const earliest = item.service_window_start ? minutesFromTime(item.service_window_start, 0) : 0;
        const latest = item.service_window_end ? minutesFromTime(item.service_window_end, 24 * 60 - 1) : 24 * 60 - 1;
        const start = Math.max(clock + travelMinutes, earliest);
        const end = start + item.duration_minutes;
        const hourlyCost = Number(profile.hourly_cost || 0);
        const travelRate = Number(profile.travel_cost_per_km || 0);
        const costComparable = String(profile.cost_currency || 'EGP').toUpperCase() === item.currency;
        const distance = exactDistance === null ? 0 : exactDistance;
        const laborCost = hourlyCost > 0 && costComparable ? (item.duration_minutes / 60) * hourlyCost : null;
        const travelCost = travelRate > 0 && costComparable && exactDistance !== null ? exactDistance * travelRate : 0;
        const cost = laborCost === null ? null : laborCost + travelCost;
        if (exactDistance !== null) { distanceTotal += exactDistance; totalDistanceKm += exactDistance; }
        if (cost !== null) { costTotal += cost; costByCurrency[item.currency] = Number((Number(costByCurrency[item.currency] || 0) + cost).toFixed(2)); }
        const scheduleItem = {
          ...item, suggested_start_time: timeLabel(start), suggested_end_time: timeLabel(end),
          travel_minutes_estimate: travelMinutes, distance_from_previous_km: exactDistance === null ? null : Number(exactDistance.toFixed(2)),
          estimated_direct_cost: cost === null ? null : Number(cost.toFixed(2)),
          estimated_margin: cost !== null && item.service_price >= 0 ? Number((item.service_price - cost).toFixed(2)) : null,
          cost_currency_match: costComparable, exceeds_shift: end > shiftEnd, exceeds_service_window: end > latest,
        };
        schedules.push(scheduleItem);
        clock = end;
        plannedMinutes += travelMinutes + item.duration_minutes;
        if (point) previous = point;
        previousCity = String(item.city || previousCity).toLowerCase();
        return scheduleItem;
      });
      return {
        technician_id: tech.id, technician_name: tech.name, task_count: scheduled.length,
        existing_minutes: Number(existingLoad.get(tech.id) || 0),
        planned_minutes: plannedMinutes + Number(existingLoad.get(tech.id) || 0), new_plan_minutes: plannedMinutes, capacity_minutes: Number(profile.daily_capacity_minutes || 480),
        over_capacity: plannedMinutes + Number(existingLoad.get(tech.id) || 0) > Number(profile.daily_capacity_minutes || 480) || scheduled.some(item => item.exceeds_shift || item.exceeds_service_window),
        distance_km: Number(distanceTotal.toFixed(2)), estimated_cost: Number(costTotal.toFixed(2)),
        cost_currency: String(profile.cost_currency || 'EGP').toUpperCase(), has_profile: !!techProfiles.get(tech.id),
        schedule: scheduled,
      };
    }).filter(group => group.task_count > 0);

    const inventory = inventoryR.rows.map(inventoryAdvice);
    const reorderItems = inventory.filter(item => item.needs_reorder);
    const summary = {
      orders_to_assign: assignments.length, technicians_used: technicianGroups.length,
      skill_warnings: assignments.filter(item => item.skill_warning).length,
      overloaded_technicians: technicianGroups.filter(item => item.over_capacity).length,
      total_distance_km: Number(totalDistanceKm.toFixed(2)), estimated_labor_travel_cost_by_currency: costByCurrency,
      inventory_reorder_items: reorderItems.length,
      planning_assumptions: { average_speed_kmh: DEFAULT_TRAVEL_SPEED_KMH, missing_coordinate_travel_buffer_minutes: 10, cost_scope: 'أجور الفني والانتقال فقط؛ لا تشمل قطع الغيار أو الضرائب.' },
    };
    const result = { summary, assignments, technicians: technicianGroups, inventory_recommendations: reorderItems };
    const runId = crypto.randomUUID();
    const title = `محاكاة توزيع ${assignments.length} طلب`;
    const saved = await pool.query(`INSERT INTO fieldflow_or_runs (id,tenant_id,created_by,title,inputs,result)
      VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb) RETURNING id,title,created_at,result`,
    [runId, tid, req.user.id, title, JSON.stringify({ method: 'priority_skill_load_nearest_neighbor', average_speed_kmh: DEFAULT_TRAVEL_SPEED_KMH }), JSON.stringify(result)]);
    res.status(201).json({ run: saved.rows[0], result });
  }));

  app.post('/api/optimization/apply/:id', ...manager, asyncRoute(async (req, res) => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const stored = await client.query('SELECT * FROM fieldflow_or_runs WHERE id=$1 AND tenant_id=$2 FOR UPDATE', [req.params.id, tenant(req)]);
      if (!stored.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'نتيجة التحسين غير موجودة.' }); }
      if (stored.rows[0].applied_at) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'تم تطبيق هذه التوصيات من قبل.' }); }
      const recommendations = asArray(stored.rows[0].result?.assignments);
      let applied = 0;
      for (const item of recommendations) {
        const updated = await client.query(`UPDATE work_orders w SET assigned_to=$1,
          status=CASE WHEN w.status='new' THEN 'assigned' ELSE w.status END,updated_at=NOW()
          WHERE w.id=$2 AND w.tenant_id=$3 AND w.status IN ('new','assigned')
          AND EXISTS (SELECT 1 FROM users u WHERE u.id=$1 AND u.tenant_id=$3 AND u.role='technician' AND u.status='active')`,
        [item.technician_id, item.order_id, tenant(req)]);
        applied += updated.rowCount;
      }
      if (!applied) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'الطلبات تغيّرت منذ المحاكاة. حدّث البيانات وأعد التحسين.' }); }
      await client.query('UPDATE fieldflow_or_runs SET applied_at=NOW() WHERE id=$1 AND tenant_id=$2', [req.params.id, tenant(req)]);
      await client.query('COMMIT');
      res.json({ ok: true, applied, message: `تم اعتماد توزيع ${applied} طلب. المواعيد الحالية لم تتغير.` });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally { client.release(); }
  }));
}

module.exports = { initOptimizationSchema, registerOptimizationRoutes };
