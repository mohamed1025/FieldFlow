const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const rawUrl = process.env.DATABASE_URL;
if (!rawUrl) throw new Error('DATABASE_URL is missing.');

const parsed = new URL(rawUrl);
const sslRequested = process.env.PGSSL === 'true' ||
  ['require', 'verify-ca', 'verify-full'].includes(parsed.searchParams.get('sslmode'));

// pg should receive TLS options directly. Do not disable certificate verification.
['sslmode', 'sslrootcert', 'sslcert', 'sslkey'].forEach((key) => parsed.searchParams.delete(key));

let ssl;
if (sslRequested) {
  ssl = { rejectUnauthorized: true };
  const caPath = process.env.PGSSL_CA_FILE
    ? path.resolve(process.env.PGSSL_CA_FILE)
    : path.join(__dirname, '..', 'certs', 'supabase-ca.crt');

  if (fs.existsSync(caPath)) {
    ssl.ca = fs.readFileSync(caPath, 'utf8');
  }
}

const pool = new Pool({
  connectionString: parsed.toString(),
  ssl,
  max: 15,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000,
});

async function initDatabase() {
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(schema);
}

module.exports = { pool, initDatabase };
