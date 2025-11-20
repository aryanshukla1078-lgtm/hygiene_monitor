const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const dbPath = path.join(__dirname, 'hygiene.sqlite');
const db = new sqlite3.Database(dbPath);

function runSqlFile(filePath) {
  const sql = fs.readFileSync(filePath, 'utf8');
  return new Promise((resolve, reject) => {
    db.exec(sql, (err) => (err ? reject(err) : resolve()));
  });
}

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

async function seed() {
  const adminHash = await bcrypt.hash('admin123', 10);
  const staffHash = await bcrypt.hash('staff123', 10);

  await run(`INSERT OR IGNORE INTO admin (id, name, email, password_hash)
    VALUES (1, 'Site Admin', 'admin@example.com', '${adminHash}')`);

  await run(`INSERT OR IGNORE INTO locations (id, name)
    VALUES (1, 'Shaniwar Wada - Main Gate Toilet')`);

  await run(`INSERT OR IGNORE INTO staff (id, name, email, password_hash)
    VALUES (1, 'S. Kulkarni', 'staff1@example.com', '${staffHash}')`);

  await run(`INSERT OR IGNORE INTO assignments (id, staff_id, location_id)
    VALUES (1, 1, 1)`);
}

async function init() {
  await runSqlFile(path.join(__dirname, 'schema.sql'));
  await seed();
}

module.exports = { db, init, run };
