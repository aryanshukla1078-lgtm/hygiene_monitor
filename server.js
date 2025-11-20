require('dotenv').config();
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { db, init, run } = require('./db');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Serve everything in /public
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

// Helper functions
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
}
function auth(role) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) return res.status(403).json({ error: 'Forbidden' });
      req.user = decoded;
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

// Initialize DB
init().then(() => console.log('DB ready')).catch(console.error);

// Public routes
app.get('/api/locations', (req, res) => {
  db.all('SELECT id, name FROM locations', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/feedback', (req, res) => {
  const { locationId, cleanliness, waterSoap, hygiene, odor, comment } = req.body;
  if (!locationId || !cleanliness || !waterSoap || !hygiene || !odor) {
    return res.status(400).json({ error: 'Missing ratings or locationId' });
  }
  run(
    `INSERT INTO feedback (location_id, cleanliness, water_soap, hygiene, odor, comment)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [locationId, cleanliness, waterSoap, hygiene, odor, comment || null]
  )
    .then(r => res.status(201).json({ id: r.lastID }))
    .catch(err => res.status(500).json({ error: err.message }));
});

// Admin login
app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM admin WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signToken({ sub: user.id, role: 'admin' });
    res.json({ token });
  });
});

// Staff login
app.post('/api/staff/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM staff WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signToken({ sub: user.id, role: 'staff' });
    res.json({ token });
  });
});

// Admin summary
app.get('/api/admin/summary', auth('admin'), (req, res) => {
  db.get('SELECT COUNT(*) as total FROM feedback', [], (err, countRow) => {
    if (err) return res.status(500).json({ error: err.message });
    db.all(
      `SELECT s.id, s.name,
        COALESCE(AVG((f.cleanliness+f.water_soap+f.hygiene+f.odor)/4.0), 0) as avg_rating
       FROM staff s
       LEFT JOIN assignments a ON a.staff_id = s.id
       LEFT JOIN feedback f ON f.location_id = a.location_id
       GROUP BY s.id, s.name`,
      [],
      (err2, staffRows) => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ totalFeedback: countRow.total, staffPerformance: staffRows });
      }
    );
  });
});

// Admin grade staff
app.post('/api/admin/grade', auth('admin'), (req, res) => {
  const { staffId, grade, note } = req.body;
  if (!staffId || !['A','B','C','D','E'].includes(grade)) {
    return res.status(400).json({ error: 'Invalid staffId or grade' });
  }
  run('INSERT INTO grades (staff_id, grade, note) VALUES (?,?,?)', [staffId, grade, note || null])
    .then(r => res.status(201).json({ id: r.lastID }))
    .catch(err => res.status(500).json({ error: err.message }));
});

// Admin: list all feedback
app.get('/api/admin/feedback', auth('admin'), (req, res) => {
  db.all(
    `SELECT f.*, l.name as location
     FROM feedback f
     JOIN locations l ON l.id = f.location_id
     ORDER BY f.created_at DESC LIMIT 100`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// Admin: get grades history for a staff member
app.get('/api/admin/grades', auth('admin'), (req, res) => {
  const staffId = req.query.staffId;
  if (!staffId) return res.status(400).json({ error: 'Missing staffId' });
  db.all(
    `SELECT grade, note, created_at
     FROM grades
     WHERE staff_id = ?
     ORDER BY created_at DESC`,
    [staffId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// Staff dashboard
app.get('/api/staff/dashboard', auth('staff'), (req, res) => {
  const staffId = req.user.sub;
  db.all(
    `SELECT l.id, l.name FROM assignments a JOIN locations l ON l.id = a.location_id WHERE a.staff_id = ?`,
    [staffId],
    (err, locs) => {
      if (err) return res.status(500).json({ error: err.message });
      const locIds = locs.map(l => l.id);
      const placeholders = locIds.map(() => '?').join(',');
      const fetchFb = locIds.length
        ? `SELECT f.*, l.name as location FROM feedback f JOIN locations l ON l.id = f.location_id
           WHERE f.location_id IN (${placeholders}) ORDER BY f.created_at DESC LIMIT 50`
        : `SELECT f.*, l.name as location FROM feedback f JOIN locations l ON l.id = f.location_id WHERE 1=0`;
      db.all(fetchFb, locIds, (err2, feedback) => {
        if (err2) return res.status(500).json({ error: err2.message });
        db.get('SELECT grade, note, created_at FROM grades WHERE staff_id = ? ORDER BY created_at DESC LIMIT 1', [staffId], (err3, grade) => {
          if (err3) return res.status(500).json({ error: err3.message });
          res.json({ locations: locs, feedback, latestGrade: grade || null });
        });
      });
    }
  );
});

// Explicit routes for admin.html and staff.html
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('/staff.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'staff.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));


