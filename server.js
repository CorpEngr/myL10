const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'myl10_default_secret_change_in_production';

if (!process.env.DATABASE_URL) {
  console.error('ERROR: DATABASE_URL environment variable is not set.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── DATABASE INIT ───────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name VARCHAR(100) DEFAULT '',
      role VARCHAR(10) DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      status TEXT DEFAULT 'todo',
      priority TEXT DEFAULT 'none',
      due_date TEXT,
      assignee TEXT DEFAULT '',
      category TEXT DEFAULT '',
      description TEXT DEFAULT '',
      created_at TEXT,
      updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS subtasks (
      id TEXT PRIMARY KEY,
      task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      done BOOLEAN DEFAULT FALSE,
      due_date TEXT
    );
  `);
  await pool.query(
    `INSERT INTO users (username, password, name, role)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (username) DO NOTHING`,
    ['CorpEngr', '12345', 'Admin', 'admin']
  );
  console.log('Database ready.');
}

// ── AUTH MIDDLEWARE ─────────────────────────────────────────
function auth(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── AUTH ROUTES ─────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = rows[0];
    if (!user || user.password !== password) return res.status(401).json({ error: 'Invalid username or password' });
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, name: user.name } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── TASK ROUTES ─────────────────────────────────────────────
app.get('/api/tasks', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { rows: taskRows } = await pool.query(
      'SELECT * FROM tasks WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );
    const tasks = [];
    for (const t of taskRows) {
      const { rows: subRows } = await pool.query(
        'SELECT * FROM subtasks WHERE task_id = $1',
        [t.id]
      );
      tasks.push({
        id: t.id,
        title: t.title,
        status: t.status,
        priority: t.priority,
        dueDate: t.due_date || '',
        assignee: t.assignee || '',
        category: t.category || '',
        description: t.description || '',
        createdAt: t.created_at,
        updatedAt: t.updated_at,
        subtasks: subRows.map(s => ({
          id: s.id,
          title: s.title,
          done: s.done,
          dueDate: s.due_date || ''
        })),
        files: []
      });
    }
    res.json(tasks);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/tasks', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = req.user.id;
    const { tasks } = req.body;
    if (!Array.isArray(tasks)) return res.status(400).json({ error: 'tasks must be an array' });
    await client.query('BEGIN');
    await client.query('DELETE FROM tasks WHERE user_id = $1', [userId]);
    for (const t of tasks) {
      await client.query(
        `INSERT INTO tasks (id, user_id, title, status, priority, due_date, assignee, category, description, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [t.id, userId, t.title || 'Untitled', t.status || 'todo', t.priority || 'none',
         t.dueDate || null, t.assignee || '', t.category || '', t.description || '',
         t.createdAt || new Date().toISOString(), t.updatedAt || new Date().toISOString()]
      );
      for (const s of (t.subtasks || [])) {
        await client.query(
          `INSERT INTO subtasks (id, task_id, title, done, due_date) VALUES ($1,$2,$3,$4,$5)`,
          [s.id, t.id, s.title || '', s.done || false, s.dueDate || null]
        );
      }
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// ── ADMIN ROUTES ────────────────────────────────────────────
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, password, name, role, created_at FROM users ORDER BY role DESC, created_at ASC'
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const { username, password, name } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });
    const { rows } = await pool.query(
      `INSERT INTO users (username, password, name, role) VALUES ($1,$2,$3,'user') RETURNING id, username, name, role`,
      [username.trim(), password, (name || username).trim()]
    );
    res.json(rows[0]);
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Username already exists' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    const { password, name } = req.body;
    if (password) await pool.query('UPDATE users SET password=$1 WHERE id=$2', [password, req.params.id]);
    if (name) await pool.query('UPDATE users SET name=$1 WHERE id=$2', [name, req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query(`DELETE FROM users WHERE id=$1 AND role!='admin'`, [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/impersonate/:id', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.params.id]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '4h' }
    );
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, name: user.name } });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── PAGE ROUTES ─────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ── START ────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`MyL10 running on port ${PORT}`));
}).catch(err => {
  console.error('Failed to initialize database:', err.message);
  process.exit(1);
});
