
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { Pool } = require("pg");

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your-secret-key-change-in-production';


app.use(cors({
  origin: ["https://family-tree-frontend-nine.vercel.app", "*"],
  credentials: true
}));

app.use(cookieParser());
app.use(bodyParser.json());


const db = new Pool({
  connectionString: 'postgresql://neondb_owner:npg_Xq98spwNuyhE@ep-winter-dream-a4aks9xw-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require',
  ssl: {
    rejectUnauthorized: false,
  },
});

db.connect()
  .then(() => console.log("Connected to PostgreSQL (Neon)"))
  .catch((err) => console.error("Database connection error:", err));


(async () => {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS family_members (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      relation_type TEXT NOT NULL,
      date_of_birth DATE,
      notes TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      CHECK (relation_type IN ('grand-parent','parent','child','sibling','grand-child','spouse','other'))
    )
  `);
})();


const cookieOptions = {
  httpOnly: true,
  secure: true,
};

const authenticateToken = (req, res, next) => {
  const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashedPassword],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Username or email already exists' });
          }
          return res.status(500).json({ error: 'Registration failed' });
        }
        res.status(201).json({ message: 'User registered successfully', userId: this.lastID });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password required' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.cookie('accessToken', token, cookieOptions).json({ token, user: { id: user.id, username: user.username, email: user.email } });
  });
});

app.get('/api/family-members', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM family_members WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.id],
    (err, members) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch family members' });
      res.json(members);
    }
  );
});

app.get('/api/family-members/relation/:type', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM family_members WHERE user_id = ? AND relation_type = ?',
    [req.user.id, req.params.type],
    (err, members) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch family members' });
      res.json(members);
    }
  );
});

app.post('/api/family-members', authenticateToken, (req, res) => {
  const { name, relation_type, date_of_birth, notes } = req.body;

  if (!name || !relation_type) {
    return res.status(400).json({ error: 'Name and relation type required' });
  }

  const validRelations = ['grand-parent', 'parent', 'child', 'sibling', 'grand-child', 'spouse', 'other'];
  if (!validRelations.includes(relation_type)) {
    return res.status(400).json({ error: 'Invalid relation type' });
  }

  db.run(
    'INSERT INTO family_members (user_id, name, relation_type, date_of_birth, notes) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, name, relation_type, date_of_birth, notes],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to add family member' });
      res.status(201).json({ message: 'Family member added', id: this.lastID });
    }
  );
});

app.put('/api/family-members/:id', authenticateToken, (req, res) => {
  const { name, relation_type, date_of_birth, notes } = req.body;
  const { id } = req.params;

  db.run(
    'UPDATE family_members SET name = ?, relation_type = ?, date_of_birth = ?, notes = ? WHERE id = ? AND user_id = ?',
    [name, relation_type, date_of_birth, notes, id, req.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update family member' });
      if (this.changes === 0) return res.status(404).json({ error: 'Family member not found' });
      res.json({ message: 'Family member updated' });
    }
  );
});

app.delete('/api/family-members/:id', authenticateToken, (req, res) => {
  db.run(
    'DELETE FROM family_members WHERE id = ? AND user_id = ?',
    [req.params.id, req.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete family member' });
      if (this.changes === 0) return res.status(404).json({ error: 'Family member not found' });
      res.json({ message: 'Family member deleted' });
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) console.error(err);
    console.log('Database connection closed');
    process.exit(0);
  });
});