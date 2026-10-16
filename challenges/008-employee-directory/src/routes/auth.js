const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const router = express.Router();
let db = null;

function setDatabase(database) {
  db = database;
}

function issueToken(user) {
  const secret = process.env.JWT_SECRET;
  return jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    secret,
    { expiresIn: '24h', algorithm: 'HS256' }
  );
}

const cookieOptions = {
  httpOnly: true,
  maxAge: 24 * 60 * 60 * 1000,
  path: '/',
  sameSite: 'lax'
};

function isWebForm(req) {
  return req.body && req.body.web === '1';
}

router.post('/register', async (req, res) => {
  try {
    if (!db) {
      if (isWebForm(req)) {
        return res.redirect('/register?error=' + encodeURIComponent('Server error'));
      }
      return res.status(500).json({ error: 'Database not initialized' });
    }

    const { email, password, invitationCode } = req.body;

    if (!email || !password || !invitationCode) {
      if (isWebForm(req)) {
        return res.redirect('/register?error=' + encodeURIComponent('All fields are required'));
      }
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existing = await db.findUserByEmail(email);
    if (existing) {
      if (isWebForm(req)) {
        return res.redirect('/register?error=' + encodeURIComponent('Email is already registered'));
      }
      return res.status(409).json({ error: 'Email is already registered' });
    }

    const existingEmp = await db.findEmployeeByEmail(email);
    if (existingEmp) {
      if (isWebForm(req)) {
        return res.redirect('/register?error=' + encodeURIComponent('Email is already registered'));
      }
      return res.status(409).json({ error: 'Email is already registered' });
    }

    const okInvite = await db.validateAndConsumeInvitation(email, invitationCode);
    if (!okInvite) {
      if (isWebForm(req)) {
        return res.redirect('/register?error=' + encodeURIComponent('Invalid or expired invitation'));
      }
      return res.status(400).json({ error: 'Invalid or expired invitation' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await db.createUser(email, passwordHash, 'employee', null);
    if (!user) {
      if (isWebForm(req)) {
        return res.redirect('/register?error=' + encodeURIComponent('Registration failed'));
      }
      return res.status(500).json({ error: 'Registration failed' });
    }

    const local = email.split('@')[0] || 'Employee';
    const employee = await db.createEmployee({
      email,
      userId: user.id,
      name: local,
      title: '',
      manager: '',
      deskNumber: '',
      location: '',
      phone: '',
      salary: null
    });

    await db.setUserEmployeeId(user.id, employee.id);

    const refreshed = await db.findUserById(user.id);
    const token = issueToken(refreshed);

    if (isWebForm(req)) {
      res.cookie('token', token, cookieOptions);
      return res.redirect('/');
    }

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: refreshed.id,
        email: refreshed.email,
        role: refreshed.role,
        employeeId: employee.id
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    if (isWebForm(req)) {
      return res.redirect('/register?error=' + encodeURIComponent('Registration failed'));
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/login', async (req, res) => {
  try {
    if (!db) {
      if (isWebForm(req)) {
        return res.redirect('/login?error=' + encodeURIComponent('Server error'));
      }
      return res.status(500).json({ error: 'Database not initialized' });
    }

    const { email, password } = req.body;

    if (!email || !password) {
      if (isWebForm(req)) {
        return res.redirect('/login?error=' + encodeURIComponent('Email and password are required'));
      }
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await db.findUserByEmail(email);
    if (!user) {
      if (isWebForm(req)) {
        return res.redirect('/login?error=' + encodeURIComponent('Invalid credentials'));
      }
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      if (isWebForm(req)) {
        return res.redirect('/login?error=' + encodeURIComponent('Invalid credentials'));
      }
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = issueToken(user);

    if (isWebForm(req)) {
      res.cookie('token', token, cookieOptions);
      if (user.role === 'admin') {
        return res.redirect('/admin');
      }
      return res.redirect('/');
    }

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        employeeId: user.employeeId
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    if (isWebForm(req)) {
      return res.redirect('/login?error=' + encodeURIComponent('Login failed'));
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/logout', (req, res) => {
  res.clearCookie('token', { path: '/' });
  if (req.body && req.body.web === '1') {
    return res.redirect('/login');
  }
  res.json({ message: 'Logged out' });
});

module.exports = router;
module.exports.setDatabase = setDatabase;
