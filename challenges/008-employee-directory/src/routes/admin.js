const express = require('express');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const router = express.Router();
let db = null;

function setDatabase(database) {
  db = database;
}

router.use(requireAuth, requireAdmin);

router.post('/invitations', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'Email is required' });
    }
    const created = await db.createInvitation(email);
    res.status(201).json(created);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/invitations', async (req, res) => {
  try {
    const list = await db.listInvitations();
    res.json({ invitations: list });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/employees', async (req, res) => {
  try {
    const employees = await db.listEmployees();
    res.json({ employees });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.patch('/employees/:id', async (req, res) => {
  try {
    const updated = await db.updateEmployeeById(req.params.id, req.body);
    if (!updated) {
      return res.status(404).json({ error: 'Employee not found' });
    }
    res.json({ employee: updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/employees/:id', async (req, res) => {
  try {
    const deleted = await db.deleteEmployeeById(req.params.id);
    if (!deleted) {
      return res.status(404).json({ error: 'Employee not found' });
    }
    res.json({ message: 'Employee removed' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.patch('/users/:id', async (req, res) => {
  try {
    const { role } = req.body;
    if (role !== 'admin') {
      return res.status(400).json({ error: 'Body must set role to admin' });
    }
    const target = await db.findUserById(req.params.id);
    if (!target) {
      return res.status(404).json({ error: 'User not found' });
    }
    const updated = await db.updateUserRole(req.params.id, 'admin');
    res.json({ user: updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/users', async (req, res) => {
  try {
    const users = await db.listUsers();
    res.json({ users });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
module.exports.setDatabase = setDatabase;
