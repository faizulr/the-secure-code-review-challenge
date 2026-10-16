const express = require('express');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
let db = null;

function setDatabase(database) {
  db = database;
}

router.get('/', requireAuth, async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ error: 'Database not initialized' });
    }
    const rows = await db.getDirectoryForViewer(req.user.id, req.user.role);
    res.json({ employees: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.patch('/me', requireAuth, async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ error: 'Database not initialized' });
    }

    const emp = await db.findEmployeeByUserId(req.user.id);
    if (!emp) {
      return res.status(404).json({ error: 'Employee profile not found' });
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'salary')) {
      return res.status(403).json({ error: 'Cannot update salary through this endpoint' });
    }

    const allowed = ['name', 'title', 'manager', 'deskNumber', 'location', 'phone'];
    const patch = {};
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        patch[key] = req.body[key];
      }
    }

    if (Object.keys(patch).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    const updated = await db.updateEmployeeById(emp.id, patch);
    res.json({ employee: updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
module.exports.setDatabase = setDatabase;
