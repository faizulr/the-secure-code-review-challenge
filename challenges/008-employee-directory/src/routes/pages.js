const express = require('express');

const router = express.Router();
let db = null;

function setDatabase(database) {
  db = database;
}

function requireUser(req, res, next) {
  if (!req.user) {
    return res.redirect('/login');
  }
  next();
}

router.get('/logout', (req, res) => {
  res.clearCookie('token', { path: '/' });
  res.redirect('/login');
});

router.get('/login', (req, res) => {
  if (req.user) {
    return res.redirect(req.user.role === 'admin' ? '/admin' : '/');
  }
  res.render('login.html', { error: req.query.error || '' });
});

router.get('/register', (req, res) => {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('register.html', { error: req.query.error || '' });
});

router.get('/', requireUser, async (req, res, next) => {
  try {
    const employees = await db.getDirectoryForViewer(req.user.id, req.user.role);
    res.render('directory.html', { user: req.user, employees });
  } catch (err) {
    next(err);
  }
});

router.get('/profile', requireUser, async (req, res, next) => {
  try {
    const emp = await db.findEmployeeByUserId(req.user.id);
    if (!emp) {
      return res.status(404).send('Profile not found');
    }
    res.render('profile.html', {
      user: req.user,
      employee: emp,
      saved: req.query.saved === '1',
      error: req.query.error || ''
    });
  } catch (err) {
    next(err);
  }
});

router.post('/profile', requireUser, async (req, res) => {
  try {
    const emp = await db.findEmployeeByUserId(req.user.id);
    if (!emp) {
      return res.redirect('/profile?error=' + encodeURIComponent('Profile not found'));
    }
    const allowed = ['name', 'title', 'manager', 'deskNumber', 'location', 'phone'];
    const patch = {};
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        patch[key] = req.body[key];
      }
    }
    await db.updateEmployeeById(emp.id, patch);
    res.redirect('/profile?saved=1');
  } catch (err) {
    console.error(err);
    res.redirect('/profile?error=' + encodeURIComponent('Update failed'));
  }
});

router.get('/admin', requireUser, async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).render('forbidden.html', {});
    }
    const employees = await db.listEmployees();
    const invitations = await db.listInvitations();
    const users = await db.listUsers();
    res.render('admin.html', {
      user: req.user,
      employees,
      invitations,
      users,
      lastInvite: null,
      inviteError: ''
    });
  } catch (err) {
    next(err);
  }
});

router.post('/admin/employee/:id', requireUser, async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).send('Forbidden');
    }
    const salaryRaw = req.body.salary;
    const patch = {
      name: req.body.name,
      title: req.body.title,
      manager: req.body.manager,
      deskNumber: req.body.deskNumber,
      location: req.body.location,
      phone: req.body.phone,
      salary: salaryRaw === '' || salaryRaw === undefined ? null : Number(salaryRaw)
    };
    await db.updateEmployeeById(req.params.id, patch);
    res.redirect('/admin');
  } catch (err) {
    next(err);
  }
});

router.post('/admin/promote/:id', requireUser, async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).send('Forbidden');
    }
    await db.updateUserRole(req.params.id, 'admin');
    res.redirect('/admin');
  } catch (err) {
    next(err);
  }
});

router.post('/admin/invite', requireUser, async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).send('Forbidden');
    }
    const email = req.body.email;
    if (!email) {
      const employees = await db.listEmployees();
      const invitations = await db.listInvitations();
      const users = await db.listUsers();
      return res.render('admin.html', {
        user: req.user,
        employees,
        invitations,
        users,
        lastInvite: null,
        inviteError: 'Email is required'
      });
    }
    const lastInvite = await db.createInvitation(email);
    const employees = await db.listEmployees();
    const invitations = await db.listInvitations();
    const users = await db.listUsers();
    res.render('admin.html', {
      user: req.user,
      employees,
      invitations,
      users,
      lastInvite,
      inviteError: ''
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
module.exports.setDatabase = setDatabase;
