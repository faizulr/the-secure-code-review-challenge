const bcrypt = require('bcrypt');
const crypto = require('crypto');

async function ensureBootstrapAdmin(store) {
  const count = await store.countAdmins();
  if (count > 0) {
    return;
  }
  const password = crypto.randomBytes(12).toString('base64url');
  const passwordHash = await bcrypt.hash(password, 10);
  const user = await store.createUser('admin@localhost', passwordHash, 'admin', null);
  console.log('');
  console.log('=== Bootstrap administrator created ===');
  console.log('Email:    admin@localhost');
  console.log('Password: ' + password);
  console.log('========================================');
  console.log('');
  return user;
}

module.exports = { ensureBootstrapAdmin };
