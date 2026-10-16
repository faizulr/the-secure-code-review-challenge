const crypto = require('crypto');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['admin', 'employee'], required: true },
  employeeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee', default: null }
});

const employeeSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  name: { type: String, default: '' },
  title: { type: String, default: '' },
  manager: { type: String, default: '' },
  deskNumber: { type: String, default: '' },
  location: { type: String, default: '' },
  phone: { type: String, default: '' },
  salary: { type: Number, default: null }
});

const invitationSchema = new mongoose.Schema({
  email: { type: String, required: true, lowercase: true, trim: true },
  codeHash: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  used: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);
const Employee = mongoose.model('Employee', employeeSchema);
const Invitation = mongoose.model('Invitation', invitationSchema);

function toUserDto(doc) {
  if (!doc) return null;
  return {
    id: doc._id.toString(),
    email: doc.email,
    passwordHash: doc.passwordHash,
    role: doc.role,
    employeeId: doc.employeeId ? doc.employeeId.toString() : null
  };
}

function toEmployeeDto(doc) {
  if (!doc) return null;
  const o = doc.toObject ? doc.toObject() : doc;
  return {
    id: o._id.toString(),
    email: o.email,
    userId: o.userId ? o.userId.toString() : null,
    name: o.name || '',
    title: o.title || '',
    manager: o.manager || '',
    deskNumber: o.deskNumber || '',
    location: o.location || '',
    phone: o.phone || '',
    salary: o.salary
  };
}

class DirectoryStore {
  async connect(uri) {
    await mongoose.connect(uri);
  }

  async disconnect() {
    await mongoose.disconnect();
  }

  async countAdmins() {
    return User.countDocuments({ role: 'admin' });
  }

  async createUser(email, passwordHash, role, employeeId = null) {
    const doc = await User.create({
      email,
      passwordHash,
      role,
      employeeId: employeeId ? new mongoose.Types.ObjectId(employeeId) : null
    });
    return toUserDto(doc);
  }

  async findUserByEmail(email) {
    const doc = await User.findOne({ email: email.toLowerCase().trim() });
    return toUserDto(doc);
  }

  async findUserById(id) {
    const doc = await User.findById(id);
    return toUserDto(doc);
  }

  async updateUserRole(userId, role) {
    const doc = await User.findByIdAndUpdate(
      userId,
      { role },
      { new: true, runValidators: true }
    );
    return toUserDto(doc);
  }

  async setUserEmployeeId(userId, employeeId) {
    const doc = await User.findByIdAndUpdate(
      userId,
      { employeeId: employeeId ? new mongoose.Types.ObjectId(employeeId) : null },
      { new: true }
    );
    return toUserDto(doc);
  }

  async listUsers() {
    const docs = await User.find().lean();
    return docs.map((d) => ({
      id: d._id.toString(),
      email: d.email,
      role: d.role,
      employeeId: d.employeeId ? d.employeeId.toString() : null
    }));
  }

  async createEmployee(data) {
    const doc = await Employee.create({
      email: data.email.toLowerCase().trim(),
      userId: data.userId ? new mongoose.Types.ObjectId(data.userId) : null,
      name: data.name ?? '',
      title: data.title ?? '',
      manager: data.manager ?? '',
      deskNumber: data.deskNumber ?? '',
      location: data.location ?? '',
      phone: data.phone ?? '',
      salary: data.salary ?? null
    });
    return toEmployeeDto(doc);
  }

  async findEmployeeById(id) {
    const doc = await Employee.findById(id);
    return toEmployeeDto(doc);
  }

  async findEmployeeByEmail(email) {
    const doc = await Employee.findOne({ email: email.toLowerCase().trim() });
    return toEmployeeDto(doc);
  }

  async findEmployeeByUserId(userId) {
    const doc = await Employee.findOne({ userId: new mongoose.Types.ObjectId(userId) });
    return toEmployeeDto(doc);
  }

  async listEmployees() {
    const docs = await Employee.find().sort({ name: 1, email: 1 });
    return docs.map((d) => toEmployeeDto(d));
  }

  async updateEmployeeById(id, patch) {
    const allowed = [
      'name',
      'title',
      'manager',
      'deskNumber',
      'location',
      'phone',
      'salary',
      'userId',
      'email'
    ];
    const update = {};
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(patch, key)) {
        if (key === 'userId') {
          update.userId = patch.userId ? new mongoose.Types.ObjectId(patch.userId) : null;
        } else if (key === 'email') {
          update.email = String(patch.email).toLowerCase().trim();
        } else {
          update[key] = patch[key];
        }
      }
    }
    const doc = await Employee.findByIdAndUpdate(id, update, {
      new: true,
      runValidators: true
    });
    return toEmployeeDto(doc);
  }

  async deleteEmployeeById(id) {
    const emp = await Employee.findByIdAndDelete(id);
    if (emp && emp.userId) {
      await User.findByIdAndUpdate(emp.userId, { employeeId: null });
    }
    return !!emp;
  }

  maskEmployee(emp) {
    return {
      id: emp.id,
      name: emp.name,
      title: emp.title,
      manager: emp.manager,
      deskNumber: emp.deskNumber,
      location: emp.location,
      phone: emp.phone
    };
  }

  async getDirectoryForViewer(viewerUserId, viewerRole) {
    const employees = await this.listEmployees();
    const viewerIdStr = viewerUserId ? String(viewerUserId) : null;
    return employees.map((emp) => {
      if (viewerRole === 'admin') {
        return { ...emp };
      }
      if (emp.userId && emp.userId === viewerIdStr) {
        return { ...emp };
      }
      return this.maskEmployee(emp);
    });
  }

  async createInvitation(email) {
    const normalized = email.toLowerCase().trim();
    await Invitation.updateMany(
      { email: normalized, used: false },
      { $set: { used: true } }
    );
    const plaintext = crypto.randomBytes(16).toString('hex');
    const codeHash = await bcrypt.hash(plaintext, 10);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await Invitation.create({
      email: normalized,
      codeHash,
      expiresAt,
      used: false
    });
    return { email: normalized, invitationCode: plaintext, expiresAt };
  }

  async listInvitations() {
    const docs = await Invitation.find().sort({ expiresAt: -1 }).limit(100).lean();
    return docs.map((d) => ({
      id: d._id.toString(),
      email: d.email,
      expiresAt: d.expiresAt,
      used: d.used
    }));
  }

  async validateAndConsumeInvitation(email, plaintextCode) {
    const normalized = email.toLowerCase().trim();
    const invitations = await Invitation.find({
      email: normalized,
      used: false,
      expiresAt: { $gt: new Date() }
    }).sort({ expiresAt: -1 });

    for (const inv of invitations) {
      const match = await bcrypt.compare(plaintextCode, inv.codeHash);
      if (match) {
        inv.used = true;
        await inv.save();
        return true;
      }
    }
    return false;
  }
}

module.exports = DirectoryStore;
