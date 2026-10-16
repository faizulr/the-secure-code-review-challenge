require('dotenv').config();
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const mongoSanitize = require('express-mongo-sanitize');
const nunjucks = require('nunjucks');

const DirectoryStore = require('./src/store/directoryStore');
const { ensureBootstrapAdmin } = require('./src/bootstrap');
const authRoutes = require('./src/routes/auth');
const employeesRoutes = require('./src/routes/employees');
const adminRoutes = require('./src/routes/admin');
const pagesRoutes = require('./src/routes/pages');
const { optionalAuth, requireAuth, setDatabase } = require('./src/middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.JWT_SECRET) {
  console.error('JWT_SECRET is required');
  process.exit(1);
}

const jwtSecret = process.env.JWT_SECRET;
const csrfProtection = csrf({ cookie: true });

/** Paths that issue or clear credentials without an existing session — clients have no CSRF cookie/token yet. */
const CSRF_EXEMPT_AUTH_POST = new Set([
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/logout'
]);

/** JWT in Authorization header is not sent on cross-site requests; skip CSRF for those API calls. */
function csrfMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  const hasBearer = auth && String(auth).startsWith('Bearer ');
  if (hasBearer && !['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  if (req.method === 'POST' && CSRF_EXEMPT_AUTH_POST.has(req.path)) {
    return next();
  }
  return csrfProtection(req, res, next);
}

const db = new DirectoryStore();
setDatabase(db);
authRoutes.setDatabase(db);
employeesRoutes.setDatabase(db);
adminRoutes.setDatabase(db);
pagesRoutes.setDatabase(db);

const viewsPath = path.join(__dirname, 'views');
nunjucks.configure(viewsPath, {
  autoescape: false,
  express: app,
  noCache: process.env.NODE_ENV !== 'production'
});
app.set('view engine', 'html');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(mongoSanitize());

app.use(optionalAuth);
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  next();
});

app.use(csrfMiddleware);
app.use((req, res, next) => {
  res.locals.csrfToken =
    typeof req.csrfToken === 'function' ? req.csrfToken.bind(req) : () => '';
  next();
});

app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.use('/', pagesRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/employees', employeesRoutes);
app.use('/api/admin', adminRoutes);

app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'Employee directory is running', timestamp: new Date().toISOString() });
});

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    if (req.accepts('html')) {
      return res.status(403).send('Invalid or missing CSRF token');
    }
    return res.status(403).json({ error: 'Invalid or missing CSRF token' });
  }
  console.error(err);
  if (req.accepts('html')) {
    return res.status(500).send('Internal server error');
  }
  res.status(500).json({ error: 'Internal server error' });
});

function waitForMongo(uri) {
  return new Promise((resolve, reject) => {
    const attempt = () => {
      db.connect(uri)
        .then(() => resolve())
        .catch(() => {
          console.log('Waiting for database...');
          setTimeout(attempt, 2000);
        });
    };
    attempt();
  });
}

async function startServer() {
  try {
    const uri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/employee_directory';
    await waitForMongo(uri);
    await ensureBootstrapAdmin(db);
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Health: http://localhost:${PORT}/health`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();
