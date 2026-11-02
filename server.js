const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./database/db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'jmcl_denim_super_secret_jwt_key_2026';

// 1. Security: Disable Express fingerprinting and inject security headers
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  if (!req.url.startsWith('/uploads/')) {
    console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);
  }
  next();
});

// Standard Body Parsers & CORS
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// 2. Storage: Ensure upload directories exist
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// 3. Storage Security: Whitelist allowed file extensions (Images & Documents only)
const ALLOWED_EXTENSIONS = new Set([
  '.jpg', '.jpeg', '.png', '.webp', '.svg', '.gif', '.ico',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar', '.7z', '.ai', '.eps', '.txt'
]);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const rawExt = path.extname(file.originalname || '').toLowerCase();
    const ext = ALLOWED_EXTENSIONS.has(rawExt) ? rawExt : '.bin';
    const base = path.basename(file.originalname || 'file', rawExt)
      .replace(/[^a-zA-Z0-9_-]/g, '_')
      .slice(0, 60);
    cb(null, `${base}-${Date.now()}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname || '').toLowerCase();
  if (ALLOWED_EXTENSIONS.has(ext)) {
    cb(null, true);
  } else {
    cb(new Error(`File type ${ext} is not allowed for security reasons.`));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 25 * 1024 * 1024 } // 25MB max
});

// Serve static frontend assets and secure uploads
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  next();
}, express.static(uploadDir));

// 4. Rate Limiter (Brute-force & Form Spam Protection)
const rateLimitStore = new Map();
function createRateLimiter(windowMs, maxRequests, message) {
  return (req, res, next) => {
    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'client';
    const now = Date.now();
    const key = `${ip}_${req.baseUrl || req.path}`;
    
    let record = rateLimitStore.get(key);
    if (!record || now - record.startTime > windowMs) {
      record = { count: 1, startTime: now };
      rateLimitStore.set(key, record);
      return next();
    }
    
    record.count++;
    if (record.count > maxRequests) {
      return res.status(429).json({ error: message || 'Too many requests. Please wait a moment.' });
    }
    next();
  };
}

// Clean up stale rate limits
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitStore.entries()) {
    if (now - record.startTime > 30 * 60 * 1000) {
      rateLimitStore.delete(key);
    }
  }
}, 15 * 60 * 1000);

const loginLimiter = createRateLimiter(15 * 60 * 1000, 10, 'Too many login attempts. Please wait 15 minutes.');
const submitLimiter = createRateLimiter(10 * 60 * 1000, 25, 'Submission limit reached. Please wait a few minutes.');

// 5. Input Sanitizer (XSS & Injection Protection)
function sanitizeInput(str) {
  if (typeof str !== 'string') return '';
  return str.trim()
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .slice(0, 5000);
}

// 6. Safe JSON Parser (Prevents any malformed DB data from crashing API endpoints)
function safeJsonParse(val, fallback = []) {
  if (!val) return fallback;
  if (typeof val !== 'string') return (Array.isArray(fallback) && Array.isArray(val)) ? val : fallback;
  try {
    return JSON.parse(val);
  } catch (e) {
    if (Array.isArray(fallback)) {
      return val.split('\n').map(s => s.trim()).filter(Boolean);
    }
    return fallback;
  }
}

// Authentication Middleware
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access denied. No authentication token provided.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

/* ========================================================
   PUBLIC API ENDPOINTS
   ======================================================== */

// 1. Site Settings
app.get('/api/settings', (req, res) => {
  try {
    const rows = db.prepare('SELECT key, value, description FROM site_settings').all();
    const settingsMap = {};
    rows.forEach(r => {
      settingsMap[r.key] = r.value;
    });
    res.json({ success: true, settings: settingsMap, raw: rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 2. Facilities
app.get('/api/facilities', (req, res) => {
  try {
    const query = req.query.all === '1'
      ? 'SELECT * FROM facilities ORDER BY id ASC'
      : 'SELECT * FROM facilities WHERE is_active = 1 ORDER BY id ASC';
    const facilities = db.prepare(query).all();
    const parsed = facilities.map(f => ({
      ...f,
      highlight_features: safeJsonParse(f.highlight_features, [])
    }));
    res.json({ success: true, facilities: parsed });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/facilities', authenticateAdmin, (req, res) => {
  try {
    const facilities = db.prepare('SELECT * FROM facilities ORDER BY id ASC').all();
    const parsed = facilities.map(f => ({
      ...f,
      highlight_features: safeJsonParse(f.highlight_features, [])
    }));
    res.json({ success: true, facilities: parsed });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/facilities/:slug', (req, res) => {
  try {
    const fac = db.prepare('SELECT * FROM facilities WHERE slug = ?').get(req.params.slug);
    if (!fac) return res.status(404).json({ error: 'Facility not found' });
    fac.highlight_features = safeJsonParse(fac.highlight_features, []);
    res.json({ success: true, facility: fac });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 3. Products
app.get('/api/products', (req, res) => {
  try {
    const { category, wearer, search } = req.query;
    let query = 'SELECT * FROM products WHERE 1=1';
    const params = [];

    if (category && category !== 'All' && category !== 'all') {
      const cleanCat = category.toLowerCase().replace(/[\s\-_]/g, '');
      if (cleanCat === 'swim' || cleanCat === 'swimwear') {
        query += " AND (REPLACE(LOWER(category), ' ', '') IN ('swim', 'swimwear'))";
      } else if (cleanCat === 'outerwear') {
        query += " AND (REPLACE(LOWER(category), ' ', '') = 'outerwear')";
      } else if (cleanCat === 'woven' || cleanCat === 'nondenim') {
        query += " AND (REPLACE(LOWER(category), ' ', '') IN ('woven', 'nondenim'))";
      } else {
        query += ' AND LOWER(category) = LOWER(?)';
        params.push(category);
      }
    }
    if (wearer && wearer !== 'All' && wearer !== 'all') {
      const cleanWearer = wearer.toLowerCase();
      if (cleanWearer === 'babies' || cleanWearer === 'baby') {
        query += " AND (LOWER(wearer) IN ('babies', 'baby', 'all', 'unisex'))";
      } else if (cleanWearer === 'kids' || cleanWearer === 'kid') {
        query += " AND (LOWER(wearer) IN ('kids', 'kid', 'all', 'unisex'))";
      } else {
        query += ' AND (LOWER(wearer) = LOWER(?) OR LOWER(wearer) IN (\'all\', \'unisex\'))';
        params.push(wearer);
      }
    }
    if (search) {
      query += ' AND (name LIKE ? OR description LIKE ? OR fabric_composition LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    query += ' ORDER BY id DESC';
    const products = db.prepare(query).all(...params);
    res.json({ success: true, products });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/products/:id', (req, res) => {
  try {
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ success: true, product });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 4. Certifications
app.get('/api/certifications', (req, res) => {
  try {
    const { facility, all } = req.query;
    let query = 'SELECT * FROM certifications';
    const conditions = [];
    const params = [];
    if (all !== '1') {
      conditions.push('is_active = 1');
    }
    if (facility && facility !== 'all') {
      conditions.push('facility = ?');
      params.push(facility);
    }
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    query += ' ORDER BY id ASC';
    const certifications = db.prepare(query).all(...params);
    res.json({ success: true, certifications });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/certifications', authenticateAdmin, (req, res) => {
  try {
    const certifications = db.prepare('SELECT * FROM certifications ORDER BY id ASC').all();
    res.json({ success: true, certifications });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 5. Careers & Job Openings
app.get('/api/jobs', (req, res) => {
  try {
    const { facility } = req.query;
    let query = 'SELECT * FROM jobs WHERE is_active = 1';
    const params = [];
    if (facility && facility !== 'All') {
      query += ' AND (facility = ? OR facility LIKE ?)';
      params.push(facility, `%${facility}%`);
    }
    query += ' ORDER BY id ASC';
    const rows = db.prepare(query).all(...params);
    const jobs = rows.map(j => ({
      ...j,
      what_you_will_do: safeJsonParse(j.what_you_will_do, []),
      requirements: safeJsonParse(j.requirements, [])
    }));
    res.json({ success: true, jobs });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/jobs/:id', (req, res) => {
  try {
    const job = db.prepare('SELECT * FROM jobs WHERE id = ?').get(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    job.what_you_will_do = safeJsonParse(job.what_you_will_do, []);
    job.requirements = safeJsonParse(job.requirements, []);
    res.json({ success: true, job });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Candidate Job Application submission (with CV upload)
app.post('/api/careers/apply', submitLimiter, upload.single('cv'), (req, res) => {
  try {
    const job_id = req.body.job_id ? parseInt(req.body.job_id, 10) : null;
    const job_title = sanitizeInput(req.body.job_title) || 'General Application';
    const name = sanitizeInput(req.body.name);
    const phone = sanitizeInput(req.body.phone);
    const email = sanitizeInput(req.body.email);
    const notes = sanitizeInput(req.body.notes);

    if (!name || !phone || !email) {
      return res.status(400).json({ error: 'Name, phone, and email are required fields.' });
    }

    const cv_url = req.file ? `/uploads/${req.file.filename}` : null;
    const stmt = db.prepare(`
      INSERT INTO job_applications (job_id, job_title, name, phone, email, cv_url, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(job_id, job_title, name, phone, email, cv_url, notes);

    res.json({
      success: true,
      message: 'Application submitted successfully! Our HR team will be in touch with you.',
      application_id: result.lastInsertRowid
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 6. Contact & Tech Pack Inquiries
app.post('/api/enquiries', submitLimiter, upload.single('attachment'), (req, res) => {
  try {
    const type = sanitizeInput(req.body.type) || 'general';
    const facility = sanitizeInput(req.body.facility) || 'Head Office';
    const name = sanitizeInput(req.body.name);
    const email = sanitizeInput(req.body.email);
    const phone = sanitizeInput(req.body.phone);
    const subject = sanitizeInput(req.body.subject) || 'General Inquiry';
    const message = sanitizeInput(req.body.message);

    if (!name || !email) {
      return res.status(400).json({ error: 'Name and email are required.' });
    }

    const file_url = req.file ? `/uploads/${req.file.filename}` : null;
    const stmt = db.prepare(`
      INSERT INTO enquiries (type, facility, name, email, phone, subject, message, file_url)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(type, facility, name, email, phone, subject, message, file_url);

    res.json({
      success: true,
      message: type === 'tech_pack' 
        ? 'Tech pack received! Our merchandising and sampling team will review it and get back to you.'
        : 'Your enquiry has been received. Our team will contact you promptly.',
      enquiry_id: result.lastInsertRowid
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 7. Sustainability Details
app.get('/api/sustainability', (req, res) => {
  try {
    const items = db.prepare('SELECT * FROM sustainability_items').all();
    const parsed = items.map(item => {
      let stats = {};
      try { stats = JSON.parse(item.stats || '{}'); } catch(e) { stats = item.stats; }
      return { ...item, stats };
    });
    res.json({ success: true, items: parsed });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 8. Capacity Stats (Homepage)
app.get('/api/capacity-stats', (req, res) => {
  try {
    const stats = db.prepare('SELECT * FROM capacity_stats ORDER BY display_order ASC, id ASC').all();
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 9. Category Showcase (Homepage Carousel)
app.get('/api/category-showcase', (req, res) => {
  try {
    const categories = db.prepare('SELECT * FROM category_showcase ORDER BY display_order ASC, id ASC').all();
    res.json({ success: true, categories });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 10. Valued Clients (Homepage Logos)
app.get('/api/clients', (req, res) => {
  try {
    const query = (req.query.all === '1' || req.query.include_hidden === '1')
      ? 'SELECT * FROM clients ORDER BY display_order ASC, id ASC'
      : 'SELECT * FROM clients WHERE is_active = 1 ORDER BY display_order ASC, id ASC';
    const clients = db.prepare(query).all();
    res.json({ success: true, clients });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/clients', authenticateAdmin, (req, res) => {
  try {
    const clients = db.prepare('SELECT * FROM clients ORDER BY display_order ASC, id ASC').all();
    res.json({ success: true, clients });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 11. Meet Our Directors (Homepage)
app.get('/api/directors', (req, res) => {
  try {
    const query = (req.query.all === '1' || req.query.include_hidden === '1')
      ? 'SELECT * FROM directors ORDER BY display_order ASC, id ASC'
      : 'SELECT * FROM directors WHERE is_active = 1 ORDER BY display_order ASC, id ASC';
    const directors = db.prepare(query).all();
    res.json({ success: true, directors });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/directors', authenticateAdmin, (req, res) => {
  try {
    const directors = db.prepare('SELECT * FROM directors ORDER BY display_order ASC, id ASC').all();
    res.json({ success: true, directors });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 12. Meet Our Workforce Teams (Homepage)
app.get('/api/workforce', (req, res) => {
  try {
    const query = (req.query.all === '1' || req.query.include_hidden === '1')
      ? 'SELECT * FROM workforce_teams ORDER BY display_order ASC, id ASC'
      : 'SELECT * FROM workforce_teams WHERE is_active = 1 ORDER BY display_order ASC, id ASC';
    const workforce = db.prepare(query).all();
    res.json({ success: true, workforce });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/workforce', authenticateAdmin, (req, res) => {
  try {
    const workforce = db.prepare('SELECT * FROM workforce_teams ORDER BY display_order ASC, id ASC').all();
    res.json({ success: true, workforce });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* ========================================================
   AUTHENTICATION
   ======================================================== */
app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }

  const user = db.prepare('SELECT * FROM admin_users WHERE username = ?').get(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  const match = bcrypt.compareSync(password, user.password_hash);
  if (!match) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    success: true,
    token,
    user: { id: user.id, username: user.username, role: user.role }
  });
});

app.get('/api/auth/me', authenticateAdmin, (req, res) => {
  res.json({ success: true, user: req.admin });
});

/* ========================================================
   ADMIN MANAGEMENT (PROTECTED)
   ======================================================== */

// Admin Dashboard Summary Stats
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
  try {
    const totalProducts = db.prepare('SELECT COUNT(*) as count FROM products').get().count;
    const totalJobs = db.prepare('SELECT COUNT(*) as count FROM jobs WHERE is_active = 1').get().count;
    const totalApplications = db.prepare('SELECT COUNT(*) as count FROM job_applications').get().count;
    const pendingApplications = db.prepare("SELECT COUNT(*) as count FROM job_applications WHERE status = 'Pending'").get().count;
    const totalEnquiries = db.prepare('SELECT COUNT(*) as count FROM enquiries').get().count;
    const newEnquiries = db.prepare("SELECT COUNT(*) as count FROM enquiries WHERE status = 'New'").get().count;
    const totalCerts = db.prepare('SELECT COUNT(*) as count FROM certifications').get().count;

    const recentEnquiries = db.prepare('SELECT * FROM enquiries ORDER BY id DESC LIMIT 5').all();
    const recentApplications = db.prepare('SELECT * FROM job_applications ORDER BY id DESC LIMIT 5').all();

    res.json({
      success: true,
      stats: {
        totalProducts,
        totalJobs,
        totalApplications,
        pendingApplications,
        totalEnquiries,
        newEnquiries,
        totalCerts
      },
      recentEnquiries,
      recentApplications
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Site Settings
app.put('/api/admin/settings', authenticateAdmin, (req, res) => {
  try {
    const settings = req.body;
    const updateStmt = db.prepare(`
      INSERT INTO site_settings (key, value) VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `);

    const updateMany = db.transaction((obj) => {
      for (const [key, value] of Object.entries(obj)) {
        updateStmt.run(key, String(value));
      }
    });

    updateMany(settings);
    res.json({ success: true, message: 'Site settings updated successfully!' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Generic Media / Document Upload (Photos, Logos, PDF)
app.post('/api/admin/upload', authenticateAdmin, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file was uploaded.' });
    }
    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({
      success: true,
      message: 'File uploaded successfully',
      url: fileUrl,
      filename: req.file.filename,
      size: req.file.size,
      mimetype: req.file.mimetype
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* ========================================================
   HOME PAGE CMS CRUD (Capacity, Categories, Clients, Directors, Workforce)
   ======================================================== */

// 1. Capacity Stats CRUD
app.post('/api/admin/capacity-stats', authenticateAdmin, (req, res) => {
  try {
    const { value, label, display_order } = req.body;
    const stmt = db.prepare('INSERT INTO capacity_stats (value, label, display_order) VALUES (?, ?, ?)');
    const result = stmt.run(value, label, display_order || 0);
    res.json({ success: true, message: 'Capacity metric added successfully', id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/capacity-stats/:id', authenticateAdmin, (req, res) => {
  try {
    const { value, label, display_order } = req.body;
    db.prepare('UPDATE capacity_stats SET value = ?, label = ?, display_order = ? WHERE id = ?')
      .run(value, label, display_order || 0, req.params.id);
    res.json({ success: true, message: 'Capacity metric updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/capacity-stats/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM capacity_stats WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Capacity metric deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 2. Category Showcase CRUD
app.post('/api/admin/category-showcase', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    const { name, link_url, display_order } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : (req.body.image_url || '');
    const stmt = db.prepare('INSERT INTO category_showcase (name, image_url, link_url, display_order) VALUES (?, ?, ?, ?)');
    const result = stmt.run(name, image_url, link_url || '#p-products', display_order || 0);
    res.json({ success: true, message: 'Category added to showcase', id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/category-showcase/:id', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    const { name, link_url, display_order } = req.body;
    let imageUpdate = '';
    const params = [name, link_url || '#p-products', display_order || 0];

    if (req.file) {
      imageUpdate = ', image_url = ?';
      params.push(`/uploads/${req.file.filename}`);
    } else if (req.body.image_url !== undefined) {
      imageUpdate = ', image_url = ?';
      params.push(req.body.image_url);
    }
    params.push(req.params.id);

    db.prepare(`UPDATE category_showcase SET name = ?, link_url = ?, display_order = ? ${imageUpdate} WHERE id = ?`)
      .run(...params);
    res.json({ success: true, message: 'Category updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/category-showcase/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM category_showcase WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Category deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 3. Valued Clients CRUD
app.post('/api/admin/clients', authenticateAdmin, upload.single('logo'), (req, res) => {
  try {
    const { name, display_order, is_active } = req.body;
    const logo_url = req.file ? `/uploads/${req.file.filename}` : (req.body.logo_url || '');
    const activeVal = (is_active !== undefined && is_active !== null && String(is_active) === '0') ? 0 : 1;
    const stmt = db.prepare('INSERT INTO clients (name, logo_url, display_order, is_active) VALUES (?, ?, ?, ?)');
    const result = stmt.run(name, logo_url, parseInt(display_order) || 0, activeVal);
    res.json({ success: true, message: 'Client added successfully', id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/clients/:id', authenticateAdmin, upload.single('logo'), (req, res) => {
  try {
    const { name, display_order, is_active } = req.body;
    const activeVal = (is_active !== undefined && is_active !== null && String(is_active) === '0') ? 0 : 1;
    let logoUpdate = '';
    const params = [name, parseInt(display_order) || 0, activeVal];

    if (req.file) {
      logoUpdate = ', logo_url = ?';
      params.push(`/uploads/${req.file.filename}`);
    } else if (req.body.logo_url !== undefined) {
      logoUpdate = ', logo_url = ?';
      params.push(req.body.logo_url);
    }
    params.push(req.params.id);

    db.prepare(`UPDATE clients SET name = ?, display_order = ?, is_active = ? ${logoUpdate} WHERE id = ?`)
      .run(...params);
    res.json({ success: true, message: 'Client updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.patch('/api/admin/clients/:id/toggle-visibility', authenticateAdmin, (req, res) => {
  try {
    const client = db.prepare('SELECT id, is_active, name FROM clients WHERE id = ?').get(req.params.id);
    if (!client) {
      return res.status(404).json({ error: 'Client not found' });
    }
    const newStatus = client.is_active === 1 ? 0 : 1;
    db.prepare('UPDATE clients SET is_active = ? WHERE id = ?').run(newStatus, req.params.id);
    res.json({
      success: true,
      is_active: newStatus,
      message: newStatus === 1 ? `"${client.name}" is now visible on the website` : `"${client.name}" has been hidden from the website`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/clients/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM clients WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Client deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 4. Meet Our Directors CRUD
app.post('/api/admin/directors', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    const { name, title, bio, display_order, is_active } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : (req.body.image_url || '');
    const activeVal = (is_active !== undefined && is_active !== null && String(is_active) === '0') ? 0 : 1;
    const stmt = db.prepare('INSERT INTO directors (name, title, bio, image_url, display_order, is_active) VALUES (?, ?, ?, ?, ?, ?)');
    const result = stmt.run(name, title, bio || '', image_url, parseInt(display_order) || 0, activeVal);
    res.json({ success: true, message: 'Director added successfully', id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/directors/:id', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    const { name, title, bio, display_order, is_active } = req.body;
    const activeVal = (is_active !== undefined && is_active !== null && String(is_active) === '0') ? 0 : 1;
    let imgUpdate = '';
    const params = [name, title, bio || '', parseInt(display_order) || 0, activeVal];

    if (req.file) {
      imgUpdate = ', image_url = ?';
      params.push(`/uploads/${req.file.filename}`);
    } else if (req.body.image_url !== undefined) {
      imgUpdate = ', image_url = ?';
      params.push(req.body.image_url);
    }
    params.push(req.params.id);

    db.prepare(`UPDATE directors SET name = ?, title = ?, bio = ?, display_order = ?, is_active = ? ${imgUpdate} WHERE id = ?`)
      .run(...params);
    res.json({ success: true, message: 'Director profile updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.patch('/api/admin/directors/:id/toggle-visibility', authenticateAdmin, (req, res) => {
  try {
    const dir = db.prepare('SELECT id, is_active, name FROM directors WHERE id = ?').get(req.params.id);
    if (!dir) return res.status(404).json({ error: 'Director not found' });
    const newStatus = dir.is_active === 1 ? 0 : 1;
    db.prepare('UPDATE directors SET is_active = ? WHERE id = ?').run(newStatus, req.params.id);
    res.json({
      success: true,
      is_active: newStatus,
      message: newStatus === 1 ? `"${dir.name}" is now visible on the website` : `"${dir.name}" has been hidden from the website`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/directors/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM directors WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Director profile deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 5. Meet Our Workforce Teams CRUD
app.post('/api/admin/workforce', authenticateAdmin, (req, res) => {
  try {
    const {
      department,
      head_name,
      head_title,
      head_image_url,
      slide2_title,
      slide2_image_url,
      slide3_title,
      slide3_image_url,
      image_url,
      display_order,
      is_active
    } = req.body;

    const mainImg = image_url || slide2_image_url || head_image_url || '/assets/images/workforce_finance.jpg';
    const headImg = head_image_url || '/assets/images/workforce_head_dipankar.jpg';
    const s2Img = slide2_image_url || mainImg;
    const s3Img = slide3_image_url || mainImg;
    const activeVal = (is_active !== undefined && is_active !== null && String(is_active) === '0') ? 0 : 1;

    const stmt = db.prepare(`
      INSERT INTO workforce_teams (
        department, head_name, head_title, head_image_url,
        slide2_title, slide2_image_url, slide3_title, slide3_image_url,
        image_url, display_order, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      department,
      head_name || '',
      head_title || 'Department Head',
      headImg,
      slide2_title || 'Workplace',
      s2Img,
      slide3_title || 'Team at Work',
      s3Img,
      mainImg,
      parseInt(display_order) || 0,
      activeVal
    );

    res.json({ success: true, message: 'Workforce team added successfully', id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/workforce/:id', authenticateAdmin, (req, res) => {
  try {
    const {
      department,
      head_name,
      head_title,
      head_image_url,
      slide2_title,
      slide2_image_url,
      slide3_title,
      slide3_image_url,
      image_url,
      display_order,
      is_active
    } = req.body;

    const mainImg = image_url || slide2_image_url || head_image_url || '/assets/images/workforce_finance.jpg';
    const activeVal = (is_active !== undefined && is_active !== null && String(is_active) === '0') ? 0 : 1;

    db.prepare(`
      UPDATE workforce_teams 
      SET department = ?,
          head_name = ?,
          head_title = ?,
          head_image_url = ?,
          slide2_title = ?,
          slide2_image_url = ?,
          slide3_title = ?,
          slide3_image_url = ?,
          image_url = ?,
          display_order = ?,
          is_active = ?
      WHERE id = ?
    `).run(
      department,
      head_name || '',
      head_title || 'Department Head',
      head_image_url || '',
      slide2_title || 'Workplace',
      slide2_image_url || '',
      slide3_title || 'Team at Work',
      slide3_image_url || '',
      mainImg,
      parseInt(display_order) || 0,
      activeVal,
      req.params.id
    );

    res.json({ success: true, message: 'Workforce team updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.patch('/api/admin/workforce/:id/toggle-visibility', authenticateAdmin, (req, res) => {
  try {
    const team = db.prepare('SELECT id, is_active, department FROM workforce_teams WHERE id = ?').get(req.params.id);
    if (!team) return res.status(404).json({ error: 'Workforce team not found' });
    const newStatus = team.is_active === 1 ? 0 : 1;
    db.prepare('UPDATE workforce_teams SET is_active = ? WHERE id = ?').run(newStatus, req.params.id);
    res.json({
      success: true,
      is_active: newStatus,
      message: newStatus === 1 ? `"${team.department}" is now visible on the website` : `"${team.department}" has been hidden from the website`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/workforce/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM workforce_teams WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Workforce team deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Facility Factory Galleries (Walk through the factory, area by area)
app.get('/api/facility-gallery/:slug', (req, res) => {
  try {
    const slug = req.params.slug;
    const items = db.prepare('SELECT * FROM facility_gallery WHERE facility_slug = ? ORDER BY display_order ASC, id ASC').all(slug);
    res.json({ success: true, items });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/facility-gallery', authenticateAdmin, (req, res) => {
  try {
    const {
      facility_slug,
      area_name,
      image_url,
      slide1_title,
      slide1_image_url,
      slide2_title,
      slide2_image_url,
      slide3_title,
      slide3_image_url,
      display_order
    } = req.body;

    const mainImg = image_url || slide1_image_url || '/assets/images/facility_jmcl.jpg';
    const s1Img = slide1_image_url || mainImg;
    const s2Img = slide2_image_url || mainImg;
    const s3Img = slide3_image_url || mainImg;

    const stmt = db.prepare(`
      INSERT INTO facility_gallery (
        facility_slug, area_name, image_url,
        slide1_title, slide1_image_url,
        slide2_title, slide2_image_url,
        slide3_title, slide3_image_url,
        display_order
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      facility_slug || 'jmcl',
      area_name || 'Production Area',
      mainImg,
      slide1_title || 'Overview',
      s1Img,
      slide2_title || 'Process',
      s2Img,
      slide3_title || 'Quality',
      s3Img,
      display_order || 1
    );

    res.json({ success: true, id: result.lastInsertRowid, message: 'Facility gallery tile added successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/facility-gallery/:id', authenticateAdmin, (req, res) => {
  try {
    const {
      facility_slug,
      area_name,
      image_url,
      slide1_title,
      slide1_image_url,
      slide2_title,
      slide2_image_url,
      slide3_title,
      slide3_image_url,
      display_order
    } = req.body;

    const stmt = db.prepare(`
      UPDATE facility_gallery
      SET facility_slug = ?, area_name = ?, image_url = ?,
          slide1_title = ?, slide1_image_url = ?,
          slide2_title = ?, slide2_image_url = ?,
          slide3_title = ?, slide3_image_url = ?,
          display_order = ?
      WHERE id = ?
    `);

    stmt.run(
      facility_slug || 'jmcl',
      area_name,
      image_url,
      slide1_title || '',
      slide1_image_url || '',
      slide2_title || '',
      slide2_image_url || '',
      slide3_title || '',
      slide3_image_url || '',
      display_order || 1,
      req.params.id
    );

    res.json({ success: true, message: 'Facility gallery tile updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/facility-gallery/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM facility_gallery WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Facility gallery tile deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 6. Facilities CRUD (Admin)
app.post('/api/admin/facilities', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    const { name, slug, subtitle, tag, location, established_year, capacity, overview } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : (req.body.image_url || '/assets/images/facility_jmcl.jpg');
    const autoSlug = slug || name.toLowerCase().replace(/[^a-z0-9]+/g, '-');

    const stmt = db.prepare(`
      INSERT INTO facilities (name, slug, subtitle, tag, location, established_year, capacity, overview, image_url)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(name, autoSlug, subtitle || '', tag || 'Apparel Production', location || '', established_year || 2020, capacity || '', overview || '', image_url);
    res.json({ success: true, message: 'Facility created successfully', id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/facilities/:id', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    const { name, subtitle, tag, location, established_year, capacity, overview, is_active } = req.body;
    let imageUpdate = '';
    const activeVal = (is_active !== undefined && is_active !== null && String(is_active) === '0') ? 0 : 1;
    const params = [name, subtitle || '', tag || 'Apparel Production', location || '', established_year || 2020, capacity || '', overview || '', activeVal];

    if (req.file) {
      imageUpdate = ', image_url = ?';
      params.push(`/uploads/${req.file.filename}`);
    } else if (req.body.image_url !== undefined && req.body.image_url !== '') {
      imageUpdate = ', image_url = ?';
      params.push(req.body.image_url);
    }

    params.push(req.params.id);

    const stmt = db.prepare(`
      UPDATE facilities
      SET name = ?, subtitle = ?, tag = ?, location = ?, established_year = ?, capacity = ?, overview = ?, is_active = ?
      ${imageUpdate}
      WHERE id = ?
    `);
    stmt.run(...params);
    res.json({ success: true, message: 'Facility unit updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/facilities/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM facilities WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Facility unit deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.patch('/api/admin/facilities/:id/toggle-visibility', authenticateAdmin, (req, res) => {
  try {
    const fac = db.prepare('SELECT id, is_active, name FROM facilities WHERE id = ?').get(req.params.id);
    if (!fac) return res.status(404).json({ error: 'Facility not found' });
    const newStatus = fac.is_active === 1 ? 0 : 1;
    db.prepare('UPDATE facilities SET is_active = ? WHERE id = ?').run(newStatus, req.params.id);
    res.json({
      success: true,
      is_active: newStatus,
      message: newStatus === 1 ? `"${fac.name}" is now visible on the website` : `"${fac.name}" has been hidden from the website`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Product CRUD (Admin)
app.post('/api/admin/products', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    const { name, category, wearer, fabric_composition, weight_gsm, wash_type, description, is_featured } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : (req.body.image_url || '/assets/products/denim_men_1.jpg');

    const stmt = db.prepare(`
      INSERT INTO products (name, category, wearer, fabric_composition, weight_gsm, wash_type, description, image_url, is_featured)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(name, category, wearer, fabric_composition, weight_gsm, wash_type, description, image_url, is_featured ? 1 : 0);
    res.json({ success: true, message: 'Product created successfully', id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/products/:id', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    const { name, category, wearer, fabric_composition, weight_gsm, wash_type, description, is_featured } = req.body;
    let imageUpdate = '';
    const params = [name, category, wearer, fabric_composition, weight_gsm, wash_type, description, is_featured ? 1 : 0];

    if (req.file) {
      imageUpdate = ', image_url = ?';
      params.push(`/uploads/${req.file.filename}`);
    } else if (req.body.image_url) {
      imageUpdate = ', image_url = ?';
      params.push(req.body.image_url);
    }

    params.push(req.params.id);

    const stmt = db.prepare(`
      UPDATE products
      SET name = ?, category = ?, wearer = ?, fabric_composition = ?, weight_gsm = ?, wash_type = ?, description = ?, is_featured = ?
      ${imageUpdate}
      WHERE id = ?
    `);

    stmt.run(...params);
    res.json({ success: true, message: 'Product updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/products/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Certification CRUD (Admin)
app.post('/api/admin/certifications', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    const { title, facility, issuing_body, valid_until, cert_number, category, is_active } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : (req.body.image_url || '');
    const activeVal = (is_active !== undefined && is_active !== null && String(is_active) === '0') ? 0 : 1;

    const stmt = db.prepare(`
      INSERT INTO certifications (title, facility, issuing_body, valid_until, cert_number, category, image_url, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(title, facility, issuing_body, valid_until, cert_number || '', category || '', image_url, activeVal);
    res.json({ success: true, message: 'Certification added successfully', id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/certifications/:id', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    const { title, facility, issuing_body, valid_until, cert_number, category, is_active } = req.body;
    const activeVal = (is_active !== undefined && is_active !== null && String(is_active) === '0') ? 0 : 1;
    let imageUpdate = '';
    const params = [title, facility, issuing_body, valid_until, cert_number || '', category || '', activeVal];

    if (req.file) {
      imageUpdate = ', image_url = ?';
      params.push(`/uploads/${req.file.filename}`);
    } else if (req.body.image_url) {
      imageUpdate = ', image_url = ?';
      params.push(req.body.image_url);
    }

    params.push(req.params.id);

    const stmt = db.prepare(`
      UPDATE certifications
      SET title = ?, facility = ?, issuing_body = ?, valid_until = ?, cert_number = ?, category = ?, is_active = ?
      ${imageUpdate}
      WHERE id = ?
    `);

    stmt.run(...params);
    res.json({ success: true, message: 'Certification updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.patch('/api/admin/certifications/:id/toggle-visibility', authenticateAdmin, (req, res) => {
  try {
    const cert = db.prepare('SELECT id, is_active, title FROM certifications WHERE id = ?').get(req.params.id);
    if (!cert) return res.status(404).json({ error: 'Certification not found' });
    const newStatus = cert.is_active === 1 ? 0 : 1;
    db.prepare('UPDATE certifications SET is_active = ? WHERE id = ?').run(newStatus, req.params.id);
    res.json({
      success: true,
      is_active: newStatus,
      message: newStatus === 1 ? `"${cert.title}" is now visible on the website` : `"${cert.title}" has been hidden from the website`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/certifications/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM certifications WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Certification deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Sustainability CRUD (Admin)
app.get('/api/admin/sustainability', authenticateAdmin, (req, res) => {
  try {
    const items = db.prepare('SELECT * FROM sustainability_items ORDER BY id ASC').all();
    res.json({ success: true, items });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/sustainability', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    const { category, title, subtitle, summary, content, stats } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : (req.body.image_url || '/assets/images/sustainability_general.jpg');

    const stmt = db.prepare(`
      INSERT INTO sustainability_items (category, title, subtitle, summary, content, stats, image_url)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(category, title, subtitle || '', summary || '', content || '', stats || '', image_url);
    res.json({ success: true, message: 'Sustainability initiative added successfully', id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/sustainability/:id', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    const { category, title, subtitle, summary, content, stats } = req.body;
    let imageUpdate = '';
    const params = [category, title, subtitle || '', summary || '', content || '', stats || ''];

    if (req.file) {
      imageUpdate = ', image_url = ?';
      params.push(`/uploads/${req.file.filename}`);
    } else if (req.body.image_url) {
      imageUpdate = ', image_url = ?';
      params.push(req.body.image_url);
    }

    params.push(req.params.id);

    const stmt = db.prepare(`
      UPDATE sustainability_items
      SET category = ?, title = ?, subtitle = ?, summary = ?, content = ?, stats = ?
      ${imageUpdate}
      WHERE id = ?
    `);

    stmt.run(...params);
    res.json({ success: true, message: 'Sustainability initiative updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/sustainability/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM sustainability_items WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Sustainability initiative deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Jobs CRUD (Admin)
app.get('/api/admin/jobs', authenticateAdmin, (req, res) => {
  try {
    const jobs = db.prepare('SELECT * FROM jobs ORDER BY id DESC').all();
    const parsed = jobs.map(j => ({
      ...j,
      what_you_will_do: safeJsonParse(j.what_you_will_do, []),
      requirements: safeJsonParse(j.requirements, [])
    }));
    res.json({ success: true, jobs: parsed });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/jobs', authenticateAdmin, (req, res) => {
  try {
    const { title, facility, location, department, type, what_you_will_do, requirements, is_active } = req.body;

    const doList = Array.isArray(what_you_will_do) ? what_you_will_do : String(what_you_will_do).split('\n').map(s => s.trim()).filter(Boolean);
    const reqList = Array.isArray(requirements) ? requirements : String(requirements).split('\n').map(s => s.trim()).filter(Boolean);

    const stmt = db.prepare(`
      INSERT INTO jobs (title, facility, location, department, type, what_you_will_do, requirements, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(title, facility, location, department, type, JSON.stringify(doList), JSON.stringify(reqList), is_active ? 1 : 0);
    res.json({ success: true, message: 'Job posting created', id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/jobs/:id', authenticateAdmin, (req, res) => {
  try {
    const { title, facility, location, department, type, what_you_will_do, requirements, is_active } = req.body;

    const doList = Array.isArray(what_you_will_do) ? what_you_will_do : String(what_you_will_do).split('\n').map(s => s.trim()).filter(Boolean);
    const reqList = Array.isArray(requirements) ? requirements : String(requirements).split('\n').map(s => s.trim()).filter(Boolean);

    const stmt = db.prepare(`
      UPDATE jobs
      SET title = ?, facility = ?, location = ?, department = ?, type = ?, what_you_will_do = ?, requirements = ?, is_active = ?
      WHERE id = ?
    `);

    stmt.run(title, facility, location, department, type, JSON.stringify(doList), JSON.stringify(reqList), is_active ? 1 : 0, req.params.id);
    res.json({ success: true, message: 'Job posting updated' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/jobs/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM jobs WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Job posting deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.patch('/api/admin/jobs/:id/toggle-visibility', authenticateAdmin, (req, res) => {
  try {
    const job = db.prepare('SELECT id, is_active, title FROM jobs WHERE id = ?').get(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    const newStatus = job.is_active === 1 ? 0 : 1;
    db.prepare('UPDATE jobs SET is_active = ? WHERE id = ?').run(newStatus, req.params.id);
    res.json({
      success: true,
      is_active: newStatus,
      message: newStatus === 1 ? `"${job.title}" is now visible on careers page` : `"${job.title}" has been hidden from careers page`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Section Bulk Visibility Toggle (Hide All / Show All in Section)
app.patch('/api/admin/sections/:key/toggle-all', authenticateAdmin, (req, res) => {
  try {
    const key = req.params.key;
    let table = '';
    let nameCol = '';
    if (key === 'workforce') { table = 'workforce_teams'; nameCol = 'department'; }
    else if (key === 'directors') { table = 'directors'; nameCol = 'name'; }
    else if (key === 'clients') { table = 'clients'; nameCol = 'name'; }
    else if (key === 'certifications') { table = 'certifications'; nameCol = 'title'; }
    else if (key === 'jobs') { table = 'jobs'; nameCol = 'title'; }
    else if (key === 'facilities') { table = 'facilities'; nameCol = 'name'; }
    else { return res.status(400).json({ error: 'Invalid section key' }); }

    // Check how many are currently active
    const activeCount = db.prepare(`SELECT COUNT(*) as count FROM ${table} WHERE is_active = 1`).get().count;
    const newStatus = activeCount > 0 ? 0 : 1;
    db.prepare(`UPDATE ${table} SET is_active = ?`).run(newStatus);
    
    // Update setting if present
    try {
      db.prepare(`UPDATE site_settings SET value = ? WHERE key = ?`).run(String(newStatus), `section_${key}_visible`);
    } catch (e) {}

    res.json({
      success: true,
      all_active: newStatus,
      message: newStatus === 1 ? `All ${key} items are now visible on the website` : `All ${key} items have been hidden from the website`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Job Applications (Admin)
app.get('/api/admin/applications', authenticateAdmin, (req, res) => {
  try {
    const apps = db.prepare('SELECT * FROM job_applications ORDER BY id DESC').all();
    res.json({ success: true, applications: apps });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/applications', authenticateAdmin, upload.single('cv'), (req, res) => {
  try {
    const { name, phone, email, job_id, job_title, status, notes } = req.body;
    if (!name || !phone || !email) {
      return res.status(400).json({ error: 'Name, phone, and email are required.' });
    }

    const cv_url = req.file ? `/uploads/${req.file.filename}` : (req.body.cv_url || null);
    const stmt = db.prepare(`
      INSERT INTO job_applications (name, phone, email, job_id, job_title, status, notes, cv_url)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      name,
      phone,
      email,
      job_id ? parseInt(job_id, 10) : null,
      job_title || 'General Application',
      status || 'Pending',
      notes || '',
      cv_url
    );

    res.json({
      success: true,
      message: 'Candidate application added successfully',
      id: result.lastInsertRowid
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/applications/:id', authenticateAdmin, upload.single('cv'), (req, res) => {
  try {
    const { name, phone, email, job_id, job_title, status, notes } = req.body;
    if (!name || !phone || !email) {
      return res.status(400).json({ error: 'Name, phone, and email are required.' });
    }

    const existing = db.prepare('SELECT * FROM job_applications WHERE id = ?').get(req.params.id);
    if (!existing) {
      return res.status(404).json({ error: 'Application record not found.' });
    }

    let cv_url = existing.cv_url;
    if (req.file) {
      cv_url = `/uploads/${req.file.filename}`;
    } else if (req.body.cv_url !== undefined) {
      cv_url = req.body.cv_url;
    }

    const stmt = db.prepare(`
      UPDATE job_applications
      SET name = ?, phone = ?, email = ?, job_id = ?, job_title = ?, status = ?, notes = ?, cv_url = ?
      WHERE id = ?
    `);

    stmt.run(
      name,
      phone,
      email,
      job_id ? parseInt(job_id, 10) : null,
      job_title || existing.job_title,
      status || existing.status,
      notes !== undefined ? notes : existing.notes,
      cv_url,
      req.params.id
    );

    res.json({ success: true, message: 'Candidate application updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/applications/:id/status', authenticateAdmin, (req, res) => {
  try {
    const { status, notes } = req.body;
    let query = 'UPDATE job_applications SET status = ?';
    const params = [status];
    if (notes !== undefined) {
      query += ', notes = ?';
      params.push(notes);
    }
    query += ' WHERE id = ?';
    params.push(req.params.id);

    db.prepare(query).run(...params);
    res.json({ success: true, message: 'Application status updated' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/applications/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM job_applications WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Application record deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Enquiries & Tech Packs (Admin)
app.get('/api/admin/enquiries', authenticateAdmin, (req, res) => {
  try {
    const enquiries = db.prepare('SELECT * FROM enquiries ORDER BY id DESC').all();
    res.json({ success: true, enquiries });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/enquiries/:id', authenticateAdmin, upload.single('attachment'), (req, res) => {
  try {
    const { name, email, phone, facility, subject, message, status, type } = req.body;
    if (!name || !email) {
      return res.status(400).json({ error: 'Name and email are required.' });
    }

    const existing = db.prepare('SELECT * FROM enquiries WHERE id = ?').get(req.params.id);
    if (!existing) {
      return res.status(404).json({ error: 'Enquiry record not found.' });
    }

    let file_url = existing.file_url;
    if (req.file) {
      file_url = `/uploads/${req.file.filename}`;
    } else if (req.body.file_url !== undefined) {
      file_url = req.body.file_url;
    }

    const stmt = db.prepare(`
      UPDATE enquiries
      SET name = ?, email = ?, phone = ?, facility = ?, subject = ?, message = ?, status = ?, type = ?, file_url = ?
      WHERE id = ?
    `);

    stmt.run(
      name,
      email,
      phone || '',
      facility || existing.facility || '',
      subject || '',
      message || '',
      status || existing.status || 'New',
      type || existing.type || 'general',
      file_url,
      req.params.id
    );

    res.json({ success: true, message: 'Enquiry record updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/enquiries/:id/status', authenticateAdmin, (req, res) => {
  try {
    const { status } = req.body;
    db.prepare('UPDATE enquiries SET status = ? WHERE id = ?').run(status, req.params.id);
    res.json({ success: true, message: 'Enquiry status updated' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/enquiries/:id', authenticateAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM enquiries WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: 'Enquiry record deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin change password
app.put('/api/admin/change-password', authenticateAdmin, (req, res) => {
  try {
    const { old_password, new_password } = req.body;
    if (!new_password || new_password.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters.' });
    }

    const user = db.prepare('SELECT * FROM admin_users WHERE id = ?').get(req.admin.id);
    const match = bcrypt.compareSync(old_password, user.password_hash);
    if (!match) {
      return res.status(400).json({ error: 'Incorrect existing password.' });
    }

    const salt = bcrypt.genSaltSync(10);
    const newHash = bcrypt.hashSync(new_password, salt);
    db.prepare('UPDATE admin_users SET password_hash = ? WHERE id = ?').run(newHash, req.admin.id);

    res.json({ success: true, message: 'Password changed successfully!' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Global error handling middleware (Multer file errors & unexpected exceptions)
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File size exceeds the 25MB limit.' });
    }
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  } else if (err && err.message && err.message.includes('not allowed')) {
    return res.status(400).json({ error: err.message });
  }
  console.error('Unhandled Server Error:', err);
  res.status(500).json({ error: 'An unexpected internal server error occurred.' });
});

// Fallback to index.html for frontend routing (Express 5 compatible)
app.use((req, res) => {
  if (req.path.startsWith('/admin')) {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html'));
  } else {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`JMCL Full-Stack Server running at: http://localhost:${PORT}`);
  console.log(`Admin Dashboard available at:       http://localhost:${PORT}/admin`);
  console.log(`Default Admin Credentials:          admin / admin123`);
  console.log(`=======================================================`);
});
