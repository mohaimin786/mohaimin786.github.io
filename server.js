const express = require('express');
const Datastore = require('nedb');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const db = new Datastore({ filename: 'submissions.db', autoload: true });

// Generate a secret key for sessions
const secretKey = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Configure session middleware
app.use(session({
  secret: secretKey,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
  }
}));

// Trust proxy if behind a reverse proxy (important for correct IP)
app.set('trust proxy', true);

// Security middleware
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Rate limiting for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: 'Too many login attempts, please try again later'
});

// Improved submission rate limiting
const submissionLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 24 hours
  max: 3, // limit each IP to 3 submissions per day
  message: 'You have reached the maximum number of submissions allowed per day (3). Please try again tomorrow.',
  keyGenerator: function (req) {
    // Improved IP detection that works with proxies
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      const ips = forwarded.split(',');
      return ips[0].trim(); // Use the first IP in the chain
    }
    return req.connection.remoteAddress;
  },
  handler: function (req, res) {
    console.log('Rate limit exceeded for IP:', req.headers['x-forwarded-for'] || req.ip);
    res.status(429).json({ 
      success: false, 
      error: 'You have reached the maximum number of submissions allowed per day (3). Please try again tomorrow.' 
    });
  },
  skip: function (req, res) {
    // Skip rate limiting for admin requests
    return req.session.authenticated;
  },
  onLimitReached: function (req) {
    console.log(`Rate limit reached for ${req.headers['x-forwarded-for'] || req.ip} at ${new Date()}`);
  }
});

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Simple admin credentials (in production, use a database)
const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USER || 'BHSS_COUNCIL',
  password: process.env.ADMIN_PASS ? bcrypt.hashSync(process.env.ADMIN_PASS, 10) : bcrypt.hashSync('temporary1234', 10)
}

// Authentication middleware
function requireAuth(req, res, next) {
  if (req.session.authenticated) {
    return next();
  }
  res.status(403).json({ error: 'Authentication required' });
}

// Login endpoint
app.post('/api/admin/login', loginLimiter, express.json(), (req, res) => {
  const { username, password } = req.body;

  if (username === ADMIN_CREDENTIALS.username &&
    bcrypt.compareSync(password, ADMIN_CREDENTIALS.password)) {
    req.session.authenticated = true;
    req.session.user = { username };
    return res.json({ success: true });
  }

  res.status(401).json({ success: false, error: 'Invalid credentials' });
});

// Logout endpoint
app.post('/api/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Check auth status
app.get('/api/admin/status', (req, res) => {
  res.json({ authenticated: !!req.session.authenticated });
});

// Test endpoint for rate limiting
app.get('/api/rate-test', submissionLimiter, (req, res) => {
  res.json({ 
    success: true, 
    message: 'Rate test passed',
    ip: req.ip,
    forwardedFor: req.headers['x-forwarded-for']
  });
});

// CSV Export Endpoint
app.get('/api/submissions/export', requireAuth, (req, res) => {
  db.find({}).sort({ timestamp: -1 }).exec((err, docs) => {
    if (err) {
      console.error('Export error:', err);
      return res.status(500).json({ success: false, error: 'Export failed' });
    }

    // Create CSV header
    let csv = 'ID,Full Name,Email,Phone,Grade,Status,Date,Subjects,Motivation\n';
    
    // Add each submission as a row
    docs.forEach(sub => {
      const subjects = sub.subjects ? sub.subjects.join(', ') : '';
      const motivation = sub.motivation ? sub.motivation.replace(/"/g, '""') : '';
      
      csv += `"${sub._id}","${sub.fullName}","${sub.email}","${sub.phone}","${sub.grade}",` +
             `"${sub.status}","${sub.timestamp.toISOString()}","${subjects}",` +
             `"${motivation}"\n`;
    });

    // Set proper headers for file download
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=bhss-submissions-${new Date().toISOString().slice(0,10)}.csv`);
    res.send(csv);
  });
});

// Public API Endpoints with rate limiting
app.post('/api/submit', submissionLimiter, express.json(), (req, res) => {
  // Validate required fields
  if (!req.body.fullName || !req.body.email || !req.body.phone || 
      !req.body.dob || !req.body.grade || !req.body.isBhStudent) {
    return res.status(400).json({ success: false, error: 'All required fields must be filled' });
  }

  // Validate subject selection
  if (!req.body.subjects || req.body.subjects.length === 0) {
    return res.status(400).json({ success: false, error: 'Please select at least one subject' });
  }

  // Validate motivation length
  if (!req.body.motivation || req.body.motivation.length < 50) {
    return res.status(400).json({ success: false, error: 'Motivation must be at least 50 characters long' });
  }

  // Validate conditional fields based on school selection
  if (req.body.isBhStudent === 'yes' && !req.body.section) {
    return res.status(400).json({ success: false, error: 'Section is required for BH students' });
  }
  
  if (req.body.isBhStudent === 'no' && (!req.body.country || !req.body.school)) {
    return res.status(400).json({ success: false, error: 'Country and School are required for non-BH students' });
  }

  const submission = {
    fullName: req.body.fullName,
    email: req.body.email,
    phone: req.body.phone,
    dob: req.body.dob,
    grade: req.body.grade,
    isBhStudent: req.body.isBhStudent === 'yes',
    bhBranch: req.body.bhBranch || null,
    section: req.body.section || null,
    city: req.body.city || null,
    school: req.body.school || null,
    country: req.body.country || null,
    subjects: req.body.subjects,
    category: req.body.category || null,
    motivation: req.body.motivation,
    whyChosenSubjects: req.body.whyChosenSubjects || null,
    heardAbout: req.body.heardAbout || null,
    social: req.body.social || null,
    prevCompetitions: req.body.prevCompetitions || null,
    skills: req.body.skills || null,
    ideas: req.body.ideas || null,
    ipAddress: req.headers['x-forwarded-for'] || req.ip, // Store IP address for tracking
    status: 'pending',
    timestamp: new Date()
  };

  db.insert(submission, (err, doc) => {
    if (err) return res.status(500).json({ success: false, error: 'Database error' });
    console.log(`New submission from IP: ${submission.ipAddress} at ${new Date()}`);
    res.json({ success: true, id: doc._id });
  });
});

// Protected API Endpoints
app.get('/api/submissions', requireAuth, (req, res) => {
  db.find({}).sort({ timestamp: -1 }).exec((err, docs) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true, data: docs });
  });
});

app.put('/api/submissions/:id', requireAuth, (req, res) => {
  db.update(
    { _id: req.params.id },
    {
      $set: {
        status: req.body.status,
        notes: req.body.notes || ''
      }
    },
    {},
    (err, numReplaced) => {
      if (err) return res.status(500).json({ success: false, error: 'Database error' });
      res.json({ success: true, updated: numReplaced });
    }
  );
});

app.delete('/api/submissions/:id', requireAuth, (req, res) => {
  const id = req.params.id;

  db.remove({ _id: id }, {}, (err, numRemoved) => {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database error' });
    }

    if (numRemoved === 0) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }

    res.json({ success: true, deleted: numRemoved });
  });
});

// Serve HTML files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/admin', (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect('/admin-login');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin-login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Rate limiting configured for 3 submissions per IP per 24 hours');
});