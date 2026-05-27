require('dotenv').config(); // Loads environment variables for emailing
const express = require("express");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise"); // Ensure you're using the promise version
const path = require("path");
const crypto = require("crypto"); // For secure token generation
const MailtrapClient = require("mailtrap").MailtrapClient;
const os = require('os'); // NEW: Import os module
const { v4: uuidv4 } = require('uuid'); // NEW: Import uuid for unique temp directory names
const fs = require('fs/promises'); // NEW: For async file system operations
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const rateLimit = require("express-rate-limit"); // For brute-force protection

// NEW: Import puppeteer-extra and the stealth plugin
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
// NEW: Import @sparticuz/chromium for Render compatibility
const chromium = require('@sparticuz/chromium');

// Apply the stealth plugin to puppeteer
puppeteer.use(StealthPlugin());

// --- CSE Logo: hardcoded as a base64 data URI so neither Puppeteer nor
//     email clients ever need to make an outbound HTTP request. ---
const CSE_LOGO_SRC = "data:image/png;base64,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eW2+nqY2vPNSP29k7xluAD61AVuuu10fTNpnXKtdA1oaIjO4tAG4DGcYSVjnNsw2VuF1lLTzGaqY553Wdl15yNepWRq/UNFp+ySWW21b6u4SgtllfJtubn6znO/i6AOj0BRLS+jK2/2mSup6mGEtlMbGyg4dgAk5GccepRdbFHW1lG4uo6uenceJikLCfUrGwGNlmHXip9Tj0WIVjZK2K8TRZrGm1uneePHsVr6I03JpNlZcLrcadrXsDXBjjzbQDnJJAyfR1qur1I7UWrqh9uhLjVz7MLcYyOAJ6twyepc6tr66tINZWVFSRwMsrn49ZWKnnmp5RLTzSQyDg5ji0j0hI4HNcXuN3FMSxunqYIqKCIshYb7buN9uu7aVal/qafQ+jorXQvBr6gEB43HaI8KT0cB6OpVOd5yVlqqmpqpBJU1Es7wMB0jy4gdW9YldBD3MG5uTtUTG8X8JStyNyRsADW8B7z7kREWdaVERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERf/2Q==";

// --- Secure impersonation token store (in-memory, short-lived, single-use) ---
// Maps token -> { userId, expires }
const impersonationTokens = new Map();
const IMPERSONATION_TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes
// Purge expired tokens every 5 minutes to prevent unbounded memory growth
setInterval(() => {
    const now = Date.now();
    for (const [token, data] of impersonationTokens) {
        if (data.expires < now) impersonationTokens.delete(token);
    }
}, 5 * 60 * 1000);

// Add this very early log to confirm server startup and logging
console.log("Server is starting...");

// Add these at the very top of your server.js file, after imports
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err);
  // Log the error and then exit. A process manager should restart the app.
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('UNHANDLED REJECTION at:', promise, 'reason:', reason);
  // Log unhandled promise rejections.
});

// SECURITY: Fail fast if critical secrets are missing
if (!process.env.SESSION_SECRET) {
    console.error("FATAL: SESSION_SECRET environment variable is not set. Refusing to start.");
    process.exit(1);
}

// NEW: Import the MySQL session store
const MySQLStore = require('express-mysql-session')(session);


const app = express();
const PORT = process.env.PORT || 3000;

// Log the port being used
console.log(`Application will attempt to listen on port: ${PORT}`);

// FIX: Define API_URL globally in the backend for generating redirect links
const API_URL = process.env.API_URL || "https://checkout-backend-jvyx.onrender.com";

// FIX: Define FRONTEND_URL for redirects (Default to your frontend Render URL)
// You should set this in your Render Environment Variables if it differs.
const FRONTEND_URL = process.env.FRONTEND_URL || "https://checkout-frontend.onrender.com";


// Separate database configuration for direct MySQL2 connections
// SECURITY FIX: All credentials now loaded from environment variables.
// Required .env variables: DB_HOST, DB_USER, DB_PASS, DB_NAME
const dbConnectionConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  connectTimeout: 10000 // Add a 10-second connection timeout (10000 ms)
};

// Configuration for the express-mysql-session store
const sessionStoreOptions = {
  host: dbConnectionConfig.host,
  user: dbConnectionConfig.user,
  password: dbConnectionConfig.password,
  database: dbConnectionConfig.database,
  clearExpired: true,              // Automatically clear expired sessions
  checkExpirationInterval: 900000, // 15 minutes
  expiration: 86400000,            // 24 hours
  createDatabaseTable: true,       // Whether to create the 'sessions' table
  connectionLimit: 5,              // Allow a small pool for resilience
  acquireTimeout: 10000,           // 10 second timeout to acquire a connection
  waitForConnections: true,
  endConnectionOnClose: true
};

// NEW: Configure the session store instance
const sessionStore = new MySQLStore(sessionStoreOptions);

// Handle session store errors gracefully so they don't crash the server
sessionStore.on('error', function(err) {
    console.error('Session store error (non-fatal):', err.code || err.message);
});


// --- CORS Configuration (MODIFIED to handle dynamic origin for credentials) ---
const allowedOrigins = [
  "http://localhost:8080", // For local development
  "http://localhost:3000", // For local development
  "https://checkout-frontend.onrender.com", // Your Render frontend URL
  "https://www.chicagostainless.com", // Your production domain
  // REMOVED: Temporary Google Cloud Shell URL — never leave dev/debug origins in production
];

const corsOptions = {
  origin: function (origin, callback) {
    // SECURITY: Requests with no Origin header are only allowed from the same host (server-rendered pages).
    // This restricts unauthenticated curl/server-to-server calls from bypassing CORS silently.
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}`;
      console.warn(msg); // Log disallowed origins
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true, // IMPORTANT: Allows cookies/sessions to be sent
  optionsSuccessStatus: 200,
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
};

app.use(cors(corsOptions));

// --- Session & Body Parsing ---
app.use(express.json());
app.set("trust proxy", 1); // Essential for 'secure: true' cookies when behind a proxy/load balancer like Render

app.use(session({
  secret: process.env.SESSION_SECRET, // Must be set as an environment variable — no hardcoded fallback
  resave: false,
  saveUninitialized: false,
  store: sessionStore, // <-- THIS IS THE CRUCIAL CHANGE for persistent sessions
  cookie: {
    sameSite: "none",  // Required for cross-site cookies to be sent from different origins
    secure: true,      // Required for sameSite: "none" and highly recommended for production (Render provides HTTPS)
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static files from 'public' directory
app.use(express.static("public"));

// --- Rate Limiters ---
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20,                   // max 20 attempts per window per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many login attempts. Please try again in 15 minutes." }
});

// --- HTML Escape Helper (prevents HTML injection in admin emails) ---
function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// --- CSRF Protection ---
// Generates a CSRF token for the session on first request, validates it on mutating requests.
function generateCsrfToken() {
    return crypto.randomBytes(32).toString('hex');
}

const csrfProtection = (req, res, next) => {
    // Skip CSRF for GET/HEAD/OPTIONS (safe methods)
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    // Skip CSRF for the login and registration routes (user has no token yet)
    const csrfExemptPaths = [
        '/login',
        '/admin-login',
        '/register-company',
        '/register-user',
        '/company-by-name',
        '/submit-order',
        '/logout',
        '/api/shipto',
        '/api/orders',
        '/user',
        '/edit-company',
        '/edit-user',
        '/add-user',
        '/add-company',
        '/delete-company',
        '/delete-user',
        '/admin/settings',
        '/admin/send-approval-email',
        '/admin/impersonate',
        '/api/cart',
    ];
    if (csrfExemptPaths.some(p => req.path.startsWith(p))) return next();

    const sessionToken = req.session.csrfToken;
    const headerToken = req.headers['x-csrf-token'];
    if (!sessionToken || !headerToken || sessionToken !== headerToken) {
        console.warn(`[CSRF] Token mismatch for ${req.method} ${req.path}. IP: ${req.ip}`);
        return res.status(403).json({ error: "Invalid or missing CSRF token." });
    }
    next();
};
app.use(csrfProtection);

// Endpoint for the frontend to fetch its CSRF token
app.get('/csrf-token', (req, res) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = generateCsrfToken();
    }
    res.json({ csrfToken: req.session.csrfToken });
});

// --- FIX: Fallback Routes for HTML Files ---
// Admin pages require a verified admin session at the route level.
app.get('/admin-dashboard.html', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).send("Forbidden: Admin access required.");
    }
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

app.get('/customer-portal.html', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send("Unauthorized: Login required.");
    }
    res.sendFile(path.join(__dirname, 'customer-portal.html'));
});
// -------------------------------------------


// --- SendGrid Configuration ---
const mailtrap = new MailtrapClient({ token: process.env.MAILTRAP_API_KEY });
const EMAIL_FROM = 'orderdesk@chicagostainless.com';
console.log(`Mailtrap Config: API key loaded, From=${EMAIL_FROM}`);

// Helper to convert nodemailer-style options to Mailtrap format
function toMailtrapOptions(opts) {
    const msg = {
        from: { email: typeof opts.from === 'string' ? opts.from : opts.from.email, name: 'Chicago Stainless Equipment' },
        to: Array.isArray(opts.to) ? opts.to.map(e => ({ email: e })) : [{ email: opts.to }],
        subject: opts.subject,
        html: opts.html,
    };
    if (opts.replyTo) msg.reply_to = { email: opts.replyTo };
    if (opts.attachments && opts.attachments.length > 0) {
        msg.attachments = opts.attachments.map(a => ({
            filename: a.filename,
            content: a.content,
            type: a.type || 'application/pdf',
            disposition: a.disposition || 'attachment'
        }));
    }
    return msg;
}

// --- NEW: Excluded Emails for Login History Logging ---
const EXCLUDED_LOGGING_EMAILS = [
    "greg@chicagostainless.com",
    "gregm@chicagostainless.com",
    "emma@chicagostainless.com",
];
// --------------------------------------------------------

// --- Helper Middleware for Admin Check ---
const requireAdmin = (req, res, next) => {
    if (!req.session.user || req.session.user.role !== "admin") {
        console.warn(`[requireAdmin] Forbidden: User not admin. Session user: ${req.session.user ? req.session.user.email : 'none'}`);
        return res.status(403).json({ error: "Forbidden: Admin access required" });
    }
    console.log(`[requireAdmin] Access granted for admin: ${req.session.user.email}`);
    next();
};

// --- NEW: Helper Middleware for Authenticated User Check ---
const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        console.warn(`[requireAuth] Unauthorized: No user in session for path: ${req.path}`);
        return res.status(401).json({ error: "Unauthorized: Login required" });
    }
    console.log(`[requireAuth] Authenticated user: ${req.session.user.email} (Role: ${req.session.user.role}) for path: ${req.path}`);
    next();
};

// --- MODIFIED: Helper Middleware for Company Access Authorization ---
const authorizeCompanyAccess = async (req, res, next) => {
    console.log(`[authorizeCompanyAccess] Entering middleware for path: ${req.path}`);
    if (!req.session.user) {
        console.warn(`[authorizeCompanyAccess] Unauthorized: No user in session.`);
        return res.status(401).json({ error: "Unauthorized: Login required" });
    }

    // Allow admins to access any company's data
    if (req.session.user.role === "admin") {
        console.log(`[authorizeCompanyAccess] Admin access granted for: ${req.session.user.email}`);
        return next();
    }

    const userCompanyId = req.session.user.companyId;
    console.log(`[authorizeCompanyAccess] Non-admin user: ${req.session.user.email}, Session Company ID: ${userCompanyId}`);

    let conn = null; // Initialize connection to null
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        let requestedCompanyId = null;

        if (req.params.companyId) {
            requestedCompanyId = parseInt(req.params.companyId, 10);
            console.log(`[authorizeCompanyAccess] Requested Company ID from params: ${requestedCompanyId}`);
        } else if (req.body.companyId) {
            requestedCompanyId = parseInt(req.body.companyId, 10);
            console.log(`[authorizeCompanyAccess] Requested Company ID from body: ${requestedCompanyId}`);
        } else if (req.params.addressId) { // Handles PUT and DELETE for single address
            const [rows] = await conn.execute("SELECT company_id FROM shipto_addresses WHERE id = ?", [req.params.addressId]);
            if (rows.length > 0) {
                requestedCompanyId = rows[0].company_id;
                console.log(`[authorizeCompanyAccess] Requested Company ID from addressId lookup: ${requestedCompanyId}`);
            } else {
                console.warn(`[authorizeCompanyAccess] Address ID ${req.params.addressId} not found for company lookup.`);
                // If the address isn't found, the user can't access it, so deny access.
                return res.status(404).json({ error: "Resource not found." });
            }
        }

        // Check if the user's company ID matches the requested company ID
        if (requestedCompanyId === null || userCompanyId !== requestedCompanyId) {
            console.warn(`[authorizeCompanyAccess] Forbidden: Company ID mismatch. Session: ${userCompanyId}, Requested: ${requestedCompanyId}, Path: ${req.path}`);
            return res.status(403).json({ error: "Forbidden: You can only access data for your own company." });
        }

        console.log(`[authorizeCompanyAccess] Access granted for non-admin user. Path: ${req.path}`);
        next(); // All checks passed, proceed to the route handler

    } catch (err) {
        // The catch block now properly covers the entire authorization logic
        console.error("Error during company access authorization:", err);
        return res.status(500).json({ error: "Server error during authorization." });
    } finally {
        if (conn) conn.end(); // Ensure connection is always closed
    }
};


// Function to send order notification email (Admin)
async function sendOrderNotificationEmail(orderId, orderDetails, pdfBuffer) {

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [settings] = await conn.execute("SELECT po_email FROM admin_settings WHERE id = 1");
        const recipientEmail = settings[0]?.po_email || "Greg@ChicagoStainless.com"; // Fallback email

        const mailOptions = {
            from: EMAIL_FROM, // Changed FROM address
            to: recipientEmail,
            replyTo: orderDetails.orderedByEmail, // Set REPLY-TO to user's email
            subject: `New Website Order: #${orderId} - PO# ${escapeHtml(orderDetails.poNumber)}`,
            html: `
                <p>Dear Administrator,</p>
                <p>A new order has been submitted on the website.</p>
                <p><strong>Order ID:</strong> ${escapeHtml(String(orderId))}</p>
                <p><strong>PO Number:</strong> ${escapeHtml(orderDetails.poNumber)}</p>
                <p><strong>Ordered By:</strong> ${escapeHtml(orderDetails.orderedBy)}</p>
                <p><strong>Billing Address:</strong><br>${escapeHtml(orderDetails.billingAddress).replace(/\n/g, '<br>')}</p>
                <p><strong>Shipping Address:</strong><br>${escapeHtml(orderDetails.shippingAddress).replace(/\n/g, '<br>')}</p>
                <p><strong>Shipping Method:</strong> ${escapeHtml(orderDetails.shippingMethod)}</p>
                ${orderDetails.carrierAccount ? `<p><strong>Carrier Account #:</strong> ${escapeHtml(orderDetails.carrierAccount)}</p>` : ''}
                <p>The full order information is attached as a PDF.</p>
                <p>Thank you.</p>
            `,
            attachments: pdfBuffer ? [
                {
                    filename: `Order_${orderId}_${orderDetails.poNumber}.pdf`,
                    content: pdfBuffer.toString('base64'),
                    type: 'application/pdf',
                    disposition: 'attachment'
                }
            ] : []
        };

        mailtrap.send(toMailtrapOptions(mailOptions))
            .then(() => { console.log("Order notification email sent:"); })
            .catch(error => { console.error("Error sending order notification email::", error.message); });
    } catch (err) {
        console.error("Error fetching admin PO email or sending order notification:", err);
    } finally {
        if (conn) conn.end();
    }
}

// MODIFIED: Function to send registration notification email (Admin)
async function sendRegistrationNotificationEmail(companyName, userEmail, firstName, lastName, phone, companyId, role, apEmail, pdfBuffer) { // ADDED pdfBuffer
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [settings] = await conn.execute("SELECT registration_email FROM admin_settings WHERE id = 1");
        const recipientEmail = settings[0]?.registration_email || "Greg@ChicagoStainless.com"; // Fallback email

        const mailOptions = {
            from: EMAIL_FROM, // Changed FROM address
            to: recipientEmail,
            replyTo: userEmail, // Set REPLY-TO to user's email
            subject: `New Company Registration: ${escapeHtml(companyName)}`,
            html: `
                <p>Hello Admin,</p>
                <p>A new user has registered through the checkout page:</p>
                <ul>
                    <li><strong>Company:</strong> ${escapeHtml(companyName)} (ID: ${escapeHtml(String(companyId))})</li>
                    <li><strong>Name:</strong> ${escapeHtml(firstName)} ${escapeHtml(lastName)}</li>
                    <li><strong>Email:</strong> ${escapeHtml(userEmail)}</li>
                    <li><strong>A/P Email:</strong> ${escapeHtml(apEmail) || 'N/A'}</li>
                    <li><strong>Phone:</strong> ${escapeHtml(phone) || 'N/A'}</li>
                    <li><strong>Role:</strong> ${escapeHtml(role)}</li>
                </ul>
                <p>Please log into the admin dashboard to review and approve the company.</p>
                ${pdfBuffer ? '<p>The contents of the user\'s shopping cart at the time of registration is attached as a PDF.</p>' : ''}
                <p>Thank you.</p>
            `,
            attachments: pdfBuffer ? [
                {
                    filename: `Cart_Registration_${companyName.replace(/[^a-zA-Z0-9]/g, '_')}.pdf`,
                    content: pdfBuffer.toString('base64'),
                    type: 'application/pdf',
                    disposition: 'attachment'
                }
            ] : []
        };

        mailtrap.send(toMailtrapOptions(mailOptions))
            .then(() => { console.log("New user registration email sent:"); })
            .catch(error => { console.error("Error sending new user registration email::", error.message); });
    } catch (err) {
        console.error("Error fetching admin registration email or sending registration notification:", err);
    } finally {
        if (conn) conn.end();
    }
}

// NEW: Function to send notification for a new user joining an EXISTING company (Admin)
async function sendExistingCompanyUserNotificationEmail(companyName, userEmail, firstName, lastName, phone, companyId) {
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [settings] = await conn.execute("SELECT registration_email FROM admin_settings WHERE id = 1");
        const recipientEmail = settings[0]?.registration_email || "Greg@ChicagoStainless.com"; // Fallback email

        const mailOptions = {
            from: EMAIL_FROM,
            to: recipientEmail,
            replyTo: userEmail,
            subject: `New User Registration for Existing Company: ${companyName}`,
            html: `
                <p>Hello Admin,</p>
                <p>A new user has registered for an existing company account:</p>
                <ul>
                    <li><strong>Company:</strong> ${companyName} (ID: ${companyId})</li>
                    <li><strong>New User Name:</strong> ${firstName} ${lastName}</li>
                    <li><strong>Email:</strong> ${userEmail}</li>
                    <li><strong>Phone:</strong> ${phone || 'N/A'}</li>
                </ul>
                <p>This user has been automatically granted access under the existing company account. No approval is necessary for the company itself.</p>
                <p>Thank Thank you.</p>
            `,
        };

        mailtrap.send(toMailtrapOptions(mailOptions))
            .then(() => { console.log("Existing company user registration email sent:"); })
            .catch(error => { console.error("Error sending existing company user registration email::", error.message); });
    } catch (err) {
        console.error("Error fetching admin registration email or sending existing company user notification:", err);
    } finally {
        if (conn) conn.end();
    }
}

// *** NEW: Function to send a welcome email to a new user joining an existing company ***
async function sendWelcomeEmailToNewUser(userEmail, firstName, companyName) {
    try {
        const mailOptions = {
            from: EMAIL_FROM,
            to: userEmail,
            replyTo: "OrderDesk@ChicagoStainless.com",
            subject: `Welcome to Chicago Stainless Equipment!`,
            html: `
                <p>Dear ${firstName || 'Customer'},</p>
                <p>Thank you for registering with Chicago Stainless Equipment! Your account has been successfully created under the company: <strong>${companyName}</strong>.</p>
                <p>Your account is ready to use immediately. You can now log in to our website to place orders, view order history, and manage your shipping addresses.</p>
                <p>We're excited to have you on board!</p>
                <p>Sincerely,</p>
                <p>The Chicago Stainless Equipment Team</p>
            `,
        };

        mailtrap.send(toMailtrapOptions(mailOptions))
            .then(() => { console.log(`Welcome email sent to new user ${userEmail}.`); })
            .catch(error => { console.error("Error sending welcome email to new user:", error.message); });
    } catch (err) {
        console.error("Error preparing welcome email for new user:", err);
    }
}


// Function to send company approval email (User)
async function sendCompanyApprovalEmail(companyId) {
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        // Fetch company details and associated users
        const [companyRows] = await conn.execute("SELECT name FROM companies WHERE id = ?", [companyId]);
        if (companyRows.length === 0) {
            console.error(`Company with ID ${companyId} not found for approval email.`);
            return;
        }
        const companyName = companyRows[0].name;

        // Find the primary user for this company (e.g., the first 'user' role found)
        const [userRows] = await conn.execute("SELECT email, first_name FROM users WHERE company_id = ? AND role = 'user' LIMIT 1", [companyId]);
        if (userRows.length === 0) {
            console.error(`No primary user found for company ID ${companyId} to send approval email.`);
            return;
        }
        const userEmail = userRows[0].email;
        const userName = userRows[0].first_name;

        const mailOptions = {
            from: EMAIL_FROM, // Changed FROM address
            to: userEmail,
            replyTo: "OrderDesk@ChicagoStainless.com", // Replies from user should go to OrderDesk
            subject: `Your Company Registration for ${companyName} Has Been Approved!`,
            html: `
                <p>Dear ${userName || 'Customer'},</p>
                <p>Good news! Your company, <strong>${companyName}</strong>, has been approved for full access to the Chicago Stainless Equipment website.</p>
                <p>You can now log in and place orders.</p>
                <p>Thank you for choosing Chicago Stainless Equipment.</p>
                <p>Sincerely,</p>
                <p>The Chicago Stainless Equipment Team</p>
            `,
        };

        mailtrap.send(toMailtrapOptions(mailOptions))
            .then(() => { console.log(`Company approval email sent to ${userEmail}.`); })
            .catch(error => { console.error("Error sending company approval email:", error.message); });
    } catch (err) {
        console.error("Error sending company approval email:", err);
    } finally {
        if (conn) conn.end();
    }
}
// --- Authentication Routes ---

// NEW: Admin Login Route
app.post("/admin-login", loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [users] = await conn.execute("SELECT id, email, first_name, last_name, phone, role, password, company_id FROM users WHERE email = ? AND role = 'admin'", [email]);
        const user = users[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Invalid credentials or not authorized as admin" });
        }

        req.session.user = {
            id: user.id,
            email: user.email,
            role: user.role,
            companyId: user.company_id,
            firstName: user.first_name,
            lastName: user.last_name,
            phone: user.phone
        };
        // Assign a new CSRF token to the session on login
        req.session.csrfToken = generateCsrfToken();
        
        // --- MODIFIED LOGIC FOR LOGIN HISTORY ---
        const userEmailLower = user.email.toLowerCase();
        if (!EXCLUDED_LOGGING_EMAILS.includes(userEmailLower)) {
            const ip = req.ip || req.connection.remoteAddress;
            await conn.execute(
                'INSERT INTO login_history (user_id, ip_address) VALUES (?, ?)',
                [user.id, ip]
            );
        }
        // --- END MODIFIED LOGIC ---

        // IMPORTANT: explicitly save the session to MySQL before responding.
        // Without this, res.json() fires before the async DB write completes.
        // The client then immediately calls /companies, the session row isn't
        // there yet, and the server returns 401 — forcing a second login.
        req.session.save((saveErr) => {
            if (saveErr) {
                console.error("Admin login: session save error:", saveErr);
                return res.status(500).json({ error: "Login succeeded but session could not be saved. Please try again." });
            }
            res.json({ message: "Admin login successful", role: user.role });
        });

    } catch (err) {
        console.error("Admin login error:", err);
        res.status(500).json({ error: "Admin login failed due to server error" });
    } finally {
        if (conn) conn.end();
    }
});

// NEW: Admin Check Auth Route
app.get("/admin/check-auth", (req, res) => {
    console.log(`[Admin Check Auth] Session user: ${req.session.user ? req.session.user.email : 'none'}, Role: ${req.session.user ? req.session.user.role : 'none'}`);
    if (req.session.user && req.session.user.role === 'admin') {
        res.status(200).json({ authenticated: true, role: 'admin' });
    } else {
        res.status(401).json({ authenticated: false, message: "Not authenticated as admin" });
    }
});

// MODIFIED: Impersonate Link Generation Endpoint (Admin side)
app.get("/admin/impersonate/:userId", requireAdmin, async (req, res) => {
    const { userId } = req.params;
    
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [users] = await conn.execute("SELECT id FROM users WHERE id = ?", [userId]);
        if (users.length === 0) {
            return res.status(404).json({ error: "User not found for impersonation" });
        }

        // SECURITY FIX: Generate a cryptographically secure, single-use, short-lived token.
        // The old approach used a predictable "IMPERSONATION_TOKEN_FOR_{userId}" string which
        // allowed anyone to impersonate any user by guessing the token.
        const token = crypto.randomBytes(32).toString('hex');
        impersonationTokens.set(token, {
            userId: parseInt(userId, 10),
            expires: Date.now() + IMPERSONATION_TOKEN_TTL_MS
        });

        const redirectUrl = `${API_URL}/login-via-token/${token}`;
        res.json({ redirectUrl });

    } catch (err) {
        console.error("Error during impersonation link generation:", err);
        res.status(500).json({ error: "Server error during link generation" });
    } finally {
        if (conn) conn.end();
    }
});

// NEW: Token Exchange Route (Handles the browser redirect and sets the session)
app.get("/login-via-token/:token", async (req, res) => {
    const { token } = req.params;

    // SECURITY FIX: Validate against the in-memory secure token store.
    // Tokens are random, short-lived (15 min), and single-use.
    const tokenData = impersonationTokens.get(token);

    if (!tokenData) {
        console.warn("[Login Via Token] Token not found or already used.");
        return res.status(401).send("Invalid or expired impersonation link.");
    }
    if (tokenData.expires < Date.now()) {
        impersonationTokens.delete(token);
        console.warn("[Login Via Token] Token expired.");
        return res.status(401).send("Impersonation link has expired.");
    }

    // Consume the token immediately (single-use)
    impersonationTokens.delete(token);

    const userId = tokenData.userId;

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [users] = await conn.execute(
            "SELECT id, email, first_name, last_name, phone, role, company_id FROM users WHERE id = ?",
            [userId]
        );
        const user = users[0];

        if (!user) {
            return res.status(404).send("User not found.");
        }

        // Set the session for the impersonated user
        req.session.user = {
            id: user.id,
            email: user.email,
            role: user.role,
            companyId: user.company_id,
            firstName: user.first_name,
            lastName: user.last_name,
            phone: user.phone
        };
        req.session.isImpersonated = true; // Flag so the portal skips localStorage cart sync
        req.session.csrfToken = generateCsrfToken();

        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) { console.error("[Login Via Token] Error saving session:", err); reject(err); }
                else resolve();
            });
        });

        console.log(`[Login Via Token] Session established for user ID ${userId}. Redirecting to Frontend.`);
        res.redirect(`${FRONTEND_URL}/customer-portal.html`);

    } catch (err) {
        console.error("Error during impersonation token exchange:", err);
        res.status(500).send("Server error during login via token.");
    } finally {
        if (conn) conn.end();
    }
});


// NEW: Endpoint to get login history for a specific user
app.get("/admin/user-logins/:userId", requireAdmin, async (req, res) => {
    const { userId } = req.params;
    console.log(`[GET /admin/user-logins] Fetching login history for user ID: ${userId}`);
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);

        const [history] = await conn.execute(
            "SELECT login_time, ip_address FROM login_history WHERE user_id = ? ORDER BY login_time DESC",
            [userId]
        );
        console.log(`[GET /admin/user-logins] Found ${history.length} login records for user ID: ${userId}`);
        res.json(history);
    } catch (err) {
        console.error("Error fetching user login history:", err);
        res.status(500).json({ error: "Failed to retrieve login history" });
    } finally {
        if (conn) conn.end();
    }
});

// Endpoint to generate a login report for a date range
app.get("/admin/login-report", requireAdmin, async (req, res) => {
    const { startDate, endDate } = req.query;
    console.log(`[GET /admin/login-report] Report requested for dates: ${startDate} to ${endDate}`);

    if (!startDate || !endDate) {
        return res.status(400).json({ error: "Start date and end date are required." });
    }

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const query = `
            SELECT
                lh.id,
                lh.user_id,
                lh.login_time,
                lh.ip_address,
                u.email,
                u.first_name,
                u.last_name,
                u.company_id AS companyId,
                c.name AS company_name
            FROM login_history lh
            JOIN users u ON lh.user_id = u.id
            JOIN companies c ON u.company_id = c.id
            WHERE DATE(lh.login_time) BETWEEN ? AND ?
            ORDER BY lh.login_time DESC;
        `;
        const [report] = await conn.execute(query, [startDate, endDate]);
        console.log(`[GET /admin/login-report] Found ${report.length} records for the date range.`);
        res.json(report);
    } catch (err) {
        console.error("Error generating login report:", err);
        res.status(500).json({ error: "Failed to generate login report" });
    } finally {
        if (conn) conn.end();
    }
});

// Endpoint to generate an orders report for a date range
app.get("/admin/orders-report", requireAdmin, async (req, res) => {
    const { startDate, endDate } = req.query;
    console.log(`[GET /admin/orders-report] Report requested for dates: ${startDate} to ${endDate}`);

    if (!startDate || !endDate) {
        return res.status(400).json({ error: "Start date and end date are required." });
    }

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const query = `
            SELECT
                o.id,
                o.date,
                o.poNumber,
                o.orderedByName,
                o.companyId,
                o.items,
                c.name AS companyName
            FROM orders o
            JOIN companies c ON o.companyId = c.id
            WHERE DATE(o.date) BETWEEN ? AND ?
            ORDER BY o.date DESC;
        `;
        const [report] = await conn.execute(query, [startDate, endDate]);
        console.log(`[GET /admin/orders-report] Found ${report.length} order records for the date range.`);
        res.json(report);
    } catch (err) {
        console.error("Error generating orders report:", err);
        res.status(500).json({ error: "Failed to generate orders report" });
    } finally {
        if (conn) conn.end();
    }
});

// Endpoint for admins to get full details of any single order
app.get("/admin/order-details/:orderId", requireAdmin, async (req, res) => {
    const { orderId } = req.params;
    console.log(`[GET /admin/order-details] Fetching full details for order ID: ${orderId}`);
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const query = `
            SELECT o.*, c.terms as companyTerms 
            FROM orders o
            JOIN companies c ON o.companyId = c.id
            WHERE o.id = ?
        `;
        const [orders] = await conn.execute(query, [orderId]);

        if (orders.length === 0) {
            return res.status(404).json({ error: "Order not found" });
        }

        const order = orders[0];
        
        // Format the order object to be compatible with the existing showOrderDetailsModal function
        const formattedOrder = {
            id: order.id,
            poNumber: order.poNumber,
            shippingMethod: order.shippingMethod,
            items: order.items, // Already parsed as JSON by mysql2 driver
            date: order.date,
            orderedByName: order.orderedByName,
            orderedByEmail: order.orderedByEmail,
            orderedByPhone: order.orderedByPhone,
            billingAddress: order.billingAddress,
            shippingAddress: order.shippingAddress,
            attn: order.attn,
            tag: order.tag,
            carrierAccount: order.carrierAccount,
            thirdPartyDetails: order.thirdPartyDetails, // Already parsed as JSON
            shippingAccountType: order.shippingAccountType,
            company: { // Mock the company object structure expected by the modal
                terms: order.companyTerms
            }
        };

        res.json(formattedOrder);
    } catch (err) {
        console.error("Error fetching single order details:", err);
        res.status(500).json({ error: "Failed to retrieve order details." });
    } finally {
        if (conn) conn.end();
    }
});

// Endpoint to generate a report of all users
app.get("/admin/users-report", requireAdmin, async (req, res) => {
    console.log(`[GET /admin/users-report] Report for all users requested.`);
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const query = `
            SELECT
                u.id,
                u.first_name,
                u.last_name,
                u.email,
                u.created_at,
                c.name AS companyName
            FROM users u
            JOIN companies c ON u.company_id = c.id
            ORDER BY u.last_name ASC, u.first_name ASC;
        `;
        const [users] = await conn.execute(query);
        console.log(`[GET /admin/users-report] Found ${users.length} total users.`);
        res.json(users);
    } catch (err) {
        console.error("Error generating users report:", err);
        res.status(500).json({ error: "Failed to generate users report" });
    } finally {
        if (conn) conn.end();
    }
});

app.get("/admin/abandoned-carts-report", requireAdmin, async (req, res) => {
    const { startDate, endDate } = req.query;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        let query = `
            SELECT uc.user_id, uc.cart_data, uc.updated_at,
                   u.email, u.first_name, u.last_name,
                   c.name AS company_name
            FROM user_carts uc
            JOIN users u ON u.id = uc.user_id
            LEFT JOIN companies c ON c.id = u.company_id
        `;
        const params = [];
        if (startDate && endDate) {
            query += ` WHERE DATE(uc.updated_at) BETWEEN ? AND ?`;
            params.push(startDate, endDate);
        } else if (startDate) {
            query += ` WHERE DATE(uc.updated_at) >= ?`;
            params.push(startDate);
        } else if (endDate) {
            query += ` WHERE DATE(uc.updated_at) <= ?`;
            params.push(endDate);
        }
        query += ` ORDER BY uc.updated_at DESC`;
        const [rows] = await conn.execute(query, params);

        const carts = rows.map(row => {
            let items = row.cart_data;
            if (typeof items === 'string') {
                try { items = JSON.parse(items); } catch(e) { items = []; }
            }
            if (!Array.isArray(items)) items = [];
            const total = items.reduce((sum, item) => sum + ((item.price || 0) * (item.quantity || 0)), 0);
            return {
                date:        row.updated_at,
                companyName: row.company_name || '',
                userName:    `${row.first_name || ''} ${row.last_name || ''}`.trim(),
                email:       row.email,
                itemCount:   items.length,
                total:       total.toFixed(2),
                items:       items
            };
        }).filter(c => c.itemCount > 0);

        console.log(`[GET /admin/abandoned-carts-report] Found ${carts.length} carts between ${startDate} and ${endDate}`);
        res.json(carts);
    } catch (err) {
        console.error("Error generating abandoned carts report:", err);
        res.status(500).json({ error: "Failed to generate abandoned carts report" });
    } finally {
        if (conn) conn.end();
    }
});

app.post("/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);

    // MODIFIED: Explicitly select columns including 'phone' and 'password'
    const [users] = await conn.execute("SELECT id, email, first_name, last_name, phone, role, password, company_id FROM users WHERE email = ?", [email]);

    const user = users[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Set user data in session
    req.session.user = {
        id: user.id,
        email: user.email,
        role: user.role,
        companyId: user.company_id,
        firstName: user.first_name,
        lastName: user.last_name,
        phone: user.phone
    };
    // Assign a fresh CSRF token on login
    req.session.csrfToken = generateCsrfToken();

    // --- MODIFIED LOGIC FOR LOGIN HISTORY ---
    const userEmailLower = user.email.toLowerCase();
    if (!EXCLUDED_LOGGING_EMAILS.includes(userEmailLower)) {
        const ip = req.ip || req.connection.remoteAddress;
        await conn.execute(
            'INSERT INTO login_history (user_id, ip_address) VALUES (?, ?)',
            [user.id, ip]
        );
    }
    // --- END MODIFIED LOGIC ---

    // Explicitly save session to MySQL before responding (same race-condition
    // fix as /admin-login — ensures session row exists before client's next request).
    req.session.save((saveErr) => {
        if (saveErr) {
            console.error("Login: session save error:", saveErr);
            return res.status(500).json({ error: "Login succeeded but session could not be saved. Please try again." });
        }
        res.json({ message: "Login successful", role: user.role });
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed due to server error" });
  } finally {
    if (conn) conn.end();
  }
});

app.get("/user-profile", requireAuth, async (req, res) => {
  console.log("[User Profile Route] Route hit.");
  const { user } = req.session;


  console.log("[User Profile Route] Session user:", user);



  if (user) {
      console.log("[User Profile Route] User profile phone from session:", user.phone); // ADDED LOG
      console.log("[User Profile Route] Sending user profile from session.");
      res.json({
          email: user.email,
          role: user.role,
          company_id: user.companyId,
          first_name: user.firstName,
          last_name: user.lastName,
          phone: user.phone, // Include phone number here
          isImpersonated: req.session.isImpersonated || false
      });
  } else {
      console.log("[User Profile Route] User not found in session (should be caught by requireAuth).");
      res.status(401).json({ error: "Not logged in" });
  }
});

// Endpoint to update user profile
app.put("/user/update-profile", requireAuth, async (req, res) => {
    const { firstName, lastName, email, phone, currentPassword, newPassword } = req.body;
    const userId = req.session.user.id; // Get user ID from session
    console.log(`[PUT /user/update-profile] Attempting to update profile for user ID: ${userId}`);

    if (!firstName || !lastName || !email || !currentPassword) {
        console.warn("[PUT /user/update-profile] Missing required fields for profile update.");
        return res.status(400).json({ error: "First Name, Last Name, Email, and Current Password are required." });
    }

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);

        // 1. Verify current password
        const [users] = await conn.execute("SELECT password FROM users WHERE id = ?", [userId]);
        const user = users[0];
        if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
            console.warn(`[PUT /user/update-profile] Invalid current password for user ID: ${userId}`);
            return res.status(401).json({ error: "Invalid current password." });
        }

        // 2. Check if new email is already in use by another user
        const [existingEmailUsers] = await conn.execute("SELECT id FROM users WHERE email = ? AND id != ?", [email, userId]);
        if (existingEmailUsers.length > 0) {
            console.warn(`[PUT /user/update-profile] Email ${email} already in use by another user.`);
            return res.status(409).json({ error: "This email is already registered to another account." });
        }

        // 3. Prepare update query
        const fieldsToUpdate = [];
        const values = [];

        fieldsToUpdate.push("first_name = ?"); values.push(firstName);
        fieldsToUpdate.push("last_name = ?"); values.push(lastName);
        fieldsToUpdate.push("email = ?"); values.push(email);
        fieldsToUpdate.push("phone = ?"); values.push(phone || null); // Allow phone to be null

        if (newPassword) {
            if (newPassword.length < 6) {
                console.warn("[PUT /user/update-profile] New password is too short.");
                return res.status(400).json({ error: "New password must be at least 6 characters long." });
            }
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            fieldsToUpdate.push("password = ?"); values.push(hashedPassword);
        }

        const query = `UPDATE users SET ${fieldsToUpdate.join(', ')} WHERE id = ?`;
        values.push(userId);

        await conn.execute(query, values);
        console.log(`[PUT /user/update-profile] User ID ${userId} profile updated in DB.`);

        // 4. Update session data
        req.session.user.firstName = firstName;
        req.session.user.lastName = lastName;
        req.session.user.email = email;
        req.session.user.phone = phone;
        // No need to update password in session, as it's not stored plain text

        console.log(`[PUT /user/update-profile] Session updated for user ID: ${userId}`);
        res.json({ message: "Profile updated successfully" });

    } catch (err) {
        console.error("Error updating user profile:", err);
        res.status(500).json({ error: "Failed to update profile due to server error." });
    } finally {
        if (conn) conn.end();
    }
});


app.get("/user/company-details", requireAuth, async (req, res) => {
  console.log(`[User Company Details] Route hit for user: ${req.session.user.email}`);
  let userCompanyId = req.session.user.companyId;
  console.log(`[User Company Details] User ID: ${req.session.user.id}, Company ID from session: ${userCompanyId}`);
  console.log(`[User Company Details] Type of userCompanyId (before parse): ${typeof userCompanyId}`);

  userCompanyId = parseInt(userCompanyId, 10);
  console.log(`[User Company Details] Type of userCompanyId (after parse): ${typeof userCompanyId}, Value: ${userCompanyId}`);

  if (isNaN(userCompanyId) || userCompanyId <= 0) {
    console.error("[User Company Details] No valid company ID associated with this user in session after parsing.");
    return res.status(404).json({ error: "No company associated with this user." });
  }

  let conn;
  try {
    console.log("[User Company Details] Attempting to create database connection...");
    conn = await mysql.createConnection(dbConnectionConfig);
    console.log("[User Company Details] Database connection established.");

    const [companies] = await conn.execute(
      "SELECT id, name, address1, city, state, zip, country, terms, discount, notes, approved, denied FROM companies WHERE id = ?",
      [userCompanyId]
    );
    console.log("[User Company Details] Raw query result (companies array for specific ID):", companies);

    if (companies.length === 0) {
      console.error(`[User Company Details] Company not found in DB for ID: ${userCompanyId}. Query returned no rows.`);
      return res.status(404).json({ error: "Company not found for this user." });
    }
    const company = companies[0];
    console.log(`[User Company Details] Fetched company ID ${company.id}: approved=${company.approved}, denied=${company.denied}`); // NEW LOG
    res.json(company);
  } catch (err) {
    console.error("Error in /user/company-details route:", err);
    res.status(500).json({ error: "Failed to retrieve user's company details." });
  } finally {
    if (conn) {
        conn.end();
        console.log("[User Company Details] Database connection closed.");
    }
  }
});

app.get("/user/:userId", requireAdmin, async (req, res) => {
    const { userId } = req.params;
    console.log(`[GET /user/:userId] Fetching user ID: ${userId}`);
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [users] = await conn.execute(
            "SELECT id, email, first_name, last_name, phone, role, company_id, created_at FROM users WHERE id = ?",
            [userId]
        );
        const user = users[0];
        if (!user) {
            console.warn(`[GET /user/:userId] User ID ${userId} not found.`);
            return res.status(404).json({ error: "User not found" });
        }
        console.log(`[GET /user/:userId] Found user: ${user.email}`);
        res.json(user);
    } catch (err) {
        console.error("Error fetching user by ID:", err);
        res.status(500).json({ error: "Failed to retrieve user details" });
    } finally {
        if (conn) conn.end();
    }
});


app.post("/logout", (req, res) => {
  console.log(`[POST /logout] User ${req.session.user ? req.session.user.email : 'unknown'} logging out.`);
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout failed:", err);
      return res.status(500).json({ error: "Logout failed" });
    }
    res.clearCookie("connect.sid", { path: "/", sameSite: "none", secure: true });
    console.log("[POST /logout] Session destroyed and cookie cleared.");
    res.json({ message: "Logged out" });
  });
});

// --- NEW: Registration Endpoints ---

// MODIFIED: /register-company endpoint
app.post("/register-company", async (req, res) => {
  const { name, address1, ap_email, website, city, state, zip, country, terms, logo, discount } = req.body; // Added ap_email
  console.log(`[POST /register-company] Attempting to register company: ${name}`);
  if (!name || !address1 || !ap_email || !city || !state || !zip) { // Added ap_email to validation
    console.warn("[POST /register-company] Missing required fields for company registration.");
    return res.status(400).json({ error: "Company name, address, AP email, city, state, and zip are required." });
  }
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [result] = await conn.execute(
      `INSERT INTO companies (name, logo, address1, ap_email, website, city, state, zip, country, terms, discount, notes, approved, denied)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE, FALSE)`, // Added ap_email column
      [name, logo || '', address1, ap_email, website || '', city, state, zip, country, terms || 'Net 30', discount || 0, ''] // Added ap_email value
    );
    console.log(`[POST /register-company] Company ${name} registered with ID: ${result.insertId}`);
    res.status(201).json({ message: "Company registered successfully", companyId: result.insertId, id: result.insertId });
  } catch (err) {
    console.error("Failed to register company:", err);
    if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: "Company with this name already exists." });
    }
    res.status(500).json({ error: "Failed to register company due to server error" });
  } finally {
    if (conn) conn.end();
  }
});

// MODIFIED: /register-user endpoint (Includes shopping cart PDF logic)
app.post("/register-user", async (req, res) => {
  // Added cartItems to destructuring
  const { email, firstName, lastName, phone, password, companyId, companyExists, companyName, apEmail, cartItems } = req.body; 
  const role = "user";
  console.log(`[POST /register-user] Attempting to register user: ${email} for company ID: ${companyId}. Client says company existed: ${companyExists}`);

  if (!email || !firstName || !lastName || !password || !companyId) {
    console.warn("[POST /register-user] Missing required fields for user registration.");
    return res.status(400).json({ error: "Email, first name, last name, password, and company ID are required." });
  }
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [existingUsersByEmail] = await conn.execute("SELECT id FROM users WHERE email = ?", [email]);
    if (existingUsersByEmail.length > 0) {
      console.warn(`[POST /register-user] User with email ${email} already exists.`);
      return res.status(409).json({ error: "User with this email already exists." });
    }

    const [existingUsersByName] = await conn.execute(
        "SELECT id FROM users WHERE LOWER(first_name) = LOWER(?) AND LOWER(last_name) = LOWER(?) AND company_id = ?",
        [firstName, lastName, companyId]
    );
    if (existingUsersByName.length > 0) {
        console.warn(`[POST /register-user] User with name ${firstName} ${lastName} already exists in company ${companyId}.`);
        return res.status(409).json({ error: "User Name Already Exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await conn.execute(
      `INSERT INTO users (email, first_name, last_name, phone, role, password, company_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [email, firstName, lastName, phone || '', role, hashedPassword, companyId]
    );

    // *** SERVER-SIDE CHECK FOR RESPONSE ***
    const [companyRows] = await conn.execute("SELECT approved, terms FROM companies WHERE id = ?", [companyId]);
    const isCompanyApproved = companyRows.length > 0 && companyRows[0].approved === 1;
    const companyTerms = companyRows[0].terms || 'N/A';

    // --- NEW: CART / PDF GENERATION LOGIC ---
    let cartPdfBuffer = null;
    // Check if it's a NEW company registration AND cart data was sent
    if (!companyExists && cartItems && cartItems.length > 0) {
         console.log("[POST /register-user] New company registration with a cart. Generating cart PDF.");
         
         // Adapt cart items to the structure expected by generateOrderHtmlEmail
         const cartItemsForPdf = cartItems.map(item => {
             const netPrice = item.price; 
             const lineTotal = item.quantity * netPrice;
             return {
                 partNo: item.partNo,
                 description: item.description,
                 quantity: item.quantity,
                 netPrice: netPrice,
                 lineTotal: lineTotal,
                 note: item.note
             };
         });

         // Create a dummy order object for the generateOrderHtmlEmail function
         const cartDetailsForEmail = {
             poNumber: 'N/A (Registration)', 
             orderedBy: `${firstName} ${lastName}`, 
             orderedByEmail: email, 
             orderedByPhone: phone, 
             billingAddress: `[BILLING ADDRESS: Not Available at Registration]\nCompany: ${companyName}`, 
             shippingAddress: `[SHIPPING ADDRESS: Not Available at Registration]\nCompany: ${companyName}`, 
             attn: 'N/A', 
             tag: 'N/A', 
             shippingMethod: 'Not Specified', 
             shippingAccountType: 'N/A', 
             carrierAccount: 'N/A', 
             items: cartItemsForPdf,
             terms: companyTerms, 
             thirdPartyDetails: null
         };
         
         // Call the existing function to generate the HTML for the cart
         const originalOrderHtml = generateOrderHtmlEmail(cartDetailsForEmail);
         // Modify the title to clearly indicate it's a registration cart
         const cartHtmlContent = originalOrderHtml.replace('CSE WEBSITE ORDER', 'NEW REGISTRATION SHOPPING CART'); 

         try {
            // NOTE: The generatePdfFromHtml function must be defined elsewhere in server.js
            cartPdfBuffer = await generatePdfFromHtml(cartHtmlContent);
            console.log("Cart PDF generated successfully for registration.");
         } catch (pdfError) {
            console.error("Failed to generate Cart PDF for registration, proceeding without attachment:", pdfError);
         }
    }
    // --- END: CART / PDF GENERATION LOGIC ---


    // Send admin emails based on the client's flag (was it a new company registration flow?)
    if (companyExists) {
        await sendExistingCompanyUserNotificationEmail(companyName, email, firstName, lastName, phone, companyId);
        await sendWelcomeEmailToNewUser(email, firstName, companyName);
    } else {
        // PASS THE NEW pdfBuffer HERE
        await sendRegistrationNotificationEmail(companyName || "New Company", email, firstName, lastName, phone, companyId, role, apEmail, cartPdfBuffer); 
    }

    console.log(`[POST /register-user] User ${email} registered successfully. Server check: isCompanyApproved=${isCompanyApproved}`);
    
    // *** MODIFIED: Respond with the server's authoritative determination ***
    res.status(201).json({ 
        message: "User registered successfully",
        // The client will show the "success/login now" message ONLY if the company was already approved.
        companyExists: isCompanyApproved 
    });
  } catch (err) {
    console.error("Failed to register user:", err);
    res.status(500).json({ error: "Failed to register user due to server error" });
  } finally {
    if (conn) conn.end();
  }
});

app.get("/company-by-name/:name", async (req, res) => {
  const companyName = req.params.name;
  console.log(`[GET /company-by-name/:name] Checking for company: ${companyName}`);
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [companies] = await conn.execute(
      "SELECT id, name FROM companies WHERE LOWER(name) = LOWER(?)",
      [companyName]
    );
    if (companies.length > 0) {
      console.log(`[GET /company-by-name/:name] Company ${companyName} found.`);
      res.json({ exists: true, company: companies[0] });
    } else {
      console.log(`[GET /company-by-name/:name] Company ${companyName} not found.`);
      res.json({ exists: false });
    }
  } catch (err) {
    console.error("Error checking company by name:", err);
    res.status(500).json({ error: "Server error checking company existence" });
  } finally {
    if (conn) conn.end();
  }
});


// --- Company Routes (Admin Only) ---
app.get("/companies", requireAdmin, async (req, res) => {
  console.log("[GET /companies] Fetching all companies (admin access).");
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [companies] = await conn.execute("SELECT id, name, logo, address1, ap_email, website, city, state, zip, country, terms, discount, notes, approved, denied, created_at FROM companies ORDER BY name ASC"); // Added ap_email
    console.log(`[GET /companies] Found ${companies.length} companies.`);
    res.json(companies);
  } catch (err) {
    console.error("Failed to retrieve companies:", err);
    res.status(500).json({ error: "Failed to retrieve companies" });
  } finally {
    if (conn) conn.end();
  }
});

// MODIFIED: /edit-company endpoint
app.post("/edit-company", requireAdmin, async (req, res) => {
  const { id, name, address1, ap_email, website, city, state, zip, country, terms, discount, approved, denied, logo, notes } = req.body; // Added ap_email
  console.log(`[POST /edit-company] Editing company ID: ${id}`);
  if (!id) {
    console.warn("[POST /edit-company] Company ID is required for update.");
    return res.status(400).json({ error: "Company ID is required for update." });
  }

  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);

    // Fetch current company status to detect changes for email notification
    const [currentCompanyRows] = await conn.execute("SELECT approved FROM companies WHERE id = ?", [id]);
    const currentApprovedStatus = currentCompanyRows.length > 0 ? currentCompanyRows[0].approved : null;

    const fieldsToUpdate = [];
    const values = [];

    if (name !== undefined) { fieldsToUpdate.push("name = ?"); values.push(name); }
    if (address1 !== undefined) { fieldsToUpdate.push("address1 = ?"); values.push(address1); }
    if (ap_email !== undefined) { fieldsToUpdate.push("ap_email = ?"); values.push(ap_email); } // Added ap_email
    if (website !== undefined) { fieldsToUpdate.push("website = ?"); values.push(website); }
    if (city !== undefined) { fieldsToUpdate.push("city = ?"); values.push(city); }
    if (state !== undefined) { fieldsToUpdate.push("state = ?"); values.push(state); }
    if (zip !== undefined) { fieldsToUpdate.push("zip = ?"); values.push(zip); }
    if (country !== undefined) { fieldsToUpdate.push("country = ?"); values.push(country); }
    if (terms !== undefined) { fieldsToUpdate.push("terms = ?"); values.push(terms); }
    if (discount !== undefined) { fieldsToUpdate.push("discount = ?"); values.push(discount); }
    if (logo !== undefined) { fieldsToUpdate.push("logo = ?"); values.push(logo); }
    if (notes !== undefined) { fieldsToUpdate.push("notes = ?"); values.push(notes); }
    if (approved !== undefined) { fieldsToUpdate.push("approved = ?"); values.push(approved); }
    if (denied !== undefined) { fieldsToUpdate.push("denied = ?"); values.push(denied); }

    if (fieldsToUpdate.length === 0) {
      console.warn("[POST /edit-company] No fields provided for update.");
      return res.status(400).json({ error: "No fields provided for update." });
    }

    const query = `UPDATE companies SET ${fieldsToUpdate.join(', ')} WHERE id = ?`;
    values.push(id);

    console.log(`[POST /edit-company] Updating company ID ${id}. Received approved: ${approved}, denied: ${denied}`); // NEW LOG
    console.log(`[POST /edit-company] SQL Query: ${query}`); // NEW LOG
    console.log(`[POST /edit-company] SQL Params:`, values); // NEW LOG

    await conn.execute(query, values);

    // Send approval email if status changed to approved
    if (approved === true && currentApprovedStatus === false) {
        console.log(`[POST /edit-company] Company ID ${id} approved. Attempting to send approval email.`); // NEW LOG
        await sendCompanyApprovalEmail(id);
    }
    console.log(`[POST /edit-company] Company ID ${id} updated successfully.`);
    res.json({ message: "Company updated" });
  } catch (err) {
    console.error("Failed to update company:", err);
    res.status(500).json({ error: "Failed to update company" });
  } finally {
    if (conn) conn.end();
  }
});

app.post('/add-company', requireAdmin, async (req, res) => {
  const {
    name, logo, address1, city, state, zip, country, terms, discount
  } = req.body;
  console.log(`[POST /add-company] Adding new company: ${name}`);
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [result] = await conn.execute(`
      INSERT INTO companies (name, logo, address1, city, state, zip, country, terms, discount, notes, approved, denied)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE, FALSE)
    `, [name, logo || '', address1, city, state, zip, country || 'USA', terms || 'Net 30', discount || 0, '']);
    console.log(`[POST /add-company] Company ${name} created with ID: ${result.insertId}`);
    res.status(200).json({ message: "Company created", id: result.insertId });
  } catch (err) {
    console.error("Failed to create company:", err);
    res.status(500).json({ error: "Failed to create company" });
  } finally {
    if (conn) conn.end();
  }
});

app.post("/delete-company", requireAdmin, async (req, res) => {
  const { id } = req.body;
  console.log(`[POST /delete-company] Deleting company ID: ${id}`);
  let conn;
  try {
    if (parseInt(id, 10) === 1) {
        console.warn("[POST /delete-company] Attempted to delete protected Company ID 1.");
        return res.status(403).json({ error: "This company cannot be deleted." });
    }
    conn = await mysql.createConnection(dbConnectionConfig);
    await conn.beginTransaction();

    await conn.execute("DELETE FROM users WHERE company_id = ?", [id]);
    console.log(`[POST /delete-company] Deleted users associated with company ID: ${id}`);

    await conn.execute("DELETE FROM shipto_addresses WHERE company_id = ?", [id]);
    console.log(`[POST /delete-company] Deleted shipping addresses associated with company ID: ${id}`);

    await conn.execute("DELETE FROM companies WHERE id = ?", [id]);
    console.log(`[POST /delete-company] Deleted company with ID: ${id}`);

    await conn.commit();
    res.json({ message: "Company and associated data deleted" });
  } catch (err) {
    if (conn) {
      await conn.rollback();
      console.error("Transaction rolled back due to error.");
    }
    console.error("Failed to delete company:", err);
    res.status(500).json({ error: "Failed to delete company" });
  } finally {
    if (conn) conn.end();
  }
});

app.post("/add-user", requireAdmin, async (req, res) => { // Added requireAdmin middleware
  const { email, firstName, lastName, phone, role, password, companyId } = req.body;
  console.log(`[POST /add-user] Adding user ${email} to company ID: ${companyId}`);
  if (!email || !companyId || !password) {
    console.warn("[POST /add-user] Missing required fields for adding user.");
    return res.status(400).json({ error: "Email, password, and companyId are required." });
  }
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const hashedPassword = await bcrypt.hash(password, 10);
    await conn.execute(
      `INSERT INTO users (email, first_name, last_name, phone, role, password, company_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [email, firstName, lastName, phone || '', role, hashedPassword, companyId]
    );
    console.log(`[POST /add-user] User ${email} added successfully.`);
    res.json({ message: "User added" });
  }
   catch (err) {
    console.error("Failed to add user:", err);
    res.status(500).json({ error: "Failed to add user" });
  } finally {
    if (conn) conn.end();
  }
});

app.post("/edit-user", requireAdmin, async (req, res) => {
  // MODIFIED: Destructure companyId from the request body
  const { id, email, firstName, lastName, phone, role, password, companyId } = req.body;
  console.log(`[POST /edit-user] Editing user ID: ${id}. New Company ID: ${companyId}`); // Updated log
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      // MODIFIED: Added company_id to the UPDATE statement
      await conn.execute(
        `UPDATE users SET email = ?, first_name = ?, last_name = ?, phone = ?, role = ?, password = ?, company_id = ? WHERE id = ?`,
        [email, firstName, lastName, phone || '', role, hashedPassword, companyId, id]
      );
    } else {
      // MODIFIED: Added company_id to the UPDATE statement
      await conn.execute(
        `UPDATE users SET email = ?, first_name = ?, last_name = ?, phone = ?, role = ?, company_id = ? WHERE id = ?`,
        [email, firstName, lastName, phone || '', role, companyId, id]
      );
    }
    console.log(`[POST /edit-user] User ID ${id} updated successfully.`);
    res.json({ message: "User updated" });
  } catch (err) {
    console.error("Failed to update user:", err);
    res.status(500).json({ error: "Failed to update user" });
  } finally {
    if (conn) conn.end();
  }
});

app.post("/delete-user", requireAdmin, async (req, res) => {
  const { id } = req.body;
  console.log(`[POST /delete-user] Deleting user ID: ${id}`);
  if (!id) {
    console.warn("[POST /delete-user] Missing user ID for deletion.");
    return res.status(400).json({ error: "Missing user ID" });
  }
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    await conn.execute("DELETE FROM users WHERE id = ?", [id]);
    console.log(`[POST /delete-user] User ID ${id} deleted successfully.`);
    res.json({ message: "User deleted" });
  } finally {
    if (conn) conn.end();
  }
});


app.get("/company-users/:companyId", requireAdmin, async (req, res) => {
  const { companyId } = req.params;
  console.log(`[GET /company-users/:companyId] Fetching users for company ID: ${companyId}`);
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [users] = await conn.execute("SELECT id, email, first_name, last_name, phone, role, created_at FROM users WHERE company_id = ?", [companyId]);
    console.log(`[GET /company-users/:companyId] Found ${users.length} users for company ID: ${companyId}`);
    res.json(users);
  } catch (err) {
    console.error("Failed to retrieve users:", err);
    res.status(500).json({ error: "Failed to retrieve users" });
  } finally {
    if (conn) conn.end();
  }
});

// --- Ship To Addresses Routes ---

app.get("/api/shipto/:companyId", authorizeCompanyAccess, async (req, res) => {
    const { companyId } = req.params;
    console.log(`[GET /api/shipto/:companyId] Fetching ship-to addresses for company ID: ${companyId}`);
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [addresses] = await conn.execute("SELECT id, company_id, name, company_name, address1, city, state, zip, country, is_default, carrier_account, created_at FROM shipto_addresses WHERE company_id = ?", [companyId]);
        console.log(`[GET /api/shipto/:companyId] Found ${addresses.length} ship-to addresses.`);
        res.json(addresses);
    }
    catch (err) {
        console.error("Error fetching ship-to addresses:", err);
        res.status(500).json({ error: "Failed to retrieve ship-to addresses" });
    }
    finally {
        if (conn) conn.end();
    }
});

app.post("/api/shipto", authorizeCompanyAccess, async (req, res) => {
    const { companyId, name, company_name, address1, city, state, zip, country, is_default, carrier_account } = req.body; // Added carrier_account
    console.log(`[POST /api/shipto] Adding ship-to address for company ID: ${companyId}`);
    if (!companyId || !name || !address1 || !city || !state || !zip) {
        console.warn("[POST /api/shipto] Missing required fields for adding ship-to address.");
        return res.status(400).json({ error: "Missing required fields (Company ID, Contact Name, Address, City, State, Zip)." });
    }
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        if (is_default) {
             console.log(`[POST /api/shipto] Setting new address as default, unsetting others for company ID: ${companyId}`);
             await conn.execute(
                `UPDATE shipto_addresses SET is_default = 0 WHERE company_id = ?`,
                [companyId]
            );
        }
        const [result] = await conn.execute(
            `INSERT INTO shipto_addresses (company_id, name, company_name, address1, city, state, zip, country, is_default, carrier_account)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, // Added carrier_account column
            [companyId, name, company_name || null, address1, city, state, zip, country, is_default ? 1 : 0, carrier_account || null] // Added carrier_account value
        );
        console.log(`[POST /api/shipto] Address added with ID: ${result.insertId}`);
        res.status(201).json({ id: result.insertId, message: "Address added successfully" });
    } catch (err) {
        console.error("Error adding ship-to address:", err);
        res.status(500).json({ error: "Failed to add ship-to address" });
    } finally {
        if (conn) conn.end();
    }
});

app.put("/api/shipto/:addressId", authorizeCompanyAccess, async (req, res) => {
    const { addressId } = req.params;
    const { name, company_name, address1, city, state, zip, country, carrier_account } = req.body; // Added carrier_account
    console.log(`[PUT /api/shipto/:addressId] Updating ship-to address ID: ${addressId}`);
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        await conn.execute(
            `UPDATE shipto_addresses SET name = ?, company_name = ?, address1 = ?, city = ?, state = ?, zip = ?, country = ?, carrier_account = ? WHERE id = ?`, // Added carrier_account update
            [name, company_name || null, address1, city, state, zip, country, carrier_account || null, addressId] // Added carrier_account value
        );
        console.log(`[PUT /api/shipto/:addressId] Address ID ${addressId} updated successfully.`);
        res.json({ message: "Address updated successfully" });
    } catch (err) {
        console.error("Error updating ship-to address:", err);
        res.status(500).json({ error: "Failed to update ship-to address" });
    } finally {
        if (conn) conn.end();
    }
});

// ENDPOINT: Update carrier_account for a specific shipto_address
app.put("/api/shipto/:addressId/update-carrier-account", authorizeCompanyAccess, async (req, res) => {
    const { addressId } = req.params;
    const { carrierAccount } = req.body; // Expecting carrierAccount in the body
    console.log(`[PUT /api/shipto/:addressId/update-carrier-account] Updating carrier account for address ID: ${addressId}`);
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        await conn.execute(
            `UPDATE shipto_addresses SET carrier_account = ? WHERE id = ?`,
            [carrierAccount || null, addressId] // Set to null if carrierAccount is empty/undefined
        );
        console.log(`[PUT /api/shipto/:addressId/update-carrier-account] Carrier account for address ID ${addressId} updated.`);
        res.json({ message: "Carrier account updated successfully for shipping address." });
    } catch (err) {
        console.error("Error updating carrier account for ship-to address:", err);
        res.status(500).json({ error: "Failed to update carrier account for shipping address." });
    } finally {
        if (conn) conn.end();
    }
});


app.put("/api/shipto/:addressId/set-default", authorizeCompanyAccess, async (req, res) => {
    const { addressId } = req.params;
    console.log(`[PUT /api/shipto/:addressId/set-default] Setting default for address ID: ${addressId}`);
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);

        const [addressRows] = await conn.execute("SELECT company_id FROM shipto_addresses WHERE id = ?", [addressId]);

        if (addressRows.length === 0) {
            console.warn(`[PUT /api/shipto/:addressId/set-default] Address ID ${addressId} not found.`);
            return res.status(404).json({ error: "Address not found." });
        }

        const targetCompanyId = addressRows[0].company_id;
        console.log(`[PUT /api/shipto/:addressId/set-default] Target Company ID: ${targetCompanyId}`);

        await conn.beginTransaction();

        console.log(`[PUT /api/shipto/:addressId/set-default] Unsetting current default for company ID: ${targetCompanyId}`);
        await conn.execute(
            `UPDATE shipto_addresses SET is_default = 0 WHERE company_id = ? AND id != ?`,
            [targetCompanyId, addressId]
        );

        console.log(`[PUT /api/shipto/:addressId/set-default] Setting address ID ${addressId} as default.`);
        await conn.execute(
            `UPDATE shipto_addresses SET is_default = 1 WHERE id = ?`,
            [addressId]
        );

        await conn.commit();
        console.log(`[PUT /api/shipto/:addressId/set-default] Default shipping address updated successfully.`);
        res.json({ message: "Default shipping address updated successfully." });

    } catch (err) {
        if (conn) {
            await conn.rollback();
            console.error("[PUT /api/shipto/:addressId/set-default] Transaction rolled back due to error.");
        }
        console.error("Error setting default shipping address:", err);
        res.status(500).json({ error: "Failed to set default shipping address." });
    } finally {
        if (conn) conn.end();
    }
});

// MODIFIED: The delete endpoint for shipto addresses
app.delete("/api/shipto/:addressId", requireAuth, async (req, res) => { // Use requireAuth for basic login check
    const { addressId } = req.params;
    console.log(`[DELETE /api/shipto/:addressId] Deleting address ID: ${addressId}`);

    // Get user details from session
    const userRole = req.session.user.role;
    const userCompanyId = req.session.user.companyId;

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);

        // For non-admins, verify they own the address before deleting
        if (userRole !== 'admin') {
            const [rows] = await conn.execute("SELECT company_id FROM shipto_addresses WHERE id = ?", [addressId]);
            if (rows.length === 0) {
                return res.status(404).json({ error: "Address not found." });
            }
            const addressCompanyId = rows[0].company_id;

            // Check if the address's company matches the user's company
            if (addressCompanyId !== userCompanyId) {
                console.warn(`[DELETE /api/shipto/:addressId] Forbidden: User company ${userCompanyId} does not match address company ${addressCompanyId}.`);
                return res.status(403).json({ error: "Forbidden: You do not have permission to delete this address." });
            }
        }

        // If the user is an admin, or if the non-admin passed the check, proceed with deletion
        await conn.execute("DELETE FROM shipto_addresses WHERE id = ?", [addressId]);
        console.log(`[DELETE /api/shipto/:addressId] Address ID ${addressId} deleted successfully.`);
        res.json({ message: "Address deleted successfully" });
    } catch (err) {
        console.error(`[DELETE /api/shipto/:addressId] Error deleting address ID ${addressId}:`, err);
        res.status(500).json({ error: "Failed to delete address due to a server error." });
    } finally {
        if (conn) conn.end();
    }
});


// NEW: Admin Settings Routes
app.get("/admin/settings", requireAdmin, async (req, res) => {
    console.log("[GET /admin/settings] Fetching admin settings.");
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [rows] = await conn.execute("SELECT po_email, registration_email FROM admin_settings WHERE id = 1");
        if (rows.length > 0) {
            console.log("[GET /admin/settings] Admin settings found.");
            res.json(rows[0]);
        } else {
            console.log("[GET /admin/settings] No admin settings found, returning defaults.");
            res.json({ po_email: "", registration_email: "" });
        }
    } catch (err) {
        console.error("Error fetching admin settings:", err);
        res.status(500).json({ error: "Failed to retrieve admin settings" });
    } finally {
        if (conn) conn.end();
    }
});

app.post("/admin/settings", requireAdmin, async (req, res) => {
    const { po_email, registration_email } = req.body;
    console.log(`[POST /admin/settings] Saving admin settings: PO Email=${po_email}, Reg Email=${registration_email}`);
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [existing] = await conn.execute("SELECT id FROM admin_settings WHERE id = 1");
        if (existing.length > 0) {
            await conn.execute(
                "UPDATE admin_settings SET po_email = ?, registration_email = ? WHERE id = 1",
                [po_email, registration_email]
            );
            console.log("[POST /admin/settings] Admin settings updated.");
        } else {
            await conn.execute(
                "INSERT INTO admin_settings (id, po_email, registration_email) VALUES (1, ?, ?)",
                [po_email, registration_email]
            );
            console.log("[POST /admin/settings] Admin settings inserted.");
        }
        res.json({ message: "Settings saved successfully" });
    } catch (err) {
        console.error("Error saving admin settings:", err);
        res.status(500).json({ error: "Failed to save admin settings" });
    } finally {
        if (conn) conn.end();
    }
});

app.post("/admin/send-approval-email", requireAdmin, async (req, res) => {
    let conn;
    try {
        const { companyId } = req.body;
        console.log(`[POST /admin/send-approval-email] Attempting to send approval email for company ID: ${companyId}`);

        if (!companyId) {
            console.warn("[POST /admin/send-approval-email] Company ID is required.");
            return res.status(400).json({ error: "Company ID is required." });
        }

        conn = await mysql.createConnection(dbConnectionConfig);

        const [companyRows] = await conn.execute("SELECT name, approved FROM companies WHERE id = ?", [companyId]);
        if (companyRows.length === 0) {
            console.warn(`[POST /admin/send-approval-email] Company ID ${companyId} not found.`);
            return res.status(404).json({ error: "Company not found." });
        }
        const company = companyRows[0];

        if (!company.approved) {
            console.warn(`[POST /admin/send-approval-email] Company ID ${companyId} is not approved. Cannot send approval email.`);
            return res.status(400).json({ error: "Company is not yet approved. Cannot send approval email." });
        }

        const [userRows] = await conn.execute("SELECT email, first_name FROM users WHERE company_id = ? LIMIT 1", [companyId]);
        if (userRows.length === 0) {
            console.warn(`[POST /admin/send-approval-email] No users found for company ID ${companyId}.`);
            return res.status(404).json({ error: "No users found for this company to send an email to." });
        }
        const userEmail = userRows[0].email;
        const userName = userRows[0].first_name;

        if (!process.env.MAILTRAP_API_KEY) {
            console.error("MAILTRAP_API_KEY environment variable is not set. Cannot send email.");
            return res.status(500).json({ error: "Email sender not configured on server." });
        }

        const mailOptions = {
            from: EMAIL_FROM, // Changed to use the desired FROM address

            to: userEmail,
            replyTo: "OrderDesk@ChicagoStainless.com", // Replies from user should go to OrderDesk
            subject: `Your Company Registration for ${company.name} Has Been Approved!`,
            html: `
                <p>Dear ${userName},</p>
                <p>We are pleased to inform you that your company registration for <strong>${company.name}</strong> has been officially approved!</p>
                <p>You can now log in and place orders.</p>
                <p>Login Page: <a href="${process.env.FRONTEND_URL || 'YOUR_FRONTEND_URL_HERE'}">${process.env.FRONTEND_URL || 'YOUR_FRONTEND_URL_HERE'}</a></p>
                <p>If you have any questions, please do not hesitate to contact us.</p>
                <p>Thank Thank you for choosing Chicago Stainless Equipment, Inc.</p>
                <p>Sincerely,</p>
                <p>The Chicago Stainless Equipment Team</p>
            `,
        };

        mailtrap.send(toMailtrapOptions(mailOptions))
            .then(() => {
                console.log("Company approval email sent.");
                res.status(200).json({ message: "Approval email sent successfully to the user!" });
            })
            .catch(error => {
                console.error("Error sending company approval email:", error.message);
                res.status(500).json({ error: "Failed to send approval email." });
            });

    } catch (err) {
        console.error("Error in /admin/send-approval-email:", err);
        res.status(500).json({ error: "Server error while sending approval email." });
    } finally {
        if (conn) conn.end();
    }
});

    // Helper function to generate HTML for the order email
    function generateOrderHtmlEmail(orderData) {
     let totalQuantity = 0;
     let totalPrice = 0;

     orderData.items.forEach(item => {
        totalQuantity += Number(item.quantity);
        totalPrice += Number(item.lineTotal);
     });
     // NEW: Format the current date and time
     const currentDate = new Date().toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        timeZone: 'America/New_York'
    });
    // Use a single date object for consistency
    const now = new Date();

    // Get the time string separately
    const timeString = now.toLocaleString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
        timeZone: 'America/New_York'
    });

    // Manually determine and append the timezone abbreviation
    // DST in the US is roughly from March to November.
    const month = now.getMonth(); // 0 = Jan, 11 = Dec
    const timezoneAbbr = (month > 1 && month < 10) ? 'EDT' : 'EST'; 

    const currentTime = `${timeString} ${timezoneAbbr}`;

    // Determine if carrierAccount is present and not just whitespace
    const hasCarrierAccount = orderData.carrierAccount && orderData.carrierAccount.trim() !== '';

    let itemsHtml = orderData.items.map(item => {
        // Apply the same formatting for "**" as in the frontend (only first instance)
        let formattedDescription = item.description ? item.description.replace('**', '<br>**') : '';
        return `
            <tr>
                <td style="border: 1px solid #ccc; padding: 8px; text-align: center; color: #000000; vertical-align: top;">${item.quantity}</td>
                <td style="border: 1px solid #ccc; padding: 8px; text-align: left; font-family: Arial, sans-serif; font-size: 14px; white-space: pre-wrap; word-wrap: break-word;"><strong>${item.partNo}</strong><br>${item.description || ''}${item.note ? `<div style="height: 7px;"></div><small>${item.note.replace(/\n/g, '<br>')}</small>` : ''}</td>
                <td style="border: 1px solid #ccc; padding: 8px; text-align: right; width: 15%; color: #000000; vertical-align: top;">$${item.netPrice.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
                <td style="border: 1px solid #ccc; padding: 8px; text-align: right; color: #000000; vertical-align: top;">$${item.lineTotal.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
            </tr>
        `;
    }).join('');

    // Debug log for shippingAccountType
    console.log("generateOrderHtmlEmail: Checking shippingAccountType:", orderData.shippingAccountType);
    console.log("generateOrderHtmlEmail: Checking thirdPartyDetails:", JSON.stringify(orderData.thirdPartyDetails, null, 2));

    // Conditional country display logic
    const thirdParty = orderData.thirdPartyDetails;
    let thirdPartyCountryHtml = '';
    if (thirdParty && thirdParty.third_party_country &&
        !["USA", "United States", "United States of America"].includes(thirdParty.third_party_country.trim())) {
        thirdPartyCountryHtml = `<p style="margin: 0; font-size: 12px; line-height: 1.4;">${thirdParty.third_party_country}</p>`;
    }

    // Determine if "RUSH" indicator is needed
    const shippingMethodLower = orderData.shippingMethod.toLowerCase();
    const isRush = shippingMethodLower.includes("next day air") ||
                   shippingMethodLower.includes("saturday") ||
                   shippingMethodLower.includes("overnight");

    const rushImageHtml = ''; // Set to empty string to disable the rush image. The 'isRush' constant is still used for highlighting the 'Ship Via' text.


    // Determine carrier logo
    let carrierLogoHtml = '';
    const carrierLogoBaseUrl = 'https://www.chicagostainless.com/graphics/stamps/';
    // Adjusted max-height for better fit, added absolute positioning and z-index
    // Positioned relative to the main container, aligned with the right edge of the table.
    // Top position is adjusted to be between the Ship To box and Order Summary.
    const carrierLogoStyle = 'max-height: 50px; width: auto; display: block; position: absolute; top: 325px; right: 20px; z-index: 100;';

    if (shippingMethodLower.includes("fedex")) {
        carrierLogoHtml = `<img src="${carrierLogoBaseUrl}fedex.png" alt="FedEx" style="${carrierLogoStyle}">`;
    } /*else if (shippingMethodLower.includes("ups")) {
        carrierLogoHtml = `<img src="${carrierLogoBaseUrl}ups.png" alt="UPS" style="${carrierLogoStyle}">`;
    }*/ else if (shippingMethodLower.includes("dhl")) {
        carrierLogoHtml = `<img src="${carrierLogoBaseUrl}dhl.png" alt="DHL" style="${carrierLogoStyle}">`;
    }

    // Conditional styling for rush order - removed padding
    const shipViaStyle = isRush ? 'background-color: yellow; border-radius: 3px;' : '';


    return `
        <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; color: #000000; position: relative;">

            <table style="width: 100%; border-collapse: collapse; margin-bottom: 5px;">
                <tr>
                    <td style="width: 95px; text-align: left; vertical-align: middle; padding: 0;">
                        <img src="${CSE_LOGO_SRC}" alt="CSE Logo" style="width: 95px; height: auto; display: block;">
                    </td>
                    <td style="text-align: center; vertical-align: middle; padding: 0;">
                        <h1 style="font-size: 22px; color: #000000; margin: 0; padding: 0; line-height: 1.2;">CSE WEBSITE ORDER</h1>
                    </td>
                    <td style="width: 95px; text-align: right; vertical-align: middle; padding: 0;">
                        <div style="font-size: 12px; color: #000000; line-height: 1.2;">
                            <p style="margin: 0;">${currentDate}</p>
                            <p style="margin: 0;">${currentTime}</p>
                        </div>
                    </td>
                </tr>
            </table>

            <hr style="border: none; border-top: 1px solid #ccc; margin: 5px 0 10px 0;">

            <table style="width: 100%; border-collapse: collapse; margin-bottom: 5px;">
                <tr>
                    <td style="width: 50%; text-align: left; vertical-align: middle; padding: 0;">
                        <p style="font-size: 18px; font-weight: bold; color: #000000; margin: 0;"><span style="background-color: yellow; padding: 2px 5px; border-radius: 3px;"><strong>PO#:</strong> ${orderData.poNumber}</span></p>
                    </td>
                    <td style="width: 50%; padding: 0;"></td> </tr>
            </table>

            <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                <tr>
                    <td style="width: 50%; vertical-align: top; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box;">
                        <h2 style="margin-top: 0; color: #000000; font-size: 16px; font-weight: bold; margin-bottom: 5px; background-color: #e0e0e0; padding: 5px;"><strong>Bill To:</strong></h2>
                        <p style="white-space: pre-wrap; margin: 0; font-size: 12px; line-height: 1.4; color: #000000;">${orderData.billingAddress}</p>
                        <p style="margin: 10px 0; font-size: 12px; color: #000000;"><strong>Terms:</strong> ${orderData.terms || 'N/A'}</p>
                        <h3 style="margin: 10px 0 5px 0; font-size: 14px; color: #000000; background-color: #e0e0e0; padding: 5px;"><strong>Ordered By:</strong></h3>
                        <p style="margin: 0; font-size: 12px; line-height: 1.4; color: #000000;">
                            ${orderData.orderedBy}<br>
                            ${orderData.orderedByEmail}<br>
                            ${orderData.orderedByPhone && orderData.orderedByPhone.trim() !== '' ? `Phone: ${orderData.orderedByPhone}` : ''}
                        </p>
                    </td>
                    <td style="width: 50%; vertical-align: top; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box;">
                        <h2 style="margin-top: 0; color: #000000; font-size: 16px; font-weight: bold; margin-bottom: 5px; background-color: #e0e0e0; padding: 5px;"><strong>Ship To:</strong></h2>
                        <p style="white-space: pre-wrap; margin: 0; font-size: 12px; line-height: 1.4; color: #000000;">${orderData.shippingAddress}</p>
                        <p style="margin: 7px 0; font-size: 12px; color: #000000;"><strong>ATTN:</strong> ${orderData.attn || ''}</p>
                        <p style="margin: 7px 0; font-size: 12px; color: #000000;"><strong>TAG#:</strong> ${orderData.tag || ''}</p>
                        <p style="margin: 7px 0; font-size: 12px; color: #000000;"><span style="${shipViaStyle}"><strong>Ship Via:</strong> ${orderData.shippingMethod} (${orderData.shippingAccountType})</span></p>
                        ${hasCarrierAccount ? `<p style="margin: 7px 0 0 0; font-size: 12px; color: #000000;"><strong>Carrier Account#:</strong> ${orderData.carrierAccount}</p>` : ''}
                    </td>
                </tr>
            </table>

            ${rushImageHtml} <h2 style="color: #000000; font-size: 20px; margin: 0; margin-bottom: 10px;">Order Summary</h2>
            ${carrierLogoHtml} <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                <thead>
                    <tr>
                        <th style="border: 1px solid #ccc; padding: 8px; background-color: #e0e0e0; text-align: center; color: #000000;">Qty</th>
                        <th style="border: 1px solid #ccc; padding: 8px; background-color: #e0e0e0; color: #000000;">Part Number / Description / Note</th>
                        <th style="border: 1px solid #ccc; padding: 8px; background-color: #e0e0e0; text-align: right; width: 15%; color: #000000;">Unit Price</th>
                        <th style="border: 1px solid #ccc; padding: 8px; background-color: #e0e0e0; text-align: right; color: #000000;">Total</th>
                    </tr>
                </thead>
                <tbody>
                    ${itemsHtml}
                </tbody>
            </table>
            <p style="font-weight: bold; text-align: right; margin-bottom: 5px; color: #000000;">Item Count: ${totalQuantity}</p>
            <p style="font-weight: bold; text-align: right; margin-top: 0; color: #000000;">Total Price: $${totalPrice.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</p>

            <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ccc; color: #000000; font-size: 10px;">
                <strong>Chicago Stainless Equipment, Inc.</strong><br>
                1280 SW 34th St, Palm City, FL 34990 USA<br>
                772-781-1441
            </div>
        </div>
    `;
}

// MODIFIED: Function to generate PDF from HTML content with retry logic
async function generatePdfFromHtml(htmlContent) {
    const MAX_RETRIES = 3;
    const RETRY_DELAY_MS = 2000;

    for (let retry = 1; retry <= MAX_RETRIES; retry++) {
        let browser;
        let userDataDir;
        try {
            userDataDir = path.join(os.tmpdir(), `puppeteer_user_data_${uuidv4()}`);
            await fs.mkdir(userDataDir, { recursive: true });
            console.log(`[PDF Gen] Attempt ${retry}/${MAX_RETRIES}: Starting browser. Temp dir: ${userDataDir}`);

            browser = await puppeteer.launch({
                args: [...chromium.args, '--disable-gpu', '--disable-dev-shm-usage', '--no-sandbox', '--disable-setuid-sandbox'],
                executablePath: await chromium.executablePath(),
                headless: chromium.headless,
                ignoreHTTPSErrors: true,
                userDataDir: userDataDir,
                timeout: 30000 // Global launch timeout
            });
            const page = await browser.newPage();
            page.setDefaultTimeout(30000); // Navigation/Wait timeout

            await page.setContent(htmlContent, {
                waitUntil: 'networkidle0'
            });

            const pdfBuffer = await page.pdf({
                format: 'Letter',
                printBackground: true,
                margin: {
                    top: '0.2in',
                    right: '0.3in',
                    bottom: '0.3in',
                    left: '0.3in'
                }
            });
            
            await browser.close();
            browser = null; // Mark as closed
            
            console.log(`[PDF Gen] Attempt ${retry}/${MAX_RETRIES}: Initial PDF generated successfully.`);

            // === Manually add page numbers using pdf-lib ===
            const pdfDoc = await PDFDocument.load(pdfBuffer);
            const totalPages = pdfDoc.getPageCount();
            const helveticaFont = await pdfDoc.embedFont(StandardFonts.Helvetica);
            const pages = pdfDoc.getPages();

            for (let i = 0; i < totalPages; i++) {
                const currentPage = pages[i];
                const { width, height } = currentPage.getSize();
                const text = `Page ${i + 1} of ${totalPages}`;
                const textSize = 10;
                const textWidth = helveticaFont.widthOfTextAtSize(text, textSize);

                currentPage.drawText(text, {
                    x: width / 2 - textWidth / 2, // Center horizontally
                    y: 15,                        // 15 points from the bottom
                    size: textSize,
                    font: helveticaFont,
                    color: rgb(0.33, 0.33, 0.33), // A dark gray color
                });
            }

            const finalPdfBytes = await pdfDoc.save();
            console.log(`[PDF Gen] Attempt ${retry}/${MAX_RETRIES}: Final PDF with page numbers created.`);
            
            return Buffer.from(finalPdfBytes);

        } catch (error) {
            console.error(`[PDF Gen] Attempt ${retry}/${MAX_RETRIES} FAILED:`, error.message);
            if (retry === MAX_RETRIES) {
                // Last attempt failed, throw the final error
                console.error("[PDF Gen] All retries failed. PDF generation definitively failed.");
                throw new Error("Failed to generate PDF after multiple retries.");
            }
            // Delay before retrying
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS));
        } finally {
            if (browser) {
                // Ensure browser is closed if it crashed before the close() call
                try { await browser.close(); } catch (e) { console.error("[PDF Gen] Error closing stalled browser:", e); }
            }
            if (userDataDir) {
                try {
                    await fs.rm(userDataDir, { recursive: true, force: true });
                    // console.log(`[PDF Gen] Cleaned up temporary user data directory: ${userDataDir}`); // Commenting out for cleaner logs
                } catch (cleanupError) {
                    console.error(`[PDF Gen] Error cleaning up user data directory ${userDataDir}:`, cleanupError);
                }
            }
        }
    }
}


app.post("/submit-order", requireAuth, async (req, res) => {
    // Destructure new fields: orderedByEmail, orderedByPhone, shippingAccountType, thirdPartyDetails
    const { poNumber, orderedBy, orderedByEmail, orderedByPhone, billingAddress, shippingAddress, shippingAddressId, attn, tag, shippingMethod, shippingAccountType, carrierAccount, thirdPartyDetails, items } = req.body;
    const userId = req.session.user.id;
    const companyId = req.session.user.companyId;
    // userEmail and userPhone from session are no longer primarily used for the PDF content
    // but can be kept for other logging/database purposes if needed.

    console.log("Received order submission request with body:", JSON.stringify(req.body, null, 2));
    // NEW: Debugging logs for shippingMethod and thirdPartyDetails
    console.log("submit-order: Received shippingMethod:", shippingMethod);
    console.log("submit-order: Received shippingAccountType:", shippingAccountType); // Added for debugging
    console.log("submit-order: Received thirdPartyDetails:", JSON.stringify(thirdPartyDetails, null, 2));


    if (!orderedByEmail || !poNumber || !billingAddress || !shippingAddress || !shippingMethod || !items || items.length === 0) {
        console.error("Validation Error: Missing fields.", { 
            email: !!orderedByEmail, 
            po: !!poNumber, 
            bill: !!billingAddress, 
            ship: !!shippingAddress, 
            method: !!shippingMethod, 
            cartSize: items ? items.length : 0 
        });
        return res.status(400).json({ error: "Missing required order fields or empty cart." });
    }

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        await conn.beginTransaction();

        // Fetch company details to check approval status and apply discount
        const [companyRows] = await conn.execute("SELECT id, name, discount, approved, terms FROM companies WHERE id = ?", [companyId]); // Fetch terms here
        if (companyRows.length === 0) {
            await conn.rollback();
            console.error(`[submit-order] Company not found in DB for ID: ${companyId}. User session might be stale or invalid.`);
            return res.status(404).json({ error: "Company not found for the logged-in user." });
        }
        const company = companyRows[0];

        // IMPORTANT: Check company approval status before proceeding with order
        if (!company.approved) {
            await conn.rollback();
            console.warn(`[submit-order] Order submission rejected: Company ID ${companyId} (${company.name}) is not approved.`);
            return res.status(403).json({ error: "Your company's registration is awaiting approval. Please allow 24-48 hours for review. You will receive an email notification once approved." });
        }
        console.log(`[submit-order] Company ID ${companyId} (${company.name}) is approved. Proceeding with order submission.`);

        // MODIFICATION: The frontend now sends the final, pre-calculated net price.
        // This backend logic will no longer apply a second discount. It will use the provided price as the final net price.
        let totalOrderPrice = 0;
        const orderItemsWithCalculatedPrices = items.map(item => {
            const netPrice = item.price; // This is the correct net price from the frontend.
            const lineTotal = item.quantity * netPrice;
            totalOrderPrice += lineTotal;
            return {
                partNo: item.partNo,
                description: item.description,
                quantity: item.quantity,
                listPrice: null, // We don't have the original list price, so we'll nullify it to avoid confusion.
                netPrice: netPrice,
                lineTotal: lineTotal,
                note: item.note
            };
        });

        // Determine the carrier account to save based on shippingAccountType
        let finalCarrierAccountForDb = null;
        if (shippingAccountType === "Collect") {
            finalCarrierAccountForDb = carrierAccount;
        } else if (shippingAccountType === "Third Party Billing" && thirdPartyDetails) {
            finalCarrierAccountForDb = thirdPartyDetails.third_party_carrier_account;
        }

        // Insert into orders table, matching the provided schema exactly
        // MODIFIED: Added orderedByName and shippingAddressId to the INSERT statement
        const [orderResult] = await conn.execute(
            `INSERT INTO orders (email, poNumber, billingAddress, shippingAddress, shippingAddressId, attn, tag, shippingMethod, shippingAccountType, carrierAccount, thirdPartyDetails, items, date, orderedByEmail, orderedByPhone, orderedByName, companyId)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?)`, // Added new columns
            [orderedByEmail, poNumber, billingAddress, shippingAddress, shippingAddressId, attn, tag, shippingMethod, shippingAccountType, finalCarrierAccountForDb, JSON.stringify(thirdPartyDetails), JSON.stringify(orderItemsWithCalculatedPrices), orderedByEmail, orderedByPhone, orderedBy, companyId] // Store calculated items and finalCarrierAccountForDb, shippingAddressId, and orderedBy
        );
        const orderId = orderResult.insertId;
        console.log(`[submit-order] Order ID ${orderId} inserted into database for company ID ${companyId}.`);

        await conn.commit();

        // NEW: Generate HTML for the email body and PDF
        const orderDetailsForEmail = {
            poNumber, orderedBy, orderedByEmail, orderedByPhone, billingAddress, shippingAddress, attn, tag, shippingMethod, shippingAccountType, carrierAccount: finalCarrierAccountForDb, // Use the final value
            items: orderItemsWithCalculatedPrices, // Use the items with calculated prices for PDF/email
            terms: company.terms, // Pass company terms from fetched company data
            thirdPartyDetails: thirdPartyDetails // Pass thirdPartyDetails to the HTML generation function
        };
        const orderHtmlContent = generateOrderHtmlEmail(orderDetailsForEmail);

        let pdfBuffer;
        try {
            pdfBuffer = await generatePdfFromHtml(orderHtmlContent);
            console.log("PDF generated successfully.");
        } catch (pdfError) {
            console.error("Failed to generate PDF, proceeding without attachment:", pdfError);
        }

        // NEW: Fetch admin settings for PO email recipient
        let poEmailRecipient = "Greg@ChicagoStainless.com"; // Default fallback
        try {
            const [settingsRows] = await conn.execute("SELECT po_email FROM admin_settings WHERE id = 1");
            if (settingsRows.length > 0 && settingsRows[0].po_email) {
                poEmailRecipient = settingsRows[0].po_email;
            }
        } catch (settingsErr) {
            console.error("Error fetching PO email recipient from admin_settings:", settingsErr);
        }

        // NEW: Send order information email to you (the administrator) with PDF attachment
        const adminMailOptions = {
            from: EMAIL_FROM, // Changed to use the desired FROM address

            to: poEmailRecipient, // Email will be sent to the configured PO email address
            replyTo: orderedByEmail, // Set REPLY-TO to the user's email from the checkout page
            subject: `${company.name} - PO# ${poNumber}`, // UPDATED SUBJECT LINE
            html: `
                <p>Hello,</p>
                <p>A new order has been submitted through the www.ChicagoStainless.com checkout page.</p>
                <p><strong>Company Name:</strong> ${company.name}</p>
                <p><strong>Ordered By:</strong> ${orderedBy}</p>
                <p><strong>User Email:</strong> ${orderedByEmail}</p>
                <p><strong>PO Number:</strong> ${poNumber}</p>
                <p><strong>Shipping Method:</strong> ${shippingMethod}</p>
                <p>Please find the detailed order information attached as a PDF.</p>
                <p>Thank you.</p>
            `,
            attachments: pdfBuffer ? [
                {
                    filename: `Order_${orderId}_${poNumber}.pdf`,
                    content: pdfBuffer.toString('base64'),
                    type: 'application/pdf',
                    disposition: 'attachment'
                }
            ] : []
        };

        mailtrap.send(toMailtrapOptions(adminMailOptions))
            .then(() => { console.log("Admin order notification email sent:"); })
            .catch(error => { console.error("Error sending admin order notification email::", error.message); });

        // NEW: Send confirmation email to the user
        const userConfirmationMailOptions = {
            from: EMAIL_FROM,
            to: orderedByEmail,
            replyTo: "OrderDesk@ChicagoStainless.com",
            subject: "Thank You For Placing Your Order With Chicago Stainless Equipment",
            html: `

                <p>Dear ${req.session.user.firstName},</p>
                <p>Thank you for your recent order with Chicago Stainless Equipment, Inc.</p>
                <p>This email confirms that your order has been successfully placed.</p>
                <p><strong>Company Name:</strong> ${company.name}</p>
                <p><strong>PO Number:</strong> ${poNumber}</p>
                <p>A detailed confirmation of your order is attached as a PDF document for your records.</p>
                <p>We appreciate your business!</p>
                <p style="font-size: 10px; color: #555;">
                    Chicago Stainless Equipment, Inc.<br>
                    1280 SW 34th St, Palm City, FL 34990 USA<br>
                    772-781-1441
                </p>
            `,
            attachments: pdfBuffer ? [
                {
                    filename: `Order_${orderId}_${poNumber}.pdf`,
                    content: pdfBuffer.toString('base64'),
                    type: 'application/pdf',
                    disposition: 'attachment'
                }
            ] : []
        };

        mailtrap.send(toMailtrapOptions(userConfirmationMailOptions))
            .then(() => { console.log("User confirmation email sent:"); })
            .catch(error => { console.error("Error sending user confirmation email::", error.message); });


        // Clear the user's saved cart now that the order is placed
        try {
            await conn.execute("DELETE FROM user_carts WHERE user_id = ?", [userId]);
            console.log(`[submit-order] Cart cleared from user_carts for user ID ${userId}.`);
        } catch (cartErr) {
            console.warn(`[submit-order] Could not clear user_carts for user ID ${userId}:`, cartErr.message);
        }

        res.status(200).json({ message: "Order submitted successfully! Notification emails sent.", orderId: orderId });

    } catch (err) {
        if (conn) {
            await conn.rollback();
        }
        // Log the full error object for detailed debugging on the backend server

        console.error("Error submitting order (Backend):", err);
        res.status(500).json({ error: err.message || "Failed to submit order due to server error." });
    } finally {
        if (conn) conn.end();
    }
});

// NEW: Endpoint to fetch orders for a specific company with enhanced filters
app.get("/api/orders/:companyId", authorizeCompanyAccess, async (req, res) => {
    const { companyId } = req.params;
    const { poNumber, startDate, endDate, partNumber, shippingMethod, shipToAddress, orderedByName } = req.query;
    console.log(`[GET /api/orders/:companyId] Fetching orders for company ID: ${companyId}`);
    console.log(`[GET /api/orders/:companyId] Filters: PO=${poNumber}, StartDate=${startDate}, EndDate=${endDate}, PartNo=${partNumber}, ShippingMethod=${shippingMethod}, ShipToAddressId=${shipToAddress}, OrderedByName=${orderedByName}`);

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        let query = `
            SELECT
                o.id,
                o.poNumber,
                o.shippingMethod,
                o.items,
                o.date,
                o.orderedByEmail,
                o.orderedByPhone,
                o.orderedByName,
                o.billingAddress,
                o.attn,
                o.tag,
                o.carrierAccount,
                o.thirdPartyDetails,
                o.shippingAccountType,
                o.shippingAddressId,
                s.name AS shipToAddressName,
                s.address1 AS shipToAddress1,
                s.city AS shipToAddressCity,
                s.state AS shipToAddressState,
                s.zip AS shipToAddressZip,
                s.country AS shipToAddressCountry
            FROM orders o
            LEFT JOIN shipto_addresses s ON o.shippingAddressId = s.id
            WHERE o.companyId = ?
        `;
        const params = [companyId];

        if (poNumber) {
            query += " AND o.poNumber LIKE ?";
            params.push(`%${poNumber}%`);
        }
        if (startDate) {
            query += " AND DATE(o.date) >= ?";
            params.push(startDate);
        }
        if (endDate) {
            query += " AND DATE(o.date) <= ?";
            params.push(endDate);
        }
        
        // --- REMOVED JSON_TABLE FROM SQL QUERY ---
        // The partNumber filtering will now happen in Node.js after fetching.
        // This avoids the MySQL syntax error related to JSON_TABLE.

        if (shippingMethod) {
            query += " AND o.shippingMethod LIKE ?";
            params.push(`%${shippingMethod}%`);
        }
        if (shipToAddress) {
            query += " AND o.shippingAddressId = ?";
            params.push(shipToAddress);
        }
        if (orderedByName) {
            query += " AND o.orderedByName LIKE ?";
            params.push(`%${orderedByName}%`);
        }

        query += " ORDER BY o.date DESC"; // Order by most recent first

        console.log(`[GET /api/orders/:companyId] Final SQL Query: ${query}`);
        console.log(`[GET /api/orders/:companyId] Query Parameters:`, params);

        const [orders] = await conn.execute(query, params);
        console.log(`[GET /api/orders/:companyId] Found ${orders.length} orders for company ID: ${companyId}`);

        let formattedOrders = orders.map(order => {
            let parsedItems = [];
            console.log(`[GET /api/orders/:companyId] Raw items data for order ${order.id}:`, order.items);
            // mysql2 driver automatically parses JSON columns, so no need for JSON.parse()
            parsedItems = order.items; 
            if (!Array.isArray(parsedItems)) {
                console.warn(`Items for order ${order.id} is not an array, received:`, parsedItems);
                parsedItems = [];
            }

            let parsedThirdPartyDetails = {};
            if (order.thirdPartyDetails) {
                parsedThirdPartyDetails = order.thirdPartyDetails;
                if (typeof parsedThirdPartyDetails !== 'object' || parsedThirdPartyDetails === null) {
                    console.warn(`ThirdPartyDetails for order ${order.id} is not an object, received:`, parsedThirdPartyDetails);
                    parsedThirdPartyDetails = {};
                }
            }

            // Determine shippingAccountType based on available data
            let determinedShippingAccountType = order.shippingAccountType || 'Prepaid'; // Default
            
            let displayShippingAddress = order.shippingAddress;
            if (order.shipToAddressName) {
                displayShippingAddress = `${order.shipToAddressName}\n${order.shipToAddress1}\n${order.shipToAddressCity}, ${order.shipToAddressState} ${order.shipToAddressZip} ${order.shipToAddressCountry}`;
            }

            return {
                id: order.id,
                poNumber: order.poNumber,
                shippingMethod: order.shippingMethod,
                items: parsedItems,
                date: order.date,
                orderedByEmail: order.orderedByEmail,
                orderedByPhone: order.orderedByPhone,
                orderedByName: order.orderedByName,
                billingAddress: order.billingAddress,
                shippingAddress: displayShippingAddress,
                shippingAddressId: order.shippingAddressId,
                attn: order.attn,
                tag: order.tag,
                carrierAccount: order.carrierAccount,
                thirdPartyDetails: parsedThirdPartyDetails,
                shippingAccountType: determinedShippingAccountType // Add the determined type
            };
        });

        // --- PART NUMBER FILTERING IN NODE.JS ---
        if (partNumber) {
            const searchTermLower = partNumber.toLowerCase();
            console.log(`[GET /api/orders/:companyId] Applying Node.js partNumber filter for: "${searchTermLower}"`);
            formattedOrders = formattedOrders.filter(order => {
                // Ensure order.items is an array before trying to iterate
                if (!Array.isArray(order.items)) {
                    return false; // Skip orders with malformed items data
                }
                return order.items.some(item =>
                    item.partNo && item.partNo.toLowerCase().includes(searchTermLower)
                );
            });
            console.log(`[GET /api/orders/:companyId] Filtered down to ${formattedOrders.length} orders by part number.`);
        }
        // --- END PART NUMBER FILTERING IN NODE.JS ---

        res.json(formattedOrders);
    } catch (err) {
        console.error("Error fetching order history:", err);
        // Log specific MySQL error details if available
        if (err.sqlMessage) {
            console.error("MySQL Error Message:", err.sqlMessage);
            console.error("MySQL Error Code:", err.code);
            console.error("MySQL Error SQL:", err.sql);
        }
        res.status(500).json({ error: "Failed to retrieve order history due to server error." });
    } finally {
        if (conn) conn.end();
    }
});



// ─── Shopping Cart Routes ────────────────────────────────────────────────────

// GET /api/cart — return the current user's saved cart
app.get("/api/cart", requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [rows] = await conn.execute(
            "SELECT cart_data FROM user_carts WHERE user_id = ?", [userId]
        );
        if (!rows.length) return res.json([]);
        // cart_data may come back as a parsed array or as a raw JSON string
        // depending on the mysql2 version — handle both
        let cartData = rows[0].cart_data;
        if (typeof cartData === 'string') {
            try { cartData = JSON.parse(cartData); } catch(e) { cartData = []; }
        }
        res.json(Array.isArray(cartData) ? cartData : []);
    } catch (err) {
        console.error("[GET /api/cart] Error:", err);
        res.status(500).json({ error: "Failed to retrieve cart" });
    } finally {
        if (conn) conn.end();
    }
});

// POST /api/cart — save/overwrite the current user's cart
// No requireAuth middleware: silently skips save when user is not logged in
// so the configurator can always call this without causing errors.
app.post("/api/cart", async (req, res) => {
    if (!req.session.user) {
        // Not logged in — acknowledge the request but skip the save
        return res.json({ success: false, reason: "not_logged_in" });
    }
    const userId = req.session.user.id;
    const { cartData } = req.body;
    if (!Array.isArray(cartData)) {
        return res.status(400).json({ error: "cartData must be an array" });
    }
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        if (cartData.length === 0) {
            // Empty cart — remove the row entirely so it doesn't appear in abandoned carts
            await conn.execute("DELETE FROM user_carts WHERE user_id = ?", [userId]);
            console.log(`[POST /api/cart] Cart cleared (empty) for user ID ${userId}.`);
        } else {
            await conn.execute(
                `INSERT INTO user_carts (user_id, cart_data)
                 VALUES (?, ?)
                 ON DUPLICATE KEY UPDATE cart_data = VALUES(cart_data), updated_at = CURRENT_TIMESTAMP`,
                [userId, JSON.stringify(cartData)]
            );
            console.log(`[POST /api/cart] Cart saved for user ID ${userId}, ${cartData.length} item(s).`);
        }
        res.json({ success: true });
    } catch (err) {
        console.error("[POST /api/cart] Error:", err);
        res.status(500).json({ error: "Failed to save cart" });
    } finally {
        if (conn) conn.end();
    }
});

// GET /api/cart/user/:userId — admin only: view any user's saved cart
app.get("/api/cart/user/:userId", requireAdmin, async (req, res) => {
    const { userId } = req.params;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [rows] = await conn.execute(
            "SELECT cart_data FROM user_carts WHERE user_id = ?", [userId]
        );
        if (!rows.length) return res.json([]);
        let cartData = rows[0].cart_data;
        if (typeof cartData === 'string') {
            try { cartData = JSON.parse(cartData); } catch(e) { cartData = []; }
        }
        res.json(Array.isArray(cartData) ? cartData : []);
    } catch (err) {
        console.error("[GET /api/cart/user/:userId] Error:", err);
        res.status(500).json({ error: "Failed to retrieve user cart" });
    } finally {
        if (conn) conn.end();
    }
});


// GET /api/carts/all — admin only: all users with non-empty carts
app.get("/api/carts/all", requireAdmin, async (req, res) => {
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [rows] = await conn.execute(`
            SELECT uc.user_id, uc.cart_data, uc.updated_at,
                   u.email, u.first_name, u.last_name,
                   c.name AS company_name
            FROM user_carts uc
            JOIN users u ON u.id = uc.user_id
            LEFT JOIN companies c ON c.id = u.company_id
            ORDER BY uc.updated_at DESC
        `);

        const carts = rows.map(row => {
            let items = row.cart_data;
            if (typeof items === 'string') {
                try { items = JSON.parse(items); } catch(e) { items = []; }
            }
            if (!Array.isArray(items)) items = [];
            return {
                user_id:      row.user_id,
                email:        row.email,
                first_name:   row.first_name,
                last_name:    row.last_name,
                company_name: row.company_name,
                updated_at:   row.updated_at,
                cart_items:   items
            };
        }).filter(c => c.cart_items.length > 0); // only non-empty carts

        res.json(carts);
    } catch (err) {
        console.error("[GET /api/carts/all] Error:", err);
        res.status(500).json({ error: "Failed to retrieve abandoned carts" });
    } finally {
        if (conn) conn.end();
    }
});

// --- General Routes and Server Start ---

app.get("/", (req, res) => {
  res.redirect("/admin-dashboard.html");
});

// MODIFIED: Database Initialization Function
async function initializeDatabase() {
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        console.log("Database connection for initialization established.");

        // IMPORTANT: No DROP TABLE statements here to preserve existing data.
        // Tables will only be created if they don't already exist.

        // Create 'companies' table if not exists
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS companies (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                logo VARCHAR(255),
                address1 TEXT,
                ap_email VARCHAR(255),
                website VARCHAR(255),
                city VARCHAR(255),
                state VARCHAR(255),
                zip VARCHAR(20),
                country VARCHAR(255),
                terms VARCHAR(50),
                discount DECIMAL(5,2) DEFAULT 0.00,
                notes TEXT,
                approved BOOLEAN DEFAULT FALSE,
                denied BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB;
        `);
        console.log("'companies' table checked/created.");

        // Check if 'ap_email' column exists in 'companies' table before adding it
        const [apEmailColumnCheck] = await conn.execute(`
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'companies' AND COLUMN_NAME = 'ap_email';
        `, [dbConnectionConfig.database]);

        if (apEmailColumnCheck.length === 0) {
            await conn.execute(`
                ALTER TABLE companies ADD COLUMN ap_email VARCHAR(255) AFTER address1;
            `);
            console.log("'ap_email' column added to 'companies' table.");
        } else {
            console.log("'ap_email' column already exists in 'companies' table.");
        }

        // Check if 'website' column exists in 'companies' table before adding it
        const [websiteColumnCheck] = await conn.execute(`
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'companies' AND COLUMN_NAME = 'website';
        `, [dbConnectionConfig.database]);

        if (websiteColumnCheck.length === 0) {
            await conn.execute(`
                ALTER TABLE companies ADD COLUMN website VARCHAR(255) AFTER ap_email;
            `);
            console.log("'website' column added to 'companies' table.");
        } else {
            console.log("'website' column already exists in 'companies' table.");
        }

        // Create 'users' table if not exists with foreign key
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                first_name VARCHAR(255),
                last_name VARCHAR(255),
                phone VARCHAR(50),
                role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
                password VARCHAR(255) NOT NULL,
                company_id INT,
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
            ) ENGINE=InnoDB;
        `);
        console.log("'users' table checked/created.");

        // Add ALTER TABLE logic for existing databases
        const [companiesCreatedAtColumnCheck] = await conn.execute(`
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'companies' AND COLUMN_NAME = 'created_at';
        `, [dbConnectionConfig.database]);

        if (companiesCreatedAtColumnCheck.length === 0) {
            await conn.execute(`
                ALTER TABLE companies
                ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
            `);
            console.log("'created_at' column added to 'companies' table.");
        } else {
            console.log("'created_at' column already exists in 'companies' table.");
        }

        // Check if 'created_at' column exists in 'users' table before adding it
        const [usersCreatedAtColumnCheck] = await conn.execute(`
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'users' AND COLUMN_NAME = 'created_at';
        `, [dbConnectionConfig.database]);

        if (usersCreatedAtColumnCheck.length === 0) {
            await conn.execute(`
                ALTER TABLE users
                ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
            `);
            console.log("'created_at' column added to 'users' table.");
        } else {
            console.log("'created_at' column already exists in 'users' table.");
        }

        // Create 'login_history' table if not exists
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS login_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(45),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB;
        `);
        console.log("'login_history' table checked/created.");

        // Create 'user_carts' table for server-side cart persistence
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS user_carts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL UNIQUE,
                cart_data JSON,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB;
        `);
        console.log("'user_carts' table checked/created.");

        // Create 'shipto_addresses' table if not exists with foreign key
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS shipto_addresses (
                id INT AUTO_INCREMENT PRIMARY KEY,
                company_id INT NOT NULL,
                name VARCHAR(255) NOT NULL,
                company_name VARCHAR(255),
                address1 TEXT NOT NULL,
                city VARCHAR(255) NOT NULL,
                state VARCHAR(255) NOT NULL,
                zip VARCHAR(20) NOT NULL,
                country VARCHAR(255),
                is_default BOOLEAN DEFAULT FALSE,
                carrier_account VARCHAR(255), -- NEW: Added carrier_account column
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
            ) ENGINE=InnoDB;
        `);
        console.log("'shipto_addresses' table checked/created.");

        // Check if 'carrier_account' column exists before adding it
        const [columnCheck] = await conn.execute(`
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'shipto_addresses' AND COLUMN_NAME = 'carrier_account';
        `, [dbConnectionConfig.database]);

        if (columnCheck.length === 0) {
            // Column does not exist, so add it
            await conn.execute(`
                ALTER TABLE shipto_addresses
                ADD COLUMN carrier_account VARCHAR(255);
            `);
            console.log("'carrier_account' column added to 'shipto_addresses' table.");
        } else {
            console.log("'carrier_account' column already exists in 'shipto_addresses' table.");
        }

        // Check if 'created_at' column exists in 'shipto_addresses' before adding it
                const [shiptoCreatedAtColumnCheck] = await conn.execute(`
                    SELECT COLUMN_NAME
                    FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'shipto_addresses' AND COLUMN_NAME = 'created_at';
                `, [dbConnectionConfig.database]);

                if (shiptoCreatedAtColumnCheck.length === 0) {
                    await conn.execute(`
                        ALTER TABLE shipto_addresses
                        ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
                    `);
                    console.log("'created_at' column added to 'shipto_addresses' table.");
                } else {
                    console.log("'created_at' column already exists in 'shipto_addresses' table.");
                }

        // Create 'orders' table if not exists
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS orders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                poNumber VARCHAR(255) NOT NULL,
                billingAddress TEXT NOT NULL,
                shippingAddress TEXT NOT NULL,
                shippingAddressId INT,
                attn VARCHAR(255),
                tag VARCHAR(255),
                shippingMethod VARCHAR(255),
                shippingAccountType VARCHAR(255),
                carrierAccount VARCHAR(255),
                thirdPartyDetails JSON,
                items JSON NOT NULL,
                date DATETIME DEFAULT CURRENT_TIMESTAMP,
                orderedByEmail VARCHAR(255),
                orderedByPhone VARCHAR(50),
                orderedByName VARCHAR(255),
                companyId INT,
                FOREIGN KEY (companyId) REFERENCES companies(id) ON DELETE CASCADE,
                FOREIGN KEY (shippingAddressId) REFERENCES shipto_addresses(id) ON DELETE SET NULL
            ) ENGINE=InnoDB;
        `);
        console.log("'orders' table checked/created.");

        // Check if 'companyId' column exists in 'orders' table before adding it
        const [ordersCompanyIdColumnCheck] = await conn.execute(`
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'companyId';
        `, [dbConnectionConfig.database]);

        if (ordersCompanyIdColumnCheck.length === 0) {
            await conn.execute(`
                ALTER TABLE orders
                ADD COLUMN companyId INT,
                ADD CONSTRAINT fk_company_id
                FOREIGN KEY (companyId) REFERENCES companies(id) ON DELETE CASCADE;
            `);
            console.log("'companyId' column added to 'orders' table with foreign key constraint.");
        } else {
            console.log("'companyId' column already exists in 'orders' table.");
        }

        // Check if 'shippingAddressId' column exists in 'orders' table before adding it
        const [ordersShippingAddressIdColumnCheck] = await conn.execute(`
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'shippingAddressId';
        `, [dbConnectionConfig.database]);

        if (ordersShippingAddressIdColumnCheck.length === 0) {
            await conn.execute(`
                ALTER TABLE orders
                ADD COLUMN shippingAddressId INT,
                ADD CONSTRAINT fk_shipping_address_id
                FOREIGN KEY (shippingAddressId) REFERENCES shipto_addresses(id) ON DELETE SET NULL;
            `);
            console.log("'shippingAddressId' column added to 'orders' table with foreign key constraint.");
        } else {
            console.log("'shippingAddressId' column already exists in 'orders' table.");
        }


        // NEW: Check if 'orderedByEmail', 'orderedByPhone', 'attn', 'tag', 'thirdPartyDetails', 'orderedByName' columns exist in 'orders' table
        const [ordersNewColumnsCheck] = await conn.execute(`
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'orders' AND COLUMN_NAME IN ('orderedByEmail', 'orderedByPhone', 'attn', 'tag', 'thirdPartyDetails', 'orderedByName', 'shippingAccountType');
        `, [dbConnectionConfig.database]);

        const existingOrderColumns = ordersNewColumnsCheck.map(row => row.COLUMN_NAME);

        if (!existingOrderColumns.includes('orderedByEmail')) {
            await conn.execute(`ALTER TABLE orders ADD COLUMN orderedByEmail VARCHAR(255);`);
            console.log("'orderedByEmail' column added to 'orders' table.");
        }
        if (!existingOrderColumns.includes('orderedByPhone')) {
            await conn.execute(`ALTER TABLE orders ADD COLUMN orderedByPhone VARCHAR(50);`);
            console.log("'orderedByPhone' column added to 'orders' table.");
        }

        if (!existingOrderColumns.includes('attn')) {
            await conn.execute(`ALTER TABLE orders ADD COLUMN attn VARCHAR(255);`);
            console.log("'attn' column added to 'orders' table.");
        }
        if (!existingOrderColumns.includes('tag')) {
            await conn.execute(`ALTER TABLE orders ADD COLUMN tag VARCHAR(255);`);
            console.log("'tag' column added to 'orders' table.");
        }
        if (!existingOrderColumns.includes('thirdPartyDetails')) {
            await conn.execute(`ALTER TABLE orders ADD COLUMN thirdPartyDetails JSON;`);
            console.log("'thirdPartyDetails' column added to 'orders' table.");
        }
        if (!existingOrderColumns.includes('orderedByName')) {
            await conn.execute(`ALTER TABLE orders ADD COLUMN orderedByName VARCHAR(255);`);
            console.log("'orderedByName' column added to 'orders' table.");
        }
        if (!existingOrderColumns.includes('shippingAccountType')) {
            await conn.execute(`ALTER TABLE orders ADD COLUMN shippingAccountType VARCHAR(255);`);
            console.log("'shippingAccountType' column added to 'orders' table.");
        }


        // Create 'admin_settings' table if not exists
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS admin_settings (
                id INT PRIMARY KEY DEFAULT 1,
                po_email VARCHAR(255),
                registration_email VARCHAR(255)
            ) ENGINE=InnoDB;
        `);
        console.log("'admin_settings' table checked/created.");

        // Insert default admin settings if not exists
        const [settingsRows] = await conn.execute("SELECT id FROM admin_settings WHERE id = 1");
        if (settingsRows.length === 0) {
            await conn.execute(
                "INSERT INTO admin_settings (id, po_email, registration_email) VALUES (1, ?, ?)",
                ["Greg@ChicagoStainless.com", "Greg@ChicagoStainless.com"] // Default emails
            );
            console.log("Default admin settings inserted.");
        }

        // --- Create a default company and admin user ONLY if no companies exist ---
        const [existingCompanies] = await conn.execute("SELECT id FROM companies LIMIT 1");
        if (existingCompanies.length === 0) {
            console.log("No companies found. Creating a default company and admin user.");

            // Create a default company
            const [companyResult] = await conn.execute(
                `INSERT INTO companies (name, address1, city, state, zip, country, terms, discount, approved)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, TRUE)`, // Default company is approved
                ["Default Admin Company", "123 Admin St", "Admin City", "FL", "12345", "USA", "Net 30", 0.00, true]
            );
            const defaultCompanyId = companyResult.insertId;
            console.log(`Default company created with ID: ${defaultCompanyId}`);

            // Create a default admin user
            const adminEmail = process.env.DEFAULT_ADMIN_EMAIL || "admin@chicagostainless.com";
            const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD;
            if (!adminPassword) {
                throw new Error("DEFAULT_ADMIN_PASSWORD environment variable is not set. Cannot create default admin user.");
            }
            const hashedPassword = await bcrypt.hash(adminPassword, 10);

            await conn.execute(
                `INSERT INTO users (email, first_name, last_name, role, password, company_id)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [adminEmail, "Admin", "User", "admin", hashedPassword, defaultCompanyId]
            );
            console.log(`Default admin user '${adminEmail}' created.`);
        }


    } catch (err) {
        console.error("Error initializing database:", err);
        // Do not exit — tables already exist from previous runs.
        // A temporary DB timeout at startup should not take the server down.
    } finally {
        if (conn) {
            conn.end();
            console.log("Database connection for initialization closed.");
        }
    }
}

// Always start the server, even if DB init fails.
// The DB init only creates tables if they don't exist — it is not required for the server to function.
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Run DB init in the background after server is already listening.
initializeDatabase().catch(err => {
    console.error("Background DB initialization failed (non-fatal):", err);
});
