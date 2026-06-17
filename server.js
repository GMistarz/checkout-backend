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
const twilio = require('twilio'); // For SMS notifications

// NEW: Import puppeteer-extra and the stealth plugin
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
// NEW: Import @sparticuz/chromium for Render compatibility
const chromium = require('@sparticuz/chromium');

// Apply the stealth plugin to puppeteer
puppeteer.use(StealthPlugin());

// --- CSE Logo: hardcoded as a base64 data URI so neither Puppeteer nor
//     email clients ever need to make an outbound HTTP request. ---
const CSE_LOGO_SRC = "data:image/jpeg;base64,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";

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
  connectTimeout: 10000, // 10-second connection timeout
  dateStrings: true      // Return DATETIME/TIMESTAMP as "YYYY-MM-DD HH:MM:SS" strings
                         // instead of JS Date objects. Required so parseToLocal() on the
                         // client can correctly interpret them as US/Central time.
                         // Without this, mysql2 serializes Date objects with a 'Z' suffix
                         // which bypasses the timezone correction in the dashboard.
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

// --- Twilio SMS Configuration ---
const twilioClient = (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN)
    ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
    : null;
if (twilioClient) {
    console.log('Twilio Config: credentials loaded, SMS notifications enabled.');
} else {
    console.warn('Twilio Config: TWILIO_ACCOUNT_SID or TWILIO_AUTH_TOKEN not set — SMS notifications disabled.');
}

// Helper to send SMS to one or more phone numbers (semicolon or comma-separated string or array)
async function sendSmsNotification(toNumbers, body) {
    if (!twilioClient) {
        console.warn('Twilio not configured — skipping SMS notification.');
        return;
    }
    const numbers = Array.isArray(toNumbers)
        ? toNumbers
        : toNumbers.split(/[;,]/).map(n => n.trim()).filter(Boolean);
    for (const to of numbers) {
        try {
            await twilioClient.messages.create({
                from: process.env.TWILIO_FROM_NUMBER,
                to,
                body
            });
            console.log(`SMS sent to ${to}`);
        } catch (err) {
            console.error(`Error sending SMS to ${to}:`, err.message);
        }
    }
}

// --- Excluded Emails for Login History Logging ---
// Any @chicagostainless.com address is excluded automatically, plus any
// additional external addresses listed below.
const EXCLUDED_LOGGING_EMAILS = [
    // Add non-CSE addresses here if ever needed
];
function isExcludedFromLogging(email) {
    const lower = (email || '').toLowerCase();
    if (lower.endsWith('@chicagostainless.com')) return true;
    return EXCLUDED_LOGGING_EMAILS.includes(lower);
}
// -------------------------------------------------

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
        const [settings] = await conn.execute("SELECT po_email, po_sms FROM admin_settings WHERE id = 1");
        const rawPoEmail = settings[0]?.po_email || "Greg@ChicagoStainless.com"; // Fallback email
        const recipientEmail = rawPoEmail.split(/[;,]/).map(e => e.trim()).filter(Boolean);

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

        // Send SMS notification if phone numbers are configured
        const poSmsNumbers = (settings[0]?.po_sms || '').split(/[;,]/).map(n => n.trim()).filter(Boolean);
        if (poSmsNumbers.length) {
            sendSmsNotification(poSmsNumbers,
                `New Website Order #${orderId} — PO# ${orderDetails.poNumber} from ${orderDetails.orderedBy}. Check your email for the full details.`
            );
        }
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
        const [settings] = await conn.execute("SELECT registration_email, registration_sms FROM admin_settings WHERE id = 1");
        const rawRegEmail1 = settings[0]?.registration_email || "Greg@ChicagoStainless.com"; // Fallback email
        const recipientEmail = rawRegEmail1.split(/[;,]/).map(e => e.trim()).filter(Boolean);

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

        // Send SMS notification if phone numbers are configured
        const regSmsNumbers1 = (settings[0]?.registration_sms || '').split(/[;,]/).map(n => n.trim()).filter(Boolean);
        if (regSmsNumbers1.length) {
            sendSmsNotification(regSmsNumbers1,
                `New Company Registration: ${companyName} — ${firstName} ${lastName} (${userEmail}). Check your email for details.`
            );
        }
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
        const [settings] = await conn.execute("SELECT registration_email, registration_sms FROM admin_settings WHERE id = 1");
        const rawRegEmail2 = settings[0]?.registration_email || "Greg@ChicagoStainless.com"; // Fallback email
        const recipientEmail = rawRegEmail2.split(/[;,]/).map(e => e.trim()).filter(Boolean);

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

        // Send SMS notification if phone numbers are configured
        const regSmsNumbers2 = (settings[0]?.registration_sms || '').split(/[;,]/).map(n => n.trim()).filter(Boolean);
        if (regSmsNumbers2.length) {
            sendSmsNotification(regSmsNumbers2,
                `New User Registration: ${firstName} ${lastName} joined ${companyName} (${userEmail}). Check your email for details.`
            );
        }
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
        if (!isExcludedFromLogging(userEmailLower)) {
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

// Customer Check Auth Route — returns session state + company discount for the configurator pages
// Returns 200 with { authenticated: true, firstName, discount } when logged in,
// or 200 with { authenticated: false } when not (never 401, so the front-end fetch is always clean).
app.get("/check-auth", async (req, res) => {
    if (!req.session.user) {
        return res.status(200).json({ authenticated: false });
    }
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [companies] = await conn.execute(
            "SELECT discount, logo, logo_code FROM companies WHERE id = ?",
            [req.session.user.companyId]
        );
        const discount  = parseFloat(companies[0]?.discount) || 0;
        const logoCode  = companies[0]?.logo_code || '';   // configurator logo code, e.g. "Dixon"
        res.status(200).json({
            authenticated: true,
            firstName:     req.session.user.firstName,
            lastName:      req.session.user.lastName,
            email:         req.session.user.email,
            discount:      discount,
            logoCode:      logoCode
        });
    } catch (err) {
        console.error("[check-auth] Error fetching company data:", err);
        // Still return the authenticated state even if the lookup fails
        res.status(200).json({
            authenticated: true,
            firstName:     req.session.user.firstName,
            lastName:      req.session.user.lastName,
            email:         req.session.user.email,
            discount:      0,
            logoCode:      ''
        });
    } finally {
        if (conn) conn.end();
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

// Endpoint to return configurator logo options parsed from logos.php.
// The admin dashboard uses this to keep its Configurator Logo dropdown
// in sync with logos.php automatically — no hardcoded list needed.
// Embedded logo options — fallback used when chicagostainless.com/logos.php is unreachable.
// Update logos.php on your website and the live fetch will pick it up automatically.
const EMBEDDED_LOGO_OPTIONS = [
  { value: "CSE", label: "CSE Logo" },
  { value: "TEST", label: "TEST" },
  { value: "NO LOGO", label: "No Logo" },
  { value: "A&", label: "A&B Process Systems" },
  { value: "APG", label: "Adcor Packaging (APG)" },
  { value: "ADVANCED PROCESS", label: "Advanced Process Solutions" },
  { value: "APS", label: "Advanced Process Systems" },
  { value: "APT", label: "Advanced Process Technologies" },
  { value: "ALLTECH", label: "Alltech Supply" },
  { value: "AMPCO", label: "Ampco Pumps Company" },
  { value: "APOTEK", label: "Apotek Solutions" },
  { value: "APPLIED", label: "Applied Industrial Technologies" },
  { value: "APV", label: "APV" },
  { value: "ARMOR", label: "Armor Industries" },
  { value: "ARROW", label: "Arrow Process Systems" },
  { value: "AUBURN", label: "Auburn Mechanical" },
  { value: "AUSTENITEX", label: "Austenitex" },
  { value: "ATS", label: "Automated Technical Services" },
  { value: "AXIFLOW", label: "Axiflow Technologies" },
  { value: "BARNEYS", label: "Barney's Pumps" },
  { value: "BARNUM", label: "Barnum Equipment" },
  { value: "BEECO", label: "Bykowski Equipment (BEECO)" },
  { value: "BERGEN", label: "Bergen Industrial Supply" },
  { value: "BETHEL", label: "Bethel Engineering" },
  { value: "BIO", label: "Bio Integrity" },
  { value: "BMB", label: "BMB Process & Filtration" },
  { value: "BROWER", label: "Brower Equipment" },
  { value: "BRUNS BROS", label: "Bruns Brothers Process Equipment" },
  { value: "CASELLA", label: "Casella Process Solutions" },
  { value: "CIP", label: "Centerline Industrial Products" },
  { value: "CIS", label: "Central Industrial Sales" },
  { value: "CSI", label: "Central States Industrial (CSI)" },
  { value: "CENTREX", label: "Centrex Technical Sales" },
  { value: "CFR", label: "Complete Filtration Resources" },
  { value: "CSS", label: "Complete Separator Services" },
  { value: "CORROSION", label: "Corrosion Fulid Products" },
  { value: "CPE", label: "CPE Systems" },
  { value: "CRANE", label: "Crane Engineering" },
  { value: "CUSTOM FAB", label: "Custom Fabricating & Repair" },
  { value: "DEC", label: "Dairy Engineering Company" },
  { value: "DEJONG", label: "DeJong Consulting" },
  { value: "DIXON", label: "Dixon Sanitary" },
  { value: "DOBBINS", label: "Dobbins Company" },
  { value: "DR TECH", label: "Dr Tech" },
  { value: "DUVA SANITARY", label: "Duva Sanitary" },
  { value: "ELEVATED AUTOMATION", label: "Elevated Automation" },
  { value: "ENERGYWATER", label: "Energy Water Solutions" },
  { value: "ECE", label: "Environmental Compliance Equipment" },
  { value: "ERDMANN", label: "Erdmann Corporation" },
  { value: "EPS", label: "Extreme Process Solutions" },
  { value: "EYERS GROVE", label: "Eyers Grove Management Group" },
  { value: "F&", label: "F & H Food Equipment" },
  { value: "FESINTL", label: "FESINTL Corp" },
  { value: "F&", label: "Filter & Water Technologies" },
  { value: "FPS", label: "Filter Process & Supply" },
  { value: "FLUID GAUGE", label: "Fluid Gauge Company" },
  { value: "FRISTAM", label: "Fristam Pumps" },
  { value: "GALLOUP", label: "Galloup" },
  { value: "GMS", label: "GMS Metal Works" },
  { value: "GRAM", label: "Gram Equipment" },
  { value: "GRAYCO", label: "GrayCo Stainless" },
  { value: "H2O", label: "H2O Solutions" },
  { value: "H&", label: "H&H Extraction Solutions" },
  { value: "HARCO", label: "Harco Enterprises" },
  { value: "HARRINGTON PROCESS", label: "Harrington Process" },
  { value: "HARVILL", label: "Harvill Industries" },
  { value: "HERITAGE", label: "Heritage Equipment" },
  { value: "HCS", label: "High Country Stainless" },
  { value: "HIGHLAND", label: "Highland Equipment" },
  { value: "HAT", label: "Holland Applied Technologies" },
  { value: "IDEAL", label: "Ideal Process Solutions" },
  { value: "IPM", label: "IPM Panama" },
  { value: "IPS", label: "Industrial Pipe & Supply" },
  { value: "INFINI-MIX", label: "Infini-Mix" },
  { value: "JADLER", label: "Jadler Industries" },
  { value: "KELLER", label: "Keller Technologies" },
  { value: "KODIAK", label: "Kodiak Controls" },
  { value: "KOSS", label: "Koss Industrial" },
  { value: "KPGNA", label: "Krones Process Group North America" },
  { value: "LPS", label: "Lake Process Systems" },
  { value: "LIGHTHOUSE", label: "Lighthouse Process" },
  { value: "LLANES", label: "Llanes Barreto" },
  { value: "MGN", label: "M.G. Newell" },
  { value: "MAC PASS", label: "Mac Pass" },
  { value: "MANE", label: "Mane" },
  { value: "MAREL", label: "Marel" },
  { value: "MARINOS", label: "Marino's & Company" },
  { value: "MARTINBROS", label: "Martin Brothers" },
  { value: "MCKENNA", label: "McKenna Engineering & Equipment" },
  { value: "MEMBRANE", label: "Membrane Systems Specialists" },
  { value: "Mohawk", label: "Mohawk Technology" },
  { value: "NATIONAL", label: "National Utilities" },
  { value: "N-J", label: "Nelson-Jameson" },
  { value: "NETHER", label: "Nether Industries" },
  { value: "NIPR", label: "NIPR Sanitary" },
  { value: "NPP", label: "Northland Process Piping" },
  { value: "NSI", label: "NSI Newlands" },
  { value: "NU-CON", label: "Nu-Con Equipment" },
  { value: "MUELLER", label: "Paul Mueller" },
  { value: "PEISA", label: "Proyectos e Instrumentos, S A de C V" },
  { value: "PVFCO", label: "Pipe Valve & Fitting Company" },
  { value: "PPT", label: "PPT Florida" },
  { value: "PGE", label: "Preferred Global Equipment" },
  { value: "PROSALES", label: "Pro Sales" },
  { value: "PSI", label: "Process Solutions & Integration" },
  { value: "PTI", label: "Process Technologies" },
  { value: "PROCOMP", label: "ProComp" },
  { value: "PRYDE", label: "Pryde Measurement" },
  { value: "PURE SUPPLY", label: "Pure Supply" },
  { value: "QSI", label: "Quality Stainless" },
  { value: "QTS", label: "Quality Tank Solutions" },
  { value: "QUALTECH", label: "Qualtech Distribution" },
  { value: "QUENTIN", label: "Quentin Corperation" },
  { value: "RMS", label: "R. Mueller Service & Equipment" },
  { value: "RACE", label: "Race Company" },
  { value: "RMS", label: "Rocky Mountain Stainless" },
  { value: "RODEM", label: "Rodem" },
  { value: "RSM", label: "RS Mechanical" },
  { value: "RSP", label: "RSP Design" },
  { value: "SSI", label: "Samuelson Sales" },
  { value: "SANI-MATIC", label: "Sani-Matic" },
  { value: "SANITUBE", label: "Sanitube" },
  { value: "SIPCO", label: "Sanitary & Industrial Products" },
  { value: "SEK", label: "Sanitary Korea" },
  { value: "SEMI BULK", label: "Semi-Bulk" },
  { value: "SSS", label: "Service Supply System" },
  { value: "SILVERLINE", label: "Silverline" },
  { value: "SMITHFIELD", label: "Smithfield BioScience" },
  { value: "SONIC", label: "Sonic Corporation" },
  { value: "SOUTHERN", label: "Southern Piping Solutions" },
  { value: "SPS", label: "Specialty Process Systems" },
  { value: "SPX", label: "SPX Flow" },
  { value: "STAIN DIST", label: "Stainless Distributors" },
  { value: "SEC", label: "Stainless Equipment" },
  { value: "SPE", label: "Stainless Process Equipment" },
  { value: "SST", label: "Stainless Supply Technology" },
  { value: "STATCO", label: "Statco Engineering & Fabricators" },
  { value: "STEAM", label: "Steam Engineering" },
  { value: "S&", label: "Steel & O'Brien Manufacturing" },
  { value: "TTS", label: "Team Technical Services" },
  { value: "TELTRU", label: "Tel-Tru Manufacturing" },
  { value: "TEMP PRESS", label: "Temp-Press" },
  { value: "TETRA PAK", label: "Tetra Pak" },
  { value: "TSI", label: "Todd Street" },
  { value: "TRINOVA", label: "Trinova" },
  { value: "TRIPLEX", label: "Triplex Sales" },
  { value: "TWINCO", label: "Twinco" },
  { value: "US GAUGE", label: "U.S. Gauge" },
  { value: "VAF", label: "VA Filtration" },
  { value: "WHC", label: "W.H. Cooke & Company" },
  { value: "WACCO", label: "Wacco" },
  { value: "WAYLAND", label: "Wayland Industries" },
  { value: "WRF", label: "White River Fabrication" },
  { value: "WILCO", label: "Wilco Equipment" },
  { value: "WINTERS", label: "Winters Instruments" },
  { value: "WPS", label: "Wright Process Systems" },
  { value: "ZMT", label: "ZM Technologies" }
];

app.get("/admin/logo-options", requireAdmin, async (req, res) => {
    // Fetch logos.php directly from the live website so any additions are
    // picked up automatically — no need to redeploy server.js or Render.
    try {
        const response = await fetch('https://www.chicagostainless.com/logos.php');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const html = await response.text();

        const distMatch = html.match(/id=['"]Distributors['"][^>]*>([\s\S]*?)<\/optgroup>/i);
        if (!distMatch) return res.json(EMBEDDED_LOGO_OPTIONS);

        const optionRegex = /<option[^>]+value=['"]([^'"]+)['"][^>]*>([^<]*)<\/option>/gi;
        const options = [];
        let m;
        while ((m = optionRegex.exec(distMatch[1])) !== null) {
            const code = m[1].split(';')[0].trim();
            const label = m[2].trim();
            if (code) options.push({ value: code, label: label });
        }
        console.log(`[GET /admin/logo-options] Loaded ${options.length} options from chicagostainless.com/logos.php`);
        return res.json(options);
    } catch (err) {
        // Network error or site down — fall back to the embedded list
        console.warn('[GET /admin/logo-options] Could not fetch logos.php from website, using embedded fallback:', err.message);
        return res.json(EMBEDDED_LOGO_OPTIONS);
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
            WHERE lh.login_time >= ? AND lh.login_time < DATE_ADD(?, INTERVAL 1 DAY)
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
            WHERE o.date >= ? AND o.date < DATE_ADD(?, INTERVAL 1 DAY)
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
            query += ` WHERE uc.updated_at >= ? AND uc.updated_at < DATE_ADD(?, INTERVAL 1 DAY)`;
            params.push(startDate, endDate);
        } else if (startDate) {
            query += ` WHERE uc.updated_at >= ?`;
            params.push(startDate);
        } else if (endDate) {
            query += ` WHERE uc.updated_at < DATE_ADD(?, INTERVAL 1 DAY)`;
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
    if (!isExcludedFromLogging(userEmailLower)) {
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
    const [companies] = await conn.execute("SELECT id, name, logo, logo_code, address1, ap_email, website, city, state, zip, country, terms, discount, notes, approved, denied, created_at FROM companies ORDER BY name ASC"); // Added ap_email
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
  const { id, name, address1, ap_email, website, city, state, zip, country, terms, discount, approved, denied, logo, logo_code, notes } = req.body; // Added ap_email
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
    if (logo_code !== undefined) { fieldsToUpdate.push("logo_code = ?"); values.push(logo_code); }
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
    name, logo, logo_code, address1, city, state, zip, country, terms, discount
  } = req.body;
  console.log(`[POST /add-company] Adding new company: ${name}`);
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [result] = await conn.execute(`
      INSERT INTO companies (name, logo, logo_code, address1, city, state, zip, country, terms, discount, notes, approved, denied)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE, FALSE)
    `, [name, logo || '', logo_code || '', address1, city, state, zip, country || 'USA', terms || 'Net 30', discount || 0, '']);
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
        const [rows] = await conn.execute("SELECT po_email, registration_email, po_sms, registration_sms FROM admin_settings WHERE id = 1");
        if (rows.length > 0) {
            console.log("[GET /admin/settings] Admin settings found.");
            res.json(rows[0]);
        } else {
            console.log("[GET /admin/settings] No admin settings found, returning defaults.");
            res.json({ po_email: "", registration_email: "", po_sms: "", registration_sms: "" });
        }
    } catch (err) {
        console.error("Error fetching admin settings:", err);
        res.status(500).json({ error: "Failed to retrieve admin settings" });
    } finally {
        if (conn) conn.end();
    }
});

app.post("/admin/settings", requireAdmin, async (req, res) => {
    const { po_email, registration_email, po_sms, registration_sms } = req.body;
    console.log(`[POST /admin/settings] Saving admin settings: PO Email=${po_email}, Reg Email=${registration_email}, PO SMS=${po_sms}, Reg SMS=${registration_sms}`);
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [existing] = await conn.execute("SELECT id FROM admin_settings WHERE id = 1");
        if (existing.length > 0) {
            await conn.execute(
                "UPDATE admin_settings SET po_email = ?, registration_email = ?, po_sms = ?, registration_sms = ? WHERE id = 1",
                [po_email, registration_email, po_sms || null, registration_sms || null]
            );
            console.log("[POST /admin/settings] Admin settings updated.");
        } else {
            await conn.execute(
                "INSERT INTO admin_settings (id, po_email, registration_email, po_sms, registration_sms) VALUES (1, ?, ?, ?, ?)",
                [po_email, registration_email, po_sms || null, registration_sms || null]
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


    // Carrier badge — inline styled text, no outbound HTTP requests needed
    let carrierLogoHtml = '';
    const badgeBase = 'position:absolute;top:325px;right:20px;z-index:100;padding:4px 10px;border-radius:4px;font-weight:bold;font-size:14px;letter-spacing:1px;';
    if (shippingMethodLower.includes("fedex")) {
        carrierLogoHtml = `<span style="${badgeBase}background:#4d148c;color:#ff6600;">Fed<span style="color:#fff;">Ex</span></span>`;
    } else if (shippingMethodLower.includes("ups")) {
        carrierLogoHtml = `<span style="${badgeBase}background:#351c15;color:#ffb500;">UPS</span>`;
    } else if (shippingMethodLower.includes("dhl")) {
        carrierLogoHtml = `<span style="${badgeBase}background:#FFCC00;color:#D40511;">DHL</span>`;
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
        let poEmailRecipient = ["Greg@ChicagoStainless.com"]; // Default fallback
        let poSmsRecipient = [];
        try {
            const [settingsRows] = await conn.execute("SELECT po_email, po_sms FROM admin_settings WHERE id = 1");
            if (settingsRows.length > 0 && settingsRows[0].po_email) {
                poEmailRecipient = settingsRows[0].po_email.split(/[;,]/).map(e => e.trim()).filter(Boolean);
            }
            if (settingsRows.length > 0 && settingsRows[0].po_sms) {
                poSmsRecipient = settingsRows[0].po_sms.split(/[;,]/).map(n => n.trim()).filter(Boolean);
            }
        } catch (settingsErr) {
            console.error("Error fetching PO email/SMS recipient from admin_settings:", settingsErr);
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

        // Send SMS notification if phone numbers are configured
        if (poSmsRecipient.length) {
            sendSmsNotification(poSmsRecipient,
                `New Website Order — ${company.name}, PO# ${poNumber}, by ${orderedBy}. Check your email for the full details.`
            );
        }

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
            query += " AND o.date >= ?";
            params.push(startDate);
        }
        if (endDate) {
            query += " AND o.date < DATE_ADD(?, INTERVAL 1 DAY)";
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
            // mysql2 auto-parses JSON columns, but if the actual column type is TEXT it returns a
            // string. Handle both cases defensively so items always ends up as an array.
            if (Array.isArray(order.items)) {
                parsedItems = order.items;
            } else if (typeof order.items === 'string' && order.items.trim()) {
                try { parsedItems = JSON.parse(order.items); } catch(e) {
                    console.warn(`Items for order ${order.id} failed JSON.parse:`, e.message);
                    parsedItems = [];
                }
            }
            if (!Array.isArray(parsedItems)) {
                console.warn(`Items for order ${order.id} is not an array after parsing, received:`, parsedItems);
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
                logo_code VARCHAR(100),
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

        // Check if 'logo_code' column exists in 'companies' table before adding it
        const [logoCodeColumnCheck] = await conn.execute(`
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'companies' AND COLUMN_NAME = 'logo_code';
        `, [dbConnectionConfig.database]);

        if (logoCodeColumnCheck.length === 0) {
            await conn.execute(`
                ALTER TABLE companies ADD COLUMN logo_code VARCHAR(100) AFTER logo;
            `);
            console.log("'logo_code' column added to 'companies' table.");
        } else {
            console.log("'logo_code' column already exists in 'companies' table.");
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
                registration_email VARCHAR(255),
                po_sms VARCHAR(500),
                registration_sms VARCHAR(500)
            ) ENGINE=InnoDB;
        `);
        console.log("'admin_settings' table checked/created.");

        // Migrate existing admin_settings table: add SMS columns if they don't exist
        const [poSmsColCheck] = await conn.execute(`
            SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'admin_settings' AND COLUMN_NAME = 'po_sms';
        `, [dbConnectionConfig.database]);
        if (poSmsColCheck.length === 0) {
            await conn.execute(`ALTER TABLE admin_settings ADD COLUMN po_sms VARCHAR(500);`);
            console.log("'po_sms' column added to 'admin_settings' table.");
        }
        const [regSmsColCheck] = await conn.execute(`
            SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'admin_settings' AND COLUMN_NAME = 'registration_sms';
        `, [dbConnectionConfig.database]);
        if (regSmsColCheck.length === 0) {
            await conn.execute(`ALTER TABLE admin_settings ADD COLUMN registration_sms VARCHAR(500);`);
            console.log("'registration_sms' column added to 'admin_settings' table.");
        }

        // Insert default admin settings if not exists
        const [settingsRows] = await conn.execute("SELECT id FROM admin_settings WHERE id = 1");
        if (settingsRows.length === 0) {
            await conn.execute(
                "INSERT INTO admin_settings (id, po_email, registration_email, po_sms, registration_sms) VALUES (1, ?, ?, NULL, NULL)",
                ["Greg@ChicagoStainless.com", "Greg@ChicagoStainless.com"]
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
