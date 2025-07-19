require('dotenv').config(); // Loads environment variables for emailing
const express = require("express");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise"); // Ensure you're using the promise version
const path = require("path");
const nodemailer = require("nodemailer");
const os = require('os'); // NEW: Import os module
const { v4: uuidv4 } = require('uuid'); // NEW: Import uuid for unique temp directory names
const fs = require('fs/promises'); // NEW: For async file system operations

// NEW: Import puppeteer-extra and the stealth plugin
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
// NEW: Import @sparticuz/chromium for Render compatibility
const chromium = require('@sparticuz/chromium');

// Apply the stealth plugin to puppeteer
puppeteer.use(StealthPlugin());

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

// NEW: Import the MySQL session store
const MySQLStore = require('express-mysql-session')(session);

const app = express();
const PORT = process.env.PORT || 3000;

// Log the port being used
console.log(`Application will attempt to listen on port: ${PORT}`);


// Separate database configuration for direct MySQL2 connections
const dbConnectionConfig = {
  host: "192.254.232.38",
  user: "gmistarz_cse",
  password: "Csec@1280",
  database: "gmistarz_cse",
  // No session-specific options here
  // port: 3306, // Uncomment if your MySQL server is not on the default port
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
  connectionLimit: 1               // Limit connections for the session store
};

// NEW: Configure the session store instance
const sessionStore = new MySQLStore(sessionStoreOptions);


const allowedOrigins = [
  "https://www.chicagostainless.com",
  "https://checkout-backend-jvyx.onrender.com",
  "https://2o7myf7j5pj32q9x8ip2u5h5qlghtdamz9t44ucn4mlv3r76zx-h775241406.scf.usercontent.goog"
];

// --- CORS Configuration ---
const corsOptions = {
  origin: function (origin, callback) {
    console.log(`[CORS Check] Request Origin: ${origin}`); // Log the incoming origin
    if (!origin || allowedOrigins.includes(origin)) {
      console.log(`[CORS Check] Origin ${origin} ALLOWED.`);
      callback(null, true);
    } else {
      console.error(`[CORS Check] Origin ${origin} NOT ALLOWED.`);
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200, // Some legacy browsers (IE11, various SmartTVs) choke on 204
  // Explicitly allow headers that might be sent in preflight
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'] // Explicitly list allowed methods
};

app.use(cors(corsOptions));
// Removed: app.options('*', cors(corsOptions)); // This line was causing the TypeError

// --- Session & Body Parsing ---
app.use(express.json());
app.set("trust proxy", 1); // Essential for 'secure: true' cookies when behind a proxy/load balancer like Render

app.use(session({
  secret: "secret-key", // Replace with a strong, unique secret key in production
  resave: false,
  saveUninitialized: false,
  store: sessionStore, // <-- THIS IS THE CRUCIAL CHANGE for persistent sessions
  cookie: {
    sameSite: "none",  // Required for cross-site cookies to be sent from different origins
    secure: true,      // Required for sameSite: "none" and highly recommended for production (Render provides HTTPS)
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// --- Nodemailer Transporter Configuration ---
// IMPORTANT: Replace with your actual email service credentials or environment variables.
// Note: For some SMTP servers, the 'from' address in mailOptions must match or be an alias
// of the 'user' in the auth object below. If you encounter issues, ensure your SMTP
// provider allows sending from arbitrary 'from' addresses, or consider using your
// authenticated email address as the 'from' address in mailOptions.
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST, // Using environment variable
    port: process.env.SMTP_PORT, // Using environment variable
    secure: process.env.SMTP_SECURE === 'true', // Using environment variable, convert string to boolean
    auth: {
        user: process.env.EMAIL_USER, // Using environment variable
        pass: process.env.EMAIL_PASS // Using environment variable
    },
    tls: {
        // Do not fail on invalid certs
        rejectUnauthorized: false
    }
});

// NEW: Log Nodemailer configuration details (excluding password for security)
console.log(`Nodemailer Config: Host=${process.env.SMTP_HOST}, Port=${process.env.SMTP_PORT}, Secure=${process.env.SMTP_SECURE}, User=${process.env.EMAIL_USER}`);


// --- Helper Middleware for Admin Check ---
const requireAdmin = (req, res, next) => {
    // console.log("Checking session for admin role:", req.session.user); // Optional: for more debugging
    if (!req.session.user || req.session.user.role !== "admin") {
        return res.status(403).json({ error: "Forbidden: Admin access required" }); // More specific message
    }
    next();
};

// --- NEW: Helper Middleware for Authenticated User Check ---
const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ error: "Unauthorized: Login required" });
    }
    next();
};

// --- NEW: Helper Middleware for Company Access Authorization ---
// This middleware checks if the user is authenticated and if their company_id
// matches the company_id being accessed in the request.
// Admins can access any company's data.
const authorizeCompanyAccess = async (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ error: "Unauthorized: Login required" });
    }

    // Allow admins to access any company's data
    if (req.session.user.role === "admin") {
        return next();
    }

    const userCompanyId = req.session.user.companyId;

    // Determine the companyId from the request based on route
    let requestedCompanyId = null;
    if (req.params.companyId) { // For routes like /api/shipto/:companyId
        requestedCompanyId = parseInt(req.params.companyId, 10);
    } else if (req.body.companyId) { // For POST routes like /api/shipto (add new)
        requestedCompanyId = parseInt(req.body.companyId, 10);
    } else if (req.params.addressId) { // For PUT/DELETE/SET_DEFAULT on /api/shipto/:addressId
        let conn;
        try {
            conn = await mysql.createConnection(dbConnectionConfig);
            const [rows] = await conn.execute("SELECT company_id FROM shipto_addresses WHERE id = ?", [req.params.addressId]);
            if (rows.length > 0) {
                requestedCompanyId = rows[0].company_id;
            }
        } catch (err) {
            console.error("Error fetching company_id for address:", err);
            return res.status(500).json({ error: "Server error while authorizing company access" });
        } finally {
            if (conn) conn.end();
        }
    }

    // For the submit-order route, we assume the user's companyId is implicitly linked to the order.
    // We don't need a requestedCompanyId from params/body for this specific route's authorization,
    // but we ensure the user is authenticated and has a companyId.
    if (req.path === '/submit-order' && !userCompanyId) {
        return res.status(403).json({ error: "Forbidden: User not associated with a company." });
    }


    if (requestedCompanyId === null || userCompanyId !== requestedCompanyId) {
        // Only apply this check if a specific companyId was requested in the URL/body
        // and it doesn't match the user's companyId, or if no companyId was found
        // but the route requires it (e.g., shipto management).
        // For /submit-order, this block will be skipped unless a companyId param was explicitly passed.
        if (req.path.startsWith('/api/shipto/') || req.path === '/api/shipto') {
            return res.status(403).json({ error: "Forbidden: You can only access data for your own company." });
        }
    }

    next();
};


// --- Authentication Routes ---

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let conn; // Declare conn outside try-finally to ensure it's accessible for closing
  console.log(`[Login Route] Attempting login for email: ${email}`);
  try {
    console.log("[Login Route] Attempting to create database connection...");
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    console.log("[Login Route] Database connection established.");

    const [users] = await conn.execute("SELECT * FROM users WHERE email = ?", [email]);
    console.log(`[Login Route] Query result for user ${email}:`, users);

    const user = users[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      console.log("[Login Route] Invalid credentials.");
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Set user data in session
    req.session.user = { 
        id: user.id, 
        email: user.email, 
        role: user.role, 
        companyId: user.company_id,
        firstName: user.first_name, // Include first name
        lastName: user.last_name     // Include last name
    };
    
    // Log for debugging on Render
    console.log(`[Login Success] req.session.user set to: ${JSON.stringify(req.session.user)}`);
    
    res.json({ message: "Login successful", role: user.role });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed due to server error" });
  } finally {
    if (conn) {
        conn.end(); // Ensure connection is closed
        console.log("[Login Route] Database connection closed.");
    }
  }
});

app.get("/user-profile", requireAuth, async (req, res) => { // Use requireAuth
  console.log("[User Profile Route] Route hit.");
  const { user } = req.session;
  console.log("[User Profile Route] Session user:", user);

  // The session 'user' object already contains most of the profile data needed.
  // We can directly send it, or fetch from DB if more fields are needed.
  // For simplicity, sending directly from session, ensuring it includes first_name and last_name.
  if (user) {
      console.log("[User Profile Route] Sending user profile from session.");
      res.json({
          email: user.email,
          role: user.role,
          company_id: user.companyId,
          first_name: user.firstName,
          last_name: user.lastName
      });
  } else {
      // This case should ideally be caught by requireAuth, but as a fallback:
      console.log("[User Profile Route] User not found in session (should be caught by requireAuth).");
      res.status(401).json({ error: "Not logged in" });
  }
});

// MODIFIED: Moved this route definition to appear BEFORE /user/:userId
app.get("/user/company-details", requireAuth, async (req, res) => {
  let userCompanyId = req.session.user.companyId; // Declare with let to allow reassignment
  console.log(`[User Company Details] User ID: ${req.session.user.id}, Company ID from session: ${userCompanyId}`);
  console.log(`[User Company Details] Type of userCompanyId (before parse): ${typeof userCompanyId}`);

  // Explicitly parse to an integer to ensure type consistency for the SQL query
  userCompanyId = parseInt(userCompanyId, 10);
  console.log(`[User Company Details] Type of userCompanyId (after parse): ${typeof userCompanyId}, Value: ${userCompanyId}`);


  if (isNaN(userCompanyId) || userCompanyId <= 0) { // Check if parsing resulted in NaN or an invalid ID
    console.error("[User Company Details] No valid company ID associated with this user in session after parsing.");
    return res.status(404).json({ error: "No company associated with this user." });
  }

  let conn;
  try {
    console.log("[User Company Details] Attempting to create database connection...");
    conn = await mysql.createConnection(dbConnectionConfig);
    console.log("[User Company Details] Database connection established.");

    // NEW: Log all companies to verify table visibility
    const [allCompanies] = await conn.execute("SELECT id, name FROM companies");
    console.log("[User Company Details] All companies found in DB:", allCompanies);

    console.log("[User Company Details] Fetching specific company details for ID:", userCompanyId);
    // Using direct parameter binding for the integer ID
    const [companies] = await conn.execute(
      "SELECT name, address1, city, state, zip, country, terms, discount, notes FROM companies WHERE id = ?", // Re-added notes
      [userCompanyId]
    );
    console.log("[User Company Details] Raw query result (companies array for specific ID):", companies); // Log the actual result

    if (companies.length === 0) {
      console.error(`[User Company Details] Company not found in DB for ID: ${userCompanyId}. Query returned no rows.`);
      return res.status(404).json({ error: "Company not found for this user." });
    }
    console.log("[User Company Details] Successfully fetched company details:", companies[0]);
    res.json(companies[0]);
  } catch (err) {
    console.error("Error in /user/company-details route:", err); // Log the full error object
    res.status(500).json({ error: "Failed to retrieve user's company details." });
  } finally {
    if (conn) {
      conn.end();
      console.log("[User Company Details] Database connection closed.");
    }
  }
});

// NEW: Get single user by ID (for editing) - This route should come AFTER /user/company-details
app.get("/user/:userId", requireAdmin, async (req, res) => {
    const { userId } = req.params;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [users] = await conn.execute(
            "SELECT id, email, first_name, last_name, phone, role, company_id FROM users WHERE id = ?",
            [userId]
        );
        const user = users[0];
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        res.json(user);
    } catch (err) {
        console.error("Error fetching user by ID:", err);
        res.status(500).json({ error: "Failed to retrieve user details" });
    } finally {
        if (conn) conn.end();
    }
});


app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout failed:", err);
      return res.status(500).json({ error: "Logout failed" });
    }
    // Clear the session cookie from the client
    res.clearCookie("connect.sid", { path: "/", sameSite: "none", secure: true }); // Ensure cookie options match the session setup
    res.json({ message: "Logged out" });
  });
});

// --- NEW: Registration Endpoints ---

app.post("/register-company", async (req, res) => {
  const { name, address1, city, state, zip, country, terms, logo, discount } = req.body; // Removed notes
  if (!name || !address1 || !city || !state || !zip) {
    return res.status(400).json({ error: "Company name, address, city, state, and zip are required." });
  }
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [result] = await conn.execute(
      `INSERT INTO companies (name, logo, address1, city, state, zip, country, terms, discount, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [name, logo || '', address1, city, state, zip, country || 'USA', terms || 'Net 30', discount || 0, ''] // Re-added notes value (empty string)
    );
    res.status(201).json({ message: "Company registered successfully", companyId: result.insertId, id: result.insertId }); // Added id to response
  } catch (err) {
    console.error("Failed to register company:", err);
    // Check for duplicate entry error (e.g., if company name is unique)
    if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: "Company with this name already exists." });
    }
    res.status(500).json({ error: "Failed to register company due to server error" });
  } finally {
    if (conn) conn.end();
  }
});

app.post("/register-user", async (req, res) => {
  const { email, firstName, lastName, phone, password, companyId } = req.body;
  // Role is hardcoded to 'user' for new registrations from checkout
  const role = "user"; 

  if (!email || !firstName || !lastName || !password || !companyId) {
    return res.status(400).json({ error: "Email, first name, last name, password, and company ID are required." });
  }
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    // Check if user with this email already exists
    const [existingUsersByEmail] = await conn.execute("SELECT id FROM users WHERE email = ?", [email]);
    if (existingUsersByEmail.length > 0) {
      return res.status(409).json({ error: "User with this email already exists." });
    }

    // NEW: Check if user with same first_name and last_name exists within the same company
    const [existingUsersByName] = await conn.execute(
        "SELECT id FROM users WHERE LOWER(first_name) = LOWER(?) AND LOWER(last_name) = LOWER(?) AND company_id = ?",
        [firstName, lastName, companyId]
    );
    if (existingUsersByName.length > 0) {
        return res.status(409).json({ error: "User Name Already Exists" }); // Specific message for frontend
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await conn.execute(
      `INSERT INTO users (email, first_name, last_name, phone, role, password, company_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [email, firstName, lastName, phone || '', role, hashedPassword, companyId]
    );
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Failed to register user:", err);
    res.status(500).json({ error: "Failed to register user due to server error" });
  } finally {
    if (conn) conn.end();
  }
});

// NEW: Endpoint to get company by name (case-insensitive)
app.get("/company-by-name/:name", async (req, res) => {
  const companyName = req.params.name;
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [companies] = await conn.execute(
      "SELECT id, name FROM companies WHERE LOWER(name) = LOWER(?)", // Case-insensitive comparison
      [companyName]
    );
    if (companies.length > 0) {
      res.json({ exists: true, company: companies[0] });
    } else {
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
// These remain requireAdmin as they are for overall company management
app.get("/companies", requireAdmin, async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    const [companies] = await conn.execute("SELECT *, discount, notes FROM companies"); // Re-added notes in select
    res.json(companies);
  } catch (err) {
    console.error("Failed to retrieve companies:", err);
    res.status(500).json({ error: "Failed to retrieve companies" });
  } finally {
    if (conn) conn.end();
  }
});

// Updated: Removed address2 from edit-company route
app.post("/edit-company", requireAdmin, async (req, res) => {
  const { id } = req.body;
  if (!id) {
    return res.status(400).json({ error: "Company ID is required for update." });
  }

  const fieldsToUpdate = [];
  const values = [];

  // Dynamically build the SET clause for the UPDATE query
  for (const key in req.body) {
    if (key !== 'id') { // Exclude 'id' from the SET clause
      fieldsToUpdate.push(`${key} = ?`);
      values.push(req.body[key]);
    }
  }

  if (fieldsToUpdate.length === 0) {
    return res.status(400).json({ error: "No fields provided for update." });
  }

  values.push(id); // Add the ID for the WHERE clause

  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    await conn.execute(
      `UPDATE companies SET ${fieldsToUpdate.join(', ')} WHERE id = ?`,
      values
    );
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
    name, logo, address1, city, state, zip, country, terms, discount // Removed notes
  } = req.body;
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    const [result] = await conn.execute(`
      INSERT INTO companies (name, logo, address1, city, state, zip, country, terms, discount, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [name, logo, address1, city, state, zip, country, terms, discount, '']); // Re-added notes as empty string
    res.status(200).json({ message: "Company created", id: result.insertId }); // Added id to response
  } catch (err) {
    console.error("Failed to create company:", err);
    res.status(500).json({ error: "Failed to create company" });
  } finally {
    if (conn) conn.end();
  }
});

app.post("/delete-company", requireAdmin, async (req, res) => {
  const { id } = req.body;
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    await conn.execute("DELETE FROM companies WHERE id = ?", [id]); 
    res.json({ message: "Company deleted" });
  } catch (err) {
    console.error("Failed to delete company:", err);
    res.status(500).json({ error: "Failed to delete company" });
  } finally {
    if (conn) conn.end();
  }
});

// NEW: Temporary route to test company details retrieval by hardcoding ID 1
app.get("/test-company-details", async (req, res) => {
  const testCompanyId = 1; // Hardcode company ID 1 for testing
  console.log(`[Test Company Details] Attempting to fetch details for hardcoded ID: ${testCompanyId}`);

  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    console.log("[Test Company Details] Database connection established.");

    const [companies] = await conn.execute(
      "SELECT name, address1, city, state, zip, country, terms, discount, notes FROM companies WHERE id = ?", // Re-added notes
      [testCompanyId]
    );
    console.log("[Test Company Details] Raw query result (companies array for hardcoded ID):", companies);

    if (companies.length === 0) {
      console.error(`[Test Company Details] Company not found in DB for hardcoded ID: ${testCompanyId}. Query returned no rows.`);
      return res.status(404).json({ error: `Test company with ID ${testCompanyId} not found.` });
    }
    console.log("[Test Company Details] Successfully fetched company details:", companies[0]);
    res.json(companies[0]);
  } catch (err) {
    console.error("Error in /test-company-details route:", err);
    res.status(500).json({ error: "Failed to retrieve test company details." });
  } finally {
    if (conn) {
      conn.end();
      console.log("[Test Company Details] Database connection closed.");
    }
  }
});


app.post("/add-user", async (req, res) => {
  const { email, firstName, lastName, phone, role, password, companyId } = req.body;
  if (!email || !companyId || !password) {
    return res.status(400).json({ error: "Email, password, and companyId are required." });
  }
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    const hashedPassword = await bcrypt.hash(password, 10);
    await conn.execute(
      `INSERT INTO users (email, first_name, last_name, phone, role, password, company_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [email, firstName, lastName, phone, role, hashedPassword, companyId]
    );
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
  const { id, email, firstName, lastName, phone, role, password } = req.body;
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      await conn.execute(
        `UPDATE users SET email = ?, first_name = ?, last_name = ?, phone = ?, role = ?, password = ? WHERE id = ?`,
        [email, firstName, lastName, phone, role, hashedPassword, id]
      );
    } else {
      await conn.execute(
        `UPDATE users SET email = ?, first_name = ?, last_name = ?, phone = ?, role = ? WHERE id = ?`,
        [email, firstName, lastName, phone, role, id]
      );
    }
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
  if (!id) return res.status(400).json({ error: "Missing user ID" });
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    await conn.execute("DELETE FROM users WHERE id = ?", [id]);
    res.json({ message: "User deleted" });
  } catch (err) {
    console.error("Delete user error:", err);
    res.status(500).json({ error: "Failed to delete user" });
  } finally {
    if (conn) conn.end();
  }
});

app.get("/company-users/:companyId", requireAdmin, async (req, res) => {
  const { companyId } = req.params;
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    // Select only necessary fields for display
    const [users] = await conn.execute("SELECT id, email, first_name, last_name, phone, role FROM users WHERE company_id = ?", [companyId]);
    res.json(users);
  } catch (err) {
    console.error("Failed to retrieve users:", err);
    res.status(500).json({ error: "Failed to retrieve users" });
  } finally {
    if (conn) conn.end();
  }
});

// --- Ship To Addresses Routes ---

// Get all ship-to addresses for a company
app.get("/api/shipto/:companyId", authorizeCompanyAccess, async (req, res) => { // Use authorizeCompanyAccess
    const { companyId } = req.params;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
        // Include company_name in the select query
        const [addresses] = await conn.execute("SELECT id, company_id, name, company_name, address1, city, state, zip, country, is_default FROM shipto_addresses WHERE company_id = ?", [companyId]);
        res.json(addresses);
    } catch (err) {
        console.error("Error fetching ship-to addresses:", err);
        res.status(500).json({ error: "Failed to retrieve ship-to addresses" });
    } finally {
        if (conn) conn.end();
    }
});

app.post("/api/shipto", authorizeCompanyAccess, async (req, res) => { // Use authorizeCompanyAccess
    const { companyId, name, company_name, address1, city, state, zip, country, is_default } = req.body; 
    
    if (!companyId || !name || !address1 || !city || !state || !zip) { // 'name' is now 'Contact Name'
        return res.status(400).json({ error: "Missing required fields (Company ID, Contact Name, Address, City, State, Zip)." });
    }
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
        // If the new address is set as default, first unset all others for this company
        if (is_default) {
             await conn.execute(
                `UPDATE shipto_addresses SET is_default = 0 WHERE company_id = ?`,
                [companyId]
            );
        }
        // Include company_name in the insert statement
        const [result] = await conn.execute(
            `INSERT INTO shipto_addresses (company_id, name, company_name, address1, city, state, zip, country, is_default) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [companyId, name, company_name || null, address1, city, state, zip, country, is_default ? 1 : 0]
        );
        res.status(201).json({ id: result.insertId, message: "Address added successfully" });
    } catch (err) {
        console.error("Error adding ship-to address:", err);
        res.status(500).json({ error: "Failed to add ship-to address" });
    } finally {
        if (conn) conn.end();
    }
});

app.put("/api/shipto/:addressId", authorizeCompanyAccess, async (req, res) => { // Use authorizeCompanyAccess
    const { addressId } = req.params;
    const { name, company_name, address1, city, state, zip, country } = req.body; 
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
        // Include company_name in the update statement
        await conn.execute(
            `UPDATE shipto_addresses SET name = ?, company_name = ?, address1 = ?, city = ?, state = ?, zip = ?, country = ? WHERE id = ?`,
            [name, company_name || null, address1, city, state, zip, country, addressId]
        );
        res.json({ message: "Address updated successfully" });
    } catch (err) {
        console.error("Error updating ship-to address:", err);
        res.status(500).json({ error: "Failed to update ship-to address" });
    } finally {
        if (conn) conn.end();
    }
});

// MODIFIED: /api/shipto/:addressId/set-default route to allow admins to set default for any company
app.put("/api/shipto/:addressId/set-default", authorizeCompanyAccess, async (req, res) => { // Changed middleware to authorizeCompanyAccess
    const { addressId } = req.params;

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
        
        // 1. Determine the companyId associated with the addressId
        const [addressRows] = await conn.execute("SELECT company_id FROM shipto_addresses WHERE id = ?", [addressId]);
        
        if (addressRows.length === 0) {
            return res.status(404).json({ error: "Address not found." });
        }
        
        const targetCompanyId = addressRows[0].company_id;

        // The authorizeCompanyAccess middleware now handles the permission check.
        // If the user is an admin, they will pass. If they are a regular user,
        // authorizeCompanyAccess will ensure targetCompanyId matches their companyId.
        // Therefore, the explicit check `if (req.session.user.companyId !== targetCompanyId)` is removed from here.

        await conn.beginTransaction(); // Start a transaction

        // 2. Unset the 'is_default' flag for all other addresses of this target company
        await conn.execute(
            `UPDATE shipto_addresses SET is_default = 0 WHERE company_id = ? AND id != ?`,
            [targetCompanyId, addressId]
        );

        // 3. Set the 'is_default' flag to 1 for the selected address
        await conn.execute(
            `UPDATE shipto_addresses SET is_default = 1 WHERE id = ?`,
            [addressId]
        );

        await conn.commit(); // Commit the transaction
        res.json({ message: "Default shipping address updated successfully." });

    } catch (err) {
        if (conn) {
            await conn.rollback(); // Rollback on error
        }
        console.error("Error setting default shipping address:", err);
        res.status(500).json({ error: "Failed to set default shipping address." });
    } finally {
        if (conn) conn.end();
    }
});

app.delete("/api/shipto/:addressId", authorizeCompanyAccess, async (req, res) => { // Use authorizeCompanyAccess
    const { addressId } = req.params;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
        await conn.execute("DELETE FROM shipto_addresses WHERE id = ?", [addressId]);
        res.json({ message: "Address deleted successfully" });
    } catch (err) {
        console.error("Error deleting ship-to address:", err);
        res.status(500).json({ error: "Failed to delete ship-to address" });
    } finally {
        if (conn) conn.end();
    }
});

// Helper function to generate HTML for the order email
function generateOrderHtmlEmail(orderData) {
    let itemsHtml = orderData.items.map(item => `
        <tr>
            <td style="border: 1px solid #ccc; padding: 8px; text-align: center;">${item.quantity}</td>
            <td style="border: 1px solid #ccc; padding: 8px;">${item.partNo}</td>
            <td style="border: 1px solid #ccc; padding: 8px; text-align: right;">$${item.price.toFixed(2)}</td>
            <td style="border: 1px solid #ccc; padding: 8px; text-align: right;">$${(item.price * item.quantity).toFixed(2)}</td>
            <td style="border: 1px solid #ccc; padding: 8px;">${item.note || ''}</td>
        </tr>
    `).join('');

    const totalQuantity = orderData.items.reduce((sum, item) => sum + item.quantity, 0);
    const totalPrice = orderData.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    return `
        <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.05);">
            <div style="text-align: center; margin-bottom: 20px;">
                <img src="https://www.chicagostainless.com/graphics/cse_logo.png" alt="Company Logo" style="height: 60px;">
                <h1 style="color: #333;">Order Information</h1>
            </div>
            
            <p>Order details:</p>

            <div style="display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px;">
                <div style="flex: 1; min-width: 300px; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <h2 style="margin-top: 0; color: #555;">Billed To:</h2>
                    <p style="white-space: pre-wrap;">${orderData.billingAddress}</p>
                    <p><strong>Ordered By:</strong> ${orderData.orderedBy}</p>
                    <p><strong>PO#:</strong> ${orderData.poNumber}</p>
                    <p><strong>Terms:</strong> ${orderData.terms || 'N/A'}</p>
                </div>
                <div style="flex: 1; min-width: 300px; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <h2 style="margin-top: 0; color: #555;">Ship To:</h2>
                    <p style="white-space: pre-wrap;">${orderData.shippingAddress}</p>
                    <p><strong>ATTN:</strong> ${orderData.attn || 'N/A'}</p>
                    <p><strong>Tag#:</strong> ${orderData.tag || 'N/A'}</p>
                    <p><strong>Shipping Method:</strong> ${orderData.shippingMethod}</p>
                    <p><strong>Carrier Account#:</strong> ${orderData.carrierAccount || 'N/A'}</p>
                </div>
            </div>

            <h2 style="color: #555;">Order Summary</h2>
            <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                <thead>
                    <tr>
                        <th style="border: 1px solid #ccc; padding: 8px; background-color: #f2f2f2; text-align: center;">Qty</th>
                        <th style="border: 1px solid #ccc; padding: 8px; background-color: #f2f2f2;">Part Number</th>
                        <th style="border: 1px solid #ccc; padding: 8px; background-color: #f2f2f2; text-align: right;">Unit Price</th>
                        <th style="border: 1px solid #ccc; padding: 8px; background-color: #f2f2f2; text-align: right;">Total</th>
                        <th style="border: 1px solid #ccc; padding: 8px; background-color: #f2f2f2;">Note</th>
                    </tr>
                </thead>
                <tbody>
                    ${itemsHtml}
                </tbody>
            </table>
            <p style="font-weight: bold; text-align: right;">Item Count: ${totalQuantity}</p>
            <p style="font-weight: bold; text-align: right;">Total Price: $${totalPrice.toFixed(2)}</p>

            <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; color: #777;">
                <strong>Chicago Stainless Equipment, Inc.</strong><br>
                1280 SW 34th St<br>
                Palm City, FL 34990 USA<br>
                772-781-1441
            </div>
        </div>
    `;
}

// NEW: Function to generate PDF from HTML content
async function generatePdfFromHtml(htmlContent) {
    let browser;
    let userDataDir; // Declare userDataDir here
    try {
        // Create a unique temporary directory for Puppeteer's user data
        userDataDir = path.join(os.tmpdir(), `puppeteer_user_data_${uuidv4()}`);
        await fs.mkdir(userDataDir, { recursive: true });
        console.log(`Created temporary user data directory: ${userDataDir}`);

        // Use @sparticuz/chromium for executable path and args
        browser = await puppeteer.launch({
            args: [...chromium.args, '--disable-gpu', '--disable-dev-shm-usage', '--no-sandbox', '--disable-setuid-sandbox'], // Include necessary args for Render
            executablePath: await chromium.executablePath(), // Get the path from chromium package
            headless: chromium.headless, // Use recommended headless setting
            ignoreHTTPSErrors: true, // Sometimes useful for local dev or specific setups
            userDataDir: userDataDir // NEW: Use the unique temporary directory
        });
        const page = await browser.newPage();

        // Set content of the page
        await page.setContent(htmlContent, {
            waitUntil: 'networkidle0' // Wait until network is idle
        });

        // Generate PDF
        const pdfBuffer = await page.pdf({
            format: 'Letter', // Or 'A4', etc.
            printBackground: true, // Ensure background colors/images are printed
            margin: {
                top: '0.5in',
                right: '0.5in',
                bottom: '0.5in',
                left: '0.5in'
            }
        });
        console.log(`PDF generated successfully. Buffer size: ${pdfBuffer.length} bytes.`); // Log PDF buffer size
        return pdfBuffer;
    } catch (error) {
        console.error("Error generating PDF:", error);
        throw new Error("Failed to generate PDF for order confirmation.");
    } finally {
        if (browser) {
            await browser.close();
        }
        // NEW: Clean up the temporary user data directory
        if (userDataDir) {
            try {
                await fs.rm(userDataDir, { recursive: true, force: true });
                console.log(`Cleaned up temporary user data directory: ${userDataDir}`);
            } catch (cleanupError) {
                console.error(`Error cleaning up user data directory ${userDataDir}:`, cleanupError);
            }
        }
    }
}


app.post("/submit-order", requireAuth, async (req, res) => {
    const { poNumber, orderedBy, billingAddress, shippingAddress, shippingAddressId, attn, tag, shippingMethod, carrierAccount, items } = req.body;
    const userId = req.session.user.id;
    const companyId = req.session.user.companyId;
    const userEmail = req.session.user.email; // Get user's email from session

    console.log("Received order submission request with body:", JSON.stringify(req.body, null, 2));

    // Validate required fields based on the 'orders' table schema provided
    if (!userEmail || !poNumber || !billingAddress || !shippingAddress || !shippingMethod || !items || items.length === 0) {
        console.error("Validation Error: Missing required order fields or empty cart.", { userEmail, poNumber, billingAddress, shippingAddress, shippingMethod, items });
        return res.status(400).json({ error: "Missing required order fields or empty cart." });
    }

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        await conn.beginTransaction(); // Start a transaction

        // Insert into orders table, matching the provided schema exactly
        const [orderResult] = await conn.execute(
            `INSERT INTO orders (email, poNumber, billingAddress, shippingAddress, shippingMethod, carrierAccount, items, date)
             VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
            [userEmail, poNumber, billingAddress, shippingAddress, shippingMethod, carrierAccount, JSON.stringify(items)]
        );
        const orderId = orderResult.insertId;

        // Fetch company name for the email subject
        let companyName = "Unknown Company";
        if (companyId) {
            const [companyRows] = await conn.execute("SELECT name FROM companies WHERE id = ?", [companyId]);
            if (companyRows.length > 0) {
                companyName = companyRows[0].name;
            }
        }

        await conn.commit(); // Commit the transaction

        // NEW: Generate HTML for the email body and PDF
        const orderDetailsForEmail = {
            poNumber, orderedBy, billingAddress, shippingAddress, attn, tag, shippingMethod, carrierAccount, items,
            terms: req.body.terms // Ensure terms are passed if available
        };
        const orderHtmlContent = generateOrderHtmlEmail(orderDetailsForEmail);

        let pdfBuffer;
        try {
            pdfBuffer = await generatePdfFromHtml(orderHtmlContent);
            console.log("PDF generated successfully.");
        } catch (pdfError) {
            console.error("Failed to generate PDF, proceeding without attachment:", pdfError);
            // Optionally, send an email without the PDF if PDF generation fails
        }

        // NEW: Send order information email to you (the administrator) with PDF attachment
        const myEmailAddress = "Greg@ChicagoStainless.com"; // Your specified recipient email address

        const mailOptions = {
            from: process.env.EMAIL_USER, // Changed to use the authenticated email user for better deliverability
            to: myEmailAddress, // Email will be sent to this address
            subject: `${companyName} - PO# ${poNumber}`, // UPDATED SUBJECT LINE
            html: `
                <p>Hello,</p>
                <p>A new order has been submitted through the www.ChicagoStainless.com checkout page.</p>
                <p><strong>Order ID:</strong> ${orderId}</p>
                <p><strong>Customer Email:</strong> ${userEmail}</p>
                <p><strong>PO Number:</strong> ${poNumber}</p>
                <p>Please find the detailed order information attached as a PDF.</p>
                <p>Thank you.</p>
            `,
            attachments: pdfBuffer ? [
                {
                    filename: `Order_${orderId}_${poNumber}.pdf`,
                    content: pdfBuffer,
                    contentType: 'application/pdf'
                }
            ] : []
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending order notification email:", error);
                // This error should not prevent the frontend from receiving success
            } else {
                console.log("Order notification email sent:", info.response);
            }
        });

        res.status(200).json({ message: "Order submitted successfully! Notification email sent.", orderId: orderId });

    } catch (err) {
        if (conn) {
            await conn.rollback(); // Rollback on error
        }
        // Log the full error object for detailed debugging on the backend server
        console.error("Error submitting order (Backend):", err); 
        res.status(500).json({ error: "Failed to submit order due to server error." });
    } finally {
        if (conn) conn.end();
    }
});


// --- General Routes and Server Start ---

app.get("/", (req, res) => {
  res.redirect("/admin-dashboard.html"); 
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
}); 
