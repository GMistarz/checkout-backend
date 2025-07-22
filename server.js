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
  host: process.env.DB_HOST || "localhost", // Use environment variable
  user: process.env.DB_USER || "root",     // Use environment variable
  password: process.env.DB_PASSWORD || "password", // Use environment variable
  database: process.env.DB_NAME || "checkout_db",  // Use environment variable
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
  "http://localhost:8080",
  "http://localhost:3000",
  "https://checkout-frontend.onrender.com",
  "https://www.chicagostainless.com",
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

// --- Session & Body Parsing ---
app.use(express.json());
app.set("trust proxy", 1); // Essential for 'secure: true' cookies when behind a proxy/load balancer like Render

app.use(session({
  secret: process.env.SESSION_SECRET || "supersecretkey", // Use environment variable for secret
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


// --- Nodemailer Transporter Configuration ---
// IMPORTANT: Replace with your actual email service credentials or environment variables.
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_SECURE === 'true', // Convert string to boolean
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false // Do not fail on invalid certs
    }
});

// NEW: Log Nodemailer configuration details (excluding password for security)
console.log(`Nodemailer Config: Host=${process.env.EMAIL_HOST}, Port=${process.env.EMAIL_PORT}, Secure=${process.env.EMAIL_SECURE}, User=${process.env.EMAIL_USER}`);


// --- Helper Middleware for Admin Check ---
const requireAdmin = (req, res, next) => {
    if (!req.session.user || req.session.user.role !== "admin") {
        return res.status(403).json({ error: "Forbidden: Admin access required" });
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
            console.error("Error fetching company_id for authorization:", err);
            return res.status(500).json({ error: "Server error during authorization." });
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
        if (req.path.startsWith('/api/shipto/') || req.path === '/api/shipto') {
            return res.status(403).json({ error: "Forbidden: You can only access data for your own company." });
        }
    }

    next();
};


// Function to send order notification email (Admin)
async function sendOrderNotificationEmail(orderId, orderDetails, pdfBuffer) {
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [settings] = await conn.execute("SELECT po_email FROM admin_settings WHERE id = 1");
        const recipientEmail = settings[0]?.po_email || "Greg@ChicagoStainless.com"; // Fallback email

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: recipientEmail,
            subject: `New Website Order: #${orderId} - PO# ${orderDetails.poNumber}`,
            html: `
                <p>Dear Administrator,</p>
                <p>A new order has been submitted on the website.</p>
                <p><strong>Order ID:</strong> ${orderId}</p>
                <p><strong>PO Number:</strong> ${orderDetails.poNumber}</p>
                <p><strong>Ordered By:</strong> ${orderDetails.orderedBy}</p>
                <p><strong>Billing Address:</strong><br>${orderDetails.billingAddress.replace(/\n/g, '<br>')}</p>
                <p><strong>Shipping Address:</strong><br>${orderDetails.shippingAddress.replace(/\n/g, '<br>')}</p>
                <p><strong>Shipping Method:</strong> ${orderDetails.shippingMethod}</p>
                ${orderDetails.carrierAccount ? `<p><strong>Carrier Account #:</strong> ${orderDetails.carrierAccount}</p>` : ''}
                <p>The full order information is attached as a PDF.</p>
                <p>Thank you.</p>
            `,
            attachments: pdfBuffer ? [
                {
                    filename: `Order_${orderId}_${orderDetails.poNumber}.pdf`,
                    content: pdfBuffer,
                    contentType: 'application/pdf'
                }
            ] : []
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending order notification email:", error);
            } else {
                console.log("Order notification email sent:", info.response);
            }
        });
    } catch (err) {
        console.error("Error fetching admin PO email or sending order notification:", err);
    } finally {
        if (conn) conn.end();
    }
}

// Function to send registration notification email (Admin)
async function sendRegistrationNotificationEmail(companyName, userEmail, firstName, lastName, phone, companyId, role) {
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [settings] = await conn.execute("SELECT registration_email FROM admin_settings WHERE id = 1");
        const recipientEmail = settings[0]?.registration_email || "Greg@ChicagoStainless.com"; // Fallback email

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: recipientEmail,
            subject: `New Company Registration: ${companyName}`,
            html: `
                <p>Hello Admin,</p>
                <p>A new user has registered through the checkout page:</p>
                <ul>
                    <li><strong>Name:</strong> ${firstName} ${lastName}</li>
                    <li><strong>Email:</strong> ${userEmail}</li>
                    <li><strong>Phone:</strong> ${phone || 'N/A'}</li>
                    <li><strong>Company:</strong> ${companyName} (ID: ${companyId})</li>
                    <li><strong>Role:</strong> ${role}</li>
                </ul>
                <p>Please log into the admin dashboard to review and approve the company.</p>
                <p>Thank you.</p>
            `,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending registration notification email:", error);
            } else {
                console.log("Registration notification email sent:", info.response);
            }
        });
    } catch (err) {
        console.error("Error fetching admin registration email or sending registration notification:", err);
    } finally {
        if (conn) conn.end();
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
            from: process.env.EMAIL_USER,
            to: userEmail,
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

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending company approval email:", error);
            } else {
                console.log(`Company approval email sent to ${userEmail}:`, info.response);
            }
        });
    } catch (err) {
        console.error("Error sending company approval email:", err);
    } finally {
        if (conn) conn.end();
    }
}


// --- Authentication Routes ---

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let conn;
  console.log(`[Login Route] Attempting login for email: ${email}`);
  try {
    console.log("[Login Route] Attempting to create database connection...");
    conn = await mysql.createConnection(dbConnectionConfig);
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
        firstName: user.first_name,
        lastName: user.last_name
    };

    console.log(`[Login Success] req.session.user set to: ${JSON.stringify(req.session.user)}`);

    res.json({ message: "Login successful", role: user.role });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed due to server error" });
  } finally {
    if (conn) {
        conn.end();
        console.log("[Login Route] Database connection closed.");
    }
  }
});

app.get("/user-profile", requireAuth, async (req, res) => {
  console.log("[User Profile Route] Route hit.");
  const { user } = req.session;
  console.log("[User Profile Route] Session user:", user);

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
      console.log("[User Profile Route] User not found in session (should be caught by requireAuth).");
      res.status(401).json({ error: "Not logged in" });
  }
});

app.get("/user/company-details", requireAuth, async (req, res) => {
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
      "SELECT name, address1, city, state, zip, country, terms, discount, notes, approved, denied FROM companies WHERE id = ?",
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
    res.clearCookie("connect.sid", { path: "/", sameSite: "none", secure: true });
    res.json({ message: "Logged out" });
  });
});

// --- NEW: Registration Endpoints ---

app.post("/register-company", async (req, res) => {
  const { name, address1, city, state, zip, country, terms, logo, discount } = req.body;
  if (!name || !address1 || !city || !state || !zip) {
    return res.status(400).json({ error: "Company name, address, city, state, and zip are required." });
  }
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [result] = await conn.execute(
      `INSERT INTO companies (name, logo, address1, city, state, zip, country, terms, discount, notes, approved, denied)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE, FALSE)`, // Default to not approved, not denied
      [name, logo || '', address1, city, state, zip, country || 'USA', terms || 'Net 30', discount || 0, '']
    );
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

app.post("/register-user", async (req, res) => {
  const { email, firstName, lastName, phone, password, companyId } = req.body;
  const role = "user";

  if (!email || !firstName || !lastName || !password || !companyId) {
    return res.status(400).json({ error: "Email, first name, last name, password, and company ID are required." });
  }
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [existingUsersByEmail] = await conn.execute("SELECT id FROM users WHERE email = ?", [email]);
    if (existingUsersByEmail.length > 0) {
      return res.status(409).json({ error: "User with this email already exists." });
    }

    const [existingUsersByName] = await conn.execute(
        "SELECT id FROM users WHERE LOWER(first_name) = LOWER(?) AND LOWER(last_name) = LOWER(?) AND company_id = ?",
        [firstName, lastName, companyId]
    );
    if (existingUsersByName.length > 0) {
        return res.status(409).json({ error: "User Name Already Exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await conn.execute(
      `INSERT INTO users (email, first_name, last_name, phone, role, password, company_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [email, firstName, lastName, phone || '', role, hashedPassword, companyId]
    );

    // Send notification email to admin
    await sendRegistrationNotificationEmail(req.body.companyName || "New Company", email, firstName, lastName, phone, companyId, role);

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Failed to register user:", err);
    res.status(500).json({ error: "Failed to register user due to server error" });
  } finally {
    if (conn) conn.end();
  }
});

app.get("/company-by-name/:name", async (req, res) => {
  const companyName = req.params.name;
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [companies] = await conn.execute(
      "SELECT id, name FROM companies WHERE LOWER(name) = LOWER(?)",
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
app.get("/companies", requireAdmin, async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [companies] = await conn.execute("SELECT id, name, logo, address1, city, state, zip, country, terms, discount, notes, approved, denied FROM companies ORDER BY name ASC");
    res.json(companies);
  } catch (err) {
    console.error("Failed to retrieve companies:", err);
    res.status(500).json({ error: "Failed to retrieve companies" });
  } finally {
    if (conn) conn.end();
  }
});

app.post("/edit-company", requireAdmin, async (req, res) => {
  const { id, name, address1, city, state, zip, country, terms, discount, approved, denied, logo, notes } = req.body;
  if (!id) {
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
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [result] = await conn.execute(`
      INSERT INTO companies (name, logo, address1, city, state, zip, country, terms, discount, notes, approved, denied)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE, FALSE)
    `, [name, logo || '', address1, city, state, zip, country || 'USA', terms || 'Net 30', discount || 0, '']);
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
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    await conn.beginTransaction();

    await conn.execute("DELETE FROM users WHERE company_id = ?", [id]);
    console.log(`Deleted users associated with company ID: ${id}`);

    await conn.execute("DELETE FROM shipto_addresses WHERE company_id = ?", [id]);
    console.log(`Deleted shipping addresses associated with company ID: ${id}`);

    await conn.execute("DELETE FROM companies WHERE id = ?", [id]);
    console.log(`Deleted company with ID: ${id}`);

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

app.post("/add-user", async (req, res) => {
  const { email, firstName, lastName, phone, role, password, companyId } = req.body;
  if (!email || !companyId || !password) {
    return res.status(400).json({ error: "Email, password, and companyId are required." });
  }
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
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
    conn = await mysql.createConnection(dbConnectionConfig);
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
    conn = await mysql.createConnection(dbConnectionConfig);
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
    conn = await mysql.createConnection(dbConnectionConfig);
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

app.get("/api/shipto/:companyId", authorizeCompanyAccess, async (req, res) => {
    const { companyId } = req.params;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [addresses] = await conn.execute("SELECT id, company_id, name, company_name, address1, city, state, zip, country, is_default FROM shipto_addresses WHERE company_id = ?", [companyId]);
        res.json(addresses);
    } catch (err) {
        console.error("Error fetching ship-to addresses:", err);
        res.status(500).json({ error: "Failed to retrieve ship-to addresses" });
    } finally {
        if (conn) conn.end();
    }
});

app.post("/api/shipto", authorizeCompanyAccess, async (req, res) => {
    const { companyId, name, company_name, address1, city, state, zip, country, is_default } = req.body;

    if (!companyId || !name || !address1 || !city || !state || !zip) {
        return res.status(400).json({ error: "Missing required fields (Company ID, Contact Name, Address, City, State, Zip)." });
    }
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        if (is_default) {
             await conn.execute(
                `UPDATE shipto_addresses SET is_default = 0 WHERE company_id = ?`,
                [companyId]
            );
        }
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

app.put("/api/shipto/:addressId", authorizeCompanyAccess, async (req, res) => {
    const { addressId } = req.params;
    const { name, company_name, address1, city, state, zip, country } = req.body;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
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

app.put("/api/shipto/:addressId/set-default", authorizeCompanyAccess, async (req, res) => {
    const { addressId } = req.params;

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);

        const [addressRows] = await conn.execute("SELECT company_id FROM shipto_addresses WHERE id = ?", [addressId]);

        if (addressRows.length === 0) {
            return res.status(404).json({ error: "Address not found." });
        }

        const targetCompanyId = addressRows[0].company_id;

        await conn.beginTransaction();

        await conn.execute(
            `UPDATE shipto_addresses SET is_default = 0 WHERE company_id = ? AND id != ?`,
            [targetCompanyId, addressId]
        );

        await conn.execute(
            `UPDATE shipto_addresses SET is_default = 1 WHERE id = ?`,
            [addressId]
        );

        await conn.commit();
        res.json({ message: "Default shipping address updated successfully." });

    } catch (err) {
        if (conn) {
            await conn.rollback();
        }
        console.error("Error setting default shipping address:", err);
        res.status(500).json({ error: "Failed to set default shipping address." });
    } finally {
        if (conn) conn.end();
    }
});

app.delete("/api/shipto/:addressId", authorizeCompanyAccess, async (req, res) => {
    const { addressId } = req.params;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        await conn.execute("DELETE FROM shipto_addresses WHERE id = ?", [addressId]);
        res.json({ message: "Address deleted successfully" });
    } catch (err) {
        console.error("Error deleting ship-to address:", err);
        res.status(500).json({ error: "Failed to delete ship-to address" });
    } finally {
        if (conn) conn.end();
    }
});

// NEW: Admin Settings Routes
app.get("/admin/settings", requireAdmin, async (req, res) => {
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [rows] = await conn.execute("SELECT po_email, registration_email FROM admin_settings WHERE id = 1");
        if (rows.length > 0) {
            res.json(rows[0]);
        } else {
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
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [existing] = await conn.execute("SELECT id FROM admin_settings WHERE id = 1");
        if (existing.length > 0) {
            await conn.execute(
                "UPDATE admin_settings SET po_email = ?, registration_email = ? WHERE id = 1",
                [po_email, registration_email]
            );
        } else {
            await conn.execute(
                "INSERT INTO admin_settings (id, po_email, registration_email) VALUES (1, ?, ?)",
                [po_email, registration_email]
            );
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

        if (!companyId) {
            return res.status(400).json({ error: "Company ID is required." });
        }

        conn = await mysql.createConnection(dbConnectionConfig);

        const [companyRows] = await conn.execute("SELECT name, approved FROM companies WHERE id = ?", [companyId]);
        if (companyRows.length === 0) {
            return res.status(404).json({ error: "Company not found." });
        }
        const company = companyRows[0];

        if (!company.approved) {
            return res.status(400).json({ error: "Company is not yet approved. Cannot send approval email." });
        }

        const [userRows] = await conn.execute("SELECT email, first_name FROM users WHERE company_id = ? LIMIT 1", [companyId]);
        if (userRows.length === 0) {
            return res.status(404).json({ error: "No users found for this company to send an email to." });
        }
        const userEmail = userRows[0].email;
        const userName = userRows[0].first_name || "Valued Customer";

        if (!process.env.EMAIL_USER) {
            console.error("EMAIL_USER environment variable is not set. Cannot send email.");
            return res.status(500).json({ error: "Email sender not configured on server." });
        }

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: userEmail,
            subject: `Your Company Registration for ${company.name} Has Been Approved!`,
            html: `
                <p>Dear ${userName},</p>
                <p>We are pleased to inform you that your company registration for <strong>${company.name}</strong> has been officially approved!</p>
                <p>You can now log in to your account and start placing orders.</p>
                <p>Login Page: <a href="${process.env.FRONTEND_URL || 'YOUR_FRONTEND_URL_HERE'}">${process.env.FRONTEND_URL || 'YOUR_FRONTEND_URL_HERE'}</a></p>
                <p>If you have any questions, please do not hesitate to contact us.</p>
                <p>Thank you for choosing Chicago Stainless Equipment, Inc.</p>
                <p>Sincerely,</p>
                <p>The Chicago Stainless Equipment Team</p>
            `,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending company approval email:", error);
                return res.status(500).json({ error: "Failed to send approval email." });
            } else {
                console.log("Company approval email sent:", info.response);
                res.status(200).json({ message: "Approval email sent successfully to the user!" });
            }
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
    let userDataDir;
    try {
        userDataDir = path.join(os.tmpdir(), `puppeteer_user_data_${uuidv4()}`);
        await fs.mkdir(userDataDir, { recursive: true });
        console.log(`Created temporary user data directory: ${userDataDir}`);

        browser = await puppeteer.launch({
            args: [...chromium.args, '--disable-gpu', '--disable-dev-shm-usage', '--no-sandbox', '--disable-setuid-sandbox'],
            executablePath: await chromium.executablePath(),
            headless: chromium.headless,
            ignoreHTTPSErrors: true,
            userDataDir: userDataDir
        });
        const page = await browser.newPage();

        await page.setContent(htmlContent, {
            waitUntil: 'networkidle0'
        });

        const pdfBuffer = await page.pdf({
            format: 'Letter',
            printBackground: true,
            margin: {
                top: '0.5in',
                right: '0.5in',
                bottom: '0.5in',
                left: '0.5in'
            }
        });
        console.log(`PDF generated successfully. Buffer size: ${pdfBuffer.length} bytes.`);
        return pdfBuffer;
    } catch (error) {
        console.error("Error generating PDF:", error);
        throw new Error("Failed to generate PDF for order confirmation.");
    } finally {
        if (browser) {
            await browser.close();
        }
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
    const userEmail = req.session.user.email;

    console.log("Received order submission request with body:", JSON.stringify(req.body, null, 2));

    if (!userEmail || !poNumber || !billingAddress || !shippingAddress || !shippingMethod || !items || items.length === 0) {
        console.error("Validation Error: Missing required order fields or empty cart.", { userEmail, poNumber, billingAddress, shippingAddress, shippingMethod, items });
        return res.status(400).json({ error: "Missing required order fields or empty cart." });
    }

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        await conn.beginTransaction();

        // Fetch company details to check approval status and apply discount
        const [companyRows] = await conn.execute("SELECT id, name, discount, approved FROM companies WHERE id = ?", [companyId]);
        if (companyRows.length === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Company not found for the logged-in user." });
        }
        const company = companyRows[0];

        // IMPORTANT: Check company approval status before proceeding with order
        if (!company.approved) {
            await conn.rollback();
            return res.status(403).json({ error: "Your company's registration is awaiting approval. Please allow 24-48 hours for review. You will receive an email notification once approved." });
        }

        const discountFactor = (100 - (company.discount || 0)) / 100;
        let totalOrderPrice = 0;

        // Calculate total price with discount applied (for internal record and PDF)
        const orderItemsWithCalculatedPrices = items.map(item => {
            const listPrice = item.price;
            const netPrice = listPrice * discountFactor;
            const lineTotal = item.quantity * netPrice;
            totalOrderPrice += lineTotal;
            return {
                partNo: item.partNo,
                description: item.description,
                quantity: item.quantity,
                listPrice: listPrice,
                netPrice: netPrice,
                lineTotal: lineTotal,
                note: item.note
            };
        });

        // Insert into orders table, matching the provided schema exactly
        const [orderResult] = await conn.execute(
            `INSERT INTO orders (email, poNumber, billingAddress, shippingAddress, shippingMethod, carrierAccount, items, date)
             VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
            [userEmail, poNumber, billingAddress, shippingAddress, shippingMethod, carrierAccount, JSON.stringify(orderItemsWithCalculatedPrices)] // Store calculated items
        );
        const orderId = orderResult.insertId;

        await conn.commit();

        // NEW: Generate HTML for the email body and PDF
        const orderDetailsForEmail = {
            poNumber, orderedBy, billingAddress, shippingAddress, attn, tag, shippingMethod, carrierAccount,
            items: orderItemsWithCalculatedPrices, // Use the items with calculated prices for PDF/email
            terms: company.terms // Pass company terms
        };
        const orderHtmlContent = generateOrderHtmlEmail(orderDetailsForEmail);

        let pdfBuffer;
        try {
            pdfBuffer = await generatePdfFromHtml(orderHtmlContent);
            console.log("PDF generated successfully.");
        } catch (pdfError) {
            console.error("Failed to generate PDF, proceeding without attachment:", pdfError);
        }

        await sendOrderNotificationEmail(orderId, orderDetailsForEmail, pdfBuffer);

        res.status(200).json({ message: "Order submitted successfully! Notification email sent.", orderId: orderId });

    } catch (err) {
        if (conn) {
            await conn.rollback();
        }
        console.error("Error submitting order (Backend):", err);
        res.status(500).json({ error: err.message || "Failed to submit order due to server error." });
    } finally {
        if (conn) conn.end();
    }
});


// --- General Routes and Server Start ---

app.get("/", (req, res) => {
  res.redirect("/admin.html");
});

// Database Initialization Function
async function initializeDatabase() {
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        console.log("Database connection for initialization established.");

        // Drop foreign key constraints if they exist before dropping tables or re-creating
        try {
            await conn.execute(`
                ALTER TABLE users DROP FOREIGN KEY IF EXISTS users_ibfk_1;
            `);
            console.log("Dropped existing foreign key 'users_ibfk_1' from 'users' table.");
        } catch (error) {
            console.warn("Could not drop foreign key 'users_ibfk_1':", error.message);
        }
        try {
            await conn.execute(`
                ALTER TABLE shipto_addresses DROP FOREIGN KEY IF EXISTS shipto_addresses_ibfk_1;
            `);
            console.log("Dropped existing foreign key 'shipto_addresses_ibfk_1' from 'shipto_addresses' table.");
        } catch (error) {
            console.warn("Could not drop foreign key 'shipto_addresses_ibfk_1':", error.message);
        }

        // Create 'companies' table
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS companies (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                logo VARCHAR(255),
                address1 TEXT,
                city VARCHAR(255),
                state VARCHAR(255),
                zip VARCHAR(20),
                country VARCHAR(255),
                terms VARCHAR(50),
                discount DECIMAL(5,2) DEFAULT 0.00,
                notes TEXT,
                approved BOOLEAN DEFAULT FALSE,
                denied BOOLEAN DEFAULT FALSE
            ) ENGINE=InnoDB;
        `);
        console.log("'companies' table checked/created.");

        // Create 'users' table
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                first_name VARCHAR(255),
                last_name VARCHAR(255),
                phone VARCHAR(50),
                role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
                password VARCHAR(255) NOT NULL,
                company_id INT
            ) ENGINE=InnoDB;
        `);
        console.log("'users' table checked/created.");

        // Add foreign key constraint for 'users' table with ON DELETE CASCADE
        try {
            await conn.execute(`
                ALTER TABLE users
                ADD CONSTRAINT users_ibfk_1
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE;
            `);
            console.log("Added foreign key 'users_ibfk_1' with ON DELETE CASCADE to 'users' table.");
        } catch (error) {
            if (error.code !== 'ER_DUP_KEYNAME') {
                console.warn("Could not add foreign key 'users_ibfk_1' (it might already exist):", error.message);
            }
        }

        // Create 'shipto_addresses' table
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
                is_default BOOLEAN DEFAULT FALSE
            ) ENGINE=InnoDB;
        `);
        console.log("'shipto_addresses' table checked/created.");

        // Add foreign key constraint for 'shipto_addresses' table with ON DELETE CASCADE
        try {
            await conn.execute(`
                ALTER TABLE shipto_addresses
                ADD CONSTRAINT shipto_addresses_ibfk_1
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE;
            `);
            console.log("Added foreign key 'shipto_addresses_ibfk_1' with ON DELETE CASCADE to 'shipto_addresses' table.");
        } catch (error) {
            if (error.code !== 'ER_DUP_KEYNAME') {
                console.warn("Could not add foreign key 'shipto_addresses_ibfk_1' (it might already exist):", error.message);
            }
        }

        // Create 'orders' table
        await conn.execute(`
            CREATE TABLE IF NOT EXISTS orders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                poNumber VARCHAR(255) NOT NULL,
                billingAddress TEXT NOT NULL,
                shippingAddress TEXT NOT NULL,
                shippingMethod VARCHAR(255),
                carrierAccount VARCHAR(255),
                items JSON NOT NULL,
                date DATETIME DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB;
        `);
        console.log("'orders' table checked/created.");

        // Create 'admin_settings' table
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


    } catch (err) {
        console.error("Error initializing database:", err);
        process.exit(1);
    } finally {
        if (conn) {
            conn.end();
            console.log("Database connection for initialization closed.");
        }
    }
}

// Call database initialization before starting the server
initializeDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}).catch(err => {
    console.error("Failed to start server due to database initialization error:", err);
    process.exit(1);
});
