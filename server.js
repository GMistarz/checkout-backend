require('dotenv').config(); // Loads environment variables for emailing
const express = require("express");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise"); // Ensure you're using the promise version
const path = require("path");
const nodemailer = require("nodemailer");

// NEW: Import puppeteer-extra, puppeteer-core, and the stealth plugin
const puppeteerExtra = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const puppeteerCore = require('puppeteer-core'); // Import puppeteer-core
const chromium = require('@sparticuz/chromium'); // Import @sparticuz/chromium

// Apply the stealth plugin to puppeteer-extra
puppeteerExtra.use(StealthPlugin());

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
console.log(`Application will attempt to listen on port ${PORT}`);

// MySQL Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'password',
    database: process.env.DB_NAME || 'checkout_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test DB connection
pool.getConnection()
    .then(connection => {
        console.log("Successfully connected to the database!");
        connection.release(); // Release the connection immediately
    })
    .catch(err => {
        console.error("Failed to connect to the database:", err);
        // Optionally, exit the process if DB connection is critical for startup
        // process.exit(1);
    });

// Session store configuration
const sessionStore = new MySQLStore({
    clearExpired: true,
    checkExpirationInterval: 900000, // How frequently to check for expired sessions (15 minutes)
    expiration: 86400000, // The maximum age of a session (1 day)
    endConnectionOnClose: true,
}, pool); // Pass the pool directly

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:8080', // THIS LINE IS UPDATED
    credentials: true
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files from 'public' directory

app.use(session({
    key: 'session_cookie_name', // Cookie name
    secret: process.env.SESSION_SECRET || 'supersecretkey', // Secret for signing the session ID cookie
    store: sessionStore,
    resave: false, // Don't save session if unmodified
    saveUninitialized: false, // Don't create session until something stored
    cookie: {
        maxAge: 86400000, // 1 day
        httpOnly: true, // Prevent client-side JS from reading the cookie
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        sameSite: 'Lax' // Protect against CSRF
    }
}));

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_SECURE === 'true', // Use 'true' for 465, 'false' for 587
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Verify transporter configuration
transporter.verify(function (error, success) {
    if (error) {
        console.error("Nodemailer transporter verification failed:", error);
    } else {
        console.log("Nodemailer transporter is ready to send emails");
    }
});


// --- Authentication Routes ---

app.post("/register-company", async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();

        const { name, address1, city, state, zip, country, terms, logo, discount } = req.body;

        if (!name || !terms) {
            await conn.rollback();
            return res.status(400).json({ error: "Company name and terms are required." });
        }

        // Check if company already exists by name (case-insensitive)
        const [existingCompanies] = await conn.execute(
            'SELECT id FROM companies WHERE LOWER(name) = LOWER(?)',
            [name]
        );

        if (existingCompanies.length > 0) {
            await conn.rollback();
            return res.status(409).json({ error: "Company with this name already exists." });
        }

        // Insert new company
        const [companyResult] = await conn.execute(
            'INSERT INTO companies (name, address1, city, state, zip, country, terms, logo, discount, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [name, address1, city, state, zip, country, terms, logo, discount, ''] // Initialize notes as empty string
        );
        const companyId = companyResult.insertId;

        await conn.commit();
        res.status(201).json({ message: "Company registered successfully!", companyId: companyId });

    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error registering company:", err);
        res.status(500).json({ error: "Failed to register company." });
    } finally {
        if (conn) conn.release();
    }
});

app.get("/company-by-name/:companyName", async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { companyName } = req.params;
        const [rows] = await conn.execute(
            'SELECT id, name, address1, city, state, zip, country, terms, logo, discount, notes FROM companies WHERE LOWER(name) = LOWER(?)',
            [companyName]
        );
        if (rows.length > 0) {
            res.status(200).json({ exists: true, company: rows[0] });
        } else {
            res.status(200).json({ exists: false });
        }
    } catch (err) {
        console.error("Error checking company existence:", err);
        res.status(500).json({ error: "Failed to check company existence." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/register-user", async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();

        const { email, firstName, lastName, phone, role, password, companyId } = req.body;

        if (!email || !password || !companyId) {
            await conn.rollback();
            return res.status(400).json({ error: "Email, password, and company ID are required." });
        }

        // Check if user with this email already exists
        const [existingUsersByEmail] = await conn.execute(
            'SELECT id FROM users WHERE LOWER(email) = LOWER(?)',
            [email]
        );

        if (existingUsersByEmail.length > 0) {
            await conn.rollback();
            return res.status(409).json({ error: "User with this email already exists." });
        }

        // Check if user with same first_name and last_name exists for this company
        const [existingUsersByName] = await conn.execute(
            'SELECT id FROM users WHERE LOWER(first_name) = LOWER(?) AND LOWER(last_name) = LOWER(?) AND company_id = ?',
            [firstName, lastName, companyId]
        );

        if (existingUsersByName.length > 0) {
            await conn.rollback();
            return res.status(409).json({ error: "User Name Already Exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [userResult] = await conn.execute(
            'INSERT INTO users (email, first_name, last_name, phone, role, password, company_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [email, firstName, lastName, phone, role, hashedPassword, companyId]
        );
        const userId = userResult.insertId;

        await conn.commit();
        res.status(201).json({ message: "User registered successfully!", userId: userId });

    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error registering user:", err);
        res.status(500).json({ error: "Failed to register user." });
    } finally {
        if (conn) conn.release();
    }
});


app.post("/login", async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { email, password } = req.body;

        const [rows] = await conn.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = rows[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        req.session.userId = user.id;
        req.session.role = user.role;
        req.session.companyId = user.company_id; // Store companyId in session

        res.status(200).json({ message: "Logged in successfully", user: { id: user.id, email: user.email, role: user.role, company_id: user.company_id } });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "An error occurred during login." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Logout error:", err);
            return res.status(500).json({ error: "Failed to log out" });
        }
        res.clearCookie('session_cookie_name'); // Clear the session cookie
        res.status(200).json({ message: "Logged out successfully" });
    });
});

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: "Unauthorized" });
    }
};

// Middleware to check if user is an admin
const isAdmin = (req, res, next) => {
    if (req.session.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: "Forbidden: Admins only" });
    }
};

// Middleware to authorize access to company-specific data
const authorizeCompanyAccess = async (req, res, next) => {
    const requestedCompanyId = parseInt(req.params.companyId || req.body.companyId, 10);
    if (isNaN(requestedCompanyId)) {
        return res.status(400).json({ error: "Invalid company ID provided." });
    }

    if (req.session.role === 'admin') {
        // Admins can access any company's data
        next();
    } else if (req.session.role === 'user' && req.session.companyId === requestedCompanyId) {
        // Regular users can only access data for their own company
        next();
    } else {
        res.status(403).json({ error: "Forbidden: You do not have access to this company's data." });
    }
};

// --- User Profile Endpoint ---
app.get("/user-profile", isAuthenticated, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const [rows] = await conn.execute('SELECT id, email, first_name, last_name, phone, role, company_id FROM users WHERE id = ?', [req.session.userId]);
        if (rows.length > 0) {
            res.status(200).json(rows[0]);
        } else {
            res.status(404).json({ error: "User not found" });
        }
    } catch (err) {
        console.error("Error fetching user profile:", err);
        res.status(500).json({ error: "Failed to fetch user profile." });
    } finally {
        if (conn) conn.release();
    }
});

// NEW: Endpoint to get company details for the logged-in user
app.get("/user/company-details", isAuthenticated, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        if (!req.session.companyId) {
            return res.status(404).json({ error: "User is not associated with a company." });
        }
        const [rows] = await conn.execute('SELECT id, name, address1, city, state, zip, country, terms, logo, discount, notes FROM companies WHERE id = ?', [req.session.companyId]);
        if (rows.length > 0) {
            res.status(200).json(rows[0]);
        } else {
            res.status(404).json({ error: "Company not found for the user." });
        }
    } catch (err) {
        console.error("Error fetching user's company details:", err);
        res.status(500).json({ error: "Failed to fetch user's company details." });
    } finally {
        if (conn) conn.release();
    }
});


// --- Company Management Endpoints (Admin Only) ---
app.get("/companies", isAuthenticated, isAdmin, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const [rows] = await conn.execute('SELECT id, name, address1, city, state, zip, country, terms, logo, discount, notes FROM companies ORDER BY name');
        res.status(200).json(rows);
    } catch (err) {
        console.error("Error fetching companies:", err);
        res.status(500).json({ error: "Failed to fetch companies." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/add-company", isAuthenticated, isAdmin, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();
        const { name, address1, city, state, zip, country, terms, logo, discount, notes } = req.body;

        if (!name || !terms) {
            await conn.rollback();
            return res.status(400).json({ error: "Company name and terms are required." });
        }

        // Check for existing company name (case-insensitive)
        const [existingCompanies] = await conn.execute(
            'SELECT id FROM companies WHERE LOWER(name) = LOWER(?)',
            [name]
        );
        if (existingCompanies.length > 0) {
            await conn.rollback();
            return res.status(409).json({ error: "A company with this name already exists." });
        }

        const [result] = await conn.execute(
            'INSERT INTO companies (name, address1, city, state, zip, country, terms, logo, discount, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [name, address1, city, state, zip, country, terms, logo, discount, notes || '']
        );
        const newCompanyId = result.insertId;

        await conn.commit();
        res.status(201).json({ message: "Company added successfully!", id: newCompanyId });
    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error adding company:", err);
        res.status(500).json({ error: "Failed to add company." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/edit-company", isAuthenticated, isAdmin, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();
        const { id, name, address1, city, state, zip, country, terms, logo, discount, notes } = req.body;

        if (!id || !name || !terms) {
            await conn.rollback();
            return res.status(400).json({ error: "Company ID, name, and terms are required for update." });
        }

        // Check for duplicate company name, excluding the current company being edited
        const [existingCompanies] = await conn.execute(
            'SELECT id FROM companies WHERE LOWER(name) = LOWER(?) AND id != ?',
            [name, id]
        );
        if (existingCompanies.length > 0) {
            await conn.rollback();
            return res.status(409).json({ error: "Another company with this name already exists." });
        }

        const [result] = await conn.execute(
            'UPDATE companies SET name = ?, address1 = ?, city = ?, state = ?, zip = ?, country = ?, terms = ?, logo = ?, discount = ?, notes = ? WHERE id = ?',
            [name, address1, city, state, zip, country, terms, logo, discount, notes || '', id]
        );

        if (result.affectedRows === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Company not found or no changes made." });
        }

        await conn.commit();
        res.status(200).json({ message: "Company updated successfully!" });
    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error updating company:", err);
        res.status(500).json({ error: "Failed to update company." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/delete-company", isAuthenticated, isAdmin, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();
        const { id } = req.body;

        if (!id) {
            await conn.rollback();
            return res.status(400).json({ error: "Company ID is required for deletion." });
        }

        // Delete associated shipping addresses first
        await conn.execute('DELETE FROM shipto_addresses WHERE company_id = ?', [id]);

        // Delete associated users
        await conn.execute('DELETE FROM users WHERE company_id = ?', [id]);

        // Delete the company
        const [result] = await conn.execute('DELETE FROM companies WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Company not found." });
        }

        await conn.commit();
        res.status(200).json({ message: "Company and associated data deleted successfully!" });
    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error deleting company:", err);
        res.status(500).json({ error: "Failed to delete company." });
    } finally {
        if (conn) conn.release();
    }
});

app.get("/company-users/:companyId", isAuthenticated, authorizeCompanyAccess, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { companyId } = req.params;
        const [rows] = await conn.execute('SELECT id, email, first_name, last_name, phone, role, company_id FROM users WHERE company_id = ? ORDER BY last_name, first_name', [companyId]);
        res.status(200).json(rows);
    } catch (err) {
        console.error("Error fetching company users:", err);
        res.status(500).json({ error: "Failed to fetch company users." });
    } finally {
        if (conn) conn.release();
    }
});

app.get("/user/:userId", isAuthenticated, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { userId } = req.params;

        // Ensure the user is either an admin or is requesting their own profile
        if (req.session.role !== 'admin' && req.session.userId !== parseInt(userId, 10)) {
            return res.status(403).json({ error: "Forbidden: You can only view your own user details." });
        }

        const [rows] = await conn.execute('SELECT id, email, first_name, last_name, phone, role, company_id FROM users WHERE id = ?', [userId]);
        if (rows.length > 0) {
            res.status(200).json(rows[0]);
        } else {
            res.status(404).json({ error: "User not found." });
        }
    } catch (err) {
        console.error("Error fetching user details:", err);
        res.status(500).json({ error: "Failed to fetch user details." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/add-user", isAuthenticated, isAdmin, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();
        const { email, firstName, lastName, phone, role, password, companyId } = req.body;

        if (!email || !password || !companyId) {
            await conn.rollback();
            return res.status(400).json({ error: "Email, password, and company ID are required." });
        }

        // Check if user with this email already exists
        const [existingUsersByEmail] = await conn.execute(
            'SELECT id FROM users WHERE LOWER(email) = LOWER(?)',
            [email]
        );
        if (existingUsersByEmail.length > 0) {
            await conn.rollback();
            return res.status(409).json({ error: "User with this email already exists." });
        }

        // Check if user with same first_name and last_name exists for this company
        const [existingUsersByName] = await conn.execute(
            'SELECT id FROM users WHERE LOWER(first_name) = LOWER(?) AND LOWER(last_name) = LOWER(?) AND company_id = ?',
            [firstName, lastName, companyId]
        );
        if (existingUsersByName.length > 0) {
            await conn.rollback();
            return res.status(409).json({ error: "User Name Already Exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await conn.execute(
            'INSERT INTO users (email, first_name, last_name, phone, role, password, company_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [email, firstName, lastName, phone, role, hashedPassword, companyId]
        );
        const newUserId = result.insertId;

        await conn.commit();
        res.status(201).json({ message: "User added successfully!", id: newUserId });
    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error adding user:", err);
        res.status(500).json({ error: "Failed to add user." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/edit-user", isAuthenticated, isAdmin, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();
        const { id, email, firstName, lastName, phone, role, password, companyId } = req.body;

        if (!id || !email || !companyId) {
            await conn.rollback();
            return res.status(400).json({ error: "User ID, email, and company ID are required for update." });
        }

        let updateSql = 'UPDATE users SET email = ?, first_name = ?, last_name = ?, phone = ?, role = ?, company_id = ?';
        const updateParams = [email, firstName, lastName, phone, role, companyId];

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updateSql += ', password = ?';
            updateParams.push(hashedPassword);
        }
        updateSql += ' WHERE id = ?';
        updateParams.push(id);

        const [result] = await conn.execute(updateSql, updateParams);

        if (result.affectedRows === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "User not found or no changes made." });
        }

        await conn.commit();
        res.status(200).json({ message: "User updated successfully!" });
    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error updating user:", err);
        res.status(500).json({ error: "Failed to update user." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/delete-user", isAuthenticated, isAdmin, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();
        const { id } = req.body;

        if (!id) {
            await conn.rollback();
            return res.status(400).json({ error: "User ID is required for deletion." });
        }

        const [result] = await conn.execute('DELETE FROM users WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "User not found." });
        }

        await conn.commit();
        res.status(200).json({ message: "User deleted successfully!" });
    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error deleting user:", err);
        res.status(500).json({ error: "Failed to delete user." });
    } finally {
        if (conn) conn.release();
    }
});

// --- Shipping Address Endpoints ---

// Get all shipping addresses for a company
app.get("/api/shipto/:companyId", isAuthenticated, authorizeCompanyAccess, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { companyId } = req.params;
        const [rows] = await conn.execute('SELECT * FROM shipto_addresses WHERE company_id = ? ORDER BY is_default DESC, name ASC', [companyId]);
        res.status(200).json(rows);
    } catch (err) {
        console.error("Error fetching shipping addresses:", err);
        res.status(500).json({ error: "Failed to fetch shipping addresses." });
    } finally {
        if (conn) conn.release();
    }
});

// Add a new shipping address
app.post("/api/shipto", isAuthenticated, authorizeCompanyAccess, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();
        const { companyId, name, company_name, address1, city, state, zip, country } = req.body;

        if (!companyId || !name || !address1 || !city || !state || !zip) {
            await conn.rollback();
            return res.status(400).json({ error: "Company ID, Address Reference, Address, City, State, and Zip are required." });
        }

        const [result] = await conn.execute(
            'INSERT INTO shipto_addresses (company_id, name, company_name, address1, city, state, zip, country, is_default) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)',
            [companyId, name, company_name, address1, city, state, zip, country]
        );
        const newAddressId = result.insertId;

        await conn.commit();
        res.status(201).json({ message: "Shipping address added successfully!", id: newAddressId });
    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error adding shipping address:", err);
        res.status(500).json({ error: "Failed to add shipping address." });
    } finally {
        if (conn) conn.release();
    }
});

// Update a shipping address
app.put("/api/shipto/:addressId", isAuthenticated, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();
        const { addressId } = req.params;
        const { name, company_name, address1, city, state, zip, country } = req.body;

        if (!name || !address1 || !city || !state || !zip) {
            await conn.rollback();
            return res.status(400).json({ error: "Address Reference, Address, City, State, and Zip are required." });
        }

        // First, verify that the user has access to this address's company
        const [addressRows] = await conn.execute('SELECT company_id FROM shipto_addresses WHERE id = ?', [addressId]);
        if (addressRows.length === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Shipping address not found." });
        }
        const companyIdOfAddress = addressRows[0].company_id;

        if (req.session.role !== 'admin' && req.session.companyId !== companyIdOfAddress) {
            await conn.rollback();
            return res.status(403).json({ error: "Forbidden: You do not have access to update this shipping address." });
        }

        const [result] = await conn.execute(
            'UPDATE shipto_addresses SET name = ?, company_name = ?, address1 = ?, city = ?, state = ?, zip = ?, country = ? WHERE id = ?',
            [name, company_name, address1, city, state, zip, country, addressId]
        );

        if (result.affectedRows === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Shipping address not found or no changes made." });
        }

        await conn.commit();
        res.status(200).json({ message: "Shipping address updated successfully!" });
    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error updating shipping address:", err);
        res.status(500).json({ error: "Failed to update shipping address." });
    } finally {
        if (conn) conn.release();
    }
});

// Delete a shipping address
app.delete("/api/shipto/:addressId", isAuthenticated, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();
        const { addressId } = req.params;

        // First, verify that the user has access to this address's company
        const [addressRows] = await conn.execute('SELECT company_id FROM shipto_addresses WHERE id = ?', [addressId]);
        if (addressRows.length === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Shipping address not found." });
        }
        const companyIdOfAddress = addressRows[0].company_id;

        if (req.session.role !== 'admin' && req.session.companyId !== companyIdOfAddress) {
            await conn.rollback();
            return res.status(403).json({ error: "Forbidden: You do not have access to delete this shipping address." });
        }

        const [result] = await conn.execute('DELETE FROM shipto_addresses WHERE id = ?', [addressId]);

        if (result.affectedRows === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Shipping address not found." });
        }

        await conn.commit();
        res.status(200).json({ message: "Shipping address deleted successfully!" });
    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error deleting shipping address:", err);
        res.status(500).json({ error: "Failed to delete shipping address." });
    } finally {
        if (conn) conn.release();
    }
});

// Set a shipping address as default
app.put("/api/shipto/:addressId/set-default", isAuthenticated, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();
        const { addressId } = req.params;
        const { companyId } = req.body; // Expect companyId in body for validation

        if (!companyId) {
            await conn.rollback();
            return res.status(400).json({ error: "Company ID is required." });
        }

        // Verify that the user has access to this company
        if (req.session.role !== 'admin' && req.session.companyId !== companyId) {
            await conn.rollback();
            return res.status(403).json({ error: "Forbidden: You do not have access to this company." });
        }

        // Verify that the address belongs to the specified company
        const [addressRows] = await conn.execute('SELECT id FROM shipto_addresses WHERE id = ? AND company_id = ?', [addressId, companyId]);
        if (addressRows.length === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Shipping address not found for the specified company." });
        }

        // Set all addresses for this company to not default
        await conn.execute('UPDATE shipto_addresses SET is_default = 0 WHERE company_id = ?', [companyId]);

        // Set the specified address as default
        const [result] = await conn.execute('UPDATE shipto_addresses SET is_default = 1 WHERE id = ?', [addressId]);

        if (result.affectedRows === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Shipping address not found or no changes made." });
        }

        await conn.commit();
        res.status(200).json({ message: "Default shipping address set successfully!" });
    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error setting default shipping address:", err);
        res.status(500).json({ error: "Failed to set default shipping address." });
    } finally {
        if (conn) conn.release();
    }
});

// --- PDF Generation and Emailing ---

async function generatePdfFromHtml(htmlContent, orderId, poNumber) {
    let browser;
    try {
        // Launch puppeteer using @sparticuz/chromium's bundled puppeteer-core
        browser = await puppeteerExtra.launch({
            executablePath: await chromium.executablePath(), // Path to the Chromium executable
            args: [...chromium.args, '--hide-scrollbars', '--disable-web-security'], // Recommended args from @sparticuz/chromium
            headless: chromium.headless, // Use chromium's headless mode setting
            ignoreHTTPSErrors: true,
        });

        const page = await browser.newPage();

        // Set content and wait for network to be idle
        await page.setContent(htmlContent, { waitUntil: 'networkidle0' });

        // Generate PDF
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

        return pdfBuffer;
    } catch (error) {
        console.error("Error generating PDF:", error);
        throw new Error("Failed to generate PDF for order confirmation.");
    } finally {
        if (browser) {
            await browser.close();
        }
    }
}


app.post("/submit-order", isAuthenticated, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.beginTransaction();

        const { poNumber, orderedBy, billingAddress, shippingAddress, shippingAddressId, attn, tag, shippingMethod, carrierAccount, items } = req.body;
        const userId = req.session.userId;
        const companyId = req.session.companyId;

        if (!userId || !companyId) {
            await conn.rollback();
            return res.status(401).json({ error: "User or company information missing from session." });
        }

        if (!poNumber || !orderedBy || !billingAddress || !shippingAddress || !shippingMethod || !items || items.length === 0) {
            await conn.rollback();
            return res.status(400).json({ error: "Missing required order details." });
        }

        // Fetch company discount
        const [companyRows] = await conn.execute('SELECT discount FROM companies WHERE id = ?', [companyId]);
        const companyDiscount = companyRows.length > 0 ? companyRows[0].discount : 0;
        const discountFactor = (100 - companyDiscount) / 100;

        // Calculate total price with discount applied
        let totalPrice = 0;
        const processedItems = items.map(item => {
            const netPrice = item.price * discountFactor;
            const lineTotal = item.quantity * netPrice;
            totalPrice += lineTotal;
            return {
                ...item,
                netPrice: netPrice, // Store the calculated net price
                lineTotal: lineTotal // Store the calculated line total
            };
        });

        // Insert order into orders table
        const [orderResult] = await conn.execute(
            'INSERT INTO orders (user_id, company_id, po_number, ordered_by, billing_address, shipping_address, shipping_address_id, attn, tag, shipping_method, carrier_account, total_price, discount_percentage) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [userId, companyId, poNumber, orderedBy, billingAddress, shippingAddress, shippingAddressId, attn, tag, shippingMethod, carrierAccount, totalPrice, companyDiscount]
        );
        const orderId = orderResult.insertId;

        // Insert order items into order_items table
        for (const item of processedItems) {
            await conn.execute(
                'INSERT INTO order_items (order_id, part_number, quantity, list_price, net_price, line_total, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [orderId, item.partNo, item.quantity, item.price, item.netPrice, item.lineTotal, item.note]
            );
        }

        await conn.commit();

        // --- PDF Generation and Emailing (outside transaction for atomicity) ---
        let pdfBuffer = null;
        let emailHtmlContent = `
            <h1>Order Confirmation - Order #${orderId}</h1>
            <p><strong>PO Number:</strong> ${poNumber}</p>
            <p><strong>Ordered By:</strong> ${orderedBy}</p>
            <p><strong>Billing Address:</strong><br>${billingAddress.replace(/\n/g, '<br>')}</p>
            <p><strong>Shipping Address:</strong><br>${shippingAddress.replace(/\n/g, '<br>')}</p>
            ${attn ? `<p><strong>ATTN:</strong> ${attn}</p>` : ''}
            ${tag ? `<p><strong>Tag#:</strong> ${tag}</p>` : ''}
            <p><strong>Shipping Method:</strong> ${shippingMethod}</p>
            ${carrierAccount ? `<p><strong>Carrier Account #:</strong> ${carrierAccount}</p>` : ''}
            
            <h2>Items:</h2>
            <table border="1" cellpadding="5" cellspacing="0" width="100%">
                <thead>
                    <tr>
                        <th>Qty</th>
                        <th>Part Number</th>
                        <th>List Price</th>
                        <th>Net Price (-${companyDiscount}%)</th>
                        <th>Total</th>
                        <th>Notes</th>
                    </tr>
                </thead>
                <tbody>
                    ${processedItems.map(item => `
                        <tr>
                            <td>${item.quantity}</td>
                            <td>${item.partNo}</td>
                            <td>$${item.price.toFixed(2)}</td>
                            <td>$${item.netPrice.toFixed(2)}</td>
                            <td>$${item.lineTotal.toFixed(2)}</td>
                            <td>${item.note || ''}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            <h3>Total Order Price: $${totalPrice.toFixed(2)}</h3>
            <p>Thank you for your order!</p>
            <p>For any questions, please contact us at 772-781-1441 or sales@chicagostainless.com.</p>
            <p>This is an automated email. Please do not reply.</p>
        `;

        try {
            pdfBuffer = await generatePdfFromHtml(emailHtmlContent, orderId, poNumber);
            console.log("PDF generated successfully.");
        } catch (pdfError) {
            console.error("Failed to generate PDF, proceeding without attachment:", pdfError);
            // Optionally, append a message to the email body if PDF generation fails
            emailHtmlContent += `<p style="color: red;">Note: A PDF attachment could not be generated for this order. Please contact support for order details.</p>`;
        }

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.ORDER_NOTIFICATION_EMAIL, // Send to a dedicated order notification email
            subject: `New Order #${orderId} - PO# ${poNumber} from ${orderedBy}`,
            html: `
                <p>A new order has been submitted through the checkout portal.</p>
                <p><strong>Order ID:</strong> ${orderId}</p>
                <p><strong>PO Number:</strong> ${poNumber}</p>
                <p><strong>Ordered By:</strong> ${orderedBy}</p>
                <p><strong>Company ID:</strong> ${companyId}</p>
                <p><strong>Total Price:</strong> $${totalPrice.toFixed(2)}</p>
                <p>Full order information attached as a PDF.</p>
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
    console.log(`Server running on port ${PORT}`);
});
