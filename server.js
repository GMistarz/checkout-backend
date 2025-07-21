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
  console.error('UNHANDLED REJECTION:', reason);
  // Log the reason and then exit. A process manager should restart the app.
  process.exit(1);
});


const app = express();
const PORT = process.env.PORT || 3000;

// Database connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_SECURE === 'true', // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Middleware
app.use(cors({
    origin: ["https://checkout-frontend-jvyx.onrender.com", "http://localhost:5500", "http://127.0.0.1:5500"], // Allow your frontend origin
    credentials: true // Allow cookies to be sent
}));
app.use(express.json()); // For parsing application/json
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files from 'public' directory

app.use(session({
    secret: process.env.SESSION_SECRET || "supersecretkey", // Use a strong secret from .env
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Function to initialize database tables
async function initializeDatabase() {
    let conn;
    try {
        conn = await pool.getConnection();
        console.log("Database connected for initialization.");

        // Create 'companies' table
        await conn.query(`
            CREATE TABLE IF NOT EXISTS companies (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                logo VARCHAR(255),
                address1 TEXT,
                city VARCHAR(100),
                state VARCHAR(100),
                zip VARCHAR(20),
                country VARCHAR(100),
                terms VARCHAR(50),
                discount DECIMAL(5, 2) DEFAULT 0.00,
                notes TEXT,
                approved BOOLEAN DEFAULT FALSE,
                denied BOOLEAN DEFAULT FALSE
            );
        `);
        console.log("Table 'companies' ensured.");

        // Create 'users' table
        await conn.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                company_id INT,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                first_name VARCHAR(255),
                last_name VARCHAR(255),
                phone VARCHAR(50),
                role ENUM('user', 'admin') DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
            );
        `);
        console.log("Table 'users' ensured.");

        // Create 'products' table
        await conn.query(`
            CREATE TABLE IF NOT EXISTS products (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                price DECIMAL(10, 2) NOT NULL,
                image_url VARCHAR(255),
                category VARCHAR(100),
                stock_quantity INT DEFAULT 0
            );
        `);
        console.log("Table 'products' ensured.");

        // Create 'cart_items' table
        await conn.query(`
            CREATE TABLE IF NOT EXISTS cart_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
                UNIQUE (user_id, product_id) -- Ensures one entry per product per user
            );
        `);
        console.log("Table 'cart_items' ensured.");

        // Create 'orders' table
        await conn.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                company_id INT NOT NULL,
                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_amount DECIMAL(10, 2) NOT NULL,
                status VARCHAR(50) DEFAULT 'Pending',
                po_number VARCHAR(255),
                shipping_address_id INT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
            );
        `);
        console.log("Table 'orders' ensured.");

        // Create 'order_items' table
        await conn.query(`
            CREATE TABLE IF NOT EXISTS order_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                order_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL,
                price DECIMAL(10, 2) NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            );
        `);
        console.log("Table 'order_items' ensured.");

        // Create 'shipping_addresses' table
        await conn.query(`
            CREATE TABLE IF NOT EXISTS shipping_addresses (
                id INT AUTO_INCREMENT PRIMARY KEY,
                company_id INT NOT NULL,
                name VARCHAR(255) NOT NULL, -- e.g., "Main Warehouse", "Branch Office"
                company_name VARCHAR(255), -- Optional: if different from billing company name
                address1 TEXT NOT NULL,
                city VARCHAR(100) NOT NULL,
                state VARCHAR(100) NOT NULL,
                zip VARCHAR(20) NOT NULL,
                country VARCHAR(100),
                is_default BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
            );
        `);
        console.log("Table 'shipping_addresses' ensured.");

        // NEW: Create 'settings' table for admin configurations
        await conn.query(`
            CREATE TABLE IF NOT EXISTS settings (
                id INT PRIMARY KEY DEFAULT 1, -- Assuming only one row for admin settings
                po_email VARCHAR(255),
                registration_email VARCHAR(255)
            );
        `);
        console.log("Table 'settings' ensured.");

        // NEW: Ensure there's always one row in the settings table
        await conn.query(`
            INSERT IGNORE INTO settings (id, po_email, registration_email) VALUES (1, NULL, NULL);
        `);
        console.log("Default settings row ensured.");

    } catch (err) {
        console.error("Error initializing database:", err);
        process.exit(1); // Exit if database initialization fails
    } finally {
        if (conn) conn.release();
    }
}

// Call initializeDatabase when the server starts
initializeDatabase();

// Middleware to check if user is authenticated and is an admin
const isAdmin = (req, res, next) => {
    if (req.session.userId && req.session.role === 'admin') {
        next(); // User is authenticated and is an admin, proceed
    } else {
        res.status(403).json({ error: "Access denied. Admins only." });
    }
};

// Middleware to check if user is authenticated (either user or admin)
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        next(); // User is authenticated, proceed
    } else {
        res.status(401).json({ error: "Unauthorized. Please log in." });
    }
};

// --- Auth Routes ---

app.post("/register", async (req, res) => {
    let conn;
    try {
        const { email, password, role, companyName, terms } = req.body;

        if (!email || !password || !companyName || !terms) {
            return res.status(400).json({ error: "Email, password, company name, and terms are required." });
        }

        conn = await pool.getConnection();

        // Check if company already exists
        let [companies] = await conn.query("SELECT id FROM companies WHERE name = ?", [companyName]);
        let companyId;

        if (companies.length > 0) {
            companyId = companies[0].id;
        } else {
            // Create new company if it doesn't exist
            const [companyResult] = await conn.query(
                "INSERT INTO companies (name, terms, approved, denied) VALUES (?, ?, FALSE, FALSE)", // Set approved/denied to FALSE for new companies
                [companyName, terms]
            );
            companyId = companyResult.insertId;
        }

        // Check if user already exists
        const [users] = await conn.query("SELECT id FROM users WHERE email = ?", [email]);
        if (users.length > 0) {
            return res.status(409).json({ error: "User with this email already exists." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [userResult] = await conn.query(
            "INSERT INTO users (company_id, email, password, role) VALUES (?, ?, ?, ?)",
            [companyId, email, hashedPassword, role || 'user']
        );

        // Fetch registration email setting
        const [settings] = await conn.query("SELECT registration_email FROM settings WHERE id = 1");
        const registrationEmailRecipient = settings.length > 0 ? settings[0].registration_email : null;

        if (registrationEmailRecipient) {
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: registrationEmailRecipient,
                subject: 'New Company/User Registration',
                html: `
                    <p>A new ${role || 'user'} has registered:</p>
                    <ul>
                        <li><strong>Email:</strong> ${email}</li>
                        <li><strong>Company:</strong> ${companyName}</li>
                        <li><strong>Terms:</strong> ${terms}</li>
                        <li><strong>Status:</strong> Pending Admin Approval</li>
                    </ul>
                    <p>Please review the registration in the admin dashboard.</p>
                `,
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error("Error sending registration notification email:", error);
                } else {
                    console.log("Registration notification email sent:", info.response);
                }
            });
        }

        res.status(201).json({ message: "User registered successfully!", userId: userResult.insertId, companyId: companyId });

    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ error: "Failed to register user." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/login", async (req, res) => {
    let conn;
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required." });
        }

        conn = await pool.getConnection();
        const [users] = await conn.query("SELECT u.*, c.approved, c.denied FROM users u JOIN companies c ON u.company_id = c.id WHERE u.email = ?", [email]);

        if (users.length === 0) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        const user = users[0];

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        // Check company approval status for non-admin users
        if (user.role !== 'admin') {
            if (user.denied) { // Check if denied first
                return res.status(403).json({ error: "Your company registration has been denied. Please contact support." });
            }
            if (!user.approved) { // Then check if not approved (meaning pending)
                return res.status(403).json({ error: "Your company registration is pending approval. Please wait for an administrator to approve your account." });
            }
        }

        req.session.userId = user.id;
        req.session.role = user.role;
        req.session.companyId = user.company_id; // Store company_id in session

        res.status(200).json({ message: "Logged in successfully!", role: user.role, companyId: user.company_id });

    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "Failed to log in." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Session destruction error:", err);
            return res.status(500).json({ error: "Failed to log out." });
        }
        res.clearCookie('connect.sid'); // Clear session cookie
        res.status(200).json({ message: "Logged out successfully." });
    });
});

app.get("/check-auth", (req, res) => {
    if (req.session.userId) {
        res.status(200).json({
            isAuthenticated: true,
            userId: req.session.userId,
            role: req.session.role,
            companyId: req.session.companyId
        });
    } else {
        res.status(200).json({ isAuthenticated: false });
    }
});

app.post("/forgot-password", async (req, res) => {
    let conn;
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: "Email is required." });
        }

        conn = await pool.getConnection();
        const [users] = await conn.query("SELECT id FROM users WHERE email = ?", [email]);

        if (users.length === 0) {
            // For security, don't reveal if the email doesn't exist
            return res.status(200).json({ message: "If your email is in our system, a password reset link has been sent." });
        }

        const user = users[0];
        const resetToken = uuidv4(); // Generate a unique token
        // In a real application, you would store this token in the database with an expiry time
        // For this example, we'll just send it in the email.
        // await conn.query("UPDATE users SET reset_token = ?, reset_token_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE id = ?", [resetToken, user.id]);

        const resetLink = `${process.env.FRONTEND_URL}/reset-password.html?token=${resetToken}&email=${email}`; // Assuming a reset-password page

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset Request',
            html: `
                <p>You requested a password reset. Click the link below to reset your password:</p>
                <p><a href="${resetLink}">Reset Password</a></p>
                <p>This link will expire in 1 hour.</p>
                <p>If you did not request this, please ignore this email.</p>
            `,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending password reset email:", error);
                return res.status(500).json({ error: "Failed to send password reset email." });
            } else {
                console.log("Password reset email sent:", info.response);
                res.status(200).json({ message: "If your email is in our system, a password reset link has been sent." });
            }
        });

    } catch (err) {
        console.error("Forgot password error:", err);
        res.status(500).json({ error: "Failed to process forgot password request." });
    } finally {
        if (conn) conn.release();
    }
});

// --- Admin Endpoints (Protected by isAdmin middleware) ---

// Companies
app.get("/companies", isAdmin, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const [rows] = await conn.query("SELECT * FROM companies");
        res.status(200).json(rows);
    } catch (err) {
        console.error("Error fetching companies:", err);
        res.status(500).json({ error: "Failed to fetch companies." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/add-company", isAdmin, async (req, res) => {
    let conn;
    try {
        const { name, logo, address1, city, state, zip, country, terms, discount, notes, approved, denied } = req.body;
        if (!name || !terms) {
            return res.status(400).json({ error: "Company name and terms are required." });
        }

        conn = await pool.getConnection();
        const [result] = await conn.query(
            "INSERT INTO companies (name, logo, address1, city, state, zip, country, terms, discount, notes, approved, denied) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [name, logo, address1, city, state, zip, country, terms, discount, notes, approved, denied]
        );
        res.status(201).json({ message: "Company added successfully!", id: result.insertId });
    } catch (err) {
        console.error("Error adding company:", err);
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: "A company with this name already exists." });
        }
        res.status(500).json({ error: "Failed to add company." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/edit-company", isAdmin, async (req, res) => {
    let conn;
    try {
        const { id, name, logo, address1, city, state, zip, country, terms, discount, notes, approved, denied } = req.body;
        if (!id || !name || !terms) {
            return res.status(400).json({ error: "Company ID, name, and terms are required for update." });
        }

        conn = await pool.getConnection();
        const [result] = await conn.query(
            "UPDATE companies SET name = ?, logo = ?, address1 = ?, city = ?, state = ?, zip = ?, country = ?, terms = ?, discount = ?, notes = ?, approved = ?, denied = ? WHERE id = ?",
            [name, logo, address1, city, state, zip, country, terms, discount, notes, approved, denied, id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Company not found." });
        }
        res.status(200).json({ message: "Company updated successfully!" });
    } catch (err) {
        console.error("Error updating company:", err);
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: "A company with this name already exists." });
        }
        res.status(500).json({ error: "Failed to update company." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/delete-company", isAdmin, async (req, res) => {
    let conn;
    try {
        const { id } = req.body;
        if (!id) {
            return res.status(400).json({ error: "Company ID is required." });
        }

        conn = await pool.getConnection();
        // The ON DELETE CASCADE in table definitions will handle associated users and shipping addresses
        const [result] = await conn.query("DELETE FROM companies WHERE id = ?", [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Company not found." });
        }
        res.status(200).json({ message: "Company and associated data deleted successfully!" });
    } catch (err) {
        console.error("Error deleting company:", err);
        res.status(500).json({ error: "Failed to delete company." });
    } finally {
        if (conn) conn.release();
    }
});

// Users within a company (for admin dashboard)
app.get("/company-users/:companyId", isAdmin, async (req, res) => {
    let conn;
    try {
        const { companyId } = req.params;
        conn = await pool.getConnection();
        const [rows] = await conn.query("SELECT id, email, first_name, last_name, phone, role, company_id FROM users WHERE company_id = ?", [companyId]);
        res.status(200).json(rows);
    } catch (err) {
        console.error("Error fetching company users:", err);
        res.status(500).json({ error: "Failed to fetch company users." });
    } finally {
        if (conn) conn.release();
    }
});

// Get a single user by ID (for editing)
app.get("/user/:userId", isAdmin, async (req, res) => {
    let conn;
    try {
        const { userId } = req.params;
        conn = await pool.getConnection();
        const [users] = await conn.query("SELECT id, company_id, email, first_name, last_name, phone, role FROM users WHERE id = ?", [userId]);
        if (users.length === 0) {
            return res.status(404).json({ error: "User not found." });
        }
        res.status(200).json(users[0]);
    } catch (err) {
        console.error("Error fetching user:", err);
        res.status(500).json({ error: "Failed to fetch user." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/add-user", isAdmin, async (req, res) => {
    let conn;
    try {
        const { companyId, email, password, firstName, lastName, phone, role } = req.body;
        if (!companyId || !email || !password) {
            return res.status(400).json({ error: "Company ID, email, and password are required." });
        }

        conn = await pool.getConnection();
        const [existingUsers] = await conn.query("SELECT id FROM users WHERE email = ?", [email]);
        if (existingUsers.length > 0) {
            return res.status(409).json({ error: "User with this email already exists." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await conn.query(
            "INSERT INTO users (company_id, email, password, first_name, last_name, phone, role) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [companyId, email, hashedPassword, firstName, lastName, phone, role || 'user']
        );
        res.status(201).json({ message: "User added successfully!", id: result.insertId });
    } catch (err) {
        console.error("Error adding user:", err);
        res.status(500).json({ error: "Failed to add user." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/edit-user", isAdmin, async (req, res) => {
    let conn;
    try {
        const { id, companyId, email, password, firstName, lastName, phone, role } = req.body;
        if (!id || !companyId || !email) {
            return res.status(400).json({ error: "User ID, company ID, and email are required for update." });
        }

        conn = await pool.getConnection();

        // Check for duplicate email if email is being changed
        const [existingUserWithEmail] = await conn.query("SELECT id FROM users WHERE email = ? AND id != ?", [email, id]);
        if (existingUserWithEmail.length > 0) {
            return res.status(409).json({ error: "Another user with this email already exists." });
        }

        let updateQuery = "UPDATE users SET company_id = ?, email = ?, first_name = ?, last_name = ?, phone = ?, role = ? WHERE id = ?";
        let queryParams = [companyId, email, firstName, lastName, phone, role, id];

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updateQuery = "UPDATE users SET company_id = ?, email = ?, password = ?, first_name = ?, last_name = ?, phone = ?, role = ? WHERE id = ?";
            queryParams = [companyId, email, hashedPassword, firstName, lastName, phone, role, id];
        }

        const [result] = await conn.query(updateQuery, queryParams);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "User not found." });
        }
        res.status(200).json({ message: "User updated successfully!" });
    } catch (err) {
        console.error("Error updating user:", err);
        res.status(500).json({ error: "Failed to update user." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/delete-user", isAdmin, async (req, res) => {
    let conn;
    try {
        const { id } = req.body;
        if (!id) {
            return res.status(400).json({ error: "User ID is required." });
        }

        conn = await pool.getConnection();
        const [result] = await conn.query("DELETE FROM users WHERE id = ?", [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "User not found." });
        }
        res.status(200).json({ message: "User deleted successfully!" });
    } catch (err) {
        console.error("Error deleting user:", err);
        res.status(500).json({ error: "Failed to delete user." });
    } finally {
        if (conn) conn.release();
    }
});

// --- Admin Settings Endpoints ---

// NEW: GET route to fetch admin settings
app.get("/admin/settings", isAdmin, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        // Fetch the single row for settings (assuming id=1)
        const [settings] = await conn.query("SELECT po_email, registration_email FROM settings WHERE id = 1");

        if (settings.length === 0) {
            // If no settings exist, return default empty values
            return res.status(200).json({ po_email: null, registration_email: null });
        }
        res.status(200).json(settings[0]);
    } catch (err) {
        console.error("Error fetching admin settings:", err);
        res.status(500).json({ error: "Failed to fetch admin settings." });
    } finally {
        if (conn) conn.release();
    }
});

// NEW: POST route to save/update admin settings
app.post("/admin/settings", isAdmin, async (req, res) => {
    let conn;
    try {
        const { po_email, registration_email } = req.body;

        conn = await pool.getConnection();

        // Update the single row for settings (assuming id=1)
        const [result] = await conn.query(
            "UPDATE settings SET po_email = ?, registration_email = ? WHERE id = 1",
            [po_email, registration_email]
        );

        if (result.affectedRows === 0) {
            // This case should ideally not happen if INSERT IGNORE is used on init,
            // but as a fallback, insert if the row doesn't exist.
            await conn.query(
                "INSERT INTO settings (id, po_email, registration_email) VALUES (1, ?, ?) ON DUPLICATE KEY UPDATE po_email = VALUES(po_email), registration_email = VALUES(registration_email)",
                [po_email, registration_email]
            );
        }
        res.status(200).json({ message: "Admin settings updated successfully!" });
    } catch (err) {
        console.error("Error saving admin settings:", err);
        res.status(500).json({ error: "Failed to save admin settings." });
    } finally {
        if (conn) conn.release();
    }
});


// --- Product Endpoints ---
app.get("/products", isAuthenticated, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const [rows] = await conn.query("SELECT * FROM products");
        res.status(200).json(rows);
    } catch (err) {
        console.error("Error fetching products:", err);
        res.status(500).json({ error: "Failed to fetch products." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/products", isAdmin, async (req, res) => {
    let conn;
    try {
        const { name, description, price, imageUrl, category, stockQuantity } = req.body;
        if (!name || !price) {
            return res.status(400).json({ error: "Product name and price are required." });
        }

        conn = await pool.getConnection();
        const [result] = await conn.query(
            "INSERT INTO products (name, description, price, image_url, category, stock_quantity) VALUES (?, ?, ?, ?, ?, ?)",
            [name, description, price, imageUrl, category, stockQuantity]
        );
        res.status(201).json({ message: "Product added successfully!", id: result.insertId });
    } catch (err) {
        console.error("Error adding product:", err);
        res.status(500).json({ error: "Failed to add product." });
    } finally {
        if (conn) conn.release();
    }
});

app.put("/products/:id", isAdmin, async (req, res) => {
    let conn;
    try {
        const { id } = req.params;
        const { name, description, price, imageUrl, category, stockQuantity } = req.body;
        if (!name || !price) {
            return res.status(400).json({ error: "Product name and price are required for update." });
        }

        conn = await pool.getConnection();
        const [result] = await conn.query(
            "UPDATE products SET name = ?, description = ?, price = ?, image_url = ?, category = ?, stock_quantity = ? WHERE id = ?",
            [name, description, price, imageUrl, category, stockQuantity, id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Product not found." });
        }
        res.status(200).json({ message: "Product updated successfully!" });
    } catch (err) {
        console.error("Error updating product:", err);
        res.status(500).json({ error: "Failed to update product." });
    } finally {
        if (conn) conn.release();
    }
});

app.delete("/products/:id", isAdmin, async (req, res) => {
    let conn;
    try {
        const { id } = req.params;
        conn = await pool.getConnection();
        const [result] = await conn.query("DELETE FROM products WHERE id = ?", [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Product not found." });
        }
        res.status(200).json({ message: "Product deleted successfully!" });
    } catch (err) {
        console.error("Error deleting product:", err);
        res.status(500).json({ error: "Failed to delete product." });
    } finally {
        if (conn) conn.release();
    }
});

// --- Cart Endpoints ---
app.get("/cart", isAuthenticated, async (req, res) => {
    let conn;
    try {
        const userId = req.session.userId;
        conn = await pool.getConnection();
        const [cartItems] = await conn.query(`
            SELECT ci.product_id, ci.quantity, p.name, p.price, p.image_url
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            WHERE ci.user_id = ?
        `, [userId]);
        res.status(200).json(cartItems);
    } catch (err) {
        console.error("Error fetching cart items:", err);
        res.status(500).json({ error: "Failed to fetch cart items." });
    } finally {
        if (conn) conn.release();
    }
});

app.post("/cart", isAuthenticated, async (req, res) => {
    let conn;
    try {
        const userId = req.session.userId;
        const { productId, quantity } = req.body;

        if (!productId || !quantity || quantity <= 0) {
            return res.status(400).json({ error: "Product ID and a valid quantity are required." });
        }

        conn = await pool.getConnection();
        await conn.beginTransaction();

        // Check if product exists and has enough stock
        const [products] = await conn.query("SELECT stock_quantity FROM products WHERE id = ?", [productId]);
        if (products.length === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Product not found." });
        }
        const availableStock = products[0].stock_quantity;

        // Check if item already in cart
        const [cartItem] = await conn.query("SELECT quantity FROM cart_items WHERE user_id = ? AND product_id = ?", [userId, productId]);

        let newQuantityInCart = quantity;
        if (cartItem.length > 0) {
            newQuantityInCart += cartItem[0].quantity;
        }

        if (newQuantityInCart > availableStock) {
            await conn.rollback();
            return res.status(400).json({ error: `Not enough stock. Available: ${availableStock}` });
        }

        if (cartItem.length > 0) {
            await conn.query(
                "UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?",
                [newQuantityInCart, userId, productId]
            );
        } else {
            await conn.query(
                "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)",
                [userId, productId, quantity]
            );
        }

        await conn.commit();
        res.status(200).json({ message: "Item added/updated in cart successfully!" });

    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error adding to cart:", err);
        res.status(500).json({ error: "Failed to add item to cart." });
    } finally {
        if (conn) conn.release();
    }
});

app.put("/cart/:productId", isAuthenticated, async (req, res) => {
    let conn;
    try {
        const userId = req.session.userId;
        const { productId } = req.params;
        const { quantity } = req.body;

        if (!quantity || quantity <= 0) {
            return res.status(400).json({ error: "Valid quantity is required." });
        }

        conn = await pool.getConnection();
        await conn.beginTransaction();

        // Check if product exists and has enough stock
        const [products] = await conn.query("SELECT stock_quantity FROM products WHERE id = ?", [productId]);
        if (products.length === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Product not found." });
        }
        const availableStock = products[0].stock_quantity;

        if (quantity > availableStock) {
            await conn.rollback();
            return res.status(400).json({ error: `Not enough stock. Available: ${availableStock}` });
        }

        const [result] = await conn.query(
            "UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?",
            [quantity, userId, productId]
        );

        if (result.affectedRows === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Item not found in cart." });
        }

        await conn.commit();
        res.status(200).json({ message: "Cart item updated successfully!" });

    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error updating cart item:", err);
        res.status(500).json({ error: "Failed to update cart item." });
    } finally {
        if (conn) conn.release();
    }
});

app.delete("/cart/:productId", isAuthenticated, async (req, res) => {
    let conn;
    try {
        const userId = req.session.userId;
        const { productId } = req.params;

        conn = await pool.getConnection();
        const [result] = await conn.query(
            "DELETE FROM cart_items WHERE user_id = ? AND product_id = ?",
            [userId, productId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Item not found in cart." });
        }
        res.status(200).json({ message: "Item removed from cart successfully!" });
    } catch (err) {
        console.error("Error removing from cart:", err);
        res.status(500).json({ error: "Failed to remove item from cart." });
    } finally {
        if (conn) conn.release();
    }
});

// --- Order Endpoints ---
app.post("/submit-order", isAuthenticated, async (req, res) => {
    let conn;
    try {
        const userId = req.session.userId;
        const companyId = req.session.companyId;
        const { poNumber, shippingAddressId } = req.body;

        if (!poNumber || !shippingAddressId) {
            return res.status(400).json({ error: "PO Number and Shipping Address are required." });
        }

        conn = await pool.getConnection();
        await conn.beginTransaction();

        // Fetch cart items
        const [cartItems] = await conn.query(`
            SELECT ci.product_id, ci.quantity, p.price, p.name as product_name
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            WHERE ci.user_id = ?
        `, [userId]);

        if (cartItems.length === 0) {
            await conn.rollback();
            return res.status(400).json({ error: "Cart is empty." });
        }

        // Fetch company discount
        const [companies] = await conn.query("SELECT discount FROM companies WHERE id = ?", [companyId]);
        const companyDiscount = companies.length > 0 ? (companies[0].discount / 100) : 0;

        let totalAmount = 0;
        for (const item of cartItems) {
            totalAmount += item.quantity * item.price;
        }

        // Apply discount
        totalAmount -= (totalAmount * companyDiscount);
        totalAmount = parseFloat(totalAmount.toFixed(2)); // Round to 2 decimal places

        // Insert into orders table
        const [orderResult] = await conn.query(
            "INSERT INTO orders (user_id, company_id, total_amount, po_number, shipping_address_id) VALUES (?, ?, ?, ?, ?)",
            [userId, companyId, totalAmount, poNumber, shippingAddressId]
        );
        const orderId = orderResult.insertId;

        // Insert into order_items and update product stock
        for (const item of cartItems) {
            await conn.query(
                "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
                [orderId, item.product_id, item.quantity, item.price]
            );
            await conn.query(
                "UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?",
                [item.quantity, item.product_id]
            );
        }

        // Clear the cart
        await conn.query("DELETE FROM cart_items WHERE user_id = ?", [userId]);

        await conn.commit();

        // --- PDF Generation and Email Notification ---
        let browser;
        let pdfBuffer = null;
        let tempDir = null;

        try {
            // Determine the executable path for Chromium
            const executablePath = await chromium.executablePath;

            // Create a unique temporary directory for the user data dir
            tempDir = path.join(os.tmpdir(), uuidv4());
            await fs.mkdir(tempDir, { recursive: true });

            browser = await puppeteer.launch({
                args: [...chromium.args, `--user-data-dir=${tempDir}`], // Use the temp directory
                executablePath: executablePath,
                headless: chromium.headless,
            });
            const page = await browser.newPage();

            // Construct HTML for the PDF
            const orderDetailsHtml = `
                <h1 style="text-align: center;">Purchase Order</h1>
                <p><strong>Order ID:</strong> ${orderId}</p>
                <p><strong>PO Number:</strong> ${poNumber}</p>
                <p><strong>Order Date:</strong> ${new Date().toLocaleDateString()}</p>
                <p><strong>Total Amount:</strong> $${totalAmount.toFixed(2)}</p>
                <h3>Items:</h3>
                <table border="1" cellspacing="0" cellpadding="5" width="100%">
                    <thead>
                        <tr>
                            <th>Product</th>
                            <th>Quantity</th>
                            <th>Price</th>
                            <th>Subtotal</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${cartItems.map(item => `
                            <tr>
                                <td>${item.product_name}</td>
                                <td>${item.quantity}</td>
                                <td>$${item.price.toFixed(2)}</td>
                                <td>$${(item.quantity * item.price).toFixed(2)}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
                <p><strong>Company Discount Applied:</strong> ${ (companyDiscount * 100).toFixed(2) }%</p>
                <p><strong>Final Total:</strong> $${totalAmount.toFixed(2)}</p>
            `;

            await page.setContent(orderDetailsHtml, { waitUntil: 'networkidle0' });
            pdfBuffer = await page.pdf({ format: 'A4' });

        } catch (pdfError) {
            console.error("Error generating PDF:", pdfError);
            // Do not block the order submission if PDF generation fails
        } finally {
            if (browser) {
                await browser.close();
                // Clean up the temporary directory
                if (tempDir) {
                    await fs.rm(tempDir, { recursive: true, force: true });
                }
            }
        }

        // Fetch PO email setting
        const [settings] = await conn.query("SELECT po_email FROM settings WHERE id = 1");
        const poEmailRecipient = settings.length > 0 ? settings[0].po_email : null;

        if (!poEmailRecipient) {
            console.warn("PO Email recipient not configured in settings. Skipping email notification.");
            return res.status(200).json({ message: "Order submitted successfully! PO Email recipient not configured." });
        }

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: poEmailRecipient, // Send to the configured PO email
            subject: `New Purchase Order #${poNumber} (Order ID: ${orderId})`,
            html: `
                <p>A new purchase order has been submitted:</p>
                <ul>
                    <li><strong>Order ID:</strong> ${orderId}</li>
                    <li><strong>PO Number:</strong> ${poNumber}</li>
                    <li><strong>Total Amount:</strong> $${totalAmount.toFixed(2)}</li>
                </ul>
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


// --- Shipping Address Endpoints ---
// Get shipping addresses for a company
app.get("/api/shipto/:companyId", isAuthenticated, async (req, res) => {
    let conn;
    try {
        const { companyId } = req.params;
        // Ensure the logged-in user is associated with this company, or is an admin
        if (req.session.role !== 'admin' && req.session.companyId !== parseInt(companyId, 10)) {
            return res.status(403).json({ error: "Access denied to shipping addresses for this company." });
        }

        conn = await pool.getConnection();
        const [addresses] = await conn.query("SELECT * FROM shipping_addresses WHERE company_id = ?", [companyId]);
        res.status(200).json(addresses);
    } catch (err) {
        console.error("Error fetching shipping addresses:", err);
        res.status(500).json({ error: "Failed to fetch shipping addresses." });
    } finally {
        if (conn) conn.release();
    }
});

// Add a new shipping address
app.post("/api/shipto", isAuthenticated, async (req, res) => {
    let conn;
    try {
        const { companyId, name, company_name, address1, city, state, zip, country } = req.body;
        
        // Ensure the logged-in user is associated with this company, or is an admin
        if (req.session.role !== 'admin' && req.session.companyId !== parseInt(companyId, 10)) {
            return res.status(403).json({ error: "Unauthorized to add address for this company." });
        }

        if (!companyId || !name || !address1 || !city || !state || !zip) {
            return res.status(400).json({ error: "Company ID, address reference, address, city, state, and zip are required." });
        }

        conn = await pool.getConnection();
        const [result] = await conn.query(
            "INSERT INTO shipping_addresses (company_id, name, company_name, address1, city, state, zip, country) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [companyId, name, company_name, address1, city, state, zip, country]
        );
        res.status(201).json({ message: "Shipping address added successfully!", id: result.insertId });
    } catch (err) {
        console.error("Error adding shipping address:", err);
        res.status(500).json({ error: "Failed to add shipping address." });
    } finally {
        if (conn) conn.release();
    }
});

// Update a shipping address
app.put("/api/shipto/:id", isAuthenticated, async (req, res) => {
    let conn;
    try {
        const { id } = req.params;
        const { name, company_name, address1, city, state, zip, country } = req.body;

        if (!name || !address1 || !city || !state || !zip) {
            return res.status(400).json({ error: "Address reference, address, city, state, and zip are required for update." });
        }

        conn = await pool.getConnection();

        // First, get the company_id of the address to ensure authorization
        const [addresses] = await conn.query("SELECT company_id FROM shipping_addresses WHERE id = ?", [id]);
        if (addresses.length === 0) {
            return res.status(404).json({ error: "Shipping address not found." });
        }
        const addressCompanyId = addresses[0].company_id;

        // Ensure the logged-in user is associated with this company, or is an admin
        if (req.session.role !== 'admin' && req.session.companyId !== addressCompanyId) {
            return res.status(403).json({ error: "Unauthorized to update this address." });
        }

        const [result] = await conn.query(
            "UPDATE shipping_addresses SET name = ?, company_name = ?, address1 = ?, city = ?, state = ?, zip = ?, country = ? WHERE id = ?",
            [name, company_name, address1, city, state, zip, country, id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Shipping address not found." });
        }
        res.status(200).json({ message: "Shipping address updated successfully!" });
    } catch (err) {
        console.error("Error updating shipping address:", err);
        res.status(500).json({ error: "Failed to update shipping address." });
    } finally {
        if (conn) conn.release();
    }
});

// Delete a shipping address
app.delete("/api/shipto/:id", isAuthenticated, async (req, res) => {
    let conn;
    try {
        const { id } = req.params;

        conn = await pool.getConnection();

        // First, get the company_id of the address to ensure authorization
        const [addresses] = await conn.query("SELECT company_id FROM shipping_addresses WHERE id = ?", [id]);
        if (addresses.length === 0) {
            return res.status(404).json({ error: "Shipping address not found." });
        }
        const addressCompanyId = addresses[0].company_id;

        // Ensure the logged-in user is associated with this company, or is an admin
        if (req.session.role !== 'admin' && req.session.companyId !== addressCompanyId) {
            return res.status(403).json({ error: "Unauthorized to delete this address." });
        }

        const [result] = await conn.query("DELETE FROM shipping_addresses WHERE id = ?", [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Shipping address not found." });
        }
        res.status(200).json({ message: "Shipping address deleted successfully!" });
    } catch (err) {
        console.error("Error deleting shipping address:", err);
        res.status(500).json({ error: "Failed to delete shipping address." });
    } finally {
        if (conn) conn.release();
    }
});

// Set a shipping address as default for a company
app.put("/api/shipto/:id/set-default", isAuthenticated, async (req, res) => {
    let conn;
    try {
        const { id } = req.params; // The ID of the address to make default
        const { companyId } = req.body; // The company ID this address belongs to

        if (!companyId) {
            return res.status(400).json({ error: "Company ID is required." });
        }

        conn = await pool.getConnection();
        await conn.beginTransaction();

        // Ensure the logged-in user is associated with this company, or is an admin
        if (req.session.role !== 'admin' && req.session.companyId !== parseInt(companyId, 10)) {
            await conn.rollback();
            return res.status(403).json({ error: "Unauthorized to modify addresses for this company." });
        }

        // 1. Set all other addresses for this company to not default
        await conn.query("UPDATE shipping_addresses SET is_default = FALSE WHERE company_id = ?", [companyId]);

        // 2. Set the specified address to default
        const [result] = await conn.query(
            "UPDATE shipping_addresses SET is_default = TRUE WHERE id = ? AND company_id = ?",
            [id, companyId]
        );

        if (result.affectedRows === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Shipping address not found or does not belong to the specified company." });
        }

        await conn.commit();
        res.status(200).json({ message: "Shipping address set as default successfully!" });
    } catch (err) {
        if (conn) await conn.rollback();
        console.error("Error setting default shipping address:", err);
        res.status(500).json({ error: "Failed to set default shipping address." });
    } finally {
        if (conn) conn.release();
    }
});


// --- General Routes and Server Start ---

app.get("/", (req, res) => {
  res.redirect("/admin-dashboard.html"); // Redirect to admin dashboard by default
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
