const express = require("express");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise");
const path = require("path");

// NEW: Import the MySQL session store
const MySQLStore = require('express-mysql-session')(session);

const app = express();
const PORT = process.env.PORT || 3000;

// Separate database configuration for direct MySQL2 connections
const dbConnectionConfig = {
  host: "192.254.232.38",
  user: "gmistarz_cse",
  password: "Csec@1280",
  database: "gmistarz_cse",
  // No session-specific options here
  // port: 3306, // Uncomment if your MySQL server is not on the default port
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
  connectionLimit: 10,
};

const sessionStore = new MySQLStore(sessionStoreOptions);

// Middleware
app.use(cors({
    origin: "http://192.254.232.38", // Ensure this matches your frontend URL
    credentials: true,
}));
app.use(express.json()); // Body parser for JSON
app.use(express.static(path.join(__dirname, 'public')));

// Session Middleware
app.use(session({
    secret: 'SuperSecretKey_For_Session_Security',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true if using HTTPS (for production)
        httpOnly: true,
        maxAge: 86400000, // 24 hours
    }
}));

// Authorization Middleware
const requireAuth = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ error: "Unauthorized" });
    }
};

const requireAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: "Forbidden" });
    }
};

// --- Authentication Routes ---
app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [rows] = await conn.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", [username]);

        if (rows.length > 0) {
            const user = rows[0];
            const passwordMatch = await bcrypt.compare(password, user.password_hash);

            if (passwordMatch) {
                req.session.user = { id: user.id, username: user.username, role: user.role };
                res.json({ message: "Login successful", user: { username: user.username, role: user.role } });
            } else {
                res.status(401).json({ error: "Invalid credentials" });
            }
        } else {
            res.status(401).json({ error: "Invalid credentials" });
        }
    } catch (err) {
        console.error("Error during login:", err);
        res.status(500).json({ error: "Internal server error" });
    } finally {
        if (conn) conn.end();
    }
});

app.get("/api/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: "Failed to log out" });
        }
        res.status(200).json({ message: "Logged out successfully" });
    });
});

app.get("/api/check-auth", (req, res) => {
    if (req.session.user) {
        res.json({ isAuthenticated: true, user: req.session.user });
    } else {
        res.json({ isAuthenticated: false });
    }
});

// --- Company Routes ---

// Get all companies (Admin only)
app.get("/api/companies", requireAdmin, async (req, res) => {
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [rows] = await conn.execute("SELECT id, name, description, logo, billing_address, phone, fax, email, website FROM companies");
        res.json(rows);
    } catch (err) {
        console.error("Error fetching companies:", err);
        res.status(500).json({ error: "Failed to fetch companies" });
    } finally {
        if (conn) conn.end();
    }
});

// Get a single company by ID
app.get("/api/companies/:id", requireAdmin, async (req, res) => {
    const { id } = req.params;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [rows] = await conn.execute("SELECT id, name, description, logo, billing_address, phone, fax, email, website FROM companies WHERE id = ?", [id]);
        if (rows.length > 0) {
            res.json(rows[0]);
        } else {
            res.status(404).json({ error: "Company not found" });
        }
    } catch (err) {
        console.error("Error fetching company:", err);
        res.status(500).json({ error: "Failed to fetch company" });
    } finally {
        if (conn) conn.end();
    }
});

// Create a new company
app.post("/api/companies", requireAdmin, async (req, res) => {
    const { name, description, logo, billing_address, phone, fax, email, website } = req.body;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [result] = await conn.execute(
            "INSERT INTO companies (name, description, logo, billing_address, phone, fax, email, website) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [name, description, logo, billing_address, phone, fax, email, website]
        );
        res.status(201).json({ id: result.insertId, message: "Company created successfully" });
    } catch (err) {
        console.error("Error creating company:", err);
        res.status(500).json({ error: "Failed to create company" });
    } finally {
        if (conn) conn.end();
    }
});

// Update an existing company
app.put("/api/companies/:id", requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, description, logo, billing_address, phone, fax, email, website } = req.body;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [result] = await conn.execute(
            "UPDATE companies SET name = ?, description = ?, logo = ?, billing_address = ?, phone = ?, fax = ?, email = ?, website = ? WHERE id = ?",
            [name, description, logo, billing_address, phone, fax, email, website, id]
        );
        if (result.affectedRows > 0) {
            res.json({ message: "Company updated successfully" });
        } else {
            res.status(404).json({ error: "Company not found" });
        }
    } catch (err) {
        console.error("Error updating company:", err);
        res.status(500).json({ error: "Failed to update company" });
    } finally {
        if (conn) conn.end();
    }
});

// Delete a company
app.delete("/api/companies/:id", requireAdmin, async (req, res) => {
    const { id } = req.params;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [result] = await conn.execute("DELETE FROM companies WHERE id = ?", [id]);
        if (result.affectedRows > 0) {
            res.json({ message: "Company deleted successfully" });
        } else {
            res.status(404).json({ error: "Company not found" });
        }
    } catch (err) {
        console.error("Error deleting company:", err);
        res.status(500).json({ error: "Failed to delete company" });
    } finally {
        if (conn) conn.end();
    }
});

// --- Ship-to Address Routes ---

// Get all ship-to addresses for a specific company
app.get("/api/companies/:companyId/shipto", requireAdmin, async (req, res) => {
    const { companyId } = req.params;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        const [rows] = await conn.execute(
            "SELECT id, company_id, name, address1, address2, city, state, zip, country, is_default FROM shipto_addresses WHERE company_id = ? ORDER BY is_default DESC, name",
            [companyId]
        );
        res.json(rows);
    } catch (err) {
        console.error("Error fetching ship-to addresses:", err);
        res.status(500).json({ error: "Failed to fetch ship-to addresses" });
    } finally {
        if (conn) conn.end();
    }
});

// Add a new ship-to address
app.post("/api/shipto", requireAdmin, async (req, res) => {
    const { companyId, name, address1, address2, city, state, zip, country, is_default } = req.body;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        await conn.beginTransaction();

        // If the new address is marked as default, unset previous defaults
        if (is_default) {
            await conn.execute("UPDATE shipto_addresses SET is_default = 0 WHERE company_id = ?", [companyId]);
        }

        // Insert the new address
        const [result] = await conn.execute(
            `INSERT INTO shipto_addresses (company_id, name, address1, address2, city, state, zip, country, is_default) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [companyId, name, address1, address2, city, state, zip, country, is_default ? 1 : 0]
        );

        await conn.commit();
        res.status(201).json({ id: result.insertId, message: "Address added successfully" });

    } catch (err) {
        if (conn) {
            await conn.rollback();
        }
        console.error("Error adding ship-to address:", err);
        res.status(500).json({ error: "Failed to add ship-to address" });
    } finally {
        if (conn) conn.end();
    }
});

// Update an existing ship-to address (Now handles is_default)
app.put("/api/shipto/:addressId", requireAdmin, async (req, res) => {
    const { addressId } = req.params;
    // Ensure all fields, including isDefault, are extracted from the request body
    const { companyId, name, address1, address2, city, state, zip, country, isDefault } = req.body;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        await conn.beginTransaction(); // Start a transaction for consistency

        // 1. If isDefault is true, unset all other defaults for this company
        if (isDefault) {
             await conn.execute(
                `UPDATE shipto_addresses SET is_default = 0 WHERE company_id = ? AND id != ?`,
                [companyId, addressId]
            );
        }

        // 2. Update the selected address, including the is_default status
        const [result] = await conn.execute(
            `UPDATE shipto_addresses SET name = ?, address1 = ?, address2 = ?, city = ?, state = ?, zip = ?, country = ?, is_default = ? WHERE id = ?`,
            [name, address1, address2, city, state, zip, country, isDefault ? 1 : 0, addressId]
        );

        if (result.affectedRows === 0) {
            await conn.rollback();
            return res.status(404).json({ error: "Address not found or update failed." });
        }

        await conn.commit(); // Commit the transaction
        res.json({ message: "Address updated successfully" });

    } catch (err) {
        if (conn) {
            await conn.rollback(); // Rollback on error
        }
        console.error("Error updating ship-to address:", err);
        res.status(500).json({ error: "Failed to update ship-to address" });
    } finally {
        if (conn) conn.end();
    }
});


// Dedicated endpoint to set a default address
app.put("/api/shipto/:addressId/set-default", requireAdmin, async (req, res) => {
    const { addressId } = req.params;
    const { companyId } = req.body; // Expecting companyId in the request body
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        await conn.beginTransaction(); // Start transaction

        // 1. Unset the default for all other addresses of the company
        const [unsetResult] = await conn.execute(
            "UPDATE shipto_addresses SET is_default = 0 WHERE company_id = ?",
            [companyId]
        );

        // 2. Set the requested address as the default (is_default = 1)
        const [setResult] = await conn.execute(
            "UPDATE shipto_addresses SET is_default = 1 WHERE id = ? AND company_id = ?",
            [addressId, companyId]
        );

        if (setResult.affectedRows === 0) {
            await conn.rollback();
            // Handle case where addressId might not belong to the company (or doesn't exist)
            return res.status(404).json({ error: "Address not found or does not belong to your company." });
        }

        await conn.commit(); // Commit the transaction if both updates succeed
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

// Delete a ship-to address
app.delete("/api/shipto/:addressId", requireAdmin, async (req, res) => {
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

// --- General Routes and Server Start ---
app.get("/", (req, res) => {
    res.send("API Server is running.");
});

// Serve the admin-dashboard.html file
app.get("/admin-dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

// Serve the login.html file
app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});