const express = require("express");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise"); // Ensure you're using the promise version
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
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true
}));

// --- Session & Body Parsing ---
app.use(express.json());
app.set("trust proxy", 1); // Essential for 'secure: true' cookies when behind a proxy/load balancer like Render

app.use(session({
  secret: "secret-key", // Replace with a strong, unique secret key in production
  resave: false,
  saveUninitialized: false,
  store: sessionStore, // <-- THIS IS THE CRUCIAL CHANGE for persistent sessions
  cookie: {
    sameSite: "none",  // Required for cross-site cookies
    secure: true,      // Required for sameSite: "none" and highly recommended for production (Render provides HTTPS)
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// --- Helper Middleware for Admin Check ---
const requireAdmin = (req, res, next) => {
    // console.log("Checking session for admin role:", req.session.user); // Optional: for more debugging
    if (!req.session.user || req.session.user.role !== "admin") {
        return res.status(403).json({ error: "Forbidden: Admin access required" }); // More specific message
    }
    next();
};

// --- Authentication Routes ---

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let conn; // Declare conn outside try-finally to ensure it's accessible for closing
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    const [users] = await conn.execute("SELECT * FROM users WHERE email = ?", [email]);

    const user = users[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Set user data in session
    req.session.user = { id: user.id, email: user.email, role: user.role, companyId: user.company_id };
    
    // Log for debugging on Render
    console.log(`[Login Success] req.session.user set to: ${JSON.stringify(req.session.user)}`);
    
    res.json({ message: "Login successful", role: user.role });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed due to server error" });
  } finally {
    if (conn) conn.end(); // Ensure connection is closed
  }
});

app.get("/user-profile", async (req, res) => {
  const { user } = req.session;
  if (!user) return res.status(401).json({ error: "Not logged in" });

  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    const [rows] = await conn.execute(
      "SELECT email, role, company_id FROM users WHERE email = ?",
      [user.email]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error("User profile error:", err);
    res.status(500).json({ error: "Failed to retrieve user profile" });
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

// --- Company Routes ---

app.get("/companies", requireAdmin, async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    const [companies] = await conn.execute("SELECT * FROM companies");
    res.json(companies);
  } catch (err) {
    console.error("Failed to retrieve companies:", err);
    res.status(500).json({ error: "Failed to retrieve companies" });
  } finally {
    if (conn) conn.end();
  }
});

app.post("/edit-company", requireAdmin, async (req, res) => {
  const { id, name, address1, address2, city, state, zip, country, terms, logo } = req.body;
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    await conn.execute(
      `UPDATE companies SET name = ?, address1 = ?, address2 = ?, city = ?, state = ?, zip = ?, country = ?, terms = ?, logo = ? WHERE id = ?`,
      [name, address1, address2, city, state, zip, country, terms, logo, id]
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
    name, logo, address1, address2, city, state, zip, country, terms
  } = req.body;
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    await conn.execute(`
      INSERT INTO companies (name, logo, address1, address2, city, state, zip, country, terms)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [name, logo, address1, address2, city, state, zip, country, terms]);
    res.status(200).json({ message: "Company created" });
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
    // Deleting company also removes associated users and ship-to addresses due to CASCADE ON DELETE in the foreign keys
    await conn.execute("DELETE FROM companies WHERE id = ?", [id]);
    res.json({ message: "Company deleted" });
  } catch (err) {
    console.error("Failed to delete company:", err);
    res.status(500).json({ error: "Failed to delete company" });
  } finally {
    if (conn) conn.end();
  }
});

// --- User Routes ---

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
  } catch (err) {
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
app.get("/api/shipto/:companyId", requireAdmin, async (req, res) => {
    const { companyId } = req.params;
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
        const [addresses] = await conn.execute("SELECT * FROM shipto_addresses WHERE company_id = ?", [companyId]);
        res.json(addresses);
    } catch (err) {
        console.error("Error fetching ship-to addresses:", err);
        res.status(500).json({ error: "Failed to retrieve ship-to addresses" });
    } finally {
        if (conn) conn.end();
    }
});

// Add a new ship-to address
app.post("/api/shipto", requireAdmin, async (req, res) => {
    const { companyId, name, address1, address2, city, state, zip, country, is_default } = req.body;
    
    // Updated validation: removed the requirement for 'country'
    if (!companyId || !address1 || !city || !state || !zip) {
        return res.status(400).json({ error: "Missing required fields." });
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
        const [result] = await conn.execute(
            `INSERT INTO shipto_addresses (company_id, name, address1, address2, city, state, zip, country, is_default) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [companyId, name, address1, address2, city, state, zip, country, is_default ? 1 : 0]
        );
        res.status(201).json({ id: result.insertId, message: "Address added successfully" });
    } catch (err) {
        console.error("Error adding ship-to address:", err);
        res.status(500).json({ error: "Failed to add ship-to address" });
    } finally {
        if (conn) conn.end();
    }
});

// Update an existing ship-to address (DOES NOT handle is_default yet)
app.put("/api/shipto/:addressId", requireAdmin, async (req, res) => {
    const { addressId } = req.params;
    const { name, address1, address2, city, state, zip, country } = req.body; // is_default is not in this body
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
        await conn.execute(
            `UPDATE shipto_addresses SET name = ?, address1 = ?, address2 = ?, city = ?, state = ?, zip = ?, country = ? WHERE id = ?`,
            [name, address1, address2, city, state, zip, country, addressId]
        );
        res.json({ message: "Address updated successfully" });
    } catch (err) {
        console.error("Error updating ship-to address:", err);
        res.status(500).json({ error: "Failed to update ship-to address" });
    } finally {
        if (conn) conn.end();
    }
});

// NEW ENDPOINT: Set a specific address as default
app.put("/api/shipto/:addressId/set-default", requireAdmin, async (req, res) => {
    const { addressId } = req.params;
    // We need the companyId to unset other defaults for the same company
    const { companyId } = req.session.user; // Assuming companyId is in session for the admin user

    if (!companyId) {
        return res.status(400).json({ error: "Company ID not found in session." });
    }

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
        await conn.beginTransaction(); // Start a transaction

        // 1. Unset the 'is_default' flag for all other addresses of this company
        await conn.execute(
            `UPDATE shipto_addresses SET is_default = 0 WHERE company_id = ? AND id != ?`,
            [companyId, addressId]
        );

        // 2. Set the 'is_default' flag to 1 for the selected address
        const [result] = await conn.execute(
            `UPDATE shipto_addresses SET is_default = 1 WHERE id = ? AND company_id = ?`,
            [addressId, companyId]
        );

        if (result.affectedRows === 0) {
            await conn.rollback(); // Rollback if no row was updated (e.g., addressId doesn't exist or doesn't belong to company)
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
  res.redirect("/admin-dashboard.html"); 
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});