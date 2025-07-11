const express = require("express");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const dbConfig = {
  host: "192.254.232.38",
  user: "gmistarz_cse",
  password: "Csec@1280",
  database: "gmistarz_cse"
};

const allowedOrigins = [
  "https://www.chicagostainless.com",
  "https://checkout-backend-jvyx.onrender.com"
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
app.set("trust proxy", 1);
app.use(session({
  secret: "secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production", // Use secure cookies in production
    httpOnly: true,
    sameSite: "lax", // Adjust as needed, 'none' for cross-site with secure:true
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Middleware to check if the user is authenticated and is an admin
const requireAdmin = (req, res, next) => {
  if (req.session && req.session.user && req.session.user.role === "admin") {
    next();
  } else {
    res.status(403).json({ error: "Access denied. Admin privileges required." });
  }
};

// --- Routes ---

// Login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);
    const [rows] = await conn.execute("SELECT * FROM users WHERE email = ?", [email]);
    conn.end();

    if (rows.length > 0) {
      const user = rows[0];
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (passwordMatch) {
        req.session.user = { id: user.id, email: user.email, role: user.role };
        res.json({ message: "Login successful", user: { id: user.id, email: user.email, role: user.role } });
      } else {
        res.status(401).json({ error: "Invalid credentials" });
      }
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Logout route
app.post("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: "Failed to log out" });
    }
    res.clearCookie("connect.sid"); // Clear session cookie
    res.json({ message: "Logged out successfully" });
  });
});

// Get all companies (admin only)
app.get("/companies", requireAdmin, async (req, res) => {
  try {
    const conn = await mysql.createConnection(dbConfig);
    const [rows] = await conn.execute("SELECT * FROM companies");
    conn.end();
    res.json(rows);
  } catch (err) {
    console.error("Error fetching companies:", err);
    res.status(500).json({ error: "Failed to fetch companies" });
  }
});

// Add a new company (admin only)
app.post("/add-company", requireAdmin, async (req, res) => {
  const { name, logo, address1, address2, city, state, zip, country, terms } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);
    const [result] = await conn.execute(
      `INSERT INTO companies (name, logo, address1, address2, city, state, zip, country, terms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [name, logo, address1, address2, city, state, zip, country, terms]
    );
    conn.end();
    res.status(201).json({ message: "Company added successfully", id: result.insertId });
  } catch (err) {
    console.error("Error adding company:", err);
    res.status(500).json({ error: "Failed to add company" });
  }
});

// Edit an existing company (admin only)
app.post("/edit-company", requireAdmin, async (req, res) => {
  const { id, name, logo, address1, address2, city, state, zip, country, terms } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute(
      `UPDATE companies SET name = ?, logo = ?, address1 = ?, address2 = ?, city = ?, state = ?, zip = ?, country = ?, terms = ? WHERE id = ?`,
      [name, logo, address1, address2, city, state, zip, country, terms, id]
    );
    conn.end();
    res.json({ message: "Company updated successfully" });
  } catch (err) {
    console.error("Error updating company:", err);
    res.status(500).json({ error: "Failed to update company" });
  }
});

// Delete a company (admin only)
app.post("/delete-company", requireAdmin, async (req, res) => {
  const { id } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);
    // Delete associated users first
    await conn.execute("DELETE FROM users WHERE company_id = ?", [id]);
    // Then delete the company
    await conn.execute("DELETE FROM companies WHERE id = ?", [id]);
    conn.end();
    res.json({ message: "Company deleted successfully" });
  } catch (err) {
    console.error("Error deleting company:", err);
    res.status(500).json({ error: "Failed to delete company" });
  }
});

// Get users for a specific company (admin only)
app.get("/company-users/:companyId", requireAdmin, async (req, res) => {
  const { companyId } = req.params;
  try {
    const conn = await mysql.createConnection(dbConfig);
    const [rows] = await conn.execute("SELECT id, email, first_name, last_name, phone, role FROM users WHERE company_id = ?", [companyId]);
    conn.end();
    res.json(rows);
  } catch (err) {
    console.error("Error fetching company users:", err);
    res.status(500).json({ error: "Failed to fetch company users" });
  }
});

// Add a new user (admin only)
app.post("/add-user", requireAdmin, async (req, res) => {
  const { companyId, email, firstName, lastName, phone, role, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute(
      `INSERT INTO users (company_id, email, first_name, last_name, phone, role, password) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [companyId, email, firstName, lastName, phone, role, hashedPassword]
    );
    conn.end();
    res.status(201).json({ message: "User added successfully" });
  } catch (err) {
    console.error("Error adding user:", err);
    res.status(500).json({ error: "Failed to add user" });
  }
});

// Edit an existing user (admin only)
app.post("/edit-user", requireAdmin, async (req, res) => {
  const { id, email, firstName, lastName, phone, role, password } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);
    let query = `UPDATE users SET email = ?, first_name = ?, last_name = ?, phone = ?, role = ?`;
    const params = [email, firstName, lastName, phone, role];

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      query += `, password = ?`;
      params.push(hashedPassword);
    }

    query += ` WHERE id = ?`;
    params.push(id);

    await conn.execute(query, params);
    conn.end();
    res.json({ message: "User updated successfully" });
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).json({ error: "Failed to update user" });
  }
});

// Delete a user (admin only)
app.post("/delete-user", requireAdmin, async (req, res) => {
  const { id } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute("DELETE FROM users WHERE id = ?", [id]);
    conn.end();
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).json({ error: "Failed to delete user" });
  }
});

// --- Ship-to Addresses API (Admin Only) ---

// Get all ship-to addresses for a company
app.get("/api/shipto/:companyId", requireAdmin, async (req, res) => {
  const { companyId } = req.params;
  try {
    const conn = await mysql.createConnection(dbConfig);
    // MODIFIED: Select the is_default column
    const [rows] = await conn.execute("SELECT id, name, address1, address2, city, state, zip, country, is_default FROM shipto_addresses WHERE company_id = ?", [companyId]);
    conn.end();
    res.json(rows);
  } catch (err) {
    console.error("Error fetching ship-to addresses:", err);
    res.status(500).json({ error: "Failed to fetch ship-to addresses" });
  }
});

// Add a new ship-to address
app.post("/api/shipto", requireAdmin, async (req, res) => {
  const { companyId, name, address1, address2, city, state, zip, country, isDefault } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);

    // If setting as default, unset all other defaults for this company
    if (isDefault) {
      await conn.execute(
        `UPDATE shipto_addresses SET is_default = FALSE WHERE company_id = ?`,
        [companyId]
      );
    }

    // MODIFIED: Include is_default in the INSERT statement
    const [result] = await conn.execute(
      `INSERT INTO shipto_addresses (company_id, name, address1, address2, city, state, zip, country, is_default) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [companyId, name, address1, address2, city, state, zip, country, isDefault]
    );
    conn.end();
    res.status(201).json({ message: "Address added successfully", id: result.insertId });
  } catch (err) {
    console.error("Error adding ship-to address:", err);
    res.status(500).json({ error: "Failed to add ship-to address" });
  }
});

// Update a ship-to address
app.put("/api/shipto/:addressId", requireAdmin, async (req, res) => {
  const { addressId } = req.params;
  const { name, address1, address2, city, state, zip, country, isDefault, companyId } = req.body; // Added companyId from body for default logic

  try {
    const conn = await mysql.createConnection(dbConfig);

    // If setting as default, unset all other defaults for this company
    if (isDefault) {
      await conn.execute(
        `UPDATE shipto_addresses SET is_default = FALSE WHERE company_id = ? AND id != ?`,
        [companyId, addressId]
      );
    }

    // MODIFIED: Include is_default in the UPDATE statement
    await conn.execute(
      `UPDATE shipto_addresses SET name = ?, address1 = ?, address2 = ?, city = ?, state = ?, zip = ?, country = ?, is_default = ? WHERE id = ?`,
      [name, address1, address2, city, state, zip, country, isDefault, addressId]
    );
    conn.end();
    res.json({ message: "Address updated successfully" });
  } catch (err) {
    console.error("Error updating ship-to address:", err);
    res.status(500).json({ error: "Failed to update ship-to address" });
  }
});

// Delete a ship-to address
app.delete("/api/shipto/:addressId", requireAdmin, async (req, res) => {
  const { addressId } = req.params;
  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute("DELETE FROM shipto_addresses WHERE id = ?", [addressId]);
    conn.end();
    res.json({ message: "Address deleted successfully" });
  } catch (err) {
    console.error("Error deleting ship-to address:", err);
    res.status(500).json({ error: "Failed to delete ship-to address" });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
