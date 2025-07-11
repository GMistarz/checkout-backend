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
  "https://checkout-backend-jvyx.onrender.com",
  // Added the frontend origin to allow CORS requests from the Canvas environment
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
app.set("trust proxy", 1);
app.use(session({
  secret: "secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: "none",
    secure: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// --- Helper Middleware for Admin Check ---
const requireAdmin = (req, res, next) => {
    if (!req.session.user || req.session.user.role !== "admin") {
        return res.status(403).json({ error: "Forbidden" });
    }
    next();
};

// --- Authentication Routes ---

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const conn = await mysql.createConnection(dbConfig);
  const [users] = await conn.execute("SELECT * FROM users WHERE email = ?", [email]);
  conn.end();

  const user = users[0];
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  req.session.user = { email: user.email, role: user.role, companyId: user.company_id };
  res.json({ message: "Login successful", role: user.role });
});

app.get("/user-profile", async (req, res) => {
  const { user } = req.session;
  if (!user) return res.status(401).json({ error: "Not logged in" });

  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute(
    "SELECT email, role, company_id FROM users WHERE email = ?",
    [user.email]
  );
  conn.end();

  res.json(rows[0]);
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Logout failed" });
    res.clearCookie("connect.sid", { path: "/" });
    res.json({ message: "Logged out" });
  });
});

// --- Company Routes ---

app.get("/companies", requireAdmin, async (req, res) => {
  try {
    const conn = await mysql.createConnection(dbConfig);
    const [companies] = await conn.execute("SELECT * FROM companies");
    conn.end();
    res.json(companies);
  } catch (err) {
    res.status(500).json({ error: "Failed to retrieve companies" });
  }
});

app.post("/edit-company", requireAdmin, async (req, res) => {
  const { id, name, address1, address2, city, state, zip, country, terms, logo } = req.body;

  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute(
      `UPDATE companies SET name = ?, address1 = ?, address2 = ?, city = ?, state = ?, zip = ?, country = ?, terms = ?, logo = ? WHERE id = ?`,
      [name, address1, address2, city, state, zip, country, terms, logo, id]
    );
    conn.end();
    res.json({ message: "Company updated" });
  } catch (err) {
    res.status(500).json({ error: "Failed to update company" });
  }
});

app.post('/add-company', requireAdmin, async (req, res) => {
  const {
    name, logo, address1, address2, city, state, zip, country, terms
  } = req.body;

  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute(`
      INSERT INTO companies (name, logo, address1, address2, city, state, zip, country, terms)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [name, logo, address1, address2, city, state, zip, country, terms]);
    conn.end();

    res.status(200).json({ message: "Company created" });
  } catch (err) {
    console.error("Failed to create company:", err);
    res.status(500).json({ error: "Failed to create company" });
  }
});

app.post("/delete-company", requireAdmin, async (req, res) => {
  const { id } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);

    // Deleting company also removes associated users and ship-to addresses due to CASCADE ON DELETE in the foreign keys
    await conn.execute("DELETE FROM companies WHERE id = ?", [id]);

    conn.end();
    res.json({ message: "Company deleted" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete company" });
  }
});

// --- User Routes ---

app.post("/add-user", async (req, res) => {
  const { email, firstName, lastName, phone, role, password, companyId } = req.body;
  if (!email || !companyId || !password) {
    return res.status(400).json({ error: "Email, password, and companyId are required." });
  }

  try {
    const conn = await mysql.createConnection(dbConfig);
    const hashedPassword = await bcrypt.hash(password, 10);
    await conn.execute(
      `INSERT INTO users (email, first_name, last_name, phone, role, password, company_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [email, firstName, lastName, phone, role, hashedPassword, companyId]
    );
    conn.end();
    res.json({ message: "User added" });
  } catch (err) {
    res.status(500).json({ error: "Failed to add user" });
  }
});

app.post("/edit-user", requireAdmin, async (req, res) => {
  const { id, email, firstName, lastName, phone, role, password } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);
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
    conn.end();
    res.json({ message: "User updated" });
  } catch (err) {
    res.status(500).json({ error: "Failed to update user" });
  }
});

app.post("/delete-user", requireAdmin, async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: "Missing user ID" });

  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute("DELETE FROM users WHERE id = ?", [id]);
    conn.end();
    res.json({ message: "User deleted" });
  } catch (err) {
    console.error("Delete user error:", err);
    res.status(500).json({ error: "Failed to delete user" });
  }
});

app.get("/company-users/:companyId", requireAdmin, async (req, res) => {
  const { companyId } = req.params;
  try {
    const conn = await mysql.createConnection(dbConfig);
    // Select only necessary fields for display
    const [users] = await conn.execute("SELECT id, email, first_name, last_name, phone, role FROM users WHERE company_id = ?", [companyId]);
    conn.end();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: "Failed to retrieve users" });
  }
});

// --- Ship To Addresses Routes ---

// Get all ship-to addresses for a company
app.get("/api/shipto/:companyId", requireAdmin, async (req, res) => {
    const { companyId } = req.params;
    try {
        const conn = await mysql.createConnection(dbConfig);
        const [addresses] = await conn.execute("SELECT * FROM shipto_addresses WHERE company_id = ?", [companyId]);
        conn.end();
        res.json(addresses);
    } catch (err) {
        console.error("Error fetching ship-to addresses:", err);
        res.status(500).json({ error: "Failed to retrieve ship-to addresses" });
    }
});

// Add a new ship-to address
app.post("/api/shipto", requireAdmin, async (req, res) => {
    const { companyId, name, address1, address2, city, state, zip, country } = req.body;
    
    if (!companyId || !address1 || !city || !state || !zip || !country) {
        return res.status(400).json({ error: "Missing required fields." });
    }

    try {
        const conn = await mysql.createConnection(dbConfig);
        const [result] = await conn.execute(
            `INSERT INTO shipto_addresses (company_id, name, address1, address2, city, state, zip, country) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [companyId, name, address1, address2, city, state, zip, country]
        );
        conn.end();
        res.status(201).json({ id: result.insertId, message: "Address added successfully" });
    } catch (err) {
        console.error("Error adding ship-to address:", err);
        res.status(500).json({ error: "Failed to add ship-to address" });
    }
});

// Update an existing ship-to address
app.put("/api/shipto/:addressId", requireAdmin, async (req, res) => {
    const { addressId } = req.params;
    const { name, address1, address2, city, state, zip, country } = req.body;

    try {
        const conn = await mysql.createConnection(dbConfig);
        await conn.execute(
            `UPDATE shipto_addresses SET name = ?, address1 = ?, address2 = ?, city = ?, state = ?, zip = ?, country = ? WHERE id = ?`,
            [name, address1, address2, city, state, zip, country, addressId]
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

// --- General Routes and Server Start ---

app.get("/", (req, res) => {
  res.redirect("/admin-dashboard.html");
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
