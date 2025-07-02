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
  "http://localhost:3000"
];

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

app.post("/register", async (req, res) => {
  const { email, password, role = "user", terms = "", companyId = null } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });

  const conn = await mysql.createConnection(dbConfig);
  const [existing] = await conn.execute("SELECT email FROM users WHERE email = ?", [email]);
  if (existing.length > 0) return res.status(409).json({ error: "Email already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);
  await conn.execute(
    "INSERT INTO users (email, password, role, terms, company_id) VALUES (?, ?, ?, ?, ?)",
    [email, hashedPassword, role, terms, companyId]
  );
  conn.end();
  res.json({ message: "User registered successfully" });
});

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

app.post("/logout", (req, res) => {
  req.session.destroy();
  res.json({ message: "Logged out" });
});

app.get("/user-profile", async (req, res) => {
  const { user } = req.session;
  if (!user) return res.status(401).json({ error: "Not logged in" });

  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute(
    "SELECT email, role, terms, company_id FROM users WHERE email = ?",
    [user.email]
  );
  conn.end();

  res.json(rows[0]);
});

app.get("/users", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const conn = await mysql.createConnection(dbConfig);
  const [users] = await conn.execute("SELECT * FROM users");
  conn.end();
  res.json(users);
});

app.post("/update-terms", async (req, res) => {
  const { user } = req.session;
  const { email, terms } = req.body;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const conn = await mysql.createConnection(dbConfig);
  await conn.execute("UPDATE users SET terms = ? WHERE email = ?", [terms, email]);
  conn.end();
  res.json({ message: "Terms updated" });
});

app.post("/submit-order", async (req, res) => {
  const { user } = req.session;
  if (!user) return res.status(401).json({ error: "Not logged in" });

  const order = req.body;
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute(
    "INSERT INTO orders (email, poNumber, shippingMethod, carrierAccount, billingAddress, shippingAddress, items, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [
      user.email,
      order.poNumber || "",
      order.shippingMethod || "",
      order.carrierAccount || "",
      order.billingAddress || "",
      order.shippingAddress || "",
      JSON.stringify(order.items || []),
      new Date().toISOString()
    ]
  );
  conn.end();
  res.json({ message: "Order received" });
});

app.get("/orders", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const conn = await mysql.createConnection(dbConfig);
  const [orders] = await conn.execute("SELECT * FROM orders");
  conn.end();
  orders.forEach(o => o.items = JSON.parse(o.items || "[]"));
  res.json(orders);
});

app.post("/add-company", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const { name, address1, address2, city, state, zip, country, terms } = req.body;
  if (!name || !address1 || !city || !state || !zip || !country || !terms) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute(
      `INSERT INTO companies (name, address1, address2, city, state, zip, country, terms)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [name, address1, address2 || "", city, state, zip, country, terms]
    );
    conn.end();
    res.json({ message: "Company added successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to add company" });
  }
});

app.get("/companies", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }

  try {
    const conn = await mysql.createConnection(dbConfig);
    const [companies] = await conn.execute("SELECT * FROM companies");
    conn.end();
    res.json(companies);
  } catch (err) {
    res.status(500).json({ error: "Failed to retrieve companies" });
  }
});

app.post("/add-shipto", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const { companyId, address1, address2, city, state, zip, country, isDefault } = req.body;
  if (!companyId || !address1 || !city || !state || !zip || !country) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const conn = await mysql.createConnection(dbConfig);
    if (isDefault) {
      await conn.execute("UPDATE shipto SET is_default = 0 WHERE company_id = ?", [companyId]);
    }
    await conn.execute(
      `INSERT INTO shipto (company_id, address1, address2, city, state, zip, country, is_default)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [companyId, address1, address2 || "", city, state, zip, country, isDefault ? 1 : 0]
    );
    conn.end();
    res.json({ message: "Ship-to address added" });
  } catch (err) {
    res.status(500).json({ error: "Failed to add ship-to address" });
  }
});

app.get("/shipto/:companyId", async (req, res) => {
  const { user } = req.session;
  if (!user) return res.status(401).json({ error: "Not logged in" });

  const { companyId } = req.params;
  try {
    const conn = await mysql.createConnection(dbConfig);
    const [addresses] = await conn.execute(
      "SELECT * FROM shipto WHERE company_id = ?",
      [companyId]
    );
    conn.end();
    res.json(addresses);
  } catch (err) {
    res.status(500).json({ error: "Failed to retrieve ship-to addresses" });
  }
});

// Edit user
app.post("/edit-user", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const { id, email, firstName, lastName, phone, terms, role } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute(
      `UPDATE users SET email = ?, first_name = ?, last_name = ?, phone = ?, terms = ?, role = ? WHERE id = ?`,
      [email, firstName, lastName, phone, terms, role, id]
    );
    conn.end();
    res.json({ message: "User updated" });
  } catch (err) {
    res.status(500).json({ error: "Failed to update user" });
  }
});

// Delete user
app.post("/delete-user", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const { id } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute("DELETE FROM users WHERE id = ?", [id]);
    conn.end();
    res.json({ message: "User deleted" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete user" });
  }
});

// Edit company
app.post("/edit-company", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const { id, name, address1, address2, city, state, zip, country, terms } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute(
      `UPDATE companies SET name = ?, address1 = ?, address2 = ?, city = ?, state = ?, zip = ?, country = ?, terms = ? WHERE id = ?`,
      [name, address1, address2, city, state, zip, country, terms, id]
    );
    conn.end();
    res.json({ message: "Company updated" });
  } catch (err) {
    res.status(500).json({ error: "Failed to update company" });
  }
});

// Delete company
app.post("/delete-company", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const { id } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute("DELETE FROM companies WHERE id = ?", [id]);
    conn.end();
    res.json({ message: "Company deleted" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete company" });
  }
});

// Set default ship-to address
app.post("/set-default-shipto", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const { companyId, shiptoId } = req.body;
  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute("UPDATE shipto SET is_default = 0 WHERE company_id = ?", [companyId]);
    await conn.execute("UPDATE shipto SET is_default = 1 WHERE id = ?", [shiptoId]);
    conn.end();
    res.json({ message: "Default ship-to address set" });
  } catch (err) {
    res.status(500).json({ error: "Failed to set default address" });
  }
});

// Get users by company
app.get("/company-users/:companyId", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const { companyId } = req.params;
  try {
    const conn = await mysql.createConnection(dbConfig);
    const [users] = await conn.execute("SELECT * FROM users WHERE company_id = ?", [companyId]);
    conn.end();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: "Failed to retrieve users" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
