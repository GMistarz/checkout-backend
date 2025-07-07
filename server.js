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

app.post("/edit-company", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

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

app.post('/add-company', async (req, res) => {
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

app.post("/edit-user", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

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

app.post("/delete-user", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }

  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Missing email" });

  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.execute("DELETE FROM users WHERE email = ?", [email]);
    conn.end();
    res.json({ message: "User deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete user" });
  }
});


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

app.get("/", (req, res) => {
  res.redirect("/admin-dashboard.html");
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
