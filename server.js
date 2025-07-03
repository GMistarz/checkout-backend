const express = require("express");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise");
const multer = require("multer");
const fs = require("fs");
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
app.use(express.static("uploads"));
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

const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
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

app.post("/edit-company", upload.single("logo"), async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const { id, name, address1, address2, city, state, zip, country, terms } = req.body;
  const logo = req.file ? `/` + req.file.filename : null;

  try {
    const conn = await mysql.createConnection(dbConfig);
    if (logo) {
      await conn.execute(
        `UPDATE companies SET name = ?, logo = ?, address1 = ?, address2 = ?, city = ?, state = ?, zip = ?, country = ?, terms = ? WHERE id = ?`,
        [name, logo, address1, address2, city, state, zip, country, terms, id]
      );
    } else {
      await conn.execute(
        `UPDATE companies SET name = ?, address1 = ?, address2 = ?, city = ?, state = ?, zip = ?, country = ?, terms = ? WHERE id = ?`,
        [name, address1, address2, city, state, zip, country, terms, id]
      );
    }
    conn.end();
    res.json({ message: "Company updated" });
  } catch (err) {
    res.status(500).json({ error: "Failed to update company" });
  }
});

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
