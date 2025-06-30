// server.js - Using MySQL instead of JSON for user and order storage

const express = require("express");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const dbConfig = {
  host: "gmistarz_cse.hgns1.hostgator.com",
  user: "gmistarz_user",
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
  const { email, password, role = "user", terms = "" } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });

  const conn = await mysql.createConnection(dbConfig);
  const [existing] = await conn.execute("SELECT email FROM users WHERE email = ?", [email]);
  if (existing.length > 0) return res.status(409).json({ error: "Email already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);
  await conn.execute("INSERT INTO users (email, password, role, terms) VALUES (?, ?, ?, ?)", [email, hashedPassword, role, terms]);
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

  req.session.user = { email: user.email, role: user.role };
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
  const [rows] = await conn.execute("SELECT email, role, terms FROM users WHERE email = ?", [user.email]);
  conn.end();

  res.json(rows[0]);
});

app.get("/users", async (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const conn = await mysql.createConnection(dbConfig);
  const [users] = await conn.execute("SELECT email, role, terms FROM users");
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

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

