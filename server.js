// server.js
const express = require("express");
const cors = require("cors");
const session = require("express-session");
const fs = require("fs");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Allowed origins for CORS
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
app.use(session({
  secret: "secret-key",
  resave: false,
  saveUninitialized: true
}));

const USERS_FILE = path.join(__dirname, "users.json");
const ORDERS_FILE = path.join(__dirname, "orders.json");

function readJSON(file) {
  if (!fs.existsSync(file)) return [];
  return JSON.parse(fs.readFileSync(file));
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

app.post("/register", async (req, res) => {
  const { email, password, role = "user", terms = "" } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });

  const users = readJSON(USERS_FILE);
  if (users.find(u => u.email === email)) {
    return res.status(409).json({ error: "Email already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ email, password: hashedPassword, role, terms });
  writeJSON(USERS_FILE, users);
  res.json({ message: "User registered successfully" });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.email === email);

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

app.get("/user-profile", (req, res) => {
  const { user } = req.session;
  if (!user) return res.status(401).json({ error: "Not logged in" });

  const users = readJSON(USERS_FILE);
  const fullUser = users.find(u => u.email === user.email);
  res.json({ email: fullUser.email, role: fullUser.role, terms: fullUser.terms });
});

app.get("/users", (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const users = readJSON(USERS_FILE);
  res.json(users);
});

app.post("/update-terms", (req, res) => {
  const { user } = req.session;
  const { email, terms } = req.body;

  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const users = readJSON(USERS_FILE);
  const target = users.find(u => u.email === email);
  if (!target) return res.status(404).json({ error: "User not found" });

  target.terms = terms;
  writeJSON(USERS_FILE, users);
  res.json({ message: "Terms updated" });
});

app.post("/submit-order", (req, res) => {
  const { user } = req.session;
  if (!user) return res.status(401).json({ error: "Not logged in" });

  const order = req.body;
  order.email = user.email;
  order.date = new Date().toISOString();

  const orders = readJSON(ORDERS_FILE);
  orders.push(order);
  writeJSON(ORDERS_FILE, orders);
  res.json({ message: "Order received" });
});

app.get("/orders", (req, res) => {
  const { user } = req.session;
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const orders = readJSON(ORDERS_FILE);
  res.json(orders);
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
