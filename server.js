const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs'); // bcryptjs is Windows-friendly
const session = require('express-session');

const app = express();
const PORT = 3000;
const USERS_FILE = path.join(__dirname, 'users.json');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));

function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  const data = fs.readFileSync(USERS_FILE);
  return JSON.parse(data);
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function ensureAdmin(req, res, next) {
  if (req.session?.user?.role === 'admin') {
    return next();
  }
  return res.status(403).json({ error: 'Forbidden' });
}

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });

  req.session.user = { email: user.email, role: user.role };
  res.json({ email: user.email, role: user.role });
});

app.post('/admin-hash-password', ensureAdmin, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });

  const hashed = await bcrypt.hash(password, 10);
  res.json({ hashedPassword: hashed });
});

app.get('/admin-users', ensureAdmin, (req, res) => {
  const users = loadUsers();
  res.json(users);
});

app.post('/admin-users', ensureAdmin, (req, res) => {
  const { email, paymentTerms } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.paymentTerms = paymentTerms;
  saveUsers(users);
  res.json({ success: true });
});

app.post('/admin-create-user', ensureAdmin, async (req, res) => {
  const { email, name, company, password, paymentTerms } = req.body;
  const users = loadUsers();

  if (users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'Email already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({
    email,
    name,
    company,
    password: hashedPassword,
    paymentTerms,
    role: 'user'
  });

  saveUsers(users);
  res.json({ success: true });
});

app.post('/admin-reset-password', ensureAdmin, async (req, res) => {
  const { email, newPassword } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.password = await bcrypt.hash(newPassword, 10);
  saveUsers(users);
  res.json({ success: true });
});

const ORDERS_FILE = path.join(__dirname, 'orders.json'); // already declared earlier

function loadOrders() {
  if (!fs.existsSync(ORDERS_FILE)) return [];
  const data = fs.readFileSync(ORDERS_FILE);
  return JSON.parse(data);
}

app.get('/admin-orders', ensureAdmin, (req, res) => {
  const orders = loadOrders();
  res.json(orders);
});

function saveOrders(orders) {
  fs.writeFileSync(ORDERS_FILE, JSON.stringify(orders, null, 2));
}

app.post('/place-order', (req, res) => {
  const user = req.session.user;
  if (!user) return res.status(401).json({ error: 'Not logged in' });

  const { billingAddress, shippingAddress, poNumber, shippingMethod, carrierAccount, items } = req.body;
  if (!billingAddress || !shippingAddress || !poNumber || !shippingMethod || !items?.length) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const orders = loadOrders();
  const newOrder = {
    id: orders.length + 1,
    email: user.email,
    billingAddress,
    shippingAddress,
    poNumber,
    shippingMethod,
    carrierAccount,
    items,
    timestamp: new Date().toISOString()
  };

  orders.push(newOrder);
  saveOrders(orders);

  res.json({ success: true, orderId: newOrder.id });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
