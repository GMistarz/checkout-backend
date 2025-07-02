const express = require("express");
const app = express();
const cors = require("cors");
const session = require("express-session");
const fs = require("fs");
const path = require("path");

app.use(cors({
  origin: ["https://www.chicagostainless.com", "http://localhost:3000"],
  credentials: true
}));

app.use(express.json());
app.use(session({
  secret: "secret123",
  resave: false,
  saveUninitialized: true
}));

const DATA_PATH = path.join(__dirname, "data");
const companiesFile = path.join(DATA_PATH, "companies.json");

// Utility: Load JSON file
function loadJSON(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const content = fs.readFileSync(filePath);
  return JSON.parse(content);
}

// Utility: Save JSON file
function saveJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

// Route: Add a company
app.post("/add-company", (req, res) => {
  const { name, address1, address2, city, state, zip, country, terms } = req.body;

  if (!name || !address1 || !city || !state || !zip || !country || !terms) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const companies = loadJSON(companiesFile);

  const newCompany = {
    id: Date.now().toString(),
    name,
    address1,
    address2,
    city,
    state,
    zip,
    country,
    terms,
    users: [],
    shipToAddresses: []
  };

  companies.push(newCompany);
  saveJSON(companiesFile, companies);
  res.json({ message: "Company added successfully" });
});

// Route: Get all companies
app.get("/companies", (req, res) => {
  const companies = loadJSON(companiesFile);
  res.json(companies);
});

// Route: Edit company
app.post("/edit-company", (req, res) => {
  const { id, name, address1, address2, city, state, zip, country, terms } = req.body;
  const companies = loadJSON(companiesFile);

  const company = companies.find(c => c.id === id);
  if (!company) return res.status(404).json({ error: "Company not found" });

  Object.assign(company, { name, address1, address2, city, state, zip, country, terms });
  saveJSON(companiesFile, companies);
  res.json({ message: "Company updated successfully" });
});

// Route: Delete company
app.post("/delete-company", (req, res) => {
  const { id } = req.body;
  let companies = loadJSON(companiesFile);
  companies = companies.filter(c => c.id !== id);
  saveJSON(companiesFile, companies);
  res.json({ message: "Company deleted successfully" });
});

// Route: Add user to company
app.post("/add-user", (req, res) => {
  const { companyId, firstName, lastName, email, phone, password } = req.body;

  if (!companyId || !firstName || !lastName || !email || !phone || !password) {
    return res.status(400).json({ error: "Missing user fields" });
  }

  const companies = loadJSON(companiesFile);
  const company = companies.find(c => c.id === companyId);
  if (!company) return res.status(404).json({ error: "Company not found" });

  const newUser = { id: Date.now().toString(), firstName, lastName, email, phone, password };
  company.users.push(newUser);
  saveJSON(companiesFile, companies);
  res.json({ message: "User added successfully" });
});

// Route: Edit user in company
app.post("/edit-user", (req, res) => {
  const { companyId, userId, firstName, lastName, email, phone, password } = req.body;
  const companies = loadJSON(companiesFile);
  const company = companies.find(c => c.id === companyId);
  if (!company) return res.status(404).json({ error: "Company not found" });

  const user = company.users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: "User not found" });

  Object.assign(user, { firstName, lastName, email, phone, password });
  saveJSON(companiesFile, companies);
  res.json({ message: "User updated successfully" });
});

// Route: Delete user from company
app.post("/delete-user", (req, res) => {
  const { companyId, userId } = req.body;
  const companies = loadJSON(companiesFile);
  const company = companies.find(c => c.id === companyId);
  if (!company) return res.status(404).json({ error: "Company not found" });

  company.users = company.users.filter(u => u.id !== userId);
  saveJSON(companiesFile, companies);
  res.json({ message: "User deleted successfully" });
});

// Route: Add ship-to address
app.post("/add-shipto", (req, res) => {
  const { companyId, label, address1, address2, city, state, zip, country, isDefault } = req.body;

  if (!companyId || !label || !address1 || !city || !state || !zip || !country) {
    return res.status(400).json({ error: "Missing ship-to fields" });
  }

  const companies = loadJSON(companiesFile);
  const company = companies.find(c => c.id === companyId);
  if (!company) return res.status(404).json({ error: "Company not found" });

  if (isDefault) {
    company.shipToAddresses.forEach(addr => addr.isDefault = false);
  }

  const newAddress = {
    id: Date.now().toString(),
    label,
    address1,
    address2,
    city,
    state,
    zip,
    country,
    isDefault: !!isDefault
  };

  company.shipToAddresses.push(newAddress);
  saveJSON(companiesFile, companies);
  res.json({ message: "Ship-to address added successfully" });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
