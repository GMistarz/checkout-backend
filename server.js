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

// --- NEW: Helper Middleware for Authenticated User Check ---
const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ error: "Unauthorized: Login required" });
    }
    next();
};

// --- NEW: Helper Middleware for Company Access Authorization ---
// This middleware checks if the user is authenticated and if their company_id
// matches the company_id being accessed in the request.
const authorizeCompanyAccess = async (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ error: "Unauthorized: Login required" });
    }

    const userCompanyId = req.session.user.companyId;

    // Determine the companyId from the request based on route
    let requestedCompanyId = null;
    if (req.params.companyId) { // For routes like /api/shipto/:companyId
        requestedCompanyId = parseInt(req.params.companyId, 10);
    } else if (req.body.companyId) { // For POST routes like /api/shipto (add new)
        requestedCompanyId = parseInt(req.body.companyId, 10);
    } else if (req.params.addressId) { // For PUT/DELETE/SET_DEFAULT on /api/shipto/:addressId
        let conn;
        try {
            conn = await mysql.createConnection(dbConnectionConfig);
            const [rows] = await conn.execute("SELECT company_id FROM shipto_addresses WHERE id = ?", [req.params.addressId]);
            if (rows.length > 0) {
                requestedCompanyId = rows[0].company_id;
            }
        } catch (err) {
            console.error("Error fetching company_id for address:", err);
            return res.status(500).json({ error: "Server error while authorizing company access" });
        } finally {
            if (conn) conn.end();
        }
    }

    // For the submit-order route, we assume the user's companyId is implicitly linked to the order.
    // We don't need a requestedCompanyId from params/body for this specific route's authorization,
    // but we ensure the user is authenticated and has a companyId.
    if (req.path === '/submit-order' && !userCompanyId) {
        return res.status(403).json({ error: "Forbidden: User not associated with a company." });
    }


    if (requestedCompanyId === null || userCompanyId !== requestedCompanyId) {
        // Only apply this check if a specific companyId was requested in the URL/body
        // and it doesn't match the user's companyId, or if no companyId was found
        // but the route requires it (e.g., shipto management).
        // For /submit-order, this block will be skipped unless a companyId param was explicitly passed.
        if (req.path.startsWith('/api/shipto/') || req.path === '/api/shipto') {
            return res.status(403).json({ error: "Forbidden: You can only access data for your own company." });
        }
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
    req.session.user = { 
        id: user.id, 
        email: user.email, 
        role: user.role, 
        companyId: user.company_id,
        firstName: user.first_name, // Include first name
        lastName: user.last_name     // Include last name
    };
    
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

app.get("/user-profile", requireAuth, async (req, res) => { // Use requireAuth
  const { user } = req.session;
  // The session 'user' object already contains most of the profile data needed.
  // We can directly send it, or fetch from DB if more fields are needed.
  // For simplicity, sending directly from session, ensuring it includes first_name and last_name.
  if (user) {
      res.json({
          email: user.email,
          role: user.role,
          company_id: user.companyId,
          first_name: user.firstName,
          last_name: user.lastName
      });
  } else {
      // This case should ideally be caught by requireAuth, but as a fallback:
      res.status(401).json({ error: "Not logged in" });
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

// --- NEW: Registration Endpoints ---

app.post("/register-company", async (req, res) => {
  const { name, address1, city, state, zip, country, terms, logo } = req.body;
  if (!name || !address1 || !city || !state || !zip) {
    return res.status(400).json({ error: "Company name, address, city, state, and zip are required." });
  }
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [result] = await conn.execute(
      `INSERT INTO companies (name, logo, address1, city, state, zip, country, terms)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [name, logo || '', address1, city, state, zip, country || 'USA', terms || 'Net 30']
    );
    res.status(201).json({ message: "Company registered successfully", companyId: result.insertId });
  } catch (err) {
    console.error("Failed to register company:", err);
    // Check for duplicate entry error (e.g., if company name is unique)
    if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: "Company with this name already exists." });
    }
    res.status(500).json({ error: "Failed to register company due to server error" });
  } finally {
    if (conn) conn.end();
  }
});

app.post("/register-user", async (req, res) => {
  const { email, firstName, lastName, phone, password, companyId } = req.body;
  // Role is hardcoded to 'user' for new registrations from checkout
  const role = "user"; 

  if (!email || !firstName || !lastName || !password || !companyId) {
    return res.status(400).json({ error: "Email, first name, last name, password, and company ID are required." });
  }
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    // Check if user with this email already exists
    const [existingUsers] = await conn.execute("SELECT id FROM users WHERE email = ?", [email]);
    if (existingUsers.length > 0) {
      return res.status(409).json({ error: "User with this email already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await conn.execute(
      `INSERT INTO users (email, first_name, last_name, phone, role, password, company_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [email, firstName, lastName, phone || '', role, hashedPassword, companyId]
    );
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Failed to register user:", err);
    res.status(500).json({ error: "Failed to register user due to server error" });
  } finally {
    if (conn) conn.end();
  }
});


// --- Company Routes (Admin Only) ---
// These remain requireAdmin as they are for overall company management
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

// Updated: Removed address2 from edit-company route
app.post("/edit-company", requireAdmin, async (req, res) => {
  const { id, name, address1, city, state, zip, country, terms, logo } = req.body;
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    await conn.execute(
      `UPDATE companies SET name = ?, address1 = ?, city = ?, state = ?, zip = ?, country = ?, terms = ?, logo = ? WHERE id = ?`,
      [name, address1, city, state, zip, country, terms, logo, id]
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
    name, logo, address1, city, state, zip, country, terms
  } = req.body;
  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
    await conn.execute(`
      INSERT INTO companies (name, logo, address1, city, state, zip, country, terms)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [name, logo, address1, city, state, zip, country, terms]);
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

app.get("/user/company-details", requireAuth, async (req, res) => {
  const userCompanyId = req.session.user.companyId;
  if (!userCompanyId) {
    return res.status(404).json({ error: "No company associated with this user." });
  }

  let conn;
  try {
    conn = await mysql.createConnection(dbConnectionConfig);
    const [companies] = await conn.execute(
      "SELECT name, address1, city, state, zip, country, terms FROM companies WHERE id = ?",
      [userCompanyId]
    );

    if (companies.length === 0) {
      return res.status(404).json({ error: "Company not found for this user." });
    }
    res.json(companies[0]);
  } catch (err) {
    console.error("Error fetching user's company details:", err);
    res.status(500).json({ error: "Failed to retrieve user's company details." });
  } finally {
    if (conn) conn.end();
  }
});


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
app.get("/api/shipto/:companyId", authorizeCompanyAccess, async (req, res) => { // Use authorizeCompanyAccess
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

app.post("/api/shipto", authorizeCompanyAccess, async (req, res) => { // Use authorizeCompanyAccess
    const { companyId, name, address1, city, state, zip, country, is_default } = req.body;
    
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
            `INSERT INTO shipto_addresses (company_id, name, address1, city, state, zip, country, is_default) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [companyId, name, address1, city, state, zip, country, is_default ? 1 : 0]
        );
        res.status(201).json({ id: result.insertId, message: "Address added successfully" });
    } catch (err) {
        console.error("Error adding ship-to address:", err);
        res.status(500).json({ error: "Failed to add ship-to address" });
    } finally {
        if (conn) conn.end();
    }
});

app.put("/api/shipto/:addressId", authorizeCompanyAccess, async (req, res) => { // Use authorizeCompanyAccess
    const { addressId } = req.params;
    const { name, address1, city, state, zip, country } = req.body; // is_default is not in this body
    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
        await conn.execute(
            `UPDATE shipto_addresses SET name = ?, address1 = ?, city = ?, state = ?, zip = ?, country = ? WHERE id = ?`,
            [name, address1, city, state, zip, country, addressId]
        );
        res.json({ message: "Address updated successfully" });
    } catch (err) {
        console.error("Error updating ship-to address:", err);
        res.status(500).json({ error: "Failed to update ship-to address" });
    } finally {
        if (conn) conn.end();
    }
});

app.put("/api/shipto/:addressId/set-default", authorizeCompanyAccess, async (req, res) => { // Use authorizeCompanyAccess
    const { addressId } = req.params;

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig); // Use dbConnectionConfig here
        
        // 1. Determine the companyId associated with the addressId
        const [addressRows] = await conn.execute("SELECT company_id FROM shipto_addresses WHERE id = ?", [addressId]);
        
        if (addressRows.length === 0) {
            return res.status(404).json({ error: "Address not found." });
        }
        
        const targetCompanyId = addressRows[0].company_id;

        // Ensure the logged-in user's company matches the target company
        if (req.session.user.companyId !== targetCompanyId) {
            return res.status(403).json({ error: "Forbidden: You can only set default addresses for your own company." });
        }

        await conn.beginTransaction(); // Start a transaction

        // 2. Unset the 'is_default' flag for all other addresses of this target company
        await conn.execute(
            `UPDATE shipto_addresses SET is_default = 0 WHERE company_id = ? AND id != ?`,
            [targetCompanyId, addressId]
        );

        // 3. Set the 'is_default' flag to 1 for the selected address
        // We only need to check the addressId here since we verified the companyId in step 2.
        await conn.execute(
            `UPDATE shipto_addresses SET is_default = 1 WHERE id = ?`,
            [addressId]
        );

        await conn.commit(); // Commit the transaction
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

app.delete("/api/shipto/:addressId", authorizeCompanyAccess, async (req, res) => { // Use authorizeCompanyAccess
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

app.post("/submit-order", requireAuth, async (req, res) => {
    const { poNumber, orderedBy, billingAddress, shippingAddress, shippingAddressId, attn, tag, shippingMethod, carrierAccount, items } = req.body;
    const userId = req.session.user.id;
    const companyId = req.session.user.companyId;
    const userEmail = req.session.user.email; // Get user's email from session

    console.log("Received order submission request with body:", JSON.stringify(req.body, null, 2));

    // Validate required fields based on the *actual* columns in the 'orders' table schema provided
    if (!userEmail || !poNumber || !billingAddress || !shippingAddress || !shippingMethod || !items || items.length === 0) {
        console.error("Validation Error: Missing required order fields or empty cart.", { userEmail, poNumber, billingAddress, shippingAddress, shippingMethod, items });
        return res.status(400).json({ error: "Missing required order fields or empty cart." });
    }

    let conn;
    try {
        conn = await mysql.createConnection(dbConnectionConfig);
        await conn.beginTransaction(); // Start a transaction

        // Insert into orders table, matching the provided schema exactly
        const [orderResult] = await conn.execute(
            `INSERT INTO orders (email, poNumber, billingAddress, shippingAddress, shippingMethod, carrierAccount, items, date)
             VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
            [userEmail, poNumber, billingAddress, shippingAddress, shippingMethod, carrierAccount, JSON.stringify(items)]
        );
        const orderId = orderResult.insertId;

        // Removed the INSERT into order_items table as per the provided 'orders' table schema
        // which includes an 'items' JSON column.

        await conn.commit(); // Commit the transaction
        res.status(200).json({ message: "Order submitted successfully!", orderId: orderId });

    } catch (err) {
        if (conn) {
            await conn.rollback(); // Rollback on error
        }
        // Log the full error object for detailed debugging on the backend server
        console.error("Error submitting order (Backend):", err); 
        res.status(500).json({ error: "Failed to submit order due to server error." });
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
