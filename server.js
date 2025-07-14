<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Checkout</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    /* Style for the dropdown options */
    #shipToAddressDropdown option {
      background-color: #bfbfbf; /* Slightly darker grey for dropdown options */
      color: #333; /* Ensure text is readable */
    }
  </style>
</head>
<body style="font-family: Arial, sans-serif; margin: 20px; background: #f9f9f9;">

<div style="max-width: 1000px; margin: 0 auto; display: flex; align-items: flex-end; justify-content: flex-start; margin-bottom: 15px; position: relative; min-height: 60px;">
  <img src="https://www.chicagostainless.com/graphics/cse_logo.png" alt="Company Logo" style="height: 60px; margin-right: 20px; z-index: 1;">
  <h1 style="position: absolute; left: 50%; transform: translateX(-50%); margin: 0; z-index: 0; white-space: nowrap; bottom: 0;">Checkout</h1>
</div>


<div id="authForm" style="max-width: 400px; margin: 0 auto 30px; padding: 20px; background: #ffffff; border: 1px solid #ccc; border-radius: 6px; display: none;">
  <h3 id="authTitle" style="text-align: center;">Login or Register</h3>
  <div style="margin-bottom: 10px;">
    <label for="authUsername">Email</label>
    <input type="email" id="authUsername" style="width: 100%; padding: 10px; font-family: Arial, sans-serif; font-size: 15px;">
  </div>
  <div style="margin-bottom: 10px;">
    <label for="authPassword">Password</label>
    <input type="password" id="authPassword" style="width: 100%; padding: 10px; font-family: Arial, sans-serif; font-size: 15px;">
  </div>
  <div style="display: flex; gap: 10px;">
    <!-- Removed onclick attributes here -->
    <button id="loginBtn" type="button" style="flex: 1; padding: 10px; background: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 18px; font-weight: bold;">Login</button>
    <button id="requestRegistrationBtn" type="button" style="flex: 1; padding: 10px; background: #6c757d; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 18px; font-weight: bold;">Request Registration</button>
  </div>
</div>

<form id="checkoutForm" style="max-width: 1000px; margin: 0 auto 30px; background: white; padding: 25px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); display: none;" onsubmit="submitOrder(event)">
  <div style="display: flex; gap: 40px; flex-wrap: wrap;">
    <div style="flex: 1; min-width: 300px;">
      <h2>Billed To:</h2>
      <textarea id="billedToInfo" placeholder="Name and Address" rows="4" style="width: 100%; margin-bottom: 15px; font-family: Arial, sans-serif; font-size: 15px;" required readonly></textarea>
      <input id="orderedBy" placeholder="Ordered By (required)" style="width: 100%; margin-bottom: 15px; font-family: Arial, sans-serif; font-size: 15px;" required>
      <input id="poNumber" placeholder="PO# (required)" style="width: 100%; margin-bottom: 15px; font-family: Arial, sans-serif; font-size: 15px;" required>
      <input id="terms" placeholder="Terms" style="width: 100%; margin-bottom: 15px; font-family: Arial, sans-serif; font-size: 15px;" readonly>
    </div>
    <div style="flex: 1; min-width: 300px;">
      <h2>Ship To:</h2>
      <select id="shipToAddressDropdown" style="width: 100%; padding: 10px; margin-bottom: 15px; font-family: Arial, sans-serif; font-size: 15px; background-color: #E0DFDF;" onchange="displaySelectedShipToAddress()" required>
        <option value="">-- Select Shipping Address --</option>
      </select>
      <div style="display: flex; gap: 10px; margin-bottom: 15px;">
        <button type="button" id="addShipToBtn" style="padding: 8px 12px; background: #28a745; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: bold;">Add New</button>
        <button type="button" id="editShipToBtn" style="padding: 8px 12px; background: #ffc107; color: #212529; border: none; border-radius: 6px; cursor: pointer; display: none; font-size: 14px; font-weight: bold;">Edit</button>
        <button type="button" id="deleteShipToBtn" style="padding: 8px 12px; background: #dc3545; color: white; border: none; border-radius: 6px; cursor: pointer; display: none; font-size: 14px; font-weight: bold;">Delete</button>
      </div>
      <textarea id="shipToInfo" placeholder="Name and Address" rows="4" style="width: 100%; margin-bottom: 15px; font-family: Arial, sans-serif; font-size: 15px;" required readonly></textarea>
      <input id="attn" placeholder="ATTN:" style="width: 100%; margin-bottom: 15px; font-family: Arial, sans-serif; font-size: 15px;">
      <input id="tag" placeholder="Tag#" style="width: 100%; margin-bottom: 15px; font-family: Arial, sans-serif; font-size: 15px;">
      <select id="shippingMethod" onchange="toggleCarrierAccount()" style="width: 100%; margin-bottom: 15px; font-family: Arial, sans-serif; font-size: 15px;" required>
        <option value="">-- Select Shipping Method --</option>
        <option value="UPS Ground PPA">UPS Ground PPA</option>
        <option value="UPS Second Day Air PPA">UPS Second Day Air PPA</option>
        <option value="UPS Next Day Air PPA">UPS Next Day Air PPA</option>
        <option value="UPS Next Day Air Saver PPA">UPS Next Day Air Saver PPA</option>
        <option value="UPS Next Day Air AM PPA">UPS Next Day Air AM PPA</option>
        <option value="UPS Saturday AM Delivery PPA">UPS Saturday AM Delivery PPA</option>
        <option value="UPS Ground Collect">UPS Ground Collect</option>
        <option value="UPS Second Day Air Collect">UPS Second Day Air Collect</option>
        <option value="UPS Next Day Air Collect">UPS Next Day Air Collect</option>
        <option value="UPS Next Day Air Saver Collect">UPS Next Day Air Saver Collect</option>
        <option value="UPS Next Day Air AM Collect">UPS Next Day Air AM Collect</option>
        <option value="UPS Saturday AM Delivery Collect">UPS Saturday AM Delivery Collect</option>
        <option value="UPS Ground 3rd Party Billing">UPS Ground 3rd Party Billing</option>
        <option value="UPS Second Day Air 3rd Party Billing">UPS Second Day Air 3rd Party Billing</option>
        <option value="UPS Next Day Air 3rd Party Billing">UPS Next Day Air 3rd Party Billing</option>
        <option value="UPS Next Day Air Saver 3rd Party Billing">UPS Next Day Air Saver 3rd Party Billing</option>
        <option value="UPS Next Day Air AM 3rd Party Billing">UPS Next Day Air AM 3rd Party Billing</option>
        <option value="UPS Saturday AM Delivery 3rd Party Billing">UPS Saturday AM Delivery 3rd Party Billing</option>
        <option value="FedEx Ground Collect">FedEx Ground Collect - 1 to 5 Business Days</option>
        <option value="FedEx Express Saver Collect">FedEx Express Saver Collect - 3 Business Days</option>
        <option value="FedEx 2Day A.M. Collect">FedEx 2Day A.M. Collect - 2 Business Days By 10:30 AM</option>
        <option value="FedEx 2Day A.M. Collect">FedEx 2Day Collect - 2 Business Days By End of Day</option>
        <option value="FedEx Standard Overnight Collect">FedEx Standard Overnight Collect - Delivery Overnight By 3:00pm</option>
        <option value="FedEx Priority Overnight Collect">FedEx Priority Overnight Collect - Delivery Overnight By 10:30am</option>
        <option value="FedEx First Overnight Collect">FedEx First Overnight Collect - Delivery Overnight By 8:00am</option>        <option value="FedEx Express Saver Collect">FedEx Express Saver Collect - 3 Business Days</option>
        <option value="FedEx Ground 3rd Party Billing">FedEx Ground 3rd Party Billing - 1 to 5 Business Days</option>
      </select>
      <div id="carrierAccountContainer" style="display: none;">
        <input id="carrierAccount" placeholder="Carrier Account #" style="width: 100%; margin-bottom: 15px; font-family: Arial, sans-serif; font-size: 15px;">
      </div>
    </div>
  </div>

  <h2>Order Summary</h2>
  <table id="summaryTable" style="width: 100%; border-collapse: collapse; margin-bottom: 15px;">

    <thead>
      <tr>
        <th style="border: 1px solid #ccc; padding: 8px;">Qty</th>
        <th style="border: 1px solid #ccc; padding: 8px;">Part Number</th>
        <th style="border: 1px solid #ccc; padding: 8px;">Unit Price</th>
        <th style="border: 1px solid #ccc; padding: 8px;">Total</th>
        <th style="border: 1px solid #ccc; padding: 8px;">Note</th>
      </tr>
    </thead>
    <tbody>
      <tr><td colspan="5" style="height: 3px;"></td></tr>
    </tbody>
  </table>
  <p><strong>Item Count:</strong> <span id="cartQuantityTotal">0</span></p>
  <p><strong>Total Price:</strong> $<span id="cartTotal">0.00</span></p>

  <div style="display: flex; gap: 20px;">
    <button type="button" id="continueShoppingBtn" style="flex: 1; padding: 15px; background: #6c757d; color: white; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; font-size: 18px;">Continue Shopping</button>
    <button type="submit" style="flex: 1; padding: 15px; background: #28a745; color: white; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; font-size: 18px;">Submit</button>
    <button type="button" id="logoutBtn" style="flex: 1; padding: 15px; background: #dc3545; color: white; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; font-size: 18px;">Logout</button>
  </div>
</form>

<!-- Message Box -->
<div id="messageBox" style="position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); padding: 15px 30px; border-radius: 8px; font-weight: bold; box-shadow: 0 6px 12px rgba(0,0,0,0.2); text-align: center; font-size: 20px; z-index: 1002; display: none;"></div>

<!-- Shipping Address Modal -->
<div id="shippingAddressModal" style="display: none; position: fixed; z-index: 1001; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4);">
  <div style="background-color: #fefefe; margin: 10% auto; padding: 20px; border: 1px solid #888; width: 80%; max-width: 500px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.2); position: relative;">
    <span onclick="closeModal('shippingAddressModal')" style="color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer;">&times;</span>
    <h2 id="shippingAddressModalTitle"></h2>
    <input type="hidden" id="shipToAddressId" />
    <input type="hidden" id="shipToCompanyId" />
    
    <label for="modalShipToName" style="display: block; margin-bottom: 5px; font-weight: bold;">Name:</label>
    <input id="modalShipToName" placeholder="Name" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />

    <label for="modalShipToAddress1" style="display: block; margin-bottom: 5px; font-weight: bold;">Address:</label>
    <textarea id="modalShipToAddress1" placeholder="Address" required rows="4" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;"></textarea>
    
    <label for="modalShipToCity" style="display: block; margin-bottom: 5px; font-weight: bold;">City:</label>
    <input id="modalShipToCity" placeholder="City" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />

    <label for="modalShipToState" style="display: block; margin-bottom: 5px; font-weight: bold;">State:</label>
    <input id="modalShipToState" placeholder="State" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />

    <label for="modalShipToZip" style="display: block; margin-bottom: 5px; font-weight: bold;">Zip Code:</label>
    <input id="modalShipToZip" placeholder="Zip Code" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />

    <label for="modalShipToCountry" style="display: block; margin-bottom: 5px; font-weight: bold;">Country:</label>
    <input id="modalShipToCountry" placeholder="Country" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />

    <div style="display: flex; justify-content: space-between;">
        <button id="saveShippingAddressBtn" type="button" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #007bff; color: white; font-size: 18px; font-weight: bold;">Save Address</button>
        <button id="cancelShippingAddressBtn" type="button" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #6c757d; color: white; font-size: 18px; font-weight: bold;">Cancel</button>
    </div>
  </div>
</div>

<!-- Custom Confirmation Modal -->
<div id="confirmationModal" style="display: none; position: fixed; z-index: 1003; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4);">
  <div style="background-color: #fefefe; margin: 15% auto; padding: 20px; border: 1px solid #888; width: 80%; max-width: 400px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.2); text-align: center;">
    <p id="confirmationMessage" style="font-size: 18px; margin-bottom: 20px;"></p>
    <div style="display: flex; justify-content: space-around;">
      <button id="confirmYesBtn" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #dc3545; color: white; font-size: 18px; font-weight: bold;">Yes</button>
      <button id="confirmNoBtn" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 18px; font-weight: bold;">No</button>
    </div>
  </div>
</div>

<!-- New Registration Modal -->
<div id="registrationModal" style="display: none; position: fixed; z-index: 1004; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4);">
  <div style="background-color: #fefefe; margin: 5% auto; padding: 20px; border: 1px solid #888; width: 80%; max-width: 600px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.2); position: relative;">
    <span onclick="closeModal('registrationModal')" style="color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer;">&times;</span>
    <h2 style="text-align: center;">New Company & User Registration</h2>
    
    <div style="display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 15px;">
      <div style="flex: 1; min-width: 250px;">
        <label for="regFirstName" style="display: block; margin-bottom: 5px; font-weight: bold;">First Name:</label>
        <input type="text" id="regFirstName" placeholder="First Name" required style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
      </div>
      <div style="flex: 1; min-width: 250px;">
        <label for="regLastName" style="display: block; margin-bottom: 5px; font-weight: bold;">Last Name:</label>
        <input type="text" id="regLastName" placeholder="Last Name" required style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
      </div>
    </div>

    <div style="display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 15px;">
      <div style="flex: 1; min-width: 250px;">
        <label for="regEmail" style="display: block; margin-bottom: 5px; font-weight: bold;">Email Address:</label>
        <input type="email" id="regEmail" placeholder="Email Address" required style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
      </div>
      <div style="flex: 1; min-width: 250px;">
        <label for="regPhone" style="display: block; margin-bottom: 5px; font-weight: bold;">Phone Number:</label>
        <input type="tel" id="regPhone" placeholder="Phone Number" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
      </div>
    </div>

    <div style="margin-bottom: 15px;">
      <label for="regCompanyName" style="display: block; margin-bottom: 5px; font-weight: bold;">Company Name:</label>
      <input type="text" id="regCompanyName" placeholder="Company Name" required style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
    </div>

    <div style="margin-bottom: 15px;">
      <label for="regAddress1" style="display: block; margin-bottom: 5px; font-weight: bold;">Company Address:</label>
      <input type="text" id="regAddress1" placeholder="Address Line 1" required style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
    </div>

    <div style="display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 15px;">
      <div style="flex: 1; min-width: 150px;">
        <label for="regCity" style="display: block; margin-bottom: 5px; font-weight: bold;">City:</label>
        <input type="text" id="regCity" placeholder="City" required style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
      </div>
      <div style="flex: 1; min-width: 100px;">
        <label for="regState" style="display: block; margin-bottom: 5px; font-weight: bold;">State:</label>
        <input type="text" id="regState" placeholder="State" required style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
      </div>
      <div style="flex: 1; min-width: 100px;">
        <label for="regZip" style="display: block; margin-bottom: 5px; font-weight: bold;">Zip Code:</label>
        <input type="text" id="regZip" placeholder="Zip Code" required style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
      </div>
    </div>
    
    <div style="margin-bottom: 15px;">
      <label for="regPassword" style="display: block; margin-bottom: 5px; font-weight: bold;">Password:</label>
      <input type="password" id="regPassword" placeholder="Password" required style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
    </div>

    <div style="margin-bottom: 15px;">
      <label for="regConfirmPassword" style="display: block; margin-bottom: 5px; font-weight: bold;">Confirm Password:</label>
      <input type="password" id="regConfirmPassword" placeholder="Confirm Password" required style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
    </div>

    <div style="display: flex; justify-content: space-between;">
        <button id="submitRegistrationBtn" type="button" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #007bff; color: white; font-size: 18px; font-weight: bold;">Submit Registration</button>
        <button id="cancelRegistrationBtn" type="button" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #6c757d; color: white; font-size: 18px; font-weight: bold;">Cancel</button>
    </div>
  </div>
</div>

<script>
document.addEventListener("DOMContentLoaded", () => {
  const API_URL = "https://checkout-backend-jvyx.onrender.com";
  let userProfile = null;
  let companyShippingAddresses = [];
  let confirmActionCallback = null; // To store the callback for confirmation modal

  // Helper function to show messages
  function showMessage(type, message) {
    const messageBox = document.getElementById("messageBox");
    messageBox.textContent = message;
    // Remove existing classes and add the new type class
    messageBox.className = ''; // Clear all classes
    messageBox.style.backgroundColor = ''; // Clear background color
    messageBox.style.color = ''; // Clear text color

    if (type === 'success') {
      messageBox.style.backgroundColor = '#28a745';
      messageBox.style.color = 'white';
    } else if (type === 'error') {
      messageBox.style.backgroundColor = '#dc3545';
      messageBox.style.color = 'white';
    } else if (type === 'info') { // New type for informational messages
      messageBox.style.backgroundColor = '#17a2b8';
      messageBox.style.color = 'white';
    }
    messageBox.style.display = "block";
    setTimeout(() => {
      messageBox.style.display = "none";
    }, 2500);
  }

  // Helper function for API calls
  async function apiFetch(endpoint, options = {}) {
    const url = `${API_URL}${endpoint}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      credentials: 'include',
    });

    // Log response details for debugging
    console.log(`API Call: ${options.method || 'GET'} ${url}, Status: ${response.status}`);
    // Changed console.error to console.warn for 401 status
    if (!response.ok) {
      const errorBody = await response.text();
      // Suppress console.warn for expected 401 on user-profile check
      if (response.status === 401 && endpoint === "/user-profile") {
        // No console output for this specific expected scenario
      } else if (response.status === 401) {
        console.warn(`API Warning (401 for other endpoints): ${errorBody}`);
      } else {
        console.error(`API Error Response (for non-OK status): ${errorBody}`);
      }
    }
    return response; // Always return the response
  }

  function closeModal(modalId) {
    document.getElementById(modalId).style.display = "none";
  }

  // Custom confirmation modal functions
  function showConfirmModal(message, callback) {
    document.getElementById('confirmationMessage').textContent = message;
    document.getElementById('confirmationModal').style.display = 'block';
    confirmActionCallback = callback;
  }

  function hideConfirmModal() {
    document.getElementById('confirmationModal').style.display = 'none';
    confirmActionCallback = null;
  }

  document.getElementById('confirmYesBtn').onclick = () => {
    if (confirmActionCallback) {
      confirmActionCallback(true);
    }
    hideConfirmModal();
  };

  document.getElementById('confirmNoBtn').onclick = () => {
    if (confirmActionCallback) {
      confirmActionCallback(false);
    }
    hideConfirmModal();
  };

  async function handleLogin() {
    const email = document.getElementById("authUsername").value.trim();
    const password = document.getElementById("authPassword").value.trim();

    if (!email || !password) {
      showMessage("error", "Enter both email and password");
      return;
    }

    console.log(`Attempting to login with email: ${email}`);
    try {
      const res = await apiFetch("/login", {
        method: "POST",
        body: JSON.stringify({ email, password })
      });

      console.log(`Login API response status: ${res.status}, ok: ${res.ok}`);

      if (res.ok) { // Check res.ok here
        localStorage.setItem("userLoggedIn", "true");
        await loadUserProfileAndCompanyData(); // Load profile and company data after successful auth
        document.getElementById("authForm").style.display = "none";
        document.getElementById("checkoutForm").style.display = "block";
        updateSummary();
      } else {
        const errorData = await res.json().catch(() => ({ error: 'Unknown error', rawResponse: res.statusText }));
        console.error("Authentication failed response:", errorData);
        // Check for specific "user not found" or "invalid credentials" error
        if (res.status === 401 || (errorData.error && errorData.error.includes("Invalid credentials"))) {
          showMessage("info", "Your request has been submitted. As soon as it is approved, you will be notified.");
          // Optionally, clear the form or disable it to prevent re-submission
          document.getElementById("authUsername").value = "";
          document.getElementById("authPassword").value = "";
        } else {
          showMessage("error", `Login failed. ${errorData.error || res.statusText || 'Please try again.'}`);
        }
      }
    } catch (error) {
      // Generic network or other unexpected error
      showMessage("error", `An error occurred during login. ${error.message || 'Please try again.'}`);
      console.error("Auth error:", error);
    }
  }

  function openRegistrationModal() {
    document.getElementById('registrationModal').style.display = 'block';
    // Clear previous input values
    document.getElementById('regFirstName').value = '';
    document.getElementById('regLastName').value = '';
    document.getElementById('regEmail').value = '';
    document.getElementById('regCompanyName').value = '';
    document.getElementById('regAddress1').value = '';
    document.getElementById('regCity').value = '';
    document.getElementById('regState').value = '';
    document.getElementById('regZip').value = '';
    document.getElementById('regPhone').value = '';
    document.getElementById('regPassword').value = '';
    document.getElementById('regConfirmPassword').value = '';
  }

  async function requestRegistration() {
    const email = document.getElementById("authUsername").value.trim();
    const password = document.getElementById("authPassword").value.trim();

    if (!email && !password) { // If both are blank, open the new modal
      openRegistrationModal();
      return;
    }

    // Existing behavior if email/password are provided
    showMessage("info", "Your request has been submitted. As soon as it is approved, you will be notified.");
    document.getElementById("authUsername").value = "";
    document.getElementById("authPassword").value = "";

    console.log(`Client-side registration request simulated for email: ${email}. No backend call made.`);
  }

  async function submitRegistration() {
    console.log("Attempting to submit registration..."); // New log
    const firstName = document.getElementById('regFirstName').value.trim();
    const lastName = document.getElementById('regLastName').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const companyName = document.getElementById('regCompanyName').value.trim();
    const address1 = document.getElementById('regAddress1').value.trim();
    const city = document.getElementById('regCity').value.trim();
    const state = document.getElementById('regState').value.trim();
    const zip = document.getElementById('regZip').value.trim();
    const phone = document.getElementById('regPhone').value.trim();
    const password = document.getElementById('regPassword').value.trim();
    const confirmPassword = document.getElementById('regConfirmPassword').value.trim();

    // Basic client-side validation
    if (!firstName || !lastName || !email || !companyName || !address1 || !city || !state || !zip || !password || !confirmPassword) {
      console.log("Validation failed: All fields are required."); // New log
      showMessage('error', 'All fields are required.');
      return;
    }
    if (password !== confirmPassword) {
      console.log("Validation failed: Passwords do not match."); // New log
      showMessage('error', 'Passwords do not match.');
      return;
    }
    if (password.length < 3) { // Changed from 6 to 3
      console.log("Validation failed: Password too short."); // New log
      showMessage('error', 'Password must be at least 3 characters long.'); // Updated message
      return;
    }

    try {
      // Step 1: Register the company
      const companyData = {
        name: companyName,
        address1: address1,
        city: city,
        state: state,
        zip: zip,
        country: "USA", // Assuming USA as default, adjust if needed
        terms: "Net 30", // Default terms, adjust if needed
        logo: "" // No logo on initial registration
      };
      
      showMessage('info', 'Registering company...');
      console.log("Sending company registration data:", companyData); // New log
      const companyRes = await apiFetch("/register-company", {
        method: "POST",
        body: JSON.stringify(companyData)
      });

      if (!companyRes.ok) {
        const errorData = await companyRes.json().catch(() => ({ error: 'Unknown error' }));
        console.error("Company registration failed response:", errorData); // New log
        showMessage('error', `Company registration failed: ${errorData.error || companyRes.statusText}`);
        return;
      }
      const companyResult = await companyRes.json();
      const companyId = companyResult.companyId; // Assuming backend returns companyId
      console.log("Company registered successfully with ID:", companyId); // New log

      // Step 2: Register the user
      const userData = {
        email: email,
        firstName: firstName,
        lastName: lastName,
        phone: phone,
        role: "user", // Default role for new registrations
        password: password,
        companyId: companyId
      };

      showMessage('info', 'Registering user...');
      console.log("Sending user registration data:", userData); // New log
      const userRes = await apiFetch("/register-user", {
        method: "POST",
        body: JSON.stringify(userData)
      });

      if (!userRes.ok) {
        const errorData = await userRes.json().catch(() => ({ error: 'Unknown error' }));
        console.error("User registration failed response:", errorData); // New log
        showMessage('error', `User registration failed: ${errorData.error || userRes.statusText}`);
        return;
      }
      console.log("User registered successfully."); // New log

      showMessage('success', 'Registration successful! You can now log in.');
      closeModal('registrationModal');
      // Optionally, pre-fill login form with new email
      document.getElementById("authUsername").value = email;
      document.getElementById("authPassword").value = ''; // Clear password for security
      document.getElementById("authForm").style.display = "block"; // Ensure login form is visible

    } catch (error) {
      console.error("Registration process error (caught by try/catch):", error); // New log
      showMessage('error', `An unexpected error occurred during registration: ${error.message}`);
    }
  }


  const checkLoginStatus = async () => { // Changed to named function expression
    try {
      const res = await apiFetch("/user-profile");
      if (res.ok) { // Check res.ok here
        userProfile = await res.json();
        console.log("User Profile:", userProfile); // Log user profile for debugging
        
        document.getElementById("authForm").style.display = "none";
        document.getElementById("checkoutForm").style.display = "block";
        
        await loadUserProfileAndCompanyData(); // Load profile and company data
        updateSummary();
      } else {
        // User is not logged in, or session expired. Expected behavior for checkLoginStatus.
        console.log("User not logged in, displaying auth form."); // Informational log
        document.getElementById("authForm").style.display = "block";
        document.getElementById("checkoutForm").style.display = "none";
      }
    } catch (error) {
      // This catch block is for network errors or other truly unexpected issues with apiFetch itself
      console.error("Unexpected error during login status check:", error);
      document.getElementById("authForm").style.display = "block";
      document.getElementById("checkoutForm").style.display = "none";
      showMessage("error", "Failed to connect to authentication service. Please try again later.");
    }
  };


  async function loadUserProfileAndCompanyData() {
    try {
      const profileRes = await apiFetch("/user-profile");
      if (profileRes.ok) { // Check res.ok here
        userProfile = await profileRes.json();
        console.log("User Profile:", userProfile); // Log user profile for debugging

        // Populate "Ordered By" with user's first and last name
        document.getElementById("orderedBy").value = `${userProfile.first_name || ''} ${userProfile.last_name || ''}`.trim();

        // Populate "Bill To" and "Terms" from company data using the new user-specific endpoint
        if (userProfile.company_id) {
          const companyDetailsRes = await apiFetch(`/user/company-details`); // NEW ENDPOINT
          if (companyDetailsRes.ok) { // Check res.ok here
            const company = await companyDetailsRes.json();
            console.log("User's Company Data:", company); // Log company data for debugging

            document.getElementById("billedToInfo").value = `${company.name || ''}\n${company.address1 || ''}\n${company.city || ''}, ${company.state || ''} ${company.zip || ''} ${company.country || ''}`.trim();
            document.getElementById("terms").value = company.terms || "";

            // Fetch shipping addresses for the company using the now-authorized endpoint
            const shipToRes = await apiFetch(`/api/shipto/${userProfile.company_id}`);
            if (shipToRes.ok) { // Check res.ok here
              companyShippingAddresses = await shipToRes.json();
              console.log("Shipping Addresses:", companyShippingAddresses); // Log shipping addresses for debugging
              updateShippingAddressDropdown();

              // Ensure shipping address dropdown and buttons are enabled if data is successfully loaded
              document.getElementById("shipToAddressDropdown").disabled = false;
              document.getElementById("addShipToBtn").disabled = false;
              document.getElementById("addShipToBtn").style.opacity = '1';
            } else {
              console.error("Failed to fetch shipping addresses:", await shipToRes.text());
              showMessage("error", "Failed to load shipping addresses.");
            }
          } else {
            console.error("Failed to fetch user's company details:", await companyDetailsRes.text());
            showMessage("error", "Failed to load company data.");
          }
        } else {
          console.log("No company_id found for user. Bill To and Terms will not be populated.");
          document.getElementById("billedToInfo").value = '';
          document.getElementById("terms").value = '';
          companyShippingAddresses = []; // Ensure shipping addresses are empty
          updateShippingAddressDropdown(); // This will disable dropdown and hide buttons
          document.getElementById("shipToAddressDropdown").disabled = true; // Explicitly disable dropdown
          document.getElementById("addShipToBtn").disabled = true;
          document.getElementById("addShipToBtn").style.opacity = '0.5';
        }
      } else {
        // User is not logged in, or session expired. Expected behavior for checkLoginStatus.
        console.log("User not logged in, displaying auth form."); // Informational log
        document.getElementById("authForm").style.display = "block";
        document.getElementById("checkoutForm").style.display = "none";
      }
    } catch (error) {
      // This catch block is for network errors or other truly unexpected issues with apiFetch itself
      console.error("Unexpected error during login status check:", error);
      document.getElementById("authForm").style.display = "block";
      document.getElementById("checkoutForm").style.display = "none";
      showMessage("error", "Failed to connect to authentication service. Please try again later.");
    }
  }

  function updateShippingAddressDropdown() {
    const dropdown = document.getElementById("shipToAddressDropdown");
    dropdown.innerHTML = '<option value="">-- Select Shipping Address --</option>';

    if (companyShippingAddresses.length === 0) {
      document.getElementById("editShipToBtn").style.display = 'none';
      document.getElementById("deleteShipToBtn").style.display = 'none';
      document.getElementById("shipToInfo").value = ''; // Clear ship to info if no addresses
      dropdown.disabled = true; // Ensure dropdown is disabled
      dropdown.innerHTML = '<option value="">-- No Shipping Addresses Found --</option>';
    } else {
      dropdown.disabled = false; // Enable dropdown if addresses are loaded
      companyShippingAddresses.sort((a, b) => (b.is_default || 0) - (a.is_default || 0));

      companyShippingAddresses.forEach(address => {
        const option = document.createElement("option");
        option.value = address.id;
        option.textContent = `${address.name} ${address.is_default ? '(Default)' : ''}`;
        dropdown.appendChild(option);
      });

      const defaultAddress = companyShippingAddresses.find(addr => addr.is_default);
      if (defaultAddress) {
        dropdown.value = defaultAddress.id;
      } else {
        dropdown.value = companyShippingAddresses[0].id;
      }
      displaySelectedShipToAddress(); // Display details for the selected address
      document.getElementById("editShipToBtn").style.display = 'inline-block';
      document.getElementById("deleteShipToBtn").style.display = 'inline-block';
    }
  }

  function displaySelectedShipToAddress() {
    const dropdown = document.getElementById("shipToAddressDropdown");
    const shipToInfoTextarea = document.getElementById("shipToInfo");
    const selectedAddressId = dropdown.value; 
    if (!selectedAddressId) { 
      shipToInfoTextarea.value = '';
      document.getElementById("editShipToBtn").style.display = 'none';
      document.getElementById("deleteShipToBtn").style.display = 'none';
      return;
    }

    const selectedAddress = companyShippingAddresses.find(addr => addr.id == selectedAddressId);
    if (selectedAddress) {
      // Corrected typo: changed 'shipToTextarea' to 'shipToInfoTextarea'
      shipToInfoTextarea.value = `${selectedAddress.name || ''}\n${selectedAddress.address1 || ''}\n${selectedAddress.city || ''}, ${selectedAddress.state || ''} ${selectedAddress.zip || ''} ${selectedAddress.country || ''}`.trim();
      document.getElementById("editShipToBtn").style.display = 'inline-block';
      document.getElementById("deleteShipToBtn").style.display = 'inline-block';
    } else {
      shipToInfoTextarea.value = '';
      document.getElementById("editShipToBtn").style.display = 'none';
      document.getElementById("deleteShipToBtn").style.display = 'none';
    }
  }

  async function logoutUser() {
    try {
      const res = await apiFetch("/logout", { method: "POST" });
      if (res.ok) {
        localStorage.removeItem("userLoggedIn");
        // Redirect to the specified URL after successful logout
        window.location.href = document.referrer || '/'; 
      } else {
        console.error("Logout failed:", await res.text());
        showMessage("error", "Failed to log out.");
      }
    } catch (error) {
      console.error("Logout error:", error);
      showMessage("error", "An error occurred during logout.");
    }
  }

  function toggleCarrierAccount() {
    const value = document.getElementById("shippingMethod").value.toLowerCase();
    const carrierAccountInput = document.getElementById("carrierAccount");
    const carrierAccountContainer = document.getElementById("carrierAccountContainer");

    const show = value.includes("collect") || value.includes("3rd party");
    carrierAccountContainer.style.display = show ? "block" : "none";

    // Set or remove the 'required' attribute based on the 'show' variable
    if (show) {
      carrierAccountInput.setAttribute("required", "required");
    } else {
      carrierAccountInput.removeAttribute("required");
    }
  }

  function loadCart() {
    const stored = localStorage.getItem("shoppingCart");
    let cart = [];

    try {
      if (stored) cart = JSON.parse(stored);
    } catch (e) {
      cart = [];
    }
    return cart;
  }

  function updateSummary() {
    const cart = loadCart();
    const tbody = document.querySelector("#summaryTable tbody");
    const totalEl = document.getElementById("cartTotal");
    const quantityEl = document.getElementById("cartQuantityTotal");
    tbody.innerHTML = '<tr><td colspan="5" style="height: 12px;"></td></tr>';
    let total = 0;
    let quantity = 0;
    cart.forEach((item, index) => { // 'index' is correctly defined here
      const lineTotal = item.price * item.quantity;
      total += lineTotal;
      quantity += item.quantity;

      // Sanitize item.note to prevent XSS
      const sanitizedNote = item.note ? escapeHTML(item.note) : '';

      const row = document.createElement("tr");
      row.innerHTML = `
        <td style="border: 1px solid #ccc; padding: 8px; text-align: center;">${item.quantity}</td>
        <td style="border: 1px solid #ccc; padding: 8px;">${escapeHTML(item.partNo)}</td>
        <td style="border: 1px solid #ccc; padding: 8px; text-align: right;">$${item.price.toFixed(2)}</td>
        <td style="border: 1px solid #ccc; padding: 8px; text-align: right;">$${lineTotal.toFixed(2)}</td>
        <td style="border: 1px solid #ccc; padding: 8px;">${sanitizedNote}</td>
      `;
      tbody.appendChild(row);
    });
    totalEl.textContent = total.toFixed(2);
    quantityEl.textContent = quantity;
  }

  // Helper function to escape HTML for display
  function escapeHTML(str) {
      var div = document.createElement('div');
      div.appendChild(document.createTextNode(str));
      return div.innerHTML;
  }

  async function submitOrder(e) {
    e.preventDefault();
    const cart = loadCart();
    if (!cart.length) {
      showMessage("error", "Cart is empty");
      return;
    }

    const selectedShipToId = document.getElementById("shipToAddressDropdown").value;
    const selectedShipToAddress = companyShippingAddresses.find(addr => addr.id == selectedShipToId);

    // If shipping addresses are unavailable, prevent order submission
    if (!selectedShipToId || !selectedShipToAddress) {
      showMessage("error", "Cannot submit order: Please select a valid shipping address.");
      return;
    }

    const data = {
      poNumber: document.getElementById("poNumber").value,
      orderedBy: document.getElementById("orderedBy").value,
      billingAddress: document.getElementById("billedToInfo").value,
      shippingAddress: document.getElementById("shipToInfo").value, // This will be the formatted text
      shippingAddressId: selectedShipToId, // Send the ID for backend reference
      attn: document.getElementById("attn").value,
      tag: document.getElementById("tag").value,
      shippingMethod: document.getElementById("shippingMethod").value,
      carrierAccount: document.getElementById("carrierAccount").value,
      items: cart
    };

    console.log("Submitting order data:", data); // Log the data being sent

    try {
      const res = await apiFetch("/submit-order", {
        method: "POST",
        body: JSON.stringify(data)
      });

      console.log(`Submit Order API response status: ${res.status}, ok: ${res.ok}`); // Log response status and ok

      if (res.ok) { // Check res.ok here
        showMessage("success", "Order submitted successfully!");
        localStorage.removeItem("shoppingCart");
        // Redirect to the specified URL after successful submission
        setTimeout(() => {
          window.location.href = document.referrer || '/';
        }, 1000); // Reload after a short delay to show message
      } else {
        const errorData = await res.json().catch(() => ({ error: 'Unknown error' }));
        console.error("Order submission failed response:", errorData);
        showMessage("error", errorData.error || `Failed to submit order. ${res.statusText || 'Please try again.'}`);
      }
    } catch (error) {
      showMessage("error", `Failed to submit order. ${error.message || 'Please try again.'}`);
      console.error("Order submission error:", error);
    }
  }

  // Shipping Address Management Functions (similar to admin-dashboard)
  async function openShippingAddressModal(isAdd = true, address = null) {
    // Check if dropdown is disabled, implies backend issue or no company_id
    if (document.getElementById("shipToAddressDropdown").disabled && !userProfile.company_id) {
      showMessage('error', 'Shipping address management is currently unavailable as no company is associated or backend issue.');
      return;
    }
    
    const modalTitle = document.getElementById("shippingAddressModalTitle");
    const addressIdInput = document.getElementById("shipToAddressId");
    const companyIdInput = document.getElementById("shipToCompanyId");
    const nameInput = document.getElementById("modalShipToName");
    const address1Input = document.getElementById("modalShipToAddress1");
    const cityInput = document.getElementById("modalShipToCity");
    const stateInput = document.getElementById("modalShipToState");
    const zipInput = document.getElementById("modalShipToZip");
    const countryInput = document.getElementById("modalShipToCountry");

    if (isAdd) {
      modalTitle.textContent = "Add Shipping Address";
      addressIdInput.value = "";
      companyIdInput.value = userProfile.company_id; // Ensure companyId is set for new addresses
      nameInput.value = "";
      address1Input.value = "";
      cityInput.value = "";
      stateInput.value = "";
      zipInput.value = "";
      countryInput.value = "";
    } else if (address) {
      modalTitle.textContent = "Edit Shipping Address";
      addressIdInput.value = address.id;
      companyIdInput.value = address.company_id;
      nameInput.value = address.name || '';
      address1Input.value = address.address1 || '';
      cityInput.value = address.city || '';
      stateInput.value = address.state || '';
      zipInput.value = address.zip || '';
      countryInput.value = address.country || '';
    }

    document.getElementById("shippingAddressModal").style.display = "block";
  }

  async function editSelectedShippingAddress() {
    if (document.getElementById("shipToAddressDropdown").disabled) {
      showMessage('error', 'Shipping address management is currently unavailable.');
      return;
    }
    const dropdown = document.getElementById("shipToAddressDropdown");
    const selectedAddressId = dropdown.value;
    
    if (selectedAddressId) {
      const selectedAddress = companyShippingAddresses.find(addr => addr.id == selectedAddressId);
      if (selectedAddress) {
        openShippingAddressModal(false, selectedAddress);
      } else {
        showMessage('error', 'Selected address not found.');
      }
    } else {
      showMessage('error', 'Please select an address to edit.');
    }
  }

  async function submitShippingAddress() {
    const addressId = document.getElementById('shipToAddressId').value;
    const companyId = document.getElementById('shipToCompanyId').value; // Get companyId from hidden input
    const name = document.getElementById('modalShipToName').value;
    const address1 = document.getElementById('modalShipToAddress1').value;
    const city = document.getElementById('modalShipToCity').value;
    const state = document.getElementById('modalShipToState').value;
    const zip = document.getElementById('modalShipToZip').value;
    const country = document.getElementById('modalShipToCountry').value;

    // companyId is now mandatory for POST requests, but for PUT, it's derived from addressId in backend
    if (!userProfile.company_id || !name || !address1 || !city || !state || !zip) {
      showMessage('error', "Company ID, Name, Address, City, State, and Zip are required.");
      return;
    }

    const addressData = {
      companyId: userProfile.company_id, // Always send user's company ID for authorization
      name: name,
      address1: address1,
      city: city,
      state: state,
      zip: zip,
      country: country
    };

    let endpoint = "/api/shipto";
    let method = "POST";
    let successMessage = "Address Added Successfully!";

    if (addressId) {
      endpoint = `/api/shipto/${addressId}`;
      method = "PUT";
      // For PUT, backend will derive companyId from addressId, no need to send it in body
      delete addressData.companyId; 
      successMessage = "Address Updated Successfully!";
    }

    try {
      const response = await apiFetch(endpoint, {
        method: method,
        body: JSON.stringify(addressData)
      });

      if (response.ok) {
        showMessage('success', successMessage);
        closeModal('shippingAddressModal');
        await loadUserProfileAndCompanyData(); // Refresh addresses
      } else {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        showMessage('error', errorData.error || `Failed to save shipping address: ${response.statusText}`);
      }
    } catch (error) {
      console.error("Error saving shipping address:", error);
      showMessage('error', "An error occurred while saving the shipping address.");
    }
  }

  function confirmDeleteShippingAddress() {
    if (document.getElementById("shipToAddressDropdown").disabled) {
      showMessage('error', 'Shipping address management is currently unavailable.');
      return;
    }
    const dropdown = document.getElementById("shipToAddressDropdown");
    const addressId = dropdown.value;
    if (!addressId) {
      showMessage('error', 'No address selected to delete.');
      return;
    }
    showConfirmModal("Are you sure you want to delete this shipping address?", async (confirmed) => {
      if (confirmed) {
        await deleteSelectedShippingAddress();
      }
    });
  }

  async function deleteSelectedShippingAddress() {
    const dropdown = document.getElementById("shipToAddressDropdown");
    const addressId = dropdown.value;
    // companyId is not directly used here, but authorizeCompanyAccess middleware will verify it

    try {
      const response = await apiFetch(`/api/shipto/${addressId}`, {
        method: "DELETE"
      });

      if (response.ok) {
        showMessage('success', "Address Deleted Successfully!");
        await loadUserProfileAndCompanyData(); // Refresh addresses
      } else {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        showMessage('error', errorData.error || "Failed to delete address.");
      }
    } catch (error) {
      console.error("Error deleting address:", error);
      showMessage('error', "An error occurred while deleting the address.");
    }
  }

  // Event Listeners for buttons
  document.getElementById('loginBtn').addEventListener('click', handleLogin);
  document.getElementById('requestRegistrationBtn').addEventListener('click', requestRegistration);
  document.getElementById('addShipToBtn').addEventListener('click', () => openShippingAddressModal(true));
  document.getElementById('editShipToBtn').addEventListener('click', editSelectedShippingAddress);
  document.getElementById('deleteShipToBtn').addEventListener('click', confirmDeleteShippingAddress);
  document.getElementById('saveShippingAddressBtn').addEventListener('click', submitShippingAddress);
  document.getElementById('cancelShippingAddressBtn').addEventListener('click', () => closeModal('shippingAddressModal'));
  document.getElementById('logoutBtn').addEventListener('click', logoutUser);
  document.getElementById('continueShoppingBtn').addEventListener('click', () => {
    window.location.href = document.referrer || '/';
  });

  // New event listeners for registration modal
  document.getElementById('submitRegistrationBtn').addEventListener('click', submitRegistration);
  document.getElementById('cancelRegistrationBtn').addEventListener('click', () => closeModal('registrationModal'));


  // Initial call to check login status when the DOM is ready
  checkLoginStatus();
});
</script>

<div style="text-align: center; margin-top: 50px; padding-bottom: 20px;">
  <strong>Chicago Stainless Equipment, Inc.</strong><br>
  1280 SW 34th St<br>
  Palm City, FL 34990 USA<br>
  772-781-1441
</div>

</body>
</html>
