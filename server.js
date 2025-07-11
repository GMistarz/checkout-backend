<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Admin Dashboard</title>
  <style>
    /* Keyframes for the success message animation */
    @keyframes popIn {
      from { transform: translate(-50%, -50%) scale(0.8); opacity: 0; }
      to { transform: translate(-50%, -50%) scale(1); opacity: 1; }
    }
  </style>
</head>
<body style="font-family: Arial, sans-serif; margin: 0; background: #f0f0f0;">
  <div style="background: white; padding: 10px 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
    <div style="display: flex; align-items: center; gap: 20px;">
      <img src="https://www.chicagostainless.com/graphics/cse_logo.png" style="height: 50px;" />
      <button id="createCompanyButton" onclick="openAddCompanyModal(true)" style="padding: 8px 16px;">Create New Company</button>
    </div>
    <h1 style="position: absolute; left: 50%; transform: translateX(-50%); margin: 0;">Admin Dashboard</h1>
    <button onclick="logout()" style="padding: 8px 16px;">Logout</button>
  </div>

  <div style="padding: 20px;">
    <div id="companies"></div>
  </div>

  <div id="successMessage" style="display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%) scale(0.8);
    background: #dff0d8; color: #3c763d; padding: 40px; font-weight: bold; border-radius: 12px; box-shadow: 0 0 25px rgba(0, 0, 0, 0.4);
    z-index: 9999; border: 3px solid #3c763d; font-size: 20px; animation: popIn 0.3s ease-out forwards; transition: transform 0.3s ease-out;">
  </div>

  <div id="addCompanyModal" style="display:none; position:fixed; top:0; left:0; width:100vw; height:100vh; background:rgba(0,0,0,0.5); justify-content:center; align-items:center;">
    <div style="background:white; padding:20px; border-radius:10px; width:400px; display:flex; flex-direction:column;">
      <h3 id="companyModalTitle">Add New Company</h3>
      <input id="companyName" placeholder="Company Name" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="companyLogo" placeholder="Logo URL" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="companyAddress1" placeholder="Address Line 1" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="companyAddress2" placeholder="Address Line 2" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="companyCity" placeholder="City" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="companyState" placeholder="State" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="companyZip" placeholder="Zip Code" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="companyCountry" placeholder="Country" style="width:100%; margin-bottom:8px; padding:6px;" />
      <select id="companyTerms" style="width:100%; margin-bottom:8px; padding:6px;">
        <option value="C.O.D.">C.O.D.</option>
        <option value="Credit Card">Credit Card</option>
        <option value="Net 15 Days">Net 15 Days</option>
        <option value="Net 30 Days">Net 30 Days</option>
        <option value="Net 45 Days">Net 45 Days</option>
        <option value="Net 60 Days">Net 60 Days</option>
        <option value="Pre Paid">Pre Paid</option>
      </select>
      <div style="margin-top:10px; display:flex; justify-content:flex-end; gap:8px;">
        <button onclick="submitCompanyModal()">Save</button>
        <button onclick="closeAddCompanyModal()">Cancel</button>
      </div>
    </div>
  </div>

  <div id="editCompanyModal" style="display:none; position:fixed; top:0; left:0; width:100vw; height:100vh; background:rgba(0,0,0,0.5); justify-content:center; align-items:center;">
    <div style="background:white; padding:20px; border-radius:10px; width:400px; display:flex; flex-direction:column;">
      <h3>Edit Company</h3>
      <input id="editCompanyName" placeholder="Company Name" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="editCompanyLogo" placeholder="Logo URL" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="editCompanyAddress1" placeholder="Address Line 1" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="editCompanyAddress2" placeholder="Address Line 2" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="editCompanyCity" placeholder="City" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="editCompanyState" placeholder="State" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="editCompanyZip" placeholder="Zip Code" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="editCompanyCountry" placeholder="Country" style="width:100%; margin-bottom:8px; padding:6px;" />
      <select id="editCompanyTerms" style="width:100%; margin-bottom:8px; padding:6px;">
        <option value="C.O.D.">C.O.D.</option>
        <option value="Credit Card">Credit Card</option>
        <option value="Net 15 Days">Net 15 Days</option>
        <option value="Net 30 Days">Net 30 Days</option>
        <option value="Net 45 Days">Net 45 Days</option>
        <option value="Net 60 Days">Net 60 Days</option>
        <option value="Pre Paid">Pre Paid</option>
      </select>
      <div style="margin-top:10px;">
        <button onclick="submitEditCompany()" style="margin-right: 8px;">Save</button>
        <button onclick="closeModal('editCompanyModal')" style="margin-right: 8px;">Cancel</button>
        <button onclick="deleteCompany(editingCompanyId)" style="background:#d9534f; color:white;">Delete Company</button>
      </div>
    </div>
  </div>

  <div id="editUserModal" style="display:none; position:fixed; top:0; left:0; width:100vw; height:100vh; background:rgba(0,0,0,0.5); justify-content:center; align-items:center;">
    <div style="background:white; padding:20px; border-radius:10px; width:400px; display:flex; flex-direction:column;">
      <h3>Edit User</h3>
      <input id="editUserEmail" placeholder="Email" style="margin-bottom:8px; padding:6px;" />
      <input id="editUserFirstName" placeholder="First Name" style="margin-bottom:8px; padding:6px;" />
      <input id="editUserLastName" placeholder="Last Name" style="margin-bottom:8px; padding:6px;" />
      <input id="editUserPhone" placeholder="Phone" style="margin-bottom:8px; padding:6px;" />
      <select id="editUserRole" style="margin-bottom:8px; padding:6px;">
        <option value="user">User</option>
        <option value="admin">Admin</option>
      </select>
      <input id="editUserPassword" placeholder="New Password (optional)" type="password" style="margin-bottom:8px; padding:6px;" />
      <div style="margin-top:10px; display:flex; justify-content:space-between; gap:8px;">
        <div>
          <button onclick="submitEditUser()">Save</button>
          <button onclick="closeModal('editUserModal')">Cancel</button>
        </div>
        <button onclick="deleteUser()" style="background:#d9534f;color:white;">Delete User</button>
      </div>
    </div>
  </div>

  <div id="addUserModal" style="display:none; position:fixed; top:0; left:0; width:100vw; height:100vh; background:rgba(0,0,0,0.5); justify-content:center; align-items:center;">
    <div style="background:white; padding:20px; border-radius:10px; width:400px; display:flex; flex-direction:column;">
      <h3>Add New User</h3>
      <input id="newUserEmail" placeholder="Email" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="newUserFirstName" placeholder="First Name" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="newUserLastName" placeholder="Last Name" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="newUserPhone" placeholder="Phone" style="width:100%; margin-bottom:8px; padding:6px;" />
      <select id="newUserRole" style="width:100%; margin-bottom:8px; padding:6px;">
        <option value="user">User</option>
        <option value="admin">Admin</option>
      </select>
      <input id="newUserPassword" type="password" placeholder="Password" style="width:100%; margin-bottom:8px; padding:6px;" />
      <div style="margin-top:10px; display:flex; justify-content:flex-end; gap:8px;">
        <button onclick="submitAddUser()">Save</button>
        <button onclick="closeModal('addUserModal')">Cancel</button>
      </div>
    </div>
  </div>

  <div id="shippingAddressModal" style="display:none; position:fixed; top:0; left:0; width:100vw; height:100vh; background:rgba(0,0,0,0.5); justify-content:center; align-items:center;">
    <div style="background:white; padding:20px; border-radius:10px; width:400px; display:flex; flex-direction:column;">
      <h3 id="shippingAddressModalTitle">Add Shipping Address</h3>
      <input id="shipToName" placeholder="Location Name (Optional)" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="shipToAddress1" placeholder="Address Line 1" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="shipToAddress2" placeholder="Address Line 2" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="shipToCity" placeholder="City" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="shipToState" placeholder="State" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="shipToZip" placeholder="Zip Code" style="width:100%; margin-bottom:8px; padding:6px;" />
      <input id="shipToCountry" placeholder="Country" style="width:100%; margin-bottom:8px; padding:6px;" />
      <!-- New checkbox for default address -->
      <div style="display: flex; align-items: center; margin-top: 10px; margin-bottom: 10px;">
        <input type="checkbox" id="shipToIsDefault" style="margin-right: 8px;" />
        <label for="shipToIsDefault">Set as Default Address</label>
      </div>
      <div style="margin-top:10px; display:flex; justify-content:flex-end; gap:8px;">
        <button onclick="submitShippingAddress()">Save</button>
        <button onclick="closeModal('shippingAddressModal')">Cancel</button>
      </div>
    </div>
  </div>

  <script>
    const API_BASE = "https://checkout-backend-jvyx.onrender.com";
    let currentCompanyId = null;
    let currentUserId = null;
    let expandedCompanyId = null;
    let editingCompanyId = null;
    let editingShippingAddressId = null;;
    let companies = [];
    
    // We now store the addresses temporarily once fetched for the current company
    let currentShippingAddresses = []; 

    // Helper Functions
    function logout() {
      fetch(`${API_BASE}/logout`, { method: 'POST', credentials: 'include' })
        .then(() => window.location.href = "/admin.html");
    }

    function closeModal(id) {
      document.getElementById(id).style.display = "none";
      // Ensure we refresh the expanded company details if a modal related to it was closed
      if (expandedCompanyId) {
          toggleCompanyDetails(expandedCompanyId, true); // Force refresh
      } else {
          fetchCompanies();
      }
    }

    function closeAddCompanyModal() {
      document.getElementById("addCompanyModal").style.display = "none";
      fetchCompanies(expandedCompanyId);
    }

    function showSuccess(message) {
      const el = document.getElementById("successMessage");
      el.innerText = message;
      el.style.display = "block";
      el.style.animation = "none";
      el.offsetHeight; // trigger reflow
      el.style.animation = null;
      setTimeout(() => el.style.display = "none", 3000);
    }

    // Add Company Functions (uses addCompanyModal inputs)
    function openAddCompanyModal(isNew = true) {
      editingCompanyId = isNew ? null : editingCompanyId;
      document.getElementById("companyModalTitle").innerText = isNew ? "Add New Company" : "Edit Company";
      document.getElementById("companyName").value = "";
      document.getElementById("companyLogo").value = "";
      document.getElementById("companyAddress1").value = "";
      document.getElementById("companyAddress2").value = "";
      document.getElementById("companyCity").value = "";
      document.getElementById("companyState").value = "";
      document.getElementById("companyZip").value = "";
      document.getElementById("companyCountry").value = "";
      document.getElementById("companyTerms").value = "C.O.D.";
      document.getElementById("addCompanyModal").style.display = "flex";
    }

    function submitCompanyModal() {
      const payload = {
        id: editingCompanyId,
        name: document.getElementById("companyName").value,
        logo: document.getElementById("companyLogo").value,
        address1: document.getElementById("companyAddress1").value,
        address2: document.getElementById("companyAddress2").value,
        city: document.getElementById("companyCity").value,
        state: document.getElementById("companyState").value,
        zip: document.getElementById("companyZip").value,
        country: document.getElementById("companyCountry").value,
        terms: document.getElementById("companyTerms").value
      };

      const url = editingCompanyId ? `${API_BASE}/edit-company` : `${API_BASE}/add-company`;
      const isNewCompany = !editingCompanyId;

      fetch(url, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      })
      .then(res => {
        if (!res.ok) {
            return res.json().then(errorData => {
                console.error("API error details:", errorData);
                throw new Error(errorData.error || `HTTP error! status: ${res.status}`);
            }).catch(e => {
                throw new Error(`HTTP error! status: ${res.status}`);
            });
        }
        return res.json();
      })
      .then(() => {
        closeAddCompanyModal();
        editingCompanyId = null;

        if (isNewCompany) {
            showSuccess("New Company Created Successfully");
            setTimeout(() => {
                fetchCompanies();
            }, 100); 
        } else {
            fetchCompanies();
        }
      })
      .catch(error => {
        console.error("Failed to save company:", error);
        alert("Failed to save company. Please check the console for details.");
      });
    }

    // Edit Company Functions (uses editCompanyModal inputs)
    function editCompany(companyId) {
      editingCompanyId = companyId;
      fetch(`${API_BASE}/companies`, { credentials: 'include' })
        .then(res => res.json())
        .then(companies => {
          const company = companies.find(c => c.id === companyId);
          if (!company) return alert("Company not found");

          // Populate the fields of the dedicated Edit Company Modal
          document.getElementById("editCompanyName").value = company.name;
          document.getElementById("editCompanyLogo").value = company.logo;
          document.getElementById("editCompanyAddress1").value = company.address1;
          document.getElementById("editCompanyAddress2").value = company.address2;
          document.getElementById("editCompanyCity").value = company.city;
          document.getElementById("editCompanyState").value = company.state;
          document.getElementById("editCompanyZip").value = company.zip;
          document.getElementById("editCompanyCountry").value = company.country;
          document.getElementById("editCompanyTerms").value = company.terms;

          // Open the dedicated Edit Company Modal
          document.getElementById("editCompanyModal").style.display = "flex";
        });
    }

    // This function handles the submission from the editCompanyModal
    function submitEditCompany() {
      const payload = {
        id: editingCompanyId,
        name: document.getElementById("editCompanyName").value,
        logo: document.getElementById("editCompanyLogo").value,
        address1: document.getElementById("editCompanyAddress1").value,
        address2: document.getElementById("editCompanyAddress2").value,
        city: document.getElementById("editCompanyCity").value,
        state: document.getElementById("editCompanyState").value,
        zip: document.getElementById("editCompanyZip").value,
        country: document.getElementById("editCompanyCountry").value,
        terms: document.getElementById("editCompanyTerms").value
      };

      fetch(`${API_BASE}/edit-company`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      })
      .then(res => {
        if (!res.ok) throw new Error("Failed to update company");
        
        document.getElementById("editCompanyModal").style.display = "none";
        showSuccess("Company Updated Successfully");
        fetchCompanies(payload.id);
      })
      .catch(() => alert("Failed to update company"));
    }

    function deleteCompany(companyId) {
      if (!confirm("Are you sure you want to delete this company?")) return;

      fetch(`${API_BASE}/delete-company`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: companyId })
      })
        .then(res => {
          if (!res.ok) throw new Error("Failed to delete company");
          showSuccess("Company Deleted Successfully");
          fetchCompanies();
        })
        .catch(() => alert("Failed to delete company"));
    }

    // User Functions
    function openAddUserModalForCompany(companyId) {
      currentCompanyId = companyId;
      document.getElementById("addUserModal").style.display = "flex";
    }

    function submitAddUser() {
      const payload = {
        companyId: currentCompanyId,
        email: document.getElementById("newUserEmail").value,
        firstName: document.getElementById("newUserFirstName").value,
        lastName: document.getElementById("newUserLastName").value,
        phone: document.getElementById("newUserPhone").value,
        role: document.getElementById("newUserRole").value,
        password: document.getElementById("newUserPassword").value
      };

      fetch(`${API_BASE}/add-user`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      })
        .then(res => {
          if (!res.ok) throw new Error("Failed to add user");
          closeModal("addUserModal");
          showSuccess("User Added Successfully"); // Added success message
          fetchCompanies(expandedCompanyId); 
        })
        .catch(() => alert("Failed to add user"));
    }

    // Helper to safely parse user data from JSON
    function openEditUserModal(user) {
      currentUserId = user.id;
      document.getElementById("editUserEmail").value = user.email;
      document.getElementById("editUserFirstName").value = user.first_name;
      document.getElementById("editUserLastName").value = user.last_name;
      document.getElementById("editUserPhone").value = user.phone;
      document.getElementById("editUserRole").value = user.role;
      document.getElementById("editUserPassword").value = "";
      document.getElementById("editUserModal").style.display = "flex";
    }

    function submitEditUser() {
      const payload = {
        id: currentUserId,
        email: document.getElementById("editUserEmail").value,
        firstName: document.getElementById("editUserFirstName").value,
        lastName: document.getElementById("editUserLastName").value,
        phone: document.getElementById("editUserPhone").value,
        role: document.getElementById("editUserRole").value,
        password: document.getElementById("editUserPassword").value
      };

      fetch(`${API_BASE}/edit-user`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      })

      .then(res => {
        if (!res.ok) throw new Error("Failed to update user");
        document.getElementById("editUserModal").style.display = "none";
        showSuccess("User Updated Successfully");
        fetchCompanies(expandedCompanyId);
      })
      .catch(() => alert("Failed to update user"));
    }

    function deleteUser() {
      if (!confirm("Are you sure you want to delete this user?")) return;
      fetch(`${API_BASE}/delete-user`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: currentUserId })
      })
      .then(res => {
        if (!res.ok) throw new Error("Failed to delete user");
        document.getElementById("editUserModal").style.display = "none";
        showSuccess("User Deleted Successfully");
        fetchCompanies();
      })
      .catch(() => alert("Failed to delete user"));
    }

    // Shipping Address Functions (Integrated with Backend API)

    function openShippingAddressModal(addressId = null) {
        // Ensure currentCompanyId is set, although it should be if the modal is opened from a company listing
        if (!currentCompanyId) {
            alert("Please select a company first.");
            return;
        }

        editingShippingAddressId = addressId;
        document.getElementById("shippingAddressModalTitle").innerText = addressId ? "Edit Shipping Address" : "Add Shipping Address";
        
        // Reset fields
        document.getElementById("shipToName").value = "";
        document.getElementById("shipToAddress1").value = "";
        document.getElementById("shipToAddress2").value = "";
        document.getElementById("shipToCity").value = "";
        document.getElementById("shipToState").value = "";
        document.getElementById("shipToZip").value = "";
        document.getElementById("shipToCountry").value = "";
        document.getElementById("shipToIsDefault").checked = false; // Reset checkbox

        if (addressId !== null) {
            // Find the address in the current loaded list
            const address = currentShippingAddresses.find(addr => addr.id === addressId);
            if (address) {
                document.getElementById("shipToName").value = address.name || '';
                document.getElementById("shipToAddress1").value = address.address1 || '';
                document.getElementById("shipToAddress2").value = address.address2 || '';
                document.getElementById("shipToCity").value = address.city || '';
                document.getElementById("shipToState").value = address.state || '';
                document.getElementById("shipToZip").value = address.zip || '';
                document.getElementById("shipToCountry").value = address.country || '';
                document.getElementById("shipToIsDefault").checked = address.is_default || false; // Set checkbox based on data
            }
        }
        document.getElementById("shippingAddressModal").style.display = "flex";
    }

    function submitShippingAddress() {
        if (!currentCompanyId) {
            alert("Error: No company selected for shipping address.");
            return;
        }

        const addressData = {
            name: document.getElementById("shipToName").value.trim(),
            address1: document.getElementById("shipToAddress1").value.trim(),
            address2: document.getElementById("shipToAddress2").value.trim(),
            city: document.getElementById("shipToCity").value.trim(),
            state: document.getElementById("shipToState").value.trim(),
            zip: document.getElementById("shipToZip").value.trim(),
            country: document.getElementById("shipToCountry").value.trim(),
            companyId: currentCompanyId,
            isDefault: document.getElementById("shipToIsDefault").checked // Include checkbox state
        };

        // MODIFIED: Made country an optional field in client-side validation
        if (!addressData.address1 || !addressData.city || !addressData.state || !addressData.zip) {
            alert("Please fill in all required address fields (Address 1, City, State, Zip).");
            return;
        }

        let url = `${API_BASE}/api/shipto`;
        let method = 'POST';
        let successMessage = "Shipping Address Added Successfully";

        if (editingShippingAddressId) {
            method = 'PUT';
            url = `${API_BASE}/api/shipto/${editingShippingAddressId}`;
            successMessage = "Shipping Address Updated Successfully";
        }

        fetch(url, {
            method: method,
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(addressData)
        })
        .then(async response => {
            if (!response.ok) {
                // Read the response body to get potential error details from the backend
                const errorText = await response.text();
                let errorData = { error: "Unknown error" };
                try {
                    errorData = JSON.parse(errorText);
                } catch (e) {
                    console.error("Non-JSON error response from server:", errorText);
                }
                
                console.error(`Failed to save shipping address. Status: ${response.status}`, errorData);
                
                if (response.status === 403) {
                    throw new Error("Authorization failed. Please log in as admin.");
                } else if (response.status === 400) {
                    throw new Error("Bad Request: " + (errorData.error || "Missing fields."));
                } else {
                    throw new Error(errorData.error || 'Failed to save shipping address');
                }
            }
            return response.json();
        })
        .then(() => {
            document.getElementById("shippingAddressModal").style.display = "none";
            showSuccess(successMessage);
            // Refresh the company details view to show the updated addresses
            toggleCompanyDetails(currentCompanyId, true); 
        })
        .catch(error => {
            console.error("Error submitting shipping address:", error);
            // Alert the user with the specific error message
            alert(`Failed to save shipping address: ${error.message}`);
        });
    }

    function deleteSelectedShippingAddress() {
        // Use dynamic ID for dropdown
        const select = document.getElementById(`shipToAddressDropdown-${currentCompanyId}`);
        const addressIdToDelete = select.value;

        if (!addressIdToDelete) {
            alert("Please select an address to delete.");
            return;
        }

        if (!confirm("Are you sure you want to delete this shipping address?")) {
            return;
        }

        fetch(`${API_BASE}/api/shipto/${addressIdToDelete}`, {
            method: 'DELETE',
            credentials: 'include',
        })
        .then(async response => {
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: "Unknown error" }));
                throw new Error(errorData.error || 'Failed to delete shipping address');
            }
            return response.json();
        })
        .then(() => {
            showSuccess("Shipping Address Deleted Successfully");
            // Refresh the company details view
            toggleCompanyDetails(currentCompanyId, true);
        })
        .catch(error => {
            console.error("Error deleting shipping address:", error);
            alert(`Failed to delete shipping address: ${error.message}`);
        });
    }

    function editSelectedShippingAddress() {
        // Use dynamic ID for dropdown
        const select = document.getElementById(`shipToAddressDropdown-${currentCompanyId}`);
        const addressIdToEdit = parseInt(select.value);
        if (addressIdToEdit) {
            openShippingAddressModal(addressIdToEdit);
        } else {
            alert("Please select an address to edit.");
        }
    }

    // Fetches addresses from the backend and updates the dropdown
    function fetchShippingAddresses(companyId) {
        return fetch(`${API_BASE}/api/shipto/${companyId}`, { credentials: 'include' })
            .then(response => {
                if (!response.ok) throw new Error('Failed to fetch shipping addresses');
                return response.json();
            })
            .then(addresses => {
                // Store fetched addresses locally for quick access during edits
                currentShippingAddresses = addresses; 
                // Removed direct call to updateShippingDropdown here
                return addresses; 
            })
            .catch(error => {
                console.error("Error fetching shipping addresses:", error);
                // Clear dropdown if fetch fails (this will be handled by toggleCompanyDetails now)
                return [];
            });
    }

    // New function to display address details
    function displaySelectedAddressDetails(companyId, address) {
        const detailsDiv = document.getElementById(`selectedAddressDetails-${companyId}`);
        if (!detailsDiv) {
            console.error("Address details display div not found for company:", companyId);
            return;
        }

        if (!address) {
            detailsDiv.innerHTML = '<div>No address selected.</div>';
            return;
        }

        const locationName = address.name && address.name.trim() !== '' ? address.name.trim() : 'Unnamed Location';
        let addressLines = [];
        addressLines.push(`${locationName}`); // Removed bold tag
        addressLines.push(address.address1 || '');
        if (address.address2 && address.address2.trim() !== '') {
            addressLines.push(address.address2.trim());
        }

        // Construct the city, state, zip line carefully
        let cityStateZip = `${address.city || ''}`;
        if (address.state && address.state.trim() !== '') {
            cityStateZip += `, ${address.state.trim()}`;
        }
        if (address.zip && address.zip.trim() !== '') {
            cityStateZip += ` ${address.zip.trim()}`; // No comma before zip
        }
        addressLines.push(cityStateZip.trim()); // Trim to remove any leading/trailing spaces if parts are empty

        // Only add country if it exists as a separate line
        if (address.country && address.country.trim() !== '') {
            addressLines.push(address.country.trim());
        }

        // Filter out empty lines and join with <br>
        detailsDiv.innerHTML = addressLines.filter(line => line.trim() !== '').join('<br>');
    }

    // New function for dropdown onchange event
    function handleAddressSelectionChange(companyId, selectedAddressId) {
        // Find the selected address from the globally stored currentShippingAddresses
        const selectedAddress = currentShippingAddresses.find(addr => addr.id == selectedAddressId); // Use == for loose comparison if IDs might be string/number
        displaySelectedAddressDetails(companyId, selectedAddress);
    }


    function updateShippingDropdown(companyId, addresses) {
        // The dropdown element's ID is now dynamic based on companyId
        const select = document.getElementById(`shipToAddressDropdown-${companyId}`);
        
        if (!select) {
            console.error("Dropdown element not found for company:", companyId);
            return;
        }

        // Clear existing options
        select.innerHTML = '<option value="">Select Address</option>';

        addresses.forEach(addr => {
            const option = document.createElement('option');
            option.value = addr.id;
            // Display only the name or the first line of the address in the dropdown
            const locationName = addr.name && addr.name.trim() !== '' ? addr.name.trim() : addr.address1;
            option.text = locationName; 
            select.appendChild(option);
        });

        // Initial display of the first address's details or "No address selected"
        if (addresses.length > 0) {
            // Find the default address, or use the first one if no default is found
            const defaultAddress = addresses.find(addr => addr.is_default) || addresses[0];
            select.value = defaultAddress.id;
            displaySelectedAddressDetails(companyId, defaultAddress);
        } else {
            // If no addresses, display "No address selected"
            displaySelectedAddressDetails(companyId, null); 
        }
    }

    // Company Display and Fetching
    function fetchCompanies(expandId = null) {
      return fetch(`${API_BASE}/companies`, { credentials: 'include' })
        .then(async response => {
            if (!response.ok) {
                // If the response is not OK, we check the status code
                console.error("Failed to fetch companies. Status:", response.status);
                // Redirect if Unauthorized (likely 401 or 403)
                if (response.status === 401 || response.status === 403) {
                    alert("Session expired or unauthorized. Please log in.");
                    window.location.href = "/admin.html";
                }
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
          // Sort companies alphabetically by name
          data.sort((a, b) => a.name.localeCompare(b.name));
          companies = data;
          const container = document.getElementById("companies");
          container.innerHTML = "";
          data.forEach(company => {
            const section = document.createElement("div");
            section.id = `company-${company.id}`;
            section.style = "background:white; margin-bottom:12px; padding:10px; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,0.1);";
            section.innerHTML = `
              <div style='cursor:pointer; display:flex; justify-content:space-between; align-items:center;' onclick="toggleCompanyDetails(${company.id})">
                <strong>${company.name}</strong>
                <span id="toggle-icon-${company.id}">+</span>
              </div>
              <div id="company-details-${company.id}" style="display:none; margin-top:10px;"></div>
            `;
            container.appendChild(section);
          });

          if (expandId) {
            // Use a short delay to ensure DOM rendering is complete before toggling
            setTimeout(() => {
              toggleCompanyDetails(expandId, true); // Force refresh of details
            }, 50);
          }
        })
        .catch(error => {
            console.error("Error loading companies:", error);
            // Check if the error is a TypeError indicating a network issue (e.g., CORS)
            if (error instanceof TypeError && error.message === 'Failed to fetch') {
                alert("Failed to connect to the backend server. This might be due to a network issue or a CORS policy block. Please ensure the backend is running and accessible from this origin.");
            } else if (!error.message.includes("log in")) {
                // Only show generic alert if we haven't already redirected for authorization
                alert("Failed to load companies. Please check console for details.");
            }
        });
    }

    // Pass a forceRefresh flag to ensure the details are re-rendered even if already open
    function toggleCompanyDetails(companyId, forceRefresh = false) {
      const details = document.getElementById(`company-details-${companyId}`);
      const icon = document.getElementById(`toggle-icon-${companyId}`);
      
      // Update the global currentCompanyId immediately when details are toggled or refreshed
      currentCompanyId = companyId; 

      // Close previously expanded company if different
      if (expandedCompanyId && expandedCompanyId !== companyId) {
        const previousDetails = document.getElementById(`company-details-${expandedCompanyId}`);
        const previousIcon = document.getElementById(`toggle-icon-${expandedCompanyId}`);
        if (previousDetails && previousIcon) {
          previousDetails.style.display = "none";
          previousIcon.innerText = "+";
        }
      }

      const isVisible = details.style.display === "block";

      // If already visible and we are not forcing a refresh, just toggle it closed
      if (isVisible && !forceRefresh) {
          details.style.display = "none";
          icon.innerText = "+";
          expandedCompanyId = null;
          return;
      }
      
      // If currently hidden or forcing refresh, expand and load details
      details.style.display = "block";
      icon.innerText = "-";
      expandedCompanyId = companyId;

      // Fetch users and company data
      Promise.all([
          fetch(`${API_BASE}/company-users/${companyId}`, { credentials: 'include' }).then(res => res.json()),
          fetchShippingAddresses(companyId) // Fetch shipping addresses
      ])
      .then(([users, addresses]) => {
          const company = companies.find(c => c.id === companyId);
          
          // Sort users alphabetically by last name
          users.sort((a, b) => {
              const lastNameA = a.last_name || '';
              const lastNameB = b.last_name || '';
              return lastNameA.localeCompare(lastNameB);
          });

          // Render the company details HTML with a new grid structure
          details.innerHTML = `
            <div style="display: grid; grid-template-columns: 1fr 1fr auto; gap: 20px; align-items: start; margin-bottom: 20px;">
              
              <!-- Column 1: Bill To, Buttons, Users -->
              <div>
                <div style="font-weight: normal; margin-bottom: 10px;">
                  <u><strong>Bill To Address:</strong></u>
                  <div>${company.name || ''}</div>
                  <div>${company.address1 || ''}</div>
                  <div>${company.address2 || ''}</div>
                  <div>${company.city || ''}, ${company.state || ''} ${company.zip || ''} ${company.country && company.country.trim() !== '' ? company.country.trim() : ''}</div>
                  <div>Terms: ${company.terms || ''}</div>
                </div>

                <div style="margin-top:10px; display:flex; gap:8px; margin-bottom: 20px;">
                  <button onclick="editCompany(${companyId})">Edit Company</button>
                  <button onclick="deleteCompany(${companyId})">Delete Company</button>
                  <button onclick="openAddUserModalForCompany(${companyId})">Add User</button>
                </div>

                <div>
                  <div><strong>Users:</strong><ul style="list-style: none; padding: 0;">
                    ${Array.isArray(users) ? users.map(u => {
                        const userJson = JSON.stringify(u).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
                        return `
                      <li style="margin-bottom: 6px;">
                        <button onclick='openEditUserModal(${userJson})' style="margin-right: 6px;">Edit</button>
                        ${u.first_name || ''} ${u.last_name || ''} (${u.email}) - ${u.role}
                      </li>`;
                    }).join('') : '<li>No users found.</li>'}
                  </ul></div>
                </div>
              </div>

              <!-- Column 2: Ship To -->
              <div>
                  <div style="font-weight: normal; width: 400px; margin-top: -20px; margin-left: -80px;">
                      <u><strong>Ship To Addresses:</strong></u>
                      <div style="margin-bottom: 8px;">
                          <select id="shipToAddressDropdown-${companyId}" style="width: 100%; padding: 6px;" onchange="handleAddressSelectionChange(${companyId}, this.value)">
                          </select>
                      </div>
                      <div id="selectedAddressDetails-${companyId}" style="margin-top: 5px; padding: 8px; border: 1px solid #ccc; border-radius: 4px; background-color: #f9f9f9; min-height: 80px;">
                          No address selected.
                      </div>
                      <div style="display: flex; gap: 8px; margin-bottom: 10px; margin-top: 10px;">
                          <button onclick="openShippingAddressModal(null)">Add</button>
                          <button onclick="editSelectedShippingAddress()">Edit</button>
                          <button onclick="deleteSelectedShippingAddress()">Delete</button>
                      </div>
                  </div>
              </div>

              <!-- Column 3: Company Logo -->
              <div style="display: flex; flex-direction: column; align-items: flex-end; width: 100%;">
                  ${company.logo ? `
                      <img src="${company.logo}" style="margin-top: 15px; margin-right: 75px; max-height: 80px; max-width: 150px;" />
                  ` : ''}
              </div>
            </div>
          `;

          // updateShippingDropdown call now happens AFTER details.innerHTML is set
          updateShippingDropdown(companyId, addresses);

      })
      .catch(error => {
          console.error("Error fetching company details or addresses:", error);
          details.innerHTML = "<div>Error loading company details.</div>";
          if (error instanceof TypeError && error.message === 'Failed to fetch') {
              alert("Failed to connect to the backend server for company details. This might be due to a network issue or a CORS policy block.");
          }
      });
    }

    window.onload = () => {
      document.getElementById("addCompanyModal").style.display = "none";
      document.getElementById("editCompanyModal").style.display = "none";
      document.getElementById("shippingAddressModal").style.display = "none";
      fetchCompanies();
    };

  </script>
</body>
</html>
