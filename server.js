<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <base href="/">
    <title>Admin Dashboard</title>
    <style>
        /* Keyframes for the success message animation remain as they cannot be inlined */
        @keyframes popIn {
            from { transform: translate(-50%, -50%) scale(0.8); opacity: 0; }
            to { transform: translate(-50%, -50%) scale(1); opacity: 1; }
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        /* Styles for the approval status dropdown to remove default appearance and custom arrow */
        .approval-status-select {
            -webkit-appearance: none; /* Remove default dropdown arrow */
            -moz-appearance: none;
            appearance: none;
            background-image: none; /* Remove custom arrow image */
        }
        /* Style for the selected company item in the list */
        .company-list-item.selected-company-item {
            background-color: #e0f2f7 !important; /* Light blue highlight */
            border-left: 5px solid #007bff; /* Blue border to indicate selection */
            font-weight: bold;
        }
        /* General style for company list items and hover effect */
        .company-list-item {
            padding: 10px;
            border-bottom: 1px solid #ccc;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background-color: white; /* Default background */
            transition: background-color 0.2s, border-left 0.2s; /* Smooth transition for highlight */
        }
        .company-list-item:hover {
            background-color: #ffe60f; /* Hover effect */
        }
        /* Specific style for pending company list items */
        .company-list-item.pending-item {
            background-color: #fff3cd; /* Light yellow for pending items */
        }
        .company-list-item.pending-item:hover {
            background-color: #ffe8a1; /* Slightly darker light yellow on hover */
        }
        /* Specific style for denied company list items */
        .company-list-item.denied-item {
            background-color: #f8d7da; /* Light red for denied items */
        }
        .company-list-item.denied-item:hover {
            background-color: #f5c6cb; /* Slightly darker light red on hover */
        }

        /* Loading Overlay Styles */
        #loadingOverlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            display: none; /* Hidden by default */
            justify-content: center;
            align-items: center;
            z-index: 9999;
        }

        .spinner {
            border: 8px solid #f3f3f3; /* Light grey */
            border-top: 8px solid #3498db; /* Blue */
            border-radius: 50%;
            width: 60px;
            height: 60px;
            animation: spin 2s linear infinite;
        }

        /* Print-specific styles for the order details modal */
        /* Print-specific styles — primary printing handled via printOrderDetails() new-window */
        @media print {
          body > *:not(#orderDetailsModal) { display: none !important; }
          #orderDetailsModal {
              position: static !important; display: block !important;
              background-color: transparent !important; overflow: visible !important;
              padding: 0 !important; margin: 0 !important;
              width: 100% !important; height: auto !important;
          }
          #orderDetailsWrapper {
              width: auto !important; max-width: 100% !important;
              box-shadow: none !important; border-radius: 0 !important;
              padding: 20px !important; margin: 0 !important;
              max-height: none !important; overflow: visible !important;
              display: block !important; background: #fff;
          }
          .no-print-modal { display: none !important; }
        }

        /* Styles for sortable table headers */
        .sortable-header {
            cursor: pointer;
            position: relative;
        }
        .sortable-header::after {
            content: '';
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            border: 5px solid transparent;
            opacity: 0.5;
        }
        .sortable-header.asc::after {
            border-bottom-color: #333;
            opacity: 1;
        }
        .sortable-header.desc::after {
            border-top-color: #333;
            opacity: 1;
        }
        
        /* Tab Styling */
        .tab-button {
            padding: 10px 20px;
            cursor: pointer;
            border: 1px solid transparent;
            border-bottom: none;
            background-color: #f1f1f1;
            font-weight: bold;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            transition: background-color 0.3s ease;
            margin-right: 5px;
            outline: none;
        }
        .tab-button.active {
            background-color: white;
            border-color: #ccc;
            border-bottom: 1px solid white;
            position: relative;
            top: 1px;
        }
        .tab-content {
            display: none;
            animation: fadeIn 0.5s;
        }
        .tab-content.active {
            display: block;
        }

        /* For order history table rows */
        .order-row-item:hover {
            background-color: #f0f8ff; /* AliceBlue for a light, pleasant hover */
            cursor: pointer;
        }
        
        /* For login history table rows */
        .login-history-row:hover {
            background-color: #f0f8ff; /* AliceBlue for a light, pleasant hover */
        }
        
        /* Styling for the Activity Feed - Updated Colors */
        .activity-item {
            padding: 12px;
            margin-bottom: 10px;
            border-left: 5px solid;
            border-radius: 4px;
            background-color: #f9f9f9;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            font-size: 14px;
        }
        /* New Orders: #007bff */
        .activity-item.order {
            border-left-color: #007bff;
        }
        /* Pending Approvals: #ffc107 */
        .activity-item.registration-pending {
            border-left-color: #ffc107; 
        }
        /* Approved Registration: #28a745 */
        .activity-item.registration-approved {
            border-left-color: #28a745; 
        }
        /* Denied Registration: #dc3545 */
        .activity-item.registration-denied {
            border-left-color: #dc3545; 
        }
        /* Logins: #a3a3a3 */
        .activity-item.login {
            border-left-color: #a3a3a3; 
        }
        .activity-item strong {
            font-weight: bold;
            color: #333;
        }
    </style>

</head>
<body style="font-family: Arial, sans-serif; margin: 0; padding: 70px 0 0 0; background-color: #f4f4f4; color: #333; overflow-y: auto;">

    <div id="loadingOverlay">
        <div class="spinner"></div>
    </div>

    <div id="adminLoginForm" style="max-width: 400px; margin: 100px auto 30px; padding: 25px; background: white; box-shadow: 0 0 10px rgba(0,0,0,0.1); border-radius: 8px; display: none;">
        <h3 style="text-align: center; color: #333;">Admin Login</h3>
        <div style="margin-bottom: 10px;">
            <label for="adminEmail">Email</label>
            <input type="email" id="adminEmail" style="width: 100%; padding: 10px; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px;">
        </div>
        <div style="margin-bottom: 10px;">
            <label for="adminPassword">Password</label>
            <input type="password" id="adminPassword" onkeydown="if(event.key === 'Enter') handleAdminLogin();" style="width: 100%; padding: 10px; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px;">
        </div>

        <div style="margin-bottom: 15px; display: flex; align-items: center;">
            <input type="checkbox" id="rememberMe" style="margin-right: 8px;">
            <label for="rememberMe">Remember Me</label>
        </div>
       <button id="adminLoginBtn" type="button" style="width: 100%; height: 60px; padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 18px; font-weight: bold; background: #007bff; color: white; transition: background-color 0.2s ease;">Login</button>
    </div>

    <div id="adminDashboardContent" style="display: none;">
            <div style="background: white; padding: 10px 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); position: fixed; top: 0; z-index: 1000; left: 0; right: 0;">
            <div style="display: flex; align-items: center; gap: 20px; flex-shrink: 0;">
                <img src="https://www.chicagostainless.com/graphics/cse_logo.png" alt="Company Logo" style="height: 50px;" />
                <button id="createCompanyButton" onclick="openAddCompanyModal()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #007bff; color: white; font-size: 16px; font-weight: bold;">Create New Company</button>

                <div id="reportsDropdownContainer" style="position: relative; display: inline-block;">
                    <button id="reportsButton" onclick="toggleReportsDropdown()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #17a2b8; color: white; font-size: 16px; font-weight: bold;">Reports</button>
                    <div id="reportsDropdownContent" style="display: none; position: absolute; background-color: white; min-width: 160px; box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2); z-index: 1001; border-radius: 5px;">
                        <a href="#" onclick="openLoginReportModal(); return false;" style="color: black; padding: 12px 16px; text-decoration: none; display: block; text-align: left;">Logins Report</a>
                        <a href="#" onclick="openOrdersReportModal(); return false;" style="color: black; padding: 12px 16px; text-decoration: none; display: block; text-align: left;">Orders Report</a>
                        <a href="#" onclick="openUsersReportModal(); return false;" style="color: black; padding: 12px 16px; text-decoration: none; display: block; text-align: left;">Users Report</a>
                        <a href="#" onclick="openAbandonedCartsReportModal(); return false;" style="color: black; padding: 12px 16px; text-decoration: none; display: block; text-align: left;">Abandoned Carts Report</a>
                    </div>
                </div>

            </div>
            <h1 style="flex: 1; min-width: 0; text-align: center; margin: 0; padding: 0 15px; font-size: 24px; color: #333; overflow: hidden; white-space: nowrap; text-overflow: ellipsis;">Admin Dashboard</h1>
            <div style="display: flex; align-items: center; flex-shrink: 0;">
                <div id="liveClock" style="text-align: right; margin-right: 18px; line-height: 1.3; font-family: 'Segoe UI', Arial, sans-serif;">
                    <div id="liveDate" style="font-size: 15px; color: #222; font-weight: 600; white-space: nowrap; letter-spacing: 0.5px;"></div>
                    <div id="liveTime" style="font-size: 15px; color: #222; font-weight: 600; white-space: nowrap; letter-spacing: 0.5px;"></div>
                    <div id="lastUpdated" style="font-size: 11px; color: #888; font-weight: normal; white-space: nowrap; margin-top: 2px;"></div>
                </div>
                <button onclick="openSettingsModal()" 
                        style="background: none; border: none; cursor: pointer; padding: 0; margin-right: 15px; display: flex; align-items: center; justify-content: center;">
                    <img src="https://www.chicagostainless.com/graphics/gear.png" alt="Settings Gear" style="height: 24px; vertical-align: middle;" 
                         onerror="this.onerror=null;this.src='https://placehold.co/24x24/cccccc/333333?text=Gear';" />
                </button>
                <button onclick="logout()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 0px; background-color: #dc3545; color: white; font-size: 16px; font-weight: bold;">Logout</button>
            </div>
        </div>
        
        <div id="messageContainer"></div>
        <div id="undoToastContainer" style="position: fixed; bottom: 20px; right: 20px; z-index: 3000; display: flex; flex-direction: column-reverse; gap: 10px;"></div>

        <div id="main-content" style="height: calc(100vh - 70px); overflow-y: hidden; display: flex; flex-direction: column;">

            <div id="dashboardSummaryPanel" style="display: flex; align-items: center; gap: 0; flex-wrap: wrap; margin: 20px 20px 0 20px; background: white; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); padding: 10px 4px; flex-shrink: 0;">
                <div style="padding: 4px 20px; white-space: nowrap;">
                    <span style="font-size: 12px; color: #666;">Pending</span>
                    <span id="summaryPendingApprovalCount" style="font-size: 17px; font-weight: bold; color: #333; margin-left: 6px;">–</span>
                </div>
                <div style="width: 1px; align-self: stretch; background: #e0e0e0;"></div>
                <div style="padding: 4px 20px; white-space: nowrap;">
                    <span style="font-size: 12px; color: #666;">Approved</span>
                    <span id="summaryApprovedCount" style="font-size: 17px; font-weight: bold; color: #28a745; margin-left: 6px;">–</span>
                </div>
                <div style="width: 1px; align-self: stretch; background: #e0e0e0;"></div>
                <div style="padding: 4px 20px; white-space: nowrap;">
                    <span style="font-size: 12px; color: #666;">Denied</span>
                    <span id="summaryDeniedCount" style="font-size: 17px; font-weight: bold; color: #dc3545; margin-left: 6px;">–</span>
                </div>
                <div style="width: 1px; align-self: stretch; background: #e0e0e0;"></div>
                <div onclick="openAbandonedCartsReportModal()" style="padding: 4px 20px; white-space: nowrap; cursor: pointer;">
                    <span style="font-size: 12px; color: #666;">Abandoned Carts</span>
                    <span id="summaryAbandonedCartsCount" style="font-size: 17px; font-weight: bold; color: #333; margin-left: 6px;">–</span>
                    <span id="summaryAbandonedCartsValue" style="font-size: 12px; color: #888; margin-left: 4px;"></span>
                </div>
                <div style="width: 1px; align-self: stretch; background: #e0e0e0;"></div>
                <div onclick="openOrdersReportModal()" style="padding: 4px 20px; white-space: nowrap; cursor: pointer;">
                    <span style="font-size: 12px; color: #666;">Orders (7 Days)</span>
                    <span id="summaryOrdersWeekCount" style="font-size: 17px; font-weight: bold; color: #333; margin-left: 6px;">–</span>
                    <span id="summaryOrdersWeekValue" style="font-size: 12px; color: #888; margin-left: 4px;"></span>
                </div>
            </div>

            <div style="display: flex; padding: 20px; gap: 20px; flex: 1; min-height: 0; overflow-y: auto; overflow-x: auto;">
                <!-- Column 1: Companies List (Flex 1) -->
                <div id="companiesColumn" style="flex: 0 0 420px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); position: relative;">
                    <h2>Companies</h2>
                    <div id="companiesList" style="height: calc(100% - 80px); overflow-y: auto; position: relative;">
                    </div>
                </div>

                <!-- Column 2: Company Details / Tabs (Flex 2) -->
                <div id="companyDetailsPanel" style="flex: 0 0 880px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); display: flex; flex-direction: column;">
                    <!-- START: Header with Company Name and Approval Dropdown -->
                    <div style="display: grid; grid-template-columns: 1fr auto; align-items: center; margin-bottom: 10px; width: 100%;">
                        <h2 id="companyDetailsPanelTitle" style="margin: 0; font-size: 24px; color: #333; justify-self: start;"></h2>
                        <div style="justify-self: end;">
                            <select id="approvalStatusDropdown" class="approval-status-select" onchange="updateCompanyApprovalStatus()"
                                    style="display:none; padding: 8px 12px; border-radius: 5px; border: 1px solid #ccc; font-size: 16px; font-weight: bold; cursor: pointer; text-align: center;">
                                <option value="Pending" style="background-color: #ffc107; color: #212529;" selected>Pending</option>
                                <option value="Approved" style="background-color: #28a745; color: white;">Approved</option>
                                <option value="Denied" style="background-color: #dc3545; color: white;">Denied</option>
                            </select>
                        </div>
                    </div>
                    <!-- END: Header -->

                    <!-- START: Tabs and Logo container -->
                    <div id="tabsAndLogoContainer" style="display: none; grid-template-columns: 1fr auto 1fr; align-items: flex-end; border-bottom: 1px solid #ccc; margin-bottom: 15px;">
                        <div id="companyTabs" style="display: flex; border-bottom: none; margin-bottom: -1px; justify-self: start;">
                            <button class="tab-button active" onclick="openTab(event, 'companyDetailsTab')">Company Details</button>
                            <button class="tab-button" onclick="openTab(event, 'orderHistoryTab')">Order History</button>
                            <!-- NEW: Login History Tab -->
                            <button class="tab-button" onclick="openTab(event, 'loginHistoryCompanyTab')">Login History</button>
                        </div>
                        <div style="justify-self: center;">
                             <img id="companyDetailLogo" src="" alt="Company Logo" style="max-height: 50px; max-width: 100px; display: none; margin-bottom: 5px;" />
                        </div>
                        <div></div> <!-- Empty div for right column balance -->
                    </div>
                    <!-- END: Tabs and Logo container -->
                     
                    <!-- START: Initial Message -->
                    <p id="initialDetailsMessage" style="display: block;">Select a company from the list to view details.</p>
                    <!-- END: Initial Message -->
                    
                    <!-- START: Tab Content Container -->
                    <div id="tabContentContainer" style="flex-grow: 1; overflow-y: auto; display: none;">
                        <!-- Tab 1: Company Details -->
                        <div id="companyDetailsTab" class="tab-content active" style="display: block;">
                            <div id="detailsContent" style="height: 100%; overflow-y: auto; flex-grow: 1; display: flex; flex-direction: column;">
                                <div id="dynamicCompanyContent" style="flex-grow: 1; display: flex; flex-direction: column;">
                                    <!-- Content injected by JS -->
                                </div>
                            </div>
                        </div>

                        <!-- Tab 2: Order History -->
                        <div id="orderHistoryTab" class="tab-content" style="display: none;">
                             <div id="orderHistorySearchContainer">
                                <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 15px; align-items: flex-end;">
                                    <div style="flex: 1; min-width: 150px;"><label for="adminOrderSearchPoNumber" style="font-size:12px;">PO Number</label><input type="text" id="adminOrderSearchPoNumber" placeholder="Search by PO..." style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;"></div>
                                    <div style="flex: 1; min-width: 150px;"><label for="adminOrderSearchShipToAddress" style="font-size:12px;">Ship To</label><select id="adminOrderSearchShipToAddress" style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;"><option value="">All Shipping Addresses</option></select></div>
                                    <div style="flex: 1; min-width: 120px;"><label for="adminOrderSearchStartDate" style="font-size:12px;">Start Date</label><input type="date" id="adminOrderSearchStartDate" style="width: 100%; padding: 7px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;"></div>
                                    <div style="flex: 1; min-width: 120px;"><label for="adminOrderSearchEndDate" style="font-size:12px;">End Date</label><input type="date" id="adminOrderSearchEndDate" style="width: 100%; padding: 7px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;"></div>
                                    <button type="button" onclick="searchCompanyOrders()" style="padding: 8px 15px; border: none; border-radius: 5px; cursor: pointer; background-color: #007bff; color: white; font-weight: bold;">Search</button>
                                    <button type="button" onclick="clearCompanyOrderSearch()" style="padding: 8px 15px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-weight: bold;">Clear</button>
                                </div>
                            </div>
                            <div style="max-height: 60vh; overflow-y: auto;">
                                <table id="adminOrderHistoryTable" style="width: 100%; border-collapse: collapse;">
                                    <thead>
                                        <tr>
                                            <th style="border: 1px solid #ccc; padding: 8px; text-align: left; background-color: #e0e0e0; font-weight: bold;">Date</th>
                                            <th style="border: 1px solid #ccc; padding: 8px; text-align: left; background-color: #e0e0e0; font-weight: bold;">PO#</th>
                                            <th style="border: 1px solid #ccc; padding: 8px; text-align: left; background-color: #e0e0e0; font-weight: bold;">Ordered By</th>
                                            <th style="border: 1px solid #ccc; padding: 8px; text-align: left; background-color: #e0e0e0; font-weight: bold;">Total</th>
                                        </tr>
                                    </thead>
                                    <tbody></tbody>
                                </table>
                                <p id="adminNoOrdersMessage" style="text-align: center; display: none; margin-top: 20px;">No orders found for this company.</p>
                            </div>
                        </div>

                        <!-- NEW: Tab 3: Login History for all company users -->
                        <div id="loginHistoryCompanyTab" class="tab-content" style="display: none;">
                            <div style="max-height: 70vh; overflow-y: auto;">
                                <table style="width: 100%; border-collapse: collapse;">
                                    <thead>
                                        <tr>
                                            <th style="border: 1px solid #ccc; padding: 8px; text-align: left; background-color: #e0e0e0; font-weight: bold;">Login Time (UTC)</th>
                                            <th style="border: 1px solid #ccc; padding: 8px; text-align: left; background-color: #e0e0e0; font-weight: bold;">User Email</th>
                                            <th style="border: 1px solid #ccc; padding: 8px; text-align: left; background-color: #e0e0e0; font-weight: bold;">IP Address</th>
                                        </tr>
                                    </thead>
                                    <tbody id="companyLoginHistoryTableBody">
                                        <!-- Login history rows will be injected here -->
                                    </tbody>
                                </table>
                                <p id="companyNoLoginHistoryMessage" style="text-align: center; display: none; margin-top: 20px;">No login history found for users in this company.</p>
                            </div>
                        </div>

                    </div>
                    <!-- END: Tab Content Container -->
                </div>

                <!-- Column 3: Activity Feed (Flex 1) -->
                <div style="flex: 0 0 420px; min-width: 0; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); display: flex; flex-direction: column;">
                    <h2 style="margin-top: 0; border-bottom: 2px solid #ccc; padding-bottom: 5px;">Recent Activity</h2>
                    <!-- Loading indicator lives OUTSIDE the feed container so it is never wiped by innerHTML -->
                    <div id="noActivityMessage" style="text-align: center; color: #6c757d; margin-top: 20px; display: block;">Loading activity...</div>
                    <div id="activityFeedContainer" style="flex-grow: 1; overflow-y: auto; height: calc(100% - 80px);">
                        <!-- Activity items will be injected here by renderActivityList() -->
                    </div>
                </div>

            </div>

<div id="loginHistoryModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1001; overflow-y: auto;">
                <div style="position: relative; background: white; padding: 20px 40px; margin: 10% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 600px;">
  
                    <span onclick="closeModal('loginHistoryModal')" style="position: absolute; top: 10px; right: 20px; font-size: 28px; font-weight: bold; cursor: pointer; color: black;">&times;</span>

                    <h2 id="loginHistoryModalTitle">Login History</h2>
                    <div id="loginHistoryContent" style="max-height: 400px; overflow-y: auto; margin-top: 15px;">
                        <table style="width: 100%; border-collapse: collapse;">
                            <thead>
                                <tr>
                                    <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Login Time (UTC)</th>
                                    <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">IP Address</th>
                                </tr>
                            </thead>
                            <tbody id="loginHistoryTableBody"></tbody>
                        </table>
                        <p id="noLoginHistoryMessage" style="display: none; text-align: center; margin-top: 20px;">No login history found for this user.</p>
                    </div>
                    <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
                        <button onclick="closeModal('loginHistoryModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Close</button>
                    </div>
                </div>
            </div>

        <div id="loginReportModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1001; overflow-y: auto;">
                <div style="position: relative; background: white; padding: 20px 40px; margin: 5% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 800px;">

                    <span onclick="closeModal('loginReportModal')" style="position: absolute; top: 10px; right: 20px; font-size: 28px; font-weight: bold; cursor: pointer; color: black;">&times;</span>

                    <h2>Login History Report</h2>
                    
                    <div style="display: flex; gap: 20px; align-items: center; margin-bottom: 12px;">
                        <div>
                            <label for="reportStartDate" style="display: block; margin-bottom: 5px;">Start Date:</label>
                            <input type="date" id="reportStartDate" style="padding: 8px; border-radius: 4px; border: 1px solid #ccc;">
                        </div>
                        <div>
                            <label for="reportEndDate" style="display: block; margin-bottom: 5px;">End Date:</label>
                            <input type="date" id="reportEndDate" style="padding: 8px; border-radius: 4px; border: 1px solid #ccc;">
                        </div>
                        <button onclick="generateLoginReport()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #007bff; color: white; font-size: 16px; font-weight: bold; align-self: flex-end;">Generate Report</button>
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 20px; flex-wrap: wrap;">
                        <span style="font-size: 13px; color: #666;">Quick range:</span>
                        <button onclick="applyLoginReportPreset(7)" style="padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background-color: #f8f9fa; font-size: 13px;">Last 7 days</button>
                        <button onclick="applyLoginReportPreset(30)" style="padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background-color: #f8f9fa; font-size: 13px;">Last 30 days</button>
                        <button onclick="applyLoginReportPresetThisMonth()" style="padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background-color: #f8f9fa; font-size: 13px;">This month</button>
                        <button onclick="applyLoginReportPresetAll()" style="padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background-color: #f8f9fa; font-size: 13px;">All time</button>
                    </div>
                    <div style="margin-bottom: 16px;">
                        <label for="loginReportFilter" style="display: block; margin-bottom: 5px;">Filter by Name / Email / Company:</label>
                        <input type="text" id="loginReportFilter" placeholder="Type to filter..." oninput="filterLoginReportDisplay()"
                            style="padding: 8px; border-radius: 4px; border: 1px solid #ccc; width: 360px; font-size: 14px;">
                    </div>
                    <div id="loginReportLoading" style="display: none; text-align: center; padding: 30px; color: #666;">Loading login history...</div>
                    <div id="loginReportResults" style="display: none;">
                        <p id="loginReportSummaryBar" style="margin: 0 0 12px 0; font-size: 14px; color: #333; font-weight: bold;"></p>
                        <button onclick="downloadLoginReportCSV()" style="margin-bottom: 15px; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #28a745; color: white; font-size: 16px; font-weight: bold;">Download as CSV</button>
                        <div style="max-height: 50vh; overflow-y: auto;">
                            <table style="width: 100%; border-collapse: collapse;">
                                <thead>
                                    <tr>
                                    <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Login Time (UTC)</th>
                                    <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Email</th>
                                    <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">First Name</th>
                                    <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Last Name</th>
                                    <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Company</th>
                                    </tr>
                                </thead>
                                <tbody id="loginReportTableBody"></tbody>
                            </table>
                        </div>
                        <p id="noLoginReportMessage" style="display: none; text-align: center; margin-top: 20px;">No login records found for the selected date range.</p>
                    </div>
                    <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
                        <button onclick="closeModal('loginReportModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Close</button>
                    </div>
                </div>
            </div>

        <div id="ordersReportModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1001; overflow-y: auto;">
                <div style="position: relative; background: white; padding: 20px 40px; margin: 5% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 1150px;">

                    <span onclick="closeModal('ordersReportModal')" style="position: absolute; top: 10px; right: 20px; font-size: 28px; font-weight: bold; cursor: pointer; color: black;">&times;</span>

                    <h2>Orders Report</h2>
                    <div style="display: flex; gap: 20px; align-items: center; margin-bottom: 12px;">
                        <div>
                            <label for="ordersReportStartDate" style="display: block; margin-bottom: 5px;">Start Date:</label>
                            <input type="date" id="ordersReportStartDate" style="padding: 8px; border-radius: 4px; border: 1px solid #ccc;">
                        </div>
                        <div>
                            <label for="ordersReportEndDate" style="display: block; margin-bottom: 5px;">End Date:</label>
                            <input type="date" id="ordersReportEndDate" style="padding: 8px; border-radius: 4px; border: 1px solid #ccc;">
                        </div>
                        <button onclick="generateOrdersReport()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #007bff; color: white; font-size: 16px; font-weight: bold; align-self: flex-end;">Generate Report</button>
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 20px; flex-wrap: wrap;">
                        <span style="font-size: 13px; color: #666;">Quick range:</span>
                        <button onclick="applyOrdersReportPreset(7)" style="padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background-color: #f8f9fa; font-size: 13px;">Last 7 days</button>
                        <button onclick="applyOrdersReportPreset(30)" style="padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background-color: #f8f9fa; font-size: 13px;">Last 30 days</button>
                        <button onclick="applyOrdersReportPresetThisMonth()" style="padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background-color: #f8f9fa; font-size: 13px;">This month</button>
                        <button onclick="applyOrdersReportPresetAll()" style="padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background-color: #f8f9fa; font-size: 13px;">All time</button>
                    </div>
                    <div id="ordersReportLoading" style="display: none; text-align: center; padding: 30px; color: #666;">Loading orders...</div>
                    <div style="margin-bottom: 16px;">
                        <label for="ordersReportFilter" style="display: block; margin-bottom: 5px;">Filter by Company / PO# / Ordered By:</label>
                        <input type="text" id="ordersReportFilter" placeholder="Type to filter..." oninput="filterOrdersReportDisplay()"
                            style="padding: 8px; border-radius: 4px; border: 1px solid #ccc; width: 360px; font-size: 14px;">
                    </div>
                    <div id="ordersReportResults" style="display: none;">
                        <p id="ordersReportSummaryBar" style="margin: 0 0 12px 0; font-size: 14px; color: #333; font-weight: bold;"></p>
                        <div style="max-height: 60vh; overflow-y: auto;">
                            <table style="width: 100%; border-collapse: collapse;">
                                <thead>
                                    <tr>
                                        <th class="sortable-header desc" onclick="sortOrdersReport('date')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Date</th>
                                        <th class="sortable-header" onclick="sortOrdersReport('companyName')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Company Name</th>
                                        <th class="sortable-header" onclick="sortOrdersReport('poNumber')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">PO#</th>
                                        <th class="sortable-header" onclick="sortOrdersReport('computedTotal')" style="border: 1px solid #ddd; padding: 8px 24px 8px 8px; background-color: #f2f2f2; text-align: right;">Total</th>
                                        <th class="sortable-header" onclick="sortOrdersReport('orderedByName')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Ordered By</th>
                                    </tr>
                                </thead>
                                <tbody id="ordersReportTableBody"></tbody>
                            </table>
                        </div>
                        <p id="noOrdersReportMessage" style="display: none; text-align: center; margin-top: 20px;">No orders found for the selected date range.</p>
                    </div>
                    <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
                        <button onclick="closeModal('ordersReportModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Close</button>
                    </div>
                </div>
            </div>

        <div id="orderDetailsModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); z-index: 1002; align-items: center; justify-content: center; padding: 40px 0; box-sizing: border-box;" onclick="clickOutsideCloseOrderDetails(event)">
                <div id="orderDetailsWrapper" style="position: relative; width: 860px; max-width: 96%; max-height: 90vh; background: #fff; padding: 30px 30px 24px; border-radius: 10px; overflow-y: auto; box-shadow: 0 8px 32px rgba(0,0,0,0.28);">
                    <!-- Toolbar -->
                    <div class="no-print-modal" style="position: absolute; top: 10px; right: 10px; display: flex; gap: 6px; z-index: 1001;">
                        <button onclick="printOrderDetails()" title="Print" style="background: none; border: none; cursor: pointer; padding: 4px;">
                            <img src="https://www.chicagostainless.com/graphics/print.png" alt="Print" style="width: 24px; height: 24px;">
                        </button>
                        <button onclick="closeOrderDetailsModal()" title="Close" style="background: none; border: none; cursor: pointer; padding: 4px;">
                            <img src="graphics/exit.png" alt="Close" style="width: 24px; height: 24px;">
                        </button>
                    </div>
                    <!-- Document content — populated by showOrderDetailsModal() -->
                    <div id="orderDocumentContent"></div>
                </div>
            </div>

        <div id="abandonedCartsReportModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1001; overflow-y: auto;">
                <div style="position: relative; background: white; padding: 20px 40px; margin: 5% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 1000px;">
                    <span onclick="closeModal('abandonedCartsReportModal')" style="position: absolute; top: 10px; right: 20px; font-size: 28px; font-weight: bold; cursor: pointer; color: black;">&times;</span>
                    <h2>Abandoned Carts Report</h2>
                    <div style="display: flex; gap: 20px; align-items: center; margin-bottom: 12px; flex-wrap: wrap;">
                        <div>
                            <label for="abandonedCartsStartDate" style="display: block; margin-bottom: 5px;">Start Date:</label>
                            <input type="date" id="abandonedCartsStartDate" style="padding: 8px; border-radius: 4px; border: 1px solid #ccc;">
                        </div>
                        <div>
                            <label for="abandonedCartsEndDate" style="display: block; margin-bottom: 5px;">End Date:</label>
                            <input type="date" id="abandonedCartsEndDate" style="padding: 8px; border-radius: 4px; border: 1px solid #ccc;">
                        </div>
                        <button onclick="generateAbandonedCartsReport()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #007bff; color: white; font-size: 16px; font-weight: bold; align-self: flex-end;">Generate Report</button>
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 20px; flex-wrap: wrap;">
                        <span style="font-size: 13px; color: #666;">Quick range:</span>
                        <button onclick="applyAbandonedCartsPreset(7)" style="padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background-color: #f8f9fa; font-size: 13px;">Last 7 days</button>
                        <button onclick="applyAbandonedCartsPreset(30)" style="padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background-color: #f8f9fa; font-size: 13px;">Last 30 days</button>
                        <button onclick="applyAbandonedCartsPresetThisMonth()" style="padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background-color: #f8f9fa; font-size: 13px;">This month</button>
                        <button onclick="applyAbandonedCartsPresetAll()" style="padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background-color: #f8f9fa; font-size: 13px;">All time</button>
                    </div>
                    <div style="margin-bottom: 16px;">
                        <label for="abandonedCartsFilter" style="display: block; margin-bottom: 5px;">Filter by Company / Customer / Email:</label>
                        <input type="text" id="abandonedCartsFilter" placeholder="Type to filter..." oninput="filterAbandonedCartsDisplay()"
                            style="padding: 8px; border-radius: 4px; border: 1px solid #ccc; width: 360px; font-size: 14px;">
                    </div>
                    <div id="abandonedCartsLoading" style="display: none; text-align: center; padding: 30px; color: #666;">Loading abandoned carts...</div>
                    <div id="abandonedCartsReportResults" style="display: none;">
                        <p id="abandonedCartsRangeLabel" style="margin: 0 0 4px 0; font-size: 14px; color: #555; font-style: italic;"></p>
                        <p id="abandonedCartsSummaryBar" style="margin: 0 0 12px 0; font-size: 14px; color: #333; font-weight: bold;"></p>
                        <button onclick="downloadAbandonedCartsCSV()" style="margin-bottom: 15px; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #28a745; color: white; font-size: 16px; font-weight: bold;">Download as CSV</button>
                        <div style="max-height: 60vh; overflow-y: auto;">
                            <table style="width: 100%; border-collapse: collapse;">
                                <thead>
                                    <tr>
                                        <th class="sortable-header desc" onclick="sortAbandonedCartsReport('date')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left; cursor: pointer;">Date</th>
                                        <th class="sortable-header" onclick="sortAbandonedCartsReport('companyName')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left; cursor: pointer;">Company</th>
                                        <th class="sortable-header" onclick="sortAbandonedCartsReport('userName')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left; cursor: pointer;">User</th>
                                        <th class="sortable-header" onclick="sortAbandonedCartsReport('email')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left; cursor: pointer;">Email</th>
                                        <th class="sortable-header" onclick="sortAbandonedCartsReport('itemCount')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left; cursor: pointer;">Items</th>
                                        <th class="sortable-header" onclick="sortAbandonedCartsReport('total')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left; cursor: pointer;">Total</th>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="abandonedCartsTableBody"></tbody>
                            </table>
                        </div>
                        <p id="noAbandonedCartsMessage" style="display: none; text-align: center; margin-top: 20px;">No abandoned carts found.</p>
                    </div>
                    <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
                        <button onclick="closeModal('abandonedCartsReportModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Close</button>
                    </div>
                </div>
            </div>

        <div id="abandonedCartDetailModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1002; overflow-y: auto;">
                <div style="position: relative; background: white; padding: 20px 40px; margin: 6% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 800px;">
                    <span onclick="closeModal('abandonedCartDetailModal')" style="position: absolute; top: 10px; right: 20px; font-size: 28px; font-weight: bold; cursor: pointer; color: black;">&times;</span>
                    <h2>Abandoned Cart Details</h2>
                    <div id="abandonedCartDetailMeta" style="margin-bottom: 16px; font-size: 14px; color: #444;"></div>
                    <div id="abandonedCartDetailBody">
                        <table style="width: 100%; border-collapse: collapse;">
                            <thead>
                                <tr>
                                    <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Product</th>
                                    <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Description</th>
                                    <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: right;">Qty</th>
                                    <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: right;">Price</th>
                                </tr>
                            </thead>
                            <tbody id="abandonedCartDetailTableBody"></tbody>
                        </table>
                        <p id="noAbandonedCartDetailMessage" style="display: none; text-align: center; margin-top: 20px;">No item details are available for this cart.</p>
                    </div>
                    <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px;">
                        <button id="abandonedCartDetailDeleteBtn" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #dc3545; color: white; font-size: 16px; font-weight: bold;">Delete Cart</button>
                        <button onclick="closeModal('abandonedCartDetailModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Close</button>
                    </div>
                </div>
            </div>

        <div id="usersReportModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1001; overflow-y: auto;">
                <div style="position: relative; background: white; padding: 20px 40px; margin: 5% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 1000px;">
                    <span onclick="closeModal('usersReportModal')" style="position: absolute; top: 10px; right: 20px; font-size: 28px; font-weight: bold; cursor: pointer; color: black;">&times;</span>
                    <h2>All Users Report</h2>
                    <div style="margin-bottom: 16px;">
                        <label for="usersReportFilter" style="display: block; margin-bottom: 5px;">Filter by Name / Email / Company:</label>
                        <input type="text" id="usersReportFilter" placeholder="Type to filter..." oninput="filterUsersReportDisplay()"
                            style="padding: 8px; border-radius: 4px; border: 1px solid #ccc; width: 360px; font-size: 14px;">
                    </div>
                    <div id="usersReportResults" style="display: none;">
                        <p id="usersReportSummaryBar" style="margin: 0 0 12px 0; font-size: 14px; color: #333; font-weight: bold;"></p>
                        <button onclick="downloadUsersReportCSV()" style="margin-bottom: 15px; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #28a745; color: white; font-size: 16px; font-weight: bold;">Download as CSV</button>
                        <div style="max-height: 60vh; overflow-y: auto;">
                            <table style="width: 100%; border-collapse: collapse;">
                                <thead>
                                    <tr>
                                        <th class="sortable-header asc" onclick="sortUsersReport('last_name')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">User Name (Last, First)</th>
                                        <th class="sortable-header" onclick="sortUsersReport('email')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Email</th>
                                        <th class="sortable-header" onclick="sortUsersReport('companyName')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Company Name</th>
                                        <th class="sortable-header" onclick="sortUsersReport('created_at')" style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2; text-align: left;">Date Created</th>
                                    </tr>
                                </thead>
                                <tbody id="usersReportTableBody"></tbody>
                            </table>
                        </div>
                        <p id="noUsersReportMessage" style="display: none; text-align: center; margin-top: 20px;">No users found.</p>
                    </div>
                    <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
                        <button onclick="closeModal('usersReportModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Close</button>
                    </div>
                </div>
            </div>

        <div id="addCompanyModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1000; overflow-y: auto;">
                <div style="background: white; padding: 25px 35px; margin: 3% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 700px; max-height: 93vh; overflow-y: auto; box-sizing: border-box;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px;">
                        <h2 style="margin: 0;">Add New Company</h2>
                        <button onclick="emailCompanyInfo('add')" title="Email company info" style="background: none; border: none; cursor: pointer; padding: 4px; color: #555; display: flex; align-items: center;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="2" y="4" width="20" height="16" rx="2"/>
                                <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
                            </svg>
                        </button>
                    </div>
                    <input type="hidden" id="companyId" />

                    <label for="companyName" style="display: block; margin-bottom: 5px; font-weight: bold;">Name:<span style="color: red;">*</span></label>
                    <input type="text" id="companyName" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />

                    <label for="companyAddress1" style="display: block; margin-bottom: 5px; font-weight: bold;">Address:</label>
                    <textarea id="companyAddress1" placeholder="Billing Address" rows="3" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box; resize: none;"></textarea>

                    <!-- City / State / Zip / Country -->
                    <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                        <div style="flex: 2;">
                            <label for="companyCity" style="display: block; margin-bottom: 5px; font-weight: bold;">City:</label>
                            <input id="companyCity" placeholder="City" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />
                        </div>
                        <div style="flex: 1;">
                            <label for="companyState" style="display: block; margin-bottom: 5px; font-weight: bold;">State:</label>
                            <input id="companyState" placeholder="State" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />
                        </div>
                        <div style="flex: 1;">
                            <label for="companyZip" style="display: block; margin-bottom: 5px; font-weight: bold;">Zip:</label>
                            <input id="companyZip" placeholder="Zip Code" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />
                        </div>
                        <div style="flex: 2;">
                            <label for="companyCountry" style="display: block; margin-bottom: 5px; font-weight: bold;">Country:</label>
                            <input id="companyCountry" placeholder="Country" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />
                        </div>
                    </div>

                    <label for="companyWebsite" style="display: block; margin-bottom: 5px; font-weight: bold;">Website:</label>
                    <input type="url" id="companyWebsite" placeholder="www.example.com or https://www.example.com" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />

                    <label for="companyApEmail" style="display: block; margin-bottom: 5px; font-weight: bold;">Accounts Payable Email:</label>
                    <input type="email" id="companyApEmail" placeholder="Accounts Payable Email" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />

                    <label for="companyLogo" style="display: block; margin-bottom: 5px; font-weight: bold;">Logo URL:</label>
                    <input type="text" id="companyLogo" placeholder="https://example.com/logo.png" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />

                    <label for="companyLogoCode" style="display: block; margin-bottom: 5px; font-weight: bold;">Configurator Logo:</label>
                    <select id="companyLogoCode" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;">
                        <option value="">-- Loading... --</option>
                    </select>

                    <label for="companyPhone" style="display: block; margin-bottom: 5px; font-weight: bold;">Phone Number:</label>
                    <input type="tel" id="companyPhone" placeholder="Phone Number" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />

                    <!-- Terms / Discount -->
                    <div style="display: flex; gap: 15px; margin-bottom: 20px;">
                        <div style="flex: 2;">
                            <label for="companyTerms" style="display: block; margin-bottom: 5px; font-weight: bold;">Terms:<span style="color: red;">*</span></label>
                            <select id="companyTerms" required style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;">
                                <option value="C.O.D.">C.O.D.</option>
                                <option value="Credit Card">Credit Card</option>
                                <option value="Net 15 Days">Net 15 Days</option>
                                <option value="Net 30 Days">Net 30 Days</option>
                                <option value="Net 45 Days">Net 45 Days</option>
                                <option value="Net 60 Days">Net 60 Days</option>
                                <option value="Pre Paid">Pre Paid</option>
                            </select>
                        </div>
                        <div style="flex: 1;">
                            <label for="companyDiscount" style="display: block; margin-bottom: 5px; font-weight: bold;">Discount (%):<span style="color: red;">*</span></label>
                            <input type="number" id="companyDiscount" required placeholder="0-100" min="0" max="100" value="0" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />
                        </div>
                    </div>

                    <div style="display: flex; justify-content: space-between;">
                        <button onclick="submitCompanyModal()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #007bff; color: white; font-size: 16px; font-weight: bold;">Save Company</button>
                        <button onclick="closeModal('addCompanyModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Cancel</button>
                    </div>
                </div>
            </div>

        <div id="editCompanyModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1000; overflow-y: auto;">
                <div style="background: white; padding: 25px 35px; margin: 3% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 700px; max-height: 93vh; overflow-y: auto; box-sizing: border-box;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px;">
                        <h2 style="margin: 0;">Edit Company</h2>
                        <button onclick="emailCompanyInfo('edit')" title="Email company info" style="background: none; border: none; cursor: pointer; padding: 4px; color: #555; display: flex; align-items: center;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="2" y="4" width="20" height="16" rx="2"/>
                                <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
                            </svg>
                        </button>
                    </div>
                    <input type="hidden" id="editCompanyId" />

                    <label for="editCompanyName" style="display: block; margin-bottom: 5px; font-weight: bold;">Name:<span style="color: red;">*</span></label>
                    <input type="text" id="editCompanyName" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />

                    <label for="editCompanyAddress1" style="display: block; margin-bottom: 5px; font-weight: bold;">Address:</label>
                    <textarea id="editCompanyAddress1" placeholder="Billing Address" rows="3" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box; resize: none;"></textarea>

                    <!-- City / State / Zip / Country -->
                    <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                        <div style="flex: 2;">
                            <label for="editCompanyCity" style="display: block; margin-bottom: 5px; font-weight: bold;">City:</label>
                            <input id="editCompanyCity" placeholder="City" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />
                        </div>
                        <div style="flex: 1;">
                            <label for="editCompanyState" style="display: block; margin-bottom: 5px; font-weight: bold;">State:</label>
                            <input id="editCompanyState" placeholder="State" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />
                        </div>
                        <div style="flex: 1;">
                            <label for="editCompanyZip" style="display: block; margin-bottom: 5px; font-weight: bold;">Zip:</label>
                            <input id="editCompanyZip" placeholder="Zip Code" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />
                        </div>
                        <div style="flex: 2;">
                            <label for="editCompanyCountry" style="display: block; margin-bottom: 5px; font-weight: bold;">Country:</label>
                            <input id="editCompanyCountry" placeholder="Country" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />
                        </div>
                    </div>

                    <label for="editCompanyWebsite" style="display: block; margin-bottom: 5px; font-weight: bold;">Website:</label>
                    <input type="url" id="editCompanyWebsite" placeholder="www.example.com or https://www.example.com" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />

                    <label for="editCompanyApEmail" style="display: block; margin-bottom: 5px; font-weight: bold;">Accounts Payable Email:</label>
                    <input type="email" id="editCompanyApEmail" placeholder="Accounts Payable Email" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />

                    <label for="editCompanyLogo" style="display: block; margin-bottom: 5px; font-weight: bold;">Logo URL:</label>
                    <input type="text" id="editCompanyLogo" placeholder="https://example.com/logo.png" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />

                    <label for="editCompanyLogoCode" style="display: block; margin-bottom: 5px; font-weight: bold;">Configurator Logo:</label>
                    <select id="editCompanyLogoCode" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;">
                        <option value="">-- Loading... --</option>
                    </select>

                    <label for="editCompanyPhone" style="display: block; margin-bottom: 5px; font-weight: bold;">Phone Number:</label>
                    <input type="tel" id="editCompanyPhone" placeholder="Phone Number" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />

                    <!-- Terms / Discount -->
                    <div style="display: flex; gap: 15px; margin-bottom: 20px;">
                        <div style="flex: 2;">
                            <label for="editCompanyTerms" style="display: block; margin-bottom: 5px; font-weight: bold;">Terms:<span style="color: red;">*</span></label>
                            <select id="editCompanyTerms" required style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;">
                                <option value="C.O.D.">C.O.D.</option>
                                <option value="Credit Card">Credit Card</option>
                                <option value="Net 15 Days">Net 15 Days</option>
                                <option value="Net 30 Days">Net 30 Days</option>
                                <option value="Net 45 Days">Net 45 Days</option>
                                <option value="Net 60 Days">Net 60 Days</option>
                                <option value="Pre Paid">Pre Paid</option>
                            </select>
                        </div>
                        <div style="flex: 1;">
                            <label for="editCompanyDiscount" style="display: block; margin-bottom: 5px; font-weight: bold;">Discount (%):<span style="color: red;">*</span></label>
                            <input type="number" id="editCompanyDiscount" required placeholder="0-100" min="0" max="100" value="0" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; box-sizing: border-box;" />
                        </div>
                    </div>

                    <div style="display: flex; justify-content: space-between;">
                        <button onclick="submitEditCompany()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #007bff; color: white; font-size: 16px; font-weight: bold;">Update Company</button>
                        <button onclick="closeModal('editCompanyModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Cancel</button>
                    </div>
                </div>
            </div>

        <div id="addUserModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1000; overflow-y: auto;">
                <div style="background: white; padding: 20px 40px; margin: 5% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 500px;">
                    <h2>Add User</h2>
                    <input type="hidden" id="addUserId" />
                    <input type="hidden" id="addUserCompanyId" />
                    
                    <label for="addUserEmail" style="display: block; margin-bottom: 5px; font-weight: bold;">Email:</label>
                    <input type="email" id="addUserEmail" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc;" />

                    <label for="addUserFirstName" style="display: block; margin-bottom: 5px; font-weight: bold;">First Name:</label>
                    <input type="text" id="addUserFirstName" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc;" />

                    <label for="addUserLastName" style="display: block; margin-bottom: 5px; font-weight: bold;">Last Name:</label>
                    <input type="text" id="addUserLastName" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc;" />

                    <label for="addUserPhone" style="display: block; margin-bottom: 5px; font-weight: bold;">Phone:</label>
                    <input type="text" id="addUserPhone" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 44; border: 1px solid #ccc;" />

                    <label for="addUserRole" style="display: block; margin-bottom: 5px; font-weight: bold;">Role:</label>
                    <select id="addUserRole" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc;">
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                    </select>

                    <label for="addUserPassword" style="display: block; margin-bottom: 5px; font-weight: bold;">Password:</label>
                    <input type="password" id="addUserPassword" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc;" />

                    <div style="display: flex; justify-content: space-between;">
                        <button onclick="submitAddUser()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #007bff; color: white; font-size: 16px; font-weight: bold;">Add User</button>
                        <button onclick="closeModal('addUserModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Cancel</button>
                    </div>
                </div>
            </div>

        <div id="editUserModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1000; overflow-y: auto;">
                <div style="background: white; padding: 20px 40px; margin: 5% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 500px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px;">
                        <h2 style="margin: 0;">Edit User</h2>
                        <button onclick="emailUserInfo()" title="Email user info" style="background: none; border: none; cursor: pointer; padding: 4px; color: #555; display: flex; align-items: center;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="2" y="4" width="20" height="16" rx="2"/>
                                <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
                            </svg>
                        </button>
                    </div>
                    <input type="hidden" id="editUserId" />
                    
                    <label for="editUserEmail" style="display: block; margin-bottom: 5px; font-weight: bold;">Email:</label>
                    <input type="email" id="editUserEmail" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc;" />

                    <label for="editUserFirstName" style="display: block; margin-bottom: 5px; font-weight: bold;">First Name:</label>
                    <input type="text" id="editUserFirstName" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc;" />

                    <label for="editUserLastName" style="display: block; margin-bottom: 5px; font-weight: bold;">Last Name:</label>
                    <input type="text" id="editUserLastName" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc;" />

                    <label for="editUserPhone" style="display: block; margin-bottom: 5px; font-weight: bold;">Phone:</label>
                    <input type="text" id="editUserPhone" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 44; border: 1px solid #ccc;" />

                    <label for="editUserDateCreated" style="display: block; margin-bottom: 5px; font-weight: bold;">Date Created:</label>
                    <input type="text" id="editUserDateCreated" readonly style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; background-color: #e9ecef; cursor: not-allowed;" />

                    <label for="editUserRole" style="display: block; margin-bottom: 5px; font-weight: bold;">Role:</label>
                    <select id="editUserRole" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc;">
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                    </select>

                    <label for="editUserCompany" style="display: block; margin-bottom: 5px; font-weight: bold;">Company:</label>
                    <select id="editUserCompany" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc;"></select>

                    <label for="editUserPassword" style="display: block; margin-bottom: 5px; font-weight: bold;">Password (leave blank if unchanged):</label>
                    <input type="password" id="editUserPassword" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc;" />

                    <div style="display: flex; justify-content: space-between;">
                        <button onclick="submitEditUser()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #007bff; color: white; font-size: 16px; font-weight: bold;">Update User</button>
                        <button onclick="closeModal('editUserModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Cancel</button>
                    </div>
                </div>
            </div>

        <div id="shippingAddressModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1000; overflow-y: auto;">
                <div style="background: white; padding: 20px 40px; margin: 5% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 500px; position: relative;">
                    <h2 id="shippingAddressModalTitle" style="border-bottom: 2px solid #eee; padding-bottom: 10px; margin-top: 0;"></h2>
                    <div id="shippingAddressDateCreated" style="position: absolute; top: 25px; right: 40px; font-size: 14px; color: #555;"></div>

                    <input type="hidden" id="shipToAddressId" />
                    <input type="hidden" id="shipToCompanyId" />

                    <div id="copyBillingAddressRow" style="display: none; margin-bottom: 15px;">
                        <button type="button" onclick="copyBillingAddressToShipping()" style="padding: 8px 14px; border: 1px solid #007bff; border-radius: 5px; cursor: pointer; background-color: #eaf3ff; color: #007bff; font-size: 14px; font-weight: bold;">Copy from Billing Address</button>
                    </div>

                    <label for="addressRef" style="display: block; margin-bottom: 5px; font-weight: bold;">Address Reference:</label>
                    <input id="addressRef" placeholder="Address Reference" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />

                    <label for="shipToCompanyName" style="display: block; margin-bottom: 5px; font-weight: bold;">Company Name:</label>
                    <input id="shipToCompanyName" placeholder="Company Name" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />

                    <label for="shipToAddress1" style="display: block; margin-bottom: 5px; font-weight: bold;">Address:</label>
                    <textarea id="shipToAddress1" placeholder="Address" rows="4" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;"></textarea>
                    
                    <label for="shipToCity" style="display: block; margin-bottom: 5px; font-weight: bold;">City:</label>
                    <input id="shipToCity" placeholder="City" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />

                    <label for="shipToState" style="display: block; margin-bottom: 5px; font-weight: bold;">State:</label>
                    <input id="shipToState" placeholder="State" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />

                    <label for="shipToZip" style="display: block; margin-bottom: 5px; font-weight: bold;">Zip Code:</label>
                    <input id="shipToZip" placeholder="Zip Code" required style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />

                    <label for="shipToCountry" style="display: block; margin-bottom: 5px; font-weight: bold;">Country:</label>
                    <input id="shipToCountry" placeholder="Country" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />

                    <label for="shipToCarrierAccount" style="display: block; margin-bottom: 5px; font-weight: bold;">Carrier Account #:</label>
                    <input id="shipToCarrierAccount" placeholder="Optional" style="width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />

                    <div style="display: flex; justify-content: space-between;">
                        <button onclick="submitShippingAddress()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #007bff; color: white; font-size: 16px; font-weight: bold;">Save Address</button>
                        <button onclick="closeModal('shippingAddressModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Cancel</button>
                    </div>
                </div>
            </div>

        <div id="settingsModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1000; overflow-y: auto;">
                <div style="background: white; padding: 20px 40px; margin: 5% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 500px;">
                    <h2>Admin Settings</h2>

                    <label for="poEmail" style="display: block; margin-bottom: 5px; font-weight: bold;">Email Purchase Orders to:</label>
                    <input type="text" id="poEmail" placeholder="email1@example.com; email2@example.com" style="width: 100%; padding: 8px; margin-bottom: 5px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
                    <div style="font-size: 12px; color: #666; margin-bottom: 15px;">Separate multiple addresses with a semicolon or comma.</div>

                    <label for="poSms" style="display: block; margin-bottom: 5px; font-weight: bold;">Text Purchase Order alerts to:</label>
                    <input type="text" id="poSms" placeholder="+13125551234; +17085559876" style="width: 100%; padding: 8px; margin-bottom: 5px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
                    <div style="font-size: 12px; color: #666; margin-bottom: 15px;">Enter phone numbers in E.164 format (e.g. +13125551234). Separate multiple numbers with a semicolon or comma. Leave blank to disable.</div>

                    <label for="registrationEmail" style="display: block; margin-bottom: 5px; font-weight: bold;">Email Registration Notices to:</label>
                    <input type="text" id="registrationEmail" placeholder="email1@example.com; email2@example.com" style="width: 100%; padding: 8px; margin-bottom: 5px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
                    <div style="font-size: 12px; color: #666; margin-bottom: 15px;">Separate multiple addresses with a semicolon or comma.</div>

                    <label for="registrationSms" style="display: block; margin-bottom: 5px; font-weight: bold;">Text Registration alerts to:</label>
                    <input type="text" id="registrationSms" placeholder="+13125551234; +17085559876" style="width: 100%; padding: 8px; margin-bottom: 5px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
                    <div style="font-size: 12px; color: #666; margin-bottom: 15px;">Enter phone numbers in E.164 format (e.g. +13125551234). Separate multiple numbers with a semicolon or comma. Leave blank to disable.</div>

                    <label for="loginEmail" style="display: block; margin-bottom: 5px; font-weight: bold;">Email Login Notices to:</label>
                    <input type="text" id="loginEmail" placeholder="email1@example.com; email2@example.com" style="width: 100%; padding: 8px; margin-bottom: 5px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
                    <div style="font-size: 12px; color: #666; margin-bottom: 15px;">Separate multiple addresses with a semicolon or comma. Leave blank to disable.</div>

                    <label for="loginSms" style="display: block; margin-bottom: 5px; font-weight: bold;">Text Login alerts to:</label>
                    <input type="text" id="loginSms" placeholder="+13125551234; +17085559876" style="width: 100%; padding: 8px; margin-bottom: 5px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px;" />
                    <div style="font-size: 12px; color: #666; margin-bottom: 15px;">Enter phone numbers in E.164 format (e.g. +13125551234). Separate multiple numbers with a semicolon or comma. Leave blank to disable.</div>

                    <div style="background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 12px 14px; margin-bottom: 18px;">
                        <label style="display: flex; align-items: flex-start; gap: 10px; cursor: pointer; margin: 0;">
                            <input type="checkbox" id="smsConsentCheckbox" style="margin-top: 3px; flex-shrink: 0; width: 16px; height: 16px; cursor: pointer;">
                            <span style="font-size: 12px; color: #444; line-height: 1.5;">
                                By entering phone numbers above, I confirm that the recipients are authorized Chicago Stainless Equipment administrators who have consented to receive transactional SMS notifications for new purchase orders, customer registrations, and user logins. Message frequency varies. Message and data rates may apply. Recipients may reply STOP at any time to opt out. View our
                                <a href="https://www.chicagostainless.com/graphics/documents/privacy-policy.pdf" target="_blank" style="color: #007bff;">Privacy Policy</a> and
                                <a href="https://www.chicagostainless.com/graphics/documents/terms.pdf" target="_blank" style="color: #007bff;">Terms &amp; Conditions</a>.
                            </span>
                        </label>
                    </div>

                    <div style="display: flex; justify-content: space-between;">
                        <button onclick="saveSettings()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #007bff; color: white; font-size: 16px; font-weight: bold;">Save Settings</button>
                        <button onclick="closeModal('settingsModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Cancel</button>
                    </div>
                </div>
            </div>

        <div id="sendApprovalEmailConfirmationModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1000; overflow-y: auto;">
                <div style="background: white; padding: 20px 40px; margin: 10% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 400px; text-align: center;">
                    <h2 style="margin-top: 0;">Send Approval Email?</h2>
                    <p>Do you want to send an approval email to the user for this company?</p>
                    <div style="display: flex; justify-content: space-around; margin-top: 20px;">
                        <button onclick="confirmSendApprovalEmail()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #28a745; color: white; font-size: 16px; font-weight: bold;">Send Email</button>
                        <button onclick="cancelSendApprovalEmail()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Don't Send</button>
                    </div>
                </div>
            </div>

        <div id="deleteUserConfirmationModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1000; overflow-y: auto;">
                <div style="background: white; padding: 20px 40px; margin: 10% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 400px; text-align: center;">
                    <h2 style="margin-top: 0;">Delete User</h2>
                    <p>Are you sure you want to delete this user?</p>
                    <div style="display: flex; justify-content: space-around; margin-top: 20px;">
                        <button onclick="confirmUserDeletion()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #dc3545; color: white; font-size: 16px; font-weight: bold;">Yes, Delete</button>
                        <button onclick="closeModal('deleteUserConfirmationModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Cancel</button>
                    </div>
                </div>
            </div>

        <div id="deleteCompanyConfirmationModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1000; overflow-y: auto;">
                <div style="background: white; padding: 20px 40px; margin: 10% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 400px; text-align: center;">
                    <h2 style="margin-top: 0;">Delete Company</h2>
                    <p>Are you sure you want to delete this company and all associated data (users and shipping addresses)?</p>
                    <div style="display: flex; justify-content: space-around; margin-top: 20px;">
                        <button onclick="confirmCompanyDeletion()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #dc3545; color: white; font-size: 16px; font-weight: bold;">Yes, Delete</button>
                        <button onclick="closeModal('deleteCompanyConfirmationModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Cancel</button>
                    </div>
                </div>
            </div>

        <div id="deleteAddressConfirmationModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); z-index: 1000; overflow-y: auto;">
                <div style="background: white; padding: 20px 40px; margin: 10% auto; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 400px; text-align: center;">
                    <h2 style="margin-top: 0;">Delete Address</h2>
                    <p>Are you sure you want to delete this shipping address?</p>
                    <div style="display: flex; justify-content: space-around; margin-top: 20px;">
                        <button onclick="confirmAddressDeletion()" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #dc3545; color: white; font-size: 16px; font-weight: bold;">Yes, Delete</button>
                        <button onclick="closeModal('deleteAddressConfirmationModal')" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; background-color: #6c757d; color: white; font-size: 16px; font-weight: bold;">Cancel</button>
                    </div>
                </div>
            </div>

        </div> 
    </div>
    <script>
        const API_URL = "https://checkout-backend-jvyx.onrender.com"; // Backend URL
        let companies = []; // Store companies data globally
        let currentAddresses = []; // Store shipping addresses for the currently viewed company
        let currentCompanyId = null; // Store the ID of the currently selected company
        let currentCompanyIdForEmail = null;
        let userIdToDelete = null;
        let companyIdToDelete = null;
        let addressIdToDelete = null;

        // ----------------- Helper Functions -----------------

        function toggleReportsDropdown() {
            const dropdown = document.getElementById('reportsDropdownContent');
            dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
        }

        window.addEventListener('click', function(event) {
            const dropdownContainer = document.getElementById('reportsDropdownContainer');
            if (dropdownContainer && !dropdownContainer.contains(event.target)) {
                const dropdownContent = document.getElementById('reportsDropdownContent');
                if (dropdownContent) {
                    dropdownContent.style.display = 'none';
                }
            }
        });

        function showLoadingOverlay() {
            return; // disabled
            const loadingOverlay = document.getElementById('loadingOverlay');
            if (loadingOverlay) {
                loadingOverlay.style.display = 'flex';
            }
        }

        function hideLoadingOverlay() {
            const loadingOverlay = document.getElementById('loadingOverlay');
            if (loadingOverlay) {
                loadingOverlay.style.display = 'none';
            }
        }

        function showMessage(type, message) {
            const container = document.getElementById("messageContainer");
            const alertDiv = document.createElement("div");
            alertDiv.textContent = message;
            
            alertDiv.style.position = 'fixed';
            alertDiv.style.top = '50%';
            alertDiv.style.left = '50%';
            alertDiv.style.transform = 'translate(-50%, -50%)';
            alertDiv.style.zIndex = '1001';
            alertDiv.style.padding = '15px 30px';
            alertDiv.style.borderRadius = '8px';
            alertDiv.style.fontWeight = 'bold';
            alertDiv.style.boxShadow = '0 6px 12px rgba(0,0,0,0.2)';
            alertDiv.style.textAlign = 'center';
            alertDiv.style.fontSize = '20px';
            alertDiv.style.animation = 'popIn 0.3s ease-out';

            if (type === 'success') {
                alertDiv.style.backgroundColor = '#28a745';
                alertDiv.style.color = 'white';
            } else if (type === 'error') {
                alertDiv.style.backgroundColor = '#dc3545';
                alertDiv.style.color = 'white';
            } else if (type === 'info') {
                alertDiv.style.backgroundColor = '#17a2b8';
                alertDiv.style.color = 'white';
            }

            container.appendChild(alertDiv);

            setTimeout(() => {
                alertDiv.remove();
            }, 2500);
        }

        // ── Undoable delete pattern ──────────────────────────────
        // Instead of deleting immediately, we wait UNDO_DELAY_MS before
        // actually calling the destructive API. A toast lets the admin
        // cancel the pending delete during that window.
        const UNDO_DELAY_MS = 7000;
        const pendingUndoableActions = {};

        function scheduleUndoableDelete(key, label, commitFn, onUndo) {
            // If there's already a pending delete for this key, commit it immediately first.
            if (pendingUndoableActions[key]) {
                clearTimeout(pendingUndoableActions[key].timeoutId);
                removeUndoToast(pendingUndoableActions[key].toastId);
                delete pendingUndoableActions[key];
            }

            const toastId = `undoToast-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

            const timeoutId = setTimeout(async () => {
                delete pendingUndoableActions[key];
                removeUndoToast(toastId);
                try {
                    await commitFn();
                } catch (error) {
                    console.error(`Error completing deferred delete for ${label}:`, error);
                    showMessage('error', `Failed to delete ${label}.`);
                }
            }, UNDO_DELAY_MS);

            pendingUndoableActions[key] = { timeoutId, toastId };

            showUndoToast(toastId, label, () => {
                clearTimeout(timeoutId);
                delete pendingUndoableActions[key];
                removeUndoToast(toastId);
                if (onUndo) onUndo();
                showMessage('info', `Cancelled — ${label} was not deleted.`);
            });
        }

        function showUndoToast(toastId, label, onUndo) {
            const container = document.getElementById('undoToastContainer');
            if (!container) return;

            const toast = document.createElement('div');
            toast.id = toastId;
            toast.style.cssText = 'background:#323232;color:white;padding:12px 16px;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,0.3);display:flex;align-items:center;justify-content:space-between;gap:16px;font-size:14px;min-width:280px;max-width:400px;animation:popIn 0.2s ease-out;';

            const text = document.createElement('span');
            text.textContent = `Deleting ${label}...`;

            const undoBtn = document.createElement('button');
            undoBtn.textContent = 'Undo';
            undoBtn.style.cssText = 'padding:6px 14px;border:none;border-radius:4px;cursor:pointer;background-color:#007bff;color:white;font-weight:bold;font-size:13px;flex-shrink:0;';
            undoBtn.onclick = onUndo;

            toast.appendChild(text);
            toast.appendChild(undoBtn);
            container.appendChild(toast);
        }

        function removeUndoToast(toastId) {
            const toast = document.getElementById(toastId);
            if (toast) toast.remove();
        }

        async function apiFetch(endpoint, options = {}) {
            showLoadingOverlay();
            const url = `${API_URL}${endpoint}`;
            // If the caller sets skipAuthRedirect: true, a 401/403 will throw but
            // won't automatically show the login form (used by the login route itself
            // to avoid a visible flicker when the session write races the response).
            const skipAuthRedirect = options.skipAuthRedirect || false;
            try {
                const response = await fetch(url, {
                    ...options,
                    headers: {
                        'Content-Type': 'application/json',
                        ...options.headers,
                    },
                    credentials: 'include',
                });

                hideLoadingOverlay();

                if (response.status === 403 || response.status === 401) {
                    if (!skipAuthRedirect) showLoginForm();
                    const error = new Error("Authentication required or session expired.");
                    error.status = response.status;
                    throw error;
                }

                if (!response.ok) {
                    let errorData = {};
                    let errorMessage = `HTTP Error: ${response.status} ${response.statusText}`;
                    try {
                        const contentType = response.headers.get('content-type');
                        if (contentType && contentType.includes('application/json')) {
                            errorData = await response.json();
                            errorMessage = errorData.error || errorData.message || errorMessage;
                        } else {
                            const rawErrorText = await response.text();
                            errorMessage = `Server responded with non-JSON content (Status: ${response.status}). Raw response: ${rawErrorText.substring(0, 200)}...`;
                        }
                    } catch (e) {
                        console.warn('API Error: Could not parse error response or read body.', e);
                        errorMessage = `Failed to process server error response. Status: ${response.status}. Error: ${e.message}`;
                    }
                    const error = new Error(errorMessage);
                    error.response = response;
                    error.data = errorData;
                    throw error;
                }
                return response;
            } catch (error) {
                hideLoadingOverlay();
                console.error("API Fetch Error:", error);
                throw error;
            }
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = "none";
        }

        function openTab(evt, tabName) {
            let i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
                tabcontent[i].classList.remove("active");
            }
            tablinks = document.getElementsByClassName("tab-button");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].classList.remove("active");
            }
            document.getElementById(tabName).style.display = "block";
            document.getElementById(tabName).classList.add("active");
            evt.currentTarget.classList.add("active");

            // Custom function call for the new tab
            if (tabName === 'loginHistoryCompanyTab') {
                fetchCompanyLoginHistory(currentCompanyId);
            }
        }


        // ----------------- Authentication -----------------

        function showLoginForm() {
            document.getElementById('adminLoginForm').style.display = 'block';
            document.getElementById('adminDashboardContent').style.display = 'none';
            document.body.style.overflowY = 'auto';
        }

        function showDashboardContent() {
            document.getElementById('adminLoginForm').style.display = 'none';
            document.getElementById('adminDashboardContent').style.display = 'block';
            document.body.style.overflowY = 'hidden';
            
        }

        let isAdminLoggingIn = false; // Guards against double-submit (double-click, Enter+click, etc.)

        async function handleAdminLogin() {
            if (isAdminLoggingIn) return; // A login request is already in flight — ignore this trigger

            const email = document.getElementById('adminEmail').value.trim();
            const password = document.getElementById('adminPassword').value.trim();
            const rememberMe = document.getElementById('rememberMe').checked;

            if (rememberMe) {
                localStorage.setItem('adminRememberedEmail', email);
            } else {
                localStorage.removeItem('adminRememberedEmail');
            }

            if (!email || !password) {
                showMessage('error', 'Please enter both email and password.');
                return;
            }

            isAdminLoggingIn = true;
            const adminLoginBtnEl = document.getElementById('adminLoginBtn');
            if (adminLoginBtnEl) adminLoginBtnEl.disabled = true;

            try {
                const response = await apiFetch('/admin-login', {
                    method: 'POST',
                    body: JSON.stringify({ email, password }),
                    skipAuthRedirect: true
                });

                if (response.ok) {
                    showMessage('success', 'Admin login successful!');
                    showDashboardContent();
                    await fetchCompaniesAndInitializeDashboard();
                    await fetchActivityFeed();
                    refreshDashboardSummary();
                } else {
                    const errorData = await response.json();
                    showMessage('error', errorData.error || 'Admin login failed. Invalid credentials.');
                }
            } catch (error) {
                console.error("Admin login error:", error);
                if (error.status !== 401 && error.status !== 403) {
                    showMessage('error', error.message || 'An error occurred during login. Please try again.');
                }
            } finally {
                isAdminLoggingIn = false;
                if (adminLoginBtnEl) adminLoginBtnEl.disabled = false;
            }
        }

        function checkRememberMe() {
            const rememberedEmail = localStorage.getItem('adminRememberedEmail');
            if (rememberedEmail) {
                document.getElementById('adminEmail').value = rememberedEmail;
                document.getElementById('rememberMe').checked = true;
            }
        }

        async function logout() {
            try {
                const response = await apiFetch("/logout", { method: "POST" });
                const result = await response.json();
                if (response.ok) {
                    showMessage('info', 'Logged out successfully.');
                    showLoginForm();
                } else {
                    showMessage('error', result.error || "Logout failed");
                }
            } catch (error) {
                console.error("Logout error:", error);
                showMessage('error', "An error occurred during logout.");
            }
        }

        async function checkAdminLoginStatus() {
            try {
                const response = await apiFetch("/admin/check-auth");
                if (response.ok) {
                    showDashboardContent();
                    await fetchCompaniesAndInitializeDashboard();
                    
                    // Call activity feed function on successful login/auth check
                    await fetchActivityFeed(); 
                    refreshDashboardSummary();
                } else {
                    showLoginForm();
                }
            } catch (error) {
                console.log("Admin not authenticated or session expired:", error.message);
                showLoginForm();
            }
        }

        // ----------------- Company Management (Fetch & Display) -----------------

        async function fetchCompanies() {
            try {
                const response = await apiFetch("/companies");
                companies = await response.json();
                console.log("Companies fetched successfully:", companies);
                displayCompanies(companies);
            }
            catch (error) {
                console.error("Error fetching companies in fetchCompanies():", error);

                if (error.status !== 401 && error.status !== 403) {
                    showMessage('error', error.message || "Failed to fetch companies.");
                }
                companies = [];
            }
        }

        function displayCompanies(companies) {
            const list = document.getElementById("companiesList");
            list.innerHTML = '';

            const pendingCompanies = companies.filter(c => !c.approved && !c.denied);
            const approvedCompanies = companies.filter(c => c.approved);
            const deniedCompanies = companies.filter(c => c.denied);

            pendingCompanies.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
            approvedCompanies.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
            deniedCompanies.sort((a, b) => (a.name || '').localeCompare(b.name || ''));

            let companyListHtml = '';

            if (pendingCompanies.length > 0) {
                companyListHtml += `
                    <div style="padding: 8px 10px; font-weight: bold; color: #212529; background-color: #ffc107; border-bottom: 1px solid #ccc; margin-top: 10px;">
                        Pending
                    </div>
                `;
                pendingCompanies.forEach(company => {
                    let regDate = '';
                    if (company.created_at) {
                        try {
                            const date = new Date(company.created_at);
                            if (!isNaN(date.getTime())) {
                                const month = String(date.getMonth() + 1).padStart(2, '0');
                                const day = String(date.getDate()).padStart(2, '0');
                                const year = date.getFullYear();
                                regDate = `${month}/${day}/${year}`;
                            } else {
                                console.error('Invalid date in company list:', company.created_at);
                            }
                        } catch (error) {
                            console.error('Error parsing date in company list:', company.created_at, error);
                        }
                    }
                    companyListHtml += `
                        <div data-company-id="${company.id}" class="company-list-item pending-item" onclick="event.preventDefault(); event.stopPropagation(); toggleCompanyDetails(${company.id}); return false;">
                            <div>
                                <div style="font-weight: bold;">${escapeHTML(company.name)}</div>
                                <div style="font-size: 11px; color: #856404; margin-top: 2px;">Requested: ${regDate}</div>
                            </div>
                        </div>
                    `;
                });
            }

            if (approvedCompanies.length > 0) {
                companyListHtml += `
                    <div style="padding: 8px 10px; font-weight: bold; color: white; background-color: #28a745; border-bottom: 1px solid #ccc; margin-top: 10px;">
                        Approved
                    </div>
                `;
                let currentLetter = '';
                approvedCompanies.forEach(company => {
                    const firstLetter = (company.name || ' ').charAt(0).toUpperCase();
                    if (firstLetter !== currentLetter) {
                        companyListHtml += `
                            <div style="padding: 8px 10px; font-weight: bold; color: #333; background-color: #e0e0e0; border-bottom: 1px solid #ccc; margin-top: 5px;">
                                ${firstLetter}
                            </div>
                        `;
                        currentLetter = firstLetter;
                    }
                    companyListHtml += `
                        <div data-company-id="${company.id}" class="company-list-item" onclick="event.preventDefault(); event.stopPropagation(); toggleCompanyDetails(${company.id}); return false;">
                            <span>${escapeHTML(company.name)}</span>
                        </div>
                    `;
                });
            }

            if (deniedCompanies.length > 0) {
                companyListHtml += `
                    <div style="padding: 8px 10px; font-weight: bold; color: white; background-color: #dc3545; border-bottom: 1px solid #ccc; margin-top: 10px;">
                        Denied
                    </div>
                `;
                deniedCompanies.forEach(company => {
                    companyListHtml += `
                        <div data-company-id="${company.id}" class="company-list-item denied-item" onclick="event.preventDefault(); event.stopPropagation(); toggleCompanyDetails(${company.id}); return false;">
                            <span>${escapeHTML(company.name)}</span>
                        </div>
                    `;

                });
            }

            list.innerHTML = companyListHtml;

            if (currentCompanyId) {
                const selectedElement = document.querySelector(`div[data-company-id="${currentCompanyId}"]`);
                if (selectedElement) {
                    selectedElement.classList.add('selected-company-item');
                }
            }
        }

        async function toggleCompanyDetails(companyId, selectedAddressIdToRestore = null) {
            console.log("Calling toggleCompanyDetails for ID:", companyId);
            const numericCompanyId = parseInt(companyId, 10);
            const details = document.getElementById("detailsContent");
            const companyDetailLogo = document.getElementById("companyDetailLogo");
            const initialMessage = document.getElementById("initialDetailsMessage");
            const approvalStatusDropdown = document.getElementById("approvalStatusDropdown");

            document.querySelectorAll(`.company-list-item`).forEach(item => {
                item.classList.remove('selected-company-item');
            });

            const selectedElement = document.querySelector(`div[data-company-id="${numericCompanyId}"]`);
            if (selectedElement) {
                selectedElement.classList.add('selected-company-item');
            }

            if (initialMessage) {
                initialMessage.style.display = 'none';
            }
            document.getElementById('tabsAndLogoContainer').style.display = 'grid';
            document.getElementById('tabContentContainer').style.display = 'block';

            // Reset tab selection to 'Company Details'
            const defaultTab = document.querySelector('#companyTabs .tab-button.active');
            if (defaultTab) {
                // Manually click the Company Details button to ensure state is correct
                document.querySelector('#companyTabs button:nth-child(1)').click();
            }


            const company = companies.find(c => c.id === numericCompanyId);
            document.getElementById('companyDetailsPanelTitle').textContent = company ? company.name : 'Company Not Found';
            console.log("Company found in global array for details display:", company);
            currentCompanyId = numericCompanyId;
            
            if (!company) {
                console.error("Company not found in current 'companies' array for ID:", numericCompanyId);
                document.getElementById("dynamicCompanyContent").innerHTML = "<div>Company not found.</div>";
                if (companyDetailLogo) {
                    companyDetailLogo.src = '';
                    companyDetailLogo.style.display = 'none';
                }
                if (approvalStatusDropdown) {
                    approvalStatusDropdown.style.display = 'none';
                }
                
                // Explicit call to refresh activity feed even on company failure
                await fetchActivityFeed(); 
                return;
            }

            if (companyDetailLogo) {
                if (company.logo) {
                    companyDetailLogo.src = company.logo;
                    companyDetailLogo.style.display = 'block';
                } else {
                    companyDetailLogo.src = '';
                    companyDetailLogo.style.display = 'none';
                }
            }

            if (approvalStatusDropdown) {
                if (company.approved) {
                    approvalStatusDropdown.value = 'Approved';
                } else if (company.denied) {
                    approvalStatusDropdown.value = 'Denied';
                } else {
                    approvalStatusDropdown.value = 'Pending';
                }
                updateApprovalStatusDropdownStyle(approvalStatusDropdown.value);
                approvalStatusDropdown.style.display = 'block';
            }

            try {
                const [usersResponse, addressesResponse] = await Promise.all([
                    apiFetch(`/company-users/${numericCompanyId}`),
                    apiFetch(`/api/shipto/${numericCompanyId}`)
                ]);

                if (!usersResponse.ok || !addressesResponse.ok) {
                    throw new Error("Failed to fetch company details.");
                }

                const users = await usersResponse.json();
                currentAddresses = await addressesResponse.json();

                users.sort((a, b) => {
                    const lastNameA = a.last_name || '';
                    const lastNameB = b.last_name || '';
                    const firstNameA = a.first_name || '';
                    const firstNameB = a.first_name || '';

                    if (lastNameA < lastNameB) return -1;
                    if (lastNameA > lastNameB) return 1;
                    if (firstNameA < firstNameB) return -1;
                    if (firstNameA > firstNameB) return 1;
                    return 0;
                });

                const dynamicContentDiv = document.getElementById("dynamicCompanyContent");
                if (!dynamicContentDiv) {
                    console.error("Error: dynamicCompanyContent div not found.");
                    return;
                }

                let formattedDate = 'N/A';
                let dateLabel = 'Date Created';
                if (company.created_at) {
                    try {
                        const date = new Date(company.created_at);
                        
                        // Check if date is valid
                        if (!isNaN(date.getTime())) {
                            const month = String(date.getMonth() + 1).padStart(2, '0');
                            const day = String(date.getDate()).padStart(2, '0');
                            const year = date.getFullYear();
                            let hours = date.getHours();
                            const minutes = String(date.getMinutes()).padStart(2, '0');
                            const ampm = hours >= 12 ? 'PM' : 'AM';
                            hours = hours % 12;
                            hours = hours ? hours : 12; // Convert 0 to 12
                            const hoursStr = String(hours).padStart(2, '0');
                            formattedDate = `${month}/${day}/${year} at ${hoursStr}:${minutes} ${ampm}`;
                        } else {
                            console.error('Invalid date:', company.created_at);
                            formattedDate = 'Invalid Date';
                        }
                    } catch (error) {
                        console.error('Error parsing date:', company.created_at, error);
                        formattedDate = 'Error parsing date';
                    }
                    
                    // Show "Registration Requested" for pending companies
                    if (!company.approved && !company.denied) {
                        dateLabel = 'Registration Requested';
                    }
                }

                // Store current company & users for the email button
                window._currentCompanyEmailData = { company, users };

                dynamicContentDiv.innerHTML = `
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 0;">
                        <div style="padding: 15px; border: 1px solid #ddd; border-radius: 6px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #0056b3; padding-bottom: 5px;">
                                <h3 style="margin: 0; color: #0056b3; font-size: 1.17em;">Company Information</h3>
                                <div style="display: flex; align-items: center; gap: 12px;">
                                    <button onclick="emailCompanyFullInfo()" title="Email company info" style="background: none; border: none; cursor: pointer; padding: 2px; color: #555; display: flex; align-items: center;">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <rect x="2" y="4" width="20" height="16" rx="2"/>
                                            <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
                                        </svg>
                                    </button>
                                    <span style="font-size: 13px; color: ${!company.approved && !company.denied ? '#856404' : '#555'}; font-weight: ${!company.approved && !company.denied ? 'bold' : 'normal'};">${dateLabel}: ${formattedDate}</span>
                                </div>
                            </div>
                            <p style="margin: 8px 0 4px 0;"><strong>Name:</strong> ${escapeHTML(company.name)}</p>
                            <p style="margin: 4px 0;"><strong>Company ID:</strong> ${company.id}</p>
                            <p style="margin: 4px 0;"><strong>Phone:</strong> ${escapeHTML(company.phone || '')}</p>
                            <p style="margin: 4px 0;"><strong>AP Email:</strong> ${escapeHTML(company.ap_email || 'N/A')}</p>
                            <p style="margin: 4px 0;"><strong>Website:</strong> ${company.website && /^https?:\/\//i.test(company.website.trim()) ? '<a href="' + escapeHTML(company.website) + '" target="_blank" rel="noopener noreferrer">' + escapeHTML(company.website) + '</a>' : (company.website ? escapeHTML(company.website) : 'N/A')}</p>
                            <p style="margin: 4px 0;"><strong>Terms:</strong> ${escapeHTML(company.terms)}</p>
                            <p style="margin: 4px 0;"><strong>Discount:</strong> ${company.discount !== undefined && company.discount !== null ? company.discount + '%' : '0%'}</p>
                            <div style="display: flex; gap: 10px; margin-top: 12px;">
                                <button onclick="editCompany(${company.id})" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #ffc107; color: #212529; font-size: 16px; font-weight: bold;">Edit Company</button>
                                ${company.id !== 1 ? `
                                    <button onclick="deleteCompany(${company.id})" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #dc3545; color: white; font-size: 16px; font-weight: bold;">Delete Company</button>
                                ` : ''}
                            </div>
                        </div>

                        <div style="padding: 15px; border: 1px solid #ddd; border-radius: 6px;">
                            <h3 style="margin-top: 0; border-bottom: 2px solid #0056b3; padding-bottom: 5px; color: #0056b3;">Bill To</h3>
                            <div>${escapeHTML(company.name || '')}</div>
                            <div>${escapeHTML(company.address1 || '').replace(/\n/g, '<br>')}</div>
                            <div>${escapeHTML(company.city || '')}${company.state ? ', ' + escapeHTML(company.state) : ''} ${escapeHTML(company.zip || '')} ${company.country && company.country.trim() !== '' ? escapeHTML(company.country.trim()) : ''}</div>
                        </div>

                        <div style="padding: 15px; border: 1px solid #ddd; border-radius: 6px; background-color: white;">
                            <h3 style="margin-top: 0; border-bottom: 2px solid #0056b3; padding-bottom: 5px; color: #0056b3;">Shipping Address</h3>
                            <select id="shipToAddressDropdown-${companyId}" onchange="handleAddressSelectionChange(event)" style="width: 100%; padding: 8px; margin-bottom: 10px;"></select>
                            <div id="selectedAddressDetails-${companyId}" style="border: 1px solid #ccc; padding: 10px; margin-top: 10px; border-radius: 4px; min-height: 50px; background-color: #d0d0d0;"></div>
                            
                            <div style="display: flex; gap: 10px; margin-top: 10px;">
                                <button onclick="openShippingAddressModal(true)" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #28a745; color: white; font-size: 16px; font-weight: bold;">Add New</button>
                                <button id="editAddressBtn-${companyId}" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #ffc107; color: #212529; display:none; font-size: 16px; font-weight: bold;">Edit</button>
                                <button id="deleteAddressBtn-${companyId}" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #dc3545; color: white; display:none; font-size: 16px; font-weight: bold;">Delete</button>
                                <button id="makeDefaultBtn-${companyId}" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; background-color: #007bff; color: white; display:none; font-size: 16px; font-weight: bold;">Make Default</button>
                            </div>
                        </div>

                        <div style="padding: 15px; border: 1px solid #ddd; border-radius: 6px; display: flex; flex-direction: column;">
                            <h3 style="margin-top: 0; border-bottom: 2px solid #0056b3; padding-bottom: 5px; color: #0056b3;">Notes</h3>
                            <textarea id="companyNotes" rows="12" style="width: 98%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; font-family: Arial, sans-serif; font-size: 15px; resize: vertical; overflow-y: auto;" onblur="saveCompanyNotes()">${escapeHTML(company.notes || '')}</textarea>
                        </div>
                    </div>

                    <div style="margin-top: 20px; border-top: 1px solid #ccc; padding-top: 15px;">
                        <h3 style="margin-top: 0; border-bottom: 2px solid #0056b3; padding-bottom: 5px; color: #0056b3;">Users <button onclick="openAddUserModalForCompany(${companyId})" style="padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 0px; margin-left: 25px; background-color: #28a745; color: white; font-size: 14px; font-weight: bold;">Add User</button></h3>
                        <div id="usersList">
                            ${users.length > 0 ? users.map(user => `
                                <div style="padding: 6px 0; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; gap: 10px;">
                                    <span style="flex: 1; min-width: 0;">${escapeHTML(user.last_name || '')}${user.first_name ? ', ' + escapeHTML(user.first_name) : ''} - ${escapeHTML(user.email)} (${escapeHTML(user.role)})</span>
                                    <div style="display: flex; gap: 5px; flex-shrink: 0;">
                                        <button onclick="impersonateUser(${user.id})" style="padding: 5px 12px; border: none; border-radius: 5px; cursor: pointer; background-color: #0056b3; color: white; font-size: 12px; font-weight: bold;">Impersonate</button>
                                        <button class="history-btn" data-user-id="${user.id}" data-user-email="${escapeHTML(user.email)}" style="padding: 5px 12px; border: none; border-radius: 5px; cursor: pointer; background-color: #17a2b8; color: white; font-size: 12px; font-weight: bold;">History</button>
                                        <button onclick="editUser(${user.id})" style="padding: 5px 12px; border: none; border-radius: 5px; cursor: pointer; background-color: #ffc107; color: #212529; font-size: 12px; font-weight: bold;">Edit</button>
                                        <button onclick="deleteUser(${user.id})" style="padding: 5px 12px; border: none; border-radius: 5px; cursor: pointer; background-color: #dc3545; color: white; font-size: 12px; font-weight: bold;">Delete</button>
                                    </div>
                                </div>
                            `).join('') : '<div style="margin-top: 10px; padding: 10px; border-radius: 4px; background-color: #e2e3e5; color: #383d41; display:block;">No users found for this company.</div>'}
                        </div>
                    </div>
                `;

                updateShippingDropdown(companyId, currentAddresses, selectedAddressIdToRestore);

                document.getElementById(`editAddressBtn-${companyId}`).addEventListener('click', editSelectedShippingAddress);
                document.getElementById(`deleteAddressBtn-${companyId}`).addEventListener('click', deleteSelectedShippingAddress);
                dynamicContentDiv.querySelectorAll('.history-btn').forEach(btn => {
                    btn.addEventListener('click', () => openLoginHistoryModal(btn.dataset.userId, btn.dataset.userEmail));
                });
                document.getElementById(`makeDefaultBtn-${companyId}`).addEventListener('click', setAddressAsDefault);
                
                // Load order history for the selected company
                await loadOrderHistoryForCompany(numericCompanyId);
                
                await fetchActivityFeed(); // Explicit call to refresh activity feed

            } catch (error) {
                console.error("Error fetching company details or addresses:", error);
                document.getElementById("dynamicCompanyContent").innerHTML = "<div>Error loading company details.</div>";
                await fetchActivityFeed(); // Explicit call to refresh activity feed after catch
            }
        }

        function updateApprovalStatusDropdownStyle(selectedValue) {
            const dropdown = document.getElementById('approvalStatusDropdown');
            if (dropdown) {
                dropdown.style.backgroundColor = '';
                dropdown.style.color = '';
                if (selectedValue === 'Approved') {
                    dropdown.style.backgroundColor = '#28a745';
                    dropdown.style.color = 'white';
                } else if (selectedValue === 'Denied') {
                    dropdown.style.backgroundColor = '#dc3545';
                    dropdown.style.color = 'white';
                } else if (selectedValue === 'Pending') {
                    dropdown.style.backgroundColor = '#ffc107';
                    dropdown.style.color = '#212529';
                }
            }
        }

        async function updateCompanyApprovalStatus() {
            const dropdown = document.getElementById('approvalStatusDropdown');
            const newStatus = dropdown.value;
            
            let isApproved = false;
            let isDenied = false;

            if (newStatus === 'Approved') {
                isApproved = true;
                isDenied = false;
            } else if (newStatus === 'Denied') {
                isApproved = false;
                isDenied = true;
            } else {
                isApproved = false;
                isDenied = false;
            }

            if (!currentCompanyId) {
                showMessage('error', 'No company selected to update approval status.');
                return;
            }

            updateApprovalStatusDropdownStyle(newStatus);

            try {
                const companyToUpdate = companies.find(c => c.id === currentCompanyId);

                if (!companyToUpdate) {
                    console.error("Company not found in local array for status update:", currentCompanyId);
                    showMessage('error', "Error: Company data not found for status update.");
                    return;
                }

                const updatedCompanyData = { 
                    ...companyToUpdate, 
                    approved: isApproved,
                    denied: isDenied
                };

                const response = await apiFetch("/edit-company", {
                    method: "POST",
                    body: JSON.stringify(updatedCompanyData)
                });

                if (response.ok) {
                    showMessage('success', `Company approval status updated to ${newStatus}!`);
                    const companyIndex = companies.findIndex(c => c.id === currentCompanyId);
                    if (companyIndex !== -1) {
                        companies[companyIndex].approved = isApproved;
                        companies[companyIndex].denied = isDenied;
                    }
                    await fetchCompanies();
                    toggleCompanyDetails(currentCompanyId);
                    await fetchActivityFeed(); // Refresh activity feed on approval/status change
                    refreshDashboardSummary();

                    if (newStatus === 'Approved') {
                        openSendApprovalEmailConfirmationModal(currentCompanyId);
                    }

                } else {
                    const errorData = await response.json();
                    showMessage('error', errorData.error || `Failed to update approval status: ${response.statusText}`);
                    const originalCompany = companies.find(c => c.id === currentCompanyId);
                    if (originalCompany) {
                        if (originalCompany.approved) {
                            dropdown.value = 'Approved';
                        } else if (originalCompany.denied) {
                            dropdown.value = 'Denied';
                        } else {
                            dropdown.value = 'Pending';
                        }
                    }
                    updateApprovalStatusDropdownStyle(dropdown.value);
                }
            } catch (error) {
                console.error("Error updating approval status:", error);
                showMessage('error', "An error occurred while updating the approval status.");
                const originalCompany = companies.find(c => c.id === currentCompanyId);
                if (originalCompany) {
                    if (originalCompany.approved) {
                        dropdown.value = 'Approved';
                    } else if (originalCompany.denied) {
                        dropdown.value = 'Denied';
                    } else {
                        dropdown.value = 'Pending';
                    }
                }
                updateApprovalStatusDropdownStyle(dropdown.value);
            }
        }
        
        // ------------- Company Login History Tab Functions ---------------

        async function fetchCompanyLoginHistory(companyId) {
            if (!companyId) {
                document.getElementById('companyNoLoginHistoryMessage').textContent = 'No company selected.';
                document.getElementById('companyNoLoginHistoryMessage').style.display = 'block';
                return;
            }

            const tableBody = document.getElementById('companyLoginHistoryTableBody');
            const noHistoryMessage = document.getElementById('companyNoLoginHistoryMessage');
            tableBody.innerHTML = '';
            noHistoryMessage.style.display = 'none';
            noHistoryMessage.textContent = 'No login history found for users in this company.';
            
            let companyLoginHistory = [];

            try {
                // Define a very wide date range (beginning of time) to fetch all records
                const startDate = '1970-01-01'; 
                const endDate = new Date().toISOString().split('T')[0]; // Today's date (YYYY-MM-DD)
                
                const response = await apiFetch(`/admin/login-report?startDate=${startDate}&endDate=${endDate}`);
                
                const allLoginHistory = await response.json();
                
                // Find the current company's data to ensure accurate filtering
                const currentCompany = companies.find(c => c.id == companyId);
                const currentCompanyName = currentCompany ? currentCompany.name : null;

                // Filter the full report client-side by the current companyId OR companyName
                companyLoginHistory = allLoginHistory.filter(login => 
                    login.companyId == companyId || (currentCompanyName && login.company_name === currentCompanyName)
                );
                
                if (!Array.isArray(companyLoginHistory) || companyLoginHistory.length === 0) {
                    noHistoryMessage.style.display = 'block';
                    return;
                }

                // Sort by login time, descending (newest first)
                companyLoginHistory.sort((a, b) => new Date(b.login_time) - new Date(a.login_time));

                companyLoginHistory.forEach(login => {
                    const row = tableBody.insertRow();
                    row.className = 'login-history-row';
                    const dateCell = row.insertCell(0);
                    const emailCell = row.insertCell(1);
                    const ipCell = row.insertCell(2);

                    const loginDate = new Date(login.login_time);
                    // Use UTC time string for consistency, then format
                    const formattedTime = loginDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
                    const formattedDate = loginDate.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });

                    // Assuming login_time is returned as a UTC timestamp from the server
                    dateCell.textContent = `${formattedDate} ${formattedTime} (UTC)`; 
                    emailCell.textContent = login.email || 'N/A';
                    ipCell.textContent = login.ip_address || 'N/A';

                    [dateCell, emailCell, ipCell].forEach(cell => {
                        cell.style.border = '1px solid #ddd';
                        cell.style.padding = '8px';
                    });
                });

            } catch (error) {
                console.error("Error fetching company login history:", error);
                noHistoryMessage.textContent = 'Could not retrieve login history. Failed to fetch general report.';
                noHistoryMessage.style.display = 'block';
            }
        }


        // ------------- Single User Login History Modal Functions ---------------

        async function openLoginHistoryModal(userId, userEmail) {
            document.getElementById('loginHistoryModalTitle').textContent = `Login History for ${userEmail}`;
            const tableBody = document.getElementById('loginHistoryTableBody');
            const noHistoryMessage = document.getElementById('noLoginHistoryMessage');
            tableBody.innerHTML = '';
            noHistoryMessage.style.display = 'none';

            try {
                // Note: Assuming this endpoint works for individual user history if the company endpoint failed.
                const response = await apiFetch(`/admin/user-logins/${userId}`);
                if (!response.ok) {
                    throw new Error('Failed to fetch login history.');
                }
                const loginHistory = await response.json();

                if (loginHistory.length > 0) {
                    // Sort by login time, descending (newest first)
                    loginHistory.sort((a, b) => new Date(b.login_time) - new Date(a.login_time));

                    loginHistory.forEach(login => {
                        const row = tableBody.insertRow();
                        const dateCell = row.insertCell(0);
                        const ipCell = row.insertCell(1);

                        const loginDate = new Date(login.login_time);
                        dateCell.textContent = loginDate.toLocaleString('en-US', { timeZone: 'UTC', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
                        ipCell.textContent = login.ip_address;

                        dateCell.style.border = '1px solid #ddd';
                        dateCell.style.padding = '8px';
                        ipCell.style.border = '1px solid #ddd';
                        ipCell.style.padding = '8px';
                    });
                } else {
                    noHistoryMessage.style.display = 'block';
                }

                document.getElementById('loginHistoryModal').style.display = 'block';

            } catch (error) {
                console.error("Error fetching login history:", error);
                showMessage('error', "Could not retrieve login history.");
            }
        }

        // ----------------- Global Login Report Modal Functions -----------------

        function openLoginReportModal() {
            document.getElementById('reportStartDate').valueAsDate = new Date(1970, 0, 1);
            document.getElementById('reportEndDate').valueAsDate = new Date();

            const loginFilterEl = document.getElementById('loginReportFilter');
            if (loginFilterEl) loginFilterEl.value = '';

            document.getElementById('loginReportLoading').style.display = 'none';
            document.getElementById('loginReportResults').style.display = 'none';
            document.getElementById('loginReportModal').style.display = 'block';
            generateLoginReport(); // auto-load all on open
        }

        function applyLoginReportPreset(days) {
            const end = new Date();
            const start = new Date();
            start.setDate(start.getDate() - (days - 1));
            document.getElementById('reportStartDate').valueAsDate = start;
            document.getElementById('reportEndDate').valueAsDate = end;
            generateLoginReport();
        }

        function applyLoginReportPresetThisMonth() {
            const now = new Date();
            const start = new Date(now.getFullYear(), now.getMonth(), 1);
            document.getElementById('reportStartDate').valueAsDate = start;
            document.getElementById('reportEndDate').valueAsDate = now;
            generateLoginReport();
        }

        function applyLoginReportPresetAll() {
            document.getElementById('reportStartDate').valueAsDate = new Date(1970, 0, 1);
            document.getElementById('reportEndDate').valueAsDate = new Date();
            generateLoginReport();
        }

        async function generateLoginReport() {
            const startDate = document.getElementById('reportStartDate').value;
            const endDate = document.getElementById('reportEndDate').value;

            if (!startDate || !endDate) {
                return showMessage('error', 'Please select both a start and end date.');
            }
            if (new Date(startDate) > new Date(endDate)) {
                return showMessage('error', 'Start date cannot be after the end date.');
            }

            const loadingEl = document.getElementById('loginReportLoading');
            document.getElementById('loginReportResults').style.display = 'none';
            loadingEl.style.display = 'block';

            try {
                const response = await apiFetch(`/admin/login-report?startDate=${startDate}&endDate=${endDate}`);
                loginReportData = await response.json();
                const loginFilterEl = document.getElementById('loginReportFilter');
                if (loginFilterEl) loginFilterEl.value = '';
                displayLoginReport();
            } catch (error) {
                showMessage('error', 'Failed to generate login report.');
                console.error("Error generating login report:", error);
            } finally {
                loadingEl.style.display = 'none';
            }
        }

        let loginReportData = [];

        function displayLoginReport() {
            renderLoginReportTable(loginReportData);
        }

        function filterLoginReportDisplay() {
            const q = document.getElementById('loginReportFilter').value.toLowerCase().trim();
            const filtered = q
                ? loginReportData.filter(login =>
                    (login.email        || '').toLowerCase().includes(q) ||
                    (login.first_name   || '').toLowerCase().includes(q) ||
                    (login.last_name    || '').toLowerCase().includes(q) ||
                    (login.company_name || '').toLowerCase().includes(q))
                : loginReportData;
            renderLoginReportTable(filtered);
        }

        function renderLoginReportTable(logins) {
            const tableBody = document.getElementById('loginReportTableBody');
            const noResultsMessage = document.getElementById('noLoginReportMessage');
            const resultsContainer = document.getElementById('loginReportResults');
            const summaryBar = document.getElementById('loginReportSummaryBar');

            tableBody.innerHTML = '';

            if (summaryBar) {
                summaryBar.textContent = `${logins.length} login${logins.length === 1 ? '' : 's'}`;
            }

            if (logins.length === 0) {
                noResultsMessage.style.display = 'block';
                tableBody.style.display = 'none';
            } else {
                noResultsMessage.style.display = 'none';
                tableBody.style.display = '';
                logins.forEach(login => {
                    const row = tableBody.insertRow();
                    const loginDate = new Date(login.login_time);
                    row.insertCell(0).textContent = loginDate.toLocaleString('en-US', { timeZone: 'UTC' });
                    row.insertCell(1).textContent = login.email;
                    row.insertCell(2).textContent = login.first_name || '';
                    row.insertCell(3).textContent = login.last_name || '';
                    row.insertCell(4).textContent = login.company_name;
                });
            }
            resultsContainer.style.display = 'block';
        }
        function downloadLoginReportCSV() {
            const table = document.getElementById('loginReportTableBody');
            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += "Login Time (UTC),Email,First Name,Last Name,Company\n"; 

            for (let i = 0; i < table.rows.length; i++) {
                let row = [], cols = table.rows[i].querySelectorAll("td");
                for (let j = 0; j < cols.length; j++) {
                    row.push('"' + cols[j].innerText.replace(/"/g, '""') + '"');
                }
                csvContent += row.join(",") + "\n";
            }

            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            const startDate = document.getElementById('reportStartDate').value;
            const endDate = document.getElementById('reportEndDate').value;
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", `login_report_${startDate}_to_${endDate}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
        function openSendApprovalEmailConfirmationModal(companyId) {
            currentCompanyIdForEmail = companyId;
            document.getElementById("sendApprovalEmailConfirmationModal").style.display = "block";
        }

        async function confirmSendApprovalEmail() {
            if (currentCompanyIdForEmail) {
                await sendApprovalEmail(currentCompanyIdForEmail);
            }
            closeModal('sendApprovalEmailConfirmationModal');
            currentCompanyIdForEmail = null;
        }

        function cancelSendApprovalEmail() {
            closeModal('sendApprovalEmailConfirmationModal');
            currentCompanyIdForEmail = null;
        }

        async function sendApprovalEmail(companyId) {
            try {
                const response = await apiFetch("/admin/send-approval-email", {
                    method: "POST",
                    body: JSON.stringify({ companyId: companyId })
                });

                if (response.ok) {
                    showMessage('success', 'Approval email sent to the company user!');
                } else {
                    const errorData = await response.json();
                    showMessage('error', errorData.error || 'Failed to send approval email.');
                }
            } catch (error) {
                console.error('Error sending approval email:', error);
                showMessage('error', 'An error occurred while sending the approval email.');
            }
        }


        // ----------------- User Impersonation -----------------
        async function impersonateUser(userId) {
            try {
                // STEP 1: Request a special URL/token from the backend that will initiate the redirect flow.
                const response = await apiFetch(`/admin/impersonate/${userId}`, {
                    method: "GET"
                }); 
                if (!response.ok) {
                    throw new Error("Failed to get impersonation token or redirect URL. Check API endpoint.");
                }
                const result = await response.json();
                
                if (result.redirectUrl) {
                    // STEP 2: Open the new tab and navigate directly to the URL provided by the backend.
                    // The backend route /login-via-token/:token handles the session creation and final redirect.
                    window.open(result.redirectUrl, '_blank');
                    showMessage('info', 'Impersonating user. Portal opened in new tab.');
                } else {
                    showMessage('error', 'Impersonation failed: Redirect URL not received.');
                }
            } catch (error) {
                console.error("Error during user impersonation:", error);
                showMessage('error', error.message || "An error occurred during impersonation.");
            }
        }

        // ----------------- Company Modals & Operations -----------------

        function emailCompanyFullInfo() {
            const data = window._currentCompanyEmailData;
            if (!data) return;
            const { company, users } = data;

            const formatDate = (val) => {
                if (!val) return '';
                const d = new Date(val);
                if (isNaN(d)) return '';
                return d.toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', year: 'numeric' });
            };

            const cityLine = [company.city, company.state, company.zip, company.country].filter(Boolean).join(', ');

            const companyLines = [
                `Company: ${company.name}`,
                company.address1  ? `Address: ${company.address1.replace(/\n/g, ', ')}` : '',
                cityLine          || '',
                company.phone     ? `Phone: ${company.phone}` : '',
                company.website   ? `Website: ${company.website}` : '',
                company.ap_email  ? `A/P Email: ${company.ap_email}` : '',
                company.terms     ? `Terms: ${company.terms}` : '',
                (company.discount !== undefined && company.discount !== null) ? `Discount: ${company.discount}%` : '',
                company.created_at ? `Date Created: ${formatDate(company.created_at)}` : '',
                company.notes     ? `Notes: ${company.notes}` : '',
            ].filter(Boolean).join('\n');

            const userLines = users.length > 0
                ? users.map(u => {
                    const name = [u.first_name, u.last_name].filter(Boolean).join(' ');
                    const parts = [
                        name || '',
                        u.email,
                        `(${u.role})`,
                        u.phone       ? `Phone: ${u.phone}` : '',
                        u.created_at  ? `Created: ${formatDate(u.created_at)}` : '',
                    ].filter(Boolean);
                    return `  - ${parts.join(' | ')}`;
                  }).join('\n')
                : '  No users on file.';

            const body = `${companyLines}\n\nUsers:\n${userLines}`;

            const subject = encodeURIComponent(`Company Info: ${company.name}`);
            window.location.href = `mailto:?subject=${subject}&body=${encodeURIComponent(body)}`;
        }

        function emailCompanyInfo(modalType) {
            const prefix = modalType === 'edit' ? 'editCompany' : 'company';

            const name     = document.getElementById(prefix + 'Name')?.value || '';
            const address  = document.getElementById(prefix + 'Address1')?.value || '';
            const city     = document.getElementById(prefix + 'City')?.value || '';
            const state    = document.getElementById(prefix + 'State')?.value || '';
            const zip      = document.getElementById(prefix + 'Zip')?.value || '';
            const country  = document.getElementById(prefix + 'Country')?.value || '';
            const phone    = document.getElementById(prefix + 'Phone')?.value || '';
            const website  = document.getElementById(prefix + 'Website')?.value || '';
            const apEmail  = document.getElementById(prefix + 'ApEmail')?.value || '';
            const terms    = document.getElementById(prefix + 'Terms')?.value || '';
            const discount = document.getElementById(prefix + 'Discount')?.value || '';
            const logo     = document.getElementById(prefix + 'Logo')?.value || '';

            const cityLine = [city, state, zip, country].filter(Boolean).join(', ');

            const body = [
                `Company: ${name}`,
                address   ? `Address: ${address.replace(/\n/g, ', ')}` : '',
                cityLine  ? cityLine : '',
                phone     ? `Phone: ${phone}` : '',
                website   ? `Website: ${website}` : '',
                apEmail   ? `A/P Email: ${apEmail}` : '',
                logo      ? `Logo URL: ${logo}` : '',
                terms     ? `Terms: ${terms}` : '',
                discount  ? `Discount: ${discount}%` : '',
            ].filter(Boolean).join('\n');

            const subject = encodeURIComponent(`Company Info: ${name}`);
            const encodedBody = encodeURIComponent(body);
            window.location.href = `mailto:?subject=${subject}&body=${encodedBody}`;
        }

        function emailUserInfo() {
            const firstName   = document.getElementById('editUserFirstName')?.value || '';
            const lastName    = document.getElementById('editUserLastName')?.value || '';
            const email       = document.getElementById('editUserEmail')?.value || '';
            const phone       = document.getElementById('editUserPhone')?.value || '';
            const role        = document.getElementById('editUserRole')?.value || '';
            const dateCreated = document.getElementById('editUserDateCreated')?.value || '';
            const companyEl   = document.getElementById('editUserCompany');
            const company     = companyEl?.options[companyEl.selectedIndex]?.text || '';

            const fullName = [firstName, lastName].filter(Boolean).join(' ');

            const body = [
                fullName    ? `Name: ${fullName}` : '',
                email       ? `Email: ${email}` : '',
                phone       ? `Phone: ${phone}` : '',
                company     ? `Company: ${company}` : '',
                role        ? `Role: ${role.charAt(0).toUpperCase() + role.slice(1)}` : '',
                dateCreated ? `Date Created: ${dateCreated}` : '',
            ].filter(Boolean).join('\n');

            const subject = encodeURIComponent(`User Info: ${fullName || email}`);
            const encodedBody = encodeURIComponent(body);
            window.location.href = `mailto:?subject=${subject}&body=${encodedBody}`;
        }

        function openAddCompanyModal() {
            document.getElementById("addCompanyModal").style.display = "block";
            document.getElementById("companyId").value = "";
            document.getElementById("companyName").value = "";
            document.getElementById("companyLogo").value = "";
            document.getElementById("companyLogoCode").value = "";
            document.getElementById("companyAddress1").value = "";
            document.getElementById("companyApEmail").value = "";
            document.getElementById("companyPhone").value = "";
            document.getElementById("companyWebsite").value = "";
            document.getElementById("companyCity").value = "";
            document.getElementById("companyState").value = "";
            document.getElementById("companyZip").value = "";
            document.getElementById("companyCountry").value = "";
            document.getElementById("companyTerms").value = "";
            document.getElementById("companyDiscount").value = "0";
        }

        async function submitCompanyModal() {
            const id = document.getElementById("companyId").value;
            const name = document.getElementById("companyName").value;
            const logo = document.getElementById("companyLogo").value;
            const logo_code = document.getElementById("companyLogoCode").value;
            const address1 = document.getElementById("companyAddress1").value;
            const ap_email = document.getElementById("companyApEmail").value;
            let website = document.getElementById("companyWebsite").value.trim();
            // Auto-prepend https:// if user didn't include a protocol
            if (website && !website.match(/^https?:\/\//i)) {
                website = 'https://' + website;
            }
            const city = document.getElementById("companyCity").value;
            const state = document.getElementById("companyState").value;
            const zip = document.getElementById("companyZip").value;
            const country = document.getElementById("companyCountry").value;
            const terms = document.getElementById("companyTerms").value;
            const discount = document.getElementById("companyDiscount").value;
            const phone = document.getElementById("companyPhone").value;

            if (!name || !terms) {
                showMessage('error', 'Name and Terms are required.');
                return;
            }

            if (!id) {
                const isDuplicate = companies.some(company => company.name.toLowerCase() === name.toLowerCase());
                if (isDuplicate) {
                    showMessage('error', 'A company with this name already exists.');
                    return;
                }
            }

            const companyData = {
                name, logo, logo_code, address1, ap_email, website, city, state, zip, country, terms, phone,
                discount: parseInt(discount, 10),
                notes: '',
                approved: false,
                denied: false
            };

            let endpoint = "/add-company";
            let method = "POST";
            let successMessage = "Company Added Successfully!";
            let companyToSelectId = null;

            if (id) {
                endpoint = "/edit-company";
                successMessage = "Company Updated Successfully!";
                companyToSelectId = id;
            }

            try {
                const response = await apiFetch(endpoint, {
                    method: method,
                    body: JSON.stringify(companyData)
                });

                if (response.ok) {
                    const resultData = await response.json();
                    showMessage('success', successMessage);
                    closeModal('addCompanyModal');
                    
                    if (!id) {
                        companyToSelectId = resultData.id; 
                        console.log("New company ID from backend:", companyToSelectId);
                    } else {
                        console.log("Edited company ID:", companyToSelectId);
                    }

                    await fetchCompanies();
                    console.log("Companies array after fetchCompanies in submitCompanyModal:", companies);
                    if (companyToSelectId) {
                        toggleCompanyDetails(companyToSelectId);
                    }
                    await fetchActivityFeed(); // Refresh activity feed on company addition/edit
                } else {
                    const errorData = await response.json();
                    showMessage('error', errorData.error || `Failed to save company: ${response.statusText}`);
                }
            }
            catch (error) {
                    console.error("Error saving company:", error);
                showMessage('error', "An error occurred while saving the company.");
            }
        }

        function editCompany(id) {
            const company = companies.find(c => c.id === id);
            if (company) {
                document.getElementById("editCompanyId").value = company.id;
                document.getElementById("editCompanyName").value = company.name || '';
                document.getElementById("editCompanyLogo").value = company.logo || '';
                // Pre-select the saved logo_code in the dropdown (repopulate first in case
                // the options were cleared, then set the value).
                populateLogoDropdowns(company.logo_code || '').then(() => {
                    document.getElementById("editCompanyLogoCode").value = company.logo_code || '';
                });
                document.getElementById("editCompanyAddress1").value = company.address1 || '';
                document.getElementById("editCompanyApEmail").value = company.ap_email || '';
                document.getElementById("editCompanyPhone").value = company.phone || '';
                document.getElementById("editCompanyWebsite").value = company.website || '';
                document.getElementById("editCompanyCity").value = company.city || '';
                document.getElementById("editCompanyState").value = company.state || '';
                document.getElementById("editCompanyZip").value = company.zip || '';
                document.getElementById("editCompanyCountry").value = company.country || '';
                document.getElementById("editCompanyTerms").value = company.terms || '';
                document.getElementById("editCompanyDiscount").value = (company.discount !== undefined && company.discount !== null) ? company.discount : "0";
                document.getElementById("editCompanyModal").style.display = "block";
            }
        }

        async function submitEditCompany() {
            const id = document.getElementById("editCompanyId").value;
            const name = document.getElementById("editCompanyName").value;
            const logo = document.getElementById("editCompanyLogo").value;
            const logo_code = document.getElementById("editCompanyLogoCode").value;
            let website = document.getElementById("editCompanyWebsite").value.trim();
            // Auto-prepend https:// if user didn't include a protocol
            if (website && !website.match(/^https?:\/\//i)) {
                website = 'https://' + website;
            }
            const address1 = document.getElementById("editCompanyAddress1").value;
            const ap_email = document.getElementById("editCompanyApEmail").value;
            const phone = document.getElementById("editCompanyPhone").value;
            const city = document.getElementById("editCompanyCity").value;
            const state = document.getElementById("editCompanyState").value;
            const zip = document.getElementById("editCompanyZip").value;
            const country = document.getElementById("editCompanyCountry").value;
            const terms = document.getElementById("editCompanyTerms").value;
            const discount = document.getElementById("editCompanyDiscount").value;

            const companyToUpdate = companies.find(c => c.id === parseInt(id, 10));

            if (!companyToUpdate) {
                console.error("Company not found in local array for edit update:", id);
                showMessage('error', "Error: Company data not found for edit update.");
                return;
            }

            if (!name || !terms) {
                showMessage('error', 'Name and Terms are required.');
                return;
            }

            const companyData = {
                id: parseInt(id, 10),
                name, logo, logo_code, address1, ap_email, website, city, state, zip, country, terms, phone,
                discount: parseInt(discount, 10),
                notes: companyToUpdate.notes || '',
                approved: companyToUpdate.approved,
                denied: companyToUpdate.denied
            };

            try {
                const response = await apiFetch("/edit-company", {
                    method: "POST",
                    body: JSON.stringify(companyData)
                });

                if (response.ok) {
                    showMessage('success', "Company Updated Successfully!");
                    closeModal('editCompanyModal');
                    await fetchCompanies();
                    console.log("submitEditCompany: Companies array after refresh:", companies);
                    toggleCompanyDetails(id);
                    await fetchActivityFeed(); // Refresh activity feed on company addition/edit
                } else {
                    const errorData = await response.json();
                    showMessage('error', errorData.error || `Failed to update company: ${response.statusText}`);
                }
            } catch (error) {
                console.error("Error updating company:", error);
                showMessage('error', "An error occurred while updating the company.");
            }
        }

        function deleteCompany(id) {
            companyIdToDelete = id;
            document.getElementById('deleteCompanyConfirmationModal').style.display = 'block';
        }

        async function confirmCompanyDeletion() {
            if (!companyIdToDelete) return;
            const idToDelete = companyIdToDelete;
            const label = 'company';

            closeModal('deleteCompanyConfirmationModal');
            companyIdToDelete = null;

            document.getElementById("dynamicCompanyContent").innerHTML = "<p>Select a company from the list to view details.</p>";
            const approvalStatusDropdown = document.getElementById("approvalStatusDropdown");
            if (approvalStatusDropdown) {
                approvalStatusDropdown.style.display = 'none';
            }

            scheduleUndoableDelete(`company-${idToDelete}`, label, async () => {
                try {
                    const response = await apiFetch("/delete-company", {
                        method: "POST",
                        body: JSON.stringify({ id: idToDelete })
                    });

                    if (response.ok) {
                        showMessage('success', "Company Deleted Successfully!");
                        await fetchCompanies();
                        await fetchActivityFeed(); // Refresh activity feed on company deletion
                        refreshDashboardSummary();
                    } else {
                        const errorData = await response.json();
                        showMessage('error', errorData.error || "Failed to delete company.");
                    }
                } catch (error) {
                    console.error("Error deleting company:", error);
                    showMessage('error', "An error occurred while deleting the company.");
                }
            });
        }

        // ----------------- User Modals & Operations -----------------

        function openAddUserModalForCompany(companyId) {
            document.getElementById('addUserId').value = '';
            document.getElementById('addUserCompanyId').value = companyId;
            document.getElementById('addUserEmail').value = '';
            document.getElementById('addUserFirstName').value = '';
            document.getElementById('addUserLastName').value = '';
            document.getElementById('addUserPhone').value = '';
            document.getElementById('addUserRole').value = 'user';
            document.getElementById('addUserPassword').value = '';
            
            document.getElementById('addUserModal').style.display = 'block';
        }

        async function submitAddUser() {
            const companyId = document.getElementById('addUserCompanyId').value;
            const email = document.getElementById('addUserEmail').value;
            const firstName = document.getElementById('addUserFirstName').value;
            const lastName = document.getElementById('addUserLastName').value;
            const phone = document.getElementById('addUserPhone').value;
            const role = document.getElementById('addUserRole').value;
            const password = document.getElementById('addUserPassword').value;

            if (!email || !companyId || !password) {
                showMessage('error', "Email, Password, and Company ID are required.");
                return;
            }

            const userData = {
                email, firstName, lastName, phone, role, companyId, password
            };

            try {
                const response = await apiFetch("/add-user", {
                    method: "POST",
                    body: JSON.stringify(userData)
                });

                if (response.ok) {
                    showMessage('success', "User Added Successfully!");
                    closeModal('addUserModal');
                    await fetchCompanies();
                    toggleCompanyDetails(companyId);
                    await fetchActivityFeed(); // Refresh activity feed on new user
                } else {
                    const errorData = await response.json();
                    showMessage('error', errorData.error || "Failed to add user.");
                }
            } catch (error) {
                console.error("Error saving user:", error);
                showMessage('error', "An error occurred while saving the user.");
            }
        }

        async function editUser(userId) {
            try {
                const response = await apiFetch(`/user/${userId}`);
                if (!response.ok) {
                    throw new Error("Failed to fetch user details.");
                }
                const user = await response.json();

                document.getElementById('editUserId').value = user.id;
                document.getElementById('editUserEmail').value = user.email || '';
                document.getElementById('editUserFirstName').value = user.first_name || '';
                document.getElementById('editUserLastName').value = user.last_name || '';
                document.getElementById('editUserPhone').value = user.phone || '';
                document.getElementById('editUserRole').value = user.role || 'user';
                document.getElementById('editUserPassword').value = ''; 

                const dateCreatedInput = document.getElementById('editUserDateCreated');
                if (user.created_at) {
                    const date = new Date(user.created_at);
                    const month = String(date.getMonth() + 1).padStart(2, '0');
                    const day = String(date.getDate()).padStart(2, '0');
                    const year = date.getFullYear();
                    dateCreatedInput.value = `${month}/${day}/${year}`;
                } else {
                    dateCreatedInput.value = 'N/A';
                }

                const companyDropdown = document.getElementById('editUserCompany');
                companyDropdown.innerHTML = ''; 
                const sortedCompanies = [...companies].sort((a, b) => (a.name || '').localeCompare(b.name || ''));

                sortedCompanies.forEach(company => {
                    const option = document.createElement('option');
                    option.value = company.id;
                    option.textContent = `${company.name} (ID: ${company.id})`;
                    option.style.backgroundColor = '#e0e0e0';
                    if (company.id === user.company_id) {
                        option.selected = true;
                    }
                    companyDropdown.appendChild(option);
                });

                document.getElementById('editUserModal').style.display = 'block';
            } catch (error) {
                console.error("Error fetching user details:", error);
                showMessage('error', "Failed to load user details for editing.");
            }
        }

        async function submitEditUser() {
            const id = document.getElementById('editUserId').value;
            const companyId = document.getElementById('editUserCompany').value;
            const email = document.getElementById('editUserEmail').value;
            const firstName = document.getElementById('editUserFirstName').value;
            const lastName = document.getElementById('editUserLastName').value;
            const phone = document.getElementById('editUserPhone').value;
            const role = document.getElementById('editUserRole').value;
            const password = document.getElementById('editUserPassword').value;

            if (!email || !id || !companyId) {
                showMessage('error', "Email, User ID, and Company are required.");
                return;
            }

            const userData = {
                id, email, firstName, lastName, phone, role, companyId
            };
            
            if (password) {
                userData.password = password;
            }

            try {
                const response = await apiFetch("/edit-user", {
                    method: "POST",
                    body: JSON.stringify(userData)
                });

                if (response.ok) {
                    showMessage('success', "User Updated Successfully!");
                    closeModal('editUserModal');
                    await fetchCompanies();
                    toggleCompanyDetails(companyId); 
                    // No need to refresh feed here unless user update is critical (like role change to admin)
                } else {
                    const errorData = await response.json();
                    showMessage('error', errorData.error || "Failed to update user.");
                }
            } catch (error) {
                console.error("Error updating user:", error);
                showMessage('error', "An error occurred while updating the user.");
            }
        }

        function deleteUser(id) {
            userIdToDelete = id;
            document.getElementById('deleteUserConfirmationModal').style.display = 'block';
        }

        async function confirmUserDeletion() {
            if (!userIdToDelete) return;
            const idToDelete = userIdToDelete;
            const companyIdAtDeleteTime = currentCompanyId;

            closeModal('deleteUserConfirmationModal');
            userIdToDelete = null;

            scheduleUndoableDelete(`user-${idToDelete}`, 'user', async () => {
                try {
                    const response = await apiFetch("/delete-user", {
                        method: "POST",
                        body: JSON.stringify({ id: idToDelete })
                    });

                    if (response.ok) {
                        showMessage('success', "User Deleted Successfully!");
                        if (companyIdAtDeleteTime) {
                            await fetchCompanies();
                            toggleCompanyDetails(companyIdAtDeleteTime);
                        }
                        await fetchActivityFeed(); // Refresh activity feed on user deletion
                    } else {
                        const errorData = await response.json();
                        showMessage('error', errorData.error || "Failed to delete user.");
                    }
                } catch (error) {
                    console.error("Error deleting user:", error);
                    showMessage('error', "An error occurred while deleting the user.");
                }
            });
        }

        // ----------------- Shipping Address Management -----------------

        function updateShippingDropdown(companyId, addresses, selectedAddressIdToRestore = null) {
            const dropdown = document.getElementById(`shipToAddressDropdown-${companyId}`);
            const editBtn = document.getElementById(`editAddressBtn-${companyId}`);
            const deleteBtn = document.getElementById(`deleteAddressBtn-${companyId}`);
            const makeDefaultBtn = document.getElementById(`makeDefaultBtn-${companyId}`);

            dropdown.innerHTML = '';

            if (addresses.length === 0) {
                dropdown.innerHTML = '<option value="">No addresses available</option>';
                displaySelectedAddressDetails(null);
                editBtn.style.display = 'none';
                deleteBtn.style.display = 'none';
                makeDefaultBtn.style.display = 'none';
                return;
            }

            const groupedAddresses = addresses.reduce((acc, address) => {
                const firstLetter = (address.name || ' ').charAt(0).toUpperCase();
                if (!acc[firstLetter]) {
                    acc[firstLetter] = [];
                }
                acc[firstLetter].push(address);
                return acc;
            }, {});

            const sortedGroupKeys = Object.keys(groupedAddresses).sort();

            let defaultAddressId = null;
            const defaultAddress = addresses.find(addr => addr.is_default);
            if (defaultAddress) {
                defaultAddressId = defaultAddress.id;
            }

            sortedGroupKeys.forEach(letter => {
                const headerOption = document.createElement('option');
                headerOption.value = '';
                headerOption.textContent = letter;
                headerOption.disabled = true;
                headerOption.style.fontWeight = 'bold';
                headerOption.style.color = '#333';
                headerOption.style.backgroundColor = '#e0e0e0';
                dropdown.appendChild(headerOption);
                
                groupedAddresses[letter].sort((a, b) => {
                    if (defaultAddressId && b.id === defaultAddressId && a.id !== defaultAddressId) return -1;
                    if (defaultAddressId && a.id === defaultAddressId && b.id !== defaultAddressId) return 1;
                    return a.name.localeCompare(b.name);
                });

                groupedAddresses[letter].forEach(address => {
                    const option = document.createElement('option');
                    option.value = address.id;
                    option.textContent = `${address.name} ${address.is_default ? '(Default)' : ''}`;
                    dropdown.appendChild(option);
                });
            });

            if (selectedAddressIdToRestore && addresses.some(addr => addr.id == selectedAddressIdToRestore)) {
                dropdown.value = selectedAddressIdToRestore;
            } else if (defaultAddressId) {
                dropdown.value = defaultAddressId;
            } else if (addresses.length > 0) {
                dropdown.value = addresses[0].id;
            }
            
            handleAddressSelectionChange({ target: dropdown });
            
            editBtn.style.display = 'inline-block';
            deleteBtn.style.display = 'inline-block';
        }

        function handleAddressSelectionChange(event) {
            const selectedAddressId = event.target.value;
            const selectedAddress = currentAddresses.find(addr => addr.id == selectedAddressId);
            displaySelectedAddressDetails(selectedAddress);
        }

        function displaySelectedAddressDetails(address) {
            const detailsDiv = document.getElementById(`selectedAddressDetails-${currentCompanyId}`);
            const makeDefaultBtn = document.getElementById(`makeDefaultBtn-${currentCompanyId}`);

            if (!address) {
                detailsDiv.innerHTML = 'No address selected.';
                makeDefaultBtn.style.display = 'none';
                return;
            }

            const companyOrContactName = address.company_name && address.company_name.trim() !== '' ? address.company_name : address.name;

            const addressLines = [
                escapeHTML(companyOrContactName || ''),
                escapeHTML(address.address1 || '').replace(/\n/g, '<br>'),
                `${escapeHTML(address.city || '')}${address.state ? ', ' + escapeHTML(address.state) : ''} ${escapeHTML(address.zip || '')} ${address.country ? escapeHTML(address.country) : ''}`.trim(),
                address.carrier_account ? `Carrier Account #: ${escapeHTML(address.carrier_account)}` : ''
            ];

            detailsDiv.innerHTML = addressLines.filter(line => line.trim() !== '').join('<br>');
            
            if (address.is_default) {
                makeDefaultBtn.style.display = 'none';
            } else {
                makeDefaultBtn.style.display = 'inline-block';
            }
        }

        function openShippingAddressModal(isAdd = true, address = null) {
            const modalTitle = document.getElementById("shippingAddressModalTitle");
            const addressIdInput = document.getElementById("shipToAddressId");
            const companyIdInput = document.getElementById("shipToCompanyId");
            const nameInput = document.getElementById("addressRef");
            const companyNameInput = document.getElementById("shipToCompanyName");
            const address1Input = document.getElementById("shipToAddress1");
            const cityInput = document.getElementById("shipToCity");
            const stateInput = document.getElementById("shipToState");
            const zipInput = document.getElementById("shipToZip");
            const countryInput = document.getElementById("shipToCountry");
            const carrierAccountInput = document.getElementById("shipToCarrierAccount");
            const dateCreatedDiv = document.getElementById("shippingAddressDateCreated");
            const copyBillingRow = document.getElementById("copyBillingAddressRow");

            if (!modalTitle || !addressIdInput || !companyIdInput || !nameInput || !companyNameInput ||
                !address1Input || !cityInput || !stateInput || !zipInput || !countryInput || !carrierAccountInput || !dateCreatedDiv) {
                console.error("Error: One or more elements in shippingAddressModal not found.");
                return;
            }

            if (isAdd) {
                modalTitle.textContent = "Add Shipping Address";
                addressIdInput.value = "";
                companyIdInput.value = currentCompanyId;
                nameInput.value = "";
                companyNameInput.value = "";
                address1Input.value = "";
                cityInput.value = "";
                stateInput.value = "";
                zipInput.value = "";
                countryInput.value = "";
                carrierAccountInput.value = "";
                dateCreatedDiv.style.display = 'none'; // Hide date for new addresses
                if (copyBillingRow) {
                    copyBillingRow.style.display = billingAddressAlreadyExistsAsShipping(currentCompanyId) ? 'none' : 'block';
                }
            } else if (address) {
                modalTitle.textContent = "Edit Shipping Address";
                addressIdInput.value = address.id;
                companyIdInput.value = address.company_id;
                nameInput.value = address.name || '';
                companyNameInput.value = address.company_name || '';
                address1Input.value = address.address1 || '';
                cityInput.value = address.city || '';
                stateInput.value = address.state || '';
                zipInput.value = address.zip || '';
                countryInput.value = address.country || '';
                carrierAccountInput.value = address.carrier_account || '';

                if (address.created_at) {
                    const date = new Date(address.created_at);
                    const month = String(date.getMonth() + 1).padStart(2, '0');
                    const day = String(date.getDate()).padStart(2, '0');
                    const year = date.getFullYear();
                    dateCreatedDiv.textContent = `Created: ${month}/${day}/${year}`;
                    dateCreatedDiv.style.display = 'block';
                } else {
                    dateCreatedDiv.style.display = 'none'; 
                }
                if (copyBillingRow) copyBillingRow.style.display = 'none';
            }

            document.getElementById("shippingAddressModal").style.display = "block";
        }

        function normalizeAddressField(value) {
            return (value || '').toString().trim().toLowerCase();
        }

        function billingAddressAlreadyExistsAsShipping(companyId) {
            const company = companies.find(c => c.id == companyId);
            if (!company) return false;

            const billing = {
                address1: normalizeAddressField(company.address1),
                city: normalizeAddressField(company.city),
                state: normalizeAddressField(company.state),
                zip: normalizeAddressField(company.zip),
                country: normalizeAddressField(company.country)
            };

            // If the company has no billing address on file, there's nothing to copy.
            if (!billing.address1 && !billing.city && !billing.zip) return false;

            return currentAddresses.some(addr =>
                normalizeAddressField(addr.address1) === billing.address1 &&
                normalizeAddressField(addr.city) === billing.city &&
                normalizeAddressField(addr.state) === billing.state &&
                normalizeAddressField(addr.zip) === billing.zip &&
                normalizeAddressField(addr.country) === billing.country
            );
        }

        function copyBillingAddressToShipping() {
            const companyId = document.getElementById("shipToCompanyId").value;
            const company = companies.find(c => c.id == companyId);

            if (!company) {
                showMessage('error', 'Could not find billing address for this company.');
                return;
            }

            document.getElementById("shipToCompanyName").value = company.name || '';
            document.getElementById("shipToAddress1").value = company.address1 || '';
            document.getElementById("shipToCity").value = company.city || '';
            document.getElementById("shipToState").value = company.state || '';
            document.getElementById("shipToZip").value = company.zip || '';
            document.getElementById("shipToCountry").value = company.country || '';

            if (!document.getElementById("addressRef").value) {
                document.getElementById("addressRef").value = company.name || 'Billing Address';
            }
        }

        function editSelectedShippingAddress() {
            const dropdown = document.getElementById(`shipToAddressDropdown-${currentCompanyId}`);
            const selectedAddressId = dropdown.value;
            if (selectedAddressId) {
                const addressToEdit = currentAddresses.find(addr => addr.id == selectedAddressId);
                if (addressToEdit) {
                    openShippingAddressModal(false, addressToEdit);
                } else {
                    showMessage('error', 'Selected address not found for editing.');
                }
            } else {
                showMessage('error', 'Please select an address to edit.');
            }
        }

        async function submitShippingAddress() {
            const addressId = document.getElementById('shipToAddressId').value;
            const companyId = document.getElementById('shipToCompanyId').value;
            const name = document.getElementById('addressRef').value;
            const company_name = document.getElementById('shipToCompanyName').value;
            const address1 = document.getElementById('shipToAddress1').value;
            const city = document.getElementById('shipToCity').value;
            const state = document.getElementById('shipToState').value;
            const zip = document.getElementById('shipToZip').value;
            const country = document.getElementById('shipToCountry').value;
            const carrier_account = document.getElementById('shipToCarrierAccount').value;

            if (!companyId || !name || !address1 || !city || !state || !zip) {
                showMessage('error', "Address Reference, Address, City, State, and Zip are required.");
                return;
            }

            const addressData = {
                companyId: companyId,
                name: name,
                company_name: company_name,
                address1: address1,
                city: city,
                state: state,
                zip: zip,
                country: country,
                carrier_account: carrier_account || null
            };

            let endpoint = "/api/shipto";
            let method = "POST";
            let successMessage = "Address Added Successfully!";
            let idToSelectAfterRefresh = null;

            if (addressId) {
                endpoint = `/api/shipto/${addressId}`;
                method = "PUT";
                delete addressData.companyId;
                successMessage = "Address Updated Successfully!";
                idToSelectAfterRefresh = addressId;
            }

            try {
                const response = await apiFetch(endpoint, {
                    method: method,
                    body: JSON.stringify(addressData)
                });

                if (response.ok) {
                    showMessage('success', successMessage);
                    closeModal('shippingAddressModal');
                    if (method === "POST") {
                        const newAddress = await response.json();
                        idToSelectAfterRefresh = newAddress.id;
                    }
                    await fetchCompanies();
                    toggleCompanyDetails(companyId, idToSelectAfterRefresh); 
                } else {
                    const errorData = await response.json();
                    showMessage('error', errorData.error || `Failed to save shipping address: ${response.statusText}`);
                }
            } catch (error) {
                console.error("Error saving shipping address:", error);
                showMessage('error', "An error occurred while saving the shipping address.");
            }
        }
        
        function deleteSelectedShippingAddress() {
            const dropdown = document.getElementById(`shipToAddressDropdown-${currentCompanyId}`);
            const addressId = dropdown.value;

            if (!addressId) {
                showMessage('error', 'No address selected to delete.');
                return;
            }
            addressIdToDelete = addressId;
            document.getElementById('deleteAddressConfirmationModal').style.display = 'block';
        }

        async function confirmAddressDeletion() {
            if (!addressIdToDelete) return;
            const idToDelete = addressIdToDelete;
            const companyId = currentCompanyId;

            closeModal('deleteAddressConfirmationModal');
            addressIdToDelete = null;

            scheduleUndoableDelete(`address-${idToDelete}`, 'address', async () => {
                try {
                    const response = await apiFetch(`/api/shipto/${idToDelete}`, {
                        method: "DELETE"
                    });

                    if (response.ok) {
                        showMessage('success', "Address Deleted Successfully!");
                        await fetchCompanies();
                        toggleCompanyDetails(companyId);
                    } else {
                        const errorData = await response.json();
                        showMessage('error', errorData.error || "Failed to delete address.");
                    }
                } catch (error) {
                    console.error("Error deleting address:", error);
                    showMessage('error', "An error occurred while deleting the address.");
                }
            });
        }

        async function setAddressAsDefault() {
            const dropdown = document.getElementById(`shipToAddressDropdown-${currentCompanyId}`);
            const addressId = dropdown.value;
            const companyId = currentCompanyId;

            if (!addressId || !companyId) {
                showMessage('error', 'Please select an address and ensure a company is selected.');
                return;
            }

            try {
                const response = await apiFetch(`/api/shipto/${addressId}/set-default`, {
                    method: "PUT",
                    body: JSON.stringify({ companyId: companyId })
                });

                if (response.ok) {
                    showMessage('success', "Default Address Set Successfully!");
                    await fetchCompanies();
                    toggleCompanyDetails(companyId, addressId);
                } else {
                    const errorData = await response.json();
                    showMessage('error', errorData.error || "Failed to set default address.");
                }
            } catch (error) {
                console.error("Error setting default address:", error);
                showMessage('error', "An error occurred while setting the default address.");
            }
        }

        // ----------------- Notes Saving Functionality -----------------
        async function saveCompanyNotes() {
            if (!currentCompanyId) {
                console.warn("No company selected. Cannot save notes.");
                return;
            }

            const notesTextArea = document.getElementById('companyNotes');
            if (!notesTextArea) {
                console.error("Notes textarea not found.");
                return;
            }
            const notes = notesTextArea.value;

            try {
                const companyToUpdate = companies.find(c => c.id === currentCompanyId);

                if (!companyToUpdate) {
                    console.error("Company not found in local array for notes update:", currentCompanyId);
                    showMessage('error', "Error: Company data not found for notes update.");
                    return;
                }

                const updatedCompanyData = { ...companyToUpdate, notes: notes };

                const response = await apiFetch("/edit-company", {
                    method: "POST",
                    body: JSON.stringify(updatedCompanyData)
                });

                if (response.ok) {
                    showMessage('success', "Notes saved successfully!");
                    const companyIndex = companies.findIndex(c => c.id === currentCompanyId);
                    if (companyIndex !== -1) {
                        companies[companyIndex].notes = notes;
                    }
                } else {
                    const errorData = await response.json();
                    showMessage('error', errorData.error || "Failed to save notes.");
                }
            } catch (error) {
                console.error("Error saving notes:", error);
                showMessage('error', "An error occurred while saving the notes.");
            }
        }

        // ----------------- Settings Modal Functions -----------------
        async function openSettingsModal() {
            document.getElementById("settingsModal").style.display = "block";
            await loadSettings();
        }

        async function loadSettings() {
            try {
                const response = await apiFetch("/admin/settings");
                if (response.ok) {
                    const settings = await response.json();
                    document.getElementById("poEmail").value = settings.po_email || '';
                    document.getElementById("poSms").value = settings.po_sms || '';
                    document.getElementById("registrationEmail").value = settings.registration_email || '';
                    document.getElementById("registrationSms").value = settings.registration_sms || '';
                    document.getElementById("loginEmail").value = settings.login_email || '';
                    document.getElementById("loginSms").value = settings.login_sms || '';
                } else {
                    const errorData = await response.json();
                    showMessage('error', errorData.error || "Failed to load settings.");
                }
            } catch (error) {
                console.error("Error loading settings:", error);
                showMessage('error', "An error occurred while loading settings.");
            }
        }

        async function saveSettings() {
            const poEmail = document.getElementById("poEmail").value.trim();
            const poSms = document.getElementById("poSms").value.trim();
            const registrationEmail = document.getElementById("registrationEmail").value.trim();
            const registrationSms = document.getElementById("registrationSms").value.trim();
            const loginEmail = document.getElementById("loginEmail").value.trim();
            const loginSms = document.getElementById("loginSms").value.trim();

            const settingsData = {
                po_email: poEmail,
                po_sms: poSms,
                registration_email: registrationEmail,
                registration_sms: registrationSms,
                login_email: loginEmail,
                login_sms: loginSms
            };

            try {
                const response = await apiFetch("/admin/settings", {
                    method: "POST",
                    body: JSON.stringify(settingsData)
                });

                if (response.ok) {
                    showMessage('success', "Settings saved successfully!");
                    closeModal('settingsModal');
                } else {
                    const errorData = await response.json();
                    showMessage('error', errorData.error || "Failed to save settings.");
                }
            } catch (error) {
                console.error("Error saving settings:", error);
                showMessage('error', "An error occurred while saving settings.");
            }
        }

        async function refreshDashboardSummary() {
            // Pending/Approved/Denied come from the already-fetched companies list — no extra call needed.
            const pendingCountEl = document.getElementById('summaryPendingApprovalCount');
            const approvedCountEl = document.getElementById('summaryApprovedCount');
            const deniedCountEl = document.getElementById('summaryDeniedCount');
            if (pendingCountEl) pendingCountEl.textContent = companies.filter(c => !c.approved && !c.denied).length;
            if (approvedCountEl) approvedCountEl.textContent = companies.filter(c => c.approved).length;
            if (deniedCountEl) deniedCountEl.textContent = companies.filter(c => c.denied).length;

            // Abandoned carts: count + total value across all carts.
            try {
                const cartsResponse = await apiFetch('/admin/abandoned-carts-report');
                const carts = await cartsResponse.json();
                const cartsCountEl = document.getElementById('summaryAbandonedCartsCount');
                const cartsValueEl = document.getElementById('summaryAbandonedCartsValue');
                if (cartsCountEl) cartsCountEl.textContent = carts.length;
                if (cartsValueEl) {
                    const totalValue = carts.reduce((sum, c) => sum + (parseFloat(c.total) || 0), 0);
                    cartsValueEl.textContent = `($${totalValue.toFixed(2)})`;
                }
            } catch (error) {
                console.error('Error loading abandoned carts summary:', error);
            }

            // Orders in the last 7 days.
            try {
                const end = new Date();
                const start = new Date();
                start.setDate(start.getDate() - 6);
                const startStr = toDateInputValue(start);
                const endStr = toDateInputValue(end);
                const ordersResponse = await apiFetch(`/admin/orders-report?startDate=${startStr}&endDate=${endStr}`);
                const orders = await ordersResponse.json();
                const ordersCountEl = document.getElementById('summaryOrdersWeekCount');
                const ordersValueEl = document.getElementById('summaryOrdersWeekValue');
                if (ordersCountEl) ordersCountEl.textContent = orders.length;
                if (ordersValueEl) {
                    const totalValue = orders.reduce((sum, o) => sum + computeOrderTotal(o), 0);
                    ordersValueEl.textContent = `($${totalValue.toFixed(2)})`;
                }
            } catch (error) {
                console.error('Error loading orders summary:', error);

            }

            updateLastUpdatedTimestamp();
        }

        function updateLastUpdatedTimestamp() {
            const el = document.getElementById('lastUpdated');
            if (!el) return;
            const now = new Date();
            const timeStr = now.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true });
            el.textContent = `Last updated: ${timeStr}`;
        }

        async function fetchCompaniesAndInitializeDashboard() {
            await fetchCompanies();
            await populateLogoDropdowns(); // populate logo dropdowns from logos.php via server

            const initialMessage = document.getElementById("initialDetailsMessage");
            const dynamicContentDiv = document.getElementById("dynamicCompanyContent");
            const approvalStatusDropdown = document.getElementById("approvalStatusDropdown");
            const tabsAndLogoContainer = document.getElementById('tabsAndLogoContainer');
            const tabContentContainer = document.getElementById('tabContentContainer');

            if (companies.length > 0) {
                if (initialMessage) {
                    initialMessage.style.display = 'none';
                }
                const companyOneExists = companies.some(c => c.id === 1);
                if (companyOneExists) {
                    toggleCompanyDetails(1);
                } else {
                    toggleCompanyDetails(companies[0].id);
                }
            } else {
                if (initialMessage) {
                    initialMessage.style.display = 'block';
                    initialMessage.textContent = "No companies found. Create a new company to get started.";
                }
                if (dynamicContentDiv) {
                    dynamicContentDiv.innerHTML = "";
                }
                if (approvalStatusDropdown) {
                    approvalStatusDropdown.style.display = 'none';
                }
                if (tabsAndLogoContainer) {
                    tabsAndLogoContainer.style.display = 'none';
                }
                 if (tabContentContainer) {
                    tabContentContainer.style.display = 'none';
                }
            }
        }
        
        // ------------- Order History Tab Functions ---------------
        
        async function loadOrderHistoryForCompany(companyId) {
            // Populate shipping address search dropdown
            const searchDropdown = document.getElementById("adminOrderSearchShipToAddress");
            searchDropdown.innerHTML = '<option value="">All Shipping Addresses</option>';
            if (currentAddresses && currentAddresses.length > 0) {
                currentAddresses.forEach(address => {
                    const option = document.createElement("option");
                    option.value = address.id;
                    option.textContent = address.name;
                    searchDropdown.appendChild(option);
                });
            }
            // Clear previous search and fetch orders
            clearCompanyOrderSearch();
        }

        function searchCompanyOrders() {
            const poNumber = document.getElementById('adminOrderSearchPoNumber').value.trim();
            const shipToAddress = document.getElementById('adminOrderSearchShipToAddress').value;
            const startDate = document.getElementById('adminOrderSearchStartDate').value;
            const endDate = document.getElementById('adminOrderSearchEndDate').value;
            
            const filters = {};
            if (poNumber) filters.poNumber = poNumber;
            if (shipToAddress) filters.shipToAddress = shipToAddress;
            if (startDate) filters.startDate = startDate;
            if (endDate) filters.endDate = endDate;
            
            fetchCompanyOrderHistory(currentCompanyId, filters);
        }

        function clearCompanyOrderSearch() {
            document.getElementById('adminOrderSearchPoNumber').value = '';
            document.getElementById('adminOrderSearchShipToAddress').value = '';
            document.getElementById('adminOrderSearchStartDate').value = '';
            document.getElementById('adminOrderSearchEndDate').value = '';
            fetchCompanyOrderHistory(currentCompanyId);
        }

        async function fetchCompanyOrderHistory(companyId, filters = {}) {
            if (!companyId) return;

            const tableBody = document.querySelector('#adminOrderHistoryTable tbody');
            const noOrdersMessage = document.getElementById('adminNoOrdersMessage');
            tableBody.innerHTML = '';
            // Clear any previous grand total footer
            const existingTfoot = document.querySelector('#adminOrderHistoryTable tfoot');
            if (existingTfoot) existingTfoot.innerHTML = '';
            noOrdersMessage.style.display = 'none';
            let grandTotal = 0;

            const queryParams = new URLSearchParams(filters);

            try {
                const response = await apiFetch(`/api/orders/${companyId}?${queryParams.toString()}`);
                const orders = await response.json();

                if (orders.length === 0) {
                    noOrdersMessage.style.display = 'block';
                    return;
                }

                orders.forEach(order => {
                    const row = tableBody.insertRow();
                    row.className = 'order-row-item';
                    row.onclick = () => viewOrderDetails(order.id);

                    // FIX: Safely parse items whether the API returns them as an array or a JSON string
                    let parsedItems = order.items;
                    if (typeof parsedItems === 'string') {
                        try { parsedItems = JSON.parse(parsedItems); } catch(e) { parsedItems = []; }
                    }
                    if (!Array.isArray(parsedItems)) { parsedItems = []; }
                    const totalPrice = parsedItems.reduce((sum, item) => {
                        return sum + (parseFloat(item.lineTotal) || parseFloat(item.total) ||
                               (parseFloat(item.netPrice || 0) * parseInt(item.quantity || 0)) || 0);
                    }, 0);

                    grandTotal += totalPrice;

                    row.innerHTML = `
                        <td style="border: 1px solid #ddd; padding: 8px;">${new Date(order.date).toLocaleDateString()}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">${order.poNumber || ''}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">${order.orderedByName || ''}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">$${totalPrice.toFixed(2)}</td>
                    `;
                });

                // Add grand total row
                const tfoot = document.querySelector('#adminOrderHistoryTable tfoot') || document.createElement('tfoot');
                tfoot.innerHTML = `
                    <tr style="background-color: #f0f4ff; font-weight: bold;">
                        <td colspan="3" style="border: 1px solid #ddd; padding: 8px; text-align: right;">Customer Total:</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">$${grandTotal.toFixed(2)}</td>
                    </tr>
                `;
                if (!document.querySelector('#adminOrderHistoryTable tfoot')) {
                    document.getElementById('adminOrderHistoryTable').appendChild(tfoot);
                }
                
                // Add a check to refresh the activity feed after fetching orders
                await fetchActivityFeed(); 
                
            } catch (error) {
                console.error("Error fetching company order history:", error);
                noOrdersMessage.textContent = 'Failed to load order history.';
                noOrdersMessage.style.display = 'block';
            }
        }


        // ------------- Orders Report & Details Modal Functions ---------------

        let ordersReportData = [];
        let sortOrdersColumn = 'date';
        let sortOrdersDirection = 'desc';

        // Sums item.lineTotal across an order's line items (order.items is a JSON
        // array from the DB — same shape/logic showOrderDetailsModal uses).
        function computeOrderTotal(order) {
            let items = order.items;
            if (typeof items === 'string') {
                try { items = JSON.parse(items); } catch (e) { items = []; }
            }
            if (!Array.isArray(items)) items = [];
            return items.reduce((sum, item) => sum + (parseFloat(item.lineTotal) || 0), 0);
        }

        function openOrdersReportModal() {
            document.getElementById('ordersReportStartDate').valueAsDate = new Date(1970, 0, 1);
            document.getElementById('ordersReportEndDate').valueAsDate = new Date();

            document.getElementById('ordersReportLoading').style.display = 'none';
            document.getElementById('ordersReportResults').style.display = 'none';
            const ordersFilterEl = document.getElementById('ordersReportFilter');
            if (ordersFilterEl) ordersFilterEl.value = '';
            document.getElementById('ordersReportModal').style.display = 'block';
            generateOrdersReport(); // auto-load all on open
        }

        function applyOrdersReportPreset(days) {
            const end = new Date();
            const start = new Date();
            start.setDate(start.getDate() - (days - 1));
            document.getElementById('ordersReportStartDate').valueAsDate = start;
            document.getElementById('ordersReportEndDate').valueAsDate = end;
            generateOrdersReport();
        }

        function applyOrdersReportPresetThisMonth() {
            const now = new Date();
            const start = new Date(now.getFullYear(), now.getMonth(), 1);
            document.getElementById('ordersReportStartDate').valueAsDate = start;
            document.getElementById('ordersReportEndDate').valueAsDate = now;
            generateOrdersReport();
        }

        function applyOrdersReportPresetAll() {
            document.getElementById('ordersReportStartDate').valueAsDate = new Date(1970, 0, 1);
            document.getElementById('ordersReportEndDate').valueAsDate = new Date();
            generateOrdersReport();
        }

        async function generateOrdersReport() {
            const startDate = document.getElementById('ordersReportStartDate').value;
            const endDate = document.getElementById('ordersReportEndDate').value;

            if (!startDate || !endDate) {
                return showMessage('error', 'Please select both a start and end date.');
            }
            if (new Date(startDate) > new Date(endDate)) {
                return showMessage('error', 'Start date cannot be after the end date.');
            }

            const loadingEl = document.getElementById('ordersReportLoading');
            document.getElementById('ordersReportResults').style.display = 'none';
            document.getElementById('noOrdersReportMessage').style.display = 'none';
            loadingEl.style.display = 'block';

            try {
                const response = await apiFetch(`/admin/orders-report?startDate=${startDate}&endDate=${endDate}`);
                ordersReportData = await response.json();
                ordersReportData.forEach(o => { o.computedTotal = computeOrderTotal(o); });
                sortOrdersColumn = 'date';
                sortOrdersDirection = 'desc';
                sortOrdersReportData();
                const ordersFilterEl = document.getElementById('ordersReportFilter');
                if (ordersFilterEl) ordersFilterEl.value = '';
                displayOrdersReport();
            } catch (error) {
                showMessage('error', 'Failed to generate orders report.');
                console.error("Error generating orders report:", error);
            } finally {
                loadingEl.style.display = 'none';
            }
        }

        function sortOrdersReport(column) {
            if (sortOrdersColumn === column) {
                sortOrdersDirection = sortOrdersDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortOrdersColumn = column;
                sortOrdersDirection = 'asc';
            }
            sortOrdersReportData();
            filterOrdersReportDisplay();
        }

        function sortOrdersReportData() {
            ordersReportData.sort((a, b) => {
                let valA = a[sortOrdersColumn];
                let valB = b[sortOrdersColumn];

                if (sortOrdersColumn === 'date') {
                    valA = new Date(valA);
                    valB = new Date(valB);
                }

                let comparison = 0;
                if (valA > valB) {
                    comparison = 1;
                } else if (valA < valB) {
                    comparison = -1;
                }
                return sortOrdersDirection === 'asc' ? comparison : comparison * -1;
            });
        }


        function displayOrdersReport() {
            renderOrdersReportTable(ordersReportData);
        }

        function filterOrdersReportDisplay() {
            const q = document.getElementById('ordersReportFilter').value.toLowerCase().trim();
            const filtered = q
                ? ordersReportData.filter(o =>
                    (o.companyName    || '').toLowerCase().includes(q) ||
                    (o.poNumber       || '').toLowerCase().includes(q) ||
                    (o.orderedByName  || '').toLowerCase().includes(q))
                : ordersReportData;
            renderOrdersReportTable(filtered);
        }

        function renderOrdersReportTable(data) {
            const tableBody = document.getElementById('ordersReportTableBody');
            const noResultsMessage = document.getElementById('noOrdersReportMessage');
            const resultsContainer = document.getElementById('ordersReportResults');
            const summaryBar = document.getElementById('ordersReportSummaryBar');

            tableBody.innerHTML = '';

            document.querySelectorAll('.sortable-header').forEach(header => {
                header.classList.remove('asc', 'desc');
                if (header.getAttribute('onclick') === `sortOrdersReport('${sortOrdersColumn}')`) {
                    header.classList.add(sortOrdersDirection);
                }
            });

            if (summaryBar) {
                const totalValue = data.reduce((sum, o) => sum + (parseFloat(o.computedTotal) || 0), 0);
                summaryBar.textContent = `${data.length} order${data.length === 1 ? '' : 's'} · $${totalValue.toFixed(2)} total`;
            }

            if (data.length === 0) {
                noResultsMessage.style.display = 'block';
                tableBody.style.display = 'none';
            } else {
                noResultsMessage.style.display = 'none';
                tableBody.style.display = '';
                data.forEach(order => {
                    const row = tableBody.insertRow();
                    row.style.cursor = 'pointer';
                    row.onclick = () => viewOrderDetails(order.id);

                    const loginDate = new Date(order.date);
                    row.insertCell(0).textContent = loginDate.toLocaleDateString();
                    row.insertCell(1).textContent = order.companyName;
                    row.insertCell(2).textContent = order.poNumber;
                    const totalCell = row.insertCell(3);
                    totalCell.textContent = `$${(parseFloat(order.computedTotal) || 0).toFixed(2)}`;
                    totalCell.style.textAlign = 'right';
                    totalCell.style.paddingRight = '24px';
                    row.insertCell(4).textContent = order.orderedByName;
                });
            }
            resultsContainer.style.display = 'block';
        }

        async function viewOrderDetails(orderId) {
            try {
                const response = await apiFetch(`/admin/order-details/${orderId}`);
                const orderDetails = await response.json();
                showOrderDetailsModal(orderDetails);
            } catch (error) {
                showMessage('error', 'Could not load order details.');
                console.error('Error fetching order details:', error);
            }
        }

        // ------------- Users Report Functions ---------------

        let usersReportData = [];
        let sortUsersColumn = 'last_name';
        let sortUsersDirection = 'asc';

        async function openUsersReportModal() {
            try {
                const filterEl = document.getElementById('usersReportFilter');
                if (filterEl) filterEl.value = '';

                const response = await apiFetch(`/admin/users-report`);
                usersReportData = await response.json();

                sortUsersColumn = 'last_name';
                sortUsersDirection = 'asc';

                sortUsersReportData();
                displayUsersReport();

                document.getElementById('usersReportModal').style.display = 'block';

            } catch (error) {
                showMessage('error', 'Failed to generate users report.');
                console.error("Error generating users report:", error);
            }
        }

        function sortUsersReport(column) {
            if (sortUsersColumn === column) {
                sortUsersDirection = sortUsersDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortUsersColumn = column;
                sortUsersDirection = 'asc';
            }
            sortUsersReportData();
            filterUsersReportDisplay();
        }

        function sortUsersReportData() {
            usersReportData.sort((a, b) => {
                let valA = a[sortUsersColumn];
                let valB = b[sortUsersColumn];

                if (sortUsersColumn === 'created_at') {
                    valA = new Date(valA);
                    valB = new Date(valB);
                } else {
                    valA = valA ? String(valA).toLowerCase() : '';
                    valB = valB ? String(valB).toLowerCase() : '';
                }

                let comparison = 0;
                if (valA > valB) {
                    comparison = 1;
                } else if (valA < valB) {
                    comparison = -1;
                }
                return sortUsersDirection === 'asc' ? comparison : comparison * -1;
            });
        }

        function displayUsersReport() {
            const filterEl = document.getElementById('usersReportFilter');
            if (filterEl) filterEl.value = '';
            renderUsersReportTable(usersReportData);
        }

        function filterUsersReportDisplay() {
            const q = document.getElementById('usersReportFilter').value.toLowerCase().trim();
            const filtered = q
                ? usersReportData.filter(u =>
                    `${u.first_name || ''} ${u.last_name || ''}`.toLowerCase().includes(q) ||
                    (u.email       || '').toLowerCase().includes(q) ||
                    (u.companyName || '').toLowerCase().includes(q))
                : usersReportData;
            renderUsersReportTable(filtered);
        }

        function renderUsersReportTable(data) {
            const tableBody = document.getElementById('usersReportTableBody');
            const noResultsMessage = document.getElementById('noUsersReportMessage');
            const resultsContainer = document.getElementById('usersReportResults');
            const summaryBar = document.getElementById('usersReportSummaryBar');

            tableBody.innerHTML = '';

            document.querySelectorAll('#usersReportModal .sortable-header').forEach(header => {
                header.classList.remove('asc', 'desc');
                if (header.getAttribute('onclick') === `sortUsersReport('${sortUsersColumn}')`) {
                    header.classList.add(sortUsersDirection);
                }
            });

            if (summaryBar) {
                summaryBar.textContent = `${data.length} user${data.length === 1 ? '' : 's'}`;
            }

            if (data.length === 0) {
                noResultsMessage.style.display = 'block';
            } else {
                noResultsMessage.style.display = 'none';
                data.forEach(user => {
                    const row = tableBody.insertRow();

                    row.style.cursor = 'pointer';
                    row.onclick = () => {
                        editUser(user.id);
                        closeModal('usersReportModal');
                    };

                    row.insertCell(0).textContent = `${user.last_name || ''}, ${user.first_name || ''}`;
                    row.insertCell(1).textContent = user.email;
                    row.insertCell(2).textContent = user.companyName;

                    const dateCell = row.insertCell(3);
                    if (user.created_at) {
                        const date = new Date(user.created_at);
                        const month = String(date.getMonth() + 1).padStart(2, '0');
                        const day = String(date.getDate()).padStart(2, '0');
                        const year = date.getFullYear();
                        dateCell.textContent = `${month}/${day}/${year}`;
                    } else {
                        dateCell.textContent = 'N/A';
                    }
                    dateCell.style.textAlign = 'center';
                });
            }
            resultsContainer.style.display = 'block';
        }

        function downloadUsersReportCSV() {
            const q = document.getElementById('usersReportFilter') ? document.getElementById('usersReportFilter').value.toLowerCase().trim() : '';
            const data = q
                ? usersReportData.filter(u =>
                    `${u.first_name || ''} ${u.last_name || ''}`.toLowerCase().includes(q) ||
                    (u.email       || '').toLowerCase().includes(q) ||
                    (u.companyName || '').toLowerCase().includes(q))
                : usersReportData;
            if (!data.length) return;

            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += "Last Name,First Name,Email,Company,Date Created\n";
            data.forEach(user => {
                const created = user.created_at ? new Date(user.created_at).toLocaleDateString('en-US') : '';
                const row = [
                    user.last_name || '',
                    user.first_name || '',
                    user.email || '',
                    user.companyName || '',
                    created
                ].map(field => `"${String(field).replace(/"/g, '""')}"`).join(',');
                csvContent += row + '\n';
            });

            const encodedUri = encodeURI(csvContent);
            const link = document.createElement('a');
            link.setAttribute('href', encodedUri);
            link.setAttribute('download', `users_report_${new Date().toISOString().split('T')[0]}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        // --- Helper functions for Order Details Modal (Copied from customer-portal.html) ---

        function escapeHTML(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function getTimeZoneAbbreviation(date) {
            const year = date.getFullYear();
            const dstStart = new Date(year, 2, 1);
            dstStart.setDate(dstStart.getDate() + (14 - dstStart.getDay()) % 7);
            const dstEnd = new Date(year, 10, 1);
            dstEnd.setDate(dstEnd.getDate() + (7 - dstEnd.getDay()) % 7);
            return (date > dstStart && date < dstEnd) ? 'EDT' : 'EST';
        }

        function showOrderDetailsModal(order) {
            // --- Parse date/time ---
            const orderDate = new Date(order.date);
            const tzAbbr = getTimeZoneAbbreviation(orderDate);
            const dateStr = orderDate.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
            const timeStr = orderDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) + ' ' + tzAbbr;

            // --- Parse items safely ---
            let orderItems = order.items;
            if (typeof orderItems === 'string') {
                try { orderItems = JSON.parse(orderItems); } catch(e) { orderItems = []; }
            }
            if (!Array.isArray(orderItems)) orderItems = [];

            let totalQty = 0;
            let grandTotal = 0;

            const itemsHtml = orderItems.map(item => {
                const qty   = parseInt(item.quantity) || 0;
                const net   = parseFloat(item.netPrice) || 0;
                const line  = parseFloat(item.lineTotal) || 0;
                totalQty  += qty;
                grandTotal += line;
                return `
                    <tr>
                        <td style="border:1px solid #ccc;padding:8px;text-align:center;vertical-align:top;color:#000;">${qty}</td>
                        <td style="border:1px solid #ccc;padding:8px;text-align:left;font-size:14px;word-wrap:break-word;color:#000;"><strong>${escapeHTML(item.partNo || '')}</strong><br>${escapeHTML(item.description || '').replace('**', '<br>**')}${item.note ? `<div style="height:6px;"></div><small style="color:#555;">${escapeHTML(item.note).replace(/\n/g,'<br>')}</small>` : ''}</td>
                        <td style="border:1px solid #ccc;padding:8px;text-align:right;width:14%;vertical-align:top;color:#000;">$${net.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2})}</td>
                        <td style="border:1px solid #ccc;padding:8px;text-align:right;vertical-align:top;color:#000;">$${line.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2})}</td>
                    </tr>`;
            }).join('');

            // --- Rush / ship-via styling ---
            const methodLower = (order.shippingMethod || '').toLowerCase();
            const isRush = methodLower.includes('next day air') || methodLower.includes('saturday') || methodLower.includes('overnight');
            const shipViaStyle = isRush ? 'background-color:yellow;border-radius:3px;padding:1px 4px;' : '';

            const hasCarrier = order.carrierAccount && order.carrierAccount.trim() !== '';
            const carrierHtml = hasCarrier
                ? `<p style="margin:7px 0 0;font-size:12px;color:#000;"><strong>Carrier Account#:</strong> ${escapeHTML(order.carrierAccount)}</p>`
                : '';

            let thirdPartyHtml = '';
            if (order.shippingAccountType === 'Third Party Billing' && order.thirdPartyDetails) {
                const tp = order.thirdPartyDetails;
                const notUS = tp.third_party_country &&
                    !['USA','United States','United States of America'].includes(tp.third_party_country.trim());
                thirdPartyHtml = `
                    <p style="font-weight:bold;margin:8px 0 3px;font-size:12px;color:#000;">Third Party Billing:</p>
                    <p style="margin:0;font-size:12px;line-height:1.4;color:#000;">${escapeHTML(tp.third_party_name||'')}</p>
                    <p style="margin:0;font-size:12px;line-height:1.4;color:#000;">${escapeHTML(tp.third_party_address1||'')}</p>
                    <p style="margin:0;font-size:12px;line-height:1.4;color:#000;">${escapeHTML(tp.third_party_city||'')}, ${escapeHTML(tp.third_party_state||'')} ${escapeHTML(tp.third_party_zip||'')}</p>
                    ${notUS ? `<p style="margin:0;font-size:12px;line-height:1.4;color:#000;">${escapeHTML(tp.third_party_country)}</p>` : ''}`;
            }

            const phoneHtml = (order.orderedByPhone && order.orderedByPhone.trim())
                ? `Phone: ${escapeHTML(order.orderedByPhone)}` : '';

            const docHtml = `
                <div style="font-family:Arial,sans-serif;color:#000;position:relative;padding-top:10px;">
                    <table style="width:100%;border-collapse:collapse;margin-bottom:5px;">
                        <tr>
                            <td style="width:95px;text-align:left;vertical-align:middle;padding:0;">
                                <img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wAARCAC7AZADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD9U6KKKACiqOt63YeG9Ju9U1S8hsNPtIzLPc3DhUjUdSSa+BP2g/23tX8ZzXOh+A5Z9D0HmOTUxlLu7Hfb3hQ+3znuV6VyYjFU8NG83r2PrOH+Gcw4kr+zwkbRXxSfwx/zfZLX5an1d8Wv2ofAXwfaW01PUzqGsoP+QTpoE04P+3yFj/4EQfY18m+Pf+CgnjbXZJIvDGm2Hhi1z8ssq/a7nH1bCD/vk/WvlpmLszMSzMSzMTkknqSe596Svma2Y16vwvlXl/mf0vk/h1kuWRUsRD29TvLb5R2t683qdv4j+N/xB8Wlv7W8Z61dI3WIXjRR/wDfEe1f0rjZ7qe6fdPPLOx53SyFz+ZNRUV5spSlrJ3P0mhhcPhY8tCmoLskl+QUUUVJ0hRRRQAUUUUAFfcH/BNv/jy+IH/XWx/9Bmr4fr7g/wCCbf8Ax5fED/rrY/8AoM1ejl3+8x+f5M/OPET/AJJnE/8Abn/pyJ9p0UUV9ofxiFeRfG79pvwh8EIjb6hO2p6+ybotGsiDNg9GkJ4jU+rcnsDXF/tbftQD4Qacvhzw5LHL4wvYt5kIDLp8J6SMOhc87VPpuPAAP5y6hqF1qt9cXt7cS3l5cSGWa4ncvJI56szHkk+teLjcw9i/Z0tZfkftXBnADzmnHMMybjRfwxWjn536R/F9LaN+8fEP9t34leNZpY9NvovCensflg0pQZsdt0zAtn/dC14nrPinWvEU7TarrGoanK3V7y7klJ/76JrLor5mpWqVXecmz+lMBk+X5ZBQwVCMEuyV/m9382FFFFZHrhRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABX0H+wp/wAnC6f/ANg28/8AQVr58r6D/YU/5OF0/wD7Bt5/6CtdWE/jw9UfLcVf8iLG/wDXuf5M/TCq2paja6Rp9zfXs8drZ20bTTTysFSNFGWYk9AAM1Zr4e/b1+O7y3K/DXRrgrCgSfWpIz98nDR2/wBOjsPdB619lia8cPTc2fxxw7kdbiHMIYGjonrJ/wAsVu/0XdtI8j/ag/aXv/jdrzadpsstp4Mspc2ttypu3H/LeUf+gqfujnqTjwmiivh6lSVWTnN3bP7dy3LcNlOFhg8JDlhH8e7fdvqwooorM9MKKnsbC51S7S0sraa8un+5BbxtJI30VQSa9D0z9mr4p6vEJLfwHrIQjINxCsGR9JGU1cYTn8KbOLE47C4O31mrGF/5pJfm0ea0V6x/wyj8XP8AoRdR/wC/sH/xyj/hlH4uf9CLqP8A39g/+OVfsK38j+5nB/buU/8AQXT/APBkf8zyeivWP+GUfi5/0Iuo/wDf2D/45R/wyj8XP+hF1H/v7B/8co9hW/kf3MP7dyn/AKC6f/gyP+Z5PRXrH/DKPxc/6EXUf+/sH/xyj/hlH4uf9CLqP/f2D/45R7Ct/I/uYf27lP8A0F0//Bkf8zyevuD/AIJt/wDHl8QP+utj/wCgzV87/wDDKPxc/wChF1H/AL+wf/HK+sv2FvhX4s+GVr4zTxTodxorXslobcTsh8wKsu7G1j03Dr616GApVI4iLlFpa9PI/P8Aj3NsuxXDuIpUMRCcnyWSnFt+/F7J32PqmuX+J3j2y+GPgLW/E9/80GnW7SiPODK/RIx7sxVfxrqK+Pf+Ci/jJ7Lwp4W8LwyYGoXUl7cKO6QqAgPtvkz/AMBr6bE1fY0ZVOx/NfDeVrOs2w+Bl8Mpa/4VrL8Ez4j8VeJ9S8aeJNS13V7g3Op6hO1xPIem49h6KBhQOwAFZVFFfBttu7P7tp040oKnBWSVklsktkFFFa/hfwjrfjbVF03QNJvNZv2Xd9nsoTIwX+8ccKPc4FNJt2QVKkKUXOo0ordvRL5mRRXq/wDwyn8Wz/zIuo/9/If/AI5R/wAMp/Fv/oRdR/7+Qf8AxytfYVv5H9zPG/t3Kf8AoLp/+DI/5nlFFer/APDKfxb/AOhF1H/v5B/8co/4ZT+Lf/Qi6j/38g/+OUewrfyP7mH9u5T/ANBdP/wZH/M8oor1f/hlP4t/9CLqP/fyD/45R/wyn8W/+hF1H/v5B/8AHKPYVv5H9zD+3cp/6C6f/gyP+Z5RRXq//DKfxb/6EXUf+/kH/wAco/4ZT+Lf/Qi6j/38g/8AjlHsK38j+5h/buU/9BdP/wAGR/zPKKK9X/4ZT+Lf/Qi6j/38g/8AjlH/AAyn8W/+hF1H/v5B/wDHKPYVv5H9zD+3cp/6C6f/AIMj/meUUV6v/wAMp/Fv/oRdR/7+Qf8Axyj/AIZT+Lf/AEIuo/8AfyD/AOOUewrfyP7mH9u5T/0F0/8AwZH/ADPKKK7Hxz8HvGfw0tLW68UeH7nRYLqQxQvcPGRI4G4gbWJ6c1x1ZyjKLtJWZ6lDEUcVTVXDzU4vrFpr71oFFFFSdAUVe0PQdS8TapBpukafc6pqE5xFa2cTSSP64Ufz6CvSE/ZV+LbqGHgTUgCM8vCD+XmVpGnOesYt/I8/E5jgsHJRxNeEG/5pKP5tHlNFer/8Mp/Fv/oRdR/7+Qf/AByj/hlP4t/9CLqP/fyD/wCOVXsK38j+5nH/AG7lP/QXT/8ABkf8zyiivV/+GU/i3/0Iuo/9/IP/AI5R/wAMp/Fv/oRdR/7+Qf8Axyj2Fb+R/cw/t3Kf+gun/wCDI/5nlFFer/8ADKfxb/6EXUf+/kH/AMco/wCGU/i3/wBCLqP/AH8g/wDjlHsK38j+5h/buU/9BdP/AMGR/wAzyiivV/8AhlP4t/8AQi6j/wB/IP8A45R/wyn8W/8AoRdR/wC/kH/xyj2Fb+R/cw/t3Kf+gun/AODI/wCZ5RX0H+wp/wAnC6f/ANg28/8AQVrk/wDhlP4t/wDQi6j/AN/IP/jle0/sh/Af4geAfjVZav4h8LXmlaYljdRNczPEVDMq7R8rk849K6sNRqqvBuL3XRnzXE2c5ZWyXF06eKpyk6ckkpxbbs9kmfZnxN8c2vw18A674mvAGh021ecRn/lo/RE/4ExVfxr8gdc1q98Sa1f6tqUxuNQvp3ubiU/xyOxZj+Z/LFfdv/BRLxq2m+BfDvhiGTa+q3jXU4B5MUAGAfYu6H/gNfAldWaVXOqqa2X5s+X8LcpjhcrnmEl71Zu3+GOn/pV7/IKKKK8U/aQr6U/Zt/Y61H4tW8HiLxNLPovhR8NAkY23N+PVM/cj/wBsjJ/hGPmrB/ZF+BMfxm+IDXGqwmTwxouye9Q9LiQn93B9Dgs3+yuP4q/TqGGO3hSKJFjjRQqogwFA4AA7CvbwGBVZe1qbdF3PxDj7jarlEv7My12rNXlL+VPZL+81rforW1d1zXgT4Y+Fvhnpi2HhnRLTSYMYZoU/eSe7yHLOfck10+B6UtFfURioq0VZH8v1q9XEVHVrScpPdt3b9WxMD0FGB6CloqjETA9BRgegpaKAEwPQUYHoKWigBMD0FGMUtFABX58f8FFLlpPiv4bgOQkWi7xnplp5M4/75FfoPXwh/wAFHdBki8U+DNawfJns7iyLdgyOrgflIfyry8yTeGdvL8z9Q8NpxhxHRUusZpevK3+SZ8d0UUV8cf2KA5Nfp1+xZ4J0vwv8CNC1GzhQ3+tob69uQBukYswVSfRFAAHrk9zX5i19Qfsvftgx/CHQx4W8UWd1f+H45GktLqzAea03EsyFCRuQsSwwcgk8EYx6eX1adGtzVOx+Z+IOVY/N8o9jl6cpRkpOK3kkn99m07dbd7H6JYHoKMD0FfO//DeXwo/5/tV/8FctH/DeXwo/5/tV/wDBXLX0/wBbw/8AOvvP5i/1Tz7/AKAqn/gD/wAj6IwPQUYHoK+d/wDhvL4Uf8/2q/8Agrlo/wCG8vhR/wA/2q/+CuWj63h/5194f6p59/0BVP8AwB/5H0RgegowPQV87/8ADeXwo/5/tV/8FctH/DeXwo/5/tV/8FctH1vD/wA6+8P9U8+/6Aqn/gD/AMj6IwPQUYHoK8P0X9tL4R6y4Q+JzpznoNQs5oR/30V2j869c8O+K9F8XWIvdE1Wy1e0P/LexuFmT8SpOK1hVp1PgkmeRjMpzDL9cZQnTX96LS+9o1MD0FGB6ClorY8oTA9BRgegpaKAPiX/AIKR3LbfAFsOE3XspHviED+Zr4mr7T/4KR/8fvgH/rnffzhr4sr4vMP95n8vyR/aPh8kuGsLb+//AOlyCiiivOP0Q/Q//gn94H03SvhRceJlgR9X1a8mikuCPmWGJtixg9hkMx9Seegr6j2j0FfD37L37VPgL4UfCKw8Pa/dX8Wpw3NzK6QWLypteUsuGHHQivWf+G8vhR/z/ar/AOCuWvsMLiKFOhCLklofx9xRw/nuPzrFYiOFqTi5uz5W04p2jbTa1rH0RgegowPQV87/APDeXwo/5/tV/wDBXLR/w3l8KP8An+1X/wAFctdX1vD/AM6+8+X/ANU8+/6Aqn/gD/yPojA9BRgegr53/wCG8vhR/wA/2q/+CuWj/hvL4Uf8/wBqv/grlo+t4f8AnX3h/qnn3/QFU/8AAH/kfRGB6CjA9BXzv/w3l8KP+f7Vf/BXLR/w3l8KP+f7Vf8AwVy0fW8P/OvvD/VPPv8AoCqf+AP/ACPojA9BRgegr53/AOG8vhR/z/ar/wCCuWj/AIby+FH/AD/ar/4K5aPreH/nX3h/qnn3/QFU/wDAH/kfRGB6CjAHavnf/hvL4Uf8/wBqv/grlrqfhr+1T4C+K/iqLw9oF1fy6lJFJMq3Fi8S7UALfMeO9VHE0JNRjNX9TCvw1nWGpSrVsJUjGKu24tJJdXofJP8AwUG1w6j8adO08NmPTtHiG30aSSRifyC/lXzFXvf7cTs37RuuBiSFs7ML9PJB/mTXglfHYt3xE2+5/YfCVKNHIcFGP/PuL+9Xf4sKB1opspIicjrtP8q5D64/UT9jPwPF4M+Amgy+XsvNYDarcMRyTIf3f5RhBXuNcv8ACyOKH4ZeEo4eYV0i0CEd18lMV1Fff0YqFOMV0R/AOc4qeNzLEYmpvKcn+L0+WwUUUVseOFFFFABRRRQAUUUUAFFFFABXhH7Z3w0k+InwU1CWzhM2p6JINUt1UZZ1QESqPrGWOPVRXu9Iyh1KsAQeCDWVWmqsHB9T08sx9XK8bSxtH4qck/W269GtGfibweQcg9CKK97/AGtf2fJ/g540k1TTLZj4Q1eZntHQfLaynJa3b07lPVeOqmvBK+Eq05UZuEt0f3flmZYfNsJTxuFleE1f07p+aejCiiisj0wooooAKKKKACiiigAzitPw54n1fwfqkepaFqd3o9+hyLiymMT/AEOPvD2ORWZRQm07oicIVIuE1dPdPVM+4PgD+3f9suLbQviT5UDuRHD4ghQJGT2+0IOF/wB9ePUDrX2hDNHcQpLE6yRuoZXQ5DA8ggjqK/E+vsD9iT9pKbRtUtPh34kujJpl03l6PdTNk28p6W5J/gb+H0b5ejDH0OBzCTkqVZ+j/wAz+e+N+AKMKM8zyiHK46ygtrdXFdLbuO1trWs/vOiiivpD+cT4f/4KR/8AH74B/wCud9/OGviyvtP/AIKR/wDH74B/653384a+LK+KzD/eZ/L8kf2l4ff8k1hP+3//AEuQUUUV55+hhRRRQAUUUUAFFFFABRRRQAUUUUAFfQf7Cn/Jwun/APYNvP8A0Fa+fK+g/wBhT/k4XT/+wbef+grXVhP48PVHy3FX/Iixv/Xuf5Mv/t+aO+n/AB2juyPkv9It5VPqUaRD/IV8219y/wDBRrwc02k+EfFMUZIt5pdNuHHYSASR/qjj/gVfDVa46HJiJrvr955nA2LjjOHsLJPWK5X/ANutr8kn8wo4PB6UUVwH3h+rH7KXjCPxn8BPCNyJA89paDTpxnlZID5eD9Qqn8RXrdfnj+wr8bofA3i+48HavcCHSNekVrSWRsLDeAbQD6CRQF/3lX1r9DetfbYKsq1GL6rRn8R8aZNUybOa1Nr3Jtzi+lpO9vk7r5C0UUV3nwwUUUUAFFFFABRRRQAUUUUAFFFFAGP4s8JaR458PXuh65Yxajpd4nlzW8o4I7EHqCDyCOQQCK/O74+/sa+Jfhdc3Oq+HYrjxL4VyXEkKb7q0XriVBywH99R9QK/SmkxXFicJTxK97fufZ8OcV4/hqq5YZ81OXxQez812fmvmmj8TRyMjkdOKK/V74i/sw/Dj4nTS3OreHYYNRk+9qGnMbacn1YpgMf94GvFNZ/4Jx+HbiZm0rxjq1jGeiXVtFcY/EbCa+eqZXXi/dsz+g8B4oZHiYL61zUpdbrmXycbt/NI+DKK+4P+HbVt/wBFBn/8FC//AB2j/h21bf8ARQZ//BQv/wAdrH+zsV/L+K/zPY/4iJwz/wBBP/klT/5E+H6K+4P+HbVt/wBFBn/8FC//AB2j/h21bf8ARQZ//BQv/wAdo/s7Ffy/iv8AMP8AiInDP/QT/wCSVP8A5E+H6K+4P+HbVt/0UGf/AMFC/wDx2g/8E2rbHHxBnz/2CF/+O0f2div5fxX+Yf8AEROGf+gn/wAkqf8AyJ8P0V7B8ev2ZPEvwHkt7q9mh1fQbqTyodUtUKBZMEiORDnYxAJHJBwec8V4/XDUpypS5ZqzPuMDj8LmeHjisHUU4S2a/q6fk9Qp0UjwyJJG7RSIwZXQ4ZWByCD2IPNNoqDv3P1n/Zy+J5+Lnwi0PXp3DakENrfgdriP5XP/AALh/owr0yvir/gnD4mdrbxr4edyUjkt9QiQngFg0b/+gJX2rX3OEqutQjN7n8McWZZHKM7xOEpq0VK68lJKSXyvb5Hw/wD8FI/+P3wD/wBc77+cNfFlfaf/AAUj/wCP3wD/ANc77+cNfFlfLZh/vM/l+SP6k8Pv+Sawn/b/AP6XIKKKK88/Qwor6d+A37GUPxp+HNp4pfxbLpDTzzQ/ZV09ZgvluVzuMi9cZ6V6H/w7atv+igz/APgoX/47XfDA4icVKMdH5r/M+CxfHXD+BxE8LiMRacG01yTdmtHqo2+4+H6K+4P+HbVt/wBFBn/8FC//AB2j/h21bf8ARQZ//BQv/wAdqv7OxX8v4r/M5f8AiInDP/QT/wCSVP8A5E+H6K+4P+HbVt/0UGf/AMFC/wDx2j/h21bf9FBn/wDBQv8A8do/s7Ffy/iv8w/4iJwz/wBBP/klT/5E+H6K+4P+HbVt/wBFBn/8FC//AB2j/h21bf8ARQZ//BQv/wAdo/s7Ffy/iv8AMP8AiInDP/QT/wCSVP8A5E+H6K+4P+HbVt/0UGf/AMFC/wDx2j/h21bf9FBn/wDBQv8A8do/s7Ffy/iv8w/4iJwz/wBBP/klT/5E+H6+g/2FP+ThdP8A+wbef+grXrv/AA7atv8AooM//goX/wCO13/wN/Yyh+CvxBt/FCeLZdXaK2mt/sraeIQfMAGdwkbpj0row+BxEKsZSjomuq/zPAz/AI64fx2U4nC4fEXnOEklyTV21pq42PVfjx8OF+K3wo8Q+HFVftdxb+ZZs38Nwh3xH2+ZQD7E1+R00MlvNJFNG0M0bFHjcYZGBwVPuCCPwr9r+tfnd+3L8D38E+Nj400u3I0PXpc3IQfLb3uMtn0EgG4f7Qf1Fdua4dyiq0em/ofFeFufRw1eplFd2VT3of4ktV80lb07s+XqKKK+ZP6bAHB44+lfcH7NP7bVsbO08MfEa78ieICK18Qy8pIOgW4P8LdvM6H+LB5Pw/RXTQxE8PLmgfN57w/geIcN9Wxsdvhkvii+6f5p6P7j9rbS8gv7aK5tpo7i3lUPHLE4ZHU9CCOCPpU1fkB4A+M3jb4XMB4Y8R3umW+7cbQMJLZj7xOCv5AGvZtJ/wCCgnxKsIQl1Y+H9TYD/WS2kkbH67JAP0r6GnmtKS99NP7z+ecf4V5tRm/qdSFSPS7cX807r8T9GaK/Pb/h4r4+/wChd8N/98XH/wAco/4eK+Pv+hd8N/8AfFx/8crb+08P3f3Hkf8AEM+Iv+fcf/A0foTRX57f8PFfH3/Qu+G/++Lj/wCOUf8ADxXx9/0Lvhv/AL4uP/jlH9p4fu/uD/iGfEX/AD7j/wCBo/Qmivz2/wCHivj7/oXfDf8A3xcf/HKP+Hivj7/oXfDf/fFx/wDHKP7Tw/d/cH/EM+Iv+fcf/A0foTRX57f8PFfH3/Qu+G/++Lj/AOOUf8PFfH3/AELvhv8A74uP/jlH9p4fu/uD/iGfEX/PuP8A4Gj9CaK/Pb/h4r4+/wChd8N/98XH/wAco/4eK+Pv+hd8N/8AfFx/8co/tPD939wf8Qz4i/59x/8AA0foTRX57f8ADxXx9/0Lvhv/AL4uP/jlH/DxXx9/0Lvhv/vi4/8AjlH9p4fu/uD/AIhnxF/z7j/4Gj9CaK/Pb/h4r4+/6F3w3/3xcf8Axyj/AIeK+Pv+hd8N/wDfFx/8co/tPD939wf8Qz4i/wCfcf8AwNH6E0V+e3/DxXx9/wBC74b/AO+Lj/45R/w8V8ff9C74b/74uP8A45R/aeH7v7g/4hnxF/z7j/4Gj9CaK/Pb/h4r4+/6F3w3/wB8XH/xyj/h4r4+/wChd8N/98XH/wAco/tPD939wf8AEM+Iv+fcf/A0foTRX57f8PFfH3/Qu+G/++Lj/wCOUH/gop4+IOPD3hsH18u4/wDjlH9p4fu/uD/iGfEX/PuP/gaPpX9ta9060/Z18Sx35TzbhreG0VurT+cjLt9wFY/QGvzAPWu9+LPxw8XfGnUoLrxLfrLDbZ+zWNsnlW8GepVcnLH+8xJ7ZxXBV89jcQsTV54rRaH9CcF8PVuG8s+q4ialOUnJ22V0lZd9Fr5hRRRXAfen1t/wTlV/+Fi+LWGdg0mIH6+dx/I19+18bf8ABOTwo9v4f8X+JJI8Jd3MNhC57iJS7/rKo/Cvsmvs8ui44aN/P8z+MvEOvCvxHiOT7PKvmoq/3PQ+Iv8AgpHCwm8AS4+Qi+TOO/7k18U1+hX/AAUM8KPqvwp0fXI1LHR9SXzCB92KZShP/fYj/Ovz1r5/MouOJk+9vyP6B8OK8a3DlCEd4OafrzOX5NBRRRXmH6YfpH+wRrNpf/AeKyhmVrqw1G5juIs/Mhd/MU49CrDB9j6V9IV+Pvww+Lfij4P662q+GNR+xyyqEngkTzILhR0WRD1xk4IwRk4Iya93T/gon8QFRQ3h/wANuwHLeXcDP4ebX0uFzGlClGFTRrQ/mnifw6zXGZpWxmAcZQqNy1dmm9WtfPaz2P0Lor89v+Hinj7/AKF3w1/3xcf/AB2j/h4p4+/6F3w1/wB8XH/x2uv+08P3f3Hyn/EM+Iv+fcf/AANH6E0V+e3/AA8U8ff9C74a/wC+Lj/47R/w8U8ff9C74a/74uP/AI7R/aeH7v7g/wCIZ8Rf8+4/+Bo/Qmivz2/4eKePv+hd8Nf98XH/AMdo/wCHinj7/oXfDX/fFx/8do/tPD939wf8Qz4i/wCfcf8AwNH6E0V+e3/DxTx9/wBC74a/74uP/jtH/DxTx9/0Lvhr/vi4/wDjtH9p4fu/uD/iGfEX/PuP/gaP0Jor89v+Hinj7/oXfDX/AHxcf/Ha9P8A2cP2wvFnxk+KNr4Z1fR9Gs7KW0nuDLZLMJAyAED5nIxz6VcMwoVJKEXq/I48b4f57gMNUxdeEVCCbfvJ6LVn11WH428GaT8QvC2o+Htbthd6ZfxGKWPoR3DKezKQCD2IFblFei0pKzPzulUnRnGrTdpRd01umtmj8kPjh8FNa+B/jKXR9TVrixlLSafqQXCXcWevs44DL2PPQg153X7E/Er4ZeH/AIs+FrjQfEVkLqzl+ZJFO2WCTHEkbfwsM9fwOQSK/Nf48/syeKPgdfSXE8bat4Zd8QazBH8qg9FmUf6tv/HT2PYfI4zAyoNzhrH8j+uODeOcPnlOOExslDErTsp+cfPvH5rTRePUUUV5J+shRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABVnTNNutY1G1sLG3e6vbqVYIIIxlpJGICqPqSKrfyr7u/Ys/Zin8NtB8QPFlm0GpOh/snT51w9ujDBncHo7A4UHlQSTyeOnDYeWIqKEfmfMcRZ/huHcDLF13eW0Y9ZS6L07vovkfRnwT+G0Pwl+GOheGYyrzWkG66lUcSzud0rfTcTj2AruaKK+6jFQiox2R/DWJxFXGV54is7zm22+7buznPiL4Ks/iL4H1vw1f8W2p2r25fGTGxHyuPdWCsPpX5B+KPDWoeDfEepaHq0Jt9S0+draeM/wB5T1HqCMEHuCK/Z+vlr9sn9mSb4lWR8Y+F7bzPE9lEEurOMfNqEC9NvrKnb+8Pl6ha8jMcK60FUhuvyP1nw54np5Ni5YHFytSqtWb2jLZN9k1o30sulz88aKc6NG7I6lHUlWVgQQQcEEHoQe1Nr5M/rMKKKKACiiigAooooAKKKKACiiigAr6D/YU/5OF0/wD7Bt5/6CtfPlfQf7Cn/Jwun/8AYNvP/QVrqwn8eHqj5bir/kRY3/r3P8mfphRRRX3Z/CYVDd2kF9bS29zDHcW8qlJIpVDI6nggg8EH0NTUUDTad0fK3xc/YI8MeLJJ9Q8G3f8AwimovljZshlsXPsud0X/AAEkf7NfJnj39lr4mfDx5GvvDFzqFmmT9u0gfa4iPUhRvX/gSiv1cpMV5VbLaFXVe6/L/I/Ucn8Rs6yuKpVZKtBdJ7/KS1++5+J0ym3laKUGKVTgxyDaw+oPNGCe1fszrngzQPE4xrGiadqoxj/TbSOb/wBCBrjLz9mj4WX0m+XwFoO7Ofks1T/0HFebLKJ/Zmj9IoeLeDkv3+FlF+UlL8+U/JnafQ0bT6Gv1e/4Zb+E/wD0IWif+A//ANej/hlv4T/9CFon/gP/APXqf7Jq/wAy/E6/+Is5V/0D1P8AyX/5I/KHafQ0bT6Gv1e/4Zb+E/8A0IWif+A//wBej/hlv4T/APQhaJ/4D/8A16P7Jq/zL8Q/4izlX/QPU/8AJf8A5I/KHafQ0bT6Gv1e/wCGW/hP/wBCFon/AID/AP16P+GW/hP/ANCFon/gP/8AXo/smr/MvxD/AIizlX/QPU/8l/8Akj8odp9DRtPoa/V7/hlv4T/9CFon/gP/APXo/wCGW/hP/wBCFon/AID/AP16P7Jq/wAy/EP+Is5V/wBA9T/yX/5I/KHafQ0bT6Gv1e/4Zb+E/wD0IWif+A//ANej/hlv4T/9CFon/gP/APXo/smr/MvxD/iLOVf9A9T/AMl/+SPyh2n0NG0+hr9Xv+GW/hP/ANCFon/gP/8AXo/4Zb+E/wD0IWif+A//ANej+yav8y/EP+Is5V/0D1P/ACX/AOSPyh2n0NG0+hr9Xv8Ahlv4T/8AQhaJ/wCA/wD9ej/hlv4T/wDQhaJ/4D//AF6P7Jq/zL8Q/wCIs5V/0D1P/Jf/AJI/KHafQ0bT6Gv1e/4Zb+E//QhaJ/4D/wD16P8Ahlv4T/8AQhaJ/wCA/wD9ej+yav8AMvxD/iLOVf8AQPU/8l/+SPyh2n0NG0+hr9Xv+GW/hP8A9CFon/gP/wDXo/4Zb+E//QhaJ/4D/wD16P7Jq/zL8Q/4izlX/QPU/wDJf/kj8odp9DRtPoa/V7/hlv4T/wDQhaJ/4D//AF6P+GW/hP8A9CFon/gP/wDXo/smr/MvxD/iLOVf9A9T/wAl/wDkj8n2YIMsQo/2jiu4+HvwU8bfFK4SPw34dvL2Bjg3sieVap7mVsL+Ayfav1E0L4HfD3w06yab4K0K0lXpKunxlx9GIJrtkjWNVVVCqowABgAVtTyjX95P7jxcf4tJwccBhde83/7at/8AwJHzN8AP2J9E+Gtzba74qlh8R+I4iJIYgn+h2j9iqnmRx2ZhgdlB5r6aAxS0V7tKjChHlpqyPw3Nc4x2dYh4nHVHOXTsl2S2S9PzCiiitjxgooooA+ef2gf2O/D3xfmuNa0iVPDvip/me5SPNvdn/psg/i/2159Q1fCvxI+AHjz4VTyDXvD1ytmpwNRs1NxasPXzFHy/Rgp9q/XCkKhgQRkHrXl4jL6Vd8y0Z+ocP+IOaZHTjh6lq1JbKT1S7KXbyaaXSx+JisH+6wb6HNO2n0Nfr/r3wY8B+KJGk1Xwdod9KxyZZbCIufqwGa57/hlv4T/9CFon/gP/APXry3lFTpJH6hT8Wsucb1MNNPycX+N1+R+UO0+ho2n0Nfq9/wAMt/Cf/oQtE/8AAf8A+vR/wy38J/8AoQtE/wDAf/69L+yav8y/E1/4izlX/QPU/wDJf/kj8odp9DRtPoa/V7/hlv4T/wDQhaJ/4D//AF6P+GW/hP8A9CFon/gP/wDXo/smr/MvxD/iLOVf9A9T/wAl/wDkj8odp9DRtPoa/V7/AIZb+E//AEIWif8AgP8A/Xo/4Zb+E/8A0IWif+A//wBej+yav8y/EP8AiLOVf9A9T/yX/wCSPyh2n0NG0+hr9Xv+GW/hP/0IWif+A/8A9ej/AIZb+E//AEIWif8AgP8A/Xo/smr/ADL8Q/4izlX/AED1P/Jf/kj8odp9DX0F+woCP2hdPyD/AMg28/8AQVr7c/4Zb+E//QhaJ/4D/wD162vCXwN8BeBNZTVvD/hTTdJ1JEaNbm1h2uFb7wznvitqOWVKdSM3JaM8bOfEvLsyy7EYOnRmpVIyim+W2qtrqSfFP4x+Ffg3oseo+JtRFqJiVt7WJTJPcMOoRBycdycAZGSM189v/wAFH/Bsd6ynwxrf2RTzN5lvvx/ub/0zXlfiPT/+Ghf23rjw/rsrvo1nfTWQtw5AFtaozNGvcb3ViSOfmPoK+7rT4feGLLSE0uDw9pcenImwWi2UflY9Nu3FdsalfEyk6UlGKdtr3PicTl2RcN4fDwzOjOvXqwU2lPkjBS2Ssnd6O99DV0nUU1jS7O+jjlhjuoUnWOZdroGUMAw5wRnkVbrwz43fGPXvh18Wvhb4a0lLL+zfEd79mvfPhLOE82JPkIYBTh27HtR+0f8AGXxB8K/Enw3sdEWyaDxBqv2O8+1QmQiPfCvyEMMHEjc89q7JYiEFK/2bJ/O3+Z8fRyDF4qeHjSSXt1OULvpDmvfT+67dz3OivCp/jN4hj/a1g+HCrZf8I8+lG8J8k/aPM8tm+/uxjIHGK5nxD+0B4/8AiR8Sda8G/CHR9Llh0R/K1DX9YZjCsgYqQgBxjcGA+8W2sQABmk8TTV973tbrc1pcNY6rKOsYxdONVycrRjCTsuZvq3pZXb6H03RXB/Ch/Htr4bvT8SZdFOpxXDeVLo4ZYmtwine27oc7+w4Ar57+FH7XHivxf8XtDsdYtNOtvBXiO9vrTSZ4oGWYmJsR5csQTnYp45L05YmEOXmuub+tSMNw7i8b9ZeGlGcaCu2no9HL3dNXaMnbyZ9gUV4v+0H+0HJ8JZtE0HQdHPiPxprr7LDTtxVFG4LvfHJyxwAMZwxJABNZ/gO7/aEbxVpUniqy8IJ4euJf9NjsmkNxbR7SflO7BOcDq3Wm68VPkSbfWy29TKnkOJlg1jqs4U4STcVKSUpqO/Kt3rotrvRHvFFfPHxU+PXi26+LEXwv+GOmWF54ijgFxqGpaoWNvZqQGxhTyQrKSTnl1ABOcVfh98evG3hr4wW3w0+KmnabFqOoxeZpmsaTuWC4OGIBVj/FsYAjBDDBHINS8VTUuXXe1+l+x1R4Yx8sL9ZXLfk9pycy53D+fl7W1721tY+ka8B+L/7Z3gj4T6/caEYr3X9YtiEuIdPCCOB/7jyOQN3TIXOO+DXvp5Ffmy17q37KP7Q2sax4q8LDxBZ3c1ybe5uVAE0csvmCeCRgV8wDgg88sOOtY4yvOio8uib1dr2PW4NyXB5zWrrEp1JwjeFNSUHN9uZ7W/W+yPr/AOAv7UWgfHzUNR0/S9J1PTbywhWeb7WI2i2s20AOjHknPBA4Br2ivJfgp8X/AAD8W7fU9Q8HQ29lrgjX7daT2qQXYAzsL7fvpknDAkDJ6E14V4x+Nn7Qngbxl4a8Mapa+EF1XxDIYrFYY3eMsGVfnbeNvLDsaaxCpU4ym+a/VIipw9LM8yrYbB01hnBJ+zqz974byabWqVm79rM+z6K+evH3xc+IHwh+AFzrvi2DRh45mv1srKGyVpLVi7jYSN2SQgckZ7Ctb9mH4za98UbDxVpviyC1tPFHh7UmtLqG0jMaBCMLwWPIZJBnPYVssRBzVPW7V/68zxqvD2Mp4GpmKcZUoS5W073s0uZd43klfuz2+ivBPhj8bPEXi742fFPwrfrYjS/DYJsTDCVlPzEfO24hvwArif2Wf2tdb+KPi6Tw74yhsbW5voDPpNxaQtCkzRkiWM5ZsnHIxj7rD0qViqd4x7tr7tDplwrmUaNeskmqMYTlZ68s48ya01tG7l2sz6xor5g8CftF+LPEfwa+LPii7TThqfhi6uobAR27CMrGmV8xd53HPXBFeu/AHx1qXxK+D/hvxNq4gGpahC8kwtkKR5ErqMKSccKO9XTxEKrSj1V/xsceYZBjMsp1Kte1oTUHZ/aceddNrfiehUV8qa78ZfjB4k+PfjDwH4Fj8NtFoqLOp1WF1byisWcuG5O6T0HFdX8RPjP42+BvwHXxB4x0/Sb7xlNemyih08uLMFizIzfxYCISQCMnAyM5qFioNSdnaN9baaHZPhfGxlQpRnCVStycsFL3rTV02naytu76H0BRXh3wcv8A42ahrthe+MpvCd34VvbRp/M0gsZY3IBjVSDtYHPJG4cdelcDF8c/iv8AGD4h+LNH+GsXhrTNO8OXDW7LrZZri6KsyFgB0BZG6AAZGTk03iYpJuLu9lbUmnw1iKtarThWpuNNJynze5G75Um7XvfpY+r68l+On7R+hfAObRo9Z03UtQOqLM0RsFjOzy9md29167xjGehr0Twm+sSeGdKfxClrHrjW0bXqWWfJWYqN4TJJ2g5A5r4z/wCCkylrrwGo4Jivxn8YanF1pUqDqQ30/M6OE8pw2a57Sy/F+9B817Pe0ZNWa6XR2J/4KOeAR/zAdf8Aytv/AI7X1bbzi5t45VBCyKGAPuM18UeHP20vhlHbaXpsnw+nefbDbNIbezwW+VM9c9ea90/aK+Pc/wAH7XQ9I0DSk1zxfr8/2bTbFyRGvzKu9wMEjcyqFBGSTyADWFDErklOdRSStsrHtZ5w5P61h8FgsBKhOfN8VRSUkrNu+nKoq7bfR+R7PRXyhrvxz+LvwG1XQ734o6boOp+FdUmEE13oYdZLJyMkHJwSAC2MfMFbDZHPcfEX41674b/aI+HPg3TfsMmgeIbczXMkkReU8yYKOGAAwq9jXQsVC2qad0rdddj56fC+OUo+zlCcZRnNSjK8WqavNXtuuzS6Hu9FeE/Ff4z+IfBnx8+Gvg/T1sjpHiAkXhmhLSjDkfIwYAceoNSeEPjJ4g1v9qbxf8PrlbMaBpWnLdW5SEicuVtz8z7sEfvW7DtV/WIc3L52+drnKuH8bLDrEq3L7N1d/sqfI+m9+nY9yor4v8K/H743+O9J8aeI9DHhOTSvC9zMlxY3VtKksqRhnOwh8H5B3I5rqfG37WGty/s6eFfHfhqwtLXW9W1VNMls7pGmjVx5ocJypILIpBPY81isbSactdr7b+h69XgzM6daFBOEm5KDtL4ZSjzJS0urpN3s0fU9FfNNv+0/qUn7KzePDFaHxcLg6SLURHyTf+d5YGzdnG0h8Z/Gqnw7/aN8W+Jv2bviB401CPTk8R+H57iGFIrdlhGyONgGTeSeWbOCKv63Sul3V/kcj4TzJQnUkklGr7J6/aulpp8N2tT6hor5d+E3jn9oH4j6b4c8SCLwf/wi+oSxySnZIlx9nEm2TC5IDYDY59Kzvix+1n4h+Fv7RE/h25tbKfwTZG0a+kW3Y3EMU0a7pN4bHys4ONvOMdTUvF04wVSSaT8u5rDhHHVsXPA4ecKlSEZSajK9uVpOO3xXdkup9Z0V4bqHxn1xf2oNE8B2TWE3hy/0JtS80RlpWk2yFSrhsbTsXt+NeR+M/jX+0H4E8YeGfDWqWvhBdT8RTGCwWGN3QtuVfnbeNvLr2PenPFwgm7N2dtuun+ZGE4VxuMnCmqkIylBVEpSs3F83l0UW5dlY+zqK4z4TyeN5fCYb4gRaZF4g+0SZXSSTD5XGzqTz1zXZ11xlzJOx8piKP1erKlzKXK7Xi7p+afVHmXxy+PWjfAbSdM1DWbC/v4r+4a2jWwCFlYIXyd7Lxgdq7Xwd4mt/GnhTR9ftIpYLXU7SK8ijmxvVZFDANgkZwexr5Y/4KO/8iP4O/wCwrL/6Iat7xn8WNe+Dn7JPw41zw6lo+oTW+mWZW8hMqFHtyTgBl5yo7157xLhWqKfwxSZ+gQ4bp4zJsvrYVfv69SUG29NG7emx9Q0V8tah+1Zq17+y3qHjnTIrG38YaTcxafqNlcQs0UU/mqjHZuBAZTuHPGSOcGus+K/7SU/w0+Hvg6e20tdd8Z+KLeD7DpseVRpGRCzkDJ27nVQo5JYDIwSN/rVK3NfSyf3niPhbNPaxoqC53OVO1+sEpSeunLZp817W1PeaK8L+G7fH+XxXpdx4yXwnD4dnLm8tbIObm3GxioU5wTu2g8t3r3Stqc/aK9mvU8TH4H6hVVL2sKl1e8Jcy7WvZa6fkz8/v2ivCXib9nn9oZPino1k11o13efblnIJiSV12z28pH3A4LEE/wB7jlcV6za/8FEvh4dHW4utK16C9CZe1SGJ1B7gSeYAR74H0r6juLaK7geGeJJoXG145FDKw9CDwa5SP4PeBIbz7XH4L8Ppc5z5q6XAGz6521w/VqtKcnQnZPWzXU+6fEuV5nhaFLO8JKdSjFRU4T5W4rZSTT27+ux8zfti6XYeP/iv8EdNmnkTT9ameEy28gWTy5Zbf5kPODg8HBri/jp+z/4d+Bvj34US6JqGrXbanrsaSjVbpZQoSaAjZhVx945/Cvuy88O6VqN1Z3N3plndXFkc2s01ujvAeDlCRleg6Y6Cl1Pw/pety2suo6baX8lq/mW73MCSGFuPmQsDtPA5HoKKmCVRzk921Z9rWHl3GlXLqWEw1NS9lSjOMo3VpuTm09unMvuPl67dR/wUStBkZ/4R8nGef9U1cf8AA34gaZ+y38V/iD4T+ILS6NDql99sstVliZopkDSbSSoJ2srghhkAhgcGvsbUrTw9pGof29fwaZZ3yr5X9p3KRxyhcY2+a2DjHbNR3WneGfiBYIbm10rxHZKTtMscV1GD3xnIBpvDNS5oy967a+fQzjxJRqYdYbE4eToSpU6UrOz5qbclKLs1u/haPGvjj+0R4Yv/ANnHxh4h8Ka5BqUbk6JFcRBlAuJQoIG4A5COWyPSvmDx18P/AImfD34IeAtfvrXQrbQfDFxFqOnvYtJ9uie4dZAZ8jby+wHHQ461+go8A+GRpS6YPDukjTVk84Wf2GLyQ+Mbtm3GccZxmtO/0mx1XT3sb2zt7yycBWtp4leNgCCAVIwcED8qVXCSrtynLW1tPv8A8h5VxVhckjGjhMPzQ9o5y52nJx5eVJNJJOznrb7Wx8cfHzxBJoPxY+FHxzisptT8HPYQi4e3G/7OHEh57AlZyRkgFoyMgkVzvxQ+Knh7xV8dPAWs+A/iPrGprrOtWiajo6XU0NtaorwIqiMhfv8Az7gc85r7og0ewtdNXTobK3h09U8tbWOJViC/3QgGMe2KzNN8AeGNGvBd6f4c0mxugcie2sYo3z/vKoNKeEnJu0tG03p18teprg+K8HQhTdXDyc6UJU42krODbcVNOL1i3e8Wr21PlK58QW37Ov7ZXiTXfF2+z8NeK7Mi11Z0ZokY+USCQD0aMqR1AZD0OaZrfiSy/aQ/a48DXXgt21PQfCaLc32rxxsIchzJtDEDIJCKPUlscAmvsDWdA0zxHZGz1XTrTU7QncYLyBZYyfXawIpNF8PaX4btPsuk6baaXa53eTZQLCmfXCgCq+qyvy83u3v597fec0eKcOoLE+wf1pUvY83MuS3Lyc3La/Ny6Wva+vkX+gFfKesftz/C/WV1nRPEvh7Ubu2guZrYwtaw3cFyqOyhsFhjIGcMOM9a+ra5bV/hZ4N8QXhu9T8J6JqF2TuM91p0Mjk+7FcmumtGrJL2bS9Vc+bybE5ZhpyeZUZz25XCXK4tfLW+npY+I/2KvD1x4j/aD1fxX4d0yfSfB1ql4AjMWSNJW/c22/ozDhiOcbB7Z9W/abYD9qH4DgsATfNgE9f38VfU2naZZ6PZx2lhaw2VrGMJBbxiNFHsoAAqC+8P6Xqd9aXt5ptpd3lod1vcTwI8kJznKMRleQOnpXNDB8lH2Set7/in+h9PiuL1i85/tSVG0VTlTUb3dnCUU3JrV3ld/d5nyf8AtbX2r/EL43fDj4d+GVsrrVLQtrbQXzn7P5gyY/NA52hInJx13j1rG+Fd74p+FX7YlxY+OF0u1v8AxvYmR/7KZvsskvJjZd3O4tDID7v719cSjwtbeIP7QkGkRa2V8v7U/ki5K4xt3fexjjGav3nh3SNU1C11C70yyu761wbe6mt0eSLnPyMRleeeDSeFcqjqqWt0/K21vuClxRTw+XxyyWG/dOlKDf2nOT5uZPaylyu1um58r/AllP7Unx9AYEhTkA9PnNeS/DT4e33iD9lmw8b+HCf+Eq8FeILnUrRo+TJAvlPLH7/dD477WH8VfoHaeHdKsL+7vbbTLO3vLv8A4+biK3RZJv8AfYDLfjTtK0HTNCsms9N0600+0ZixgtYFijJPU7VAGTS+pXVpP+b8XdfcbLjP2U5VKNKzfsN3o1Sg4ST02mpNeSPhb4KapHq/7Kvx81BFSKO6ubq4CK2QgeFWxn23Yr0f9mH9pX4b+F/hF4N8J6l4ljtvEEYNq1n9mmYiR532LuCFed685xzX0zZ+D9B0/TbrT7XRNOtrC6/19rDaRpFLxj50Aw3HHIqnD8NfCNvMksXhbRY5UYOjpp0IZWByCDt4INOnhatJxcZK6VtvO/cnH8TZbmkMRSxVCajOoqkeWUU01BQSd4u/V9D4V8eWfw91H9rX4jxfEXxFeeHNJVY2guLCZ43efy4PkJRGONu49Ow5r34a18DtO/ZysdMv9ck1v4dS3zadFf33nSy/aC7y53BFcFTkhgOAB2r3HUPAHhjVryW7vvDmk3l3KcyT3FjFJI5xjJYrk8AflUv/AAhfh/8Asg6V/YWm/wBllzIbL7HH5BY9Ts27c++KIYWVNzas736d3112Jx3FOHx1HC05e2j7H2atGcUvcjy80fcupdU7u3Y+KvgVqdn4Q/aX0rwz8J/FmoeK/Ad7bvLqdtPuaC1G1yTkgDKkR4cAZL7Tmov2iL34I6rd+I/FfhfxhceG/iPYzyqYNN82P7VdI5VsjaACxXmRGA7nNfb+g+FNE8LRSRaLo9hpEchBdLG2SEMR6hQM1Sm+HXhS41P+0pfDOjyaju3/AGt7CIy7uud+3Ofep+py9l7O63vs9PTU61xhhv7Sjj+SonGEY3UoKVSzbftfc5ZX0W17Jat7c7+z1rniHxL8GPCmp+KRJ/blxab5nmTY8i7mEbsuBgsgRj9a+YP+ClBH2rwGpZVLRX4GTjvDX3HWXrXhXRfEhhOraRYaoYciM3tsk2zOM43A4zgdPSuith3Voexvrpr6HzeS5/TyrPVnDo+6nN8kXZLmUkktNlftsj5Q0X9uL4Q6XotjBP4d1Np7a3jR2TTrY5ZVAJB8z1FH7VNxPonxC+Enxhjsri88MWHlG7CJloFZxIpYdASrsAc43KBnkV9N/wDCrvBhH/IpaF/4LYf/AImugk0+1lsjZvbxNaFPKMBQGPZjG3b0xjjFZ/V6s4OFSS6WsuqPUjxDleDxlPF4DDTXxqalO/NGa5Wk7e69Xrr0PjP9qT4vaB+0N4b8N/D/AOHVwfFGsapqMdwxtoXC26KjDLllGD8+T/dVWzjjOh+0Vbr8JPjR8FPF2qeafDWjwLpl1fKhYRsgIy2OeVctjqdjYya9d+If7LXwu8UI2oXWkx+GLmMZOpaLN/Z7KPfbhD9SM16PZSeGvFWknTIJtN1zT0RY3t/Mjuk2jAAYZbPQdayeHqTlJ1GuZ2tby8v+CehDiHL8FRwtPAU5yowVVVIytzfvVytqa02ty+6rW1vc+VPEHjHSPjz+158NpfBV2Nb07w7bvc39/AjeTGMs2MkD/YXPcvgdDW98OGB/b8+JA3DP9ipxnn7tnX0zoXhbRvC8MkOjaTY6TDIQXjsbZIVYjuQoGakh8P6XbatNqsWm2kWpzrslvUgQTSLxwzgbiPlHBPYelbLDSupSevNd/dax5dXibD+znhqFFqn7B0Y3knLWam5SaSW91ZLsfBP7OHwTvfjLZfEC2Xxzq/h3RF1qS3vtM0zbsvQSWy5J9OMEEYr0b9qTwZpHw68HfBrwXocRt9Oi8TQLEkr7ncg5ZmJ+8zNIST6mvrDSfD2l6AJxpmm2enCd/MlFpAkXmN/ebaBk+5pdS0HTNZltZNQ060vpLV/Nt3uYFkML8fMhYHaeByPSojgoxpOC+J9fnc66/GtbEZtHGzi/Yxd1DRa8nLdtJXfm7tLRHwx4e8HX7/tRXHwqMQHh2y8Wv4zaLOVEQhDxqR/d3Oi/WmfC24Cfs1/tFWTOCbe/umbkcErg5/75r7vXTLNNQe+W1gW9dPLa5Ea+YV/ulsZx7VSg8H6DbWt9bQ6Lp0Vvfkm7hS0jCXB7mQAYfqeuetSsDyu6l/N9zVkvkb1ONlWhGFSjsqOz3lTnzTltvPbystz4S/Z3tvgdYW3gnVtX8darZ+OIbmKVtKS5l+zC4E2I02CIrtPy5G7v1rv9a8E6f8Sf2x/if4W1Ij7LqXhOOFmHLRtttikgHqrBWH0r6hi+GvhG3lSWLwtosciMHR006EFWByCDt4INasehaZFq8uqpp1qmqSoI5L1YFEzpx8pfGSOBxnsKcMG1BQlayaei30trqRi+MIVMXWxlD2nNOEormlF8jc4zXLaKso22d3tqfBX7Olxrdp+1Z4X8NeJF26z4X0m80N2LZMkUQkaIj1GyQAHuu2vVv2oWA/aX+AoLAE6kcAnr+/hr6cHhvSRrJ1f+y7L+1iu37f8AZ08/GMY8zG7GOOvSlvtB0rVL60vLzTrO7vLQ77eeeBHkhOc5RiMryByPSnHCONJ0+brf7rf5GOJ4upYnNaeZew5eWlKm4p6c0lNNrTRXne3bQ4H9oj40D4FfD8eIV0+PVLiS8itIbWScxBi24klgD0VWPSui+FPinVPHHw80LxBrOmx6RfalbC6NlFIXESPzGNxAJJTaTx3xXHfHj4Cf8L11DwpDf6x9h0DSbtru7sUgLvek7Rt3bgEG0OucH75r1qFI4I0hjVY0RQFRRgKOgAHYV1RVR1pOXw9P1Z8viJ5dDKaFOjG+IcpSnL3vdjtGP8rv8TaXZX6HyH/wUfZV8D+DtzBf+JrL1OP+WDVk/tFuF/Yi+GLbwo3aRhs4/wCXZ6+xNa8OaT4jijj1bS7LVI4m3ol5bpMFOMZAYHBxTbzwzo2o6XBpt3pNjdadBt8q0mtkeGPaMLtQjAwOBgcVzVMI5yqSv8SsfSZfxXSwWFy/DypN/Vqjm3f4rt6LTTc+Cf2w/B178JtT8RX2nx48KfEC2ie5jHCQahC6y59i2GYeu+T0rsPj/Yaj4Qf4F/FCOwm1LRNAsrNL5IRnygBG4Y+gYbgGPG5VB6ivsvVtB0zxBZi01PTrTUbVWDiC7gWVAwBAO1gRnk/nVgWVuLQWogjFqE8oQhBsCYxt29MY4xUvA3c2pWva3k07/mdNLjaUKOEjVo80qXOpu9ueMoKn2upKCSvrsmeaeB/2m/hr8RNY0zSNC8TwXer6gGMFi0MiS5VC7BgVABAU9+3Ga4bwl+1sfE/7Rd78NT4baC0jubmyiv8AzyZfNhVmZnj24CHYcc5GVJ68e16V8PvC+hah9u03w3pGn3vP+k2tjFHJyMH5lUGrVv4T0S116fW4dHsItZnQRy6ilsguJF9GkA3EcDqew9K6eSu+W8krPWy3XzPmlisjpSrKGGnJSg1Hmmrxnf4vdUU0lbRp7PvprUUUV1nygVx3xd+I1r8J/h1rfim7j88WEOYoN2DNKxCxpn3YgZ7DJrsa+b/2+bS6uPgI0lujNDBqtpLclR0jyygn23slc+Im6dKU47pHv5Bg6WYZrhsJX+Cc4p+jeq+ex4n8HPgdrf7XlzqPjr4i+Ir86X9oa3tYLUqC7L94RBgViiUkKMKSSDk8EnD8feGdR/Yk+NWg3vhnWLu60C/QTvbzkL50KyBZoZQoCtgEFXwCCR6c/Uv7F+taXqH7PHhq3sZ4nmsFlgvYlI3RTea7HcO2QwYeoIr5t/aS1eP9or9pnw54P8NyrqFpY7NPkuYDvj3GTzLlwR1VEABPTKmvDqUoQw8Ksf4jtZ9W2fuOXZrjMbxDjMtxKUcBSjUjKHKlCMI3Se2jejv620R9oeNvi94c+H+qeGNO1a4nF54juRa6dHb27SmR8oOcfdGZF5PrTvHPxa8PfDzXPDWkaxPOmoeIbr7JYQwW7Sl5NyLzj7oy68mvCviaieLP22vhjoWcWmhabJqRTsHxIy4/79xUfEPHjr9uLwBoyEzW/hnTJNRuFHPlyMHYZ9OfI/MV6csRP3rfzKK/C5+a4fh/Bv6u6zlrQqVp6rZc/Ilppe0b73vpY9w+Kvxl8L/BnSrPUPE95JbQ3k/2eBIIWmkdgpY4VecADk9sj1rV0/x/o2peAY/GUNwx0F9POpidoyGEAQuSV65wDx1r4e+Nfxd8L/EP4xeMZNbvJm0bw/ol7o2gRwWzzpPfyIyPMxUEKA2QGPZUPau5h8cjTf8AgnSlyJdtw1g2jjnubloiP++M1ksbzTmlayTa+R6VXgxUcFgpTjNVqtSnGV/htUu0o6bxSXM7uzbXQ+pfh18QtI+KPhK08SaE88ml3RcRSXELQs2xirHa3OMg/lXO3f7QHg2y17xhpEt7cLdeE7M32qt9mcxxRgKcK2MM3zD5RznNS/s++G/+ER+CPgrS2Xa8elwySKRjDyL5j/q5rxr9jeJfF/ij4v8AjWaJZY9Y11reFnGQY0Lvj6YkT8q6HVqfu49Zb/d/mfOwyzAP+0cS+Z0qDShZpN81TlV3Z/YUntv9x0X/AA3f8JR11PUh/wBwyb/Cu+tP2gPCF34j8I6H9ou4b7xTYrqGlia0dEliZWYZYjCthT8p55HqK8b+AVjB40/an+MviRreGWz05o9HgBjUoMNtOBjH/Lv+tXP24rb/AIRTQfA/xB08RJq3hjWojAjjAlRxu2cdRuiXj03VhGtWVKVaTTSfbonZ9T362S5NPNaOUUac4zqQTu5p2nOnzQjbkWik0m+q7Hsq/GfwzN8UW+H9tNc3niSOHz54re2d4rdNu7Mkg+VeCvBP8ajqa0Pit4kHg/4Z+KdbL+W1jplxOh/2xG23/wAexXE/s3fCB/h34audb1qUX/jTxJJ/aOr3zcne+XEKn+6m4/UknpjGF+3F4i/sL9nzWLcHa+q3NtYKfZpA7f8AjsbV0OpONCVSejs3/l8z52jl+DxGe4fLsE3KHNCMpP7TuueSVlaO9k7uyu3qfMX7Mv7KOhfGv4ea14j8QapfaXJBdta209uY9g2RqzySb1OQGb1HQ16N/wAE/vHetzXni/w1eajLqPh3TIEubaaVyyQHzHUhCeQjqu4L0G3jqa5r4R/sk+OPHnww0af/AIWLNoXhbWYRePo0STOoDnPzIJFRiwAPPrzXvOpfDbw/+y7+zh42/sPzZbo6dM9xqFyR51xOyeXGTjgAFwFUcDPqST5OGoyhyVeXlUU23ffQ/WOJM5w2N+t5VLE+3qV6kI04KLSpWlZvmaV29tL/AHNklp+3F8Jrm+SBtYvbeB22C9n02ZYM+7beB74r1fxj8SfDPgHwv/wkWu6zbWGjkKY7lm3CXcMqIwuS5I5AUHjnpXwDpd14iufg/wDD34Ral4ftvC2h+LL1bi28U3h+0m43yh1ZI1/1bZaNeTnBGcAkj1vxz4Vste/ar+FXw01EvceFvDmiJLBa3XzLcukchyw6NnyYwR6Kw6E1008XVlHVJvRbW1f6LufOZhwjlVHERjCU4wiqs5e9GblTpfai1FJSlK8eV3cd3bZ+w+A/2u/ht8QfEtvoVhqlzZ6jdMEtU1Gze3W5Y9AjHjJ7A4z25re+K/7Qng34NX1hZeI7u6S9vo2mgt7S0kndkUgE/KOOT3968S/bwtrO4i+Gum6bBH/wlE+solgYFAlWMYGBjnb5jRe2R7VfkDeN/wBvuFTiWDwloGT6LI6/zzcj8q1eIqxbpXV7pXt38r9PU8ulkOVYijSzKMZxounVnKDknL921FWnyLScpJfDo09z2P4X/tAeBvjBNPbeGtaW4v4E8yWxuIngnVc4LbHAyAcZIzjIz1rS0/4teHtU+J2peAraeeXxFp1qt5cxi3byo4yEI/efdz+8Xj3r5z8bw2d3+3x4Kj8MJHHf21kX1p7ZQB9yYnzMfxeW0YOf7ye1bH7LW3xZ8d/jd4uckk6kumQE9RGruP5Rx1UMTNyVN2vzNX8krnPjOHcDRw1THw5lD2EKkYtpyjKdTkSbSV42TktE2rfP3TTfi14e1b4map4DtZ55fEOmWy3d1GLdvKjQhCP3n3c/vF4965D4iftY/Df4a63Lo2oaxJfatCxWaz0u3a5aE9w5X5QR3GcjuK8B8A+J7wN+0v8AFXTCzToZbPTbledoTfhlP+yohb8BXq/7EfgXQtJ+Cmla/bwQ3Otaw0099fOoeYsJXURljyAAvT1JPU0oYirWahCybu7+Sdl8zXG8P5blFKpi8WpzjD2cOVNJurKmpzvJxfLGOyVm2+uh0WuftcfDrw74Z8Oa7fX97HZa/FLNYgWEhkZI3CMWXGVG44Gevak8C/tcfDv4jeK7Dw5ol7fz6pelhFHJp8iL8qM7EsRgABTyat/tS6pbeFPgB4xvVhhST7A1nCfLXKmZhF8vHH3yah/Z++HsGn/s4+F9HljFrcXujFpLiJAJUNwrOSD1yPM/StOet7b2aata+3/B66nmrC5L/Y7zCVKopSqSpx/eJpaOXM17PXlTimrrmd3eOxm6x+2n8LdJ8RNo66vd6hIswt3ubCxkmgDltuA4Hzc8ZUEHtmvdN2VyP1r4m+FmreJv2S/Fuk/DjxpodhqfhPXtQ2afrdogLGRmVQxHcAlMowDLnKlgBX2zkAZPAq8LVnVT9puulrW/zObibK8HllSksDFunJNxqc6kqi2ukox5WndSi7tfn+d/xr19vjP+1RP4M8ZeJJfDXg+wvmsIQxAii2xghiG+XfKxA3tkAMvYV9LfBn9kPwt8GPHTeKdH1S/v91k9tFBeCMiMuVJkDoq5yoxgjuearfH39m7wV8d9Km8U2mqW2laxHbErrltKj2s6KOBPg4ZQON4IIHcgYrzH/gnt8Qdd1GHxN4av7uS80LS4Ibq1eZywtSzMrRqx/gIXcB0G04xmvOhBU8TatG7k20z7/G42rmXDLqZTWdKGHhGnWouKSd3ZyUrauT362vez+L6a0D4yeGfEni7xT4csbmd9Q8NLu1IvbssUXXgOeGPB6ehqp8Kfjx4Q+M9rqk/hm+mnTTSn2kXNu8BUOCVbDdQdrc+1fLPwo8RSWXwI/aC+JUhxNrl9cwwyHr8wIXB/3rkflXHeHRc/s1zaTe5eCy8ZfD2VmJ4AvhEzp+IJj/7+Vp9dmuWTWju36Xsjz3wXg6v1qhSlL2sHGMNVZyjCM6qenS75e3W59y+AfjB4Y+I/g+68UaVfNHodtLLFLd30Zt1XywC7Hfj5Rn73TrXnUn7bXwsOvRaXa6nf6i0k6263Nnp0skJdmCgBsAnJI6A183+P4Lrwn+yT8G/CYmbT7HxPe/adTmBxlGfzFDe2JFbB/wCeY9K+7fC/grQ/BugWmjaNpltY6faqqxwxxjHHRiccscZLHknmt6VatWfKrKyTenV69zxcyynJ8mi8RWjOpGpUqRppSUbRpy5eaUuWV23skkrbvU4H4l/tR+AfhL4nbQPEN/dw6ksKTtHb2Ukyqr525ZRjPB4+ldX8LvipoHxg8OPrnhyWefTkuHtfMuIGhJdQC2A3JHzDn618maffePfE37VPxQ8S+BPDej+JpdNZNGlXWZ/LihQBVBTkZYmB/oCfWvsXwN/bB8J6Y/iCxstN1t4Q95aaccwRSnqqnJyBxzmrw9apVnK/w69H37nHn2UYDKcHQjBXrSjBy/eRdnKPM17NR5ktVZuRgfGu38dXngaW3+HdxbWniOa4ijW4utmyKIt+8b5gQCB04J9BXx3+zLpviLVf2t7+21zxHeeI5/D63rXV3JcyvHNImIAQrH7oaQ4GP4egr711jUotG0q8v5ziC1heeQ+iqpY/oK+Mv+CeOmya1rvxB8XXGTNcPDAHPdpHeeT+aVjiYc2JpK/+Wh7HDeLlh+HM0m4RSjFRT5VzN1Hy25t7JK6Xm2eh/tufHLV/hT4Q0vSPDty1jrGttLuvYv8AWW8EYXfsPZ2LqA3YbiOcGvBfi3+z3rPwP+GmifEOLxvqz+LWubdbwrMwCPKCf3cmdxKkYO7IYZOB0r6j/ag/Z0j+Pvh/ThbajHpOtaW0jW086FoXRwN8cmOQDtUhhnBHQ5r4l+LsHjTU9Y8PfDy78er8Q9Vt5VtrfTtLYyWttIRtjUyEL5kuCckg7FBy3Jxx45SjOUpptO3Lrs/8z7Lgiph62CwtDA1YwlGU5YhON3OPT3uVpR5dNWkn56P7k8MXus/H/wDZm0+ePVpfD+ua7pao+pWu5WimDbXdQpBAJRuARw2K+N/j/wDByx/Z/g0nVtF+KF1qviSa62tbpL5dzGoUnzgySEqAwA+bqWGM4NffHw+8HWngH4d6B4MW8VJ7TTVtQ8bgSSMqgSSID/tMT04yK+Df2gPhTpv7J3jjwvq3g/W/7SvZPMuTY6tDDcSReXtwzjaAVfcQCQGBUlT6aY6DVGM5q7SSbvt8up5nBONjLNq+EwlXlpzlOUKfIrVFaWkptNxSSXR9eu/2Zo+ieJ/it+zfY6ZreoS6D4l1rRY4rq9EJMkTuo3MUBXDFeoyMFj6V8hfH39nJvgN4PXWL34oahqF9cyiGy05YZI2nbqxLeedqquSTg9h1Ir79i8S29r4Rj17VWXS7VLJby6ac4FuuwO+4/7PP5V8V+A9PvP2zf2hbnxVq0Ei+AvDrKtvaTD5XUHdFCR/ecjzJPbC+la4ynCUYQteb0W/3s83hHMcbhq2KxkpKlg6bc6iUYu7ekacW03rolZqy7N3PZ/2KfhrrHgj4Yyavr1xcvqPiGRLxbe6kZ2ggC4iB3E4LAlyO24DqK+hqRQFAA4Apa9SlTVGCguh+YZrmNXNsdVx1ZWlN3stktkvkrIKKKK1PKCiiigArO8Q+H9O8V6JfaPq1pHf6bexNBcW0oysiEYIP+I5HUVo0Umk9GXCcqclODs1qmt0z4t8c/8ABPNrdL248DeLZ7ZpM7dO1TIRl/uGaPk+25T7+tL+yf8AD3x38HviQNA1f4b2drFdRSNdeKzI0jLCoyscbqzJgtt+QBSeSc7a+0aTFeesDSjUVSno1/XX9D9Aqcc5risDVy/HNVYTVru6kuzvFq9t/eTu9zxz4xfs32vxQ8WaV4r0zxJqXg/xVp8X2ePU9NwxaPLEAqSORuYZB6MQQRTfh5+zXafDvTvE9zbeJNT1Hxl4ggeC58UagFkuEyOCi9Bg4PJOSFycACvZqK6fq9Ln57anziz/ADJYWOC9r+7Vlay2Tuk3a7jfXlbcfI8y+F/wI0f4XfCy58F2dzLdx3a3H2q/mRRLM8oKliBxwu1QPRRXBTfsd2k/wQsvhqfFt+NPttTbUvtf2WPzHyGxGVzjAZi2a+iqKTw9JpRcdErfIqnxDmlKrOvGs+aU1Ubsn76vZ6rpd7aeWx4l8O/2d9a8C6nPdXPxQ8TeIIWsZbOGz1CTdDCzgBZAu4glQOB711XwM+Dln8DvAieGrK/m1NftMt1JdXEao7u+OoXjgKB+Feh0VUKFOm04rYxxed4/HQnTr1Lxm4tpRiruN+XZLbmf3nmfwR+CFp8F7TxAkOq3GsXWtai2oXFzcRLG24j7oC9gSx/4FR8cfgnbfHDStE02+1a402y0/UEv3jgiV/tBUEBG3dBhm5HrXplFP2MOT2dvdM/7Xx317+0vafvt+ay7W2tbbTYQDAwOleVftBfAaD4+6DpmlXWuXWi29lctdf6NCkhkYoUGd3TAZvzr1airnCNSLhJaM5cFjcRl2IhisLLlnHZ2Tt063Rl+F9Ag8KeGtJ0W1Ja2060itI2IwSsaBQTj6VzPxp+F6/GP4fX/AIUl1WfR4L14mluLeNZG2o4fbhuOSoruqKJQjKPI1oTRxlfD4mOMpytUjLmT0fvJ3vrpueP/ABC/Zy0/x1o/gCwj1e50r/hDpoZbSSGFHMgjVFCsD0z5anipvjX+ztpXxhv9J1mPVr/wz4o0riz1nTWAlRc52sDjIBJIIIIyecEivWqKzdCnJNNb2/DY9KlnuY0JUp06zTp83LotOd3knpqm907o8R+HX7Lun+FfGkXjDxN4l1bx74pgXZbX2sMNlsMEApGM4IBOCScZJAB5rC1/9ki/1H4jeIvF+k/EzXvDd3rkpa5TTYkRvL4xGHBB2gAYz6V9F0VDwtJxUbefXc6o8TZtGtLEKt70o8usYtcqd+VRceVK+tklqeY/Bz9nvwx8F/tt1phu9S1u/wD+PzWNTl825mGckZwAozyQOp5JOBXBeI/2PVufFviDV/C/j7XvBtrr7tJqenadtMczMSWwcggEsxwc43HHBxX0XRTeHpOKhy6IxpcRZpSxFTFKu3OaSk2lK6W2kk1pbTTTpY4fwD8G/DPw7+Hf/CF6dZefo0kciXS3R3vdGQYkaQjGSw44AAAAGABXjtj+xfdeFri8g8IfFTxV4V0K5kMj6ZaODjPHD7hzjjJUngZJr6aopyw9KaSa226fkLDcQZnhZ1alOs26rvLmSkpPu1JNX87XPOPjZ8G4vjR8PV8KXOs3OlwGeGaW5hjWR5BHnCkNxycHPtWt43+HS+Lfh1N4Ts9YvvD0bQxQR32msFniWMqVCntnYAcYOM8iuxoq3Sg221vocMMyxdOFKnGfu05OcVZaSdrvbX4VvdaHgHhH9k1bHxppPiXxl4513x/eaO3madDqjbYoHByGIyxYggHqBkAnOBXuOuaSmvaLf6bJPPbR3lvJbtNbMFlQOpUshIOGGeDjrV6ilClCmmorcvG5tjcxqwq4md3DSOiSWt9EkktddFqfHDf8E5NNjlaK28fanBpjHm1NkhYj0JDhSfcrXvnw++Anh34W/D7VPDHhsz2j6jDItxqkxElzJIyFBIxwB8oPCgAD8TXpdFZU8JRpO8I2Z62YcVZ1mlNUcZiHKKadrRSbW17JX+dzwY/sn6dH+z+PhZB4hvILJ7v7VPqKwIZZj5nmbSvQdFH/AAGtn42/s26N8aPBuhaDPfz6P/YzD7LdW8Su6p5fllMNxggKfqor2Ciq+r0uVx5dLJfJbHMuIs0jXjiVWfPGcpp2XxTSUnt1SSs9LaJHnHj34D+GviN8MrDwVqyS/YtPhhjs7qAhZrdo02K6nBH3cgggggkVyvws/Z0174ceI9Mvbr4p+I/EGk6cjpDot2cW5BQoA3zHIXOR0wQK9xoqnQpuSnbVGNPPMwpYaeDjVvTndtNRest2rpuLfVxsfMFp+xbqGk6nq99pHxY8TaLLqly93dDT1WESSMzNltrDONxxmvo7w7pL6DoGm6bJeT6jJaW0cDXl026WcqoBdz3ZiMn3NaNFFOhTpfArfeLMc7x+bKKxk+bl292K6W3STencwvHPhlvGfg3W9BW9k07+07OWzN1EgZ4g6lSQDwTgmuR+AnwPsPgN4Ru9DsdQm1T7TeNeSXNxEsbElFULheMAJ+pr0uirdOLmqjWqOOGYYmnhJ4GE7UptSastWttbX07XseKftA/s2t8edR0aaXxZe6DaafFLGbW1gDiYuyksSXA6KByD3q98F/2X/BXwSlN7pVtNqGtMhjOqagweVVPVYwAFjB77Rk9ya9dorP6vS9p7Xl97ueg8/wAz+oLLFWaoL7Kslq76tJN6vq2eHftAfsu2vx21vStWfxRqOg3unQNbwiCNZIgC24sBlWDE4BIbkKOOK5X4cfsI+FfCfiODW/EWs33jG8t3WWOK8jEcBccqzrlmfB5AZseoNfTdFRLCUZT9pKN2ddHirOcNg1l9HEONJJpJJJpPVrmtzfiedfHH4SzfGfwgPDn/AAkN1oGnyTLJd/ZIVka5VeVjbceF3YYjvgduun8JPhdpPwe8DWHhrSN0kNvl5rmUASXMzcvI+O59OwAHauyorb2UOf2ltdjx3mWLlgll/P8AuVLm5bJe9td6Xbt3bCiiitTzAooooA//2Q==" alt="CSE Logo" style="width:95px;height:auto;display:block;">
                            </td>
                            <td style="text-align:center;vertical-align:middle;padding:0;">
                                <h1 style="font-size:22px;color:#000;margin:0;padding:0;line-height:1.2;">CSE WEBSITE ORDER</h1>
                            </td>
                            <td style="width:95px;text-align:right;vertical-align:middle;padding:0;">
                                <div style="font-size:12px;color:#000;line-height:1.4;">
                                    <p style="margin:0;">${dateStr}</p>
                                    <p style="margin:0;">${timeStr}</p>
                                </div>
                            </td>
                        </tr>
                    </table>
                    <hr style="border:none;border-top:1px solid #ccc;margin:5px 0 10px 0;">
                    <table style="width:100%;border-collapse:collapse;margin-bottom:8px;">
                        <tr>
                            <td style="padding:0;">
                                <p style="font-size:18px;font-weight:bold;color:#000;margin:0;">
                                    <span style="background-color:yellow;padding:2px 6px;border-radius:3px;">
                                        <strong>PO#:</strong> ${escapeHTML(order.poNumber || 'N/A')}
                                    </span>
                                </p>
                            </td>
                        </tr>
                    </table>
                    <table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
                        <tr>
                            <td style="width:50%;vertical-align:top;padding:10px;border:1px solid #ddd;border-radius:5px;box-sizing:border-box;">
                                <h2 style="margin-top:0;color:#000;font-size:16px;font-weight:bold;margin-bottom:5px;background-color:#e0e0e0;padding:5px;"><strong>Bill To:</strong></h2>
                                <p style="white-space:pre-wrap;margin:0;font-size:12px;line-height:1.4;color:#000;">${escapeHTML(order.billingAddress || 'N/A')}</p>
                                <p style="margin:10px 0 0;font-size:12px;color:#000;"><strong>Terms:</strong> ${escapeHTML((order.company && order.company.terms) || 'N/A')}</p>
                                <h3 style="margin:10px 0 5px;font-size:14px;color:#000;background-color:#e0e0e0;padding:5px;"><strong>Ordered By:</strong></h3>
                                <p style="margin:0;font-size:12px;line-height:1.6;color:#000;">
                                    ${escapeHTML(order.orderedByName || '')}${order.orderedByName ? '<br>' : ''}${escapeHTML(order.orderedByEmail || '')}${(order.orderedByEmail && phoneHtml) ? '<br>' : ''}${phoneHtml}
                                </p>
                            </td>
                            <td style="width:10px;padding:0;border:none;"></td>
                            <td style="width:50%;vertical-align:top;padding:10px;border:1px solid #ddd;border-radius:5px;box-sizing:border-box;">
                                <h2 style="margin-top:0;color:#000;font-size:16px;font-weight:bold;margin-bottom:5px;background-color:#e0e0e0;padding:5px;"><strong>Ship To:</strong></h2>
                                <p style="white-space:pre-wrap;margin:0;font-size:12px;line-height:1.4;color:#000;">${escapeHTML(order.shippingAddress || 'N/A')}</p>
                                <p style="margin:7px 0;font-size:12px;color:#000;"><strong>ATTN:</strong> ${escapeHTML(order.attn || '')}</p>
                                <p style="margin:7px 0;font-size:12px;color:#000;"><strong>TAG#:</strong> ${escapeHTML(order.tag || '')}</p>
                                <p style="margin:7px 0;font-size:12px;color:#000;">
                                    <span style="${shipViaStyle}"><strong>Ship Via:</strong> ${escapeHTML(order.shippingMethod || 'N/A')} (${escapeHTML(order.shippingAccountType || '')})</span>
                                </p>
                                ${carrierHtml}
                                ${thirdPartyHtml}
                            </td>
                        </tr>
                    </table>
                    <h2 style="color:#000;font-size:20px;margin:0 0 10px;">Order Summary</h2>
                    <table style="width:100%;border-collapse:collapse;margin-bottom:6px;">
                        <thead>
                            <tr>
                                <th style="border:1px solid #ccc;padding:8px;background-color:#e0e0e0;text-align:center;color:#000;width:6%;">Qty</th>
                                <th style="border:1px solid #ccc;padding:8px;background-color:#e0e0e0;text-align:left;color:#000;">Part Number / Description / Note</th>
                                <th style="border:1px solid #ccc;padding:8px;background-color:#e0e0e0;text-align:right;color:#000;width:14%;">Unit Price</th>
                                <th style="border:1px solid #ccc;padding:8px;background-color:#e0e0e0;text-align:right;color:#000;width:13%;">Total</th>
                            </tr>
                        </thead>
                        <tbody>${itemsHtml}</tbody>
                    </table>
                    <p style="font-weight:bold;text-align:right;margin:4px 0;color:#000;">Item Count: ${totalQty}</p>
                    <p style="font-weight:bold;text-align:right;margin:0 0 20px;color:#000;">Total Price: $${grandTotal.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2})}</p>
                    <div style="text-align:center;margin-top:24px;padding-top:16px;border-top:1px solid #ccc;color:#000;font-size:10px;">
                        <strong>Chicago Stainless Equipment, Inc.</strong><br>
                        1280 SW 34th St, Palm City, FL 34990 USA<br>
                        772-781-1441
                    </div>
                </div>`;

            document.getElementById('orderDocumentContent').innerHTML = docHtml;
            document.getElementById('orderDetailsModal').style.display = 'flex';
        }

        function closeOrderDetailsModal() {
            document.getElementById('orderDetailsModal').style.display = 'none';
        }

        function clickOutsideCloseOrderDetails(event) {
            if (event.target === document.getElementById('orderDetailsModal')) {
                closeOrderDetailsModal();
            }
        }

        function printOrderDetails() {
            const content = document.getElementById('orderDocumentContent');
            if (!content) return;
            const printWindow = window.open('', '', 'width=900,height=700');
            printWindow.document.write(`<!DOCTYPE html>
<html><head><title>CSE Website Order</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: Arial, sans-serif; margin: 20px; color: #000; }
  table { width: 100%; border-collapse: collapse; }
  td, th { vertical-align: top; }
  img { max-width: 100%; }
  h1, h2, h3, p { margin: 0; padding: 0; }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
</style>
</head><body>`);
            printWindow.document.write(content.innerHTML);
            printWindow.document.write('</body></html>');
            printWindow.document.close();
            printWindow.focus();
            printWindow.onload = function () {
                printWindow.print();
                printWindow.close();
            };
        }

        // ----------------- Activity Feed Functions ---------------

        function formatActivityDate(dateString) {
            const date = new Date(dateString);
            const now = new Date();
            const diffInHours = Math.abs(now - date) / 36e5;
            
            if (diffInHours < 1) {
                const diffInMinutes = Math.floor(Math.abs(now - date) / 60000);
                return `${diffInMinutes <= 0 ? 1 : diffInMinutes} min ago`;
            } else if (diffInHours < 24) {
                return `${Math.floor(diffInHours)} hr ago`;
            } else {
                return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            }
        }

// State to keep track of the active filter between renders
let currentActivityFilter = 'all';
let cachedActivityData = [];

/**
 * Helper to correctly parse timestamps from the server as UTC.
 * The server (Render) and database store all times in UTC.
 * We must treat them as UTC so the browser converts to the user's local timezone.
 *
 * Root cause of the previous 5-hour offset bug:
 * The old version stripped the 'Z' from UTC ISO strings, which caused the browser
 * to reinterpret a UTC time (e.g. 20:00 UTC) as local wall-clock time (20:00 EST),
 * producing a 5-hour error for UTC-5 (Eastern) users.
 */
function parseToLocal(dateStr) {
    if (!dateStr) return new Date();
    if (dateStr instanceof Date) return dateStr;

    const str = String(dateStr).trim();

    // Strings that already carry timezone info — parse directly, no adjustment needed
    if (str.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(str)) {
        return new Date(str);
    }

    // The MySQL server clock is US/Central. DATETIME columns (orders.date, login_time,
    // created_at) store the server local time with no timezone marker.
    // We must shift from Central to UTC before the browser applies its own offset.
    //
    // US/Central DST rules: CDT (UTC-5) from 2nd Sunday in March at 2:00 AM
    //                    to 1st Sunday in November at 2:00 AM.
    //                    CST (UTC-6) the rest of the year.

    // Parse the bare string as if it were UTC to get a numeric baseline
    const baseline = new Date(str.replace(' ', 'T') + 'Z');
    if (isNaN(baseline.getTime())) return new Date(str);

    // Determine DST for the year of the stored value
    const yr = baseline.getUTCFullYear();

    // 2nd Sunday in March
    const dstStartBase = new Date(Date.UTC(yr, 2, 1));
    const dstStartDay = (7 - dstStartBase.getUTCDay()) % 7;  // days to first Sunday
    dstStartBase.setUTCDate(1 + dstStartDay + 7);             // + one more week = 2nd Sunday
    dstStartBase.setUTCHours(8);                              // 2:00 AM CST = 08:00 UTC

    // 1st Sunday in November
    const dstEndBase = new Date(Date.UTC(yr, 10, 1));
    const dstEndDay = (7 - dstEndBase.getUTCDay()) % 7;
    dstEndBase.setUTCDate(1 + dstEndDay);                     // 1st Sunday
    dstEndBase.setUTCHours(7);                                // 2:00 AM CDT = 07:00 UTC

    const isCDT = baseline >= dstStartBase && baseline < dstEndBase;
    const offsetMs = isCDT ? 5 * 3600000 : 6 * 3600000;  // CDT=UTC-5, CST=UTC-6

    return new Date(baseline.getTime() + offsetMs);
}

async function fetchActivityFeed() {
    const noActivityMessage = document.getElementById('noActivityMessage');
    const feedContainer = document.getElementById('activityFeedContainer');

    // Only feedContainer is required — noActivityMessage is a bonus loading indicator
    if (!feedContainer) {
        console.warn('activityFeedContainer not found in DOM. Skipping fetchActivityFeed.');
        return;
    }

    // Show loading state if the persistent indicator exists
    if (noActivityMessage) {
        noActivityMessage.innerHTML = `
            <div style="text-align: center; padding: 20px;">
                <div class="spinner-border spinner-border-sm text-primary" role="status"></div>
                <span style="margin-left: 8px;">Syncing activity...</span>
            </div>
        `;
        noActivityMessage.style.display = 'block';
    }

    try {
        const now = new Date();
        const pastDateBoundary = new Date();
        pastDateBoundary.setDate(now.getDate() - 180); // 6 Months
        
        const todayDate = now.toISOString().split('T')[0];
        const apiStartDate = '1970-01-01'; 
        
        const [ordersResponse, companiesResponse, loginsResponse, usersResponse] = await Promise.all([
            apiFetch(`/admin/orders-report?startDate=${apiStartDate}&endDate=${todayDate}`),
            apiFetch("/companies"),
            apiFetch(`/admin/login-report?startDate=${apiStartDate}&endDate=${todayDate}`),
            apiFetch("/admin/users-report")
        ]);

        const recentOrders = await ordersResponse.json();
        const allCompanies = await companiesResponse.json();
        const recentLogins = await loginsResponse.json();
        const allUsers = await usersResponse.json();
        
        let allActivity = [];

        // 1. Process Orders
        recentOrders.forEach(order => {
            const orderDate = parseToLocal(order.date);
            if (orderDate >= pastDateBoundary) {
                let items = [];
                try {
                    items = typeof order.items === 'string' ? JSON.parse(order.items) : (order.items || []);
                } catch (e) { items = []; }

                const totalPrice = items.reduce((sum, item) => {
                    return sum + (parseFloat(item.lineTotal) || parseFloat(item.total) || 
                           (parseFloat(item.netPrice || 0) * parseInt(item.quantity || 0)) || 0);
                }, 0);

                allActivity.push({
                    type: 'order',
                    category: 'orders',
                    timestamp: order.date,
                    color: '#28a745',
                    summary: `🛒 <strong>PO# ${escapeHTML(order.poNumber)}</strong> - $${totalPrice.toFixed(2)}`,
                    detail: `${escapeHTML(order.companyName)} &bull; ${escapeHTML(order.orderedByName || 'User')}`,
                    companyId: order.companyId,
                    orderId: order.id
                });
            }
        });
        
        // 2. Process Logins
        recentLogins.forEach(login => {
            const loginDate = parseToLocal(login.login_time);
            if (loginDate >= pastDateBoundary) {
                allActivity.push({
                    type: 'login',
                    category: 'logins',
                    timestamp: login.login_time,
                    color: '#007bff',
                    summary: `👤 <strong>${escapeHTML(login.email)}</strong> logged in`,
                    detail: `Account: ${escapeHTML(login.company_name)}`,
                    companyId: login.companyId 
                });
            }
        });

        // 3. Process Registrations
        allCompanies.forEach(company => {
            const companyCreationDate = parseToLocal(company.created_at);
            if (companyCreationDate < pastDateBoundary && (company.approved || company.denied)) return;
            
            let statusIcon = '📝';
            let statusText = 'New Registration';
            let type = 'registration-pending';
            let color = '#ffc107';

            if (company.approved) {
                statusIcon = '✅'; statusText = 'Company Approved';
                type = 'registration-approved'; color = '#17a2b8';
            } else if (company.denied) {
                statusIcon = '❌'; statusText = 'Registration Denied';
                type = 'registration-denied'; color = '#dc3545';
            }

            allActivity.push({
                type: type,
                category: 'registrations',
                timestamp: company.created_at || new Date(),
                color: color,
                summary: `${statusIcon} <strong>${statusText}</strong>`,
                detail: `${escapeHTML(company.name)} (ID: ${escapeHTML(String(company.id))})`,
                companyId: company.id
            });
        });

        // 4. Process New User Registrations (individual users, including new users
        //    joining an EXISTING company — these don't create a companies row, so
        //    they wouldn't otherwise appear anywhere in this feed)
        allUsers.forEach(user => {
            const userCreatedDate = parseToLocal(user.created_at);
            if (userCreatedDate < pastDateBoundary) return;

            allActivity.push({
                type: 'user-registration',
                category: 'users',
                timestamp: user.created_at,
                color: '#6f42c1',
                summary: `👥 <strong>${escapeHTML(user.first_name)} ${escapeHTML(user.last_name)}</strong> registered`,
                detail: `${escapeHTML(user.companyName)} &bull; ${escapeHTML(user.email)}`,
                companyId: user.companyId
            });
        });

        // Sort by timestamp
        allActivity.sort((a, b) => parseToLocal(b.timestamp) - parseToLocal(a.timestamp));
        cachedActivityData = allActivity; // Store for filtering
        
        renderActivityList();
        if (noActivityMessage) noActivityMessage.style.display = 'none';
        
    } catch (error) {
        console.error("Error fetching activity feed:", error);
        if (noActivityMessage) {
            noActivityMessage.textContent = 'Failed to load activity feed.';
            noActivityMessage.style.display = 'block';
        }
    }
}

function renderActivityList() {
    const feedContainer = document.getElementById('activityFeedContainer');
    if (!feedContainer) return;

    // Filter items based on selected tab
    const filteredItems = currentActivityFilter === 'all' 
        ? cachedActivityData 
        : cachedActivityData.filter(item => item.category === currentActivityFilter);

    // Get counts for badges
    const counts = {
        all: cachedActivityData.length,
        orders: cachedActivityData.filter(i => i.category === 'orders').length,
        logins: cachedActivityData.filter(i => i.category === 'logins').length,
        registrations: cachedActivityData.filter(i => i.category === 'registrations').length,
        users: cachedActivityData.filter(i => i.category === 'users').length
    };

    // 1. Render Filter Bar
    let htmlContent = `
        <div style="display: flex; gap: 5px; padding: 10px; border-bottom: 1px solid #eee; margin-bottom: 10px; overflow-x: auto; white-space: nowrap;">
            ${['all', 'orders', 'logins', 'registrations', 'users'].map(filter => {
                const isActive = currentActivityFilter === filter;
                return `
                    <button onclick="setActivityFilter('${filter}')" style="
                        padding: 6px 12px; 
                        border-radius: 20px; 
                        border: 1px solid ${isActive ? '#007bff' : '#ddd'}; 
                        background: ${isActive ? '#007bff' : '#fff'}; 
                        color: ${isActive ? '#fff' : '#666'}; 
                        font-size: 12px; 
                        cursor: pointer;
                        transition: all 0.2s;
                    ">
                        ${filter.charAt(0).toUpperCase() + filter.slice(1)} 
                        <span style="opacity: 0.7; font-size: 10px; margin-left: 4px;">(${counts[filter]})</span>
                    </button>
                `;
            }).join('')}
        </div>
    `;

    if (filteredItems.length === 0) {
        htmlContent += `<div style="text-align: center; padding: 40px; color: #999;">No ${currentActivityFilter} activity found.</div>`;
    } else {
        // Show total $ for orders above the feed
        const orderItems = filteredItems.filter(i => i.category === 'orders');
        if (orderItems.length > 0 && currentActivityFilter === 'orders') {
            const orderGrandTotal = orderItems.reduce((sum, item) => {
                const match = item.summary.match(/\$([0-9,]+\.?\d*)/);
                return sum + (match ? parseFloat(match[1].replace(/,/g, '')) : 0);
            }, 0);
            htmlContent += `
                <div style="margin: 0 8px 8px 8px; padding: 10px 14px; background: #f0f4ff; border-radius: 6px; border: 1px solid #d0dbff; display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 13px; font-weight: bold; color: #555;">${currentActivityFilter === 'orders' ? 'All Orders' : 'Orders'} Total</span>
                    <span style="font-size: 16px; font-weight: bold; color: #28a745;">$${orderGrandTotal.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</span>
                </div>
            `;
        }

        let lastHeader = '';
        const now = new Date();
        
        filteredItems.slice(0, 500).forEach(item => {
            // Force local parsing to handle timezone discrepancies
            const eventDate = parseToLocal(item.timestamp);
            
            // Group headers
            const today = new Date();
            const yesterday = new Date();
            yesterday.setDate(today.getDate() - 1);
            
            let currentHeader = eventDate.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
            if (eventDate.toDateString() === today.toDateString()) currentHeader = 'Today';
            else if (eventDate.toDateString() === yesterday.toDateString()) currentHeader = 'Yesterday';

            if (currentHeader !== lastHeader) {
                htmlContent += `<div style="padding: 15px 10px 5px; font-size: 11px; font-weight: bold; color: #888; text-transform: uppercase; letter-spacing: 1px;">${currentHeader}</div>`;
                lastHeader = currentHeader;
            }

            // Enhanced Relative time helper
            const diffSec = Math.floor((now - eventDate) / 1000);
            let relTime = '';
            
            if (diffSec < 60) {
                relTime = 'Just now';
            } else if (diffSec < 3600) {
                const mins = Math.floor(diffSec / 60);
                relTime = `${mins}m ago`;
            } else if (diffSec < 86400) {
                const hours = Math.floor(diffSec / 3600);
                relTime = `${hours}h ago`;
            } else if (diffSec < 172800) {
                relTime = 'Yesterday';
            } else {
                relTime = eventDate.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
            }

            const clickHandler = item.type === 'order' 
                ? `viewOrderDetails(${item.orderId}); toggleCompanyDetails(${item.companyId});` 
                : `toggleCompanyDetails(${item.companyId});`;
            
            htmlContent += `
                <div class="activity-item" style="cursor: pointer; padding: 12px; margin: 4px 8px; border-radius: 6px; border-left: 4px solid ${item.color}; background: #fff; transition: background 0.2s;" 
                     onclick="${clickHandler}"
                     onmouseover="this.style.background='#f8f9fa'" 
                     onmouseout="this.style.background='#fff'">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div style="font-size: 14px; color: #333; overflow-wrap: anywhere;">${item.summary}</div>
                        <div style="font-size: 11px; color: #aaa; white-space: nowrap; margin-left: 10px;">${relTime}</div>
                    </div>
                    <div style="font-size: 12px; color: #777; margin-top: 2px; overflow-wrap: anywhere;">${item.detail}</div>
                </div>
            `;
        });
    }

    feedContainer.innerHTML = htmlContent;
}

function setActivityFilter(filter) {
    currentActivityFilter = filter;
    renderActivityList();
}

        // ── Single consolidated keyboard handler ─────────────────
        document.addEventListener('keydown', function(e) {

            // --- Escape: close modals first, then clear typeahead ---
            if (e.key === 'Escape') {
                const openModals = Array.from(document.querySelectorAll('div[id$="Modal"]'))
                    .filter(m => m.style.display && m.style.display !== 'none');

                if (openModals.length > 0) {
                    openModals.forEach(modal => {
                        if (modal.id === 'orderDetailsModal') {
                            closeOrderDetailsModal();
                        } else {
                            closeModal(modal.id);
                        }
                    });
                    return;
                }

                if (typeaheadQuery) { clearTypeahead(); }
                return;
            }

            // --- All other keys: typeahead only (skip when typing in a field) ---
            if (isTypingElsewhere()) return;
            if (e.ctrlKey || e.metaKey || e.altKey) return;

            if (e.key === 'Enter') return;
            if (e.key === 'ArrowDown' && typeaheadMatches.length) {
                e.preventDefault();
                typeaheadIndex = (typeaheadIndex + 1) % typeaheadMatches.length;
                highlightMatch(); updateToast(); return;
            }
            if (e.key === 'ArrowUp' && typeaheadMatches.length) {
                e.preventDefault();
                typeaheadIndex = (typeaheadIndex - 1 + typeaheadMatches.length) % typeaheadMatches.length;
                highlightMatch(); updateToast(); return;
            }
            if (e.key === 'Backspace') {
                typeaheadQuery = typeaheadQuery.slice(0, -1);
                typeaheadQuery ? runTypeahead() : clearTypeahead();
                return;
            }
            if (e.key.length !== 1) return;
            typeaheadQuery += e.key;
            runTypeahead();
        });
        // ── End keyboard handler ──────────────────────────────────

        // ── Keyboard Type-Ahead for Companies List ───────────────
        let typeaheadQuery = '';
        let typeaheadMatches = [];
        let typeaheadIndex = 0;

        // Pill pinned to the bottom of the companies column
        const taToast = document.createElement('div');
        taToast.style.cssText = 'display:none;position:absolute;bottom:12px;left:50%;transform:translateX(-50%);' +
            'background:rgba(20,20,20,0.8);color:#fff;padding:5px 8px 5px 14px;border-radius:24px;font-size:13px;' +
            'z-index:10000;pointer-events:auto;box-shadow:0 4px 14px rgba(0,0,0,0.2);white-space:nowrap;display:none;align-items:center;gap:6px;';
        window.addEventListener('DOMContentLoaded', () => {
            const col = document.getElementById('companiesColumn');
            if (col) col.appendChild(taToast);

            // Clear typeahead when user manually clicks a company
            const listEl = document.getElementById('companiesList');
            if (listEl) {
                listEl.addEventListener('click', function(e) {
                    const item = e.target.closest('.company-list-item');
                    if (item && typeaheadQuery) clearTypeahead();
                });
            }
        });

        function isTypingElsewhere() {
            const t = document.activeElement && document.activeElement.tagName;
            return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT';
        }

        // Wrap toggleCompanyDetails so any manual click clears the typeahead
        const _origToggleCompanyDetails = toggleCompanyDetails;
        let typeaheadCalling = false;
        let typeaheadSelectTimer = null;
        toggleCompanyDetails = function(id, ...args) {
            if (!typeaheadCalling && typeaheadQuery) clearTypeahead();
            return _origToggleCompanyDetails(id, ...args);
        };

        function runTypeahead() {
            const q = typeaheadQuery.toLowerCase();
            const prefix   = companies.filter(c => c.name.toLowerCase().startsWith(q));
            const contains = companies.filter(c => !c.name.toLowerCase().startsWith(q) && c.name.toLowerCase().includes(q));
            typeaheadMatches = [...prefix, ...contains];
            typeaheadIndex = 0;
            applyMatchHighlights();
            if (typeaheadMatches.length) highlightMatch();
            updateToast();
        }

        function applyMatchHighlights() {
            // Reset all items first
            document.querySelectorAll('.company-list-item').forEach(el => {
                el.style.outline = ''; el.style.outlineOffset = '';
                el.style.backgroundColor = '';
            });
            // Light blue background on all matches
            typeaheadMatches.forEach((c, i) => {
                const el = document.querySelector(`[data-company-id="${c.id}"]`);
                if (el) el.style.backgroundColor = '#cce5ff';
            });
        }

        function highlightMatch() {
            const target = typeaheadMatches[typeaheadIndex];
            if (!target) return;
            const el = document.querySelector(`[data-company-id="${target.id}"]`);
            if (!el) return;

            // Re-apply all match backgrounds, then make current one darker
            applyMatchHighlights();
            el.style.backgroundColor = '#66b2ff';
            el.style.outline = '2px solid #007bff';
            el.style.outlineOffset = '-2px';

            // Center scroll immediately (no panel re-render yet)
            const list = document.getElementById('companiesList');
            if (list) {
                const offset = el.offsetTop - (list.clientHeight / 2) + (el.offsetHeight / 2);
                list.scrollTop = offset;
            }

            // Debounce the detail panel load so rapid typing/arrowing doesn't flash
            clearTimeout(typeaheadSelectTimer);
            typeaheadSelectTimer = setTimeout(() => {
                typeaheadCalling = true;
                _origToggleCompanyDetails(target.id);
                typeaheadCalling = false;
            }, 300);
        }

        function updateToast() {
            if (typeaheadMatches.length === 0) {
                taToast.innerHTML = `<span style="opacity:.5;font-size:11px;margin-right:4px;">JUMP TO</span>${typeaheadQuery}<span style="opacity:.5;font-size:11px;margin-left:6px;">no match</span>`;
            } else if (typeaheadMatches.length === 1) {
                taToast.innerHTML = `<span style="opacity:.5;font-size:11px;margin-right:4px;">JUMP TO</span>${typeaheadQuery}`;
            } else {
                const btnStyle = 'background:rgba(255,255,255,0.15);border:none;color:#fff;cursor:pointer;border-radius:50%;width:24px;height:24px;font-size:18px;font-weight:900;line-height:1;display:inline-flex;align-items:center;justify-content:center;padding:0;flex-shrink:0;';
                taToast.innerHTML =
                    `<button style="${btnStyle}" onclick="typeaheadPrev(event)">&#9650;</button>` +
                    `<span style="opacity:.5;font-size:11px;">JUMP TO</span> ${typeaheadQuery} ` +
                    `<span style="opacity:.5;font-size:11px;">${typeaheadIndex + 1}/${typeaheadMatches.length}</span>` +
                    `<button style="${btnStyle}" onclick="typeaheadNext(event)">&#9660;</button>`;
            }
            taToast.style.display = 'flex';
        }

        function typeaheadNext(e) {
            e.stopPropagation();
            typeaheadIndex = (typeaheadIndex + 1) % typeaheadMatches.length;
            highlightMatch(); updateToast();
        }

        function typeaheadPrev(e) {
            e.stopPropagation();
            typeaheadIndex = (typeaheadIndex - 1 + typeaheadMatches.length) % typeaheadMatches.length;
            highlightMatch(); updateToast();
        }

        function clearTypeahead() {
            typeaheadQuery = ''; typeaheadMatches = []; typeaheadIndex = 0;
            taToast.style.display = 'none';
            document.querySelectorAll('.company-list-item').forEach(el => {
                el.style.outline = ''; el.style.outlineOffset = '';
                el.style.backgroundColor = '';
            });
        }
        // ── Abandoned Carts Report ───────────────────────────────
        let abandonedCartsData = [];
        let sortAbandonedCartsColumn = 'date';
        let sortAbandonedCartsDirection = 'desc';
        let abandonedCartsRangeText = 'Showing all abandoned carts';

        function formatDateForDisplay(isoDateStr) {
            const [y, m, d] = isoDateStr.split('-');
            return new Date(y, m - 1, d).toLocaleDateString('en-US');
        }

        function toDateInputValue(date) {
            const y = date.getFullYear();
            const m = String(date.getMonth() + 1).padStart(2, '0');
            const d = String(date.getDate()).padStart(2, '0');
            return `${y}-${m}-${d}`;
        }

        function applyAbandonedCartsPreset(days) {
            const end = new Date();
            const start = new Date();
            start.setDate(start.getDate() - (days - 1));
            document.getElementById('abandonedCartsStartDate').value = toDateInputValue(start);
            document.getElementById('abandonedCartsEndDate').value   = toDateInputValue(end);
            generateAbandonedCartsReport();
        }

        function applyAbandonedCartsPresetThisMonth() {
            const now = new Date();
            const start = new Date(now.getFullYear(), now.getMonth(), 1);
            document.getElementById('abandonedCartsStartDate').value = toDateInputValue(start);
            document.getElementById('abandonedCartsEndDate').value   = toDateInputValue(now);
            generateAbandonedCartsReport();
        }

        function applyAbandonedCartsPresetAll() {
            document.getElementById('abandonedCartsStartDate').value = '';
            document.getElementById('abandonedCartsEndDate').value   = '';
            generateAbandonedCartsReport();
        }

        function openAbandonedCartsReportModal() {
            abandonedCartsData = [];
            document.getElementById('abandonedCartsReportResults').style.display = 'none';
            document.getElementById('noAbandonedCartsMessage').style.display = 'none';
            document.getElementById('abandonedCartsTableBody').innerHTML = '';
            document.getElementById('abandonedCartsStartDate').value = '';
            document.getElementById('abandonedCartsEndDate').value = '';
            document.getElementById('abandonedCartsReportModal').style.display = 'block';
            generateAbandonedCartsReport(); // auto-load all on open
        }

        async function generateAbandonedCartsReport() {
            const startDate = document.getElementById('abandonedCartsStartDate').value;
            const endDate   = document.getElementById('abandonedCartsEndDate').value;
            if (startDate && endDate && new Date(startDate) > new Date(endDate))
                return showMessage('error', 'Start date cannot be after the end date.');
            const params = new URLSearchParams();
            if (startDate) params.set('startDate', startDate);
            if (endDate)   params.set('endDate', endDate);
            const qs = params.toString() ? '?' + params.toString() : '';
            if (startDate && endDate) {
                abandonedCartsRangeText = `Showing carts from ${formatDateForDisplay(startDate)} to ${formatDateForDisplay(endDate)}`;
            } else if (startDate) {
                abandonedCartsRangeText = `Showing carts from ${formatDateForDisplay(startDate)} onward`;
            } else if (endDate) {
                abandonedCartsRangeText = `Showing carts through ${formatDateForDisplay(endDate)}`;
            } else {
                abandonedCartsRangeText = 'Showing all abandoned carts';
            }
            const loadingEl = document.getElementById('abandonedCartsLoading');
            const resultsEl = document.getElementById('abandonedCartsReportResults');
            resultsEl.style.display = 'none';
            document.getElementById('noAbandonedCartsMessage').style.display = 'none';
            loadingEl.style.display = 'block';
            try {
                const response = await apiFetch(`/admin/abandoned-carts-report${qs}`);
                abandonedCartsData = await response.json();
                sortAbandonedCartsColumn = 'date';
                sortAbandonedCartsDirection = 'desc';
                sortAbandonedCartsData();
                displayAbandonedCartsReport();
            } catch (error) {
                showMessage('error', 'Failed to generate abandoned carts report.');
                console.error('Error generating abandoned carts report:', error);
            } finally {
                loadingEl.style.display = 'none';
            }
        }

        function sortAbandonedCartsReport(column) {
            if (sortAbandonedCartsColumn === column) {
                sortAbandonedCartsDirection = sortAbandonedCartsDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortAbandonedCartsColumn = column;
                sortAbandonedCartsDirection = 'asc';
            }
            sortAbandonedCartsData();
            filterAbandonedCartsDisplay();
        }

        function sortAbandonedCartsData() {
            abandonedCartsData.sort((a, b) => {
                let valA = a[sortAbandonedCartsColumn];
                let valB = b[sortAbandonedCartsColumn];
                if (sortAbandonedCartsColumn === 'date') { valA = new Date(valA); valB = new Date(valB); }
                if (sortAbandonedCartsColumn === 'total' || sortAbandonedCartsColumn === 'itemCount') { valA = parseFloat(valA) || 0; valB = parseFloat(valB) || 0; }
                let cmp = valA > valB ? 1 : valA < valB ? -1 : 0;
                return sortAbandonedCartsDirection === 'asc' ? cmp : -cmp;
            });
        }

        function displayAbandonedCartsReport() {
            const filterEl = document.getElementById('abandonedCartsFilter');
            if (filterEl) filterEl.value = '';
            renderAbandonedCartsTable(abandonedCartsData);
        }

        function filterAbandonedCartsDisplay() {
            const q = document.getElementById('abandonedCartsFilter').value.toLowerCase().trim();
            const filtered = q
                ? abandonedCartsData.filter(c =>
                    (c.companyName || '').toLowerCase().includes(q) ||
                    (c.userName    || '').toLowerCase().includes(q) ||
                    (c.email       || '').toLowerCase().includes(q))
                : abandonedCartsData;
            renderAbandonedCartsTable(filtered);
        }

        function renderAbandonedCartsTable(data) {
            const tbody       = document.getElementById('abandonedCartsTableBody');
            const noMsg       = document.getElementById('noAbandonedCartsMessage');
            const results     = document.getElementById('abandonedCartsReportResults');
            const rangeLabel  = document.getElementById('abandonedCartsRangeLabel');
            const summaryBar  = document.getElementById('abandonedCartsSummaryBar');
            results.style.display = 'block';
            if (rangeLabel) rangeLabel.textContent = abandonedCartsRangeText;
            tbody.innerHTML = '';
            if (!data.length) {
                if (summaryBar) summaryBar.textContent = '';
                noMsg.textContent = abandonedCartsRangeText === 'Showing all abandoned carts'
                    ? 'No abandoned carts found.'
                    : 'No abandoned carts found for the selected date range.';
                noMsg.style.display = 'block';
                return;
            }
            noMsg.style.display = 'none';
            if (summaryBar) {
                const totalValue = data.reduce((sum, c) => sum + (parseFloat(c.total) || 0), 0);
                summaryBar.textContent = `${data.length} cart${data.length === 1 ? '' : 's'} · $${totalValue.toFixed(2)} total`;
            }
            data.forEach(cart => {
                const date  = cart.date  ? new Date(cart.date).toLocaleDateString('en-US') : '';
                const total = cart.total != null ? '$' + parseFloat(cart.total).toFixed(2) : '';
                const tr = document.createElement('tr');
                tr.style.cursor = 'pointer';
                tr.title = 'Click to view cart contents';
                tr.addEventListener('mouseenter', () => tr.style.backgroundColor = '#f5f5f5');
                tr.addEventListener('mouseleave', () => tr.style.backgroundColor = '');
                tr.addEventListener('click', () => openAbandonedCartDetailModal(cart));
                tr.innerHTML = `
                    <td style="border:1px solid #ddd;padding:8px;">${date}</td>
                    <td style="border:1px solid #ddd;padding:8px;">${escapeHTML(cart.companyName || '')}</td>
                    <td style="border:1px solid #ddd;padding:8px;">${escapeHTML(cart.userName || '')}</td>
                    <td style="border:1px solid #ddd;padding:8px;">${escapeHTML(cart.email || '')}</td>
                    <td style="border:1px solid #ddd;padding:8px;">${escapeHTML(cart.itemCount || '')}</td>
                    <td style="border:1px solid #ddd;padding:8px;">${escapeHTML(total)}</td>
                    <td style="border:1px solid #ddd;padding:8px;"></td>`;
                const deleteBtn = document.createElement('button');
                deleteBtn.textContent = 'Delete';
                deleteBtn.style.cssText = 'padding:5px 10px;border:none;border-radius:4px;cursor:pointer;background-color:#dc3545;color:white;font-size:13px;';
                deleteBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    deleteAbandonedCart(cart);
                });
                tr.lastElementChild.appendChild(deleteBtn);
                tbody.appendChild(tr);
            });
        }

        function openAbandonedCartDetailModal(cart) {
            const meta  = document.getElementById('abandonedCartDetailMeta');
            const tbody = document.getElementById('abandonedCartDetailTableBody');
            const noMsg = document.getElementById('noAbandonedCartDetailMessage');
            const date  = cart.date ? new Date(cart.date).toLocaleDateString('en-US') : '';
            const total = cart.total != null ? '$' + parseFloat(cart.total).toFixed(2) : '';

            meta.innerHTML = `
                <strong>${escapeHTML(cart.companyName || '')}</strong> — ${escapeHTML(cart.userName || '')} (${escapeHTML(cart.email || '')})<br>
                Date: ${date} &nbsp;|&nbsp; Items: ${escapeHTML(cart.itemCount || '')} &nbsp;|&nbsp; Total: ${escapeHTML(total)}`;
            tbody.innerHTML = '';
            noMsg.textContent = 'No item details are available for this cart.';
            document.getElementById('abandonedCartDetailModal').style.display = 'block';

            const deleteBtn = document.getElementById('abandonedCartDetailDeleteBtn');
            deleteBtn.onclick = () => deleteAbandonedCart(cart, () => closeModal('abandonedCartDetailModal'));

            const items = Array.isArray(cart.items) ? cart.items : [];
            if (!items.length) {
                noMsg.style.display = 'block';
                return;
            }
            noMsg.style.display = 'none';
            items.forEach(item => {
                const price = item.price != null ? '$' + parseFloat(item.price).toFixed(2) : '';
                tbody.innerHTML += `<tr>
                    <td style="border:1px solid #ddd;padding:8px;">${escapeHTML(item.partNo || '')}</td>
                    <td style="border:1px solid #ddd;padding:8px;">${escapeHTML(item.description || '').replace('**', '<br>')}</td>
                    <td style="border:1px solid #ddd;padding:8px;text-align:right;">${escapeHTML(item.quantity || '')}</td>
                    <td style="border:1px solid #ddd;padding:8px;text-align:right;">${escapeHTML(price)}</td>
                </tr>`;
            });
        }

        async function deleteAbandonedCart(cart, onSuccess) {
            const label = cart.companyName || cart.userName || cart.email || 'this cart';
            if (!confirm(`Delete the abandoned cart for ${label}?`)) return;

            // Optimistically remove from the visible table; restore on Undo.
            abandonedCartsData = abandonedCartsData.filter(c => c.userId !== cart.userId);
            filterAbandonedCartsDisplay();
            if (onSuccess) onSuccess();

            scheduleUndoableDelete(`cart-${cart.userId}`, `abandoned cart (${label})`, async () => {
                try {
                    await apiFetch('/admin/delete-abandoned-cart', {
                        method: 'POST',
                        body: JSON.stringify({ userId: cart.userId })
                    });
                    showMessage('success', 'Abandoned cart deleted.');
                    refreshDashboardSummary();
                } catch (error) {
                    console.error('Error deleting abandoned cart:', error);
                    showMessage('error', 'Failed to delete abandoned cart.');
                    // Restore locally since the delete didn't actually happen.
                    abandonedCartsData.push(cart);
                    sortAbandonedCartsData();
                    filterAbandonedCartsDisplay();
                }
            }, () => restoreAbandonedCart(cart));
        }

        function restoreAbandonedCart(cart) {
            if (!abandonedCartsData.some(c => c.userId === cart.userId)) {
                abandonedCartsData.push(cart);
                sortAbandonedCartsData();
            }
            filterAbandonedCartsDisplay();
        }

        function downloadAbandonedCartsCSV() {
            if (!abandonedCartsData.length) return;
            const headers = ['Date','Company','User','Email','Items','Total'];
            const rows = abandonedCartsData.map(c => [
                c.date ? new Date(c.date).toLocaleDateString('en-US') : '',
                c.companyName || '', c.userName || '', c.email || '',
                c.itemCount || '',
                c.total != null ? parseFloat(c.total).toFixed(2) : ''
            ]);
            const csv = [headers, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
            const a = document.createElement('a');
            a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
            a.download = 'abandoned_carts_report.csv';
            a.click();
        }
        // ── End Abandoned Carts Report ───────────────────────────

        // ── End Type-Ahead ───────────────────────────────────────

        // ------------- Live Clock ---------------
        function updateLiveClock() {
            const now = new Date();
            const dateEl = document.getElementById("liveDate");
            const timeEl = document.getElementById("liveTime");
            if (!dateEl || !timeEl) return;
            dateEl.textContent = now.toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric", year: "numeric" });
            timeEl.textContent = now.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true });
        }
        updateLiveClock();
        setInterval(updateLiveClock, 1000);
        // ----------------------------------------

        window.onload = async () => {
            document.getElementById('adminLoginBtn').addEventListener('click', handleAdminLogin);
            checkAdminLoginStatus();
            checkRememberMe();
            // The first activity feed fetch is now reliably triggered inside checkAdminLoginStatus on success.
        };


        // ── Configurator Logo Dropdown Population ─────────────────
        // Fetches logo options from the server (reads logos.php) and populates
        // the Configurator Logo dropdowns in both Add and Edit Company modals.
        async function populateLogoDropdowns(selectedValue) {
            const selectIds = ['companyLogoCode', 'editCompanyLogoCode'];
            const selects = selectIds.map(id => document.getElementById(id)).filter(Boolean);
            if (selects.length === 0) return;

            let options = [{ value: '', label: '-- None / Not Listed --' }];
            let loaded = false;

            try {
                const res = await apiFetch('/admin/logo-options');
                if (res.ok) {
                    const data = await res.json();
                    if (Array.isArray(data) && data.length > 0) {
                        options = options.concat(data);
                        loaded = true;
                    }
                }
            } catch(e) {
                console.warn('Could not load logo options from server (is server.js updated?):', e);
            }

            selects.forEach(sel => {
                const current = sel.value;
                sel.innerHTML = '';
                if (!loaded) {
                    // Endpoint not available yet — show a clear placeholder
                    const placeholder = document.createElement('option');
                    placeholder.value = '';
                    placeholder.textContent = '-- Deploy updated server.js to enable --';
                    sel.appendChild(placeholder);
                    return;
                }
                options.forEach(({ value, label }) => {
                    const opt = document.createElement('option');
                    opt.value = value;
                    opt.textContent = label;
                    sel.appendChild(opt);
                });
                if (selectedValue !== undefined) {
                    sel.value = selectedValue;
                } else if (current) {
                    sel.value = current;
                }
            });
        }
        // ── End Configurator Logo Dropdown Population ───────

        // ── Auto-refresh every 5 minutes ─────────────────────────
        function isAnyModalOpen() {
            return !!document.querySelector('div[id$="Modal"][style*="display: block"]');
        }

        setInterval(async () => {
            if (isAnyModalOpen()) return;   // don't disrupt an open modal
            if (typeaheadQuery) return;      // don't disrupt active typeahead
            await fetchCompanies();
            await fetchActivityFeed();       // keep the activity feed current on long idle sessions too
            refreshDashboardSummary();       // keep the summary bar in sync too
        }, 5 * 60 * 1000);
        // ── End Auto-refresh ─────────────────────────────────────

    </script>
</body>
</html>
