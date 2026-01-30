async function login(username, password) {
    try {
        const response = await fetch('http://localhost:3000/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok);

        if (response.ok) {
            // Save token in memory (or sessionStorage for page referesh)
            sessionStorage.setItem('authToken', data.token);
            showDashboard(data.user);
        } else {
            alert('Login failed: ' + data.error);
        }
    } catch (err) {
        alert('Network error');
    }
    }

    function getAuthHeader() {
        const token = sessionStorage.getItem('authToken');
        return token ? { Authorization: `Bearer ${token}` } : {};
    }

// Example: Fetch admin data
    async function loadAdminDashboard() {
        const res = await fetch('http://localhost:3000/api/admin/dashboard', {
            headers: getAuthHeader()
            });
            if (res.ok) {
                const data = await res.json();
                document.getElementById('content').innerText = data.message;
            } else {
                document.getElementById('content').innerText = 'Access denied!';
            }
        }

// Phase 4: Data Persistence
const STORAGE_KEY = 'ipt_demo_v1';

// Phase 2: Global Variables
let currentUser = null;

// Initialize database structure
window.db = {
    accounts: [],
    departments: [],
    employees: [],
    requests: []
};

// Phase 4: Load from localStorage
function loadFromStorage() {
    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
            window.db = JSON.parse(stored);
            // Ensure all arrays exist
            window.db.accounts = window.db.accounts || [];
            window.db.departments = window.db.departments || [];
            window.db.employees = window.db.employees || [];
            window.db.requests = window.db.requests || [];
        } else {
            // Seed initial data
            seedInitialData();
        }
    } catch (e) {
        console.error('Error loading from storage:', e);
        seedInitialData();
    }
}

// Phase 4: Seed initial data
function seedInitialData() {
    window.db = {
        accounts: [
            {
                id: Date.now().toString(),
                firstName: 'Admin',
                lastName: 'User',
                email: 'admin@example.com',
                password: 'Password123!',
                role: 'admin',
                verified: true
            }
        ],
        departments: [
            { id: '1', name: 'Engineering', description: 'Software team' },
            { id: '2', name: 'HR', description: 'Human Resources' }
        ],
        employees: [],
        requests: []
    };
    saveToStorage();
}

// Phase 4: Save to localStorage
function saveToStorage() {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(window.db));
    } catch (e) {
        console.error('Error saving to storage:', e);
        showToast('Error saving data', 'danger');
    }
}

// Phase 2: Navigate to hash
function navigateTo(hash) {
    window.location.hash = hash;
}

// Phase 2: Handle routing
function handleRouting() {
    const hash = window.location.hash || '#/';
    const route = hash.substring(1) || '/';
    
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Define routes
    const routeMap = {
        '/': 'home-page',
        '/home': 'home-page',
        '/register': 'register-page',
        '/verify-email': 'verify-email-page',
        '/login': 'login-page',
        '/profile': 'profile-page',
        '/accounts': 'accounts-page',
        '/departments': 'departments-page',
        '/employees': 'employees-page',
        '/my-requests': 'my-requests-page'
    };
    
    const pageId = routeMap[route];
    
    // Protected routes
    const protectedRoutes = ['/profile', '/accounts', '/departments', '/employees', '/my-requests'];
    if (protectedRoutes.includes(route) && !currentUser) {
        navigateTo('#/login');
        return;
    }
    
    // Admin-only routes
    const adminRoutes = ['/accounts', '/departments', '/employees'];
    if (adminRoutes.includes(route) && currentUser && currentUser.role !== 'admin') {
        navigateTo('#/profile');
        showToast('Access denied. Admin only.', 'danger');
        return;
    }
    
    // Show the page
    if (pageId) {
        const page = document.getElementById(pageId);
        if (page) {
            page.classList.add('active');
            
            // Call page-specific render functions
            if (route === '/profile') {
                renderProfile();
            } else if (route === '/accounts') {
                renderAccountsList();
            } else if (route === '/departments') {
                renderDepartmentsList();
            } else if (route === '/employees') {
                renderEmployeesTable();
            } else if (route === '/my-requests') {
                renderRequestsTable();
            } else if (route === '/verify-email') {
                const email = localStorage.getItem('unverified_email');
                if (email) {
                    document.getElementById('verifyEmailMessage').textContent = `Verification sent to ${email}`;
                }
            }
        }
    }
}

// Phase 3.D: Set auth state
function setAuthState(isAuth, user) {
    currentUser = user;
    const body = document.body;
    
    if (isAuth && user) {
        body.classList.remove('not-authenticated');
        body.classList.add('authenticated');
        if (user.role === 'admin') {
            body.classList.add('is-admin');
        } else {
            body.classList.remove('is-admin');
        }
        // Update username in dropdown
        const userNameDisplay = document.getElementById('userNameDisplay');
        if (userNameDisplay) {
            userNameDisplay.textContent = user.role === 'admin' ? 'Admin' : `${user.firstName} ${user.lastName}`;
        }
    } else {
        body.classList.remove('authenticated', 'is-admin');
        body.classList.add('not-authenticated');
    }
}

// Phase 8: Toast notifications
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    const toastId = 'toast-' + Date.now();
    const bgClass = {
        'success': 'bg-success',
        'danger': 'bg-danger',
        'warning': 'bg-warning',
        'info': 'bg-info'
    }[type] || 'bg-info';
    
    const toastHTML = `
        <div id="${toastId}" class="toast ${bgClass} text-white" role="alert">
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    toastContainer.insertAdjacentHTML('beforeend', toastHTML);
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, { delay: 3000 });
    toast.show();
    
    toastElement.addEventListener('hidden.bs.toast', () => {
        toastElement.remove();
    });
}

// Phase 3.A: Registration
function handleRegister(event) {
    event.preventDefault();
    
    const firstName = document.getElementById('regFirstName').value.trim();
    const lastName = document.getElementById('regLastName').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const password = document.getElementById('regPassword').value;
    
    // Validation
    if (password.length < 6) {
        showToast('Password must be at least 6 characters', 'danger');
        return;
    }
    
    // Check if email exists
    const existingAccount = window.db.accounts.find(acc => acc.email === email);
    if (existingAccount) {
        showToast('Email already exists', 'danger');
        return;
    }
    
    // Create new account
    const newAccount = {
        id: Date.now().toString(),
        firstName,
        lastName,
        email,
        password,
        role: 'user',
        verified: false
    };
    
    window.db.accounts.push(newAccount);
    saveToStorage();
    
    // Store email for verification
    localStorage.setItem('unverified_email', email);
    
    showToast('Registration successful! Please verify your email.', 'success');
    navigateTo('#/verify-email');
}

// Phase 3.B: Email Verification
function handleVerifyEmail() {
    const email = localStorage.getItem('unverified_email');
    if (!email) {
        showToast('No pending verification found', 'warning');
        navigateTo('#/register');
        return;
    }
    
    const account = window.db.accounts.find(acc => acc.email === email);
    if (account) {
        account.verified = true;
        saveToStorage();
        localStorage.removeItem('unverified_email');
        showToast('Email verified successfully!', 'success');
        navigateTo('#/login');
    } else {
        showToast('Account not found', 'danger');
        navigateTo('#/register');
    }
}

// Phase 3.C: Login
function handleLogin(event) {
    event.preventDefault();
    
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    const errorDiv = document.getElementById('loginError');
    
    // Find account
    const account = window.db.accounts.find(
        acc => acc.email === email && acc.password === password && acc.verified === true
    );
    
    if (account) {
        // Save auth token
        localStorage.setItem('auth_token', email);
        
        // Set auth state
        const user = {
            id: account.id,
            firstName: account.firstName,
            lastName: account.lastName,
            email: account.email,
            role: account.role
        };
        setAuthState(true, user);
        
        showToast('Login successful!', 'success');
        navigateTo('#/profile');
    } else {
        errorDiv.textContent = 'Invalid email, password, or unverified account';
        errorDiv.classList.remove('d-none');
        showToast('Login failed', 'danger');
    }
}

// Phase 3.E: Logout
function handleLogout() {
    localStorage.removeItem('auth_token');
    setAuthState(false, null);
    showToast('Logged out successfully', 'info');
    navigateTo('#/home');
}

// Check auth on page load
function checkAuth() {
    const authToken = localStorage.getItem('auth_token');
    if (authToken) {
        const account = window.db.accounts.find(acc => acc.email === authToken);
        if (account) {
            const user = {
                id: account.id,
                firstName: account.firstName,
                lastName: account.lastName,
                email: account.email,
                role: account.role
            };
            setAuthState(true, user);
        }
    }
}

// Phase 5: Profile Page
function renderProfile() {
    if (!currentUser) return;
    
    const profileContent = document.getElementById('profileContent');
    profileContent.innerHTML = `
        <div class="mb-3">
            <strong>Name:</strong> ${currentUser.firstName} ${currentUser.lastName}
        </div>
        <div class="mb-3">
            <strong>Email:</strong> ${currentUser.email}
        </div>
        <div class="mb-3">
            <strong>Role:</strong> ${currentUser.role === 'admin' ? 'Admin' : 'User'}
        </div>
        <button class="btn btn-primary" onclick="alert('Edit profile functionality coming soon!')">Edit Profile</button>
    `;
}

// Phase 6.A: Accounts List
function renderAccountsList() {
    const container = document.getElementById('accountsTableContainer');
    const accounts = window.db.accounts || [];
    
    if (accounts.length === 0) {
        container.innerHTML = '<p>No accounts found.</p>';
        return;
    }
    
    let html = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Verified</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    accounts.forEach(account => {
        const verifiedIcon = account.verified ? '✓' : '—';
        const verifiedClass = account.verified ? 'text-success' : 'text-muted';
        html += `
            <tr>
                <td>${account.firstName} ${account.lastName}</td>
                <td>${account.email}</td>
                <td>${account.role === 'admin' ? 'Admin' : 'User'}</td>
                <td class="${verifiedClass}">${verifiedIcon}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="editAccount('${account.id}')">Edit</button>
                    <button class="btn btn-sm btn-warning" onclick="resetPassword('${account.id}')">Reset Password</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteAccount('${account.id}')">Delete</button>
                </td>
            </tr>
        `;
    });
    
    html += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = html;
}

// Phase 6.A: Add Account
function showAccountForm(accountId = null) {
    const formCard = document.getElementById('accountFormCard');
    const form = document.getElementById('accountForm');
    const editIdInput = document.getElementById('accountFormEditId');
    
    formCard.classList.remove('d-none');
    
    if (accountId) {
        const account = window.db.accounts.find(acc => acc.id === accountId);
        if (account) {
            editIdInput.value = accountId;
            document.getElementById('accountFirstName').value = account.firstName;
            document.getElementById('accountLastName').value = account.lastName;
            document.getElementById('accountEmail').value = account.email;
            document.getElementById('accountRole').value = account.role;
            document.getElementById('accountVerified').checked = account.verified;
            document.getElementById('accountPassword').required = false;
        }
    } else {
        form.reset();
        editIdInput.value = '';
        document.getElementById('accountPassword').required = true;
    }
    
    formCard.scrollIntoView({ behavior: 'smooth' });
}

// Phase 6.A: Edit Account
function editAccount(accountId) {
    showAccountForm(accountId);
}

// Phase 6.A: Reset Password
function resetPassword(accountId) {
    const newPassword = prompt('Enter new password (min 6 characters):');
    if (newPassword && newPassword.length >= 6) {
        const account = window.db.accounts.find(acc => acc.id === accountId);
        if (account) {
            account.password = newPassword;
            saveToStorage();
            showToast('Password reset successfully', 'success');
            renderAccountsList();
        }
    } else if (newPassword) {
        showToast('Password must be at least 6 characters', 'danger');
    }
}

// Phase 6.A: Delete Account
function deleteAccount(accountId) {
    const account = window.db.accounts.find(acc => acc.id === accountId);
    if (!account) return;
    
    // Prevent self-deletion
    if (currentUser && currentUser.email === account.email) {
        showToast('You cannot delete your own account', 'danger');
        return;
    }
    
    if (confirm(`Are you sure you want to delete ${account.firstName} ${account.lastName}?`)) {
        window.db.accounts = window.db.accounts.filter(acc => acc.id !== accountId);
        // Also remove associated employee record
        window.db.employees = window.db.employees.filter(emp => emp.userId !== accountId);
        saveToStorage();
        showToast('Account deleted successfully', 'success');
        renderAccountsList();
    }
}

// Phase 6.A: Handle Account Form
function handleAccountForm(event) {
    event.preventDefault();
    
    const editId = document.getElementById('accountFormEditId').value;
    const firstName = document.getElementById('accountFirstName').value.trim();
    const lastName = document.getElementById('accountLastName').value.trim();
    const email = document.getElementById('accountEmail').value.trim();
    const password = document.getElementById('accountPassword').value;
    const role = document.getElementById('accountRole').value;
    const verified = document.getElementById('accountVerified').checked;
    
    if (editId) {
        // Edit existing
        const account = window.db.accounts.find(acc => acc.id === editId);
        if (account) {
            // Check email uniqueness (except current account)
            const emailExists = window.db.accounts.find(acc => acc.email === email && acc.id !== editId);
            if (emailExists) {
                showToast('Email already exists', 'danger');
                return;
            }
            
            account.firstName = firstName;
            account.lastName = lastName;
            account.email = email;
            if (password) {
                account.password = password;
            }
            account.role = role;
            account.verified = verified;
            saveToStorage();
            showToast('Account updated successfully', 'success');
        }
    } else {
        // Create new
        // Check email uniqueness
        const emailExists = window.db.accounts.find(acc => acc.email === email);
        if (emailExists) {
            showToast('Email already exists', 'danger');
            return;
        }
        
        if (!password || password.length < 6) {
            showToast('Password must be at least 6 characters', 'danger');
            return;
        }
        
        const newAccount = {
            id: Date.now().toString(),
            firstName,
            lastName,
            email,
            password,
            role,
            verified
        };
        window.db.accounts.push(newAccount);
        saveToStorage();
        showToast('Account created successfully', 'success');
    }
    
    document.getElementById('accountFormCard').classList.add('d-none');
    renderAccountsList();
}

// Phase 6.B: Departments List
function renderDepartmentsList() {
    const container = document.getElementById('departmentsTableContainer');
    const departments = window.db.departments || [];
    
    if (departments.length === 0) {
        container.innerHTML = '<p>No departments found.</p>';
        return;
    }
    
    let html = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Description</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    departments.forEach(dept => {
        html += `
            <tr>
                <td>${dept.name}</td>
                <td>${dept.description || ''}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="editDepartment('${dept.id}')">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteDepartment('${dept.id}')">Delete</button>
                </td>
            </tr>
        `;
    });
    
    html += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = html;
}

// Phase 6.B: Add Department
function addDepartment() {
    alert('Not implemented yet');
}

// Phase 6.B: Edit Department
function editDepartment(deptId) {
    alert('Not implemented yet');
}

// Phase 6.B: Delete Department
function deleteDepartment(deptId) {
    if (confirm('Are you sure you want to delete this department?')) {
        window.db.departments = window.db.departments.filter(dept => dept.id !== deptId);
        // Also remove from employees
        window.db.employees = window.db.employees.filter(emp => emp.departmentId !== deptId);
        saveToStorage();
        showToast('Department deleted successfully', 'success');
        renderDepartmentsList();
        renderEmployeesTable(); // Refresh employees table
    }
}

// Phase 6.C: Employees Table
function renderEmployeesTable() {
    const container = document.getElementById('employeesTableContainer');
    const employees = window.db.employees || [];
    const accounts = window.db.accounts || [];
    const departments = window.db.departments || [];
    
    if (employees.length === 0) {
        container.innerHTML = '<p>No employees found.</p>';
        return;
    }
    
    let html = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>User (email)</th>
                    <th>Position</th>
                    <th>Dept</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    employees.forEach(emp => {
        const account = accounts.find(acc => acc.id === emp.userId);
        const dept = departments.find(d => d.id === emp.departmentId);
        html += `
            <tr>
                <td>${emp.employeeId}</td>
                <td>${account ? account.email : 'N/A'}</td>
                <td>${emp.position}</td>
                <td>${dept ? dept.name : 'N/A'}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="editEmployee('${emp.id}')">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteEmployee('${emp.id}')">Delete</button>
                </td>
            </tr>
        `;
    });
    
    html += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = html;
}

// Phase 6.C: Show Employee Form
function showEmployeeForm(employeeId = null) {
    const formCard = document.getElementById('employeeFormCard');
    const form = document.getElementById('employeeForm');
    const editIdInput = document.getElementById('employeeFormEditId');
    const deptSelect = document.getElementById('employeeDepartment');
    
    // Populate departments dropdown
    const departments = window.db.departments || [];
    deptSelect.innerHTML = '<option value="">Select Department</option>';
    departments.forEach(dept => {
        deptSelect.innerHTML += `<option value="${dept.id}">${dept.name}</option>`;
    });
    
    formCard.classList.remove('d-none');
    
    if (employeeId) {
        const employee = window.db.employees.find(emp => emp.id === employeeId);
        if (employee) {
            const account = window.db.accounts.find(acc => acc.id === employee.userId);
            editIdInput.value = employeeId;
            document.getElementById('employeeId').value = employee.employeeId;
            document.getElementById('employeeEmail').value = employee.email || (account ? account.email : '');
            document.getElementById('employeePosition').value = employee.position;
            document.getElementById('employeeDepartment').value = employee.departmentId;
            document.getElementById('employeeHireDate').value = employee.hireDate || '';
        }
    } else {
        form.reset();
        editIdInput.value = '';
    }
    
    formCard.scrollIntoView({ behavior: 'smooth' });
}

// Phase 6.C: Edit Employee
function editEmployee(employeeId) {
    showEmployeeForm(employeeId);
}

// Phase 6.C: Delete Employee
function deleteEmployee(employeeId) {
    if (confirm('Are you sure you want to delete this employee?')) {
        window.db.employees = window.db.employees.filter(emp => emp.id !== employeeId);
        saveToStorage();
        showToast('Employee deleted successfully', 'success');
        renderEmployeesTable();
    }
}

// Phase 6.C: Handle Employee Form
function handleEmployeeForm(event) {
    event.preventDefault();
    
    const editId = document.getElementById('employeeFormEditId').value;
    const employeeId = document.getElementById('employeeId').value.trim();
    const email = document.getElementById('employeeEmail').value.trim();
    const position = document.getElementById('employeePosition').value.trim();
    const departmentId = document.getElementById('employeeDepartment').value;
    const hireDate = document.getElementById('employeeHireDate').value;
    
    // Find account by email
    const account = window.db.accounts.find(acc => acc.email === email);
    if (!account) {
        showToast('User email must match an existing account', 'danger');
        return;
    }
    
    if (editId) {
        // Edit existing
        const employee = window.db.employees.find(emp => emp.id === editId);
        if (employee) {
            employee.employeeId = employeeId;
            employee.userId = account.id;
            employee.email = email;
            employee.position = position;
            employee.departmentId = departmentId;
            employee.hireDate = hireDate;
            saveToStorage();
            showToast('Employee updated successfully', 'success');
        }
    } else {
        // Check for duplicate employee ID
        const duplicate = window.db.employees.find(emp => emp.employeeId === employeeId);
        if (duplicate) {
            showToast('Employee ID already exists', 'danger');
            return;
        }
        
        // Create new
        const newEmployee = {
            id: Date.now().toString(),
            employeeId,
            userId: account.id,
            email,
            position,
            departmentId,
            hireDate
        };
        window.db.employees.push(newEmployee);
        saveToStorage();
        showToast('Employee created successfully', 'success');
    }
    
    document.getElementById('employeeFormCard').classList.add('d-none');
    renderEmployeesTable();
}

// Phase 7: Render Requests Table
function renderRequestsTable() {
    if (!currentUser) return;
    
    const container = document.getElementById('requestsTableContainer');
    const requests = (window.db.requests || []).filter(req => req.employeeEmail === currentUser.email);
    
    if (requests.length === 0) {
        container.innerHTML = `
            <div class="text-center py-5">
                <p class="lead">You have no requests yet.</p>
                <button class="btn btn-success btn-lg" onclick="document.getElementById('newRequestBtn').click()">Create One</button>
            </div>
        `;
        return;
    }
    
    let html = `
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Items</th>
                    <th>Date</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    requests.forEach(req => {
        const statusClass = {
            'Pending': 'warning',
            'Approved': 'success',
            'Rejected': 'danger'
        }[req.status] || 'secondary';
        
        const itemsText = req.items.map(item => `${item.name} (${item.qty})`).join(', ');
        
        html += `
            <tr>
                <td>${req.id.substring(0, 8)}</td>
                <td>${req.type}</td>
                <td>${itemsText}</td>
                <td>${new Date(req.date).toLocaleDateString()}</td>
                <td><span class="badge bg-${statusClass}">${req.status}</span></td>
            </tr>
        `;
    });
    
    html += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = html;
}

// Phase 7: Initialize Request Modal
function initRequestModal() {
    const container = document.getElementById('requestItemsContainer');
    container.innerHTML = '';
    addRequestItem();
}

// Phase 7: Add Request Item
function addRequestItem() {
    const container = document.getElementById('requestItemsContainer');
    const itemIndex = container.children.length;
    const itemDiv = document.createElement('div');
    itemDiv.className = 'request-item';
    itemDiv.innerHTML = `
        <input type="text" class="form-control" placeholder="Item name" required>
        <input type="number" class="form-control" placeholder="Qty" min="1" value="1" style="width: 100px;" required>
        ${itemIndex === 0 ? '<button type="button" class="btn btn-sm btn-outline-secondary" onclick="addRequestItem()">+</button>' : ''}
        <button type="button" class="btn btn-sm btn-outline-danger" onclick="removeRequestItem(this)">×</button>
    `;
    container.appendChild(itemDiv);
}

// Phase 7: Remove Request Item
function removeRequestItem(button) {
    button.closest('.request-item').remove();
}

// Phase 7: Submit Request
function submitRequest() {
    const type = document.getElementById('requestType').value;
    const container = document.getElementById('requestItemsContainer');
    const items = [];
    
    container.querySelectorAll('.request-item').forEach(itemDiv => {
        const nameInput = itemDiv.querySelector('input[type="text"]');
        const qtyInput = itemDiv.querySelector('input[type="number"]');
        if (nameInput.value.trim() && qtyInput.value) {
            items.push({
                name: nameInput.value.trim(),
                qty: parseInt(qtyInput.value) || 1
            });
        }
    });
    
    if (items.length === 0) {
        showToast('Please add at least one item', 'danger');
        return;
    }
    
    const newRequest = {
        id: Date.now().toString(),
        type,
        items,
        status: 'Pending',
        date: new Date().toISOString(),
        employeeEmail: currentUser.email
    };
    
    window.db.requests.push(newRequest);
    saveToStorage();
    
    // Close modal
    const modal = bootstrap.Modal.getInstance(document.getElementById('newRequestModal'));
    modal.hide();
    
    showToast('Request submitted successfully', 'success');
    renderRequestsTable();
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Initialize
    loadFromStorage();
    checkAuth();
    
    // Set initial hash
    if (!window.location.hash) {
        navigateTo('#/');
    }
    handleRouting();
    
    // Hash change listener
    window.addEventListener('hashchange', handleRouting);
    
    // Registration form
    document.getElementById('registerForm').addEventListener('submit', handleRegister);
    
    // Email verification
    document.getElementById('simulateVerifyBtn').addEventListener('click', handleVerifyEmail);
    
    // Login form
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    
    // Logout
    document.getElementById('logoutBtn').addEventListener('click', (e) => {
        e.preventDefault();
        handleLogout();
    });
    
    // Accounts
    document.getElementById('addAccountBtn').addEventListener('click', () => showAccountForm());
    document.getElementById('accountForm').addEventListener('submit', handleAccountForm);
    document.getElementById('cancelAccountFormBtn').addEventListener('click', () => {
        document.getElementById('accountFormCard').classList.add('d-none');
    });
    
    // Departments
    document.getElementById('addDepartmentBtn').addEventListener('click', addDepartment);
    
    // Employees
    document.getElementById('addEmployeeBtn').addEventListener('click', () => showEmployeeForm());
    document.getElementById('employeeForm').addEventListener('submit', handleEmployeeForm);
    document.getElementById('cancelEmployeeFormBtn').addEventListener('click', () => {
        document.getElementById('employeeFormCard').classList.add('d-none');
    });
    
    // Requests
    document.getElementById('newRequestBtn').addEventListener('click', () => {
        initRequestModal();
        const modal = new bootstrap.Modal(document.getElementById('newRequestModal'));
        modal.show();
    });
    document.getElementById('submitRequestBtn').addEventListener('click', submitRequest);
    document.getElementById('addItemBtn').addEventListener('click', addRequestItem);
    
    // Make functions global for onclick handlers
    window.navigateTo = navigateTo;
    window.editAccount = editAccount;
    window.resetPassword = resetPassword;
    window.deleteAccount = deleteAccount;
    window.addDepartment = addDepartment;
    window.editDepartment = editDepartment;
    window.deleteDepartment = deleteDepartment;
    window.editEmployee = editEmployee;
    window.deleteEmployee = deleteEmployee;
    window.addRequestItem = addRequestItem;
    window.removeRequestItem = removeRequestItem;
});