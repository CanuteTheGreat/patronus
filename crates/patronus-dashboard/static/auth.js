// Authentication JavaScript for Patronus Dashboard

const API_BASE = '/api/v1';

// Token management
const TokenManager = {
    setTokens(accessToken, refreshToken) {
        localStorage.setItem('access_token', accessToken);
        localStorage.setItem('refresh_token', refreshToken);
    },

    getAccessToken() {
        return localStorage.getItem('access_token');
    },

    getRefreshToken() {
        return localStorage.getItem('refresh_token');
    },

    clearTokens() {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
    },

    setUser(user) {
        localStorage.setItem('user', JSON.stringify(user));
    },

    getUser() {
        const user = localStorage.getItem('user');
        return user ? JSON.parse(user) : null;
    },

    isAuthenticated() {
        return !!this.getAccessToken();
    }
};

// Alert management
const Alert = {
    show(message, type = 'info') {
        const container = document.getElementById('alertContainer');
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} show`;
        alert.textContent = message;
        container.innerHTML = '';
        container.appendChild(alert);

        // Auto-hide after 5 seconds
        setTimeout(() => {
            alert.classList.remove('show');
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    },

    error(message) {
        this.show(message, 'error');
    },

    success(message) {
        this.show(message, 'success');
    },

    info(message) {
        this.show(message, 'info');
    },

    clear() {
        document.getElementById('alertContainer').innerHTML = '';
    }
};

// API client
const API = {
    async request(endpoint, options = {}) {
        const url = `${API_BASE}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        // Add auth token if available
        const token = TokenManager.getAccessToken();
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        try {
            const response = await fetch(url, {
                ...options,
                headers
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || `HTTP ${response.status}`);
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },

    async login(email, password) {
        return this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
    },

    async initAdmin(name, email, password) {
        return this.request('/auth/init-admin', {
            method: 'POST',
            body: JSON.stringify({
                name,
                email,
                password,
                role: 'admin'
            })
        });
    },

    async refreshToken() {
        const refreshToken = TokenManager.getRefreshToken();
        if (!refreshToken) {
            throw new Error('No refresh token available');
        }

        return this.request('/auth/refresh', {
            method: 'POST',
            body: JSON.stringify({ refresh_token: refreshToken })
        });
    },

    async getCurrentUser() {
        return this.request('/auth/me');
    }
};

// Button loading state
function setButtonLoading(button, loading) {
    if (loading) {
        button.disabled = true;
        button.dataset.originalText = button.textContent;
        button.innerHTML = button.dataset.originalText + '<span class="loading"></span>';
    } else {
        button.disabled = false;
        button.textContent = button.dataset.originalText || button.textContent.replace('...', '');
    }
}

// Login form handler
document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    Alert.clear();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const loginBtn = document.getElementById('loginBtn');

    setButtonLoading(loginBtn, true);

    try {
        const response = await API.login(email, password);

        // Store tokens and user info
        TokenManager.setTokens(response.access_token, response.refresh_token);
        TokenManager.setUser(response.user);

        Alert.success('Login successful! Redirecting...');

        // Redirect to dashboard
        setTimeout(() => {
            window.location.href = '/index.html';
        }, 500);
    } catch (error) {
        Alert.error(`Login failed: ${error.message}`);
        setButtonLoading(loginBtn, false);
    }
});

// Setup form handler
document.getElementById('setupForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    Alert.clear();

    const name = document.getElementById('setupName').value;
    const email = document.getElementById('setupEmail').value;
    const password = document.getElementById('setupPassword').value;
    const passwordConfirm = document.getElementById('setupPasswordConfirm').value;
    const setupBtn = document.getElementById('setupBtn');

    // Validate password match
    if (password !== passwordConfirm) {
        Alert.error('Passwords do not match');
        return;
    }

    // Validate password strength
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
    if (!passwordRegex.test(password)) {
        Alert.error('Password does not meet requirements');
        return;
    }

    setButtonLoading(setupBtn, true);

    try {
        const response = await API.initAdmin(name, email, password);

        Alert.success('Admin account created! You can now log in.');

        // Switch back to login form
        setTimeout(() => {
            document.getElementById('setupSection').classList.remove('active');
            document.getElementById('loginSection').style.display = 'block';
            document.getElementById('email').value = email;
            document.getElementById('setupForm').reset();
        }, 1500);
    } catch (error) {
        Alert.error(`Setup failed: ${error.message}`);
    } finally {
        setButtonLoading(setupBtn, false);
    }
});

// Show setup section
document.getElementById('showSetupBtn')?.addEventListener('click', () => {
    document.getElementById('loginSection').style.display = 'none';
    document.getElementById('setupSection').classList.add('active');
    Alert.clear();
});

// Back to login
document.getElementById('backToLoginBtn')?.addEventListener('click', () => {
    document.getElementById('setupSection').classList.remove('active');
    document.getElementById('loginSection').style.display = 'block';
    document.getElementById('setupForm').reset();
    Alert.clear();
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { TokenManager, API, Alert };
}
