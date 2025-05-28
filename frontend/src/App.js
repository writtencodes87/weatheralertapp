import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_BASE = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

function App() {
  const [currentView, setCurrentView] = useState('home');
  const [user, setUser] = useState(null);
  const [admin, setAdmin] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [adminToken, setAdminToken] = useState(localStorage.getItem('adminToken'));
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (token) {
      setCurrentView('dashboard');
    } else if (adminToken) {
      setCurrentView('admin');
    }
  }, [token, adminToken]);

  const showMessage = (msg, type = 'info') => {
    setMessage(msg);
    setTimeout(() => setMessage(''), 3000);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('adminToken');
    setToken(null);
    setAdminToken(null);
    setUser(null);
    setAdmin(null);
    setCurrentView('home');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900">
      {/* Header */}
      <header className="bg-gray-900 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <div className="text-2xl font-bold text-white">
                ⚡ WeatherAlert Pro
              </div>
            </div>
            <nav className="flex space-x-4">
              {!token && !adminToken && (
                <>
                  <button
                    onClick={() => setCurrentView('home')}
                    className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium"
                  >
                    Home
                  </button>
                  <button
                    onClick={() => setCurrentView('login')}
                    className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium"
                  >
                    Login
                  </button>
                  <button
                    onClick={() => setCurrentView('register')}
                    className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium"
                  >
                    Register
                  </button>
                  <button
                    onClick={() => setCurrentView('adminLogin')}
                    className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm font-medium"
                  >
                    Admin
                  </button>
                </>
              )}
              {(token || adminToken) && (
                <button
                  onClick={handleLogout}
                  className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm font-medium"
                >
                  Logout
                </button>
              )}
            </nav>
          </div>
        </div>
      </header>

      {/* Message Banner */}
      {message && (
        <div className="bg-blue-600 text-white px-4 py-2 text-center">
          {message}
        </div>
      )}

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {currentView === 'home' && <HomeView />}
        {currentView === 'login' && (
          <LoginView 
            setUser={setUser} 
            setToken={setToken} 
            setCurrentView={setCurrentView}
            showMessage={showMessage}
          />
        )}
        {currentView === 'register' && (
          <RegisterView 
            setUser={setUser} 
            setToken={setToken} 
            setCurrentView={setCurrentView}
            showMessage={showMessage}
          />
        )}
        {currentView === 'adminLogin' && (
          <AdminLoginView 
            setAdmin={setAdmin} 
            setAdminToken={setAdminToken} 
            setCurrentView={setCurrentView}
            showMessage={showMessage}
          />
        )}
        {currentView === 'dashboard' && token && (
          <UserDashboard 
            user={user} 
            token={token}
            showMessage={showMessage}
          />
        )}
        {currentView === 'admin' && adminToken && (
          <AdminDashboard 
            admin={admin} 
            adminToken={adminToken}
            showMessage={showMessage}
          />
        )}
      </main>
    </div>
  );
}

// Home View
function HomeView() {
  return (
    <div className="text-center">
      <div className="max-w-4xl mx-auto px-4">
        <h1 className="text-5xl font-bold text-white mb-6">
          WeatherAlert Pro
        </h1>
        <p className="text-xl text-blue-100 mb-8">
          Get critical weather alerts for your counties. Never miss a tornado warning, 
          severe thunderstorm, blizzard, winter storm, or high wind alert again.
        </p>
        
        <div className="grid md:grid-cols-3 gap-6 mt-12">
          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
            <div className="text-4xl mb-4">🌪️</div>
            <h3 className="text-xl font-semibold text-white mb-2">Critical Alerts</h3>
            <p className="text-blue-100">
              Receive immediate notifications for life-threatening weather conditions
            </p>
          </div>
          
          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
            <div className="text-4xl mb-4">📍</div>
            <h3 className="text-xl font-semibold text-white mb-2">County-Specific</h3>
            <p className="text-blue-100">
              Subscribe to multiple counties across Kentucky, Indiana, Ohio, and nationwide
            </p>
          </div>
          
          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
            <div className="text-4xl mb-4">⚡</div>
            <h3 className="text-xl font-semibold text-white mb-2">Real-Time</h3>
            <p className="text-blue-100">
              Powered by the National Weather Service API for accurate, up-to-date alerts
            </p>
          </div>
        </div>
        
        <div className="mt-12">
          <h2 className="text-2xl font-bold text-white mb-4">Monitored Weather Events</h2>
          <div className="flex flex-wrap justify-center gap-4">
            {[
              'Tornado Warning',
              'Severe Thunderstorm Warning',
              'Blizzard Warning',
              'Winter Storm Warning',
              'High Wind Warning'
            ].map((event) => (
              <span
                key={event}
                className="bg-red-600 text-white px-4 py-2 rounded-full text-sm font-medium"
              >
                {event}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// Login View
function LoginView({ setUser, setToken, setCurrentView, showMessage }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await axios.post(`${API_BASE}/api/login`, {
        username,
        password
      });
      
      const { access_token, user } = response.data;
      localStorage.setItem('token', access_token);
      setToken(access_token);
      setUser(user);
      setCurrentView('dashboard');
      showMessage('Login successful!', 'success');
    } catch (error) {
      showMessage(error.response?.data?.detail || 'Login failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto">
      <div className="bg-white/10 backdrop-blur-sm rounded-lg p-8">
        <h2 className="text-2xl font-bold text-white mb-6 text-center">User Login</h2>
        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-blue-100 mb-2">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-blue-100 mb-2">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white py-2 px-4 rounded-md font-medium"
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
      </div>
    </div>
  );
}

// Register View
function RegisterView({ setUser, setToken, setCurrentView, showMessage }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await axios.post(`${API_BASE}/api/register`, {
        username,
        password
      });
      
      const { access_token, user } = response.data;
      localStorage.setItem('token', access_token);
      setToken(access_token);
      setUser(user);
      setCurrentView('dashboard');
      showMessage('Registration successful!', 'success');
    } catch (error) {
      showMessage(error.response?.data?.detail || 'Registration failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto">
      <div className="bg-white/10 backdrop-blur-sm rounded-lg p-8">
        <h2 className="text-2xl font-bold text-white mb-6 text-center">Register</h2>
        <form onSubmit={handleRegister} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-blue-100 mb-2">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
              minLength={3}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-blue-100 mb-2">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
              minLength={6}
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white py-2 px-4 rounded-md font-medium"
          >
            {loading ? 'Creating Account...' : 'Register'}
          </button>
        </form>
      </div>
    </div>
  );
}

// Admin Login View
function AdminLoginView({ setAdmin, setAdminToken, setCurrentView, showMessage }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleAdminLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await axios.post(`${API_BASE}/api/admin/login`, {
        username,
        password
      });
      
      const { access_token, admin } = response.data;
      localStorage.setItem('adminToken', access_token);
      setAdminToken(access_token);
      setAdmin(admin);
      setCurrentView('admin');
      showMessage('Admin login successful!', 'success');
    } catch (error) {
      showMessage(error.response?.data?.detail || 'Admin login failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto">
      <div className="bg-red-900/20 backdrop-blur-sm rounded-lg p-8 border border-red-500">
        <h2 className="text-2xl font-bold text-white mb-6 text-center">
          🔐 Admin Login
        </h2>
        <form onSubmit={handleAdminLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-red-100 mb-2">
              Admin Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-red-500"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-red-100 mb-2">
              Admin Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-red-500"
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-red-600 hover:bg-red-700 disabled:bg-red-400 text-white py-2 px-4 rounded-md font-medium"
          >
            {loading ? 'Logging in...' : 'Admin Login'}
          </button>
        </form>
      </div>
    </div>
  );
}

// User Dashboard
function UserDashboard({ user, token, showMessage }) {
  const [subscriptions, setSubscriptions] = useState([]);
  const [states, setStates] = useState({});
  const [selectedState, setSelectedState] = useState('');
  const [counties, setCounties] = useState([]);
  const [selectedCounties, setSelectedCounties] = useState([]);
  const [loading, setLoading] = useState(false);
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    loadSubscriptions();
    loadStates();
    loadRecentAlerts();
  }, []);

  const loadSubscriptions = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/my-subscriptions`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSubscriptions(response.data.subscriptions);
    } catch (error) {
      showMessage('Failed to load subscriptions', 'error');
    }
  };

  const loadStates = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/states`);
      setStates(response.data.states);
    } catch (error) {
      showMessage('Failed to load states', 'error');
    }
  };

  const loadCounties = async (stateCode) => {
    try {
      const response = await axios.get(`${API_BASE}/api/counties/${stateCode}`);
      setCounties(response.data.counties);
    } catch (error) {
      showMessage('Failed to load counties', 'error');
    }
  };

  const loadRecentAlerts = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/alerts`);
      setAlerts(response.data.alerts.slice(0, 5)); // Show latest 5
    } catch (error) {
      console.error('Failed to load alerts');
    }
  };

  const handleStateChange = (stateCode) => {
    setSelectedState(stateCode);
    setSelectedCounties([]);
    if (stateCode) {
      loadCounties(stateCode);
    } else {
      setCounties([]);
    }
  };

  const handleCountyToggle = (county) => {
    setSelectedCounties(prev => 
      prev.includes(county) 
        ? prev.filter(c => c !== county)
        : [...prev, county]
    );
  };

  const handleSubscribe = async () => {
    if (!selectedState || selectedCounties.length === 0) {
      showMessage('Please select a state and at least one county', 'error');
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API_BASE}/api/subscribe`, {
        state: selectedState,
        counties: selectedCounties
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      showMessage('Successfully subscribed to weather alerts!', 'success');
      setSelectedState('');
      setSelectedCounties([]);
      setCounties([]);
      loadSubscriptions();
    } catch (error) {
      showMessage(error.response?.data?.detail || 'Subscription failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleUnsubscribe = async (subscriptionId) => {
    try {
      await axios.delete(`${API_BASE}/api/subscriptions/${subscriptionId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      showMessage('Subscription removed', 'success');
      loadSubscriptions();
    } catch (error) {
      showMessage('Failed to remove subscription', 'error');
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
        <h2 className="text-2xl font-bold text-white mb-4">
          Welcome, {user?.username}!
        </h2>
        <p className="text-blue-100">
          Manage your weather alert subscriptions below.
        </p>
      </div>

      {/* Subscribe to New Counties */}
      <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
        <h3 className="text-xl font-semibold text-white mb-4">
          Subscribe to Weather Alerts
        </h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-blue-100 mb-2">
              Select State
            </label>
            <select
              value={selectedState}
              onChange={(e) => handleStateChange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Choose a state...</option>
              {Object.entries(states).map(([code, name]) => (
                <option key={code} value={code}>{name} ({code})</option>
              ))}
            </select>
          </div>

          {counties.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-blue-100 mb-2">
                Select Counties (you can select multiple)
              </label>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2 max-h-48 overflow-y-auto bg-white/5 p-3 rounded-md">
                {counties.map((county) => (
                  <label key={county} className="flex items-center text-blue-100">
                    <input
                      type="checkbox"
                      checked={selectedCounties.includes(county)}
                      onChange={() => handleCountyToggle(county)}
                      className="mr-2"
                    />
                    {county}
                  </label>
                ))}
              </div>
            </div>
          )}

          {selectedCounties.length > 0 && (
            <button
              onClick={handleSubscribe}
              disabled={loading}
              className="w-full bg-green-600 hover:bg-green-700 disabled:bg-green-400 text-white py-2 px-4 rounded-md font-medium"
            >
              {loading ? 'Subscribing...' : `Subscribe to ${selectedCounties.length} Counties`}
            </button>
          )}
        </div>
      </div>

      {/* Current Subscriptions */}
      <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
        <h3 className="text-xl font-semibold text-white mb-4">
          Your Current Subscriptions
        </h3>
        
        {subscriptions.length === 0 ? (
          <p className="text-blue-100">No subscriptions yet. Subscribe to counties above!</p>
        ) : (
          <div className="space-y-3">
            {subscriptions.map((sub) => (
              <div key={sub.id} className="bg-white/5 rounded-lg p-4">
                <div className="flex justify-between items-start">
                  <div>
                    <h4 className="font-semibold text-white">
                      {states[sub.state]} ({sub.state})
                    </h4>
                    <p className="text-blue-100 text-sm">
                      Counties: {sub.counties.join(', ')}
                    </p>
                  </div>
                  <button
                    onClick={() => handleUnsubscribe(sub.id)}
                    className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent Alerts */}
      <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
        <h3 className="text-xl font-semibold text-white mb-4">
          Recent Weather Alerts
        </h3>
        
        {alerts.length === 0 ? (
          <p className="text-blue-100">No recent alerts. Good weather!</p>
        ) : (
          <div className="space-y-3">
            {alerts.map((alert) => (
              <div key={alert.id} className="bg-red-900/20 border border-red-500 rounded-lg p-4">
                <div className="flex justify-between items-start mb-2">
                  <h4 className="font-semibold text-red-100">
                    {alert.event}
                  </h4>
                  <span className="bg-red-600 text-white px-2 py-1 rounded text-xs">
                    {alert.severity}
                  </span>
                </div>
                <p className="text-red-100 text-sm mb-2">
                  {alert.headline}
                </p>
                <p className="text-red-200 text-xs">
                  {new Date(alert.effective).toLocaleString()}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// Admin Dashboard
function AdminDashboard({ admin, adminToken, showMessage }) {
  const [stats, setStats] = useState({});
  const [users, setUsers] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [message, setMessage] = useState('');
  const [isCritical, setIsCritical] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadStats();
    loadUsers();
    loadNotifications();
  }, []);

  const loadStats = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/admin/stats`, {
        headers: { Authorization: `Bearer ${adminToken}` }
      });
      setStats(response.data);
    } catch (error) {
      showMessage('Failed to load stats', 'error');
    }
  };

  const loadUsers = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/admin/users`, {
        headers: { Authorization: `Bearer ${adminToken}` }
      });
      setUsers(response.data.users);
    } catch (error) {
      showMessage('Failed to load users', 'error');
    }
  };

  const loadNotifications = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/admin/notifications`, {
        headers: { Authorization: `Bearer ${adminToken}` }
      });
      setNotifications(response.data.notifications);
    } catch (error) {
      showMessage('Failed to load notifications', 'error');
    }
  };

  const sendNotification = async () => {
    if (!message.trim()) {
      showMessage('Please enter a message', 'error');
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API_BASE}/api/admin/notify`, {
        message: message.trim(),
        is_critical: isCritical
      }, {
        headers: { Authorization: `Bearer ${adminToken}` }
      });
      
      showMessage(`${isCritical ? 'Critical' : 'Normal'} notification sent!`, 'success');
      setMessage('');
      setIsCritical(false);
      loadNotifications();
    } catch (error) {
      showMessage(error.response?.data?.detail || 'Failed to send notification', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-red-900/20 backdrop-blur-sm rounded-lg p-6 border border-red-500">
        <h2 className="text-2xl font-bold text-white mb-4">
          🔐 Admin Dashboard
        </h2>
        <p className="text-red-100">
          Welcome, {admin?.username}. Manage users and send notifications.
        </p>
      </div>

      {/* Stats */}
      <div className="grid md:grid-cols-3 gap-6">
        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-2">Total Users</h3>
          <p className="text-3xl font-bold text-blue-300">{stats.total_users || 0}</p>
        </div>
        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-2">Notifications Sent</h3>
          <p className="text-3xl font-bold text-green-300">{stats.total_notifications || 0}</p>
        </div>
        <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-2">Recent Alerts</h3>
          <p className="text-3xl font-bold text-yellow-300">{stats.recent_alerts || 0}</p>
        </div>
      </div>

      {/* Send Manual Notification */}
      <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
        <h3 className="text-xl font-semibold text-white mb-4">
          Send Manual Notification
        </h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-blue-100 mb-2">
              Message
            </label>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              rows="3"
              placeholder="Enter your notification message..."
            />
          </div>
          
          <div className="flex items-center">
            <input
              type="checkbox"
              id="critical"
              checked={isCritical}
              onChange={(e) => setIsCritical(e.target.checked)}
              className="mr-2"
            />
            <label htmlFor="critical" className="text-blue-100">
              Critical Notification (bypasses silent mode)
            </label>
          </div>
          
          <button
            onClick={sendNotification}
            disabled={loading}
            className={`w-full py-2 px-4 rounded-md font-medium ${
              isCritical 
                ? 'bg-red-600 hover:bg-red-700 disabled:bg-red-400' 
                : 'bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400'
            } text-white`}
          >
            {loading ? 'Sending...' : `Send ${isCritical ? 'Critical' : 'Normal'} Notification`}
          </button>
        </div>
      </div>

      {/* Registered Users */}
      <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
        <h3 className="text-xl font-semibold text-white mb-4">
          Registered Users ({users.length})
        </h3>
        
        {users.length === 0 ? (
          <p className="text-blue-100">No users registered yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-gray-600">
                  <th className="text-blue-100 py-2">Username</th>
                  <th className="text-blue-100 py-2">Registered</th>
                  <th className="text-blue-100 py-2">Subscriptions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id} className="border-b border-gray-700">
                    <td className="text-white py-2">{user.username}</td>
                    <td className="text-blue-100 py-2">
                      {new Date(user.created_at).toLocaleDateString()}
                    </td>
                    <td className="text-blue-100 py-2">
                      {user.subscriptions?.length || 0} counties
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Recent Notifications */}
      <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
        <h3 className="text-xl font-semibold text-white mb-4">
          Recent Notifications
        </h3>
        
        {notifications.length === 0 ? (
          <p className="text-blue-100">No notifications sent yet.</p>
        ) : (
          <div className="space-y-3 max-h-64 overflow-y-auto">
            {notifications.slice(0, 10).map((notif) => (
              <div key={notif.id} className={`rounded-lg p-3 ${
                notif.is_critical ? 'bg-red-900/20 border border-red-500' : 'bg-blue-900/20 border border-blue-500'
              }`}>
                <div className="flex justify-between items-start mb-1">
                  <span className={`px-2 py-1 rounded text-xs ${
                    notif.is_critical ? 'bg-red-600 text-white' : 'bg-blue-600 text-white'
                  }`}>
                    {notif.is_critical ? 'CRITICAL' : 'NORMAL'}
                  </span>
                  <span className="text-xs text-gray-400">
                    {new Date(notif.created_at).toLocaleString()}
                  </span>
                </div>
                <p className="text-blue-100 text-sm">{notif.message}</p>
                {notif.manual && (
                  <p className="text-xs text-gray-400 mt-1">
                    Manual notification by {notif.sent_by_admin}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;