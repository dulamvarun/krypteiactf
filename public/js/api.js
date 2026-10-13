// API Client for Krypteia CTF
const API = {
  // Store bearer token in memory / localStorage fallback
  getToken() {
    return localStorage.getItem('krypteia_token') || '';
  },
  
  setToken(token) {
    if (token) {
      localStorage.setItem('krypteia_token', token);
    } else {
      localStorage.removeItem('krypteia_token');
    }
  },

  async request(path, options = {}) {
    const headers = options.headers || {};
    const token = this.getToken();
    if (token && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    if (options.body && typeof options.body === 'object') {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(options.body);
    }

    try {
      const res = await fetch(path, {
        method: options.method || 'GET',
        headers,
        body: options.body,
        credentials: 'same-origin' // sends cookie automatically
      });

      const json = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(json.error || json.message || `Request failed with status ${res.status}`);
      }

      return json;
    } catch (err) {
      console.error(`API Error [${path}]:`, err);
      throw err;
    }
  },

  // Auth endpoints
  async getConfig() {
    return this.request('/api/config');
  },

  async getMe() {
    return this.request('/api/auth/me');
  },

  async login(identifier, password) {
    const data = await this.request('/api/auth/login', {
      method: 'POST',
      body: { identifier, password }
    });
    if (data.token) this.setToken(data.token);
    return data;
  },

  async register(username, email, password) {
    const data = await this.request('/api/auth/register', {
      method: 'POST',
      body: { username, email, password }
    });
    if (data.token) this.setToken(data.token);
    return data;
  },

  async logout() {
    try {
      await this.request('/api/auth/logout', { method: 'POST' });
    } finally {
      this.setToken(null);
    }
  },

  // Challenges & Flag submission
  async getChallenges() {
    return this.request('/api/challenges');
  },

  async submitFlag(challengeId, flag) {
    return this.request('/api/submit-flag', {
      method: 'POST',
      body: { challengeId, flag }
    });
  },

  // Leaderboard & Rules
  async getLeaderboard() {
    return this.request('/api/leaderboard');
  },

  async getRules() {
    return this.request('/api/rules');
  }
};

window.API = API;
