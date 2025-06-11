import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api';
export const AUTH_TOKEN_KEY = 'auth_token';

// Function to get CSRF token from cookies
function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === (name + '=')) {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}

// Axios instance with auth headers
const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // This is required for CSRF to work
});

// Add debugging
const DEBUG_API = true;

// Add auth token and CSRF token to requests
apiClient.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
      if (DEBUG_API) {
        console.log(`Sending request to ${config.url} with token:`, token);
      }
    } else if (DEBUG_API) {
      console.warn(`Sending request to ${config.url} WITHOUT auth token`);
    }

    // Add CSRF token for non-GET requests
    if (!/^(GET|HEAD|OPTIONS|TRACE)$/.test(config.method.toUpperCase())) {
      const csrfToken = getCookie('csrftoken');
      if (csrfToken) {
        config.headers['X-CSRFToken'] = csrfToken;
        if (DEBUG_API) {
          console.log(`Added CSRF token to ${config.url}:`, csrfToken);
        }
      }
    }

    return config;
  },
  (error) => {
    console.error('Request error:', error);
    return Promise.reject(error);
  }
);

// Add response interceptor for debugging
apiClient.interceptors.response.use(
  (response) => {
    if (DEBUG_API) {
      console.log(`Response from ${response.config.url}:`, response.data);
    }
    return response;
  },
  (error) => {
    if (DEBUG_API) {
      console.error(`Error response from ${error.config?.url}:`, error.response?.data);
    }
    return Promise.reject(error);
  }
);

// Authentication
export const login = async (username, password) => {
  try {
    const response = await apiClient.post('/login/', { username, password });
    // Return the full response data to be handled in authUtils
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const logout = () => {
  localStorage.removeItem(AUTH_TOKEN_KEY);
};

export const register = async (userData) => {
  try {
    const response = await apiClient.post('/signup/', userData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

// User profile
export const fetchUserProfile = async () => {
  try {
    console.log('Fetching user profile...');
    const response = await apiClient.get('/settings/');
    console.log('User profile response:', response.data);
    
    if (response.data && response.data.settings && response.data.settings.user_profile) {
      return response.data.settings.user_profile;
    }
    return response.data;
  } catch (error) {
    console.error('Error fetching user profile:', error);
    throw handleApiError(error);
  }
};

export const updateUserProfile = async (profileData) => {
  try {
    const response = await apiClient.put('/users/profile', profileData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

// Dashboard data
export const fetchDashboardData = async () => {
  try {
    console.log('Fetching dashboard data...');
    const response = await apiClient.get('/dashboard/');
    console.log('Dashboard API response:', response.data);
    
    // Extract and store user data if available
    if (response.data && response.data.dashboard && response.data.dashboard.user_data && response.data.dashboard.user_data.user_info) {
      storeUserData(response.data.dashboard.user_data.user_info);
    }
    
    // Return the complete data from the server
    return response.data;
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    throw handleApiError(error);
  }
};

// Notifications
export const fetchNotifications = async (filters = {}) => {
  try {
    console.log('Fetching notifications with filters:', filters);
    console.log('Current auth token:', localStorage.getItem('auth_token'));
    
    const response = await apiClient.get('/notifications/', { params: filters });
    console.log('Raw notifications response:', response);
    console.log('Response status:', response.status);
    console.log('Response headers:', response.headers);
    console.log('Response data:', response.data);
    
    // Handle both array response and object with notifications property
    const notificationsData = Array.isArray(response.data) ? response.data : response.data.notifications || [];
    
    const notifications = notificationsData.map(notification => ({
      id: notification.id,
      message: notification.message,
      createdAt: notification.sent_at,
      read: notification.is_read,
      type: notification.notification_type,
      alert: notification.alert,
      threat: notification.threat,
      user: notification.user,
      icon: getIconForType(notification.notification_type || 'info'),
      priority: notification.priority || 'medium'
    }));
    console.log('Processed notifications:', notifications);
    return notifications;
  } catch (error) {
    console.error('Error fetching notifications:', error);
    console.error('Error details:', {
      message: error.message,
      response: error.response?.data,
      status: error.response?.status
    });
    throw handleApiError(error);
  }
};

export const markNotificationAsRead = async (notificationId) => {
  try {
    console.log(`Marking notification ${notificationId} as read...`);
    const response = await apiClient.post(`/notifications/${notificationId}/read/`);
    console.log('Mark as read response:', response.data);
    return response.data;
  } catch (error) {
    console.error('Error marking notification as read:', error);
    console.error('Error details:', {
      message: error.message,
      response: error.response?.data,
      status: error.response?.status
    });
    throw handleApiError(error);
  }
};

export const markAllNotificationsAsRead = async () => {
  try {
    console.log('Marking all notifications as read...');
    // Get all notifications first
    const notifications = await fetchNotifications();
    // Mark each notification as read individually
    const promises = notifications.map(notification => 
      apiClient.post(`/notifications/${notification.id}/read/`)
    );
    await Promise.all(promises);
    return { success: true };
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    throw handleApiError(error);
  }
};

// Helper function to get appropriate icon for notification type
const getIconForType = (type) => {
  switch (type.toLowerCase()) {
    case 'alert':
    case 'warning':
      return 'exclamation-triangle';
    case 'success':
      return 'check-circle';
    case 'error':
      return 'times-circle';
    case 'message':
      return 'envelope';
    case 'update':
      return 'sync';
    case 'security':
      return 'shield-alt';
    case 'user':
      return 'user';
    default:
      return 'bell';
  }
};

// User Management
export const fetchUsers = async () => {
  try {
    const response = await apiClient.get('/users/');
    console.log('API Response:', response); // Debug log
    
    if (response.data) {
      return response.data;
    }
    throw new Error('No data received from server');
  } catch (error) {
    console.error('Error in fetchUsers:', error);
    throw handleApiError(error);
  }
};

export const createUser = async (userData) => {
  try {
    // Ensure all required fields are present
    const requiredFields = ['username', 'email', 'password', 'firstName', 'lastName', 'role'];
    const missingFields = requiredFields.filter(field => !userData[field]);
    
    if (missingFields.length > 0) {
      throw new Error(`Missing required fields: ${missingFields.join(', ')}`);
    }

    // Format the data according to backend expectations
    const formattedData = {
      username: userData.username,
      email: userData.email,
      password: userData.password,
      first_name: userData.firstName,
      last_name: userData.lastName,
      role: userData.role,
      mobile: userData.mobile || '',
      permissions: userData.permissions || {}
    };

    // Get CSRF token from cookie
    const csrfToken = getCookie('csrftoken');
    if (!csrfToken) {
      throw new Error('CSRF token not found. Please refresh the page and try again.');
    }

    const response = await apiClient.post('/users/', formattedData, {
      headers: {
        'X-CSRFToken': csrfToken
      }
    });
    return response.data;
  } catch (error) {
    console.error('Error creating user:', error);
    if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw error;
  }
};

export const updateUser = async (userId, userData) => {
  try {
    const response = await apiClient.put(`/users/${userId}/`, userData);
    return response.data;
  } catch (error) {
    handleApiError(error);
    throw error;
  }
};

export const deleteUser = async (userId) => {
  try {
    const response = await apiClient.delete(`/users/${userId}/`);
    return response.data;
  } catch (error) {
    handleApiError(error);
    throw error;
  }
};

// Password Management
export const resetPassword = async (email) => {
  try {
    const response = await apiClient.post('/forget_password/', { email });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const changePassword = async (uidb64, token, password, confirmPassword) => {
  try {
    const response = await apiClient.post(`/reset_password/${uidb64}/${token}/`, { 
      password, 
      confirmPassword
    });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

// Help & Support
export const fetchHelpSupport = async () => {
  try {
    console.log('Fetching help and support data...');
    const response = await apiClient.get('/help-support/');
    console.log('Help support response:', response.data);
    return response.data;
  } catch (error) {
    console.error('Error fetching help and support data:', error);
    throw handleApiError(error);
  }
};

// Alias for register
export const signup = register;

// Data Analysis
export const fetchDataAnalysis = async (params = {}) => {
  try {
    console.log('Fetching data analysis...', params);
    const response = await apiClient.get('/data-analysis/', { params });
    console.log('Data analysis response:', response.data);
    
    // Check if we have valid data structure
    if (!response.data) {
      console.warn('Empty data analysis response');
      return createFallbackAnalysisData();
    }
    
    // Return the data as is
    return response.data;
  } catch (error) {
    console.error('Error fetching data analysis:', error);
    // Return fallback data so UI doesn't break
    return createFallbackAnalysisData();
  }
};

// Helper to create fallback data for data analysis
function createFallbackAnalysisData() {
  return {
    detectedThreats: { current: 12, total: 15 },
    resolvedThreats: 8,
    avgResponseTime: "45 min",
    threatsGrowth: "+5%",
    trendsOverTime: {
      categories: ["Mon", "Tue", "Wed", "Thu", "Fri"],
      series: [
        { name: "Threats", data: [5, 7, 3, 8, 4] }
      ]
    },
    sunburst: [
      { name: "Malware", value: 40 },
      { name: "Phishing", value: 30 },
      { name: "DDoS", value: 20 },
      { name: "Other", value: 10 }
    ],
    topBlocks: [
      { name: "Host1", value: 23 },
      { name: "Host2", value: 17 },
      { name: "Host3", value: 12 }
    ],
    attackVectors: [
      { name: "Network", value: 45 },
      { name: "Email", value: 35 },
      { name: "Web", value: 20 }
    ],
    alarmingHosts: [
      { host: "192.168.1.10", threat_level: "high", incidents: 14 },
      { host: "192.168.1.15", threat_level: "medium", incidents: 8 },
      { host: "192.168.1.20", threat_level: "low", incidents: 3 }
    ]
  };
}

// Security Events
export const fetchNetworkAlerts = async (params = {}) => {
  try {
    console.log('Fetching network alerts...', params);
    const response = await apiClient.get('/event-details/', { params });
    console.log('Network alerts response:', response.data);
    
    // Process the events data
    const processedData = {
      events: response.data.events || [],
      statistics: response.data.statistics || {},
      charts: response.data.charts || {},
      requests: response.data.requests || [],
      securityBlocks: response.data.securityBlocks || []
    };
    
    return processedData;
  } catch (error) {
    console.error('Error fetching network alerts:', error);
    throw handleApiError(error);
  }
};

// Reports
export const fetchReports = async (filters = {}) => {
  try {
    const response = await apiClient.get('/reports/', { params: filters });
    if (!response.data || !response.data.reports) {
      throw new Error('Invalid response format from server');
    }
    return response.data;
  } catch (error) {
    if (error.response?.status === 403) {
      throw new Error('You do not have permission to view reports');
    } else if (error.response?.status === 404) {
      throw new Error('Reports not found');
    } else if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw handleApiError(error);
  }
};

export const getReportDetails = async (reportId) => {
  try {
    const response = await apiClient.get(`/reports/${reportId}/`);
    if (!response.data) {
      throw new Error('Invalid response format from server');
    }
    return response.data;
  } catch (error) {
    if (error.response?.status === 403) {
      throw new Error('You do not have permission to view this report');
    } else if (error.response?.status === 404) {
      throw new Error('Report not found');
    } else if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw handleApiError(error);
  }
};

export const createReport = async (reportData) => {
  try {
    const response = await apiClient.post('/reports/', reportData);
    if (!response.data || !response.data.report_id) {
      throw new Error('Invalid response format from server');
    }
    return response.data;
  } catch (error) {
    if (error.response?.status === 403) {
      throw new Error('You do not have permission to create reports');
    } else if (error.response?.status === 400) {
      throw new Error(error.response.data.error || 'Invalid report data');
    } else if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw handleApiError(error);
  }
};

export const updateReport = async (reportId, reportData) => {
  try {
    console.log('Updating report:', reportId, reportData);
    const response = await apiClient.put(`/reports/${reportId}/`, reportData);
    console.log('Update report response:', response.data);
    return response.data;
  } catch (error) {
    console.error('Error updating report:', error);
    if (error.response?.status === 403) {
      throw new Error('You do not have permission to update this report');
    } else if (error.response?.status === 404) {
      throw new Error('Report not found');
    } else if (error.response?.status === 400) {
      throw new Error(error.response.data.error || 'Invalid report data');
    } else if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw handleApiError(error);
  }
};

export const deleteReports = async (reportIds) => {
  try {
    console.log('Deleting reports:', reportIds);
    const response = await apiClient.post('/reports/delete/', { ids: reportIds });
    console.log('Delete reports response:', response.data);
    return response.data;
  } catch (error) {
    console.error('Error deleting reports:', error);
    throw handleApiError(error);
  }
};

export const exportReports = async (reportIds, format = 'csv') => {
  try {
    console.log(`Exporting reports in ${format} format:`, reportIds);
    const response = await apiClient.post('/reports/export/', { 
      report_ids: reportIds,
      format: format 
    }, { 
      responseType: 'blob'  // Important for file downloads
    });
    
    // Create a download link for the file
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `reports-export.${format}`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    
    return true;
  } catch (error) {
    console.error('Error exporting reports:', error);
    throw handleApiError(error);
  }
};

export const addReport = async (reportData) => {
  try {
    console.log('Adding new report:', reportData);
    const response = await apiClient.post('/reports/', reportData);
    console.log('Add report response:', response.data);
    return response.data;
  } catch (error) {
    console.error('Error adding report:', error);
    throw handleApiError(error);
  }
};

// Security Incidents
export const fetchSecurityIncidents = async (filters = {}) => {
  try {
    const response = await apiClient.get('/incidents', { params: filters });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const getIncidentDetails = async (incidentId) => {
  try {
    const response = await apiClient.get(`/incidents/${incidentId}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

// Utilities
export const handleApiError = (error) => {
  if (error.response) {
    // Server responded with error
    const status = error.response.status;
    const data = error.response.data;
    
    if (status === 401) {
      localStorage.removeItem(AUTH_TOKEN_KEY);
      return {
        message: 'Authentication failed. Please log in again.',
        originalError: error,
        status
      };
    } else if (status === 403) {
      return {
        message: 'You do not have permission to perform this action',
        originalError: error,
        status
      };
    } else if (status === 404) {
      return {
        message: 'The requested resource was not found',
        originalError: error,
        status
      };
    } else if (status >= 400 && status < 500) {
      // Handle validation errors
      if (typeof data === 'object' && !data.message && !data.error) {
        // This is a validation error object
        return {
          message: Object.entries(data)
            .map(([field, messages]) => `${field}: ${messages.join(', ')}`)
            .join('\n'),
          originalError: error,
          status,
          validationErrors: data
        };
      }
      return {
        message: data.message || data.error || 'Bad request',
        originalError: error,
        status
      };
    } else if (status >= 500) {
      return {
        message: 'Server error. Please try again later.',
        originalError: error,
        status
      };
    }
  } else if (error.request) {
    // Request made but no response received
    return {
      message: 'No response from server. Please check your connection.',
      originalError: error
    };
  }
  
  // Default error
  return {
    message: 'An unexpected error occurred',
    originalError: error
  };
};

// Store user data in localStorage
export const storeUserData = (userData) => {
  try {
    console.log('Storing user data in localStorage:', userData);
    if (userData) {
      localStorage.setItem('user_data', JSON.stringify(userData));
    }
  } catch (error) {
    console.error('Error storing user data:', error);
  }
};

// NetworkFlow endpoints
export const fetchNetworkFlows = async (filters = {}) => {
  try {
    const response = await apiClient.get('/network-flows/', { params: filters });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const getNetworkFlowDetails = async (flowId) => {
  try {
    const response = await apiClient.get(`/network-flows/${flowId}/`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const createNetworkFlow = async (flowData) => {
  try {
    const response = await apiClient.post('/create_network_flow/', flowData);
    return response.data;
  } catch (error) {
    console.error('Error creating network flow:', error);
    throw error;
  }
};

export const updateNetworkFlow = async (flowId, flowData) => {
  try {
    const response = await apiClient.put(`/network-flows/${flowId}/`, flowData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const deleteNetworkFlow = async (flowId) => {
  try {
    await apiClient.delete(`/network-flows/${flowId}/`);
  } catch (error) {
    throw handleApiError(error);
  }
};

// Alert endpoints
export const fetchAlerts = async (filters = {}) => {
  try {
    const response = await apiClient.get('/alerts/', { params: filters });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const getAlertDetails = async (alertId) => {
  try {
    const response = await apiClient.get(`/alerts/${alertId}/`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const createAlert = async (alertData) => {
  try {
    const response = await apiClient.post('/alerts/', alertData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const updateAlert = async (alertId, alertData) => {
  try {
    const response = await apiClient.put(`/alerts/${alertId}/`, alertData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const deleteAlert = async (alertId) => {
  try {
    await apiClient.delete(`/alerts/${alertId}/`);
  } catch (error) {
    throw handleApiError(error);
  }
};

// Threat endpoints
export const fetchThreats = async (filters = {}) => {
  try {
    const response = await apiClient.get('/threats/', { params: filters });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const getThreatDetails = async (threatId) => {
  try {
    const response = await apiClient.get(`/threats/${threatId}/`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const createThreat = async (threatData) => {
  try {
    const response = await apiClient.post('/threats/', threatData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const updateThreat = async (threatId, threatData) => {
  try {
    const response = await apiClient.put(`/threats/${threatId}/`, threatData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const deleteThreat = async (threatId) => {
  try {
    await apiClient.delete(`/threats/${threatId}/`);
  } catch (error) {
    throw handleApiError(error);
  }
};

// SuspiciousIP endpoints
export const fetchSuspiciousIPs = async (filters = {}) => {
  try {
    const response = await apiClient.get('/suspicious-ips/', { params: filters });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const getSuspiciousIPDetails = async (ipId) => {
  try {
    const response = await apiClient.get(`/suspicious-ips/${ipId}/`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const createSuspiciousIP = async (ipData) => {
  try {
    const response = await apiClient.post('/suspicious-ips/', ipData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const updateSuspiciousIP = async (ipId, ipData) => {
  try {
    const response = await apiClient.put(`/suspicious-ips/${ipId}/`, ipData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const deleteSuspiciousIP = async (ipId) => {
  try {
    await apiClient.delete(`/suspicious-ips/${ipId}/`);
  } catch (error) {
    throw handleApiError(error);
  }
};

// Agent endpoints
export const fetchAgents = async (filters = {}) => {
  try {
    const response = await apiClient.get('/agents/', { params: filters });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const getAgentDetails = async (agentId) => {
  try {
    const response = await apiClient.get(`/agents/${agentId}/`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const createAgent = async (agentData) => {
  try {
    const response = await apiClient.post('/agents/', agentData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const updateAgent = async (agentId, agentData) => {
  try {
    const response = await apiClient.put(`/agents/${agentId}/`, agentData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const deleteAgent = async (agentId) => {
  try {
    await apiClient.delete(`/agents/${agentId}/`);
  } catch (error) {
    throw handleApiError(error);
  }
};

// System Settings endpoints
export const fetchSystemSettings = async () => {
  try {
    const response = await apiClient.get('/settings/system/');
    // Response structure matches SystemSettingsView.get()
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const updateSystemSettings = async (data) => {
  try {
    // Request structure matches SystemSettingsView.put()
    const response = await apiClient.put('/settings/system/', {
      system_name: data.system_name,
      maintenance_mode: data.maintenance_mode,
      max_login_attempts: data.max_login_attempts,
      notification_settings: data.notification_settings
    });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const fetchPermissionGroups = async () => {
  try {
    const response = await apiClient.get('/permission-groups/');
    return response.data;
  } catch (error) {
    handleApiError(error);
    throw error;
  }
};

export const createPermissionGroup = async (groupData) => {
  try {
    const response = await apiClient.post('/permission-groups/', groupData);
    return response.data;
  } catch (error) {
    handleApiError(error);
    throw error;
  }
};

export const updatePermissionGroup = async (groupId, groupData) => {
  try {
    const response = await apiClient.put(`/permission-groups/${groupId}/`, groupData);
    return response.data;
  } catch (error) {
    handleApiError(error);
    throw error;
  }
};

export const deletePermissionGroup = async (groupId) => {
  try {
    const response = await apiClient.delete(`/permission-groups/${groupId}/`);
    return response.data;
  } catch (error) {
    handleApiError(error);
    throw error;
  }
};

export const fetchSecurityControls = async (filters = {}) => {
  try {
    const response = await apiClient.get('/security-controls/', { params: filters });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const fetchBlockedFlows = async (filters = {}) => {
  try {
    const response = await apiClient.get('/blocked-flows/', { params: filters });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

// Settings endpoints
export const fetchUserSettings = async () => {
  try {
    const response = await apiClient.get('/settings/user/');
    // Response structure matches UserSettingsView.get()
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const updateUserSettings = async (data) => {
  try {
    // Request structure matches UserSettingsView.put()
    const response = await apiClient.put('/settings/user/', {
      first_name: data.profile.first_name,
      last_name: data.profile.last_name,
      email: data.profile.email,
      phone_number: data.profile.phone_number,
      bio: data.profile.bio,
      notification_preferences: data.notification_preferences,
      interface_settings: data.interface_settings
    });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const fetchSecuritySettings = async () => {
  try {
    const response = await apiClient.get('/settings/security/');
    // Response structure matches SecuritySettingsView.get()
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const updateSecuritySettings = async (data) => {
  try {
    // Request structure matches SecuritySettingsView.put()
    const response = await apiClient.put('/settings/security/', {
      max_login_attempts: data.max_login_attempts,
      security_policy: data.security_policy,
      backup_settings: data.backup_settings,
      maintenance_mode: data.maintenance_mode
    });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const fetchNotificationSettings = async () => {
  try {
    const response = await apiClient.get('/settings/notifications/');
    // Response structure matches NotificationSettingsView.get()
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const updateNotificationSettings = async (data) => {
  try {
    // Request structure matches NotificationSettingsView.put()
    const response = await apiClient.put('/settings/notifications/', {
      email: data.email_enabled,
      sms: data.sms_enabled,
      push: data.push_enabled
    });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

// WebSocket connection for notifications
let notificationSocket = null;

export const connectNotificationSocket = (onNotification) => {
  const token = localStorage.getItem('access_token');
  if (!token) return;

  // Close existing connection if any
  if (notificationSocket) {
    notificationSocket.close();
  }

  // Create new WebSocket connection
  notificationSocket = new WebSocket(`ws://localhost:8000/ws/notifications/`);

  notificationSocket.onopen = () => {
    console.log('Notification WebSocket connected');
  };

  notificationSocket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'notification') {
      onNotification(data.notification);
    }
  };

  notificationSocket.onclose = () => {
    console.log('Notification WebSocket disconnected');
    // Try to reconnect after 5 seconds
    setTimeout(() => connectNotificationSocket(onNotification), 5000);
  };

  notificationSocket.onerror = (error) => {
    console.error('Notification WebSocket error:', error);
  };

  return notificationSocket;
};

export const disconnectNotificationSocket = () => {
  if (notificationSocket) {
    notificationSocket.close();
    notificationSocket = null;
  }
};

// Network Activity Logs
export const fetchNetworkActivityLogs = async (params = {}) => {
  try {
    console.log('Fetching network activity logs...', params);
    const response = await apiClient.get('/network-activity-logs/', { params });
    console.log('Network activity logs response:', response.data);
    return response.data;
  } catch (error) {
    console.error('Error fetching network activity logs:', error);
    throw handleApiError(error);
  }
};

export const exportNetworkActivityLogs = async (params = {}) => {
  try {
    console.log('Exporting network activity logs...', params);
    const response = await apiClient.get('/network-activity-logs/export/', {
      params,
      responseType: 'blob'
    });
    
    // Create a download link for the file
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `network-logs-${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    
    return true;
  } catch (error) {
    console.error('Error exporting network activity logs:', error);
    throw handleApiError(error);
  }
};

export default apiClient;
