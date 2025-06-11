import React, { useState, useEffect } from "react";
import "../../styles/userManagement.css";
import editIcon from "../../assets/images/filter-lines.png";
import deleteIcon from "../../assets/images/trash-01.png";
import search from "../../assets/images/fluent_search-24-filled.png";
import filterIcon from '../../assets/images/filter-icon.png';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { 
  fetchUsers, 
  createUser, 
  updateUser, 
  deleteUser,
  fetchPermissionGroups 
} from "../../services/api";
import { CircularProgress, Fade, Zoom, Grow } from '@mui/material';
import { validateEmail, validateUsername, validateRequired, validatePassword, validatePasswordMatch } from "../../utils/validationUtils";
import { 
  defaultPermissionsForRole, 
  hasPermission, 
  getAvailableRoles,
  formatPermissionsForAPI 
} from "../../utils/permissionUtils";
import { getUserData } from "../../services/auth";
import api from "../../services/api";

const UserManagement = () => {
  const [isPopupOpen, setPopupOpen] = useState(false);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('name');
  const [darkMode, setDarkMode] = useState(false);
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const [filters, setFilters] = useState({
    role: '',
    dateFrom: '',
    dateTo: ''
  });
  const [formData, setFormData] = useState({
    username: '',
    firstName: '',
    lastName: '',
    email: '',
    mobile: '',
    role: '',
    password: '',
    confirmPassword: ''
  });
  const [formErrors, setFormErrors] = useState({});
  const [isEditing, setIsEditing] = useState(false);
  const [currentUserId, setCurrentUserId] = useState(null);
  const [permissions, setPermissions] = useState({
    dashboard: { read: false, write: false, delete: false },
    reports: { read: false, write: false, delete: false },
    users: { read: false, write: false, delete: false },
    settings: { read: false, write: false, delete: false }
  });
  const [isProcessing, setIsProcessing] = useState(false);
  const [userDeleted, setUserDeleted] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [userToDelete, setUserToDelete] = useState(null);
  const [permissionGroups, setPermissionGroups] = useState([]);
  const [userPermissions, setUserPermissions] = useState(null);
  const [currentUserPermissions, setCurrentUserPermissions] = useState(null);
  const [availableRoles, setAvailableRoles] = useState(['Viewer']);
  const [selectedUser, setSelectedUser] = useState(null);
  const [openDialog, setOpenDialog] = useState(false);

  // Updated notification function using react-toastify
  const showNotification = (message, type = 'info') => {
    const options = {
      position: "top-right",
      autoClose: 3000,
      hideProgressBar: false,
      closeOnClick: true,
      pauseOnHover: true,
      draggable: true,
      progress: undefined,
      theme: darkMode ? "dark" : "light",
    };

    switch (type) {
      case 'success':
        toast.success(message, options);
        break;
      case 'error':
        toast.error(message, options);
        break;
      case 'warning':
        toast.warning(message, options);
        break;
      default:
        toast.info(message, options);
    }
  };

  // Convert frontend permissions to API format
  const convertFrontendPermissions = (permissions) => {
    return {
      dashboard: {
        read: permissions.dashboard?.read || false,
        write: permissions.dashboard?.write || false,
        delete: permissions.dashboard?.delete || false
      },
      reports: {
        read: permissions.reports?.read || false,
        write: permissions.reports?.write || false,
        delete: permissions.reports?.delete || false
      },
      users: {
        read: permissions.users?.read || false,
        write: permissions.users?.write || false,
        delete: permissions.users?.delete || false
      },
      settings: {
        read: permissions.settings?.read || false,
        write: permissions.settings?.write || false,
        delete: permissions.settings?.delete || false
      }
    };
  };

  // Dialog handlers
  const handleCloseDialog = () => {
    setOpenDialog(false);
    setSelectedUser(null);
    setFormData({
      username: '',
      firstName: '',
      lastName: '',
      email: '',
      mobile: '',
      role: '',
      password: '',
      confirmPassword: ''
    });
    setFormErrors({});
  };

  // Delete handlers
  const cancelDelete = () => {
    setShowConfirmation(false);
    setUserToDelete(null);
  };

  const confirmDelete = async () => {
    if (!userToDelete) return;
    
    try {
      setIsProcessing(true);
      await deleteUser(userToDelete);
      setUserDeleted(true);
      setTimeout(() => {
        setShowConfirmation(false);
        setUserDeleted(false);
        loadUsers();
      }, 1500);
    } catch (error) {
      showNotification(error.message || 'Failed to delete user', 'error');
    } finally {
      setIsProcessing(false);
    }
  };

  // Check for dark mode in localStorage
  useEffect(() => {
    const isDarkMode = localStorage.getItem('darkMode') === 'true';
    setDarkMode(isDarkMode);
    
    // Listen for dark mode changes
    const handleDarkModeChange = (e) => {
      if (e.type === 'storage' && e.key && e.key !== 'darkMode') {
        return;
      }
      const currentDarkMode = localStorage.getItem('darkMode') === 'true';
      setDarkMode(currentDarkMode);
    };
    
    window.addEventListener('storage', handleDarkModeChange);
    window.addEventListener('storage-local', handleDarkModeChange);
    
    return () => {
      window.removeEventListener('storage', handleDarkModeChange);
      window.removeEventListener('storage-local', handleDarkModeChange);
    };
  }, []);

  useEffect(() => {
    loadUsers();
    loadPermissionGroups();
  }, []);

  const loadPermissionGroups = async () => {
    try {
      const groups = await fetchPermissionGroups();
      setPermissionGroups(groups);
    } catch (error) {
      console.error('Error loading permission groups:', error);
    }
  };

  const loadUsers = async () => {
    try {
      setLoading(true);
      const response = await fetchUsers();
      console.log('Received users data:', response);

      if (response && response.users) {
        // Set current user permissions
        if (response.current_user_permissions) {
          setCurrentUserPermissions(response.current_user_permissions);
        }

        const formattedUsers = response.users.map(user => ({
        id: user.id,
        username: user.username,
          firstName: user.firstName || '',
          lastName: user.lastName || '',
        email: user.email || '',
          mobile: user.mobile || '',
        role: user.role || 'Viewer',
          date: new Date(user.date).toLocaleDateString(),
          permissions: user.permissions || defaultPermissionsForRole(user.role)
        }));
      
      setUsers(formattedUsers);
        setError(null);
      } else {
        console.error('Invalid data format received:', response);
        setError('Invalid data format received from server');
      }
    } catch (error) {
      console.error('Error loading users:', error);
      setError(error.message || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  // Get default permissions based on role
  const defaultPermissionsForRole = (role) => {
    switch (role) {
      case 'Super Admin':
        return {
          dashboard: { read: true, write: true, delete: true },
          reports: { read: true, write: true, delete: true },
          users: { read: true, write: true, delete: true },
          settings: { read: true, write: true, delete: true }
        };
      case 'Admin':
        return {
          dashboard: { read: true, write: true, delete: false },
          reports: { read: true, write: true, delete: false },
          users: { read: true, write: true, delete: false },
          settings: { read: true, write: true, delete: false }
        };
      case 'Analyst':
        return {
          dashboard: { read: true, write: true, delete: false },
          reports: { read: true, write: true, delete: false },
          users: { read: false, write: false, delete: false },
          settings: { read: true, write: false, delete: false }
        };
      case 'Viewer':
      default:
        return {
          dashboard: { read: true, write: false, delete: false },
          reports: { read: true, write: false, delete: false },
          users: { read: false, write: false, delete: false },
          settings: { read: true, write: false, delete: false }
        };
    }
  };

  // Dark mode styles
  const styles = {
    container: {
      backgroundColor: darkMode ? '#1E293B' : '#f9f9f9',
      color: darkMode ? '#e0e0e0' : '#333',
      transition: 'all 0.3s ease'
    },
    title: {
      color: darkMode ? '#e0e0e0' : '#333',
      transition: 'color 0.3s ease',
      marginBottom: '20px'
    },
    table: {
      backgroundColor: darkMode ? '#273142' : '#fff',
      color: darkMode ? '#e0e0e0' : '#333',
      border: darkMode ? '1px solid #3A4557' : '1px solid #e0e0e0',
      transition: 'all 0.3s ease',
      boxShadow: darkMode ? '0 4px 12px rgba(0, 0, 0, 0.2)' : '0 4px 12px rgba(0, 0, 0, 0.1)'
    },
    tableHeader: {
      backgroundColor: darkMode ? '#334155' : '#f1f5f9',
      color: darkMode ? '#e0e0e0' : '#333',
      transition: 'all 0.3s ease'
    },
    input: {
      backgroundColor: darkMode ? '#273142' : '#fff',
      color: darkMode ? '#e0e0e0' : '#333',
      border: darkMode ? '1px solid #3A4557' : '1px solid #ddd',
      transition: 'all 0.3s ease'
    },
    button: {
      backgroundColor: darkMode ? '#3B82F6' : '#4299E1',
      color: '#fff',
      transition: 'all 0.3s ease',
      '&:hover': {
        transform: 'translateY(-2px)',
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)'
      }
    },
    popup: {
      backgroundColor: darkMode ? '#273142' : '#fff',
      color: darkMode ? '#e0e0e0' : '#333',
      boxShadow: darkMode ? '0 4px 20px rgba(0, 0, 0, 0.5)' : '0 4px 20px rgba(0, 0, 0, 0.15)',
      transition: 'all 0.3s ease',
      borderRadius: '8px',
      animation: 'popup 0.3s ease-out forwards'
    },
    actionButton: {
      cursor: 'pointer',
      transition: 'all 0.2s ease',
      '&:hover': {
        transform: 'scale(1.1)'
      }
    },
    checkbox: {
      cursor: 'pointer',
      width: '18px',
      height: '18px'
    },
    roleBadge: {
      padding: '6px 10px',
      borderRadius: '12px',
      fontSize: '12px',
      fontWeight: 'bold',
      display: 'inline-block',
      transition: 'all 0.3s ease'
    },
    confirmationModal: {
      position: 'fixed',
      top: 0,
      left: 0,
      width: '100%',
      height: '100%',
      backgroundColor: 'rgba(0, 0, 0, 0.5)',
      backdropFilter: 'blur(4px)',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      zIndex: 1000
    },
    confirmationContent: {
      backgroundColor: darkMode ? '#273142' : '#fff',
      padding: '25px',
      borderRadius: '12px',
      width: '400px',
      boxShadow: '0 4px 20px rgba(0, 0, 0, 0.3)',
      color: darkMode ? '#e0e0e0' : '#333'
    }
  };

  // Helper function to get role hierarchy level
  const getRoleLevel = (role) => {
    switch (role) {
      case 'Super Admin':
        return 4;
      case 'Admin':
        return 3;
      case 'Analyst':
        return 2;
      case 'Viewer':
        return 1;
      default:
        return 0;
    }
  };

  // Check if current user can modify target user
  const canModifyUser = (targetUser) => {
    if (!currentUserPermissions) return false;
    
    // Get current user's role level
    const currentUserRole = getUserData()?.role || 'Viewer';
    const currentUserLevel = getRoleLevel(currentUserRole);
    
    // Get target user's role level
    const targetUserLevel = getRoleLevel(targetUser?.role);
    
    // Can't modify users with higher role level
    if (targetUserLevel > currentUserLevel) {
      return false;
    }
    
    // Check specific permissions based on role
    if (currentUserRole === 'Super Admin') {
      return true;
    }
    
    if (currentUserRole === 'Admin') {
      return targetUserLevel <= 3; // Can modify Admin and below
    }
    
    if (currentUserRole === 'Analyst') {
      return targetUserLevel <= 2; // Can modify Analyst and below
    }
    
    return false; // Viewer can't modify anyone
  };

  const handleOpenDialog = (user = null) => {
    if (user && !canModifyUser(user)) {
      console.log('Permission check failed:', {
        currentUserRole: getUserData()?.role,
        targetUserRole: user?.role,
        currentUserPermissions: currentUserPermissions
      });
      showNotification('You do not have permission to modify this user', 'error');
      return;
    }

    if (user) {
      setSelectedUser(user);
      setFormData({
        username: user.username,
        email: user.email,
        password: '',
        firstName: user.firstName,
        lastName: user.lastName,
        mobile: user.mobile,
        role: user.role,
        permissions: user.permissions || defaultPermissionsForRole(user.role)
      });
    } else {
      setSelectedUser(null);
      setFormData({
        username: '',
        email: '',
        password: '',
        firstName: '',
        lastName: '',
        mobile: '',
        role: 'Viewer',
        permissions: defaultPermissionsForRole('Viewer')
      });
    }
    setOpenDialog(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Debug logs
    console.log('Form data before validation:', formData);
    
    // Validate form data
    if (!validateForm()) {
      console.log('Validation errors:', formErrors);
      showNotification('Please fill in all required fields correctly', 'error');
      return;
    }

    // Check if trying to set a role higher than current user's role
    const currentUserRole = getUserData()?.role || 'Viewer';
    const currentUserLevel = getRoleLevel(currentUserRole);
    const newRoleLevel = getRoleLevel(formData.role);
    
    if (newRoleLevel > currentUserLevel) {
      showNotification('You cannot assign a role higher than your own', 'error');
      return;
    }

    try {
      setIsProcessing(true);
      
      // Get default permissions for the selected role
      const defaultPermissions = defaultPermissionsForRole(formData.role);
      
      // Prepare data to send
      const dataToSend = {
        ...formData,
        permissions: defaultPermissions // Use default permissions based on role
      };

      if (selectedUser) {
        await api.put(`/users/${selectedUser.id}/`, dataToSend);
        showNotification('User updated successfully', 'success');
      } else {
        await createUser(dataToSend);
        showNotification('User created successfully', 'success');
      }
      handleCloseDialog();
      loadUsers();
    } catch (err) {
      console.error('Error saving user:', err);
      if (err.message.includes('CSRF')) {
        showNotification('Session expired. Please refresh the page and try again.', 'error');
      } else {
        showNotification(err.message || 'Failed to save user', 'error');
      }
    } finally {
      setIsProcessing(false);
    }
  };

  const validateForm = () => {
    const errors = {};
    
    // Required fields validation
    if (!formData.username?.trim()) {
      errors.username = 'Username is required';
    } else if (!validateUsername(formData.username)) {
      errors.username = 'Invalid username format';
    }
    
    if (!formData.email?.trim()) {
      errors.email = 'Email is required';
    } else if (!validateEmail(formData.email)) {
      errors.email = 'Invalid email format';
    }
    
    if (!selectedUser && !formData.password?.trim()) {
      errors.password = 'Password is required for new users';
    } else if (formData.password && !validatePassword(formData.password)) {
      errors.password = 'Password must be at least 8 characters long with one uppercase, one lowercase, and one number';
    }
    
    if (formData.password && formData.confirmPassword && 
        formData.password !== formData.confirmPassword) {
      errors.confirmPassword = 'Passwords do not match';
    }
    
    if (!formData.firstName?.trim()) {
      errors.firstName = 'First name is required';
    }
    
    if (!formData.lastName?.trim()) {
      errors.lastName = 'Last name is required';
    }
    
    if (!formData.role) {
      errors.role = 'Role is required';
    }
    
    setFormErrors(errors);
    
    // Show specific error message if there are errors
    if (Object.keys(errors).length > 0) {
      const errorMessages = Object.values(errors).join(', ');
      showNotification(errorMessages, 'error');
    }
    
    return Object.keys(errors).length === 0;
  };

  const handleDelete = async (userId) => {
    const userToDelete = users.find(u => u.id === userId);
    if (!userToDelete || !canModifyUser(userToDelete)) {
      showNotification('You do not have permission to delete this user', 'error');
      return;
    }

    if (window.confirm('Are you sure you want to delete this user?')) {
      try {
        await api.delete(`/api/users/${userId}/`);
        showNotification('User deleted successfully', 'success');
        loadUsers();
      } catch (err) {
        console.error('Error deleting user:', err);
        showNotification(err.response?.data?.error || 'Failed to delete user', 'error');
      }
    }
  };

  const openPopup = (user = null) => {
    if (user && !canModifyUser(user)) {
      showNotification('You do not have permission to modify this user', 'error');
      return;
    }

    if (user) {
      setFormData({
        username: user.username || '',
        firstName: user.firstName || '',
        lastName: user.lastName || '',
        email: user.email || '',
        mobile: user.mobile || '',
        role: user.role || '',
        password: '',
        confirmPassword: ''
      });
      setPermissions(user.permissions || defaultPermissionsForRole(user.role));
      setIsEditing(true);
      setCurrentUserId(user.id);
    } else {
      setFormData({
        username: '',
        firstName: '',
        lastName: '',
        email: '',
        mobile: '',
        role: '',
        password: '',
        confirmPassword: ''
      });
      setPermissions(defaultPermissionsForRole('Viewer'));
      setIsEditing(false);
      setCurrentUserId(null);
    }
    setFormErrors({});
    setPopupOpen(true);
  };

  const closePopup = () => {
    setPopupOpen(false);
    setFormErrors({});
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    
    // Update form data
    setFormData(prevData => ({
      ...prevData,
      [name]: value
    }));
    
    // Update permissions when role changes
    if (name === 'role') {
      const newPermissions = defaultPermissionsForRole(value);
      setPermissions(newPermissions);
    }
  };

  const handlePermissionChange = (module, permission, checked) => {
    setPermissions(prevPermissions => ({
      ...prevPermissions,
      [module]: {
        ...prevPermissions[module],
        [permission]: checked
      }
    }));
  };

  const handleSearch = (e) => {
    setSearchQuery(e.target.value);
  };

  const handleSort = (e) => {
    setSortBy(e.target.value);
  };

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters({
      ...filters,
      [name]: value
    });
  };

  const applyFilters = () => {
    setIsFilterOpen(false);
  };

  const cancelFilters = () => {
    setFilters({
      role: '',
      dateFrom: '',
      dateTo: ''
    });
    setIsFilterOpen(false);
  };

  // Role-specific badge style
  const getRoleBadgeStyle = (role) => {
    const baseStyle = {
      padding: '6px 12px',
      borderRadius: '20px',
      fontSize: '12px',
      fontWeight: '600',
      display: 'inline-block'
    };
    
    switch (role) {
      case 'Super Admin':
        return { 
          ...baseStyle, 
          backgroundColor: darkMode ? 'rgba(154, 64, 255, 0.2)' : 'rgba(154, 64, 255, 0.1)',
          color: '#9A40FF' 
        };
      case 'Admin':
        return { 
          ...baseStyle, 
          backgroundColor: darkMode ? 'rgba(255, 89, 68, 0.2)' : 'rgba(255, 89, 68, 0.1)',
          color: '#FF5944' 
        };
      case 'Analyst':
        return { 
          ...baseStyle, 
          backgroundColor: darkMode ? 'rgba(64, 175, 255, 0.2)' : 'rgba(64, 175, 255, 0.1)',
          color: '#40AFFF' 
        };
      case 'Viewer':
      default:
        return { 
          ...baseStyle, 
          backgroundColor: darkMode ? 'rgba(73, 214, 134, 0.2)' : 'rgba(73, 214, 134, 0.1)',
          color: '#49D686' 
        };
    }
  };

  // Filter and sort users
  const filteredUsers = users.filter(user => {
    const searchLower = searchQuery.toLowerCase();
    const matchesSearch = (
      user.name?.toLowerCase().includes(searchLower) ||
      user.email?.toLowerCase().includes(searchLower) ||
      user.role?.toLowerCase().includes(searchLower)
    );

    // تطبيق فلتر الدور إذا تم تحديده
    const matchesRole = !filters.role || user.role === filters.role;

    // تطبيق فلتر التاريخ إذا تم تحديده
    let matchesDate = true;
    if (filters.dateFrom || filters.dateTo) {
      const userDate = new Date(user.date.replace(/(\d+)\s+(\w+),\s+(\d+)/, '$2 $1, $3'));
      
      if (filters.dateFrom) {
        const fromDate = new Date(filters.dateFrom);
        matchesDate = matchesDate && userDate >= fromDate;
      }
      
      if (filters.dateTo) {
        const toDate = new Date(filters.dateTo);
        matchesDate = matchesDate && userDate <= toDate;
      }
    }

    return matchesSearch && matchesRole && matchesDate;
  });

  const sortedUsers = [...filteredUsers].sort((a, b) => {
    if (sortBy === 'name') {
      return a.name?.localeCompare(b.name);
    } else if (sortBy === 'date') {
      // تحويل التاريخ لتنسيق يمكن مقارنته
      const dateA = new Date(a.date.replace(/(\d+)\s+(\w+),\s+(\d+)/, '$2 $1, $3'));
      const dateB = new Date(b.date.replace(/(\d+)\s+(\w+),\s+(\d+)/, '$2 $1, $3'));
      return dateB - dateA; // من الأحدث للأقدم
    } else if (sortBy === 'role') {
      return a.role?.localeCompare(b.role);
    }
    return 0;
  });

  const canEditUser = (user) => {
    if (!currentUserPermissions) {
      console.log('No current user permissions available');
      return false;
    }
    
    console.log('Checking edit permissions for user:', user);
    console.log('Current user permissions:', currentUserPermissions);
    
    // Super Admin can edit anyone
    if (currentUserPermissions.users?.write) {
      console.log('User has write permission');
      return true;
    }
    
    // Admin can edit non-admin users
    if (currentUserPermissions.users?.write && user.role !== 'Super Admin') {
      console.log('User has write permission and target is not Super Admin');
      return true;
    }
    
    console.log('User does not have edit permission');
    return false;
  };

  const canDeleteUser = (user) => {
    if (!currentUserPermissions) {
      console.log('No current user permissions available');
      return false;
    }
    
    console.log('Checking delete permissions for user:', user);
    console.log('Current user permissions:', currentUserPermissions);
    
    // Only users with delete permission can delete
    if (currentUserPermissions.users?.delete) {
      // Super Admin cannot be deleted
      if (user.role === 'Super Admin') {
        console.log('Cannot delete Super Admin user');
        return false;
      }
      console.log('User has delete permission');
      return true;
    }
    
    console.log('User does not have delete permission');
    return false;
  };

  const renderPermissionsTable = () => {
    const modules = [
      { id: 'dashboard', label: 'Dashboard' },
      { id: 'reports', label: 'Reports' },
      { id: 'users', label: 'Users' },
      { id: 'settings', label: 'Settings' }
    ];

    const permissions = [
      { id: 'read', label: 'Read' },
      { id: 'write', label: 'Write' },
      { id: 'delete', label: 'Delete' }
    ];

    return (
      <div className="permissions-section">
        <h4 style={{ marginBottom: '10px', color: darkMode ? '#e0e0e0' : '#333' }}>Module Permissions</h4>
        <div className="permissions-table">
          <table style={styles.table}>
            <thead>
              <tr style={styles.tableHeader}>
                <th style={{ width: '30%' }}>Module</th>
                {permissions.map(perm => (
                  <th key={perm.id} style={{ textAlign: 'center' }}>{perm.label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {modules.map(module => (
                <tr key={module.id}>
                  <td style={{ color: darkMode ? '#e0e0e0' : '#333' }}>{module.label}</td>
                  {permissions.map(perm => (
                    <td key={`${module.id}-${perm.id}`} style={{ textAlign: 'center' }}>
                      <div className="permission-checkbox">
                        <input
                          type="checkbox"
                          id={`${module.id}-${perm.id}`}
                          checked={permissions[module.id]?.[perm.id] || false}
                          onChange={(e) => handlePermissionChange(module.id, perm.id, e.target.checked)}
                          style={{
                            ...styles.checkbox,
                            cursor: 'pointer',
                            width: '18px',
                            height: '18px',
                            accentColor: darkMode ? '#4299E1' : '#3B82F6'
                          }}
                        />
                        <label 
                          htmlFor={`${module.id}-${perm.id}`}
                          style={{ 
                            marginLeft: '5px',
                            color: permissions[module.id]?.[perm.id] ? '#10B981' : '#EF4444',
                            cursor: 'pointer'
                          }}
                        >
                          {permissions[module.id]?.[perm.id] ? '✓' : '✗'}
                        </label>
                      </div>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  const renderUserTable = () => {
    if (loading && users.length === 0) {
      return (
        <div className="loading-container" style={styles.container}>
          <CircularProgress style={{ color: darkMode ? '#4299E1' : '#3B82F6' }} />
          <p>Loading users...</p>
        </div>
      );
    }

    return (
      <table className="user-table" style={styles.table}>
        <thead>
          <tr style={styles.tableHeader}>
            <th>Name</th>
            <th>Create Date</th>
            <th>Role</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {sortedUsers.length > 0 ? (
            sortedUsers.map((user, index) => (
              <Fade in={true} style={{ transitionDelay: `${index * 30}ms` }} key={user.id || index}>
                <tr style={{ 
                  backgroundColor: darkMode ? (index % 2 === 0 ? '#1a2234' : '#273142') : (index % 2 === 0 ? '#f9f9f9' : '#ffffff'),
                  transition: 'all 0.3s ease'
                }}>
                  <td className="firstdata">
                    <div>
                      <span className="user-name" style={{ color: darkMode ? '#e0e0e0' : '#333' }}>{user.username}</span>
                      <p className="user-email" style={{ color: darkMode ? '#b0b0b0' : '#666' }}>{user.email}</p>
                    </div>
                    <span style={getRoleBadgeStyle(user.role)}>
                      {user.role}
                    </span>
                  </td>
                  <td style={{ color: darkMode ? '#e0e0e0' : '#333' }}>{user.date}</td>
                  <td>
                    <span style={{ color: darkMode ? '#e0e0e0' : '#333' }}>{user.role}</span>
                  </td>
                  <td>
                    <div className="images-action-conatiner">
                      {canEditUser(user) && (
                        <div 
                          className="action-icon edit-icon"
                          onClick={() => openPopup(user)}
                          title="Edit user"
                        >
                          <img 
                            src={editIcon} 
                            alt="Edit user" 
                            style={{ width: '18px', height: '18px' }}
                          />
                        </div>
                      )}
                      {canDeleteUser(user) && (
                        <div 
                          className="action-icon delete-icon"
                          onClick={() => handleDelete(user.id)}
                          title="Delete user"
                        >
                          <img 
                            src={deleteIcon} 
                            alt="Delete user" 
                            style={{ width: '18px', height: '18px' }}
                          />
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              </Fade>
            ))
          ) : (
            <tr>
              <td colSpan="4" style={{ textAlign: 'center', padding: '20px' }}>
                No users found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    );
  };

  if (loading && users.length === 0) {
    return (
      <div className="loading-container" style={styles.container}>
        <CircularProgress style={{ color: darkMode ? '#4299E1' : '#3B82F6' }} />
        <p>Loading users...</p>
      </div>
    );
  }

  // Display actual users or fallback to mock data if API isn't returning any real users
  const displayUsers = sortedUsers;

  return (
    <Fade in={true} timeout={300}>
      <div className="user-management" style={styles.container}>
        <ToastContainer
          position="top-right"
          autoClose={3000}
          hideProgressBar={false}
          newestOnTop
          closeOnClick
          rtl={false}
          pauseOnFocusLoss
          draggable
          pauseOnHover
          theme={darkMode ? "dark" : "light"}
        />
        <p className="title" style={styles.title}>Users Management</p>
        <div className="user-manage">
          <div className="header-actions">
            <div className="search-container">
              <img src={search} alt="Search icon" />
              <input 
                type="text" 
                placeholder="Search by name, email or role..." 
                className="search-input" 
                value={searchQuery}
                onChange={handleSearch}
                style={styles.input}
              />
            </div>
            <div className="header-btn">
              <button 
                className="add-user-btn" 
                onClick={() => openPopup()} 
              >
                Add User +
              </button>
              
              {/* Filter options */}
              <div className="filter-container">
                <button className="filter-btn" onClick={() => setIsFilterOpen(!isFilterOpen)} title="Filter and Sort">
                  <img src={filterIcon} alt="Filter icon" />
                </button>

                {/* نافذة الفلترة */}
                {isFilterOpen && (
                  <div className="filter-popup">
                    <h4>Filter & Sort</h4>
                    <div className="filter-form">
                      {/* Sort option and Role filter side by side */}
                      <div className="filter-group">
                        <label>Sort By</label>
                        <select 
                          name="sortBy" 
                          value={sortBy}
                          onChange={handleSort}
                        >
                          <option value="name">Name (A-Z)</option>
                          <option value="date">Date (Newest first)</option>
                          <option value="role">Role</option>
                        </select>
                      </div>
                      
                      {/* Filter by Role */}
                      <div className="filter-group">
                        <label>Filter by Role</label>
                        <select 
                          name="role" 
                          value={filters.role}
                          onChange={handleFilterChange}
                        >
                          <option value="">All Roles</option>
                          <option value="Super Admin">Super Admin</option>
                          <option value="Admin">Admin</option>
                          <option value="Analyst">Analyst</option>
                          <option value="Viewer">Viewer</option>
                        </select>
                      </div>
                      
                      {/* Date Range - Full width */}
                      <div className="filter-group full-width">
                        <label>Date Range</label>
                        <div style={{ display: 'flex', gap: '10px' }}>
                          <div style={{ flex: 1 }}>
                            <input 
                              type="date" 
                              name="dateFrom"
                              value={filters.dateFrom}
                              onChange={handleFilterChange}
                              placeholder="From"
                            />
                          </div>
                          <div style={{ flex: 1 }}>
                            <input 
                              type="date" 
                              name="dateTo"
                              value={filters.dateTo}
                              onChange={handleFilterChange}
                              placeholder="To"
                            />
                          </div>
                        </div>
                      </div>
                    </div>
                    
                    <div className="filter-actions">
                      <button onClick={cancelFilters} className="cancel-filter">Reset</button>
                      <button onClick={applyFilters} className="apply-filter">Apply</button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
          
          <Fade in={true} timeout={500}>
            <div className="user-list-container">
              <p className="table-title" style={styles.title}>
                Users List
                {(filters.role || filters.dateFrom || filters.dateTo) && (
                  <span className="filter-tags">
                    {filters.role && (
                      <span className="filter-tag">
                        Role: {filters.role}
                        <button onClick={() => setFilters({...filters, role: ''})}>×</button>
                      </span>
                    )}
                    {filters.dateFrom && (
                      <span className="filter-tag">
                        From: {filters.dateFrom}
                        <button onClick={() => setFilters({...filters, dateFrom: ''})}>×</button>
                      </span>
                    )}
                    {filters.dateTo && (
                      <span className="filter-tag">
                        To: {filters.dateTo}
                        <button onClick={() => setFilters({...filters, dateTo: ''})}>×</button>
                      </span>
                    )}
                  </span>
                )}
              </p>
              {error && <div className="error-message">{error}</div>}
              
              {/* مربع إحصائيات صغير فوق الجدول */}
              {!loading && (
                <div className="users-stats">
                  <div className="stat-item">
                    <span className="stat-value">{displayUsers.length}</span>
                    <span className="stat-label">Showing</span>
                  </div>
                  <div className="stat-item">
                    <span className="stat-value">{users.length}</span>
                    <span className="stat-label">Total Users</span>
                  </div>
                </div>
              )}
              
              {renderUserTable()}
            </div>
          </Fade>
          
          {/* Popup dialog */}
          {isPopupOpen && (
            <Zoom in={isPopupOpen} timeout={300}>
              <div className="popup-overlay">
                <div className="popup" style={styles.popup}>
                  <h3>{isEditing ? 'Edit User' : 'Add User'}</h3>
                  <div className="form-row">
                    <div className="form-group">
                      <input 
                        type="text" 
                        name="username"
                        placeholder="Username *" 
                        value={formData.username}
                        onChange={handleInputChange}
                        style={styles.input}
                      />
                      {formErrors.username && <span className="error">{formErrors.username}</span>}
                    </div>
                    <div className="form-group">
                      <input 
                        type="text" 
                        name="firstName"
                        placeholder="First Name *" 
                        value={formData.firstName}
                        onChange={handleInputChange}
                        style={styles.input}
                      />
                      {formErrors.firstName && <span className="error">{formErrors.firstName}</span>}
                    </div>
                    <div className="form-group">
                      <input 
                        type="text" 
                        name="lastName"
                        placeholder="Last Name *" 
                        value={formData.lastName}
                        onChange={handleInputChange}
                        style={styles.input}
                      />
                      {formErrors.lastName && <span className="error">{formErrors.lastName}</span>}
                    </div>
                  </div>
                  <div className="form-row">
                    <div className="form-group">
                      <input 
                        type="email" 
                        name="email"
                        placeholder="Email ID *" 
                        value={formData.email}
                        onChange={handleInputChange}
                        style={styles.input}
                      />
                      {formErrors.email && <span className="error">{formErrors.email}</span>}
                    </div>
                    <div className="form-group">
                      <input 
                        type="text" 
                        name="mobile"
                        placeholder="Mobile No" 
                        value={formData.mobile}
                        onChange={handleInputChange}
                        style={styles.input}
                      />
                    </div>
                    <div className="form-group">
                      <select 
                        name="role"
                        value={formData.role}
                        onChange={handleInputChange}
                        style={styles.input}
                      >
                        <option value="">Select Role Type</option>
                        <option value="Super Admin">Super Admin</option>
                        <option value="Admin">Admin</option>
                        <option value="Analyst">Analyst</option>
                        <option value="Viewer">Viewer</option>
                      </select>
                      {formErrors.role && <span className="error">{formErrors.role}</span>}
                    </div>
                  </div>
                  {!isEditing && (
                    <div className="form-row">
                      <div className="form-group">
                        <input 
                          type="password" 
                          name="password"
                          placeholder="Password*" 
                          value={formData.password}
                          onChange={handleInputChange}
                          style={styles.input}
                        />
                        {formErrors.password && <span className="error">{formErrors.password}</span>}
                      </div>
                      <div className="form-group">
                        <input 
                          type="password" 
                          name="confirmPassword"
                          placeholder="Confirm Password*" 
                          value={formData.confirmPassword}
                          onChange={handleInputChange}
                          style={styles.input}
                        />
                        {formErrors.confirmPassword && <span className="error">{formErrors.confirmPassword}</span>}
                      </div>
                    </div>
                  )}
                  {renderPermissionsTable()}
                  <div className="popup-buttons">
                    <button 
                      onClick={closePopup}
                      className="cancel-btn"
                    >
                      Cancel
                    </button>
                    <button 
                      className="save-btn" 
                      onClick={handleSubmit} 
                      disabled={isProcessing}
                    >
                      {isProcessing ? 'Processing...' : (isEditing ? 'Update User' : 'Add User')}
                    </button>
                  </div>
                </div>
              </div>
            </Zoom>
          )}
          
          {/* Confirmation Dialog */}
          {showConfirmation && (
            <Fade in={true}>
              <div style={styles.confirmationModal}>
                <Zoom in={true}>
                  <div style={styles.confirmationContent}>
                    {userDeleted ? (
                      <div style={{ textAlign: 'center', padding: '20px' }}>
                        <p style={{ color: '#10B981', fontSize: '18px', marginBottom: '10px' }}>
                          User deleted successfully!
                        </p>
                      </div>
                    ) : (
                      <>
                        <h3 style={{ marginBottom: '20px' }}>Confirm Deletion</h3>
                        <p style={{ marginBottom: '20px' }}>
                          Are you sure you want to delete this user? This action cannot be undone.
                        </p>
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                          <button
                            onClick={cancelDelete}
                            style={{ 
                              backgroundColor: darkMode ? '#334155' : '#f5f5f5', 
                              color: darkMode ? '#e0e0e0' : '#333',
                              border: 'none',
                              padding: '10px 15px',
                              borderRadius: '4px',
                              cursor: 'pointer',
                              transition: 'all 0.2s ease'
                            }}
                          >
                            Cancel
                          </button>
                          <button
                            onClick={confirmDelete}
                            disabled={isProcessing}
                            style={{ 
                              backgroundColor: isProcessing ? '#EF4444DD' : '#EF4444',
                              color: '#fff',
                              border: 'none',
                              padding: '10px 15px',
                              borderRadius: '4px',
                              cursor: isProcessing ? 'not-allowed' : 'pointer',
                              transition: 'all 0.2s ease'
                            }}
                          >
                            {isProcessing ? 'Deleting...' : 'Delete User'}
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                </Zoom>
              </div>
            </Fade>
          )}
        </div>
      </div>
    </Fade>
  );
};

export default UserManagement;
