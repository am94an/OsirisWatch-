import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';
import { useNotifications } from '../contexts/NotificationContext';
import { useTranslation } from 'react-i18next';
import { 
  Box, 
  Typography, 
  Button, 
  Paper, 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
  FormControlLabel,
  Checkbox,
  Tooltip
} from '@mui/material';
import { 
  Add as AddIcon, 
  Edit as EditIcon, 
  Delete as DeleteIcon,
  Visibility as VisibilityIcon
} from '@mui/icons-material';
import { format } from 'date-fns';
import { arEG } from 'date-fns/locale';
import { useApi } from '../contexts/ApiContext';

const UserManagement = () => {
  const { t } = useTranslation();
  const { user: currentUser, logout } = useAuth();
  const { theme } = useTheme();
  const { showNotification } = useNotifications();
  const navigate = useNavigate();
  const { api } = useApi();
  
  // Debug logs
  console.log('Current User Data:', currentUser);
  
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [openDialog, setOpenDialog] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [currentUserPermissions, setCurrentUserPermissions] = useState({
    dashboard: { read: false, write: false, delete: false },
    reports: { read: false, write: false, delete: false },
    users: { read: false, write: false, delete: false },
    settings: { read: false, write: false, delete: false }
  });

  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    firstName: '',
    lastName: '',
    mobile: '',
    role: 'Viewer',
    permissions: {
      dashboard: { read: false, write: false, delete: false },
      reports: { read: false, write: false, delete: false },
      users: { read: false, write: false, delete: false },
      settings: { read: false, write: false, delete: false }
    }
  });

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/users/');
      console.log('Received users data:', response.data);
      
      if (response.data && response.data.users) {
        setUsers(response.data.users);
        if (response.data.current_user_permissions) {
          setCurrentUserPermissions(response.data.current_user_permissions);
        }
      } else {
        console.error('Invalid data format received:', response.data);
        setError('Invalid data format received from server');
      }
    } catch (err) {
      console.error('Error loading users:', err);
      setError(err.response?.data?.error || 'Failed to load users');
      if (err.response?.status === 401) {
        showNotification('Session expired. Please login again.', 'error');
        logout();
        navigate('/login');
      }
    } finally {
      setLoading(false);
    }
  };

  // Check if current user can edit/delete a specific user
  const canEditUser = (user) => {
    if (!currentUserPermissions) return false;
    
    // Admin can edit anyone
    if (user.role === 'Admin') return true;
    
    // Analyst can only edit Viewer or Device users
    if (user.role === 'Analyst') {
      return user.role in ['Viewer', 'Device'] && currentUserPermissions.users?.write;
    }
    
    return false;
  };

  const canDeleteUser = (user) => {
    if (!currentUserPermissions) return false;
    
    // Admin can delete anyone
    if (user.role === 'Admin') return true;
    
    // Analyst can only delete Viewer or Device users
    if (user.role === 'Analyst') {
      return user.role in ['Viewer', 'Device'] && currentUserPermissions.users?.delete;
    }
    
    return false;
  };

  // Convert backend permissions to frontend format
  const convertBackendPermissions = (permissions) => {
    if (!permissions) return null;
    
    return {
      dashboard: {
        read: permissions.can_view_dashboard || false,
        write: permissions.can_view_dashboard || false,
        delete: permissions.can_view_dashboard || false
      },
      reports: {
        read: permissions.can_view_reports || false,
        write: permissions.can_edit_reports || false,
        delete: permissions.can_delete_reports || false
      },
      users: {
        read: permissions.can_view_users || false,
        write: permissions.can_edit_users || false,
        delete: permissions.can_delete_users || false
      },
      settings: {
        read: permissions.can_view_notifications || false,
        write: permissions.can_manage_notifications || false,
        delete: permissions.can_manage_notifications || false
      }
    };
  };

  // Convert frontend permissions to backend format
  const convertFrontendPermissions = (permissions) => {
    if (!permissions) return null;
    
    return {
      can_view_dashboard: permissions.dashboard?.read || false,
      can_view_reports: permissions.reports?.read || false,
      can_edit_reports: permissions.reports?.write || false,
      can_delete_reports: permissions.reports?.delete || false,
      can_view_users: permissions.users?.read || false,
      can_edit_users: permissions.users?.write || false,
      can_delete_users: permissions.users?.delete || false,
      can_view_notifications: permissions.settings?.read || false,
      can_manage_notifications: permissions.settings?.write || false
    };
  };

  const handleOpenDialog = (user = null) => {
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
        permissions: user.permissions || {
          dashboard: { read: false, write: false, delete: false },
          reports: { read: false, write: false, delete: false },
          users: { read: false, write: false, delete: false },
          settings: { read: false, write: false, delete: false }
        }
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
        permissions: {
          dashboard: { read: false, write: false, delete: false },
          reports: { read: false, write: false, delete: false },
          users: { read: false, write: false, delete: false },
          settings: { read: false, write: false, delete: false }
        }
      });
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setSelectedUser(null);
    setFormData({
      username: '',
      email: '',
      password: '',
      firstName: '',
      lastName: '',
      mobile: '',
      role: 'Viewer',
      permissions: {
        dashboard: { read: false, write: false, delete: false },
        reports: { read: false, write: false, delete: false },
        users: { read: false, write: false, delete: false },
        settings: { read: false, write: false, delete: false }
      }
    });
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handlePermissionChange = (section, action) => {
    setFormData(prev => ({
      ...prev,
      permissions: {
        ...prev.permissions,
        [section]: {
          ...prev.permissions[section],
          [action]: !prev.permissions[section][action]
        }
      }
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const dataToSend = {
        ...formData,
        permissions: convertFrontendPermissions(formData.permissions)
      };

      if (selectedUser) {
        await api.put(`/api/users/${selectedUser.id}/`, dataToSend);
        showNotification('User updated successfully', 'success');
      } else {
        await api.post('/api/users/', dataToSend);
        showNotification('User created successfully', 'success');
      }
      handleCloseDialog();
      loadUsers();
    } catch (err) {
      console.error('Error saving user:', err);
      showNotification(err.response?.data?.error || 'Failed to save user', 'error');
    }
  };

  const handleDelete = async (userId) => {
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

  if (loading) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography>Loading...</Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography color="error">{error}</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5" component="h1">
          {t('userManagement.title')}
        </Typography>
        {currentUserPermissions.users?.write && (
          <Button
            variant="contained"
            color="primary"
            startIcon={<AddIcon />}
            onClick={() => handleOpenDialog()}
          >
            {t('userManagement.addUser')}
          </Button>
        )}
      </Box>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>{t('userManagement.username')}</TableCell>
              <TableCell>{t('userManagement.name')}</TableCell>
              <TableCell>{t('userManagement.email')}</TableCell>
              <TableCell>{t('userManagement.role')}</TableCell>
              <TableCell>{t('userManagement.date')}</TableCell>
              <TableCell>{t('userManagement.actions')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {users.map((user) => (
              <TableRow key={user.id}>
                <TableCell>{user.username}</TableCell>
                <TableCell>{`${user.firstName} ${user.lastName}`}</TableCell>
                <TableCell>{user.email}</TableCell>
                <TableCell>{user.role}</TableCell>
                <TableCell>
                  {format(new Date(user.date), 'dd/MM/yyyy', { locale: arEG })}
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    {currentUserPermissions.users?.read && (
                      <Tooltip title={t('userManagement.view')}>
                        <IconButton
                          size="small"
                          onClick={() => handleOpenDialog(user)}
                        >
                          <VisibilityIcon />
                        </IconButton>
                      </Tooltip>
                    )}
                    {canEditUser(user) && (
                      <Tooltip title={t('userManagement.edit')}>
                        <IconButton
                          size="small"
                          onClick={() => handleOpenDialog(user)}
                        >
                          <EditIcon />
                        </IconButton>
                      </Tooltip>
                    )}
                    {canDeleteUser(user) && (
                      <Tooltip title={t('userManagement.delete')}>
                        <IconButton
                          size="small"
                          onClick={() => handleDelete(user.id)}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                    )}
                  </Box>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog 
        open={openDialog} 
        onClose={handleCloseDialog}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          {selectedUser ? t('userManagement.editUser') : t('userManagement.addUser')}
        </DialogTitle>
        <DialogContent>
          <Box component="form" onSubmit={handleSubmit} sx={{ mt: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label={t('userManagement.username')}
                  name="username"
                  value={formData.username}
                  onChange={handleInputChange}
                  required
                  disabled={!!selectedUser}
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label={t('userManagement.email')}
                  name="email"
                  type="email"
                  value={formData.email}
                  onChange={handleInputChange}
                  required
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label={t('userManagement.password')}
                  name="password"
                  type="password"
                  value={formData.password}
                  onChange={handleInputChange}
                  required={!selectedUser}
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label={t('userManagement.mobile')}
                  name="mobile"
                  value={formData.mobile}
                  onChange={handleInputChange}
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label={t('userManagement.firstName')}
                  name="firstName"
                  value={formData.firstName}
                  onChange={handleInputChange}
                  required
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label={t('userManagement.lastName')}
                  name="lastName"
                  value={formData.lastName}
                  onChange={handleInputChange}
                  required
                />
              </Grid>
              <Grid item xs={12}>
                <FormControl fullWidth>
                  <InputLabel>{t('userManagement.role')}</InputLabel>
                  <Select
                    name="role"
                    value={formData.role}
                    onChange={handleInputChange}
                    required
                  >
                    <MenuItem value="Admin">Admin</MenuItem>
                    <MenuItem value="Analyst">Analyst</MenuItem>
                    <MenuItem value="Viewer">Viewer</MenuItem>
                    <MenuItem value="Device">Device</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12}>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  {t('userManagement.permissions')}
                </Typography>
                <Grid container spacing={2}>
                  {Object.entries(formData.permissions).map(([section, actions]) => (
                    <Grid item xs={12} sm={6} md={3} key={section}>
                      <Paper sx={{ p: 2 }}>
                        <Typography variant="subtitle1" sx={{ mb: 1 }}>
                          {t(`permissions.${section}`)}
                        </Typography>
                        {Object.entries(actions).map(([action, value]) => (
                          <FormControlLabel
                            key={action}
                            control={
                              <Checkbox
                                checked={value}
                                onChange={() => handlePermissionChange(section, action)}
                              />
                            }
                            label={t(`permissions.${action}`)}
                          />
                        ))}
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Grid>
            </Grid>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>
            {t('common.cancel')}
          </Button>
          <Button 
            onClick={handleSubmit} 
            variant="contained" 
            color="primary"
          >
            {selectedUser ? t('common.update') : t('common.create')}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default UserManagement; 