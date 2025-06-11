import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Container,
  Paper,
  Typography,
  Tabs,
  Tab,
  Switch,
  FormControlLabel,
  TextField,
  Button,
  Alert,
  CircularProgress,
  Grid,
  Divider,
  IconButton,
  Tooltip,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Avatar,
  Card,
  CardContent,
  CardActions,
  Snackbar,
  Chip,
  InputAdornment,
  useTheme
} from '@mui/material';
import { styled } from '@mui/material/styles';
import { useNavigate } from 'react-router-dom';
import {
  fetchUserSettings,
  updateUserSettings,
  fetchSystemSettings,
  updateSystemSettings,
  fetchSecuritySettings,
  updateSecuritySettings,
  fetchNotificationSettings,
  updateNotificationSettings
} from '../../services/api';
import apiClient from '../../services/api';
import { getUserData, setUserData } from '../../services/auth';
import { hasPermission, defaultPermissionsForRole } from '../../utils/permissionUtils';
import { validateEmail } from '../../utils/validationUtils';
import InfoIcon from '@mui/icons-material/Info';
import SaveIcon from '@mui/icons-material/Save';
import RefreshIcon from '@mui/icons-material/Refresh';
import SecurityIcon from '@mui/icons-material/Security';
import NotificationsIcon from '@mui/icons-material/Notifications';
import SettingsIcon from '@mui/icons-material/Settings';
import PersonIcon from '@mui/icons-material/Person';
import VerifiedIcon from '@mui/icons-material/Verified';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import PhotoCameraIcon from '@mui/icons-material/PhotoCamera';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import '../../styles/ndashboard.css';

const StyledPaper = styled(Paper)(({ theme, isDarkMode }) => ({
  padding: theme.spacing(4),
  marginTop: theme.spacing(4),
  marginBottom: theme.spacing(4),
  borderRadius: '14px',
  boxShadow: isDarkMode ? '0 2px 10px rgba(0, 0, 0, 0.2)' : '0 2px 10px rgba(0, 0, 0, 0.05)',
  backgroundColor: isDarkMode ? '#273142' : '#ffffff',
  color: isDarkMode ? '#e0e0e0' : '#202224',
  transition: 'all 0.3s ease',
  border: isDarkMode ? '1px solid #3A4557' : 'none',
  '& .MuiTypography-root': {
    color: isDarkMode ? '#e0e0e0' : '#202224',
  },
  '& *': {
    borderColor: isDarkMode ? '#3A4557' : '#e0e0e0',
  }
}));

const StyledCard = styled(Card)(({ theme, isDarkMode }) => ({
  marginBottom: theme.spacing(3),
  borderRadius: '14px',
  boxShadow: isDarkMode ? '0 2px 10px rgba(0, 0, 0, 0.2)' : '0 2px 10px rgba(0, 0, 0, 0.05)',
  backgroundColor: isDarkMode ? '#273142' : '#ffffff',
  color: isDarkMode ? '#e0e0e0' : '#202224',
  border: isDarkMode ? '1px solid #3A4557' : 'none',
  transition: 'all 0.3s ease',
  '& .MuiCardContent-root': {
    backgroundColor: isDarkMode ? '#273142' : '#ffffff',
    padding: theme.spacing(3),
    '& .MuiTypography-root': {
      color: isDarkMode ? '#e0e0e0' : '#202224',
    },
  },
  '& .MuiTextField-root': {
    '& .MuiInputLabel-root': {
      color: isDarkMode ? '#b0b0b0' : '#636566',
    },
    '& .MuiInputBase-input': {
      color: isDarkMode ? '#e0e0e0' : '#202224',
    },
    '& .MuiOutlinedInput-root': {
      backgroundColor: isDarkMode ? '#1B2431' : '#fcfdfd',
      '& fieldset': {
        borderColor: isDarkMode ? '#3A4557' : '#e0e0e0',
      },
      '&:hover fieldset': {
        borderColor: isDarkMode ? '#4A5568' : '#b8babc',
      },
      '&.Mui-focused fieldset': {
        borderColor: isDarkMode ? '#60A5FA' : theme.palette.primary.main,
      },
    },
  },
  '& .MuiButton-root': {
    backgroundColor: isDarkMode ? '#3B82F6' : theme.palette.primary.main,
    color: '#FFFFFF',
    padding: theme.spacing(1.5, 3),
    borderRadius: '4px',
    '&:hover': {
      backgroundColor: isDarkMode ? '#2563EB' : theme.palette.primary.dark,
      transform: 'translateY(-1px)',
      boxShadow: isDarkMode ? '0 4px 6px -1px rgba(37, 99, 235, 0.2)' : theme.shadows[4],
    },
    '&:active': {
      transform: 'translateY(0)',
    },
    transition: 'all 0.2s ease',
  },
  '& .MuiDivider-root': {
    borderColor: isDarkMode ? '#3A4557' : '#e0e0e0',
    margin: theme.spacing(2, 0),
  },
}));

const Settings = () => {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  const [isDarkMode, setIsDarkMode] = useState(localStorage.getItem('darkMode') === 'true');
  const [userSettings, setUserSettings] = useState({
    profile: {
      username: '',
      email: '',
      first_name: '',
      last_name: '',
      role: '',
      profile_image: null,
      phone_number: '',
      bio: '',
      is_email_verified: false,
      last_password_change: null
    },
    notification_preferences: {
      email_notifications: true,
      sms_notifications: false,
      push_notifications: true,
      notify_on_alerts: true,
      notify_on_threats: true,
      notify_on_reports: true
    },
    interface_settings: {
      theme: 'light',
      dashboard_layout: 'default',
      language: 'en'
    }
  });
  const [systemSettings, setSystemSettings] = useState({
    system_name: '',
    version: '',
    maintenance_mode: false,
    max_login_attempts: 5,
    notification_settings: { email: true, sms: false },
    backup_settings: {},
    security_policy: '',
    last_backup: null
  });
  const [securitySettings, setSecuritySettings] = useState({
    max_login_attempts: 5,
    security_policy: '',
    backup_settings: {},
    last_backup: null,
    maintenance_mode: false
  });
  const [notificationSettings, setNotificationSettings] = useState({
    system_notifications: {},
    email_enabled: true,
    sms_enabled: false,
    push_enabled: true,
    notify_on_alerts: true,
    notify_on_threats: true,
    notify_on_reports: true
  });
  const [validationErrors, setValidationErrors] = useState({});
  const navigate = useNavigate();
  const [userData, setUserData] = useState(() => {
    try {
      const storedData = localStorage.getItem('user_data');
      return storedData ? JSON.parse(storedData) : null;
    } catch (error) {
      console.error('Error parsing user data:', error);
      return null;
    }
  });
  const [uploadingImage, setUploadingImage] = useState(false);
  const fileInputRef = useRef(null);

  useEffect(() => {
    fetchSettings();
    // Listen for dark mode changes
    const handleStorageChange = () => {
      setIsDarkMode(localStorage.getItem('darkMode') === 'true');
    };

    window.addEventListener('storage-local', handleStorageChange);
    return () => window.removeEventListener('storage-local', handleStorageChange);
  }, []);

  const handleSnackbarClose = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const showSnackbar = (message, severity = 'success') => {
    setSnackbar({ open: true, message, severity });
  };

  const validateForm = (formData, type) => {
    const errors = {};
    
    switch (type) {
      case 'user':
        if (formData.profile.email && !validateEmail(formData.profile.email)) {
          errors.email = 'Invalid email address';
        }
        break;
      case 'system':
        if (!formData.system_name) {
          errors.system_name = 'System name is required';
        }
        break;
      case 'security':
        if (formData.max_login_attempts < 1 || formData.max_login_attempts > 10) {
          errors.max_login_attempts = 'Max login attempts must be between 1 and 10';
        }
        break;
      default:
        break;
    }
    
    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const fetchSettings = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Fetch user settings
      const userResponse = await fetchUserSettings();
      console.log('User settings response:', userResponse);
      
      if (userResponse && userResponse.profile) {
        setUserSettings(userResponse);
        // Update userData with the latest profile data
        const newUserData = {
          ...userData,
          ...userResponse.profile,
          permissions: userResponse.profile.permissions || defaultPermissionsForRole(userResponse.profile.role)
        };
        setUserData(newUserData);
        localStorage.setItem('user_data', JSON.stringify(newUserData));
      } else {
        throw new Error('Invalid user settings data received');
      }

      // Get permissions from userData
      const userPermissions = userData?.permissions || defaultPermissionsForRole(userData?.role);
      console.log('User permissions:', userPermissions);

      // Check permissions using permissionUtils
      const hasSettingsReadPermission = hasPermission(userPermissions, 'settings', 'read');
      const hasSettingsWritePermission = hasPermission(userPermissions, 'settings', 'write');
      
      console.log('Settings permissions:', {
        hasSettingsReadPermission,
        hasSettingsWritePermission
      });

      // Fetch system and security settings if user has read permission
      if (hasSettingsReadPermission) {
        const [systemResponse, securityResponse] = await Promise.all([
          fetchSystemSettings(),
          fetchSecuritySettings()
        ]);

        console.log('System settings response:', systemResponse);
        console.log('Security settings response:', securityResponse);

        if (systemResponse) {
          setSystemSettings(systemResponse);
        }
        if (securityResponse) {
          setSecuritySettings(securityResponse);
        }
      }

      // Fetch notification settings
      const notificationResponse = await fetchNotificationSettings();
      console.log('Notification settings response:', notificationResponse);
      
      if (notificationResponse) {
        setNotificationSettings(notificationResponse);
      }

    } catch (err) {
      console.error('Error fetching settings:', err);
      const errorMessage = err.response?.data?.error || err.message || 'Failed to load settings. Please try again.';
      setError(errorMessage);
      showSnackbar(errorMessage, 'error');
      if (err.response?.status === 401) {
        navigate('/login');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleTabChange = (event, newValue) => {
    // Check if user has permission to access the tab
    if (newValue === 1 || newValue === 2) {
      const userPermissions = userData?.permissions || defaultPermissionsForRole(userData?.role);
      if (!hasPermission(userPermissions, 'settings', 'read')) {
        showSnackbar('You do not have permission to access this tab', 'error');
        return;
      }
    }
    setActiveTab(newValue);
    setError(null);
    setSuccess(null);
    setValidationErrors({});
  };

  const handleUserSettingsUpdate = async (e) => {
    e.preventDefault();
    try {
      if (!validateForm(userSettings, 'user')) {
        showSnackbar('Please fix validation errors', 'error');
        return;
      }

      setLoading(true);
      setError(null);
      setSuccess(null);
      
      const formData = new FormData();
      formData.append('first_name', userSettings.profile.first_name);
      formData.append('last_name', userSettings.profile.last_name);
      formData.append('email', userSettings.profile.email);
      formData.append('phone_number', userSettings.profile.phone_number);
      formData.append('bio', userSettings.profile.bio);
      
      // Add notification preferences
      Object.entries(userSettings.notification_preferences).forEach(([key, value]) => {
        formData.append(`notification_preferences[${key}]`, value);
      });
      
      // Add interface settings
      Object.entries(userSettings.interface_settings).forEach(([key, value]) => {
        formData.append(`interface_settings[${key}]`, value);
      });

      const response = await apiClient.put('/settings/user/', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      if (response.data) {
        showSnackbar('User settings updated successfully');
        // Fetch fresh data after successful update
        await fetchSettings();
      } else {
        throw new Error('Invalid response received from server');
      }
    } catch (err) {
      console.error('Error updating user settings:', err);
      const errorMessage = err.response?.data?.error || err.message || 'Failed to update user settings';
      setError(errorMessage);
      showSnackbar(errorMessage, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleSystemSettingsUpdate = async (e) => {
    e.preventDefault();
    try {
      if (!validateForm(systemSettings, 'system')) {
        showSnackbar('Please fix validation errors', 'error');
        return;
      }

      if (!hasPermission(userData?.permissions, 'settings', 'write')) {
        throw new Error('You do not have permission to update system settings');
      }

      setLoading(true);
      setError(null);
      setSuccess(null);
      
      const response = await updateSystemSettings(systemSettings);
      if (response) {
        setSystemSettings(response);
        showSnackbar('System settings updated successfully');
      } else {
        throw new Error('Invalid response received from server');
      }
    } catch (err) {
      console.error('Error updating system settings:', err);
      const errorMessage = err.response?.data?.error || err.message || 'Failed to update system settings';
      setError(errorMessage);
      showSnackbar(errorMessage, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleSecuritySettingsUpdate = async (e) => {
    e.preventDefault();
    try {
      if (!validateForm(securitySettings, 'security')) {
        showSnackbar('Please fix validation errors', 'error');
        return;
      }

      if (!hasPermission(userData?.permissions, 'settings', 'write')) {
        throw new Error('You do not have permission to update security settings');
      }

      setLoading(true);
      setError(null);
      setSuccess(null);
      
      const response = await updateSecuritySettings(securitySettings);
      if (response) {
        setSecuritySettings(response);
        showSnackbar('Security settings updated successfully');
      } else {
        throw new Error('Invalid response received from server');
      }
    } catch (err) {
      console.error('Error updating security settings:', err);
      const errorMessage = err.response?.data?.error || err.message || 'Failed to update security settings';
      setError(errorMessage);
      showSnackbar(errorMessage, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleNotificationSettingsUpdate = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      setError(null);
      setSuccess(null);
      
      const response = await updateNotificationSettings(notificationSettings);
      if (response) {
        setNotificationSettings(response);
        showSnackbar('Notification settings updated successfully');
      } else {
        throw new Error('Invalid response received from server');
      }
    } catch (err) {
      console.error('Error updating notification settings:', err);
      const errorMessage = err.response?.data?.error || err.message || 'Failed to update notification settings';
      setError(errorMessage);
      showSnackbar(errorMessage, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleImageUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    // Validate file type
    if (!file.type.startsWith('image/')) {
      showSnackbar('Please select an image file', 'error');
      return;
    }

    // Validate file size (5MB max)
    if (file.size > 5 * 1024 * 1024) {
      showSnackbar('Image size should be less than 5MB', 'error');
      return;
    }

    try {
      setUploadingImage(true);
      const formData = new FormData();
      formData.append('profile_image', file);

      const response = await apiClient.post('/update-profile-image/', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      if (response.data.profile_image) {
        // Update user settings with new image
        const updatedSettings = {
          ...userSettings,
          profile: {
            ...userSettings.profile,
            profile_image: response.data.profile_image
          }
        };
        setUserSettings(updatedSettings);

        // Update userData in localStorage
        const newUserData = {
          ...userData,
          profile_image: response.data.profile_image
        };
        setUserData(newUserData);
        localStorage.setItem('user_data', JSON.stringify(newUserData));

        showSnackbar('Profile image updated successfully', 'success');
      }
    } catch (error) {
      console.error('Error uploading image:', error);
      showSnackbar(error.response?.data?.error || 'Failed to upload image', 'error');
    } finally {
      setUploadingImage(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <div className="dashboard">
      <h3 className="title-page">User Settings</h3>

      {error && (
        <Alert severity="error" sx={{ 
          mb: 3,
          backgroundColor: isDarkMode ? '#273142' : undefined,
          color: isDarkMode ? '#e0e0e0' : undefined,
          borderRadius: '4px',
          '& .MuiAlert-icon': {
            color: isDarkMode ? '#EF4444' : undefined
          }
        }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <StyledPaper isDarkMode={isDarkMode}>
        <form onSubmit={handleUserSettingsUpdate}>
          <Grid container spacing={4}>
            <Grid item xs={12} md={4}>
              <StyledCard isDarkMode={isDarkMode}>
                <CardContent>
                  <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mb: 3 }}>
                    <Box sx={{ position: 'relative', mb: 2 }}>
                      <Avatar
                        src={userSettings.profile?.profile_image ? `http://localhost:8000${userSettings.profile.profile_image}` : ''}
                        sx={{ 
                          width: 120, 
                          height: 120, 
                          mb: 2,
                          backgroundColor: isDarkMode ? '#374151' : theme.palette.grey[200],
                          border: isDarkMode ? '3px solid #3A4557' : 'none',
                          boxShadow: isDarkMode ? '0 2px 10px rgba(0, 0, 0, 0.2)' : '0 2px 10px rgba(0, 0, 0, 0.05)',
                        }}
                      >
                        {!userSettings.profile?.profile_image && <AccountCircleIcon sx={{ width: 80, height: 80 }} />}
                      </Avatar>
                      <input
                        type="file"
                        accept="image/*"
                        style={{ display: 'none' }}
                        ref={fileInputRef}
                        onChange={handleImageUpload}
                      />
                      <IconButton
                        color="primary"
                        sx={{
                          position: 'absolute',
                          bottom: 16,
                          right: 16,
                          backgroundColor: isDarkMode ? '#1B2431' : 'white',
                          border: isDarkMode ? '1px solid #3A4557' : 'none',
                          boxShadow: isDarkMode ? '0 2px 10px rgba(0, 0, 0, 0.2)' : '0 2px 10px rgba(0, 0, 0, 0.05)',
                          '&:hover': { 
                            backgroundColor: isDarkMode ? '#273142' : theme.palette.grey[100],
                            transform: 'scale(1.05)',
                          },
                          transition: 'all 0.2s ease',
                        }}
                        onClick={() => fileInputRef.current?.click()}
                        disabled={uploadingImage}
                      >
                        {uploadingImage ? (
                          <CircularProgress size={24} />
                        ) : (
                          <PhotoCameraIcon />
                        )}
                      </IconButton>
                    </Box>
                    <Typography variant="h6" sx={{ 
                      color: isDarkMode ? '#e0e0e0' : '#202224',
                      fontWeight: 600,
                      mb: 1
                    }}>
                      {userSettings.profile?.username}
                    </Typography>
                    <Typography 
                      sx={{ 
                        mb: 2,
                        color: isDarkMode ? '#b0b0b0' : '#636566',
                        fontSize: '0.9rem'
                      }}
                    >
                      {userSettings.profile?.role}
                    </Typography>
                    {userSettings.profile?.is_email_verified && (
                      <Chip
                        icon={<VerifiedIcon />}
                        label="Email Verified"
                        color="success"
                        size="small"
                        sx={{ 
                          mt: 1,
                          backgroundColor: isDarkMode ? 'rgba(16, 185, 129, 0.2)' : theme.palette.success.main,
                          color: isDarkMode ? '#10B981' : 'white',
                          fontWeight: 500,
                          '& .MuiChip-icon': {
                            color: isDarkMode ? '#10B981' : 'white'
                          }
                        }}
                      />
                    )}
                  </Box>
                </CardContent>
              </StyledCard>
            </Grid>

            <Grid item xs={12} md={8}>
              <StyledCard isDarkMode={isDarkMode}>
                <CardContent>
                  <Typography variant="h6" gutterBottom sx={{ 
                    color: isDarkMode ? '#e0e0e0' : '#202224',
                    fontWeight: 600,
                    mb: 4,
                    display: 'flex',
                    alignItems: 'center',
                    gap: theme.spacing(1)
                  }}>
                    <AccountCircleIcon sx={{ color: isDarkMode ? '#60A5FA' : theme.palette.primary.main }} />
                    Profile Information
                  </Typography>
                  <Grid container spacing={3}>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        fullWidth
                        label="Username"
                        value={userSettings.profile?.username || ''}
                        disabled
                        error={!!validationErrors.username}
                        helperText={validationErrors.username}
                        sx={{
                          '& .MuiInputLabel-root': {
                            color: isDarkMode ? '#b0b0b0' : '#636566',
                          },
                          '& .MuiInputBase-input': {
                            color: isDarkMode ? '#e0e0e0' : '#202224',
                          },
                          '& .MuiOutlinedInput-root': {
                            backgroundColor: isDarkMode ? '#1B2431' : '#fcfdfd',
                            '& fieldset': {
                              borderColor: isDarkMode ? '#3A4557' : '#e0e0e0',
                            },
                            '&:hover fieldset': {
                              borderColor: isDarkMode ? '#4A5568' : '#b8babc',
                            },
                            '&.Mui-focused fieldset': {
                              borderColor: isDarkMode ? '#60A5FA' : theme.palette.primary.main,
                            },
                          },
                        }}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        fullWidth
                        label="Email"
                        type="email"
                        value={userSettings.profile?.email || ''}
                        onChange={(e) => setUserSettings({
                          ...userSettings,
                          profile: { ...userSettings.profile, email: e.target.value }
                        })}
                        error={!!validationErrors.email}
                        helperText={validationErrors.email}
                        InputProps={{
                          endAdornment: userSettings.profile?.is_email_verified && (
                            <InputAdornment position="end">
                              <Tooltip title="Email Verified">
                                <VerifiedIcon sx={{ color: isDarkMode ? '#10B981' : theme.palette.success.main }} />
                              </Tooltip>
                            </InputAdornment>
                          )
                        }}
                        sx={{
                          '& .MuiInputLabel-root': {
                            color: isDarkMode ? '#b0b0b0' : '#636566',
                          },
                          '& .MuiInputBase-input': {
                            color: isDarkMode ? '#e0e0e0' : '#202224',
                          },
                          '& .MuiOutlinedInput-root': {
                            backgroundColor: isDarkMode ? '#1B2431' : '#fcfdfd',
                            '& fieldset': {
                              borderColor: isDarkMode ? '#3A4557' : '#e0e0e0',
                            },
                            '&:hover fieldset': {
                              borderColor: isDarkMode ? '#4A5568' : '#b8babc',
                            },
                            '&.Mui-focused fieldset': {
                              borderColor: isDarkMode ? '#60A5FA' : theme.palette.primary.main,
                            },
                          },
                        }}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        fullWidth
                        label="First Name"
                        value={userSettings.profile?.first_name || ''}
                        onChange={(e) => setUserSettings({
                          ...userSettings,
                          profile: { ...userSettings.profile, first_name: e.target.value }
                        })}
                        sx={{
                          '& .MuiInputLabel-root': {
                            color: isDarkMode ? '#b0b0b0' : '#636566',
                          },
                          '& .MuiInputBase-input': {
                            color: isDarkMode ? '#e0e0e0' : '#202224',
                          },
                          '& .MuiOutlinedInput-root': {
                            backgroundColor: isDarkMode ? '#1B2431' : '#fcfdfd',
                            '& fieldset': {
                              borderColor: isDarkMode ? '#3A4557' : '#e0e0e0',
                            },
                            '&:hover fieldset': {
                              borderColor: isDarkMode ? '#4A5568' : '#b8babc',
                            },
                            '&.Mui-focused fieldset': {
                              borderColor: isDarkMode ? '#60A5FA' : theme.palette.primary.main,
                            },
                          },
                        }}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        fullWidth
                        label="Last Name"
                        value={userSettings.profile?.last_name || ''}
                        onChange={(e) => setUserSettings({
                          ...userSettings,
                          profile: { ...userSettings.profile, last_name: e.target.value }
                        })}
                        sx={{
                          '& .MuiInputLabel-root': {
                            color: isDarkMode ? '#b0b0b0' : '#636566',
                          },
                          '& .MuiInputBase-input': {
                            color: isDarkMode ? '#e0e0e0' : '#202224',
                          },
                          '& .MuiOutlinedInput-root': {
                            backgroundColor: isDarkMode ? '#1B2431' : '#fcfdfd',
                            '& fieldset': {
                              borderColor: isDarkMode ? '#3A4557' : '#e0e0e0',
                            },
                            '&:hover fieldset': {
                              borderColor: isDarkMode ? '#4A5568' : '#b8babc',
                            },
                            '&.Mui-focused fieldset': {
                              borderColor: isDarkMode ? '#60A5FA' : theme.palette.primary.main,
                            },
                          },
                        }}
                      />
                    </Grid>
                    <Grid item xs={12}>
                      <TextField
                        fullWidth
                        label="Bio"
                        multiline
                        rows={4}
                        value={userSettings.profile?.bio || ''}
                        onChange={(e) => setUserSettings({
                          ...userSettings,
                          profile: { ...userSettings.profile, bio: e.target.value }
                        })}
                        sx={{
                          '& .MuiInputLabel-root': {
                            color: isDarkMode ? '#b0b0b0' : '#636566',
                          },
                          '& .MuiInputBase-input': {
                            color: isDarkMode ? '#e0e0e0' : '#202224',
                          },
                          '& .MuiOutlinedInput-root': {
                            backgroundColor: isDarkMode ? '#1B2431' : '#fcfdfd',
                            '& fieldset': {
                              borderColor: isDarkMode ? '#3A4557' : '#e0e0e0',
                            },
                            '&:hover fieldset': {
                              borderColor: isDarkMode ? '#4A5568' : '#b8babc',
                            },
                            '&.Mui-focused fieldset': {
                              borderColor: isDarkMode ? '#60A5FA' : theme.palette.primary.main,
                            },
                          },
                        }}
                      />
                    </Grid>
                    <Grid item xs={12}>
                      <Typography 
                        variant="body2" 
                        sx={{ 
                          color: isDarkMode ? '#b0b0b0' : '#636566',
                          fontSize: '0.875rem',
                          display: 'flex',
                          alignItems: 'center',
                          gap: theme.spacing(1)
                        }}
                      >
                        <SecurityIcon sx={{ fontSize: '1rem' }} />
                        Last password change: {userSettings.profile?.last_password_change ? new Date(userSettings.profile.last_password_change).toLocaleString() : 'Never'}
                      </Typography>
                    </Grid>
                  </Grid>
                </CardContent>
              </StyledCard>
            </Grid>
          </Grid>

          <Box sx={{ 
            mt: 4, 
            display: 'flex', 
            justifyContent: 'flex-end',
            gap: theme.spacing(2)
          }}>
            <Button
              type="submit"
              variant="contained"
              color="primary"
              startIcon={<SaveIcon />}
              size="large"
              sx={{
                backgroundColor: isDarkMode ? '#3B82F6' : theme.palette.primary.main,
                color: '#FFFFFF',
                padding: theme.spacing(1.5, 4),
                borderRadius: '4px',
                '&:hover': {
                  backgroundColor: isDarkMode ? '#2563EB' : theme.palette.primary.dark,
                  transform: 'translateY(-1px)',
                  boxShadow: isDarkMode ? '0 4px 6px -1px rgba(37, 99, 235, 0.2)' : theme.shadows[4],
                },
                '&:active': {
                  transform: 'translateY(0)',
                },
                transition: 'all 0.2s ease',
              }}
            >
              Save Changes
            </Button>
          </Box>
        </form>
      </StyledPaper>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleSnackbarClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert 
          onClose={handleSnackbarClose} 
          severity={snackbar.severity} 
          sx={{ 
            width: '100%',
            backgroundColor: isDarkMode ? '#273142' : undefined,
            color: isDarkMode ? '#e0e0e0' : undefined,
            '& .MuiAlert-icon': {
              color: isDarkMode ? (snackbar.severity === 'error' ? '#EF4444' : '#10B981') : undefined
            }
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </div>
  );
};

export default Settings; 