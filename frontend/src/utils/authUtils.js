import { login, signup, resetPassword, changePassword, logout } from '../services/api';
import { loginUser, setUserData } from '../services/auth';

export const handleLogin = async (username, password, setMessage, setMessageType, navigate) => {
  try {
    const data = await login(username, password);
    console.log('Login response:', data); 
    if (data.access) { 
      // Store the access token
      localStorage.setItem('auth_token', data.access);
      if (data.refresh) {
        localStorage.setItem('refresh_token', data.refresh);
      }
      
      // If user data is included in the response, store it
      if (data.user) {
        setUserData(data.user);
      }
      
      setMessage('Login successful!');
      setMessageType('success');
      setTimeout(() => {
        navigate('/dashboard'); 
      }, 1000);
    } else {
      setMessage('Login failed');
      setMessageType('error');
    }
  } catch (error) {
    console.error('Login error:', error);
    setMessage(error.response?.data?.error || 'An error occurred. Please try again.');
    setMessageType('error');
  }
};

export const handleSignup = async (email, username, password, confirmPassword, setMessage, setMessageType) => {
  const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  
  if (!email || !username || !password || !confirmPassword) {
    setMessage('Please fill in all fields.');
    setMessageType('error');
    return;
  }

  if (!isValidEmail(email)) {
    setMessage('Please enter a valid email address.');
    setMessageType('error');
    return;
  }

  if (password !== confirmPassword) {
    setMessage('Passwords do not match.');
    setMessageType('error');
    return;
  }

  try {
    const userData = {
      email,
      username,
      password,
      confirm_password: confirmPassword
    };
    const data = await signup(userData);
    if (data.message && data.message.includes('success')) {
      setMessage('Signup successful! Please log in.');
      setMessageType('success');
      return true;
    } else {
      setMessage(data.message || 'Signup failed');
      setMessageType('error');
      return false;
    }
  } catch (error) {
    console.error('Signup error:', error);
    // The error is already formatted by handleApiError
    setMessage(error.message);
    setMessageType('error');
    return false;
  }
};

export const handleResetPassword = async (email, setMessage, setMessageType) => {
  try {
    const data = await resetPassword(email);
    if (data.message && data.message.includes('sent')) {
      setMessage('Password reset link sent to your email!');
      setMessageType('success');
      return true;
    } else {
      setMessage(data.message || 'Password reset failed');
      setMessageType('error');
      return false;
    }
  } catch (error) {
    console.error('Reset password error:', error);
    setMessage(error.response?.data?.error || 'An error occurred. Please try again.');
    setMessageType('error');
    return false;
  }
};

export const handleChangePassword = async (uidb64, token, newPassword, setMessage, setMessageType) => {
  try {
    const data = await changePassword(uidb64, token, newPassword);
    if (data.message && data.message.includes('success')) {
      setMessage('Password changed successfully!');
      setMessageType('success');
      return true;
    } else {
      setMessage(data.message || 'Failed to change password');
      setMessageType('error');
      return false;
    }
  } catch (error) {
    console.error('Change password error:', error);
    setMessage(error.response?.data?.error || 'An error occurred. Please try again.');
    setMessageType('error');
    return false;
  }
};

export const handleLogout = async (navigate) => {
  try {
    // Call the logout API endpoint
    await logout();
  } catch (error) {
    console.error('Logout error:', error);
  } finally {
    // Always clear local storage even if API call fails
    localStorage.removeItem('auth_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user_data');
    navigate('/');
  }
};
