import api from './api';
import { jwtDecode } from 'jwt-decode';
import { AUTH_TOKEN_KEY } from './api';

export const isAuthenticated = () => {
    const token = localStorage.getItem(AUTH_TOKEN_KEY);
    if (!token) return false;
    
    try {
        // Check if token is expired
        const decoded = jwtDecode(token);
        const currentTime = Date.now() / 1000;
        return decoded.exp > currentTime;
    } catch (error) {
        return false;
    }
};

export const loginUser = (token, refreshToken) => {
    localStorage.setItem(AUTH_TOKEN_KEY, token);
    if (refreshToken) {
        localStorage.setItem('refresh_token', refreshToken);
    }
};

export const logoutUser = () => {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user_data');
};

export const getUserData = () => {
    const userData = localStorage.getItem('user_data');
    if (userData) {
        return JSON.parse(userData);
    }
    return null;
};

export const setUserData = (data) => {
    localStorage.setItem('user_data', JSON.stringify(data));
};

export const refreshToken = async () => {
    try {
        const refreshToken = localStorage.getItem('refresh_token');
        if (!refreshToken) {
            throw new Error('No refresh token available');
        }
        
        const response = await api.post('/token/refresh/', {
            refresh: refreshToken
        });
        
        if (response.data.access) {
            localStorage.setItem(AUTH_TOKEN_KEY, response.data.access);
            return true;
        }
        return false;
    } catch (error) {
        console.error('Token refresh failed:', error);
        logoutUser();
        return false;
    }
};

export const checkAndRefreshToken = async () => {
    try {
        const token = localStorage.getItem(AUTH_TOKEN_KEY);
        if (!token) return false;
        
        const decoded = jwtDecode(token);
        const currentTime = Date.now() / 1000;
        
        // If token will expire in less than 5 minutes (300 seconds), refresh it
        if (decoded.exp - currentTime < 300) {
            return await refreshToken();
        }
        
        return true;
    } catch (error) {
        console.error('Token check failed:', error);
        return await refreshToken();
    }
};
