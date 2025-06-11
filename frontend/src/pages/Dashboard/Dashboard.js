import React, { useEffect, useState } from 'react';
import { Routes, Route, useNavigate } from 'react-router-dom';
import Navbar from '../../components/layout/Navbar.js';
import Sidebar from '../../components/Sidebar.js';
import MainContainerdash from '../../components/layout/MainContainerdash.js';
import Report from '../../components/Reports.jsx';
import UserManagement from '../../components/layout/UserManagement.jsx';
import DataAnalysis from '../../components/layout/DataAnalysis.jsx';
import HelpSupport from '../../components/layout/HelpSupport';
import SecurityOverviewPage from '../../components/layout/SecurityOverviewPage.jsx';
import EventDetails from './EventDetails.js';
import ActivityLog from './Activity Log.js';
import Settings from '../../components/layout/Settings';
import '../../styles/dashboard.css';
import { fetchDashboardData, storeUserData } from '../../services/api';
import { checkAndRefreshToken } from '../../services/auth';
import { CircularProgress } from '@mui/material';

const Dashboard = () => {
  const [darkMode, setDarkMode] = useState(false);
  const [dashboardData, setDashboardData] = useState(null);
  const [userData, setUserData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const toggleDarkMode = () => {
    setDarkMode(prevMode => !prevMode);
    document.body.classList.toggle('dark-mode', !darkMode);
  };

  useEffect(() => {
    document.body.classList.add('main-layout');

    return () => {
      document.body.classList.remove('main-layout');
    };
  }, []);

  useEffect(() => {
    const loadDashboardData = async () => {
      try {
        setLoading(true);
        
        // Check and refresh token if needed
        const tokenValid = await checkAndRefreshToken();
        if (!tokenValid) {
          navigate('/');
          return;
        }
        
        const data = await fetchDashboardData();
        console.log('Dashboard data received:', data);
        
        // Check if we got the expected nested structure
        if (data && data.dashboard) {
          console.log('Setting dashboard data from nested structure:', data.dashboard);
          setDashboardData(data.dashboard);
          
          // Extract user data from the nested structure and store it
          if (data.dashboard.user_data && data.dashboard.user_data.user_info) {
            const userData = data.dashboard.user_data.user_info;
            console.log('Setting user data from nested structure:', userData);
            setUserData(userData);
            storeUserData(userData);
          }
        } else {
          // Fallback for a flat data structure
          console.log('Setting dashboard data from flat structure:', data);
          setDashboardData(data);
          
          if (data.user_data && data.user_data.user_info) {
            const userData = data.user_data.user_info;
            console.log('Setting user data from flat structure:', userData);
            setUserData(userData);
            storeUserData(userData);
          } else {
            // Last resort: use stored data
            try {
              const storedUserData = JSON.parse(localStorage.getItem('user_data'));
              if (storedUserData) {
                console.log('Using stored user data:', storedUserData);
                setUserData(storedUserData);
              }
            } catch (error) {
              console.error('Error parsing stored user data:', error);
            }
          }
        }
        
        setLoading(false);
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
        setError('Failed to load dashboard data. Please try again.');
        setLoading(false);
        
        // If unauthorized, redirect to login
        if (error.response && error.response.status === 401) {
          navigate('/');
        }
      }
    };

    loadDashboardData();
  }, [navigate]);

  if (loading) {
    return (
      <div className="loading-container">
        <CircularProgress />
        <p>Loading dashboard...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error-container">
        <h3>Error</h3>
        <p>{error}</p>
        <button onClick={() => window.location.reload()}>Retry</button>
      </div>
    );
  }

  return (
    <div className={darkMode ? 'dark-mode' : ''}>
      <Navbar 
        notifications={userData?.notifications || []} 
        name={userData?.name} 
        role={userData?.role} 
        profileImage={userData?.profile_image} 
      />
      <Sidebar toggleDarkMode={toggleDarkMode} />
      <div className="content">
        <Routes>
          <Route path="/" element={<MainContainerdash dashboardData={dashboardData} />} />
          <Route path="reports" element={<Report />} />
          <Route path="user_management" element={<UserManagement />} />
          <Route path="data_analysis" element={<DataAnalysis />} />
          <Route path="help_support" element={<HelpSupport />} />
          <Route path="event_details" element={<EventDetails />} />
          <Route path="activity_log" element={<ActivityLog />} />
          <Route path="settings" element={<Settings />} />
        </Routes>
      </div>
    </div>
  );
};

export default Dashboard;