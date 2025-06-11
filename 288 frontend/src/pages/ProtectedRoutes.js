import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Dashboard from './Dashboard';
import ProtectedRoute from '../components/ProtectedRoute';
import UserManagement from '../components/layout/UserManagement';
import HelpSupport from '../components/layout/HelpSupport';
import Profile from '../components/layout/Profile';
import Settings from '../components/layout/Settings';

const ProtectedRoutes = () => {
  return (
    <Routes>
      <Route path="/dashboard" element={<ProtectedRoute element={<Dashboard />} />} />
      <Route path="/dashboard/user_management" element={<ProtectedRoute element={<UserManagement />} />} />
      <Route path="/dashboard/help_support" element={<ProtectedRoute element={<HelpSupport />} />} />
      <Route path="/dashboard/profile" element={<ProtectedRoute element={<Profile />} />} />
      <Route path="/dashboard/settings" element={<ProtectedRoute element={<Settings />} />} />
    </Routes>
  );
};

export default ProtectedRoutes;