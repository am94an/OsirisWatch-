// MainRouter.js
import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import LoginPage from './pages/Login/LoginPage';
import SignupPage from './pages/Signup/SignupPage';
import ForgetPasswordPage from './pages/password/ForgetPasswordPage';
import ResetPasswordPage from './pages/password/ResetPasswordPage';
import Dashboard from './pages/Dashboard/Dashboard';
import ProtectedRoute from './components/specific/ProtectedRoute';
import Login from './pages/Login/Login';
import { isAuthenticated } from './services/auth';

const MainRouter = ({ setMessage, setMessageType }) => {
  return (
    <Routes>
      {/* Public Routes */}
      <Route path="/" element={isAuthenticated() ? <Navigate to="/dashboard" /> : <Login />} />
      <Route path="/login" element={isAuthenticated() ? <Navigate to="/dashboard" /> : <LoginPage setMessage={setMessage} setMessageType={setMessageType} />} />
      <Route path="/signup" element={isAuthenticated() ? <Navigate to="/dashboard" /> : <SignupPage setMessage={setMessage} setMessageType={setMessageType} />} />
      <Route path="/forget_password" element={isAuthenticated() ? <Navigate to="/dashboard" /> : <ForgetPasswordPage setMessage={setMessage} setMessageType={setMessageType} />} />
      <Route path="/api/reset_password/:uidb64/:token" element={isAuthenticated() ? <Navigate to="/dashboard" /> : <ResetPasswordPage setMessage={setMessage} setMessageType={setMessageType} />} />
      
      {/* Protected Routes */}
      <Route path="/dashboard/*" element={<ProtectedRoute element={<Dashboard setMessage={setMessage} setMessageType={setMessageType} />} />} />
      
      {/* Catch all route - redirect to dashboard if authenticated, otherwise to login */}
      <Route path="*" element={isAuthenticated() ? <Navigate to="/dashboard" /> : <Navigate to="/login" />} />
    </Routes>
  );
};

export default MainRouter;