import React from 'react';
import { Routes, Route } from 'react-router-dom';
import LoginPage from './LoginPage';
import SignupPage from './SignupPage';
import ForgetPasswordPage from './ForgetPasswordPage';
import ResetPasswordPage from './password/ResetPasswordPage';
import Login from './Login';

const PublicRoutes = ({ setMessage }) => {
  return (
    <Routes>
      <Route path="/" element={<Login />} />
      <Route path="/login" element={<LoginPage setMessage={setMessage} />} />
      <Route path="/signup" element={<SignupPage setMessage={setMessage} />} />
      <Route path="/forget_password" element={<ForgetPasswordPage setMessage={setMessage} />} />
      <Route path="/api/reset_password/:uidb64/:token" element={<ResetPasswordPage />} />
    </Routes>
  );
};

export default PublicRoutes;