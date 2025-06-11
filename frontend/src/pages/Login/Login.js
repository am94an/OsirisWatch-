import React, { useState, useEffect } from 'react';
import '../../styles/App.css';
import LoginPage from './LoginPage'; 
import SignupPage from '../Signup/SignupPage'; 
import ForgetPasswordPage from '../password/ForgetPasswordPage'; 
import ResetPasswordPage from '../password/ResetPasswordPage'; 
import BackgroundSVGs from '../../components/specific/BackgroundSVGs'; 
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { handleLogin, handleSignup, handleResetPassword, handleChangePassword } from '../../utils/authUtils'; 
import { useNavigate, useParams } from 'react-router-dom';

const Login = () => {
  const [pageType, setPageType] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [username, setUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [message, setMessage] = useState('');
  const [uidb64, setUidb64] = useState('');
  const [token, setToken] = useState('');
  const [messageType, setMessageType] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const navigate = useNavigate();
  const params = useParams();

  useEffect(() => {
    document.body.classList.add('auth-layout');
    return () => {
      document.body.classList.remove('auth-layout');
    };
  }, []);

  useEffect(() => {
    if (params.uidb64 && params.token) {
      setUidb64(params.uidb64);
      setToken(params.token);
      setPageType('reset');
    }
  }, [params]);

  useEffect(() => {
    if (message) {
      toast(message, { type: messageType });
    }
  }, [message, messageType]);

  const renderPage = () => {
    switch (pageType) {
      case 'login':
        return (
          <LoginPage 
            switchPage={setPageType} 
            setUsername={setUsername} 
            setPassword={setPassword} 
            handleLogin={() => handleLogin(username, password, setMessage, setMessageType, navigate)} 
          />
        );
      case 'signup':
        return (
          <SignupPage 
            switchPage={setPageType} 
            setEmail={setEmail} 
            setUsername={setUsername} 
            setPassword={setPassword} 
            setConfirmPassword={setConfirmPassword} 
            handleSignup={() => handleSignup(email, username, password, confirmPassword, setMessage, setMessageType)} 
          />
        );
      case 'forget':
        return (
          <ForgetPasswordPage 
            switchPage={setPageType} 
            setEmail={setEmail} 
            handleResetPassword={() => handleResetPassword(email, setMessage)} 
          />
        );
      case 'reset':
        return (
          <ResetPasswordPage 
            handleChangePassword={() => handleChangePassword(uidb64, token, newPassword, setMessage)} 
          />
        );
      default:
        return (
          <LoginPage 
            switchPage={setPageType} 
            setUsername={setUsername} 
            setPassword={setPassword} 
            handleLogin={() => handleLogin(username, password, setMessage, setMessageType, navigate)} 
          />
        );
    }
  };

  return (
    <div className="auth-layout">
      <div className="background" style={{ position: 'fixed', top: 0, left: 0, width: '100%', height: '100%', overflow: 'hidden', pointerEvents: 'none' }}>
        <div style={{ position: 'relative' }}>
          <BackgroundSVGs />
        </div>
      </div>
      <div className="auth-page">
        {renderPage()}
      </div>
    </div>
  );
};

export default Login;