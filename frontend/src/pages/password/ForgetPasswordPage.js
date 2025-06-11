import React, { useState, useEffect } from 'react';
import { resetPassword } from '../../services/api';
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const ForgetPasswordPage = ({ switchPage }) => {
    const [email, setEmail] = useState('');
    const [message, setMessage] = useState('');

    const handleResetPassword = async () => {
        try {
            const data = await resetPassword(email);
            if (data.success) {
                setMessage('Password reset link sent to your email!');
            } else {
                setMessage(data.message || 'Password reset failed.');
            }
        } catch (error) {
            setMessage('An error occurred. Please try again.');
        }
    };

    useEffect(() => {
        if (message) {
            toast(message);
        }
    }, [message]);

    return (
        <div className="reset-container">
            <h2 className="auth-title">Reset Your Password</h2>
            <p className="auth-subtitle">Please enter your email to continue</p>
            <label className="auth-label">Email address:</label>
            <input
                type="email"
                className="auth-input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your email"
                required
            />
            <button className="auth-button" onClick={handleResetPassword}>Reset Now</button>
            <p className="auth-footer" style={{ marginTop: '30px', width: '100%', fontSize: 'medium' }}>
                Don't have an account? <span onClick={() => switchPage('signup')} className="auth-link">Create Account</span>
            </p>
        </div>
    );
};

export default ForgetPasswordPage;
