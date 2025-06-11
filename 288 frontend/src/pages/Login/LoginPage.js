import React from 'react';
import '../../styles/dashboard.css';

const LoginPage = ({ switchPage, setUsername, setPassword, handleLogin }) => (
    <div className="auth-container">
        <h2 className="auth-title">Login to Account</h2>
        <p className="auth-subtitle">Please enter your email and password to continue</p>

        <label className="auth-label" htmlFor="username">Email address:</label>
        <input
            type="text"
            id="username"
            className="auth-input"
            placeholder="Enter your email"
            onChange={(e) => setUsername(e.target.value)}
        />

        <div className="password-container">
            <label className="auth-label" htmlFor="password">Password:</label>
            <span className="forgot-password" onClick={() => switchPage('forget')}>Forget Password?</span>
        </div>
        <input
            type="password"
            id="password"
            className="auth-input"
            placeholder="Enter your password"
            onChange={(e) => setPassword(e.target.value)}
        />

        <div className="remember-container">
            <input type="checkbox" id="remember" />
            <label htmlFor="remember" className="remember-label">Remember Password</label>
        </div>

        <button className="auth-button" onClick={handleLogin}>Sign In</button>

        <p className="auth-text">
            Don't have an account? <span className="auth-link" onClick={() => switchPage('signup')}>Create Account</span>
        </p>
    </div>
);

export default LoginPage;
