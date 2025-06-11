import React from 'react';

const SignupPage = ({ switchPage, setEmail, setUsername, setPassword, setConfirmPassword, handleSignup }) => (
    <div className="auth-container">
            <h2 className="auth-title">Create an Account</h2>
            <p className="auth-subtitle">Please enter your email, username, and password to sign up</p>

            <label className="auth-label" htmlFor="email">Email address:</label>
            <input
                type="email"
                id="email"
                className="auth-input"
                placeholder="Enter your email"
                onChange={(e) => setEmail(e.target.value)}
            />

            <label className="auth-label" htmlFor="username">Username:</label>
            <input
                type="text"
                id="username"
                className="auth-input"
                placeholder="Enter your username"
                onChange={(e) => setUsername(e.target.value)}
            />

            <label className="auth-label" htmlFor="password">Password:</label>
            <input
                type="password"
                id="password"
                className="auth-input"
                placeholder="Enter your password"
                onChange={(e) => setPassword(e.target.value)}
            />

            <label className="auth-label" htmlFor="confirm-password">Confirm Password:</label>
            <input
                type="password"
                id="confirm-password"
                className="auth-input"
                placeholder="Confirm your password"
                onChange={(e) => setConfirmPassword(e.target.value)}
            />

            <button className="auth-button" onClick={handleSignup}>Sign Up</button>


            <p className="auth-text">
                Already have an account? <span className="auth-link" onClick={() => switchPage('login')}>Login</span>
            </p>
        </div>
);

export default SignupPage;
