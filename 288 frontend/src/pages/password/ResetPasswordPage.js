import React, { useState, useEffect } from 'react';
import { changePassword } from '../../services/api';
import { useParams, useNavigate } from 'react-router-dom';
import BackgroundSVGs from '../../components/specific/BackgroundSVGs';
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import '../../styles/App.css';

const ResetPasswordPage = ({ handleChangePassword }) => {
    const { uidb64, token } = useParams();
    const navigate = useNavigate();
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [message, setMessage] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    useEffect(() => {
        document.body.classList.add('auth-layout');
        return () => {
            document.body.classList.remove('auth-layout');
        };
    }, []);

    useEffect(() => {
        if (message) {
            toast(message);
        }
    }, [message]);

    const isValidPassword = (password) => password.length >= 8;

    const handleChangePasswordInternal = async () => {
        if (!isValidPassword(newPassword)) {
            setMessage('Password must be at least 8 characters long.');
            return;
        }
        if (newPassword !== confirmPassword) {
            setMessage('Passwords do not match.');
            return;
        }
        setIsLoading(true);
        try {
            console.log('Sending data:', { uidb64, token, newPassword });
            const data = await changePassword(uidb64, token, newPassword);
            if (data.success) {
                setMessage('Password changed successfully!');
                navigate('/login');
            } else {
                setMessage(data.message || 'Failed to change password.');
            }
        } catch (error) {
            setMessage('An error occurred. Please try again.');
        } finally {
            setIsLoading(false);
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
                <div className="auth-container">
                    <h2 className="auth-title">Change Your Password</h2>
                    <p className="auth-subtitle">Please enter your new password</p>
                    <label className="auth-label" htmlFor="new-password">New Password:</label>
                    <input
                        type="password"
                        id="new-password"
                        className="auth-input"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        placeholder="Enter new password"
                        required
                    />
                    <label className="auth-label" htmlFor="confirm-password">Confirm Password:</label>
                    <input
                        type="password"
                        id="confirm-password"
                        className="auth-input"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Confirm new password"
                        required
                    />
                    <button className="auth-button" onClick={handleChangePasswordInternal} disabled={isLoading}>
                        {isLoading ? 'Changing...' : 'Change Password'}
                    </button>
                    <button className="auth-button" style={{ marginTop: '10px' }} onClick={() => navigate('/')}>Go to Login</button>
                </div>
            </div>
        </div>
    );
};

export default ResetPasswordPage;
