import React, { useEffect } from 'react';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { Bounce } from 'react-toastify';
import '../../styles/App.css';

const MessageComponent = ({ message, messageType }) => {
    useEffect(() => {
        if (message) {
            const toastOptions = {
                position: "top-right",
                autoClose: 5000,
                hideProgressBar: false,
                closeOnClick: true,
                pauseOnHover: true,
                draggable: true,
                progress: undefined,
                theme: "light",
                transition: Bounce,
                className: `toast ${messageType}`,
            };

            if (messageType === 'success') {
                toast.success(message, toastOptions);
            } else if (messageType === 'error') {
                toast.error(message, toastOptions);
            } else {
                toast.info(message, toastOptions);
            }
        }
    }, [message, messageType]);

    // Use a fixed configuration for ToastContainer to prevent undefined properties
    return (
        <ToastContainer
            position="top-right"
            autoClose={5000}
            hideProgressBar={false}
            newestOnTop
            closeOnClick
            rtl={false}
            pauseOnFocusLoss
            draggable
            pauseOnHover
            theme="light"
            transition={Bounce}
        />
    );
};

export default MessageComponent;
