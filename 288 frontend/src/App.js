import React, { useState } from 'react';
import './styles/App.css';
import BackgroundSVGs from './components/specific/BackgroundSVGs';
import MessageComponent from './components/common/MessageComponent';
import MainRouter from './MainRouter';
import { BrowserRouter as Router } from 'react-router-dom';
import '@fortawesome/fontawesome-free/css/all.min.css';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const App = () => {
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('info');

  return (
    <Router>
      <div className="App">
        <MainRouter setMessage={setMessage} setMessageType={setMessageType} />
        <MessageComponent message={message} messageType={messageType} />
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
        />
      </div>
    </Router>
  );
};

export default App;