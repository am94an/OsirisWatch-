# 🛡️ OsirisWatch - Advanced Network Intrusion Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Django](https://img.shields.io/badge/Django-5.1-green.svg)
![React](https://img.shields.io/badge/React-18-blue.svg)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

</div>

## 📋 Overview

OsirisWatch is a sophisticated Intrusion Detection System (IDS) that provides real-time network traffic monitoring, threat detection, and security analytics. Built with modern technologies, it offers comprehensive network security monitoring capabilities for both small and large-scale networks.

## ✨ Key Features

- 🔍 **Real-time Network Monitoring**: Continuous analysis of network traffic patterns
- 🤖 **Advanced Threat Detection**: Machine learning-based anomaly detection
- 🏷️ **Attack Classification**: Automatic categorization of detected threats
- 🌐 **IP Reputation Analysis**: Integration with AbuseIPDB for threat intelligence
- ⚡ **Real-time Alerts**: Instant notification of security incidents
- 📊 **Comprehensive Dashboard**: Visual representation of network security status
- 📈 **Historical Analysis**: Detailed logs and reports of security events
- 🔌 **API Integration**: RESTful API for system integration and automation

## 🏗️ System Architecture

The system consists of three main components:

### 1. Backend (Django) 🐍
- Handles data processing and analysis
- Manages user authentication and authorization
- Provides RESTful API endpoints
- Implements machine learning models for threat detection

### 2. Frontend (React) ⚛️
- Interactive security dashboard
- Real-time network traffic visualization
- Threat alert management interface
- System configuration and monitoring

### 3. Collection Script 📡
- Network packet capture and analysis
- Traffic pattern extraction
- Real-time data streaming to backend

## 🚀 Getting Started

### Prerequisites

- 🐍 Python 3.8 or higher
- ⚛️ Node.js 16 or higher
- 🐘 PostgreSQL
- 📡 Wireshark (for network packet capture)
- 🔌 WinPcap (for Windows users)

### Project Setup

1. Create a virtual environment at the project root:
```bash
# Navigate to project root
cd /path/to/OsirisWatch-Project

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Unix or MacOS:
source venv/bin/activate
```

2. Install all Python dependencies:
```bash
# Install backend dependencies
pip install -r backend/requirements.txt

# Install collection script dependencies
pip install -r "collect script/requirements.txt"
```

## 🛠️ Installation Guide

### Backend Setup (Django)

1. Navigate to the backend directory:
```bash
cd backend
```

2. Set up the model files:
   - Navigate to `backend/predictions/saved_model/fit_params`
   - Extract all the zip files (fit_params.zip, fit_params.z01, fit_params.z02, fit_params.z03)
   - After extraction, you should get `fit_params.pkl`
   - Move `fit_params.pkl` to `backend/predictions/saved_model`
   - The final structure should look like:
     ```
     backend/predictions/saved_model/
     ├── fit_params.pkl
     ├── tabnet_clf_0.zip
     ├── tabnet_clf.zip
     ├── feature_names.json
     ├── label_encoder.pkl
     ├── label_mapping.json
     ├── scaler.joblib
     └── clf_params.pkl
     ```

3. Set up the database:
```bash
python manage.py migrate
```

4. Create a superuser (optional):
```bash
python manage.py createsuperuser
```

> **Note**: A default admin account is pre-configured with the following credentials:
> - Username: `osiris`
> - Password: `osiris`
> 
> It's recommended to change these credentials after first login for security purposes.

5. Run the development server:
```bash
python manage.py runserver
```

The backend will be available at `http://localhost:8000`

### Frontend Setup (React)

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm start
```

The frontend will be available at `http://localhost:3000`

### Collection Script Setup

1. Navigate to the collection script directory:
```bash
cd "collect script"
```

2. Run the script:
```bash
python main.py
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the backend directory with the following variables:

```env
# Django Core Settings
DEBUG=True
DJANGO_SECRET_KEY=your_secret_key_here

# Database Configuration
DB_NAME=your_database_name
DB_USER=your_database_user
DB_PASSWORD=your_database_password
DB_HOST=your_database_host
DB_PORT=5432

# Email Configuration
EMAIL_HOST_USER=your_email@gmail.com
EMAIL_HOST_PASSWORD=your_app_specific_password
DEFAULT_FROM_EMAIL=your_email@gmail.com

# Security Settings
ALLOWED_HOSTS=127.0.0.1,localhost
CSRF_TRUSTED_ORIGINS=http://127.0.0.1:8000,http://localhost:8000,http://localhost:3000

# AbuseIPDB API Key (for IP reputation checking)
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

### Important Settings Explanation

1. **Database Settings**:
   - If no database credentials are provided, the system will use SQLite as a fallback
   - For production, PostgreSQL is recommended

2. **Email Settings**:
   - Uses Gmail SMTP server
   - Requires an app-specific password for Gmail
   - Used for user registration and password reset

3. **Security Settings**:
   - `DEBUG`: Set to False in production
   - `ALLOWED_HOSTS`: List of allowed host names
   - `CSRF_TRUSTED_ORIGINS`: List of trusted origins for CSRF protection

4. **API Keys**:
   - `ABUSEIPDB_API_KEY`: Required for IP reputation checking
   - Get your API key from [AbuseIPDB](https://www.abuseipdb.com/)

## 🔧 Additional Requirements

### Wireshark Installation
1. Download and install Wireshark:
   - Direct download link: [Wireshark 4.4.3 (64-bit)](https://www.wireshark.org/download/win64/Wireshark-win64-4.4.3.exe)
   - Or visit: https://www.wireshark.org/download.html

2. For Windows users, install WinPcap:
   - Direct download link: [WinPcap 4.1.3](https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe)
   - Or visit: https://www.winpcap.org/install/

## 🚀 Running the System

1. Make sure you're in the project root directory and the virtual environment is activated
2. Start the backend server (from backend directory)
3. Start the frontend development server (from frontend directory)
4. Run the collection script (from collect script directory)

## 🔍 Troubleshooting

### Common Issues

1. Database Connection Issues:
   - Ensure PostgreSQL is running
   - Verify database credentials in settings.py

2. Frontend Connection Issues:
   - Check if the backend API URL is correctly configured
   - Ensure CORS settings are properly configured

3. Collection Script Issues:
   - Verify Wireshark and WinPcap are properly installed
   - Check network interface permissions

## 📚 Development vs Production

### Development Mode (DEBUG=True)
- CSRF and session security settings are relaxed
- Debug toolbar is enabled
- Detailed error pages are shown

### Production Mode (DEBUG=False)
- All security features are enabled
- SSL/HTTPS is required
- HSTS is enabled
- Detailed error pages are disabled

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
---

<div align="center">
Made with ❤️ for Network Security
</div>