// Sidebar.js
import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import '../styles/sidebar.css';

const Sidebar = ({ toggleDarkMode }) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  
  useEffect(() => {
    const darkMode = localStorage.getItem('darkMode') === 'true';
    if (darkMode) {
      document.body.classList.add('dark-mode');
    }
    
    // Close sidebar when clicking outside on mobile
    const handleClickOutside = (event) => {
      const sidebar = document.querySelector('.sidebar');
      const toggle = document.querySelector('.sidebar-toggle');
      
      if (sidebar && toggle && 
          !sidebar.contains(event.target) && 
          !toggle.contains(event.target) && 
          window.innerWidth <= 768 && 
          isSidebarOpen) {
        setIsSidebarOpen(false);
      }
    };
    
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isSidebarOpen]);
  
  // Handle window resize to auto close sidebar
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth > 768) {
        setIsSidebarOpen(false);
      }
    };
    
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const handleToggleDarkMode = (e) => {
    const isDarkMode = e.target.checked;
    
    // Save to localStorage
    localStorage.setItem('darkMode', isDarkMode);
    
    // Trigger custom event for components in the same window
    window.dispatchEvent(new CustomEvent('storage-local'));
    
    // Call parent's toggleDarkMode if provided
    if (toggleDarkMode) {
      toggleDarkMode();
    }
  };
  
  const toggleSidebar = () => {
    setIsSidebarOpen(!isSidebarOpen);
  };

  return (
    <>
      {window.innerWidth <= 768 && (
        <div className="sidebar-toggle" onClick={toggleSidebar}>
          <i className={`fas ${isSidebarOpen ? 'fa-times' : 'fa-bars'}`}></i>
        </div>
      )}
      
      <div className={`sidebar ${isSidebarOpen ? 'open' : ''}`}>
        <div className="logo">
          <h2>
            <span>Osiris</span>Watch
          </h2>
        </div>
        <div className="menu">
          <NavLink
            to="/dashboard"
            end
            className={({ isActive }) => `menu-item-s ${isActive ? 'active' : ''}`}
            onClick={() => window.innerWidth <= 768 && setIsSidebarOpen(false)}
          >
            <i className="fas fa-tachometer-alt"></i> Dashboard
          </NavLink>
          <NavLink
            to="/dashboard/data_analysis"
            className={({ isActive }) => `menu-item-s ${isActive ? 'active' : ''}`}
            onClick={() => window.innerWidth <= 768 && setIsSidebarOpen(false)}
          >
            <i className="fas fa-chart-line"></i> Data Analysis
          </NavLink>
          <NavLink
            to="/dashboard/event_details"
            className={({ isActive }) => `menu-item-s ${isActive ? 'active' : ''}`}
            onClick={() => window.innerWidth <= 768 && setIsSidebarOpen(false)}
          >
            <i className="fas fa-calendar"></i> Event Details
          </NavLink>
          <div className="divider"></div>
          <NavLink
            to="/dashboard/reports"
            className={({ isActive }) => `menu-item-s ${isActive ? 'active' : ''}`}
            onClick={() => window.innerWidth <= 768 && setIsSidebarOpen(false)}
          >
            <i className="fas fa-file-alt"></i> Reports
          </NavLink>
          <NavLink
            to="/dashboard/help_support"
            className={({ isActive }) => `menu-item-s ${isActive ? 'active' : ''}`}
            onClick={() => window.innerWidth <= 768 && setIsSidebarOpen(false)}
          >
            <i className="fas fa-life-ring"></i> Help & Support
          </NavLink>
          <NavLink
            to="/dashboard/activity_log"
            className={({ isActive }) => `menu-item-s ${isActive ? 'active' : ''}`}
            onClick={() => window.innerWidth <= 768 && setIsSidebarOpen(false)}
          >
            <i className="fas fa-clipboard-list"></i> Activity Log
          </NavLink>

          <NavLink
            to="/dashboard/user_management"
            className={({ isActive }) => `menu-item-s ${isActive ? 'active' : ''}`}
            onClick={() => window.innerWidth <= 768 && setIsSidebarOpen(false)}
          >
            <i className="fas fa-users"></i> User Management
          </NavLink>
          <NavLink
            to="/dashboard/settings"
            className={({ isActive }) => `menu-item-s ${isActive ? 'active' : ''}`}
            onClick={() => window.innerWidth <= 768 && setIsSidebarOpen(false)}
          >
            <i className="fas fa-cog"></i> Settings
          </NavLink>
        </div>
        <div className="dark-mode-switch">
          <span>Dark mode</span>
          <div className="toggle-wrapper">
            <input
              type="checkbox"
              id="dark-mode-toggle"
              onChange={handleToggleDarkMode}
              defaultChecked={localStorage.getItem('darkMode') === 'true'}
            />
            <label htmlFor="dark-mode-toggle" className="toggle-label">
              <div className="toggle-circle"></div>
            </label>
          </div>
        </div>
      </div>
    </>
  );
};

export default Sidebar;
