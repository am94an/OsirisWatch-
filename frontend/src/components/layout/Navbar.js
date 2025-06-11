import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { usePopper } from 'react-popper';
import '../../styles/navbar.css';
import { fetchNotifications, markNotificationAsRead, markAllNotificationsAsRead, connectNotificationSocket, disconnectNotificationSocket } from '../../services/api';
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { logoutUser } from '../../services/auth';

const Navbar = ({ userData }) => {
  const navigate = useNavigate();
  // State for dropdowns and notifications
  const [showProfileDropdown, setShowProfileDropdown] = useState(false);
  const [showNotificationDropdown, setShowNotificationDropdown] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [user, setUser] = useState(userData || {});
  const [isLoading, setIsLoading] = useState(false);
  const [showNotificationCenter, setShowNotificationCenter] = useState(false);
  const [loading, setLoading] = useState(true);
  
  // Refs for click outside detection
  const profileRef = useRef(null);
  const notificationRef = useRef(null);
  
  // Refs for popper
  const [profileReferenceElement, setProfileReferenceElement] = useState(null);
  const [profilePopperElement, setProfilePopperElement] = useState(null);
  const [notificationReferenceElement, setNotificationReferenceElement] = useState(null);
  const [notificationPopperElement, setNotificationPopperElement] = useState(null);
  
  // Detect if on mobile
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 480);
  
  // Popper instances with improved configuration
  const { styles: profileStyles, attributes: profileAttributes } = usePopper(
    profileReferenceElement, 
    profilePopperElement,
    {
      placement: isMobile ? 'bottom' : 'bottom-end',
      modifiers: [
        { name: 'offset', options: { offset: [0, 10] } },
        { name: 'preventOverflow', options: { padding: 20, boundary: 'viewport' } },
        { name: 'arrow', options: { element: '.arrow', padding: 5 } },
        { name: 'computeStyles', options: { gpuAcceleration: true, adaptive: true } },
        { name: 'flip', options: { fallbackPlacements: ['top-end', 'bottom-start'] } }
      ],
      strategy: 'fixed'
    }
  );
  
  const { styles: notificationStyles, attributes: notificationAttributes } = usePopper(
    notificationReferenceElement, 
    notificationPopperElement,
    {
      placement: isMobile ? 'bottom' : 'bottom-end',
      modifiers: [
        { name: 'offset', options: { offset: [0, 10] } },
        { name: 'preventOverflow', options: { padding: 20, boundary: 'viewport' } },
        { name: 'arrow', options: { element: '.arrow', padding: 5 } },
        { name: 'computeStyles', options: { gpuAcceleration: true, adaptive: true } },
        { name: 'flip', options: { fallbackPlacements: ['top-end', 'bottom-start'] } }
      ],
      strategy: 'fixed'
    }
  );

  // Load user data from localStorage if not provided as props
  useEffect(() => {
    if (!userData) {
      const storedUser = JSON.parse(localStorage.getItem('user_data'));
      if (storedUser) {
        setUser(storedUser);
      }
    }
  }, [userData]);

  // Handle window resize
  useEffect(() => {
    const handleResize = () => {
      const mobile = window.innerWidth <= 480;
      setIsMobile(mobile);
      // Close dropdowns when resizing
      setShowProfileDropdown(false);
      setShowNotificationDropdown(false);
    };
    
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const loadNotifications = async () => {
    try {
      console.log('Loading notifications in Navbar...');
      setLoading(true);
      const data = await fetchNotifications();
      console.log('Loaded notifications in Navbar:', data);
      setNotifications(data);
      setUnreadCount(data.filter(n => !n.read).length);
    } catch (error) {
      console.error('Error loading notifications in Navbar:', error);
      toast.error('Failed to load notifications');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadNotifications();
    
    // Connect to WebSocket for real-time notifications
    const socket = connectNotificationSocket((notification) => {
      console.log('Received new notification:', notification);
      setNotifications(prev => [notification, ...prev]);
      setUnreadCount(prev => prev + 1);
      showNotificationToast(notification);
    });

    // Set up polling as backup
    const intervalId = setInterval(loadNotifications, 120000); // 2 minutes

    return () => {
      disconnectNotificationSocket();
      clearInterval(intervalId);
    };
  }, []);

  const showNotificationToast = (notification) => {
    const severity = notification.priority === 'high' ? 'error' : 
                    notification.priority === 'medium' ? 'warning' : 'info';
    
    toast[severity](notification.message, {
      position: "top-right",
      autoClose: 5000,
      hideProgressBar: false,
      closeOnClick: true,
      pauseOnHover: true,
      draggable: true,
    });
  };

  const handleNotificationClick = async (notificationId) => {
    try {
      await markNotificationAsRead(notificationId);
      setNotifications(prevNotifications =>
        prevNotifications.map(notification =>
          notification.id === notificationId
            ? { ...notification, read: true }
            : notification
        )
      );
      setUnreadCount(prev => Math.max(0, prev - 1));
    } catch (error) {
      console.error('Error marking notification as read:', error);
      toast.error('Failed to mark notification as read');
    }
  };

  // Handle click outside to close dropdowns - memoized to prevent unnecessary re-renders
  const handleClickOutside = useCallback((event) => {
    if (profileRef.current && !profileRef.current.contains(event.target) && 
        profilePopperElement && !profilePopperElement.contains(event.target)) {
      setShowProfileDropdown(false);
    }
    
    if (notificationRef.current && !notificationRef.current.contains(event.target) && 
        notificationPopperElement && !notificationPopperElement.contains(event.target)) {
      setShowNotificationDropdown(false);
    }
  }, [profilePopperElement, notificationPopperElement]);

  // Close dropdowns on escape key press - memoized to prevent unnecessary re-renders
  const handleEscKey = useCallback((event) => {
    if (event.key === 'Escape') {
      setShowProfileDropdown(false);
      setShowNotificationDropdown(false);
    }
  }, []);

  // Set up event listeners
  useEffect(() => {
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleEscKey);
    
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscKey);
    };
  }, [handleClickOutside, handleEscKey]);

  // Toggle profile dropdown
  const toggleProfileDropdown = (e) => {
    e.stopPropagation();
    setShowProfileDropdown(prev => !prev);
    if (showNotificationDropdown) setShowNotificationDropdown(false);
  };

  // Toggle notification dropdown
  const toggleNotificationDropdown = (e) => {
    e.stopPropagation();
    setShowNotificationDropdown(prev => !prev);
    if (showProfileDropdown) setShowProfileDropdown(false);
    
    // If opening the notification dropdown, refresh notifications
    if (!showNotificationDropdown) {
      loadNotifications();
    }
  };

  // Handle marking all notifications as read
  const handleMarkAllAsRead = async (e) => {
    e.stopPropagation(); // Prevent event from bubbling
    e.preventDefault();
    
    try {
      await markAllNotificationsAsRead();
      // Update all notifications in the state
      setNotifications(prevNotifications => 
        prevNotifications.map(n => ({ ...n, read: true }))
      );
      setUnreadCount(0);
    } catch (error) {
      console.error('Error marking all notifications as read:', error);
    }
  };

  // Format notification date
  const formatNotificationDate = (dateString) => {
    if (!dateString) return '';
    
    try {
      const date = new Date(dateString);
      const now = new Date();
      const diffInSeconds = Math.floor((now - date) / 1000);
      
      if (diffInSeconds < 60) {
        return 'Just now';
      } else if (diffInSeconds < 3600) {
        const minutes = Math.floor(diffInSeconds / 60);
        return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'} ago`;
      } else if (diffInSeconds < 86400) {
        const hours = Math.floor(diffInSeconds / 3600);
        return `${hours} ${hours === 1 ? 'hour' : 'hours'} ago`;
      } else if (diffInSeconds < 604800) {
        const days = Math.floor(diffInSeconds / 86400);
        return `${days} ${days === 1 ? 'day' : 'days'} ago`;
      } else {
        return date.toLocaleDateString(undefined, { 
          year: 'numeric', 
          month: 'short', 
          day: 'numeric' 
        });
      }
    } catch (error) {
      console.error('Error formatting date:', error, dateString);
      return '';
    }
  };

  const handleLogout = () => {
    setShowProfileDropdown(false);
    logoutUser();
    navigate('/login');
  };

  return (
    <nav className="navbar">
      <div className="search-box">
        <i className="fas fa-search" aria-hidden="true"></i>
        <input type="text" placeholder="Search..." aria-label="Search" />
      </div>
      
      <div className="nav-right">
        {/* Notification icon and dropdown */}
        <div 
          className="notification" 
          ref={el => {
            notificationRef.current = el;
            setNotificationReferenceElement(el);
          }}
          onClick={toggleNotificationDropdown}
          aria-expanded={showNotificationDropdown}
          aria-haspopup="true"
          role="button"
          tabIndex={0}
        >
          <i className="fas fa-bell" aria-hidden="true"></i>
          {unreadCount > 0 && (
            <div className="badge" aria-label={`${unreadCount} unread notifications`}>
              {unreadCount > 99 ? '99+' : unreadCount}
            </div>
          )}
        </div>
        
        {/* Notification dropdown */}
        <div
          ref={setNotificationPopperElement}
          className={`dropdown-content ${showNotificationDropdown ? 'show' : ''}`}
          style={{
            ...notificationStyles.popper,
            zIndex: 1000,
            width: isMobile ? 'calc(100vw - 30px)' : undefined,
            maxWidth: '400px',
            right: 0
          }}
          {...notificationAttributes.popper}
          role="menu"
          aria-hidden={!showNotificationDropdown}
        >
          <div className="notification-header">
            <h3>Notifications</h3>
            {unreadCount > 0 && (
              <button 
                className="mark-all-read" 
                onClick={handleMarkAllAsRead}
                aria-label="Mark all notifications as read"
              >
                Mark all as read
              </button>
            )}
          </div>
          
          <div className="notification-list">
            {loading ? (
              <div className="notification-item" role="status">
                <p>Loading notifications...</p>
              </div>
            ) : notifications.length > 0 ? (
              notifications.map(notification => (
                <div
                  key={notification.id}
                  className={`notification-item ${!notification.read ? 'unread' : ''}`}
                  onClick={(e) => handleNotificationClick(notification.id)}
                  role="menuitem"
                  tabIndex={0}
                >
                  {notification.icon && (
                    <i className={`fas fa-${notification.icon}`} aria-hidden="true"></i>
                  )}
                  <div>
                    <p>{notification.message}</p>
                    <small>{formatNotificationDate(notification.createdAt)}</small>
                  </div>
                </div>
              ))
            ) : (
              <div className="notification-item" role="status">
                <p>No notifications yet</p>
              </div>
            )}
          </div>
        </div>
        
        {/* User profile and dropdown */}
        <div 
          className="profile" 
          ref={el => {
            profileRef.current = el;
            setProfileReferenceElement(el);
          }}
          onClick={toggleProfileDropdown}
          aria-expanded={showProfileDropdown}
          aria-haspopup="true"
          role="button"
          tabIndex={0}
        >
          <img 
            src={user.profile_image ? `http://localhost:8000${user.profile_image}` : "https://via.placeholder.com/40"} 
            alt={`${user.name || user.username || "User"}'s profile`}
          />
          <div className="profile-user">
            <span className="profile-name">{user.name || user.username || "User"}</span>
            <span className="role">{user.role || "User"}</span>
          </div>
          <i 
            className={`fas fa-chevron-${showProfileDropdown ? 'up' : 'down'}`} 
            style={{ transform: showProfileDropdown ? 'rotate(180deg)' : 'rotate(0)' }}
            aria-hidden="true"
          ></i>
        </div>
        
        {/* Profile dropdown */}
        <div
          ref={setProfilePopperElement}
          className={`dropdown-content ${showProfileDropdown ? 'show' : ''}`}
          style={{
            ...profileStyles.popper,
            zIndex: 1000,
            width: isMobile ? 'calc(100vw - 30px)' : undefined,
            maxWidth: '250px',
            right: 0
          }}
          {...profileAttributes.popper}
          role="menu"
          aria-hidden={!showProfileDropdown}
        >
          <Link to="/dashboard/profile" role="menuitem" tabIndex={showProfileDropdown ? 0 : -1} onClick={() => setShowProfileDropdown(false)}>
            <i className="fas fa-user" aria-hidden="true"></i> My Profile
          </Link>
          <Link to="/dashboard/settings" role="menuitem" tabIndex={showProfileDropdown ? 0 : -1} onClick={() => setShowProfileDropdown(false)}>
            <i className="fas fa-cog" aria-hidden="true"></i> Account Settings
          </Link>
          <Link to="/dashboard/help_support" role="menuitem" tabIndex={showProfileDropdown ? 0 : -1} onClick={() => setShowProfileDropdown(false)}>
            <i className="fas fa-question-circle" aria-hidden="true"></i> Help & Support
          </Link>
          <Link 
            to="#" 
            role="menuitem" 
            tabIndex={showProfileDropdown ? 0 : -1}
            onClick={(e) => {
              e.preventDefault();
              handleLogout();
            }}
            className="dropdown-link"
          >
            <i className="fas fa-sign-out-alt" aria-hidden="true"></i> Logout
          </Link>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;