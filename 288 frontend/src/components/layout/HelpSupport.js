import React, { useState, useEffect } from "react";
import { Key, WifiOff, User, Server, CreditCard, Tag, Shield, Clock, Settings, HelpCircle, Globe, Mail } from "lucide-react"; // Added more icons
import "../../styles/HelpSupport.css"; // Updated import path
import { fetchHelpSupport } from "../../services/api";
import { CircularProgress } from "@mui/material";

export default function HelpSupport() {
  const [helpData, setHelpData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [darkMode, setDarkMode] = useState(false);
  const [showMoreFaqs, setShowMoreFaqs] = useState(false);

  // Check for dark mode in localStorage
  useEffect(() => {
    const isDarkMode = localStorage.getItem('darkMode') === 'true';
    setDarkMode(isDarkMode);
    
    // Listen for dark mode changes
    const handleDarkModeChange = (e) => {
      // If this is a storage event with a key, check that it's darkMode
      if (e.type === 'storage' && e.key && e.key !== 'darkMode') {
        return;
      }
      
      // Get current dark mode setting
      const currentDarkMode = localStorage.getItem('darkMode') === 'true';
      setDarkMode(currentDarkMode);
    };
    
    // Listen for storage events (from other tabs) and local events
    window.addEventListener('storage', handleDarkModeChange);
    window.addEventListener('storage-local', handleDarkModeChange);
    
    return () => {
      window.removeEventListener('storage', handleDarkModeChange);
      window.removeEventListener('storage-local', handleDarkModeChange);
    };
  }, []);

  useEffect(() => {
    const loadHelpData = async () => {
      try {
        setLoading(true);
        const response = await fetchHelpSupport();
        setHelpData(response.help);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching help content:", error);
        setError("Failed to load help information. Please try again.");
        setLoading(false);
      }
    };

    loadHelpData();
  }, []);

  const darkModeStyles = {
    container: {
      backgroundColor: darkMode ? '#1E293B' : '#f7f9fc',
      color: darkMode ? '#e0e0e0' : 'inherit'
    },
    header: {
      color: darkMode ? '#e0e0e0' : 'inherit'
    },
    search: {
      backgroundColor: darkMode ? '#273142' : '#fff',
      color: darkMode ? '#e0e0e0' : 'inherit',
      border: darkMode ? '1px solid #3A4557' : '1px solid #ddd'
    },
    card: {
      backgroundColor: darkMode ? '#273142' : '#fff',
      color: darkMode ? '#e0e0e0' : 'inherit',
      boxShadow: darkMode ? '0 4px 6px rgba(0, 0, 0, 0.3)' : '0 1px 3px rgba(0, 0, 0, 0.1)'
    },
    contactBox: {
      backgroundColor: darkMode ? '#334155' : '#f0f5ff'
    },
    button: {
      backgroundColor: darkMode ? '#3B82F6' : '#4299E1',
      color: '#fff'
    },
    moreButton: {
      backgroundColor: darkMode ? '#3B82F6' : '#4299E1',
      color: '#fff',
      padding: '12px 24px',
      borderRadius: '4px',
      cursor: 'pointer',
      margin: '30px auto',
      display: 'block',
      fontSize: '16px',
      fontWeight: 'bold',
      border: 'none',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.2)'
    }
  };

  const Card = ({ children, className }) => (
    <div className={`faq-card ${className}`} style={darkModeStyles.card}>
      {children}
    </div>
  );

  const Input = ({ placeholder, className, ...props }) => (
    <input
      type="text"
      placeholder={placeholder}
      className={`faq-search ${className}`}
      style={darkModeStyles.search}
      {...props}
    />
  );

  const Button = ({ children, className, onClick }) => (
    <button
      onClick={onClick}
      className={`contact-box button ${className}`}
      style={darkModeStyles.button}
    >
      {children}
    </button>
  );

  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };

  const toggleMoreFaqs = () => {
    setShowMoreFaqs(!showMoreFaqs);
  };

  // Default FAQ items with icons
  const defaultFAQs = [
    {
      icon: <Key color={darkMode ? "#4299E1" : "#3B82F6"} />,
      title: "How do I reset my IDS Network password?",
      content:
        "You can reset your password by clicking on the 'Forgot Password' link on the login page and following the instructions.",
    },
    {
      icon: <WifiOff />,
      title: "What should I do if I encounter a network error?",
      content:
        "If you encounter a network error, please check your internet connection and try again. If the problem persists, contact our support team.",
    },
    {
      icon: <User />,
      title: "How can I update my profile information?",
      content:
        "You can update your profile information by logging into your account and navigating to the 'Profile' section.",
    },
    {
      icon: <Server />,
      title: "How do I check the status of my IDS Network services?",
      content:
        "You can check the status of your services by logging into your account and navigating to the 'Services' section.",
    },
    {
      icon: <CreditCard />,
      title: "What is the refund policy for IDS Network services?",
      content:
        "Our refund policy allows you to request a refund within 30 days of purchase if you are not satisfied with our services.",
    },
    {
      icon: <Tag />,
      title: "How do I apply a discount code to my IDS Network subscription?",
      content:
        "You can apply a discount code during the checkout process. Enter the code in the 'Discount Code' field and click 'Apply'.",
    },
  ];

  // Additional FAQs with more icons
  const additionalFAQs = [
    {
      icon: <Shield color={darkMode ? "#4299E1" : "#3B82F6"} />,
      title: "How secure is my data on IDS Network?",
      content:
        "We use industry-standard encryption and security practices to protect your data. All transmissions are secured using SSL/TLS encryption and we regularly perform security audits.",
    },
    {
      icon: <Clock />,
      title: "What are the support hours for IDS Network?",
      content:
        "Our support team is available 24/7 to assist you with any issues or questions you may have about our services.",
    },
    {
      icon: <Settings />,
      title: "How do I configure advanced settings for my account?",
      content:
        "Advanced settings can be configured in the 'Settings' section of your account dashboard. Look for the 'Advanced' tab to access these options.",
    },
    {
      icon: <HelpCircle />,
      title: "Can I get personalized assistance for my specific needs?",
      content:
        "Yes, you can schedule a one-on-one consultation with our technical team by contacting support and requesting a personalized assistance session.",
    },
    {
      icon: <Globe />,
      title: "Are IDS Network services available internationally?",
      content:
        "Yes, our services are available worldwide. However, some features may vary depending on your location due to regional regulations.",
    },
    {
      icon: <Mail />,
      title: "How do I subscribe to the IDS Network newsletter?",
      content:
        "You can subscribe to our newsletter by entering your email address in the subscription box at the bottom of our homepage or in your account settings.",
    },
  ];

  // Use API data if available, otherwise use default data
  const getDisplayFAQs = () => {
    if (helpData && helpData.faqs && helpData.faqs.length > 0) {
      // Map API data to the format needed for display
      const allIcons = [<Key />, <WifiOff />, <User />, <Server />, <CreditCard />, <Tag />, 
                        <Shield />, <Clock />, <Settings />, <HelpCircle />, <Globe />, <Mail />];
      
      return helpData.faqs.map((faq, index) => {
        return {
          icon: allIcons[index % allIcons.length],
          title: faq.question,
          content: faq.answer,
        };
      });
    }
    
    // If no API data, use the combined default and additional FAQs
    return [...defaultFAQs, ...additionalFAQs];
  };

  // Get all FAQs
  const allFAQs = getDisplayFAQs();
  
  // Filter FAQs based on search query
  const filteredFAQs = allFAQs.filter(
    (faq) =>
      faq.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      faq.content.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Determine which FAQs to display based on showMoreFaqs state and search query
  const displayFAQs = searchQuery 
    ? filteredFAQs 
    : showMoreFaqs 
      ? allFAQs 
      : allFAQs.slice(0, 6);  // Show only first 6 FAQs initially when not searching

  if (loading) {
    return (
      <div className="loading-container">
        <CircularProgress />
        <p>Loading help content...</p>
      </div>
    );
  }

  return (
    <div className="faq-container">
      {/* Header Section */}
      <div className="faq-header">
        <p className="faq-tag">FAQs</p>
        <h1>Ask us anything</h1>
        <p>Have any questions? We're here to assist you.</p>
        <div className="faq-search">
                <i className="fa fa-search"></i>
          <input 
            type="text" 
            placeholder="Search" 
            value={searchQuery}
            onChange={handleSearchChange}
          />
            </div>
      </div>

      {/* FAQ Cards Section */}
      <div className="faq-grid">
        {displayFAQs.map((faq, index) => (
          <Card key={index}>
            {faq.icon}
            <h3>{faq.title}</h3>
            <p>{faq.content}</p>
        </Card>
        ))}
        
        {filteredFAQs.length === 0 && (
          <div className="no-results">
            <p>No FAQs matching your search query. Try a different search term.</p>
          </div>
        )}
      </div>

      {/* Show More Button - always visible when not searching */}
      {!searchQuery && (
        <div className="more-button-container" style={{ textAlign: 'center', marginTop: '30px' }}>
          <button
            onClick={toggleMoreFaqs}
            style={darkModeStyles.moreButton}
          >
            {showMoreFaqs ? "Show Less" : "Show More FAQs"}
          </button>
        </div>
      )}

      {/* Footer Section */}
      <div className="contact-box">
        <div className="contact-text">
          <p>Still have questions?</p>
          <p>Can't find the answer you're looking for? Please chat to our friendly team.</p>
        </div>
        <Button>Get in touch</Button>
      </div>
    </div>
  );
}




