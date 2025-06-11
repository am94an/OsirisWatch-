import React, { useState, useEffect } from "react";
import "../styles/reports.css";
import trash from "../assets/images/trash-01.png";
import download from "../assets/images/download-cloud-02.png";
import filter from "../assets/images/filter-lines.png";
import plus from "../assets/images/plus.png";
import { 
  fetchReports, 
  deleteReports, 
  exportReports, 
  addReport,
  updateReport
} from "../services/api";
import { CircularProgress, Fade, Zoom, Grow } from "@mui/material";

const Table = () => {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [darkMode, setDarkMode] = useState(false);
  const [isFiltersOpen, setIsFiltersOpen] = useState(false);
  const [activeFilters, setActiveFilters] = useState({});
  const [showAddModal, setShowAddModal] = useState(false);
  const [newReport, setNewReport] = useState({
    threatType: "",
    targetDevice: "",
    threatStatus: "Detected",
    attackSource: "",
    severityLevel: "Medium"
  });
  const [isProcessing, setIsProcessing] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingReport, setEditingReport] = useState(null);
  const [filteredData, setFilteredData] = useState([]);
  const [filters, setFilters] = useState({
    threatType: '',
    severity: '',
    status: '',
    startDate: '',
    endDate: '',
    content: '',
    targetDevice: '',
    attackSource: ''
  });

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

  // Fetch reports data from API
  const loadReportsData = async (filters = {}) => {
    try {
      setLoading(true);
      const response = await fetchReports(filters);
      
      if (!response || !response.reports) {
        throw new Error('Invalid response format from server');
      }
      
      // Map API data to our component's expected format
      const formattedData = response.reports.map(item => {
        // Get the raw content and handle nested format
        let rawContent = '';
        if (item.content?.raw_content) {
          try {
            // Try to parse as JSON first (for nested format)
            const parsed = JSON.parse(item.content.raw_content.replace(/'/g, '"'));
            rawContent = parsed.raw_content || item.content.raw_content;
          } catch (e) {
            // If parsing fails, use the content directly
            rawContent = item.content.raw_content;
          }
        }
        
        // Initialize with default values
        const reportData = {
        id: item.id,
          threatType: item.alert?.threat_type || 'Unknown',
          timestamp: item.created_at ? new Date(item.created_at).toLocaleString() : new Date().toLocaleString(),
          targetDevice: 'No Target Device',
          threatStatus: item.report_status || 'open',
          attackSource: 'Unknown Source',
          severityLevel: item.alert?.severity || 'medium',
        selected: false,
          content: rawContent,
        user: item.user,
        threat: item.threat,
        alert: item.alert
        };

        // If we have raw content, try to parse it
        if (rawContent) {
          const lines = rawContent.split('\n');
          lines.forEach(line => {
            if (!line.trim()) return;
            
            const [key, ...valueParts] = line.split(':');
            const value = valueParts.join(':').trim();
            
            if (!value) return;

            switch (key.trim()) {
              case 'Threat Type':
                reportData.threatType = value;
                break;
              case 'Target Device':
                reportData.targetDevice = value;
                break;
              case 'Attack Source IP':
                reportData.attackSource = value;
                break;
              case 'Threat Status':
                reportData.threatStatus = value;
                break;
              case 'Severity Level':
                reportData.severityLevel = value;
                break;
              case 'Created At':
                try {
                  const date = new Date(value);
                  if (!isNaN(date.getTime())) {
                    reportData.timestamp = date.toLocaleString();
                  }
                } catch (e) {
                  console.error('Error parsing date:', e);
                }
                break;
            }
          });
        }

        // Extract values from threat description if needed
        if (reportData.targetDevice === 'No Target Device' && item.threat?.description) {
          const match = item.threat.description.match(/to ([^\s]+)/);
          if (match) {
            reportData.targetDevice = match[1];
          }
        }
        if (reportData.attackSource === 'Unknown Source' && item.threat?.description) {
          const match = item.threat.description.match(/from ([^\s]+)/);
          if (match) {
            reportData.attackSource = match[1];
          }
        }

        return reportData;
      });
      
      setData(formattedData);
      setFilteredData(formattedData);
      setLoading(false);
      setError(null);
    } catch (error) {
      console.error("Error fetching reports:", error);
      setError(error.response?.data?.error || "Failed to load reports. Please try again.");
      setLoading(false);
      setData([]); // Clear data on error
    }
  };

  useEffect(() => {
    loadReportsData();
  }, []);

  // Dark mode styles
  const styles = {
    container: {
      backgroundColor: darkMode ? '#1E293B' : '#f9f9f9',
      color: darkMode ? '#e0e0e0' : '#333',
      transition: 'all 0.3s ease'
    },
    title: {
      color: darkMode ? '#e0e0e0' : '#333',
      transition: 'color 0.3s ease'
    },
    table: {
      backgroundColor: darkMode ? '#273142' : '#fff',
      color: darkMode ? '#e0e0e0' : '#333',
      border: darkMode ? '1px solid #3A4557' : '1px solid #e0e0e0',
      transition: 'all 0.3s ease',
      boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)'
    },
    tableHeader: {
      backgroundColor: darkMode ? '#334155' : '#f5f5f5',
      color: darkMode ? '#e0e0e0' : '#333',
      transition: 'all 0.3s ease'
    },
    button: {
      backgroundColor: darkMode ? '#3B82F6' : '#4299E1',
      color: '#fff',
      transition: 'all 0.2s ease',
      '&:hover': {
        transform: 'translateY(-2px)',
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)'
      }
    },
    tableRow: {
      color: darkMode ? '#e0e0e0' : '#333',
      transition: 'all 0.2s ease'
    },
    tableRowSelected: {
      backgroundColor: darkMode ? '#334155' : '#ebf5ff',
      color: darkMode ? '#e0e0e0' : '#333',
      transition: 'background-color 0.2s ease'
    },
    loadingContainer: {
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '50px 0',
      backgroundColor: darkMode ? '#1E293B' : '#f9f9f9',
      color: darkMode ? '#e0e0e0' : '#333',
      transition: 'all 0.3s ease'
    },
    error: {
      color: darkMode ? '#FCA5A5' : '#DC2626',
      padding: '10px',
      marginTop: '20px',
      textAlign: 'center',
      transition: 'color 0.3s ease'
    },
    modal: {
      position: 'fixed',
      top: 0,
      left: 0,
      width: '100%',
      height: '100%',
      backgroundColor: 'rgba(0, 0, 0, 0.5)',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      zIndex: 1000,
      opacity: 1,
      transition: 'opacity 0.3s ease'
    },
    modalContent: {
      backgroundColor: darkMode ? '#273142' : '#fff',
      padding: '20px',
      borderRadius: '8px',
      width: '600px',
      maxWidth: '90%',
      color: darkMode ? '#e0e0e0' : '#333',
      boxShadow: '0 10px 25px rgba(0, 0, 0, 0.2)',
      transition: 'all 0.3s ease'
    },
    modalHeader: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '20px'
    },
    input: {
      width: '100%',
      padding: '10px',
      marginBottom: '15px',
      backgroundColor: darkMode ? '#1E293B' : '#fff',
      border: darkMode ? '1px solid #3A4557' : '1px solid #ddd',
      borderRadius: '4px',
      color: darkMode ? '#e0e0e0' : '#333',
      transition: 'all 0.3s ease'
    },
    select: {
      width: '100%',
      padding: '10px',
      marginBottom: '15px',
      backgroundColor: darkMode ? '#1E293B' : '#fff',
      border: darkMode ? '1px solid #3A4557' : '1px solid #ddd',
      borderRadius: '4px',
      color: darkMode ? '#e0e0e0' : '#333',
      transition: 'all 0.3s ease'
    },
    filterContainer: {
      backgroundColor: darkMode ? '#273142' : '#fff',
      padding: '15px',
      borderRadius: '8px',
      marginBottom: '20px',
      boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
      transition: 'all 0.3s ease',
      overflow: 'hidden',
      maxHeight: isFiltersOpen ? '500px' : '0px',
      opacity: isFiltersOpen ? 1 : 0,
      padding: isFiltersOpen ? '15px' : '0px'
    },
    actionButton: {
      backgroundColor: darkMode ? '#273142' : '#fff',
      color: darkMode ? '#e0e0e0' : '#333',
      transition: 'all 0.2s ease',
      border: '1px solid transparent',
      '&:hover': {
        transform: 'translateY(-2px)',
        boxShadow: '0 4px 8px rgba(0, 0, 0, 0.1)',
        border: '1px solid #3B82F6'
      }
    },
    tableRowAnimation: {
      animation: 'fadeIn 0.5s ease-in-out',
      '@keyframes fadeIn': {
        '0%': { opacity: 0, transform: 'translateY(10px)' },
        '100%': { opacity: 1, transform: 'translateY(0)' }
      }
    }
  };

  const toggleSelectAll = () => {
    const allSelected = data.every((row) => row.selected);
    setData(data.map((row) => ({ ...row, selected: !allSelected })));
  };

  const toggleRowSelect = (id) => {
    setData(
      data.map((row) =>
        row.id === id ? { ...row, selected: !row.selected } : row
      )
    );
  };

  const getSelectedIds = () => {
    return data.filter(row => row.selected).map(row => row.id);
  };

  const handleDeleteSelected = async () => {
    const selectedIds = getSelectedIds();
    if (selectedIds.length === 0) {
      alert("Please select at least one report to delete");
      return;
    }
    
    if (window.confirm(`Are you sure you want to delete ${selectedIds.length} report(s)?`)) {
      try {
        setIsProcessing(true);
        console.log('Selected IDs for deletion:', selectedIds);
        await deleteReports(selectedIds);
        // Reload reports after deletion
        await loadReportsData(activeFilters);
        setIsProcessing(false);
      } catch (error) {
        console.error("Error deleting reports:", error);
        setError("Failed to delete reports. Please try again.");
        setIsProcessing(false);
      }
    }
  };

  const handleExport = async () => {
      try {
        setIsProcessing(true);
      const selectedReports = data.filter(report => report.selected);
      
      if (selectedReports.length === 0) {
        setError("Please select at least one report to export");
        setIsProcessing(false);
        return;
      }

      const reportIds = selectedReports.map(report => report.id);
      
      // Get the access token
      let accessToken = localStorage.getItem('access_token');
      
      // Try to refresh the token if it's expired
      try {
        const refreshToken = localStorage.getItem('refresh_token');
        if (refreshToken) {
          const response = await fetch('http://localhost:8000/api/token/refresh/', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ refresh: refreshToken }),
          });

          if (response.ok) {
            const data = await response.json();
            accessToken = data.access;
            localStorage.setItem('access_token', accessToken);
          } else {
            // If refresh fails, redirect to login
            window.location.href = '/login';
            return;
          }
        }
      } catch (error) {
        console.error('Error refreshing token:', error);
        window.location.href = '/login';
        return;
      }

      // Make the export request with the new token
      const response = await fetch('http://localhost:8000/api/reports/export/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
        body: JSON.stringify({ reportIds }),
      });

      if (!response.ok) {
        if (response.status === 401) {
          // If unauthorized, redirect to login
          window.location.href = '/login';
          return;
        }
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to export reports');
      }

      // Get the blob from the response
      const blob = await response.blob();
      
      // Create a download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'reports_export.json';
      document.body.appendChild(a);
      a.click();
      
      // Clean up
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      // Show success message
      setError(null);
        setIsProcessing(false);
      } catch (error) {
      console.error("Error exporting reports:", error);
      setError(error.message || "Failed to export reports. Please try again.");
        setIsProcessing(false);
    }
  };

  const toggleFilters = () => {
    setIsFiltersOpen(!isFiltersOpen);
  };

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    if (value) {
      setActiveFilters({ ...activeFilters, [name]: value });
    } else {
      // Remove empty filters
      const newFilters = { ...activeFilters };
      delete newFilters[name];
      setActiveFilters(newFilters);
    }
  };

  const handleFilter = () => {
    const filtered = data.filter(report => {
      const matchesThreatType = !filters.threatType || 
        report.threatType.toLowerCase().includes(filters.threatType.toLowerCase());

      const matchesSeverity = !filters.severity || 
        report.severityLevel.toLowerCase() === filters.severity.toLowerCase();

      const matchesStatus = !filters.status || 
        report.threatStatus.toLowerCase() === filters.status.toLowerCase();

      const matchesDateRange = !filters.startDate || !filters.endDate || 
        (new Date(report.created_at) >= new Date(filters.startDate) && 
         new Date(report.created_at) <= new Date(filters.endDate));

      const matchesContent = !filters.content || 
        (report.content && report.content.toLowerCase().includes(filters.content.toLowerCase()));

      const matchesTargetDevice = !filters.targetDevice || 
        (report.targetDevice && report.targetDevice.toLowerCase().includes(filters.targetDevice.toLowerCase()));

      const matchesAttackSource = !filters.attackSource || 
        (report.attackSource && report.attackSource.toLowerCase().includes(filters.attackSource.toLowerCase()));

      return matchesThreatType && 
             matchesSeverity && 
             matchesStatus && 
             matchesDateRange && 
             matchesContent && 
             matchesTargetDevice && 
             matchesAttackSource;
    });
    
    setFilteredData(filtered);
    setIsFiltersOpen(false);
  };

  const handleClearFilters = () => {
    setFilters({
      threatType: '',
      severity: '',
      status: '',
      startDate: '',
      endDate: '',
      content: '',
      targetDevice: '',
      attackSource: ''
    });
    setFilteredData(data);
    setIsFiltersOpen(false);
  };

  const handleNewReportChange = (e) => {
    const { name, value } = e.target;
    setNewReport({ ...newReport, [name]: value });
  };

  const handleAddReport = async () => {
    try {
      setIsProcessing(true);
      
      // Format the new report data for the API
      const reportData = {
        threat_type: newReport.threatType,
        target_device: newReport.targetDevice,
        threat_status: newReport.threatStatus,
        attack_source: newReport.attackSource,
        severity_level: newReport.severityLevel,
        timestamp: new Date().toISOString() // Use current time
      };
      
      await addReport(reportData);
      
      // Reset form and close modal
      setNewReport({
        threatType: "",
        targetDevice: "",
        threatStatus: "Detected",
        attackSource: "",
        severityLevel: "Medium"
      });
      setShowAddModal(false);
      
      // Reload reports
      await loadReportsData(activeFilters);
      setIsProcessing(false);
    } catch (error) {
      console.error("Error adding report:", error);
      setError("Failed to add report. Please try again.");
      setIsProcessing(false);
    }
  };

  const handleEditClick = (report) => {
    // Parse the content to get the current values
    let parsedValues = {
      threatType: report.threatType,
      targetDevice: report.targetDevice,
      threatStatus: report.threatStatus,
      attackSource: report.attackSource,
      severityLevel: report.severityLevel
    };

    // If we have raw content, try to parse it
    if (report.content) {
      const lines = report.content.split('\n');
      lines.forEach(line => {
        const [key, value] = line.split(':').map(s => s.trim());
        if (!value) return;

        switch (key) {
          case 'Threat Type':
            parsedValues.threatType = value;
            break;
          case 'Target Device':
            parsedValues.targetDevice = value;
            break;
          case 'Attack Source IP':
            parsedValues.attackSource = value;
            break;
          case 'Threat Status':
            parsedValues.threatStatus = value;
            break;
          case 'Severity Level':
            parsedValues.severityLevel = value;
            break;
        }
      });
    }

    setEditingReport({
      id: report.id,
      ...parsedValues
    });
    setShowEditModal(true);
  };

  const handleEditReport = async () => {
    try {
      setIsProcessing(true);
      
      // Format the report data for the API
      const reportData = {
        content: {
          raw_content: `Threat Report:
Threat Type: ${editingReport.threatType}
Target Device: ${editingReport.targetDevice}
Attack Source IP: ${editingReport.attackSource}
Threat Status: ${editingReport.threatStatus}
Severity Level: ${editingReport.severityLevel}
Category: ${editingReport.threatType.toLowerCase()}
Description: Detected ${editingReport.threatType} attack from ${editingReport.attackSource} to ${editingReport.targetDevice}
Created At: ${new Date().toISOString()}`
        },
        report_status: editingReport.threatStatus
      };
      
      await updateReport(editingReport.id, reportData);
      setShowEditModal(false);
      setEditingReport(null);
      await loadReportsData(activeFilters);
      setIsProcessing(false);
    } catch (error) {
      console.error("Error updating report:", error);
      setError("Failed to update report. Please try again.");
      setIsProcessing(false);
    }
  };

  // Animation staggered effect for table rows
  const getAnimationDelay = (index) => {
    return {
      animationDelay: `${index * 0.05}s`
    };
  };

  if (loading && !isProcessing) {
    return (
      <div style={styles.loadingContainer}>
        <CircularProgress style={{ color: darkMode ? '#4299E1' : '#3B82F6' }} />
        <p>Loading reports data...</p>
      </div>
    );
  }

  return (
    <Fade in={true} timeout={300}>
      <div className="table-container" style={styles.container}>
        <p className="title-page" style={styles.title}>Reports</p>
      <main className="reports-main">
        <div className="table-header-container">
          <div className="table-header">
              <p className="table-header-name" style={styles.title}>Network Reports</p>
              <p className="table-description" style={{ color: darkMode ? '#b0b0b0' : '#666', transition: 'color 0.3s ease' }}>Security Threats Report</p>
              <p className="table-description2" style={{ color: darkMode ? '#b0b0b0' : '#666', transition: 'color 0.3s ease' }}>
              This page provides the latest reports on network performance and
              potential threats.
            </p>
          </div>
          <div className="table-actions">
              <button 
                className="action-button" 
                style={{...styles.actionButton}}
                onClick={handleDeleteSelected}
                disabled={isProcessing}
              >
                <img src={trash} alt="Delete" />
                <span>Delete {getSelectedIds().length > 0 ? `(${getSelectedIds().length})` : ''}</span>
            </button>
              <button 
                className="action-button" 
                style={{...styles.actionButton}}
                onClick={toggleFilters}
              >
                <img src={filter} alt="Filter" />
                <span>Filters {Object.keys(activeFilters).length > 0 ? `(${Object.keys(activeFilters).length})` : ''}</span>
            </button>
              <button 
                className="action-button" 
                style={{...styles.actionButton, border:'1px solid #D0D5DD'}}
                onClick={handleExport}
                disabled={isProcessing}
              >
                <img src={download} alt="Export" />
                <span>Export {getSelectedIds().length > 0 ? `(${getSelectedIds().length})` : ''}</span>
            </button>
              <button 
                className="cta-button" 
                style={{...styles.button}}
                onClick={() => setShowAddModal(true)}
              >
                <img src={plus} alt="Add" />
              <span>Add New Analysis</span>
            </button>
          </div>
        </div>
          
          {/* Filters panel */}
          {isFiltersOpen && (
            <div style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: 'rgba(0, 0, 0, 0.5)',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              zIndex: 1000
            }}>
              <div style={{
                backgroundColor: darkMode ? '#1a2234' : 'white',
                padding: '24px',
                borderRadius: '12px',
                width: '500px',
                maxWidth: '90%',
                boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)'
              }}>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '24px'
            }}>
                  <h3 style={{
                    margin: 0,
                    color: darkMode ? '#e0e0e0' : '#1a2234',
                    fontSize: '1.25rem',
                    fontWeight: '600'
                  }}>
                    Filter Reports
                  </h3>
                  <button
                    onClick={() => setIsFiltersOpen(false)}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: darkMode ? '#e0e0e0' : '#1a2234',
                      cursor: 'pointer',
                      fontSize: '1.25rem'
                    }}
                  >
                    ×
                  </button>
                </div>

                <div style={{
                  display: 'grid',
                  gridTemplateColumns: '1fr 1fr',
                  gap: '16px',
                  marginBottom: '24px'
                }}>
                <div>
                    <label style={{
                      display: 'block',
                      marginBottom: '8px',
                      color: darkMode ? '#e0e0e0' : '#4a5568',
                      fontSize: '0.875rem',
                      fontWeight: '500'
                    }}>
                      Threat Type
                    </label>
                  <input
                    type="text"
                      value={filters.threatType}
                      onChange={(e) => setFilters(prev => ({ ...prev, threatType: e.target.value }))}
                    placeholder="Filter by threat type"
                      style={{
                        width: '100%',
                        padding: '8px 12px',
                        border: `1px solid ${darkMode ? '#2d3748' : '#e2e8f0'}`,
                        borderRadius: '6px',
                        backgroundColor: darkMode ? '#273142' : 'white',
                        color: darkMode ? '#e0e0e0' : '#1a2234',
                        fontSize: '0.875rem'
                      }}
                  />
                </div>

                <div>
                    <label style={{
                      display: 'block',
                      marginBottom: '8px',
                      color: darkMode ? '#e0e0e0' : '#4a5568',
                      fontSize: '0.875rem',
                      fontWeight: '500'
                    }}>
                      Severity Level
                    </label>
                  <select
                      value={filters.severity}
                      onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value }))}
                      style={{
                        width: '100%',
                        padding: '8px 12px',
                        border: `1px solid ${darkMode ? '#2d3748' : '#e2e8f0'}`,
                        borderRadius: '6px',
                        backgroundColor: darkMode ? '#273142' : 'white',
                        color: darkMode ? '#e0e0e0' : '#1a2234',
                        fontSize: '0.875rem',
                        cursor: 'pointer'
                      }}
                    >
                      <option value="">All Severity Levels</option>
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                  </select>
                </div>

                <div>
                    <label style={{
                      display: 'block',
                      marginBottom: '8px',
                      color: darkMode ? '#e0e0e0' : '#4a5568',
                      fontSize: '0.875rem',
                      fontWeight: '500'
                    }}>
                      Status
                    </label>
                  <select
                      value={filters.status}
                      onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
                      style={{
                        width: '100%',
                        padding: '8px 12px',
                        border: `1px solid ${darkMode ? '#2d3748' : '#e2e8f0'}`,
                        borderRadius: '6px',
                        backgroundColor: darkMode ? '#273142' : 'white',
                        color: darkMode ? '#e0e0e0' : '#1a2234',
                        fontSize: '0.875rem',
                        cursor: 'pointer'
                      }}
                    >
                      <option value="">All Statuses</option>
                      <option value="open">Open</option>
                      <option value="closed">Closed</option>
                      <option value="review">In Review</option>
                  </select>
                </div>

                  <div>
                    <label style={{
                      display: 'block',
                      marginBottom: '8px',
                      color: darkMode ? '#e0e0e0' : '#4a5568',
                      fontSize: '0.875rem',
                      fontWeight: '500'
                    }}>
                      Target Device
                    </label>
                    <input
                      type="text"
                      value={filters.targetDevice}
                      onChange={(e) => setFilters(prev => ({ ...prev, targetDevice: e.target.value }))}
                      placeholder="Filter by target device"
                      style={{
                        width: '100%',
                        padding: '8px 12px',
                        border: `1px solid ${darkMode ? '#2d3748' : '#e2e8f0'}`,
                        borderRadius: '6px',
                        backgroundColor: darkMode ? '#273142' : 'white',
                        color: darkMode ? '#e0e0e0' : '#1a2234',
                        fontSize: '0.875rem'
                      }}
                    />
              </div>

                  <div>
                    <label style={{
                      display: 'block',
                      marginBottom: '8px',
                      color: darkMode ? '#e0e0e0' : '#4a5568',
                      fontSize: '0.875rem',
                      fontWeight: '500'
                    }}>
                      Attack Source
                    </label>
                    <input
                      type="text"
                      value={filters.attackSource}
                      onChange={(e) => setFilters(prev => ({ ...prev, attackSource: e.target.value }))}
                      placeholder="Filter by attack source"
                      style={{
                        width: '100%',
                        padding: '8px 12px',
                        border: `1px solid ${darkMode ? '#2d3748' : '#e2e8f0'}`,
                        borderRadius: '6px',
                        backgroundColor: darkMode ? '#273142' : 'white',
                        color: darkMode ? '#e0e0e0' : '#1a2234',
                        fontSize: '0.875rem'
                      }}
                    />
                  </div>

                  <div>
                    <label style={{
                      display: 'block',
                      marginBottom: '8px',
                      color: darkMode ? '#e0e0e0' : '#4a5568',
                      fontSize: '0.875rem',
                      fontWeight: '500'
                    }}>
                      Content
                    </label>
                    <input
                      type="text"
                      value={filters.content}
                      onChange={(e) => setFilters(prev => ({ ...prev, content: e.target.value }))}
                      placeholder="Search in content"
                      style={{
                        width: '100%',
                        padding: '8px 12px',
                        border: `1px solid ${darkMode ? '#2d3748' : '#e2e8f0'}`,
                        borderRadius: '6px',
                        backgroundColor: darkMode ? '#273142' : 'white',
                        color: darkMode ? '#e0e0e0' : '#1a2234',
                        fontSize: '0.875rem'
                      }}
                    />
                  </div>

                  <div style={{ gridColumn: 'span 2' }}>
                    <label style={{
                      display: 'block',
                      marginBottom: '8px',
                      color: darkMode ? '#e0e0e0' : '#4a5568',
                      fontSize: '0.875rem',
                      fontWeight: '500'
                    }}>
                      Date Range
                    </label>
                    <div style={{ display: 'flex', gap: '12px' }}>
                      <input
                        type="date"
                        value={filters.startDate}
                        onChange={(e) => setFilters(prev => ({ ...prev, startDate: e.target.value }))}
                        style={{
                          flex: 1,
                          padding: '8px 12px',
                          border: `1px solid ${darkMode ? '#2d3748' : '#e2e8f0'}`,
                          borderRadius: '6px',
                          backgroundColor: darkMode ? '#273142' : 'white',
                          color: darkMode ? '#e0e0e0' : '#1a2234',
                          fontSize: '0.875rem'
                        }}
                      />
                      <input
                        type="date"
                        value={filters.endDate}
                        onChange={(e) => setFilters(prev => ({ ...prev, endDate: e.target.value }))}
                        style={{
                          flex: 1,
                          padding: '8px 12px',
                          border: `1px solid ${darkMode ? '#2d3748' : '#e2e8f0'}`,
                          borderRadius: '6px',
                          backgroundColor: darkMode ? '#273142' : 'white',
                          color: darkMode ? '#e0e0e0' : '#1a2234',
                          fontSize: '0.875rem'
                        }}
                      />
                    </div>
                  </div>
                </div>

                <div style={{
                  display: 'flex',
                  justifyContent: 'flex-end',
                  gap: '12px',
                  borderTop: `1px solid ${darkMode ? '#2d3748' : '#e2e8f0'}`,
                  paddingTop: '20px'
                }}>
                <button 
                    onClick={handleClearFilters}
                  style={{ 
                      padding: '8px 16px',
                      backgroundColor: darkMode ? '#2d3748' : '#e2e8f0',
                      color: darkMode ? '#e0e0e0' : '#4a5568',
                    border: 'none', 
                      borderRadius: '6px',
                    cursor: 'pointer',
                      fontSize: '0.875rem',
                      fontWeight: '500',
                      transition: 'all 0.2s'
                  }}
                >
                    Clear Filters
                </button>
                <button 
                    onClick={handleFilter}
                  style={{ 
                      padding: '8px 16px',
                      backgroundColor: '#4299e1',
                      color: 'white',
                    border: 'none', 
                      borderRadius: '6px',
                    cursor: 'pointer',
                      fontSize: '0.875rem',
                      fontWeight: '500',
                      transition: 'all 0.2s'
                  }}
                >
                  Apply Filters
                </button>
              </div>
            </div>
            </div>
          )}
          
          {error && <div style={styles.error}>{error}</div>}
          
          {isProcessing && (
            <Fade in={isProcessing}>
              <div style={{ textAlign: 'center', padding: '20px 0' }}>
                <CircularProgress size={24} style={{ color: darkMode ? '#4299E1' : '#3B82F6' }} />
                <p style={{ marginTop: '10px' }}>Processing your request...</p>
              </div>
            </Fade>
          )}
          
          {!isProcessing && data.length === 0 ? (
            <Fade in={true}>
              <div style={{ textAlign: 'center', padding: '30px 0' }}>
                <p>No reports data available</p>
              </div>
            </Fade>
          ) : (
            <Fade in={true} timeout={500}>
              <table className="styled-table" style={styles.table}>
          <thead>
                  <tr style={styles.tableHeader}>
              <th>
                <input
                  type="checkbox"
                  onChange={toggleSelectAll}
                        checked={data.length > 0 && data.every((row) => row.selected)}
                />
              </th>
              <th>Threat Type</th>
              <th>Timestamp</th>
              <th>Target Device</th>
              <th>Threat Status</th>
              <th>Attack Source</th>
              <th>Severity Level</th>
            </tr>
          </thead>
          <tbody>
                  {filteredData.map((report, index) => (
                    <Fade in={true} style={{ transitionDelay: `${index * 30}ms` }} key={report.id}>
                      <tr 
                        className={report.selected ? "selected-row" : ""}
                        style={{
                          ...styles.tableRowAnimation,
                          ...getAnimationDelay(index),
                          ...(report.selected ? 
                            styles.tableRowSelected : 
                            { 
                              backgroundColor: darkMode ? 
                                (index % 2 === 0 ? '#1a2234' : '#273142') : 
                                (index % 2 === 0 ? '#f9f9f9' : '#ffffff'),
                              color: darkMode ? '#e0e0e0' : '#333'
                            }
                          )
                        }}
                      >
                <td>
                  <input
                    type="checkbox"
                    checked={report.selected}
                    onChange={() => toggleRowSelect(report.id)}
                  />
                </td>
                <td>{report.threatType}</td>
                <td>{report.timestamp}</td>
                <td>{report.targetDevice}</td>
                <td>
                  <span style={{
                    padding: '4px 8px',
                    borderRadius: '4px',
                    backgroundColor: report.threatStatus === 'open' ? '#FEF3C7' : 
                                   report.threatStatus === 'new' ? '#DBEAFE' : 
                                   report.threatStatus === 'resolved' ? '#D1FAE5' : '#F3F4F6',
                    color: report.threatStatus === 'open' ? '#92400E' : 
                          report.threatStatus === 'new' ? '#1E40AF' : 
                          report.threatStatus === 'resolved' ? '#065F46' : '#374151',
                    textTransform: 'capitalize'
                  }}>
                    {report.threatStatus}
                  </span>
                </td>
                <td>{report.attackSource}</td>
                <td>
                  <span style={{
                    padding: '4px 8px',
                    borderRadius: '4px',
                    backgroundColor: report.severityLevel === 'high' ? '#FEE2E2' : 
                                   report.severityLevel === 'medium' ? '#FEF3C7' : 
                                   report.severityLevel === 'low' ? '#D1FAE5' : '#F3F4F6',
                    color: report.severityLevel === 'high' ? '#991B1B' : 
                          report.severityLevel === 'medium' ? '#92400E' : 
                          report.severityLevel === 'low' ? '#065F46' : '#374151',
                    textTransform: 'capitalize'
                  }}>
                    {report.severityLevel}
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
                    <button
                      onClick={() => handleEditClick(report)}
                      style={{
                        padding: '4px 8px',
                        backgroundColor: darkMode ? '#334155' : '#f5f5f5',
                        color: darkMode ? '#e0e0e0' : '#333',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        transition: 'all 0.2s ease'
                      }}
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => {
                        if (window.confirm('Are you sure you want to delete this report?')) {
                          handleDeleteSelected([report.id]);
                        }
                      }}
                      style={{
                        padding: '4px 8px',
                        backgroundColor: '#FEE2E2',
                        color: '#991B1B',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        transition: 'all 0.2s ease'
                      }}
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
                    </Fade>
            ))}
          </tbody>
        </table>
            </Fade>
          )}
      </main>

        {/* Add New Report Modal */}
        {showAddModal && (
          <Fade in={showAddModal} timeout={200}>
            <div style={styles.modal}>
              <Zoom in={showAddModal} timeout={300}>
                <div style={styles.modalContent}>
                  <div style={styles.modalHeader}>
                    <h2>Add New Report</h2>
                    <button
                      onClick={() => setShowAddModal(false)}
                      style={{ 
                        background: 'none', 
                        border: 'none', 
                        fontSize: '20px', 
                        cursor: 'pointer', 
                        color: darkMode ? '#e0e0e0' : '#333',
                        transition: 'transform 0.2s ease',
                        '&:hover': {
                          transform: 'rotate(90deg)'
                        }
                      }}
                    >
                      ×
                    </button>
                  </div>
                  <div>
                    <div style={{ marginBottom: '15px' }}>
                      <label style={{ display: 'block', marginBottom: '5px' }}>Threat Type *</label>
                      <input
                        type="text"
                        name="threatType"
                        placeholder="e.g. DoS Attack, Malware, Phishing"
                        value={newReport.threatType}
                        onChange={handleNewReportChange}
                        style={styles.input}
                        required
                      />
                    </div>
                    <div style={{ marginBottom: '15px' }}>
                      <label style={{ display: 'block', marginBottom: '5px' }}>Target Device *</label>
                      <input
                        type="text"
                        name="targetDevice"
                        placeholder="e.g. Router, Server, Workstation"
                        value={newReport.targetDevice}
                        onChange={handleNewReportChange}
                        style={styles.input}
                        required
                      />
                    </div>
                    <div style={{ marginBottom: '15px' }}>
                      <label style={{ display: 'block', marginBottom: '5px' }}>Attack Source IP *</label>
                      <input
                        type="text"
                        name="attackSource"
                        placeholder="e.g. 192.168.1.1"
                        value={newReport.attackSource}
                        onChange={handleNewReportChange}
                        style={styles.input}
                        required
                      />
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                      <div>
                        <label style={{ display: 'block', marginBottom: '5px' }}>Threat Status</label>
                        <select
                          name="threatStatus"
                          value={newReport.threatStatus}
                          onChange={handleNewReportChange}
                          style={styles.select}
                        >
                          <option value="Detected">Detected</option>
                          <option value="Under Investigation">Under Investigation</option>
                          <option value="Mitigated">Mitigated</option>
                          <option value="Resolved">Resolved</option>
                          <option value="Blocked">Blocked</option>
                          <option value="Active">Active</option>
                          <option value="Quarantined">Quarantined</option>
                          <option value="Escalated">Escalated</option>
                        </select>
                      </div>
                      <div>
                        <label style={{ display: 'block', marginBottom: '5px' }}>Severity Level</label>
                        <select
                          name="severityLevel"
                          value={newReport.severityLevel}
                          onChange={handleNewReportChange}
                          style={styles.select}
                        >
                          <option value="Low">Low</option>
                          <option value="Medium">Medium</option>
                          <option value="High">High</option>
                          <option value="Critical">Critical</option>
                        </select>
                      </div>
                    </div>
                    <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                      <button
                        onClick={() => setShowAddModal(false)}
                        style={{ 
                          padding: '10px 15px', 
                          backgroundColor: darkMode ? '#334155' : '#f5f5f5', 
                          color: darkMode ? '#e0e0e0' : '#333', 
                          border: 'none', 
                          borderRadius: '4px', 
                          cursor: 'pointer',
                          transition: 'all 0.2s ease'
                        }}
                      >
                        Cancel
                      </button>
                      <button
                        onClick={handleAddReport}
                        disabled={!newReport.threatType || !newReport.targetDevice || !newReport.attackSource || isProcessing}
                        style={{ 
                          padding: '10px 15px', 
                          backgroundColor: (!newReport.threatType || !newReport.targetDevice || !newReport.attackSource || isProcessing) ? '#93C5FD' : '#4299E1',
                          color: '#fff', 
                          border: 'none', 
                          borderRadius: '4px', 
                          cursor: (!newReport.threatType || !newReport.targetDevice || !newReport.attackSource || isProcessing) ? 'not-allowed' : 'pointer',
                          transition: 'all 0.2s ease'
                        }}
                      >
                        {isProcessing ? 'Adding...' : 'Add Report'}
                      </button>
                    </div>
                  </div>
                </div>
              </Zoom>
            </div>
          </Fade>
        )}

        {/* Edit Report Modal */}
        {showEditModal && editingReport && (
          <Fade in={showEditModal} timeout={200}>
            <div style={styles.modal}>
              <Zoom in={showEditModal} timeout={300}>
                <div style={styles.modalContent}>
                  <div style={styles.modalHeader}>
                    <h2>Edit Report</h2>
                    <button
                      onClick={() => {
                        setShowEditModal(false);
                        setEditingReport(null);
                      }}
                      style={{ 
                        background: 'none', 
                        border: 'none', 
                        fontSize: '20px', 
                        cursor: 'pointer', 
                        color: darkMode ? '#e0e0e0' : '#333',
                        transition: 'transform 0.2s ease',
                        '&:hover': {
                          transform: 'rotate(90deg)'
                        }
                      }}
                    >
                      ×
                    </button>
                  </div>
                  <div>
                    <div style={{ marginBottom: '15px' }}>
                      <label style={{ display: 'block', marginBottom: '5px' }}>Threat Type *</label>
                      <input
                        type="text"
                        name="threatType"
                        value={editingReport.threatType}
                        onChange={(e) => setEditingReport({...editingReport, threatType: e.target.value})}
                        style={styles.input}
                        required
                      />
                    </div>
                    <div style={{ marginBottom: '15px' }}>
                      <label style={{ display: 'block', marginBottom: '5px' }}>Target Device *</label>
                      <input
                        type="text"
                        name="targetDevice"
                        value={editingReport.targetDevice}
                        onChange={(e) => setEditingReport({...editingReport, targetDevice: e.target.value})}
                        style={styles.input}
                        required
                      />
                    </div>
                    <div style={{ marginBottom: '15px' }}>
                      <label style={{ display: 'block', marginBottom: '5px' }}>Attack Source IP *</label>
                      <input
                        type="text"
                        name="attackSource"
                        value={editingReport.attackSource}
                        onChange={(e) => setEditingReport({...editingReport, attackSource: e.target.value})}
                        style={styles.input}
                        required
                      />
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                      <div>
                        <label style={{ display: 'block', marginBottom: '5px' }}>Threat Status</label>
                        <select
                          name="threatStatus"
                          value={editingReport.threatStatus}
                          onChange={(e) => setEditingReport({...editingReport, threatStatus: e.target.value})}
                          style={styles.select}
                        >
                          <option value="open">Open</option>
                          <option value="closed">Closed</option>
                          <option value="review">In Review</option>
                          <option value="new">New</option>
                        </select>
                      </div>
                      <div>
                        <label style={{ display: 'block', marginBottom: '5px' }}>Severity Level</label>
                        <select
                          name="severityLevel"
                          value={editingReport.severityLevel}
                          onChange={(e) => setEditingReport({...editingReport, severityLevel: e.target.value})}
                          style={styles.select}
                        >
                          <option value="low">Low</option>
                          <option value="medium">Medium</option>
                          <option value="high">High</option>
                          <option value="critical">Critical</option>
                        </select>
                      </div>
                    </div>
                    <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                      <button
                        onClick={() => {
                          setShowEditModal(false);
                          setEditingReport(null);
                        }}
                        style={{ 
                          padding: '10px 15px', 
                          backgroundColor: darkMode ? '#334155' : '#f5f5f5', 
                          color: darkMode ? '#e0e0e0' : '#333', 
                          border: 'none', 
                          borderRadius: '4px', 
                          cursor: 'pointer',
                          transition: 'all 0.2s ease'
                        }}
                      >
                        Cancel
                      </button>
                      <button
                        onClick={handleEditReport}
                        disabled={!editingReport.threatType || !editingReport.targetDevice || !editingReport.attackSource || isProcessing}
                        style={{ 
                          padding: '10px 15px', 
                          backgroundColor: (!editingReport.threatType || !editingReport.targetDevice || !editingReport.attackSource || isProcessing) ? '#93C5FD' : '#4299E1',
                          color: '#fff', 
                          border: 'none', 
                          borderRadius: '4px', 
                          cursor: (!editingReport.threatType || !editingReport.targetDevice || !editingReport.attackSource || isProcessing) ? 'not-allowed' : 'pointer',
                          transition: 'all 0.2s ease'
                        }}
                      >
                        {isProcessing ? 'Updating...' : 'Update Report'}
                      </button>
                    </div>
                  </div>
                </div>
              </Zoom>
            </div>
          </Fade>
        )}
    </div>
    </Fade>
  );
};

export default Table;
