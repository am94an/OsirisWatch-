import React, { useState, useEffect } from 'react';
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow, 
  Paper,
  Typography
} from '@mui/material';

const TopAlarmingHosts = ({ data = [] }) => {
  const [darkMode, setDarkMode] = useState(false);

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
    
    // Listen for storage events (from other tabs) and regular storage events (from same window)
    window.addEventListener('storage', handleDarkModeChange);
    
    // This is needed for changes in the same tab
    window.addEventListener('storage-local', handleDarkModeChange);
    
    return () => {
      window.removeEventListener('storage', handleDarkModeChange);
      window.removeEventListener('storage-local', handleDarkModeChange);
    };
  }, []);

  // Make sure data is properly handled
  const validData = Array.isArray(data) ? data : [];
  
  // Sort data by count in descending order
  const sortedData = [...validData].sort((a, b) => {
    const countA = a.count || a.alarm_count || a.value || 0;
    const countB = b.count || b.alarm_count || b.value || 0;
    return countB - countA;
  }).slice(0, 10); // Take only top 10

  // Dark mode styles
  const styles = {
    container: {
      backgroundColor: darkMode ? '#273142' : '#ffffff',
      padding: '20px',
      borderRadius: '8px',
      marginTop: '20px',
      marginBottom: '20px',
    },
    title: {
      color: darkMode ? '#e0e0e0' : '#202224',
      marginBottom: '15px',
    },
    paper: {
      backgroundColor: darkMode ? '#1E293B' : '#ffffff',
      boxShadow: darkMode ? '0 4px 6px rgba(0, 0, 0, 0.3)' : undefined,
    },
    tableHead: {
      backgroundColor: darkMode ? '#334155' : '#f5f5f5',
    },
    headerCell: {
      color: darkMode ? '#e0e0e0' : '#333333',
      fontWeight: 'bold',
    },
    cell: {
      color: darkMode ? '#e0e0e0' : '#333333',
      borderBottom: `1px solid ${darkMode ? '#334155' : '#e0e0e0'}`,
    },
    noData: {
      color: darkMode ? '#94A3B8' : '#666666',
    },
    riskHigh: {
      color: darkMode ? '#FCA5A5' : '#DC2626',
      fontWeight: 'bold',
    },
    riskMedium: {
      color: darkMode ? '#FCD34D' : '#D97706',
      fontWeight: 'bold',
    },
    riskLow: {
      color: darkMode ? '#93C5FD' : '#2563EB',
      fontWeight: 'bold',
    }
  };

  // Helper function to get risk level style
  const getRiskLevelStyle = (count) => {
    if (count >= 100) return styles.riskHigh;
    if (count >= 50) return styles.riskMedium;
    return styles.riskLow;
  };

  return (
    <div className="alarming-hosts-table" style={styles.container}>
      <Typography variant="h5" component="h2" gutterBottom style={styles.title}>
        Top Alarming Hosts
      </Typography>
      
      {sortedData.length === 0 ? (
        <Typography variant="body1" style={styles.noData}>
          No data available
        </Typography>
      ) : (
        <TableContainer component={Paper} style={styles.paper}>
          <Table aria-label="top alarming hosts table">
            <TableHead style={styles.tableHead}>
              <TableRow>
                <TableCell style={styles.headerCell}>IP Address</TableCell>
                <TableCell style={styles.headerCell}>Alarm Count</TableCell>
                <TableCell style={styles.headerCell}>Risk Level</TableCell>
                {validData[0]?.reason && <TableCell style={styles.headerCell}>Reason</TableCell>}
              </TableRow>
            </TableHead>
            <TableBody>
              {sortedData.map((host, index) => {
                const count = host.count || host.alarm_count || host.value || 0;
                return (
                  <TableRow key={host.ip_address || `unknown-${index}`}
                    sx={{ backgroundColor: darkMode ? (index % 2 === 0 ? '#1a2234' : '#1E293B') : (index % 2 === 0 ? '#f9f9f9' : '#ffffff') }}>
                    <TableCell style={styles.cell}>{host.ip_address || 'Unknown'}</TableCell>
                    <TableCell style={styles.cell}>{count}</TableCell>
                    <TableCell style={{...styles.cell, ...getRiskLevelStyle(count)}}>
                      {getRiskLevel(count)}
                    </TableCell>
                    {validData[0]?.reason && <TableCell style={styles.cell}>{host.reason || 'N/A'}</TableCell>}
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </div>
  );
};

// Helper function to determine risk level based on count
const getRiskLevel = (count) => {
  if (count >= 100) return 'High';
  if (count >= 50) return 'Medium';
  return 'Low';
};

export default TopAlarmingHosts;
