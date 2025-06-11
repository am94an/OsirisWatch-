import { grey } from '@mui/material/colors';
import React, { useEffect, useState } from 'react';
import { 
  Box, 
  Typography, 
  TextField, 
  Select, 
  MenuItem, 
  FormControl, 
  InputLabel,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Chip,
  Button,
  Stack,
  useTheme,
  Pagination,
  CircularProgress,
  Snackbar,
  Alert
} from '@mui/material';
import { 
  Search as SearchIcon, 
  FilterList as FilterIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon
} from '@mui/icons-material';
import { fetchNetworkActivityLogs, exportNetworkActivityLogs } from '../../services/api';

const ActivityLog = () => {
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [eventType, setEventType] = useState('');
  const [severity, setSeverity] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [exportLoading, setExportLoading] = useState(false);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: '',
    severity: 'success'
  });
  const theme = useTheme();

  const fetchLogs = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const params = {
        page,
        page_size: 10,
        search,
        event_type: eventType,
        severity
      };

      const response = await fetchNetworkActivityLogs(params);
      setLogs(response.logs);
      setTotalPages(response.pagination.total_pages);
    } catch (err) {
      setError('Failed to fetch logs. Please try again.');
      console.error('Error fetching logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page, search, eventType, severity]);

  const handleSearchChange = (event) => {
    setSearch(event.target.value);
    setPage(1); // Reset to first page on new search
  };

  const handleEventTypeChange = (event) => {
    setEventType(event.target.value);
    setPage(1);
  };

  const handleSeverityChange = (event) => {
    setSeverity(event.target.value);
    setPage(1);
  };

  const handlePageChange = (event, value) => {
    setPage(value);
  };

  const handleRefresh = () => {
    fetchLogs();
  };

  const handleExport = async () => {
    try {
      setExportLoading(true);
      const params = {
        search,
        event_type: eventType,
        severity
      };
      
      await exportNetworkActivityLogs(params);
      
      setSnackbar({
        open: true,
        message: 'Logs exported successfully',
        severity: 'success'
      });
    } catch (err) {
      console.error('Error exporting logs:', err);
      setSnackbar({
        open: true,
        message: 'Failed to export logs. Please try again.',
        severity: 'error'
      });
    } finally {
      setExportLoading(false);
    }
  };

  const handleCloseSnackbar = () => {
    setSnackbar(prev => ({ ...prev, open: false }));
  };

  useEffect(() => {
    const darkMode = localStorage.getItem('darkMode') === 'true';
    setIsDarkMode(darkMode);

    const handleStorageChange = () => {
      setIsDarkMode(localStorage.getItem('darkMode') === 'true');
    };

    window.addEventListener('storage-local', handleStorageChange);
    return () => window.removeEventListener('storage-local', handleStorageChange);
  }, []);

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'critical':
        return isDarkMode ? 'rgba(239, 68, 68, 0.15)' : '#fee2e2';
      case 'high':
        return isDarkMode ? 'rgba(249, 115, 22, 0.15)' : '#ffedd5';
      case 'medium':
        return isDarkMode ? 'rgba(234, 179, 8, 0.15)' : '#fef3c7';
      case 'low':
        return isDarkMode ? 'rgba(34, 197, 94, 0.15)' : '#dcfce7';
      default:
        return isDarkMode ? 'rgba(59, 130, 246, 0.15)' : '#dbeafe';
    }
  };

  const getSeverityTextColor = (severity) => {
    switch(severity) {
      case 'critical':
        return isDarkMode ? '#fca5a5' : '#dc2626';
      case 'high':
        return isDarkMode ? '#fdba74' : '#ea580c';
      case 'medium':
        return isDarkMode ? '#fde047' : '#ca8a04';
      case 'low':
        return isDarkMode ? '#86efac' : '#16a34a';
      default:
        return isDarkMode ? '#93c5fd' : '#2563eb';
    }
  };

  const getSeverityIcon = (severity) => {
    switch(severity) {
      case 'critical':
        return <ErrorIcon sx={{ fontSize: 16 }} />;
      case 'high':
        return <WarningIcon sx={{ fontSize: 16 }} />;
      default:
        return <InfoIcon sx={{ fontSize: 16 }} />;
    }
  };

  const formatDetails = (details) => {
    if (!details) return '';
    
    if (typeof details === 'string') return details;
    
    if (typeof details === 'object') {
      const formattedDetails = [];
      
      if (details.flow_duration) {
        formattedDetails.push(`Duration: ${details.flow_duration}s`);
      }
      
      if (details.packet_size_stats) {
        const stats = details.packet_size_stats;
        formattedDetails.push(`Packet Size: Avg=${stats.mean || 'N/A'}, Max=${stats.max || 'N/A'}`);
      }
      
      if (details.iat_stats) {
        const stats = details.iat_stats;
        formattedDetails.push(`IAT: Avg=${stats.mean || 'N/A'}, Max=${stats.max || 'N/A'}`);
      }
      
      if (details.tcp_flags) {
        formattedDetails.push(`TCP Flags: ${Object.entries(details.tcp_flags)
          .filter(([_, value]) => value)
          .map(([flag]) => flag)
          .join(', ')}`);
      }
      
      return formattedDetails.join(' | ');
    }
    
    return JSON.stringify(details);
  };
 
  const styles = {
    container: {
      padding: '32px',
      backgroundColor: isDarkMode ? '#0f172a' : '#f8fafc',
      minHeight: '100vh',
      transition: 'background-color 0.3s ease',
    },
    header: {
      marginBottom: '32px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      flexWrap: 'wrap',
      gap: '16px',
    },
    headerLeft: {
      flex: 1,
      minWidth: '300px',
    },
    headerRight: {
      display: 'flex',
      gap: '12px',
      flexWrap: 'wrap',
    },
    title: {
      fontSize: '28px',
      fontWeight: '700',
      color: isDarkMode ? '#f1f5f9' : '#1e293b',
      marginBottom: '8px',
      transition: 'color 0.3s ease',
    },
    subtitle: {
      fontSize: '15px',
      color: isDarkMode ? '#94a3b8' : '#64748b',
      marginBottom: '0',
      transition: 'color 0.3s ease',
    },
    searchAndFilters: {
      display: 'flex',
      gap: '16px',
      marginBottom: '32px',
      flexWrap: 'wrap',
      backgroundColor: isDarkMode ? '#1e293b' : 'white',
      padding: '24px',
      borderRadius: '16px',
      boxShadow: isDarkMode ? '0 4px 6px -1px rgba(0, 0, 0, 0.3)' : '0 1px 3px rgba(0,0,0,0.05)',
      transition: 'all 0.3s ease',
    },
    searchField: {
      flex: 1,
      minWidth: '300px',
      '& .MuiOutlinedInput-root': {
        backgroundColor: isDarkMode ? '#334155' : '#f8fafc',
        borderRadius: '12px',
        transition: 'background-color 0.3s ease',
        '&:hover': {
          backgroundColor: isDarkMode ? '#475569' : '#f1f5f9',
        },
        '& .MuiOutlinedInput-notchedOutline': {
          borderColor: isDarkMode ? '#475569' : '#e2e8f0',
        },
        '&:hover .MuiOutlinedInput-notchedOutline': {
          borderColor: isDarkMode ? '#64748b' : '#cbd5e1',
        },
      },
      '& .MuiInputLabel-root': {
        color: isDarkMode ? '#94a3b8' : '#64748b',
        fontSize: '14px',
      },
      '& .MuiInputBase-input': {
        color: isDarkMode ? '#f1f5f9' : '#334155',
        fontSize: '14px',
        padding: '12px 16px',
      },
    },
    filterSelect: {
      minWidth: '200px',
      '& .MuiOutlinedInput-root': {
        backgroundColor: isDarkMode ? '#334155' : '#f8fafc',
        borderRadius: '12px',
        transition: 'background-color 0.3s ease',
        '&:hover': {
          backgroundColor: isDarkMode ? '#475569' : '#f1f5f9',
        },
        '& .MuiOutlinedInput-notchedOutline': {
          borderColor: isDarkMode ? '#475569' : '#e2e8f0',
        },
        '&:hover .MuiOutlinedInput-notchedOutline': {
          borderColor: isDarkMode ? '#64748b' : '#cbd5e1',
        },
      },
      '& .MuiInputLabel-root': {
        color: isDarkMode ? '#94a3b8' : '#64748b',
        fontSize: '14px',
      },
      '& .MuiSelect-select': {
        color: isDarkMode ? '#f1f5f9' : '#334155',
        fontSize: '14px',
        padding: '12px 16px',
      },
    },
    tableContainer: {
      backgroundColor: isDarkMode ? '#1e293b' : 'white',
      borderRadius: '16px',
      boxShadow: isDarkMode ? '0 4px 6px -1px rgba(0, 0, 0, 0.3)' : '0 1px 3px rgba(0,0,0,0.05)',
      overflow: 'hidden',
      transition: 'all 0.3s ease',
      marginBottom: '32px',
    },
    table: {
      '& .MuiTableCell-head': {
        backgroundColor: isDarkMode ? '#334155' : '#f8fafc',
        color: isDarkMode ? '#94a3b8' : '#475569',
        fontWeight: '600',
        padding: '16px 24px',
        borderBottom: `1px solid ${isDarkMode ? '#475569' : '#e2e8f0'}`,
        fontSize: '13px',
        textTransform: 'uppercase',
        letterSpacing: '0.5px',
        transition: 'all 0.3s ease',
        whiteSpace: 'nowrap',
      },
      '& .MuiTableCell-body': {
        padding: '16px 24px',
        color: isDarkMode ? '#f1f5f9' : '#334155',
        borderBottom: `1px solid ${isDarkMode ? '#475569' : '#e2e8f0'}`,
        fontSize: '14px',
        transition: 'all 0.3s ease',
        maxWidth: '300px',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      },
    },
    eventChip: (severity) => ({
      backgroundColor: getSeverityColor(severity),
      color: getSeverityTextColor(severity),
      fontWeight: '500',
      fontSize: '12px',
      height: '28px',
      transition: 'all 0.3s ease',
      display: 'flex',
      alignItems: 'center',
      gap: '4px',
      padding: '0 12px',
      '&:hover': {
        backgroundColor: isDarkMode ? 'rgba(72, 128, 255, 0.25)' : '#bae6fd',
      },
    }),
    actionButton: {
      color: isDarkMode ? '#93c5fd' : '#0284c7',
      textDecoration: 'none',
      fontSize: '14px',
      fontWeight: '500',
      transition: 'color 0.3s ease',
      '&:hover': {
        color: isDarkMode ? '#60a5fa' : '#0369a1',
        textDecoration: 'underline',
      },
    },
    refreshButton: {
      textTransform: 'none',
      borderColor: isDarkMode ? '#475569' : '#e2e8f0',
      color: isDarkMode ? '#94a3b8' : '#475569',
      transition: 'all 0.3s ease',
      padding: '8px 16px',
      fontSize: '14px',
      '&:hover': {
        borderColor: isDarkMode ? '#64748b' : '#cbd5e1',
        backgroundColor: isDarkMode ? '#334155' : '#f8fafc',
      },
    },
    exportButton: {
      textTransform: 'none',
      backgroundColor: isDarkMode ? '#4880ff' : '#0284c7',
      transition: 'background-color 0.3s ease',
      padding: '8px 16px',
      fontSize: '14px',
      '&:hover': {
        backgroundColor: isDarkMode ? '#6496ff' : '#0369a1',
      },
    },
    paginationContainer: {
      display: 'flex',
      justifyContent: 'center',
      marginTop: '32px',
      '& .MuiPaginationItem-root': {
        color: isDarkMode ? '#f1f5f9' : '#334155',
        fontSize: '14px',
      },
      '& .Mui-selected': {
        backgroundColor: isDarkMode ? '#4880ff' : '#0284c7',
        color: '#ffffff',
      },
    },
  };

  return (
    <Box sx={styles.container}>
      <Box sx={styles.header}>
        <Box sx={styles.headerLeft}>
          <Typography variant="h4" sx={styles.title}>
            Network Activity Log
          </Typography>
          <Typography variant="body1" sx={styles.subtitle}>
            Monitor and analyze network security events, threats, and anomalies
          </Typography>
        </Box>
        <Box sx={styles.headerRight}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={handleRefresh}
            sx={styles.refreshButton}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={exportLoading ? <CircularProgress size={20} color="inherit" /> : <DownloadIcon />}
            onClick={handleExport}
            sx={styles.exportButton}
            disabled={exportLoading}
          >
            {exportLoading ? 'Exporting...' : 'Export Logs'}
          </Button>
        </Box>
      </Box>

      <Box sx={styles.searchAndFilters}>
        <TextField
          placeholder="Search by IP, event type, or details"
          variant="outlined"
          fullWidth
          value={search}
          onChange={handleSearchChange}
          sx={styles.searchField}
          InputProps={{
            startAdornment: <SearchIcon sx={{ color: isDarkMode ? '#94a3b8' : '#94a3b8', mr: 1 }} />,
          }}
        />
        <FormControl sx={styles.filterSelect}>
          <InputLabel>Event Type</InputLabel>
          <Select 
            label="Event Type" 
            value={eventType}
            onChange={handleEventTypeChange}
          >
            <MenuItem value="">All events</MenuItem>
            <MenuItem value="DDoS">DDoS Attacks</MenuItem>
            <MenuItem value="Port Scan">Port Scans</MenuItem>
            <MenuItem value="Brute Force">Brute Force</MenuItem>
            <MenuItem value="Malware">Malware</MenuItem>
            <MenuItem value="Protocol Anomaly">Protocol Anomalies</MenuItem>
          </Select>
        </FormControl>
        <FormControl sx={styles.filterSelect}>
          <InputLabel>Severity</InputLabel>
          <Select 
            label="Severity" 
            value={severity}
            onChange={handleSeverityChange}
          >
            <MenuItem value="">All severities</MenuItem>
            <MenuItem value="critical">Critical</MenuItem>
            <MenuItem value="high">High</MenuItem>
            <MenuItem value="medium">Medium</MenuItem>
            <MenuItem value="low">Low</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
          <CircularProgress />
        </Box>
      ) : error ? (
        <Box sx={{ p: 3, textAlign: 'center', color: 'error.main' }}>
          {error}
        </Box>
      ) : (
        <>
      <TableContainer component={Paper} sx={styles.tableContainer}>
        <Table sx={styles.table}>
          <TableHead>
            <TableRow>
              <TableCell>Date & Time</TableCell>
              <TableCell>Event</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Source IP</TableCell>
                  <TableCell>Destination IP</TableCell>
                  <TableCell>Protocol</TableCell>
                  <TableCell>Details</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
                {logs.map((log) => (
              <TableRow 
                    key={log.id} 
                hover 
                sx={{ 
                  '&:hover': { 
                    backgroundColor: isDarkMode ? '#334155' : '#f8fafc',
                    '& .MuiTableCell-root': {
                      borderBottom: `1px solid ${isDarkMode ? '#475569' : '#e2e8f0'}`,
                    }
                  },
                  transition: 'background-color 0.3s ease',
                }}
              >
                <TableCell>{log.date} {log.time}</TableCell>
                    <TableCell>{log.event}</TableCell>
                <TableCell>
                  <Chip 
                        label={log.severity.toUpperCase()} 
                    size="small" 
                        icon={getSeverityIcon(log.severity)}
                        sx={styles.eventChip(log.severity)}
                  />
                </TableCell>
                    <TableCell>{log.source_ip}</TableCell>
                    <TableCell>{log.destination_ip}</TableCell>
                    <TableCell>{log.protocol}</TableCell>
                    <TableCell>{formatDetails(log.details)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

          <Box sx={styles.paginationContainer}>
            <Pagination 
              count={totalPages} 
              page={page} 
              onChange={handlePageChange}
              color="primary"
            />
          </Box>
        </>
      )}

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert 
          onClose={handleCloseSnackbar} 
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default ActivityLog;