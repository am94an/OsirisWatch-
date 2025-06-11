import React, { useState, useEffect } from "react";
import ThreatTrendsChart from "../charts/LineCharts";
import SunburstChart from "../charts/SunburstChart";
import AlarmingHostsChart from "../charts/AlarmingHostsChart";
import AttackVectorsChart from "../charts/AttackVectorsChart";
import TopAlarmingHosts from "../charts/TopAlarmingHosts";
import "../../styles/DataAnalysis.css";
import { fetchDataAnalysis } from "../../services/api";
import { CircularProgress } from "@mui/material";

const DataAnalysis = () => {
  const [dataAnalysisData, setDataAnalysisData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
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
    
    // Listen for storage events (from other tabs) and local events
    window.addEventListener('storage', handleDarkModeChange);
    window.addEventListener('storage-local', handleDarkModeChange);
    
    return () => {
      window.removeEventListener('storage', handleDarkModeChange);
      window.removeEventListener('storage-local', handleDarkModeChange);
    };
  }, []);

  useEffect(() => {
    const loadDataAnalysis = async () => {
      try {
        setLoading(true);
        const response = await fetchDataAnalysis();
        console.log('Data analysis response:', response);
        setDataAnalysisData(response);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching data analysis:", error);
        setError("Failed to load data analysis information. Please try again.");
        setLoading(false);
      }
    };

    loadDataAnalysis();
  }, []);

  // Styles for dark mode
  const styles = {
    container: {
      backgroundColor: darkMode ? '#1E293B' : '#f9f9f9',
      color: darkMode ? '#e0e0e0' : '#333'
    },
    title: {
      color: darkMode ? '#e0e0e0' : '#333'
    },
    loading: {
      backgroundColor: darkMode ? '#1E293B' : '#f9f9f9',
      color: darkMode ? '#e0e0e0' : '#333'
    },
    chartContainer: {
      backgroundColor: darkMode ? '#273142' : '#ffffff',
      border: darkMode ? '1px solid #3A4557' : '1px solid #e0e0e0',
      boxShadow: darkMode ? '0 4px 6px rgba(0, 0, 0, 0.3)' : '0 1px 3px rgba(0, 0, 0, 0.1)'
    },
    chartTitle: {
      color: darkMode ? '#e0e0e0' : '#333'
    }
  };

  if (loading) {
    return (
      <div className="loading-container" style={styles.loading}>
        <CircularProgress style={{ color: darkMode ? '#4299E1' : '#3B82F6' }} />
        <p>Loading data analysis...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error-container" style={styles.loading}>
        <h3 style={styles.title}>Error</h3>
        <p>{error}</p>
        <button 
          onClick={() => window.location.reload()}
          style={{
            backgroundColor: darkMode ? '#3B82F6' : '#4299E1',
            color: '#fff',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Retry
        </button>
      </div>
    );
  }

  if (!dataAnalysisData) {
    return (
      <div className="error-container" style={styles.loading}>
        <h3 style={styles.title}>No Data Available</h3>
        <p>No data analysis information is currently available.</p>
        <button 
          onClick={() => window.location.reload()}
          style={{
            backgroundColor: darkMode ? '#3B82F6' : '#4299E1',
            color: '#fff',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Refresh
        </button>
      </div>
    );
  }

  // Extract data for charts with proper error handling
  const extractData = (path, defaultValue = []) => {
    try {
      const parts = path.split('.');
      let result = dataAnalysisData;
      
      for (const part of parts) {
        if (result && typeof result === 'object' && part in result) {
          result = result[part];
        } else {
          return defaultValue;
        }
      }
      
      return result || defaultValue;
    } catch (error) {
      console.error(`Error extracting ${path}:`, error);
      return defaultValue;
    }
  };

  // Process data for each chart
  const processThreatTrendsData = (data) => {
    if (!data) return [];
    if (data.categories && data.series && data.series[0] && data.series[0].data) {
      return data.series[0].data.map((value, index) => ({
        name: data.categories[index] || `Category ${index + 1}`,
        count: value || 0
      }));
    }
    return [];
  };

  const processNetworkTrafficData = (data) => {
    if (!data) return {
      tcp: { http: 0, https: 0, ftp: 0 },
      udp: { dns: 0, dhcp: 0, snmp: 0 }
    };
    
    // Return the data as is since it's already in the correct format
    return data;
  };

  const processAlarmingHostsData = (data) => {
    if (!Array.isArray(data)) return [];
    return data.map(host => ({
      ip_address: host.host || host.ip,
      count: host.incidents || host.count || 0,
      alarm_count: host.incidents || host.count || 0,
      value: host.incidents || host.count || 0,
      threat_level: host.threat_level
    }));
  };

  const processAttackVectorsData = (data) => {
    if (!Array.isArray(data)) return [];
    return data.map(vector => ({
      name: vector.name,
      count: vector.value || vector.count || 0,
      attack_type: vector.details?.type || vector.name,
      type: vector.details?.type || vector.name,
      threat_name: vector.name
    }));
  };

  // Get and process data for each chart
  const threatTrendsData = processThreatTrendsData(extractData('data_analysis.threat_trends') || extractData('data_analysis.top_threats'));
  const topApplicationsData = processNetworkTrafficData(extractData('data_analysis.network_traffic', {}));
  const alarmingHostsData = processAlarmingHostsData(extractData('data_analysis.alarming_hosts') || extractData('data_analysis.suspicious_ips.recent'));
  const attackVectorsData = processAttackVectorsData(extractData('data_analysis.attack_vectors') || extractData('data_analysis.top_threats'));

  // Add debug logging
  console.log('Processed Data:', {
    threatTrendsData,
    topApplicationsData,
    alarmingHostsData,
    attackVectorsData
  });

  return (
    <div className="data-analysis-page" style={styles.container}>
      <p className="title-page" style={styles.title}>Data Analysis</p>
      <main className="content-data">
        <div className="conatiner-chart chart1" style={styles.chartContainer}>
          <p style={styles.chartTitle}>Threat Trends</p>
          <ThreatTrendsChart data={threatTrendsData} />
        </div>
        <div className="conatiner-chart chart2" style={styles.chartContainer}>
          <p style={styles.chartTitle}>Top Applications</p>
          <SunburstChart data={topApplicationsData} />
        </div>
        <div className="conatiner-chart" style={styles.chartContainer}>
          <AlarmingHostsChart data={alarmingHostsData} />
        </div>
        <div className="conatiner-chart" style={styles.chartContainer}>
          <AttackVectorsChart data={attackVectorsData} />
        </div>
      </main>
      <TopAlarmingHosts data={alarmingHostsData} />
    </div>
  );
};

export default DataAnalysis;
