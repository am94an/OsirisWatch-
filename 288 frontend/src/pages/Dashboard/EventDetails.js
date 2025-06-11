import React, { useState, useEffect } from "react";
import { Box, Typography, Grid, Card, CardContent, Menu, MenuItem, IconButton, CircularProgress, Alert } from "@mui/material";
import ChartDataLabels from 'chartjs-plugin-datalabels';
import "./EventDetails.css";
import { Sparklines, SparklinesLine  } from 'react-sparklines';
import {
  LineChart,
  Line as RechartsLine,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
} from "recharts";
import { Bar, Line } from "react-chartjs-2";
import annotationPlugin from 'chartjs-plugin-annotation';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  Title,
  Tooltip,
  Legend,
} from "chart.js";
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';
import { fetchNetworkAlerts } from '../../services/api';

ChartJS.register(ChartDataLabels);
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  Title,
  Tooltip,
  Legend,
  annotationPlugin
);

const App = () => {
  const [timeFrameAnchor, setTimeFrameAnchor] = useState(null);
  const [siteAnchor, setSiteAnchor] = useState(null);
  const [threatTypeAnchor, setThreatTypeAnchor] = useState(null);
  const [selectedTimeFrame, setSelectedTimeFrame] = useState('Last 24 Hours');
  const [selectedSite, setSelectedSite] = useState('All Sites');
  const [selectedThreatType, setSelectedThreatType] = useState('All Threats');
  const [activeSecurityBlockTab, setActiveSecurityBlockTab] = useState('BY IDENTITY');
  const [selectedChartPeriod, setSelectedChartPeriod] = useState('Month');
  const [chartPeriodAnchor, setChartPeriodAnchor] = useState(null);
  const [requests, setRequests] = useState([]);
  const [securityBlocks, setSecurityBlocks] = useState([]);
  const [eventsData, setEventsData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [apiData, setApiData] = useState(null);
  const [selectedNetworkSegment, setSelectedNetworkSegment] = useState('All Segments');
  const [selectedAlertCategory, setSelectedAlertCategory] = useState('All Alerts');
  const [activeSecurityControlTab, setActiveSecurityControlTab] = useState('BY IDENTITY');

  // Add totalDevices constant
  const totalDevices = 100; // Total number of devices in the network

  // Realistic events data showing daily patterns
  const mockEventsData = [
    { day: "Mon", value: 15, time: "00:00", timestamp: new Date(2024, 2, 18, 0, 0), status: 'detected', deviceId: 'DEV001', wasThreat: true, site: 'Umbrella HQ', threatType: 'Malware', responseTime: 120 },
    { day: "Mon", value: 25, time: "04:00", timestamp: new Date(2024, 2, 18, 4, 0), status: 'resolved', deviceId: 'DEV002', wasThreat: true, site: 'Umbrella Branch 1', threatType: 'Phishing', responseTime: 180 },
    { day: "Tue", value: 35, time: "08:00", timestamp: new Date(2024, 2, 19, 8, 0), status: 'detected', deviceId: 'DEV003', wasThreat: true, site: 'NYC Office', threatType: 'Ransomware', responseTime: 90 },
    { day: "Tue", value: 45, time: "12:00", timestamp: new Date(2024, 2, 19, 12, 0), status: 'resolved', deviceId: 'DEV004', wasThreat: false, site: 'Default Site', threatType: 'DDoS', responseTime: 150 },
    { day: "Wed", value: 55, time: "16:00", timestamp: new Date(2024, 2, 20, 16, 0), status: 'detected', deviceId: 'DEV005', wasThreat: true, site: 'Umbrella HQ', threatType: 'Data Exfiltration', responseTime: 200 },
    { day: "Wed", value: 40, time: "20:00", timestamp: new Date(2024, 2, 20, 20, 0), status: 'resolved', deviceId: 'DEV001', wasThreat: true, site: 'Umbrella Branch 1', threatType: 'Malware', responseTime: 160 },
    { day: "Thu", value: 30, time: "00:00", timestamp: new Date(2024, 2, 21, 0, 0), status: 'detected', deviceId: 'DEV002', wasThreat: true, site: 'NYC Office', threatType: 'Phishing', responseTime: 140 },
    { day: "Thu", value: 20, time: "04:00", timestamp: new Date(2024, 2, 21, 4, 0), status: 'resolved', deviceId: 'DEV003', wasThreat: false, site: 'Default Site', threatType: 'Ransomware', responseTime: 110 },
    { day: "Fri", value: 35, time: "08:00", timestamp: new Date(2024, 2, 22, 8, 0), status: 'detected', deviceId: 'DEV004', wasThreat: true, site: 'Umbrella HQ', threatType: 'DDoS', responseTime: 170 },
    { day: "Fri", value: 50, time: "12:00", timestamp: new Date(2024, 2, 22, 12, 0), status: 'resolved', deviceId: 'DEV005', wasThreat: true, site: 'Umbrella Branch 1', threatType: 'Data Exfiltration', responseTime: 190 },
    { day: "Sat", value: 60, time: "16:00", timestamp: new Date(2024, 2, 23, 16, 0), status: 'detected', deviceId: 'DEV001', wasThreat: true, site: 'NYC Office', threatType: 'Malware', responseTime: 130 },
    { day: "Sat", value: 45, time: "20:00", timestamp: new Date(2024, 2, 23, 20, 0), status: 'resolved', deviceId: 'DEV002', wasThreat: true, site: 'Default Site', threatType: 'Phishing', responseTime: 145 },
    { day: "Sun", value: 30, time: "00:00", timestamp: new Date(2024, 2, 24, 0, 0), status: 'detected', deviceId: 'DEV003', wasThreat: true, site: 'Umbrella HQ', threatType: 'Ransomware', responseTime: 125 },
    { day: "Sun", value: 20, time: "04:00", timestamp: new Date(2024, 2, 24, 4, 0), status: 'resolved', deviceId: 'DEV004', wasThreat: false, site: 'Umbrella Branch 1', threatType: 'DDoS', responseTime: 155 }
  ];

  // Calculate total events and active events
  const totalEvents = mockEventsData.reduce((sum, item) => sum + item.value, 0);
  const activeEvents = Math.floor(totalEvents * 0.7);

  const timeFrames = [
    'Last 60 Minutes',
    'Last 24 Hours',
    'Last Week',
    'Last Month',
    'Last Quarter',
    'Historical Data'
  ];

  const sites = [
    'All Sites',
    'Umbrella HQ',
    'Umbrella Branch 1',
    'NYC Office',
    'Default Site'
  ];

  const threatTypes = [
    'All Threats',
    'Malware',
    'Phishing',
    'Ransomware',
    'DDoS',
    'Data Exfiltration'
  ];

  const networkSegments = [
    'All Segments',
    'Umbrella HQ',
    'Umbrella Branch 1',
    'NYC Office',
    'Default Segment'
  ];

  const alertCategories = [
    'All Alerts',
    'Malware',
    'Suspicious Activity',
    'Denial of Service'
  ];

  // Add chart period data
  const chartPeriodData = {
    'Day': {
      labels: ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"],
      data: [15, 25, 35, 45, 55, 40]
    },
    'Week': {
      labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
      data: [40, 80, 95, 50, 85, 105, 50]
    },
    'Month': {
      labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
      data: [100, 150, 150, 250, 280, 200, 250, 90, 300, 350, 390, 400]
    }
  };

  // Add security block data
  const securityBlockData = {
    'BY DESTINATION': {
      labels: ["Umbrella HQ", "Umbrella Branch 1", "NYC Office", "Default Site"],
      datasets: [{
        label: "",
        data: [470, 300, 200, 50],
        backgroundColor: "#42a5f5",
        barPercentage: 0.6,
        categoryPercentage: 0.3,
      }],
    },
    'BY IDENTITY': {
      labels: ["Admin Users", "Regular Users", "Service Accounts", "Guests"],
      datasets: [{
        label: "",
        data: [470, 300, 200, 50],
        backgroundColor: "#42a5f5",
        barPercentage: 0.6,
        categoryPercentage: 0.3,
      }],
    },
    'BY TYPE': {
      labels: ["Malware", "Phishing", "Ransomware", "DDoS", "Data Exfiltration"],
      datasets: [{
        label: "",
        data: [350, 280, 150, 200, 120],
        backgroundColor: "#42a5f5",
        barPercentage: 0.6,
        categoryPercentage: 0.3,
      }],
    }
  };

  // Fetch data from API
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const params = {
          timeFrame: selectedTimeFrame,
          site: selectedSite,
          threatType: selectedThreatType,
          chartPeriod: selectedChartPeriod,
          securityBlockCategory: activeSecurityBlockTab
        };
        
        const response = await fetchNetworkAlerts(params);
        setApiData(response);
        
        // Process events data
        if (response.events && Array.isArray(response.events)) {
          const processedEvents = response.events.map(event => ({
            id: event.id,
            flow_id: event.flow_id,
            timestamp: new Date(event.timestamp),
            source_ip: event.source_ip,
            destination_ip: event.destination_ip,
            protocol: event.protocol,
            threat_level: event.threat_level,
            threats: event.threats || [],
            alerts: event.alerts || [],
            suspicious_ips: event.suspicious_ips || []
          }));
          setEventsData(processedEvents);
        }
        
        // Process statistics
        if (response.statistics) {
          setRequests([{
            value: response.statistics.total_events || 0,
            previousValue: response.statistics.active_events || 0
          }]);
        }
        
        // Process security blocks
        if (response.charts && response.charts.threatsOverTime) {
          setSecurityBlocks([{
            value: response.charts.threatsOverTime.data.reduce((a, b) => a + b, 0),
            previousValue: response.charts.threatsOverTime.data[0] || 0
          }]);
        }
      } catch (err) {
        console.error('Error fetching security events:', err);
        setError('Failed to load data. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [selectedTimeFrame, selectedSite, selectedThreatType, selectedChartPeriod, activeSecurityBlockTab]);

  const handleTimeFrameClick = (event) => {
    setTimeFrameAnchor(event.currentTarget);
  };

  const handleSiteClick = (event) => {
    setSiteAnchor(event.currentTarget);
  };

  const handleThreatTypeClick = (event) => {
    setThreatTypeAnchor(event.currentTarget);
  };

  const handleTimeFrameClose = () => {
    setTimeFrameAnchor(null);
  };

  const handleSiteClose = () => {
    setSiteAnchor(null);
  };

  const handleThreatTypeClose = () => {
    setThreatTypeAnchor(null);
  };

  const handleTimeFrameSelect = (timeFrame) => {
    setSelectedTimeFrame(timeFrame);
    handleTimeFrameClose();
  };

  const handleSiteSelect = (site) => {
    setSelectedSite(site);
    handleSiteClose();
  };

  const handleThreatTypeSelect = (threatType) => {
    setSelectedThreatType(threatType);
    handleThreatTypeClose();
  };

  // Process API data for charts
  const processChartData = () => {
    if (!apiData) {
      // Return mock data if no API data
      return {
        barData: {
          labels: chartPeriodData[selectedChartPeriod].labels,
          datasets: [{
            label: "Threats Over Time",
            data: chartPeriodData[selectedChartPeriod].data,
            backgroundColor: "#42a5f5",
            barPercentage: 0.6,
            categoryPercentage: 0.3,
            fill: true
          }]
        },
        securityBlockData: securityBlockData
      };
    }

    const { events, requests, securityBlocks, charts } = apiData;

    // Process threats over time chart
    const barData = {
      labels: charts?.threatsOverTime?.labels || chartPeriodData[selectedChartPeriod].labels,
      datasets: [
        {
          label: "Threats Over Time",
          data: charts?.threatsOverTime?.data || chartPeriodData[selectedChartPeriod].data,
          backgroundColor: "#42a5f5",
          barPercentage: 0.6,
          categoryPercentage: 0.3,
          fill: true
        },
      ],
    };

    // Process security blocks data
    const processedSecurityBlockData = {
      [activeSecurityBlockTab]: {
        labels: securityBlocks?.breakdown?.labels || securityBlockData[activeSecurityBlockTab].labels,
        datasets: [{
          label: "",
          data: securityBlocks?.breakdown?.data || securityBlockData[activeSecurityBlockTab].datasets[0].data,
          backgroundColor: "#42a5f5",
          barPercentage: 0.6,
          categoryPercentage: 0.3,
        }],
      }
    };

    return { barData, securityBlockData: processedSecurityBlockData };
  };

  const chartData = processChartData();

  // Loading state
  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  // Error state
  if (error) {
    return (
      <Box p={3}>
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  // Update barData to use selected period
  const barData = {
    labels: chartPeriodData[selectedChartPeriod].labels,
    datasets: [
      {
        label: "Threats Over Time",
        data: chartPeriodData[selectedChartPeriod].data,
        backgroundColor: "#42a5f5",
        barPercentage: 0.6,
        categoryPercentage: 0.3,
        fill: true
      },
    ],
  };

  const barOptions = {
    responsive: true,
    scales: {
      x: {
        barPercentage: 0.6,
        categoryPercentage: 0.3,
        grid: {
          display: false,
        },
      },
      y: {
        beginAtZero: true,
        ticks: {
          stepSize: 100,
        },
        min: 0,
        max: 400,
        grid: {
          display: false,
        },
      },
    },
    elements: {
      bar: {
        borderRadius: 20,
      },
    },
    plugins: {
      tooltip: {
        enabled: true,
      },
      datalabels: {
        display: false,
      },
    },
  };

  const securityBlockOptions = {
    indexAxis: "y",
    scales: {
      x: {
        beginAtZero: true,
        display: false,
      },
      y: {
        grid: {
          display: false,
        },
      }
    },
    elements: {
      bar: {
        borderRadius: 100,
      },
    },
    plugins: {
      tooltip: {
        enabled: true,
      },
      datalabels: {
        display: false,
      },
    },
  };

  // Helper functions for calculations
  const calculateAverageResponseTime = (alerts) => {
    const resolvedAlerts = alerts.filter(a => a.status === 'resolved');
    if (resolvedAlerts.length === 0) return '0m 0s';
    
    const totalTime = resolvedAlerts.reduce((sum, a) => sum + (a.responseTime || 0), 0);
    const avgTime = totalTime / resolvedAlerts.length;
    
    const minutes = Math.floor(avgTime / 60);
    const seconds = Math.floor(avgTime % 60);
    
    return `${minutes}m ${seconds}s`;
  };

  const calculateAffectedDevices = (alerts) => {
    const uniqueDevices = new Set(alerts.map(a => a.deviceId));
    return totalDevices === 0 ? 0 : Math.round((uniqueDevices.size / totalDevices) * 100);
  };

  const calculateAlertAccuracy = (alerts) => {
    const truePositives = alerts.filter(a => a.status === 'resolved' && a.confirmed).length;
    const totalDetected = alerts.filter(a => a.status === 'resolved').length;
    return totalDetected === 0 ? 0 : Math.round((truePositives / totalDetected) * 100);
  };

  const calculateAlertTrend = (alerts) => {
    const currentPeriod = alerts.filter(a => a.timestamp >= new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)).length;
    const previousPeriod = alerts.filter(a => 
      a.timestamp >= new Date(Date.now() - 14 * 24 * 60 * 60 * 1000) && 
      a.timestamp < new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
    ).length;
    return previousPeriod === 0 ? 0 : Math.round(((currentPeriod - previousPeriod) / previousPeriod) * 100);
  };

  // Filter data based on selected filters
  const filterData = (data, timeFrame, networkSegment, alertCategory) => {
    let filteredData = [...data];

    // Filter by time frame
    if (timeFrame !== 'Historical Data') {
      const now = new Date();
      const timeFrameMap = {
        'Last 60 Minutes': 1,
        'Last 24 Hours': 24,
        'Last Week': 7 * 24,
        'Last Month': 30 * 24,
        'Last Quarter': 90 * 24
      };
      const hours = timeFrameMap[timeFrame];
      const cutoffTime = new Date(now - hours * 60 * 60 * 1000);
      filteredData = filteredData.filter(item => new Date(item.timestamp) >= cutoffTime);
    }

    // Filter by network segment
    if (networkSegment !== 'All Segments') {
      filteredData = filteredData.filter(item => item.networkSegment === networkSegment);
    }

    // Filter by alert category
    if (alertCategory !== 'All Alerts') {
      filteredData = filteredData.filter(item => item.alertCategory === alertCategory);
    }

    return filteredData;
  };

  // Update data based on filters
  const getFilteredData = () => {
    if (!apiData) {
      // Return mock data if no API data
      return {
        alerts: mockEventsData,
        flows: mockEventsData,
        securityControls: mockEventsData
      };
    }

    // Process network traffic data
    const networkTrafficData = apiData.flows?.map(flow => ({
      time: flow.timestamp,
      value: flow.packet_count || 0,
      previousValue: flow.previous_packet_count || 0
    })) || mockEventsData;

    // Process threat detection data
    const threatDetectionData = apiData.events?.map(event => ({
      time: event.timestamp,
      value: event.threat_count || 0,
      previousValue: event.previous_threat_count || 0
    })) || mockEventsData;

    // Process policy violations data
    const policyViolationsData = apiData.securityControls?.map(control => ({
      time: control.timestamp,
      value: control.violation_count || 0,
      previousValue: control.previous_violation_count || 0
    })) || mockEventsData;

    // Keep original Events data
    const originalEventsData = mockEventsData;

    return {
      alerts: originalEventsData,
      flows: networkTrafficData,
      securityControls: policyViolationsData
    };
  };

  const filteredData = getFilteredData();

  // Calculate metrics based on filtered data
  const calculateMetrics = () => {
    if (!apiData) return {
      detectedThreats: { current: 12, total: 15 },
      resolvedThreats: 8,
      averageResponseTime: '45m 30s',
      affectedDevices: 15,
      threatDetectionAccuracy: 92,
      threatsGrowth: 5,
      allRequestsTotal: 15000,
      blockedRequestsTotal: 5000,
      securityControlsTotal: 3000
    };

    const { statistics, events } = apiData;

    // Use mock data if API values are zero or not available
    return {
      detectedThreats: {
        current: statistics.active_events || 12,
        total: statistics.total_events || 15
      },
      resolvedThreats: (statistics.total_events || 15) - (statistics.active_events || 12),
      averageResponseTime: statistics.avg_response_time || '45m 30s',
      affectedDevices: statistics.affected_devices || 15,
      threatDetectionAccuracy: statistics.alert_accuracy || 92,
      threatsGrowth: statistics.alert_trend || 5,
      allRequestsTotal: statistics.total_events || 15000,
      blockedRequestsTotal: events?.filter(e => e.threat_level === 'high').length || 5000,
      securityControlsTotal: events?.filter(e => e.alerts && e.alerts.length > 0).length || 3000
    };
  };

  const metrics = calculateMetrics();

  // Calculate percentage changes
  const calculatePercentageChange = (current, previous) => {
    return ((current - previous) / previous * 100).toFixed(1);
  };

  const allRequestsTotal = requests.reduce((sum, item) => sum + item.value, 0);
  const allRequestsPreviousTotal = requests.reduce((sum, item) => sum + item.previousValue, 0);
  const allRequestsChange = calculatePercentageChange(allRequestsTotal, allRequestsPreviousTotal);

  const blockedRequestsTotal = requests.reduce((sum, item) => sum + item.value, 0);
  const blockedRequestsPreviousTotal = requests.reduce((sum, item) => sum + item.previousValue, 0);
  const blockedRequestsChange = calculatePercentageChange(blockedRequestsTotal, blockedRequestsPreviousTotal);

  const securityBlocksTotal = securityBlocks.reduce((sum, item) => sum + item.value, 0);
  const securityBlocksPreviousTotal = securityBlocks.reduce((sum, item) => sum + item.previousValue, 0);
  const securityBlocksChange = calculatePercentageChange(securityBlocksTotal, securityBlocksPreviousTotal);

  // Update the card content with filtered data
  const renderCardContent = (title, value, unit = '', sparklineData = null, valueStyle = {}) => (
    <CardContent sx={{ p: 0 }}>
      <Typography variant="h6" sx={{ 
        fontSize: "13px", 
        color: "#555555", 
        fontWeight: "600",
        mb: 2
      }}>
        {title}
      </Typography>
      <Typography variant="h4" sx={{ 
        fontSize: valueStyle.fontSize || "28px", 
        fontWeight: "bold",
        mb: sparklineData ? 2 : 1,
        ...valueStyle
      }}>
        {value}{unit}
      </Typography>
      {sparklineData && (
        <Sparklines data={sparklineData} limit={15} width={100} height={20} margin={5}>
          <SparklinesLine color="#42a5f5" style={{ strokeWidth: 2, fill: "none" }} />
        </Sparklines>
      )}
    </CardContent>
  );

  const handleChartPeriodClick = (event) => {
    setChartPeriodAnchor(event.currentTarget);
  };

  const handleChartPeriodClose = () => {
    setChartPeriodAnchor(null);
  };

  const handleChartPeriodSelect = (period) => {
    setSelectedChartPeriod(period);
    handleChartPeriodClose();
  };

  const handleNetworkSegmentClick = (event) => {
    setSelectedNetworkSegment(event.currentTarget.textContent);
  };

  const handleAlertCategoryClick = (event) => {
    setSelectedAlertCategory(event.currentTarget.textContent);
  };

  return (
    <Box sx={{ padding: 3 }}>
      <Typography
        variant="h4"
        sx={{
          color: "#1976d2",
          fontWeight: "bold",
          fontSize: "1.75rem",
          mb: 3
        }}
      >
        Security Events Overview
      </Typography>

      <Box sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        gap: 2, 
        width: '100%', 
        mb: 4,
        flexWrap: 'wrap'
      }}>
        {/* Time Frame Filter */}
        <Box
          sx={{
            backgroundColor: '#fff',
            border: '1px solid #e0e0e0',
            borderRadius: '8px',
            padding: '12px 16px',
            display: 'flex',
            alignItems: 'center',
            width: 'calc(33.33% - 16px)',
            minWidth: '250px',
            transition: 'all 0.2s ease',
            cursor: 'pointer',
            '&:hover': {
              backgroundColor: '#f5f9ff',
              borderColor: '#42a5f5',
              boxShadow: '0 2px 4px rgba(66, 165, 245, 0.1)',
            },
          }}
          onClick={handleTimeFrameClick}
        >
          <Typography variant="body1" sx={{ 
            color: '#666', 
            marginRight: 1,
            fontSize: '0.875rem'
          }}>Analysis Period: </Typography>
          <Typography variant="body2" sx={{ 
            fontWeight: '600', 
            color: '#000',
            fontSize: '0.875rem'
          }}>{selectedTimeFrame}</Typography>
          <IconButton 
            size="small" 
            sx={{ 
              marginLeft: 'auto',
              padding: '2px',
              color: '#666'
            }}
          >
            <KeyboardArrowDownIcon />
          </IconButton>
        </Box>

        {/* Network Segment Filter */}
        <Box
          sx={{
            backgroundColor: '#fff',
            border: '1px solid #e0e0e0',
            borderRadius: '8px',
            padding: '12px 16px',
            display: 'flex',
            alignItems: 'center',
            width: 'calc(33.33% - 16px)',
            minWidth: '250px',
            transition: 'all 0.2s ease',
            cursor: 'pointer',
            '&:hover': {
              backgroundColor: '#f5f9ff',
              borderColor: '#42a5f5',
              boxShadow: '0 2px 4px rgba(66, 165, 245, 0.1)',
            },
          }}
          onClick={handleNetworkSegmentClick}
        >
          <Typography variant="body1" sx={{ 
            color: '#666', 
            marginRight: 1,
            fontSize: '0.875rem'
          }}>Network Segment: </Typography>
          <Typography variant="body2" sx={{ 
            fontWeight: '600', 
            color: '#000',
            fontSize: '0.875rem'
          }}>{selectedNetworkSegment}</Typography>
          <IconButton 
            size="small" 
            sx={{ 
              marginLeft: 'auto',
              padding: '2px',
              color: '#666'
            }}
          >
            <KeyboardArrowDownIcon />
          </IconButton>
        </Box>

        {/* Alert Category Filter */}
        <Box
          sx={{
            backgroundColor: '#fff',
            border: '1px solid #e0e0e0',
            borderRadius: '8px',
            padding: '12px 16px',
            display: 'flex',
            alignItems: 'center',
            width: 'calc(33.33% - 16px)',
            minWidth: '250px',
            transition: 'all 0.2s ease',
            cursor: 'pointer',
            '&:hover': {
              backgroundColor: '#f5f9ff',
              borderColor: '#42a5f5',
              boxShadow: '0 2px 4px rgba(66, 165, 245, 0.1)',
            },
          }}
          onClick={handleAlertCategoryClick}
        >
          <Typography variant="body1" sx={{ 
            color: '#666', 
            marginRight: 1,
            fontSize: '0.875rem'
          }}>Alert Category: </Typography>
          <Typography variant="body2" sx={{ 
            fontWeight: '600', 
            color: '#000',
            fontSize: '0.875rem'
          }}>{selectedAlertCategory}</Typography>
          <IconButton 
            size="small" 
            sx={{ 
              marginLeft: 'auto',
              padding: '2px',
              color: '#666'
            }}
          >
            <KeyboardArrowDownIcon />
          </IconButton>
        </Box>

        {/* Dropdown Menus */}
        <Menu
          anchorEl={timeFrameAnchor}
          open={Boolean(timeFrameAnchor)}
          onClose={handleTimeFrameClose}
          PaperProps={{
            sx: {
              mt: 1,
              boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
              borderRadius: '8px',
              minWidth: '200px'
            }
          }}
        >
          {timeFrames.map((timeFrame) => (
            <MenuItem 
              key={timeFrame}
              onClick={() => handleTimeFrameSelect(timeFrame)}
              selected={selectedTimeFrame === timeFrame}
              sx={{
                fontSize: '0.875rem',
                padding: '8px 16px',
                '&:hover': {
                  backgroundColor: '#f5f9ff'
                },
                '&.Mui-selected': {
                  backgroundColor: '#e3f2fd',
                  '&:hover': {
                    backgroundColor: '#e3f2fd'
                  }
                }
              }}
            >
              {timeFrame}
            </MenuItem>
          ))}
        </Menu>

        <Menu
          anchorEl={siteAnchor}
          open={Boolean(siteAnchor)}
          onClose={handleSiteClose}
          PaperProps={{
            sx: {
              mt: 1,
              boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
              borderRadius: '8px',
              minWidth: '200px'
            }
          }}
        >
          {sites.map((site) => (
            <MenuItem 
              key={site}
              onClick={() => handleSiteSelect(site)}
              selected={selectedSite === site}
              sx={{
                fontSize: '0.875rem',
                padding: '8px 16px',
                '&:hover': {
                  backgroundColor: '#f5f9ff'
                },
                '&.Mui-selected': {
                  backgroundColor: '#e3f2fd',
                  '&:hover': {
                    backgroundColor: '#e3f2fd'
                  }
                }
              }}
            >
              {site}
            </MenuItem>
          ))}
        </Menu>

        <Menu
          anchorEl={threatTypeAnchor}
          open={Boolean(threatTypeAnchor)}
          onClose={handleThreatTypeClose}
          PaperProps={{
            sx: {
              mt: 1,
              boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
              borderRadius: '8px',
              minWidth: '200px'
            }
          }}
        >
          {threatTypes.map((threatType) => (
            <MenuItem 
              key={threatType}
              onClick={() => handleThreatTypeSelect(threatType)}
              selected={selectedThreatType === threatType}
              sx={{
                fontSize: '0.875rem',
                padding: '8px 16px',
                '&:hover': {
                  backgroundColor: '#f5f9ff'
                },
                '&.Mui-selected': {
                  backgroundColor: '#e3f2fd',
                  '&:hover': {
                    backgroundColor: '#e3f2fd'
                  }
                }
              }}
            >
              {threatType}
            </MenuItem>
          ))}
        </Menu>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Grid container spacing={3}>
            <Grid item xs={12} sm={4}>
              <Card sx={{ 
                height: 160, 
                padding: 2, 
                borderRadius: "12px",
                boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
                transition: 'all 0.2s ease',
                '&:hover': {
                  boxShadow: '0 4px 8px rgba(0,0,0,0.1)'
                }
              }}>
                {renderCardContent(
                  "Active Alerts",
                  `${metrics.detectedThreats.current}/${metrics.detectedThreats.total}`,
                  '',
                  null,
                  { fontSize: "32px" }
                )}
              </Card>
            </Grid>
            <Grid item xs={12} sm={4}>
              <Card sx={{ 
                height: 160, 
                padding: 2, 
                borderRadius: "12px",
                boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
                transition: 'all 0.2s ease',
                '&:hover': {
                  boxShadow: '0 4px 8px rgba(0,0,0,0.1)'
                }
              }}>
                {renderCardContent(
                  "Resolved Alerts",
                  metrics.resolvedThreats,
                  '',
                  null,
                  { fontSize: "32px" }
                )}
              </Card>
            </Grid>
            <Grid item xs={12} sm={4}>
              <Card sx={{ 
                height: 160, 
                padding: 2, 
                borderRadius: "12px",
                boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
                transition: 'all 0.2s ease',
                '&:hover': {
                  boxShadow: '0 4px 8px rgba(0,0,0,0.1)'
                }
              }}>
                {renderCardContent(
                  "Average Resolution Time",
                  metrics.averageResponseTime,
                  '',
                  null,
                  { fontSize: "32px" }
                )}
              </Card>
            </Grid>
            <Grid item xs={12} sm={4}>
              <Card sx={{ height: 160, padding: 2, borderRadius: "12px" }}>
                {renderCardContent(
                  "Impacted Endpoints",
                  `${metrics.affectedDevices}%`,
                  '',
                  filteredData.alerts.map(a => a.value)
                )}
              </Card>
            </Grid>
            <Grid item xs={12} sm={4}>
              <Card sx={{ height: 160, padding: 2, borderRadius: "12px" }}>
                {renderCardContent(
                  "Alert Accuracy",
                  `${metrics.threatDetectionAccuracy}%`,
                  '',
                  filteredData.alerts.map(a => a.value)
                )}
              </Card>
            </Grid>
            <Grid item xs={12} sm={4}>
              <Card sx={{ height: 160, padding: 2, borderRadius: "12px" }}>
                {renderCardContent(
                  "Alert Trend",
                  `${metrics.threatsGrowth > 0 ? '+' : ''}${metrics.threatsGrowth}%`,
                  '',
                  filteredData.alerts.map(a => a.value)
                )}
              </Card>
            </Grid>
          </Grid>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%', minHeight: 343, padding: 2, borderRadius: "12px" }}>
            <CardContent sx={{ height: '100%', p: 0 }}>
              <Box
                display="flex"
                justifyContent="space-between"
                alignItems="center"
                sx={{ 
                  borderBottom: "1px solid #999999", 
                  pb: 2,
                  mb: 3
                }}
              >
                <Typography variant="h6" sx={{ color: "#999999", fontWeight: "bold" }}>
                  Network Alerts Timeline
                </Typography>
                <Box sx={{
                  display: "flex",
                  alignItems: "center",
                  backgroundColor: "rgba(25, 118, 210, 0.1)",
                  border: "1px solid #e0e0e0",
                  borderRadius: "6px",
                  padding: "6px 12px",
                  cursor: "pointer",
                  transition: "all 0.2s ease",
                  "&:hover": {
                    backgroundColor: "rgba(25, 118, 210, 0.15)",
                    borderColor: "#42a5f5"
                  }
                }}
                onClick={handleChartPeriodClick}
                >
                  <Typography variant="subtitle2" sx={{ 
                    color: "#1976d2", 
                    fontSize: "14px", 
                    fontWeight: "600",
                    marginRight: "4px"
                  }}>
                    {selectedChartPeriod}
                  </Typography>
                  <KeyboardArrowDownIcon sx={{ 
                    color: "#1976d2",
                    fontSize: "18px"
                  }} />
                </Box>
              </Box>
              <Box sx={{ width: '100%', height: 'calc(100% - 60px)' }}>
                <Bar data={barData} options={barOptions} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={6}>
          <Card sx={{ height: 380, padding: 2, borderRadius: "12px", mb: 3 }}>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                <Typography variant="subtitle2" sx={{ fontSize: "18px", color: "#999999" }}>Events</Typography>
                <Box sx={{ display: "flex", gap: 2 }}>
                  <Box sx={{
                    display: "flex",
                    alignItems: "center",
                    backgroundColor: "rgba(25, 118, 210, 0.1)",
                    border: "1px solid #ccc",
                    borderRadius: "6px",
                    padding: "8px 12px",
                    boxShadow: "0px 2px 5px rgba(0,0,0,0.1)",
                    transition: "all 0.3s ease",
                    "&:hover": {
                      backgroundColor: "rgba(25, 118, 210, 0.15)",
                      transform: "translateY(-2px)",
                      boxShadow: "0px 4px 8px rgba(0,0,0,0.15)"
                    }
                  }}>
                    <Typography variant="body2" sx={{ color: "#1976d2", fontWeight: "bold", marginRight: "8px" }}>Events</Typography>
                    <Typography variant="body2" sx={{ color: "black", fontWeight: "bold" }}>{totalEvents}</Typography>
                  </Box>
                  <Box sx={{
                    display: "flex",
                    alignItems: "center",
                    backgroundColor: "rgba(29, 233, 182, 0.1)",
                    border: "1px solid #ccc",
                    borderRadius: "6px",
                    padding: "8px 12px",
                    boxShadow: "0px 2px 5px rgba(0,0,0,0.1)",
                    transition: "all 0.3s ease",
                    "&:hover": {
                      backgroundColor: "rgba(29, 233, 182, 0.15)",
                      transform: "translateY(-2px)",
                      boxShadow: "0px 4px 8px rgba(0,0,0,0.15)"
                    }
                  }}>
                    <Typography variant="body2" sx={{ color: "#1DE9B6", fontWeight: "bold", marginRight: "8px" }}>Active</Typography>
                    <Typography variant="body2" sx={{ color: "black", fontWeight: "bold" }}>{activeEvents}</Typography>
                  </Box>
                </Box>
              </Box>
              <ResponsiveContainer width="100%" height={280}>
                <LineChart data={filteredData.alerts} margin={{ top: 10, right: 20, left: 10, bottom: 20 }}>
                  <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="#f0f0f0" />
                  <XAxis 
                    dataKey="day"
                    tickFormatter={(value) => {
                      if (value === "MO" || value === "TU" || value === "WH" || value === "TH" || value === "FR" || value === "SA" || value === "SU") {
                        return "";
                      }
                      return value;
                    }}
                    tick={{ fontSize: 12, fill: '#666' }}
                    axisLine={{ stroke: '#e0e0e0' }}
                    height={40}
                  />
                  <YAxis 
                    domain={[0, 70]} 
                    ticks={[0, 20, 40, 60]} 
                    tickFormatter={(value) => {
                      if (value === 0) return "";
                      return value;
                    }}
                    tick={{ fontSize: 12, fill: '#666' }}
                    axisLine={{ stroke: '#e0e0e0' }}
                    width={40}
                  />
                  <RechartsTooltip 
                    contentStyle={{ 
                      backgroundColor: '#fff',
                      border: '1px solid #e0e0e0',
                      borderRadius: '8px',
                      fontSize: '12px',
                      padding: '8px 12px',
                      boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                    }}
                    formatter={(value, name, props) => {
                      return [`${value} events`, 'Events'];
                    }}
                    labelFormatter={(label) => {
                      const dataPoint = filteredData.alerts.find(item => item.day === label);
                      if (!dataPoint) return label;
                      return `${label} (${dataPoint.time || ''})`;
                    }}
                  />
                  <RechartsLine 
                    type="monotone" 
                    dataKey="value" 
                    stroke="#1DE9B6" 
                    strokeWidth={3} 
                    dot={false}
                    activeDot={{ 
                      r: 6,
                      fill: "#1DE9B6",
                      stroke: "#fff",
                      strokeWidth: 2
                    }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={6}>
          <Card sx={{ height: 380, padding: 2, borderRadius: "12px", mb: 3 }}>
            <CardContent>
              <Typography variant="h6" sx={{ color: "#999999" }}>Most Security Blocks</Typography>
              <Box display="flex" justifyContent="center" sx={{ marginY: 2, gap: 4 }}>
                {['BY DESTINATION', 'BY IDENTITY', 'BY TYPE'].map((tab) => (
                  <Typography 
                    key={tab}
                    variant="subtitle1" 
                    sx={{ 
                      color: "#888", 
                      cursor: "pointer",
                      borderBottom: activeSecurityBlockTab === tab ? "3px solid #42a5f5" : "none",
                      paddingBottom: "1px",
                      transition: "all 0.2s ease",
                      "&:hover": {
                        color: "#42a5f5"
                      }
                    }}
                    onClick={() => setActiveSecurityBlockTab(tab)}
                  >
                    {tab}
                  </Typography>
                ))}
              </Box>
              <Box display="flex" justifyContent="space-between" sx={{ borderTop: "1px solid #999999", paddingTop: 2, marginBottom: 1, paddingX: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: "bold", color: "#000" }}>
                  {activeSecurityBlockTab === 'BY TYPE' ? 'Type' : 'Identity'}
                </Typography>
                <Typography variant="subtitle2" sx={{ fontWeight: "bold", color: "#000" }}>Blocked Requests</Typography>
              </Box>
              <Box sx={{ marginTop: 2 }}>
                <Bar data={{
                  ...securityBlockData[activeSecurityBlockTab],
                  datasets: [{
                    ...securityBlockData[activeSecurityBlockTab].datasets[0],
                    data: filteredData.securityControls.map(s => s.value)
                  }]
                }} options={securityBlockOptions} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={4}>
          <Card sx={{ 
            height: 320, 
            padding: '16px', 
            borderRadius: "12px",
            boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
            transition: 'all 0.2s ease',
            '&:hover': {
              boxShadow: '0 4px 8px rgba(0,0,0,0.1)'
            }
          }}>
            <CardContent sx={{ p: 0, height: '100%', display: 'flex', flexDirection: 'column' }}>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ 
                  color: '#666',
                  fontSize: '0.875rem',
                  fontWeight: 500,
                  mb: 1
                }}>Network Traffic Analysis</Typography>
                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Typography variant="h6" sx={{ 
                    fontWeight: 'bold',
                    fontSize: '1.5rem',
                    color: '#1976d2'
                  }}>{(metrics.allRequestsTotal/1000).toFixed(1)}K<br /><span style={{ 
                    color: "#666", 
                    fontSize: '0.875rem',
                    fontWeight: 'normal'
                  }}>Total Packets</span></Typography>
                  <Typography variant="body2" sx={{ 
                    color: '#666',
                    fontSize: '0.75rem',
                    textAlign: 'right'
                  }}>
                    <span style={{ color: "#666" }}>vs. previous 24<br /></span>
                    <span style={{ 
                      color: allRequestsChange > 0 ? '#4caf50' : '#f44336',
                      fontWeight: 'bold'
                    }}>{allRequestsChange > 0 ? '▲' : '▼'} {Math.abs(allRequestsChange)}%</span>
                  </Typography>
                </Box>
              </Box>
              <Box sx={{ 
                flex: 1, 
                height: 'calc(100% - 80px)',
                minHeight: 180,
                position: 'relative'
              }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={filteredData.flows} margin={{ top: 5, right: 5, left: 5, bottom: 5 }}>
                    <CartesianGrid vertical={false} strokeDasharray="0 0" stroke="#f0f0f0" />
                    <XAxis 
                      dataKey="time" 
                      tickFormatter={(value) => {
                        if (value === "04:00am" || value === "012:00am") {
                          return "";
                        }
                        return value;
                      }}
                      tick={{ fontSize: 11, fill: '#666' }}
                      axisLine={{ stroke: '#e0e0e0' }}
                      height={30}
                    />
                    <YAxis 
                      domain={[0, 'auto']} 
                      tickFormatter={(value) => {
                        if (value === 0) return value;
                        if (value >= 1000) return `${(value/1000).toFixed(1)}k`;
                        return value;
                      }}
                      tick={{ fontSize: 11, fill: '#666' }}
                      axisLine={{ stroke: '#e0e0e0' }}
                      width={40}
                    />
                    <RechartsTooltip 
                      contentStyle={{ 
                        backgroundColor: '#fff',
                        border: '1px solid #e0e0e0',
                        borderRadius: '4px',
                        fontSize: '12px'
                      }}
                      formatter={(value) => [`${value} packets`, 'Network Traffic']}
                    />
                    <RechartsLine 
                      type="monotone" 
                      dataKey="value" 
                      stroke="#1976d2" 
                      strokeWidth={2} 
                      dot={false}
                      activeDot={{ r: 4, fill: '#1976d2' }}
                    />
                    <RechartsLine 
                      type="monotone" 
                      dataKey="previousValue" 
                      stroke="#1976d2" 
                      strokeWidth={1} 
                      strokeDasharray="5 5"
                      dot={false}
                      opacity={0.5}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={4}>
          <Card sx={{ 
            height: 320, 
            padding: '16px', 
            borderRadius: "12px",
            boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
            transition: 'all 0.2s ease',
            '&:hover': {
              boxShadow: '0 4px 8px rgba(0,0,0,0.1)'
            }
          }}>
            <CardContent sx={{ p: 0, height: '100%', display: 'flex', flexDirection: 'column' }}>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ 
                  color: '#666',
                  fontSize: '0.875rem',
                  fontWeight: 500,
                  mb: 1
                }}>Threat Detection & Prevention</Typography>
                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Typography variant="h6" sx={{ 
                    fontWeight: 'bold',
                    fontSize: '1.5rem',
                    color: '#d32f2f'
                  }}>{(metrics.blockedRequestsTotal/1000).toFixed(1)}K<br /><span style={{ 
                    color: "#666", 
                    fontSize: '0.875rem',
                    fontWeight: 'normal'
                  }}>Blocked Threats</span></Typography>
                  <Typography variant="body2" sx={{ 
                    color: '#666',
                    fontSize: '0.75rem',
                    textAlign: 'right'
                  }}>
                    <span style={{ color: "#666" }}>vs. previous 24<br /></span>
                    <span style={{ 
                      color: blockedRequestsChange > 0 ? '#4caf50' : '#f44336',
                      fontWeight: 'bold'
                    }}>{blockedRequestsChange > 0 ? '▲' : '▼'} {Math.abs(blockedRequestsChange)}%</span>
                  </Typography>
                </Box>
              </Box>
              <Box sx={{ 
                flex: 1, 
                height: 'calc(100% - 80px)',
                minHeight: 180,
                position: 'relative'
              }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={filteredData.flows} margin={{ top: 5, right: 5, left: 5, bottom: 5 }}>
                    <CartesianGrid vertical={false} strokeDasharray="0 0" stroke="#f0f0f0" />
                    <XAxis 
                      dataKey="time" 
                      tickFormatter={(value) => {
                        if (value === "10:00am" || value === "11:00am" || value === "15:00am") {
                          return "";
                        }
                        return value;
                      }}
                      tick={{ fontSize: 11, fill: '#666' }}
                      axisLine={{ stroke: '#e0e0e0' }}
                      height={30}
                    />
                    <YAxis 
                      domain={[0, 'auto']} 
                      tickFormatter={(value) => {
                        if (value === 0) return value;
                        if (value >= 1000) return `${(value/1000).toFixed(1)}k`;
                        return value;
                      }}
                      tick={{ fontSize: 11, fill: '#666' }}
                      axisLine={{ stroke: '#e0e0e0' }}
                      width={40}
                    />
                    <RechartsTooltip 
                      contentStyle={{ 
                        backgroundColor: '#fff',
                        border: '1px solid #e0e0e0',
                        borderRadius: '4px',
                        fontSize: '12px'
                      }}
                      formatter={(value) => [`${value} threats`, 'Detected Threats']}
                    />
                    <RechartsLine 
                      type="monotone" 
                      dataKey="value" 
                      stroke="#d32f2f" 
                      strokeWidth={2} 
                      dot={false}
                      activeDot={{ r: 4, fill: '#d32f2f' }}
                    />
                    <RechartsLine 
                      type="monotone" 
                      dataKey="previousValue" 
                      stroke="#d32f2f" 
                      strokeWidth={1} 
                      strokeDasharray="5 5"
                      dot={false}
                      opacity={0.5}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={4}>
          <Card sx={{ 
            height: 320, 
            padding: '16px', 
            borderRadius: "12px",
            boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
            transition: 'all 0.2s ease',
            '&:hover': {
              boxShadow: '0 4px 8px rgba(0,0,0,0.1)'
            }
          }}>
            <CardContent sx={{ p: 0, height: '100%', display: 'flex', flexDirection: 'column' }}>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ 
                  color: '#666',
                  fontSize: '0.875rem',
                  fontWeight: 500,
                  mb: 1
                }}>Security Policy Enforcement</Typography>
                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Typography variant="h6" sx={{ 
                    fontWeight: 'bold',
                    fontSize: '1.5rem',
                    color: '#9c27b0'
                  }}>{(metrics.securityControlsTotal/1000).toFixed(1)}K<br /><span style={{ 
                    color: "#666", 
                    fontSize: '0.875rem',
                    fontWeight: 'normal'
                  }}>Policy Violations</span></Typography>
                  <Typography variant="body2" sx={{ 
                    color: '#666',
                    fontSize: '0.75rem',
                    textAlign: 'right'
                  }}>
                    <span style={{ color: "#666" }}>vs. previous 24<br /></span>
                    <span style={{ 
                      color: securityBlocksChange > 0 ? '#4caf50' : '#f44336',
                      fontWeight: 'bold'
                    }}>{securityBlocksChange > 0 ? '▲' : '▼'} {Math.abs(securityBlocksChange)}%</span>
                  </Typography>
                </Box>
              </Box>
              <Box sx={{ 
                flex: 1, 
                height: 'calc(100% - 80px)',
                minHeight: 180,
                position: 'relative'
              }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={filteredData.securityControls} margin={{ top: 5, right: 5, left: 5, bottom: 5 }}>
                    <CartesianGrid vertical={false} strokeDasharray="0 0" stroke="#f0f0f0" />
                    <XAxis 
                      dataKey="time" 
                      tickFormatter={(value) => {
                        if (value === "10:00am" || value === "11:00am" || value === "15:00am") {
                          return "";
                        }
                        return value;
                      }}
                      tick={{ fontSize: 11, fill: '#666' }}
                      axisLine={{ stroke: '#e0e0e0' }}
                      height={30}
                    />
                    <YAxis 
                      domain={[0, 'auto']} 
                      tickFormatter={(value) => {
                        if (value === 0) return value;
                        if (value >= 1000) return `${(value/1000).toFixed(1)}k`;
                        return value;
                      }}
                      tick={{ fontSize: 11, fill: '#666' }}
                      axisLine={{ stroke: '#e0e0e0' }}
                      width={40}
                    />
                    <RechartsTooltip 
                      contentStyle={{ 
                        backgroundColor: '#fff',
                        border: '1px solid #e0e0e0',
                        borderRadius: '4px',
                        fontSize: '12px'
                      }}
                      formatter={(value) => [`${value} violations`, 'Policy Violations']}
                    />
                    <RechartsLine 
                      type="monotone" 
                      dataKey="value" 
                      stroke="#9c27b0" 
                      strokeWidth={2} 
                      dot={false}
                      activeDot={{ r: 4, fill: '#9c27b0' }}
                    />
                    <RechartsLine 
                      type="monotone" 
                      dataKey="previousValue" 
                      stroke="#9c27b0" 
                      strokeWidth={1} 
                      strokeDasharray="5 5"
                      dot={false}
                      opacity={0.5}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default App;