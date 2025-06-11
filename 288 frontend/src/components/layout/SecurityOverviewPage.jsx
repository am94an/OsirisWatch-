import React, { useState, useEffect } from "react";
import {
  Box,
  Card,
  CardContent,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  CircularProgress,
  Alert,
  Grid,
} from "@mui/material";
import Chart from "react-apexcharts";
import "../../styles/event.css";
import { fetchDataAnalysis } from "../../services/api";

// Fallback data in case API call fails
const fallbackData = {
  detectedThreats: { current: 27, total: 80 },
  resolvedThreats: 3298,
  avgResponseTime: "2m 34s",
  threatsGrowth: "+34%",
  affectedDevices: {
    percent: 64,
    spark: [5, 8, 6, 10, 12, 9, 11]
  },
  detectionAccuracy: {
    percent: 86,
    spark: [3, 5, 4, 6, 8, 6, 7]
  },
  trendsOverTime: {
    categories: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
    series: [10, 41, 35, 51, 49, 62]
  },
  topBlocks: [
    { name: "Server 1", value: 44 },
    { name: "Server 2", value: 55 },
    { name: "Workstation 5", value: 41 },
    { name: "Mobile 3", value: 17 }
  ],
  alarmingHosts: [
    { name: "Server 1", data: [44, 55, 57, 56, 61, 58] },
    { name: "Server 2", data: [76, 85, 101, 98, 87, 105] }
  ],
  allRequests: [10, 41, 35, 51, 49, 62, 69, 91, 148],
  blockedRequests: [5, 15, 21, 35, 41, 35, 41, 49, 62],
  securityBlocks: [1, 4, 9, 17, 25, 32, 38, 43, 50]
};

const SecurityOverviewPage = () => {
  const [timeframe, setTimeframe] = useState("all");
  const [threatType, setThreatType] = useState("all");
  const [device, setDevice] = useState("all");
  const [data, setData] = useState(fallbackData);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadData();
  }, [timeframe, threatType, device]);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchDataAnalysis({ timeframe, threatType, device });
      if (res) {
        setData(res);
      } else {
        throw new Error("No data received from server");
      }
    } catch (error) {
      console.error("Error loading security event data:", error);
      setError("Failed to load data. Please try again later.");
      // Keep using existing data or fallback to defaults
      setData(prev => prev || fallbackData);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" flexDirection="column" justifyContent="center" alignItems="center" height="100vh" gap={2}>
        <CircularProgress />
        <Typography>Loading data...</Typography>
      </Box>
    );
  }

  // Chart configurations
  const lineChartOptions = {
    chart: {
      type: 'line',
      toolbar: { show: false },
      background: 'transparent'
    },
    colors: ['#2563EB'],
    stroke: { curve: 'smooth', width: 3 },
    xaxis: {
      categories: data.trendsOverTime?.categories || [],
    },
    grid: { borderColor: '#EDF2F7', strokeDashArray: 5 },
    tooltip: { theme: 'light' },
    legend: { position: 'top' }
  };

  const barChartOptions = {
    chart: {
      type: 'bar',
      toolbar: { show: false },
      background: 'transparent'
    },
    colors: ['#3B82F6'],
    plotOptions: {
      bar: { horizontal: false, columnWidth: '60%', borderRadius: 4 }
    },
    dataLabels: { enabled: false },
    xaxis: {
      categories: data.trendsOverTime?.categories || [],
    }
  };

  const sparklineOptions = {
    chart: {
      type: 'line',
      sparkline: { enabled: true }
    },
    stroke: { curve: 'smooth', width: 2 },
    tooltip: { fixed: { enabled: false } }
  };

  // Summary metrics
  const summaryMetrics = [
    {
      title: "Detected Threats",
      value: `${data.detectedThreats?.current || 0}/${data.detectedThreats?.total || 0}`,
      spark: data.allRequests
    },
    {
      title: "Resolved Threats",
      value: data.resolvedThreats || 0,
      spark: data.blockedRequests
    },
    {
      title: "Avg Response Time",
      value: data.avgResponseTime || "N/A",
      spark: data.securityBlocks
    },
    {
      title: "Affected Devices",
      value: `${data.affectedDevices?.percent || 0}%`,
      spark: data.affectedDevices?.spark || []
    },
    {
      title: "Threat Detection Accuracy",
      value: `${data.detectionAccuracy?.percent || 0}%`,
      spark: data.detectionAccuracy?.spark || []
    },
    {
      title: "Threats Growth",
      value: data.threatsGrowth || "0%",
      isGrowth: true,
      spark: data.trendsOverTime?.series || []
    }
  ];

  return (
    <Box className="security-overview-container">
      <Typography variant="h4" className="page-title" gutterBottom>
        Security Events Overview
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* Filters */}
      <Grid container spacing={2} mb={4} className="filters-grid">
        {[{
            label:"Timeframe", state: timeframe, setter:setTimeframe, items:[{v:'all',l:'All-time'},{v:'month',l:'Last Month'},{v:'week',l:'Last Week'}]
          },
          {
            label:"Threat Type", state: threatType, setter:setThreatType, items:[{v:'all',l:'All'},{v:'malware',l:'Malware'},{v:'phishing',l:'Phishing'},{v:'ddos',l:'DDoS'}]
          },
          {
            label:"Affected Devices", state: device, setter:setDevice, items:[{v:'all',l:'All'},{v:'server',l:'Servers'},{v:'workstation',l:'Workstations'},{v:'mobile',l:'Mobile'}]
          }
        ].map((f,i)=>(
          <Grid item xs={12} sm={4} key={i}>
            <FormControl fullWidth size="small" variant="outlined" className="filter-control">
              <InputLabel>{f.label}</InputLabel>
              <Select
                value={f.state}
                label={f.label}
                onChange={e => f.setter(e.target.value)}
              >
                {f.items.map(it=> <MenuItem key={it.v} value={it.v}>{it.l}</MenuItem>)}
              </Select>
            </FormControl>
          </Grid>
        ))}
      </Grid>

      {/* Summary Cards + Threat Chart */}
      <Grid container spacing={3} mb={4}>
        {/* Left: Summary Cards */}
        <Grid item xs={12} lg={6}>
          <Grid container spacing={2}>
            {summaryMetrics.map((card, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Card className="summary-card">
                  <div>
                    <Typography variant="overline" color="text.secondary">{card.title}</Typography>
                    <Typography 
                      variant="h5" 
                      className={card.isGrowth ? (card.value.startsWith("+") ? "growth-positive" : "growth-negative") : ""}
                      mt={1}
                    >
                      {card.value}
                    </Typography>
                  </div>
                  <Box height={40} className="spark-chart">
                    <Chart 
                      options={sparklineOptions}
                      series={[{ data: card.spark }]}
                      type="line"
                      height={40}
                    />
                  </Box>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Grid>

        {/* Right: Threats Over Time Chart */}
        <Grid item xs={12} lg={6}>
          <Card className="chart-card">
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="subtitle1" className="chart-title">Threats Over Time</Typography>
              <FormControl size="small" variant="outlined" sx={{ width: 140 }}>
                <Select
                  value={timeframe}
                  onChange={e => setTimeframe(e.target.value)}
                  displayEmpty
                >
                  <MenuItem value="all">All-time</MenuItem>
                  <MenuItem value="month">Last Month</MenuItem>
                  <MenuItem value="week">Last Week</MenuItem>
                </Select>
              </FormControl>
            </Box>
            <Chart 
              options={barChartOptions}
              series={[{ name: "Threats", data: data.trendsOverTime?.series || [] }]}
              type="bar"
              height={280}
            />
          </Card>
        </Grid>
      </Grid>
        
      {/* Security Blocks and Events Charts side by side */}
      <Grid container spacing={3} mb={4}>
        {/* Security Blocks Chart */}
        <Grid item xs={12} md={6}>
          <Card className="blocks-card">
            <Typography variant="subtitle1" mb={2}>Most Security Blocks</Typography>
            <Chart 
              options={{
                ...barChartOptions,
                plotOptions: {
                  bar: { horizontal: true, barHeight: '70%', borderRadius: 4 }
                },
                xaxis: {
                  categories: data.topBlocks?.map(block => block.name) || [],
                }
              }}
              series={[{ name: "Blocks", data: data.topBlocks?.map(block => block.value) || [] }]}
              type="bar"
              height={240}
            />
          </Card>
        </Grid>

        {/* Events chart */}
        <Grid item xs={12} md={6}>
          <Card className="events-card">
            <Typography variant="subtitle1" mb={2}>Events</Typography>
            <Chart 
              options={{
                ...lineChartOptions,
                xaxis: {
                  categories: data.trendsOverTime?.categories || []
                },
                colors: ['#3B82F6', '#F59E0B']
              }}
              series={data.alarmingHosts?.map(host => ({ name: host.name, data: host.data })) || []}
              type="line"
              height={240}
            />
          </Card>
        </Grid>
      </Grid>

      {/* Mini charts row */}
      <Grid container spacing={3}>
        {[
          { title: "All Requests", data: data.allRequests || [], color: '#3B82F6' },
          { title: "Blocked Requests", data: data.blockedRequests || [], color: '#F59E0B' },
          { title: "Security Blocks", data: data.securityBlocks || [], color: '#EF4444' }
        ].map((chart, i) => (
          <Grid item xs={12} sm={4} key={i}>
            <Card className="mini-chart-card">
              <Typography variant="subtitle1" mb={2}>{chart.title}</Typography>
              <Box height="85%">
                <Chart 
                  options={{
                    ...lineChartOptions,
                    colors: [chart.color],
                    grid: { padding: { left: 0, right: 0 } }
                  }}
                  series={[{ name: chart.title, data: chart.data }]}
                  type="line"
                  height="100%"
                />
              </Box>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
};

export default SecurityOverviewPage;
