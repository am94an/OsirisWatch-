import "../../styles/ndashboard.css";
import React, { useState, useMemo, useEffect } from "react";
import Chart from "react-apexcharts";
import { downPath, icon1, icon2, icon3, icon4, upPath, upPathRed } from "../../utils/icons";

export default function MainContainerdash({ dashboardData }) {
  const [darkMode, setDarkMode] = useState(false);
  const axisLabelColor = darkMode ? "#FFFFFF" : "#000000";
  
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
  
  console.log('MainContainerdash received data:', dashboardData);
  
  // Handle empty or undefined dashboardData
  const safeDashboardData = dashboardData || {};

  // Ensure we're using the correct data structure based on API response
  // In most cases, the data needed is directly in dashboardData
  const trafficTrends = safeDashboardData.traffic_trends || {};
  
  // Extract data for traffic trends
  const rawHighData = trafficTrends.high || [];
  const rawLowData = trafficTrends.low || [];
  const rawTimestamps = trafficTrends.timestamps || [];
  
  // Generate timestamps if empty but we have data points
  const computedMaxLength = 
    rawTimestamps.length > 0 ? rawTimestamps.length : Math.max(rawHighData.length, rawLowData.length);
    
  // If timestamps are empty, generate dummy timestamps to match data points
  const effectiveTimestamps = rawTimestamps.length > 0 
    ? rawTimestamps 
    : Array.from({length: computedMaxLength}, (_, i) => new Date(Date.now() - (computedMaxLength - i - 1) * 3600000).toISOString());

  const normalizedHigh = useMemo(() => {
    if (rawHighData.length > computedMaxLength) {
      return rawHighData.slice(0, computedMaxLength);
    } else if (rawHighData.length < computedMaxLength) {
      return [...rawHighData, ...Array(computedMaxLength - rawHighData.length).fill(0)];
    }
    return rawHighData;
  }, [rawHighData, computedMaxLength]);
  const normalizedLow = useMemo(() => {
    if (rawLowData.length > computedMaxLength) {
      return rawLowData.slice(0, computedMaxLength);
    } else if (rawLowData.length < computedMaxLength) {
      return [...rawLowData, ...Array(computedMaxLength - rawLowData.length).fill(0)];
    }
    return rawLowData;
  }, [rawLowData, computedMaxLength]);
  const formattedTimestamps = useMemo(() => {
    if (effectiveTimestamps.length > 0) {
      return effectiveTimestamps.map((ts) => {
        const dateObj = new Date(ts);
        return dateObj.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      });
    }
    return Array.from({ length: computedMaxLength }, (_, i) => `Time ${i + 1}`);
  }, [effectiveTimestamps, computedMaxLength]);
  const chartData = useMemo(
    () => ({
      series: [
        { name: "High", data: normalizedHigh },
        { name: "Low", data: normalizedLow }
      ],
      options: {
        chart: { 
          type: "area", 
          height: "100%", 
          toolbar: { show: false },
          background: darkMode ? "#273142" : "#ffffff" 
        },
        colors: ["#F56565", "#4A5568"],
        dataLabels: { enabled: false },
        stroke: { curve: "smooth" },
        xaxis: {
          categories: formattedTimestamps,
          labels: { style: { colors: axisLabelColor } },
          axisBorder: { show: true, color: axisLabelColor },
          axisTicks: { show: true, color: axisLabelColor }
        },
        yaxis: {
          labels: { style: { colors: axisLabelColor } },
          axisBorder: { show: true, color: axisLabelColor },
          axisTicks: { show: true, color: axisLabelColor }
        },
        grid: { 
          show: true,
          borderColor: darkMode ? '#3A4557' : '#E0E0E0',
          strokeDashArray: 3
        },
        tooltip: { 
          enabled: true,
          theme: darkMode ? 'dark' : 'light'
        },
        theme: {
          mode: darkMode ? 'dark' : 'light'
        }
      }
    }),
    [normalizedHigh, normalizedLow, formattedTimestamps, axisLabelColor, darkMode]
  );
  const topAgentsData = useMemo(
    () => {
      // Default values for Windows, Ubuntu, and Arch Linux if API returns empty data
      const defaultAgents = [
        { name: "Windows", percentage: 50 },
        { name: "Ubuntu", percentage: 30 },
        { name: "Arch Linux", percentage: 20 }
      ];

      // Use API data if available, otherwise use default values
      const agents = (safeDashboardData.top_agents && safeDashboardData.top_agents.length > 0) 
        ? safeDashboardData.top_agents 
        : defaultAgents;

      return {
        series: agents.map((agent) => agent.percentage),
        options: {
          chart: { 
            type: "donut",
            background: darkMode ? "#273142" : "#ffffff" 
          },
          labels: agents.map((agent) => agent.name),
          colors: ["#00E396", "#008FFB", "#FEB019"],
          legend: { 
            position: "bottom", 
            labels: { colors: axisLabelColor },
            fontFamily: "inherit"
          },
          dataLabels: { enabled: false },
          plotOptions: { pie: { donut: { size: "70%" } } },
          theme: {
            mode: darkMode ? 'dark' : 'light'
          }
        }
      };
    },
    [safeDashboardData.top_agents, axisLabelColor, darkMode]
  );
  const typeOfAttackData = useMemo(
    () => ({
      series: (safeDashboardData.type_of_attack || []).map((attack) => attack.percentage),
      options: {
        chart: { 
          type: "donut",
          background: darkMode ? "#273142" : "#ffffff" 
        },
        labels: (safeDashboardData.type_of_attack || []).map((attack) => attack.type),
        colors: ["#00E396", "#008FFB", "#FEB019"],
        legend: { 
          position: "bottom", 
          labels: { colors: axisLabelColor },
          fontFamily: "inherit"
        },
        dataLabels: { enabled: false },
        plotOptions: { pie: { donut: { size: "70%" } } },
        theme: {
          mode: darkMode ? 'dark' : 'light'
        }
      }
    }),
    [safeDashboardData.type_of_attack, axisLabelColor, darkMode]
  );
  const statsData = useMemo(
    () => [
      {
        id: 1,
        title: "Threats Detected",
        value: safeDashboardData.threats_detected?.count ?? "0",
        icon: icon2,
        bgColor: darkMode ? "#374151" : "#e4e4ff",
        trend: safeDashboardData.threats_detected?.trend ?? "neutral",
        trendIcon: safeDashboardData.threats_detected?.trend === "up" ? upPathRed : downPath,
        trendValue: safeDashboardData.threats_detected
          ? `${safeDashboardData.threats_detected.change}%`
          : "0%",
        trendColor: safeDashboardData.threats_detected?.trend === "up" ? "red" : "#00B69B"
      },
      {
        id: 2,
        title: "Network Traffic",
        value: safeDashboardData.network_traffic?.count ?? "0",
        icon: icon1,
        bgColor: darkMode ? "#374151" : "#fef2d6",
        trend: safeDashboardData.network_traffic?.trend ?? "neutral",
        trendValue: safeDashboardData.network_traffic
          ? `${safeDashboardData.network_traffic.change}%`
          : "0%",
        trendIcon: safeDashboardData.network_traffic?.trend === "up" ? upPath : downPath,
        trendColor: safeDashboardData.network_traffic?.trend === "up" ? "#00B69B" : "red"
      },
      {
        id: 3,
        title: "Total Suspicious IPs",
        value: safeDashboardData.suspicious_ips?.count ?? "0",
        icon: icon3,
        bgColor: darkMode ? "#374151" : "#d9f7e7",
        trend: safeDashboardData.suspicious_ips?.trend ?? "neutral",
        trendValue: safeDashboardData.suspicious_ips
          ? `${safeDashboardData.suspicious_ips.change}%`
          : "0%",
        trendIcon: safeDashboardData.suspicious_ips?.trend === "up" ? upPath : downPath,
        trendColor: safeDashboardData.suspicious_ips?.trend === "up" ? "#00B69B" : "red"
      },
      {
        id: 4,
        title: "User Logins",
        value: safeDashboardData.user_logins?.count ?? "0",
        icon: icon4,
        bgColor: darkMode ? "#374151" : "#ffded2",
        trend: safeDashboardData.user_logins?.trend ?? "neutral",
        trendValue: safeDashboardData.user_logins
          ? `${safeDashboardData.user_logins.change}%`
          : "0%",
        trendIcon: safeDashboardData.user_logins?.trend === "up" ? upPath : downPath,
        trendColor: safeDashboardData.user_logins?.trend === "up" ? "#00B69B" : "red"
      }
    ],
    [safeDashboardData, darkMode]
  );
  return (
    <div className="dashboard">
      <div className="total-data">
        {statsData.map((stat) => (
          <div className="data" key={stat.id}>
            <div className="stat-des">
              <div>
                <h3 className="title">{stat.title}</h3>
                <p className="value">{stat.value}</p>
              </div>
              <div
                className="conatiner-icon"
                style={{
                  background: stat.bgColor,
                  height: "60px",
                  width: "60px",
                  borderRadius: 14,
                  display: "flex",
                  justifyContent: "center",
                  alignItems: "center"
                }}
              >
                <img src={stat.icon} alt="icons" />
              </div>
            </div>
            <div className="trend-text">
              <img src={stat.trendIcon} alt="trend" />
              <span style={{ color: stat.trendColor }}>{stat.trendValue}</span>
              <span>{stat.trend}</span>
            </div>
          </div>
        ))}
      </div>
      <div className="traffic-trends-chart">
        <div className="traffic-trends-chart-header">
          <h3 className="title">Traffic Trends</h3>
        </div>
        {(normalizedHigh.length > 0 || normalizedLow.length > 0) ? (
          <Chart options={chartData.options} series={chartData.series} type="area" height={350} />
        ) : (
          <p>No data available</p>
        )}
      </div>
      <div className="container-charts">
        <div className="type-of-attack-chart">
          <h4 className="title">Type Of Attack</h4>
          <Chart options={typeOfAttackData.options} series={typeOfAttackData.series} type="donut" height={250} />
        </div>
        <div className="top-agents-chart">
          <h4 className="title">Top Agents</h4>
          <Chart options={topAgentsData.options} series={topAgentsData.series} type="donut" height={250} />
        </div>
      </div>
    </div>
  );
}
