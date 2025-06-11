import React, { useEffect, useRef, useState } from 'react';
import * as echarts from 'echarts';
import '../../styles/ndashboard.css';

const AttackVectorsChart = ({ data = [] }) => {
  const chartRef = useRef(null);
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

  useEffect(() => {
    if (!chartRef.current) return;
    
    const chartInstance = echarts.init(chartRef.current);

    // Process API data for the chart
    const processChartData = () => {
      if (!Array.isArray(data) || data.length === 0) {
        return { names: [], values: [] };
      }

      // Extract attack types and their counts
      const attacksByType = {};
      
      data.forEach(item => {
        const type = item.name || item.attack_type || item.type || item.threat_name || 'Unknown';
        attacksByType[type] = (attacksByType[type] || 0) + (item.count || 1);
      });
      
      // Convert to arrays for the chart
      const sortedData = Object.entries(attacksByType)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6); // Take top 6 attack types
      
      return {
        names: sortedData.map(item => item[0]),
        values: sortedData.map(item => item[1])
      };
    };
    
    const { names, values } = processChartData();

    // Define chart colors
    const colors = darkMode ? 
      ['#4299E1', '#FC8181', '#68D391', '#F6AD55', '#9F7AEA', '#ED64A6'] :
      ['#007BFF', '#FF5252', '#4CAF50', '#FF9800', '#9C27B0', '#F06292'];

    const option = {
      title: {
        text: 'Attack Vectors',
        left: 'center',
        top: 0,
        textStyle: {
          fontSize: 22,
          fontWeight: '700',
          color: darkMode ? '#e0e0e0' : '#202224',
          fontFamily: "'Inter', sans-serif"
        },
      },
      tooltip: {
        trigger: 'item',
        formatter: '{a} <br/>{b}: {c} ({d}%)',
        backgroundColor: darkMode ? '#1B2431' : '#fff',
        borderColor: darkMode ? '#3A4557' : '#ddd',
        textStyle: {
          color: darkMode ? '#e0e0e0' : '#333'
        }
      },
      legend: {
        type: 'scroll',
        orient: 'horizontal',
        bottom: 0,
        left: 'center',
        itemGap: 20,
        itemWidth: 14,
        itemHeight: 14,
        textStyle: {
          color: darkMode ? '#b0b0b0' : '#666',
          fontSize: 12,
          fontFamily: "'Inter', sans-serif"
        },
        pageIconColor: darkMode ? '#4299E1' : '#007BFF',
        pageTextStyle: {
          color: darkMode ? '#b0b0b0' : '#666'
        }
      },
      series: [
        {
          name: 'Attack Vectors',
          type: 'pie',
          radius: ['40%', '70%'],
          center: ['50%', '45%'],
          avoidLabelOverlap: false,
          itemStyle: {
            borderRadius: 10,
            borderColor: darkMode ? '#273142' : '#ffffff',
            borderWidth: 2
          },
          label: {
            show: false,
          },
          emphasis: {
            label: {
              show: true,
              fontSize: 14,
              fontWeight: 'bold',
              color: darkMode ? '#e0e0e0' : '#333'
            },
            itemStyle: {
              shadowBlur: 10,
              shadowOffsetX: 0,
              shadowColor: 'rgba(0, 0, 0, 0.5)'
            }
          },
          labelLine: {
            show: false
          },
          data: names.map((name, index) => ({
            value: values[index],
            name: name,
            itemStyle: {
              color: colors[index % colors.length]
            }
          }))
        }
      ]
    };

    chartInstance.setOption(option);

    const handleResize = () => {
      chartInstance.resize();
    };

    window.addEventListener('resize', handleResize);

    return () => {
      chartInstance.dispose();
      window.removeEventListener('resize', handleResize);
    };
  }, [data, darkMode]);

  return (
    <div className="chart-container" style={{
      backgroundColor: darkMode ? '#273142' : '#ffffff',
      borderRadius: '14px',
      boxShadow: darkMode ? '0 2px 10px rgba(0, 0, 0, 0.2)' : '0 2px 10px rgba(0, 0, 0, 0.05)',
      padding: '24px',
      height: '100%',
      transition: 'all 0.3s ease'
    }}>
      {(Array.isArray(data) && data.length > 0) ? (
        <div
          ref={chartRef}
          style={{
            width: '100%',
            height: '350px'
          }}
        />
      ) : (
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '350px',
          color: darkMode ? '#b0b0b0' : '#666',
          fontSize: '16px',
          fontWeight: '500'
        }}>
          No attack data available
        </div>
      )}
    </div>
  );
};

export default AttackVectorsChart;
