import React, { useEffect, useRef, useState } from 'react';
import * as echarts from 'echarts';

const AlarmingHostsChart = ({ data = [] }) => {
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

    // Process data for the chart
    const chartData = data.length > 0 ? 
      data.map((item) => ({ 
        name: item.ip_address || 'Unknown IP',
        value: item.count || item.alarm_count || item.value || 0
      })).slice(0, 7) : []; // Limit to 7 items max

    const option = {
      title: {
        text: 'Alarming Hosts',
        left: 'left',
        textStyle: {
          fontSize: 24,
          fontWeight: '700',
          color: darkMode ? '#e0e0e0' : '#202224'
        },
      },
      tooltip: {
        trigger: 'axis',
        axisPointer: {
          type: 'shadow',
        },
        backgroundColor: darkMode ? '#1B2431' : '#fff',
        borderColor: darkMode ? '#3A4557' : '#ddd',
        textStyle: {
          color: darkMode ? '#e0e0e0' : '#333'
        }
      },
      grid: {
        top: '20%',
        left: '0%',
        right: '10%',
        bottom: '10%',
        containLabel: true,
      },
      xAxis: {
        type: 'value',
        axisLine: {
          show: false,
        },
        splitLine: {
          lineStyle: {
            type: 'dashed',
            color: darkMode ? '#3A4557' : '#ddd'
          },
        },
        axisLabel: {
          color: darkMode ? '#b0b0b0' : '#666'
        }
      },
      yAxis: {
        type: 'category',
        data: chartData.map((item) => item.name),
        axisLine: {
          show: false,
        },
        axisTick: {
          show: false,
        },
        axisLabel: {
          fontSize: 12,
          color: darkMode ? '#b0b0b0' : '#666'
        },
      },
      series: [
        {
          type: 'bar',
          data: chartData.map((item) => item.value),
          barWidth: '50%',
          itemStyle: {
            color: darkMode ? '#4299E1' : '#007BFF', 
            barBorderRadius: [4, 4, 0, 0], 
          },
          label: {
            show: true,
            position: 'right',
            color: darkMode ? '#e0e0e0' : '#333',
            fontSize: 12,
          },
        },
      ],
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
    <div
      ref={chartRef}
      style={{
        width: '100%',
        height: '400px',
        backgroundColor: darkMode ? '#273142' : '#ffffff'
      }}
    ></div>
  );
};

export default AlarmingHostsChart;
