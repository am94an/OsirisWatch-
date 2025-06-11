import React, { useEffect, useState } from 'react';
import Chart from 'react-apexcharts';

const ThreatTrendsChart = ({ data = [] }) => {
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
      setDarkMode(localStorage.getItem('darkMode') === 'true');
    };
    
    window.addEventListener('storage', handleDarkModeChange);
    window.addEventListener('storage-local', handleDarkModeChange);
    return () => {
      window.removeEventListener('storage', handleDarkModeChange);
      window.removeEventListener('storage-local', handleDarkModeChange);
    };
  }, []);

  const [chartOptions, setChartOptions] = useState({
    chart: {
      type: 'line',
      height: 230,
      background: darkMode ? '#273142' : '#ffffff'
    },
    stroke: {
      curve: 'smooth',
    },
    xaxis: {
      categories: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'],
      labels: {
        style: {
          colors: darkMode ? '#b0b0b0' : '#666'
        }
      },
      axisBorder: {
        color: darkMode ? '#3A4557' : '#E0E0E0'
      },
      axisTicks: {
        color: darkMode ? '#3A4557' : '#E0E0E0'
      }
    },
    yaxis: {
      labels: {
        style: {
          colors: darkMode ? '#b0b0b0' : '#666'
        }
      }
    },
    grid: {
      borderColor: darkMode ? '#3A4557' : '#E0E0E0',
      strokeDashArray: 3
    },
    tooltip: {
      enabled: true,
      shared: true,
      theme: darkMode ? 'dark' : 'light'
    },
    markers: {
      size: 4,
      hover: {
        size: 6
      }
    },
    theme: {
      mode: darkMode ? 'dark' : 'light'
    },
    title: {
      text: 'Threat Trends Over Time',
      align: 'left',
      style: {
        fontSize: '14px',
        fontWeight: 'normal',
        color: darkMode ? '#e0e0e0' : '#333'
      }
    }
  });

  const [chartSeries, setChartSeries] = useState([
    {
      name: 'Threats',
      data: [30, 40, 35, 40, 30, 45, 30], 
    },
  ]);

  // Update chart options when dark mode changes
  useEffect(() => {
    setChartOptions(prevOptions => ({
      ...prevOptions,
      chart: {
        ...prevOptions.chart,
        background: darkMode ? '#273142' : '#ffffff'
      },
      xaxis: {
        ...prevOptions.xaxis,
        labels: {
          style: {
            colors: darkMode ? '#b0b0b0' : '#666'
          }
        },
        axisBorder: {
          color: darkMode ? '#3A4557' : '#E0E0E0'
        },
        axisTicks: {
          color: darkMode ? '#3A4557' : '#E0E0E0'
        }
      },
      yaxis: {
        ...prevOptions.yaxis,
        labels: {
          style: {
            colors: darkMode ? '#b0b0b0' : '#666'
          }
        }
      },
      grid: {
        borderColor: darkMode ? '#3A4557' : '#E0E0E0',
        strokeDashArray: 3
      },
      tooltip: {
        ...prevOptions.tooltip,
        theme: darkMode ? 'dark' : 'light'
      },
      theme: {
        mode: darkMode ? 'dark' : 'light'
      },
      title: {
        ...prevOptions.title,
        style: {
          ...prevOptions.title.style,
          color: darkMode ? '#e0e0e0' : '#333'
        }
      }
    }));
  }, [darkMode]);

  useEffect(() => {
    if (data && data.length > 0) {
      try {
        // Transform API data for the chart
        // Assuming data has format like [{name: "threatName", count: value}, ...]
        const categories = data.map(item => item.name || 'Unknown');
        const values = data.map(item => item.count || 0);

        setChartOptions(prevOptions => ({
          ...prevOptions,
          xaxis: {
            ...prevOptions.xaxis,
            categories: categories.length > 0 ? categories : prevOptions.xaxis.categories
          }
        }));

        setChartSeries([{
          name: 'Threats',
          data: values.length > 0 ? values : [30, 40, 35, 40, 30, 45, 30]
        }]);
      } catch (error) {
        console.error('Error processing chart data:', error);
        // Keep default data if there's an error
      }
    }
  }, [data]);

  return (
    <div style={{ 
      backgroundColor: darkMode ? '#273142' : '#ffffff', 
      padding: '15px',
      borderRadius: '8px'
    }}>
      <Chart options={chartOptions} series={chartSeries} type="line" height={230} />
    </div>
  );
};

export default ThreatTrendsChart;