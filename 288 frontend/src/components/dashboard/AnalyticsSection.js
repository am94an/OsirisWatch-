import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../ui/Card';
import { Button } from '../ui/Button';
import { Tabs, TabsList, TabsTrigger } from '../ui/Tabs';
import { Line, Bar, Pie } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { fetchDataAnalysis } from '../../services/api';
import LoadingSpinner from '../ui/LoadingSpinner';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
);

const AnalyticsSection = () => {
  const [analyticsData, setAnalyticsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [chartType, setChartType] = useState('network');

  // Fetch analytics data from API
  useEffect(() => {
    const getAnalyticsData = async () => {
      try {
        setLoading(true);
        const data = await fetchDataAnalysis();
        setAnalyticsData(data);
        setError(null);
      } catch (err) {
        console.error('Error fetching analytics data:', err);
        setError('Failed to load analytics data. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    getAnalyticsData();
  }, []);

  if (loading) {
    return (
      <Card className="analytics-card">
        <CardHeader>
          <CardTitle>Analytics Dashboard</CardTitle>
          <CardDescription>Loading analytics data...</CardDescription>
        </CardHeader>
        <CardContent className="flex justify-center items-center h-64">
          <LoadingSpinner />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="analytics-card">
        <CardHeader>
          <CardTitle>Analytics Dashboard</CardTitle>
          <CardDescription>Error</CardDescription>
        </CardHeader>
        <CardContent className="flex justify-center items-center h-64">
          <div className="text-center text-red-500">{error}</div>
        </CardContent>
      </Card>
    );
  }

  if (!analyticsData) {
    return (
      <Card className="analytics-card">
        <CardHeader>
          <CardTitle>Analytics Dashboard</CardTitle>
          <CardDescription>No data available</CardDescription>
        </CardHeader>
        <CardContent className="flex justify-center items-center h-64">
          <div className="text-center">No analytics data available</div>
        </CardContent>
      </Card>
    );
  }

  // Network Traffic data
  const networkTrafficData = {
    labels: analyticsData.networkTraffic.labels,
    datasets: [
      {
        label: 'Incoming Traffic',
        data: analyticsData.networkTraffic.incoming,
        borderColor: 'rgba(75, 192, 192, 1)',
        backgroundColor: 'rgba(75, 192, 192, 0.2)',
        tension: 0.3,
        fill: true,
      },
      {
        label: 'Outgoing Traffic',
        data: analyticsData.networkTraffic.outgoing,
        borderColor: 'rgba(153, 102, 255, 1)',
        backgroundColor: 'rgba(153, 102, 255, 0.2)',
        tension: 0.3,
        fill: true,
      },
    ],
  };

  // User Activity data
  const userActivityData = {
    labels: analyticsData.userActivity.labels,
    datasets: [
      {
        label: 'User Activity',
        data: analyticsData.userActivity.values,
        backgroundColor: 'rgba(54, 162, 235, 0.6)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1,
      },
    ],
  };

  // Threat Distribution data
  const threatDistributionData = {
    labels: analyticsData.threats.labels,
    datasets: [
      {
        label: 'Threat Distribution',
        data: analyticsData.threats.values,
        backgroundColor: [
          'rgba(255, 99, 132, 0.6)',
          'rgba(54, 162, 235, 0.6)',
          'rgba(255, 206, 86, 0.6)',
          'rgba(75, 192, 192, 0.6)',
          'rgba(153, 102, 255, 0.6)',
        ],
        borderColor: [
          'rgba(255, 99, 132, 1)',
          'rgba(54, 162, 235, 1)',
          'rgba(255, 206, 86, 1)',
          'rgba(75, 192, 192, 1)',
          'rgba(153, 102, 255, 1)',
        ],
        borderWidth: 1,
      },
    ],
  };

  // Chart options
  const lineOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        beginAtZero: true,
      },
    },
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        beginAtZero: true,
      },
    },
  };

  const pieOptions = {
    responsive: true,
    maintainAspectRatio: false,
  };

  return (
    <Card className="analytics-card">
      <CardHeader>
        <CardTitle>Analytics Dashboard</CardTitle>
        <CardDescription>View your security analytics</CardDescription>
        <Tabs value={chartType} onValueChange={setChartType} className="mt-2">
          <TabsList>
            <TabsTrigger value="network">Network Traffic</TabsTrigger>
            <TabsTrigger value="user">User Activity</TabsTrigger>
            <TabsTrigger value="threats">Threat Distribution</TabsTrigger>
          </TabsList>
        </Tabs>
      </CardHeader>
      <CardContent className="h-80">
        {chartType === 'network' && (
          <div className="h-full">
            <Line data={networkTrafficData} options={lineOptions} />
          </div>
        )}
        {chartType === 'user' && (
          <div className="h-full">
            <Bar data={userActivityData} options={barOptions} />
          </div>
        )}
        {chartType === 'threats' && (
          <div className="h-full">
            <Pie data={threatDistributionData} options={pieOptions} />
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default AnalyticsSection; 