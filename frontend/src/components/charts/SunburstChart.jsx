import React, { useEffect, useRef, useState } from 'react';
import * as echarts from 'echarts';

const SunburstChart = ({ data }) => {
    const chartRef = useRef(null);
    const [isDarkMode, setIsDarkMode] = useState(false);

    useEffect(() => {
        // Check for dark mode in localStorage
        const darkMode = localStorage.getItem('darkMode') === 'true';
        setIsDarkMode(darkMode);
    }, []);

    useEffect(() => {
        if (!chartRef.current) return;

        const chart = echarts.init(chartRef.current);
        
        // Transform the data for the sunburst chart
        const transformedData = {
            name: 'Network Traffic',
            children: [
                {
                    name: 'TCP',
                    value: Object.values(data?.tcp || {}).reduce((a, b) => a + b, 0),
                    itemStyle: { color: '#2B4DEDBD' },
                    children: [
                        { name: 'HTTP', value: data?.tcp?.http || 0 },
                        { name: 'HTTPS', value: data?.tcp?.https || 0 },
                        { name: 'FTP', value: data?.tcp?.ftp || 0 }
                    ]
                },
                {
                    name: 'UDP',
                    value: Object.values(data?.udp || {}).reduce((a, b) => a + b, 0),
                    itemStyle: { color: '#00B07494' },
                    children: [
                        { name: 'DNS', value: data?.udp?.dns || 0 },
                        { name: 'DHCP', value: data?.udp?.dhcp || 0 },
                        { name: 'SNMP', value: data?.udp?.snmp || 0 }
                    ]
                }
            ]
        };

        const option = {
            tooltip: {
                trigger: 'item',
                formatter: '{b}: {c} bytes'
            },
            series: [{
                type: 'sunburst',
                data: [transformedData],
                radius: ['0%', '95%'],
                emphasis: {
                    focus: 'ancestor'
                },
                levels: [
                    {
                        itemStyle: {
                            color: isDarkMode ? '#2B4DEDBD' : '#2B4DED',
                            borderWidth: 2
                        },
                        label: {
                            rotate: 'tangential'
                        }
                    },
                    {
                        itemStyle: {
                            color: isDarkMode ? '#00B07494' : '#00B074',
                            borderWidth: 1
                        },
                        label: {
                            rotate: 'tangential'
                        }
                    },
                    {
                        itemStyle: {
                            borderWidth: 1
                        }
                    }
                ],
                label: {
                    color: isDarkMode ? '#fff' : '#000',
                    fontSize: 12
                }
            }]
        };

        chart.setOption(option);

        const handleResize = () => {
            chart.resize();
        };

        window.addEventListener('resize', handleResize);

        return () => {
            window.removeEventListener('resize', handleResize);
            chart.dispose();
        };
    }, [data, isDarkMode]);

    return <div ref={chartRef} style={{ width: '100%', height: '400px' }} />;
};

export default SunburstChart;