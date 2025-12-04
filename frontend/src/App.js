import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Activity, Server, HardDrive } from 'lucide-react';

const App = () => {
  const [data, setData] = useState([]);
  const [currentStats, setCurrentStats] = useState({ cpu: 0, memory: 0, disk: 0 });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('http://127.0.0.1:5000/api/system-health');
        const now = new Date().toLocaleTimeString();

        setCurrentStats(response.data);

        setData(prevData => {
          const newData = [...prevData, { time: now, ...response.data.cpu }];

          if(newData.length > 20) return newData.slice(newData.length - 20);
          return newData;
        });
      } catch (error) {
        console.error('Error fetching system health data:', error);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ padding: '20px', backgroundColor: '#f4f4f9', minHeight: '100vh', fontFamily: 'Arial, sans-serif' }}>
      <h1 style={{ color: '#333', marginBottom: '20px' }}>🛡️ Security Operations Center (SOC) Dashboard</h1>

      {/* Top Row: Stat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '20px' }}>
        <StatCard 
          icon={<Activity color="#ef4444" />} 
          title="CPU Usage" 
          value={`${currentStats.cpu}%`} 
          color="#ef4444" 
        />
        <StatCard 
          icon={<Server color="#3b82f6" />} 
          title="Memory Usage" 
          value={`${currentStats.memory}%`} 
          color="#3b82f6" 
        />
        <StatCard 
          icon={<HardDrive color="#10b981" />} 
          title="Disk Usage" 
          value={`${currentStats.disk}%`} 
          color="#10b981" 
        />
      </div>

      {/* Middle Row: Live Graph */}
      <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '10px', boxShadow: '0 4px 6px rgba(0,0,0,0.1)' }}>
        <h3 style={{ marginBottom: '15px', color: '#555' }}>Live CPU Load</h3>
        <div style={{ width: '100%', height: 300 }}>
          <ResponsiveContainer>
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis domain={[0, 100]} />
              <Tooltip />
              <Line 
                type="monotone" 
                dataKey="cpu" 
                stroke="#ef4444" 
                strokeWidth={3} 
                dot={false} 
                isAnimationActive={false} // Disable animation for smoother real-time updates
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

// Simple reusable Card component
const StatCard = ({ icon, title, value, color }) => (
  <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '10px', boxShadow: '0 2px 4px rgba(0,0,0,0.1)', display: 'flex', alignItems: 'center', gap: '15px' }}>
    <div style={{ padding: '10px', backgroundColor: `${color}20`, borderRadius: '50%' }}>
      {icon}
    </div>
    <div>
      <p style={{ margin: 0, color: '#666', fontSize: '14px' }}>{title}</p>
      <h2 style={{ margin: 0, color: '#333', fontSize: '24px' }}>{value}</h2>
    </div>
  </div>
);

export default App;