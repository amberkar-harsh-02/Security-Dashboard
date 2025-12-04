import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Activity, Server, HardDrive, Globe, AlertTriangle, CheckCircle } from 'lucide-react';

const App = () => {
  // State for System Health
  const [data, setData] = useState([]);
  const [currentStats, setCurrentStats] = useState({ cpu: 0, memory: 0, disk: 0 });

  // State for API Monitor
  const [apiStats, setApiStats] = useState({ status: "Unknown", total_requests: 0, failed_requests: 0, avg_latency: 0 });

  useEffect(() => {
    const fetchData = async () => {
      try {
        // 1. Get System Health
        const sysRes = await axios.get('http://127.0.0.1:5000/api/system-health');
        setCurrentStats(sysRes.data);

        // Update Graph
        const now = new Date().toLocaleTimeString();
        setData(prev => {
          const newData = [...prev, { time: now, cpu: sysRes.data.cpu }];
          return newData.length > 20 ? newData.slice(newData.length - 20) : newData;
        });

        // 2. Get API Monitor Stats
        const apiRes = await axios.get('http://127.0.0.1:5000/api/monitor-stats');
        setApiStats(apiRes.data);

      } catch (e) { console.error(e); }
    };

    const interval = setInterval(fetchData, 1000);
    return () => clearInterval(interval);
  }, []);

  // Button to simulate users logging in
  const generateTraffic = async () => {
    for(let i=0; i<5; i++) {
        try { await axios.post('http://127.0.0.1:5000/api/login'); } catch(e) {}
    }
  };

  return (
    <div style={{ padding: '20px', backgroundColor: '#f4f4f9', minHeight: '100vh', fontFamily: 'Arial, sans-serif' }}>
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'20px'}}>
        <h1 style={{ color: '#333' }}>🛡️ Security Operations Center</h1>
        <button onClick={generateTraffic} style={{padding:'10px 20px', backgroundColor:'#3b82f6', color:'white', border:'none', borderRadius:'5px', cursor:'pointer', fontWeight:'bold'}}>
          ⚡ Generate Traffic
        </button>
      </div>

      {/* System Health Section */}
      <h3 style={{color:'#666'}}>System Health</h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '30px' }}>
        <StatCard icon={<Activity color="#ef4444" />} title="CPU Usage" value={`${currentStats.cpu}%`} color="#ef4444" />
        <StatCard icon={<Server color="#3b82f6" />} title="Memory Usage" value={`${currentStats.memory}%`} color="#3b82f6" />
        <StatCard icon={<HardDrive color="#10b981" />} title="Disk Usage" value={`${currentStats.disk}%`} color="#10b981" />
      </div>

      {/* API Monitor Section */}
      <h3 style={{color:'#666'}}>API Endpoint Monitor (/api/login)</h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px', marginBottom: '30px' }}>
        <StatCard icon={apiStats.status === "Healthy" ? <CheckCircle color="#10b981"/> : <AlertTriangle color="#f59e0b"/>} title="Status" value={apiStats.status} color={apiStats.status === "Healthy" ? "#10b981" : "#f59e0b"} />
        <StatCard icon={<Globe color="#6366f1" />} title="Total Requests" value={apiStats.total_requests} color="#6366f1" />
        <StatCard icon={<AlertTriangle color="#ef4444" />} title="Failed Requests" value={apiStats.failed_requests} color="#ef4444" />
        <StatCard icon={<Activity color="#8b5cf6" />} title="Avg Latency" value={`${Math.round(apiStats.avg_latency)} ms`} color="#8b5cf6" />
      </div>

      {/* Graph Section */}
      <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '10px', boxShadow: '0 4px 6px rgba(0,0,0,0.1)' }}>
        <h3 style={{ marginBottom: '15px', color: '#555' }}>Live CPU Load</h3>
        <div style={{ width: '100%', height: 250 }}>
          <ResponsiveContainer>
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis domain={[0, 100]} />
              <Tooltip />
              <Line type="monotone" dataKey="cpu" stroke="#ef4444" strokeWidth={3} dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

const StatCard = ({ icon, title, value, color }) => (
  <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '10px', boxShadow: '0 2px 4px rgba(0,0,0,0.1)', display: 'flex', alignItems: 'center', gap: '15px' }}>
    <div style={{ padding: '10px', backgroundColor: `${color}20`, borderRadius: '50%' }}>{icon}</div>
    <div>
      <p style={{ margin: 0, color: '#666', fontSize: '14px' }}>{title}</p>
      <h2 style={{ margin: 0, color: '#333', fontSize: '24px' }}>{value}</h2>
    </div>
  </div>
);

export default App;