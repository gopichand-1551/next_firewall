import React from 'react';
import { ThreatLog, Severity, AnalysisType } from '../types';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Shield, AlertTriangle, Zap, Globe } from 'lucide-react';

interface DashboardProps {
  logs: ThreatLog[];
}

export const Dashboard: React.FC<DashboardProps> = ({ logs }) => {
  const totalThreats = logs.filter(l => l.severity !== Severity.SAFE).length;
  const blockedAttacks = logs.filter(l => l.blocked).length;
  const activeConnections = 142; // Simulated
  
  const severityData = [
    { name: 'Low', value: logs.filter(l => l.severity === Severity.LOW).length },
    { name: 'Medium', value: logs.filter(l => l.severity === Severity.MEDIUM).length },
    { name: 'High', value: logs.filter(l => l.severity === Severity.HIGH).length },
    { name: 'Critical', value: logs.filter(l => l.severity === Severity.CRITICAL).length },
  ];

  const typeData = [
    { name: 'SQLi', value: logs.filter(l => l.type === AnalysisType.SQL_INJECTION).length },
    { name: 'Phishing', value: logs.filter(l => l.type === AnalysisType.PHISHING).length },
    { name: 'Malware', value: logs.filter(l => l.type === AnalysisType.MALWARE).length },
    { name: 'Network', value: logs.filter(l => l.type === AnalysisType.PACKET_INSPECTION).length },
  ];

  const COLORS = ['#38bdf8', '#facc15', '#f97316', '#f43f5e'];

  return (
    <div className="space-y-6 animate-fade-in">
      <h2 className="text-2xl font-bold text-slate-100">Security Overview</h2>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard 
          title="Total Threats Detected" 
          value={totalThreats} 
          icon={AlertTriangle} 
          color="text-rose-400" 
          trend="+12% vs last hour"
        />
        <StatCard 
          title="Attacks Blocked" 
          value={blockedAttacks} 
          icon={Shield} 
          color="text-emerald-400" 
          trend="99.9% efficacy"
        />
        <StatCard 
          title="Active Traffic Analysis" 
          value={`${activeConnections} p/s`} 
          icon={Zap} 
          color="text-amber-400" 
          trend="Steady flow"
        />
        <StatCard 
          title="Global Nodes" 
          value="12" 
          icon={Globe} 
          color="text-cyan-400" 
          trend="All systems operational"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700 shadow-xl">
          <h3 className="text-lg font-semibold mb-4 text-slate-300">Threats by Severity</h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1e293b', borderColor: '#475569', color: '#f1f5f9' }}
                  itemStyle={{ color: '#e2e8f0' }}
                />
                <Bar dataKey="value" fill="#38bdf8" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700 shadow-xl">
          <h3 className="text-lg font-semibold mb-4 text-slate-300">Attack Vector Distribution</h3>
          <div className="h-64 w-full flex justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={typeData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {typeData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                   contentStyle={{ backgroundColor: '#1e293b', borderColor: '#475569', color: '#f1f5f9' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
      
      <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
        <h3 className="text-lg font-semibold mb-4 text-slate-300">Recent Activity Log</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="text-slate-400 border-b border-cyber-700 text-sm">
                <th className="p-3">Timestamp</th>
                <th className="p-3">Type</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Details</th>
                <th className="p-3">Status</th>
              </tr>
            </thead>
            <tbody className="text-sm text-slate-300">
              {logs.slice().reverse().slice(0, 5).map((log) => (
                <tr key={log.id} className="border-b border-cyber-700/50 hover:bg-cyber-700/30 transition-colors">
                  <td className="p-3 font-mono text-xs">{new Date(log.timestamp).toLocaleTimeString()}</td>
                  <td className="p-3">{log.type}</td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs font-bold ${
                      log.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-400' :
                      log.severity === 'HIGH' ? 'bg-orange-950 text-orange-400' :
                      log.severity === 'MEDIUM' ? 'bg-yellow-950 text-yellow-400' :
                      'bg-blue-950 text-blue-400'
                    }`}>
                      {log.severity}
                    </span>
                  </td>
                  <td className="p-3 truncate max-w-xs text-slate-400">{log.details}</td>
                  <td className="p-3">
                    <span className={`flex items-center gap-1 ${log.blocked ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {log.blocked ? <Shield className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                      {log.blocked ? 'BLOCKED' : 'ALERT'}
                    </span>
                  </td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr>
                  <td colSpan={5} className="p-4 text-center text-slate-500">No logs generated yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const StatCard = ({ title, value, icon: Icon, color, trend }: any) => (
  <div className="bg-cyber-800 p-5 rounded-xl border border-cyber-700 hover:border-cyber-600 transition-all">
    <div className="flex justify-between items-start mb-2">
      <div className={`p-2 rounded-lg bg-cyber-900 ${color}`}>
        <Icon className="w-6 h-6" />
      </div>
      <span className="text-xs font-mono text-slate-500 bg-cyber-900 px-2 py-1 rounded border border-cyber-700">LIVE</span>
    </div>
    <h4 className="text-slate-400 text-sm font-medium">{title}</h4>
    <p className="text-2xl font-bold text-slate-100 mt-1">{value}</p>
    <p className="text-xs text-slate-500 mt-2 flex items-center gap-1">
      <span className="text-emerald-400">●</span> {trend}
    </p>
  </div>
);