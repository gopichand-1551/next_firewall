import React, { useState, useEffect, useRef } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Zap, ShieldAlert, Activity, Server, RefreshCcw, TrendingUp, Lock } from 'lucide-react';
import { analyzeContent } from '../services/gemini';
import { AnalysisType, Severity, ThreatLog } from '../types';

interface DosGuardProps {
  addLog: (log: ThreatLog) => void;
}

interface TrafficPoint {
  time: string;
  rps: number;
  latency: number;
}

export const DosGuard: React.FC<DosGuardProps> = ({ addLog }) => {
  const [data, setData] = useState<TrafficPoint[]>([]);
  const [activeMode, setActiveMode] = useState<'NORMAL' | 'HTTP_FLOOD' | 'UDP_FLOOD' | 'SLOWLORIS'>('NORMAL');
  const [isMitigationActive, setIsMitigationActive] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [stats, setStats] = useState({ currentRps: 45, peakRps: 80, activeIPs: 120, dropped: 0 });
  
  // Track if we have already analyzed the current attack session to avoid API spam
  const attackAnalyzed = useRef(false);

  // Reset analysis flag when mode changes
  useEffect(() => {
    attackAnalyzed.current = false;
  }, [activeMode]);

  // Shared Analysis Logic
  const runAnalysis = async (rps: number, latency: number, ips: number, mode: string) => {
    setAnalyzing(true);
    
    const prompt = `Traffic Analysis Report:
    - Current RPS: ${rps}
    - Average Latency: ${latency}ms
    - Active Source IPs: ${ips}
    - Traffic Pattern: ${mode === 'NORMAL' ? 'Steady baseline' : 'Sudden spike detected'}
    - Protocol Distribution: ${mode === 'UDP_FLOOD' ? '90% UDP' : '95% TCP/HTTP'}
    
    Determine the type of attack (if any) and recommend mitigation strategies.`;

    try {
      const analysis = await analyzeContent(prompt, AnalysisType.DOS_DDOS);

      addLog({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        type: AnalysisType.DOS_DDOS,
        severity: analysis.severity,
        source: 'Traffic-Flow-Analyzer',
        details: analysis.reasoning,
        blocked: isMitigationActive
      });
    } catch (e) {
      console.error("Analysis failed", e);
    } finally {
      setAnalyzing(false);
    }
  };

  // Simulation Loop
  useEffect(() => {
    const interval = setInterval(() => {
      const now = new Date();
      const timeStr = `${now.getHours()}:${now.getMinutes()}:${now.getSeconds()}`;
      
      let newRps = 0;
      let latency = 0;
      let ips = 0;

      // Simulation Physics
      switch (activeMode) {
        case 'NORMAL':
          newRps = Math.floor(Math.random() * 30) + 20; // 20-50 RPS
          latency = Math.floor(Math.random() * 20) + 30; // 30-50ms
          ips = Math.floor(Math.random() * 10) + 100;
          break;
        case 'HTTP_FLOOD':
          newRps = Math.floor(Math.random() * 500) + 800; // 800-1300 RPS
          latency = Math.floor(Math.random() * 200) + 400; // High latency
          ips = Math.floor(Math.random() * 500) + 1000; // Botnet
          break;
        case 'UDP_FLOOD':
          newRps = Math.floor(Math.random() * 1000) + 2000; // Massive volume
          latency = Math.floor(Math.random() * 50) + 100;
          ips = Math.floor(Math.random() * 50) + 50; // Often spoofed, fewer real connections
          break;
        case 'SLOWLORIS':
          newRps = Math.floor(Math.random() * 20) + 30; // Low RPS
          latency = Math.floor(Math.random() * 2000) + 5000; // Extreme latency (holding connections)
          ips = Math.floor(Math.random() * 50) + 200;
          break;
      }

      // Apply Mitigation Effect
      if (isMitigationActive && activeMode !== 'NORMAL') {
        newRps = newRps * 0.1; // Filter out 90% of bad traffic
        latency = latency * 0.2;
        setStats(prev => ({ ...prev, dropped: prev.dropped + Math.floor(newRps * 9) }));
      }

      // Auto-Trigger AI Analysis if threshold breached and not yet analyzed
      const threshold = activeMode === 'SLOWLORIS' ? 1000 : 500; // Latency threshold for Slowloris, RPS for others
      const metric = activeMode === 'SLOWLORIS' ? latency : newRps;
      
      if (activeMode !== 'NORMAL' && !attackAnalyzed.current && metric > threshold && !isMitigationActive) {
        attackAnalyzed.current = true;
        // Trigger analysis with the values from this specific tick
        runAnalysis(newRps, latency, ips, activeMode);
      }

      setStats(prev => ({
        currentRps: newRps,
        peakRps: Math.max(prev.peakRps, newRps),
        activeIPs: ips,
        dropped: prev.dropped
      }));

      setData(prev => {
        const newData = [...prev, { time: timeStr, rps: newRps, latency }];
        if (newData.length > 20) newData.shift();
        return newData;
      });

    }, 1000);

    return () => clearInterval(interval);
  }, [activeMode, isMitigationActive]);

  const handleManualAnalysis = () => {
    runAnalysis(stats.currentRps, data[data.length-1]?.latency || 0, stats.activeIPs, activeMode);
  };

  return (
    <div className="space-y-6 h-[calc(100vh-140px)] flex flex-col animate-fade-in">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
             <Zap className="w-6 h-6 text-yellow-400" /> DDoS Protection
          </h2>
          <p className="text-slate-400">Volumetric & Application Layer Attack Mitigation</p>
        </div>
        <div className="flex gap-2">
            <button 
                onClick={() => setIsMitigationActive(!isMitigationActive)}
                className={`px-4 py-2 rounded-lg font-bold text-sm transition-all flex items-center gap-2 border ${
                    isMitigationActive 
                    ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.3)]' 
                    : 'bg-cyber-800 text-slate-400 border-cyber-700 hover:text-slate-200'
                }`}
            >
                <ShieldAlert className="w-4 h-4" />
                {isMitigationActive ? 'MITIGATION ACTIVE' : 'ENABLE MITIGATION'}
            </button>
        </div>
      </div>

      {/* Live Stats */}
      <div className="grid grid-cols-4 gap-4">
        <StatBox label="Current RPS" value={stats.currentRps} color="text-cyan-400" icon={Activity} />
        <StatBox label="Peak RPS" value={stats.peakRps} color="text-yellow-400" icon={TrendingUp} />
        <StatBox label="Active IPs" value={stats.activeIPs} color="text-indigo-400" icon={Server} />
        <StatBox label="Packets Dropped" value={stats.dropped.toLocaleString()} color="text-rose-400" icon={Lock} />
      </div>

      {/* Main Chart */}
      <div className="flex-1 bg-cyber-800 border border-cyber-700 rounded-xl p-6 shadow-xl min-h-0 flex flex-col">
        <h3 className="text-lg font-semibold text-slate-300 mb-4">Real-time Traffic Volume</h3>
        <div className="flex-1 w-full min-h-0">
             <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data}>
                    <defs>
                        <linearGradient id="colorRps" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="#38bdf8" stopOpacity={0}/>
                        </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                    <XAxis dataKey="time" stroke="#94a3b8" tick={{fontSize: 12}} />
                    <YAxis stroke="#94a3b8" tick={{fontSize: 12}} />
                    <Tooltip 
                        contentStyle={{ backgroundColor: '#1e293b', borderColor: '#475569', color: '#f1f5f9' }}
                        itemStyle={{ color: '#38bdf8' }}
                    />
                    <Area type="monotone" dataKey="rps" stroke="#38bdf8" fillOpacity={1} fill="url(#colorRps)" strokeWidth={2} animationDuration={300} />
                </AreaChart>
             </ResponsiveContainer>
        </div>
      </div>

      {/* Control Panel */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Attack Simulation */}
          <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
             <h3 className="text-lg font-bold text-slate-200 mb-4 flex items-center gap-2">
                <RefreshCcw className="w-5 h-5 text-rose-400" /> Traffic Simulation
             </h3>
             <div className="grid grid-cols-2 gap-3">
                <SimBtn active={activeMode === 'NORMAL'} onClick={() => setActiveMode('NORMAL')} label="Normal Traffic" desc="Baseline usage" />
                <SimBtn active={activeMode === 'HTTP_FLOOD'} onClick={() => setActiveMode('HTTP_FLOOD')} label="HTTP Flood" desc="High RPS L7 Attack" warning />
                <SimBtn active={activeMode === 'UDP_FLOOD'} onClick={() => setActiveMode('UDP_FLOOD')} label="UDP Reflection" desc="Volumetric L4 Attack" warning />
                <SimBtn active={activeMode === 'SLOWLORIS'} onClick={() => setActiveMode('SLOWLORIS')} label="Slowloris" desc="Connection Exhaustion" warning />
             </div>
          </div>

          {/* AI Analysis */}
          <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
             <h3 className="text-lg font-bold text-slate-200 mb-4 flex items-center gap-2">
                <Activity className="w-5 h-5 text-cyan-400" /> Intelligent Analysis
             </h3>
             <p className="text-sm text-slate-400 mb-6">
                Use Gemini 2.5 to analyze the current traffic pattern, distinct IP count, and protocol headers to identify anomaly signatures.
             </p>
             
             <button
                onClick={handleManualAnalysis}
                disabled={analyzing}
                className="w-full bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white font-bold py-3 rounded-lg shadow-lg flex items-center justify-center gap-2 disabled:opacity-50 transition-all"
             >
                {analyzing ? (
                    <>
                        <div className="animate-spin w-4 h-4 border-2 border-white border-t-transparent rounded-full"></div>
                        Analyzing Traffic Patterns...
                    </>
                ) : (
                    <>
                        <Zap className="w-4 h-4" /> Analyze Current Traffic
                    </>
                )}
             </button>
          </div>
      </div>
    </div>
  );
};

const StatBox = ({ label, value, color, icon: Icon }: any) => (
    <div className="bg-cyber-900 p-4 rounded-lg border border-cyber-700 flex items-center justify-between">
        <div>
            <p className="text-xs text-slate-500 uppercase font-semibold">{label}</p>
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
        </div>
        <div className={`p-2 rounded bg-white/5 ${color}`}>
            <Icon className="w-5 h-5" />
        </div>
    </div>
);

const SimBtn = ({ active, onClick, label, desc, warning }: any) => (
    <button
        onClick={onClick}
        className={`p-3 rounded-lg border text-left transition-all ${
            active 
            ? warning 
                ? 'bg-rose-900/30 border-rose-500 text-rose-400' 
                : 'bg-cyan-900/30 border-cyan-500 text-cyan-400'
            : 'bg-cyber-900 border-cyber-700 text-slate-400 hover:bg-cyber-700'
        }`}
    >
        <div className="font-bold text-sm">{label}</div>
        <div className="text-xs opacity-70">{desc}</div>
    </button>
);