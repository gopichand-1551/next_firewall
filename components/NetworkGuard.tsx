import React, { useState, useEffect, useRef } from 'react';
import { Packet, AnalysisType, ThreatLog, Severity, FirewallRule } from '../types';
import { analyzeContent, generateMockPacket } from '../services/gemini';
import { 
  Play, Pause, Shield, Eye, Filter, Activity, Server, 
  Plus, Trash2, AlertOctagon, Layers, Lock, Settings
} from 'lucide-react';

interface NetworkGuardProps {
  addLog: (log: ThreatLog) => void;
}

export const NetworkGuard: React.FC<NetworkGuardProps> = ({ addLog }) => {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [analyzingPacket, setAnalyzingPacket] = useState(false);
  const [activeTab, setActiveTab] = useState<'TRAFFIC' | 'RULES'>('TRAFFIC');

  // Firewall Rules State
  const [rules, setRules] = useState<FirewallRule[]>([
    { id: '1', type: 'L4_PORT', value: 8080, active: true },
    { id: '2', type: 'L7_KEYWORD', value: 'cmd.exe', active: true },
    { id: '3', type: 'L4_IP', value: '192.168.1.100', active: false },
  ]);
  
  const [newRuleValue, setNewRuleValue] = useState('');
  const [newRuleType, setNewRuleType] = useState<FirewallRule['type']>('L4_PORT');

  // Use ref to access latest rules inside interval closure
  const rulesRef = useRef(rules);
  useEffect(() => { rulesRef.current = rules; }, [rules]);

  // Add Rule
  const addRule = () => {
    if (!newRuleValue) return;
    const val = newRuleType === 'L4_PORT' ? parseInt(newRuleValue) : newRuleValue;
    setRules([...rules, {
      id: crypto.randomUUID(),
      type: newRuleType,
      value: val,
      active: true
    }]);
    setNewRuleValue('');
  };

  // Toggle Rule
  const toggleRule = (id: string) => {
    setRules(rules.map(r => r.id === id ? { ...r, active: !r.active } : r));
  };

  // Delete Rule
  const deleteRule = (id: string) => {
    setRules(rules.filter(r => r.id !== id));
  };

  // Traffic Generation & Filtering Engine
  useEffect(() => {
    let interval: any;
    if (isMonitoring) {
      interval = setInterval(async () => {
        const payload = await generateMockPacket();
        const protocols: Packet['protocol'][] = ['TCP', 'UDP', 'HTTP', 'ICMP'];
        const port = Math.floor(Math.random() * 10000);
        const srcIp = `192.168.1.${Math.floor(Math.random() * 255)}`;
        
        let status: Packet['status'] = 'ANALYZING'; // Default to AI analysis needed
        let verdictReason = '';

        // --- LAYER 1: L4 Packet Filtering (Port/IP) ---
        const l4PortRules = rulesRef.current.filter(r => r.active && r.type === 'L4_PORT');
        const l4IpRules = rulesRef.current.filter(r => r.active && r.type === 'L4_IP');

        if (l4PortRules.some(r => r.value === port)) {
            status = 'BLOCKED_L4';
            verdictReason = `Port ${port} is blacklisted via Packet Filter.`;
        } else if (l4IpRules.some(r => r.value === srcIp)) {
            status = 'BLOCKED_L4';
            verdictReason = `IP ${srcIp} is blacklisted via Packet Filter.`;
        }

        // --- LAYER 2: L7 Proxy Filtering (Content) ---
        if (status !== 'BLOCKED_L4') {
            const l7Rules = rulesRef.current.filter(r => r.active && r.type === 'L7_KEYWORD');
            const matchedRule = l7Rules.find(r => payload.includes(r.value as string));
            if (matchedRule) {
                status = 'BLOCKED_L7';
                verdictReason = `Payload contains forbidden keyword: "${matchedRule.value}"`;
            }
        }

        // If blocked by static rules, log immediately
        if (status.startsWith('BLOCKED')) {
             addLog({
                id: crypto.randomUUID(),
                timestamp: new Date().toISOString(),
                type: AnalysisType.PACKET_INSPECTION,
                severity: Severity.MEDIUM,
                source: status === 'BLOCKED_L4' ? 'Packet Filter (L4)' : 'Proxy Filter (L7)',
                details: verdictReason,
                blocked: true
            });
        }

        const newPacket: Packet = {
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          sourceIp: srcIp,
          destIp: `10.0.0.${Math.floor(Math.random() * 50)}`,
          protocol: protocols[Math.floor(Math.random() * protocols.length)],
          port: port,
          payload: payload,
          status: status,
          verdictReason: verdictReason,
          riskScore: status.startsWith('BLOCKED') ? 100 : undefined
        };

        setPackets(prev => [newPacket, ...prev].slice(0, 50)); 
      }, 1500);
    }
    return () => clearInterval(interval);
  }, [isMonitoring, addLog]);

  // Layer 3: NGFW AI Inspection
  const inspectPacket = async (packet: Packet) => {
    setSelectedPacket(packet);
    
    // If already blocked by rules, no need for expensive AI check
    if (packet.status.startsWith('BLOCKED')) return;

    setAnalyzingPacket(true);
    const analysis = await analyzeContent(
        `Payload: ${packet.payload}\nProtocol: ${packet.protocol}\nPort: ${packet.port}`, 
        AnalysisType.PACKET_INSPECTION
    );
    
    const updatedPacket = { 
        ...packet, 
        riskScore: analysis.isThreat ? 95 : 5,
        status: analysis.isThreat ? 'BLOCKED_AI' as const : 'ALLOWED' as const,
        verdictReason: analysis.reasoning
    };

    // Update packet in list
    setPackets(prev => prev.map(p => p.id === packet.id ? updatedPacket : p));
    setSelectedPacket(updatedPacket);
    setAnalyzingPacket(false);

    if (analysis.isThreat) {
        addLog({
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            type: AnalysisType.PACKET_INSPECTION,
            severity: analysis.severity,
            source: 'NGFW-AI-Engine',
            details: analysis.reasoning,
            blocked: true
        });
    }
  };

  return (
    <div className="space-y-6 h-[calc(100vh-140px)] flex flex-col animate-fade-in">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
             <Layers className="w-6 h-6 text-cyan-400" /> Network Guard (NGFW)
          </h2>
          <p className="text-slate-400">Layer 4-7 Filtering & AI-Powered Deep Packet Inspection</p>
        </div>
        <div className="flex gap-2 bg-cyber-800 p-1 rounded-lg border border-cyber-700">
            <button 
                onClick={() => setActiveTab('TRAFFIC')}
                className={`px-4 py-2 rounded text-sm font-medium transition-all ${activeTab === 'TRAFFIC' ? 'bg-cyan-600 text-white shadow-lg' : 'text-slate-400 hover:text-slate-200'}`}
            >
                Live Traffic
            </button>
            <button 
                onClick={() => setActiveTab('RULES')}
                className={`px-4 py-2 rounded text-sm font-medium transition-all ${activeTab === 'RULES' ? 'bg-cyan-600 text-white shadow-lg' : 'text-slate-400 hover:text-slate-200'}`}
            >
                Firewall Rules
            </button>
        </div>
      </div>

      {activeTab === 'TRAFFIC' ? (
        <div className="grid grid-cols-12 gap-6 flex-1 min-h-0">
            {/* Packet List */}
            <div className="col-span-8 flex flex-col bg-cyber-800 border border-cyber-700 rounded-xl overflow-hidden shadow-xl">
            <div className="p-4 border-b border-cyber-700 flex justify-between items-center bg-cyber-900/50">
                <div className="flex gap-2">
                <button 
                    onClick={() => setIsMonitoring(!isMonitoring)}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${isMonitoring ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30 hover:bg-rose-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30'}`}
                >
                    {isMonitoring ? <><Pause className="w-4 h-4" /> Stop Capture</> : <><Play className="w-4 h-4" /> Start Capture</>}
                </button>
                <select 
                    className="bg-cyber-900 border border-cyber-700 text-slate-300 text-sm rounded-lg px-3 py-2 outline-none focus:ring-1 focus:ring-cyan-500"
                    value={activeFilter}
                    onChange={(e) => setActiveFilter(e.target.value)}
                >
                    <option value="ALL">All Protocols</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="HTTP">HTTP</option>
                </select>
                </div>
                <span className="text-xs font-mono text-slate-500">BUFFER: {packets.length}/50</span>
            </div>

            <div className="flex-1 overflow-y-auto p-0">
                <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 bg-cyber-900 text-slate-400 text-xs uppercase tracking-wider font-semibold shadow-md z-10">
                    <tr>
                    <th className="p-3 border-b border-cyber-700">Src/Port</th>
                    <th className="p-3 border-b border-cyber-700">Proto</th>
                    <th className="p-3 border-b border-cyber-700">Payload Snip</th>
                    <th className="p-3 border-b border-cyber-700">Verdict</th>
                    <th className="p-3 border-b border-cyber-700">Action</th>
                    </tr>
                </thead>
                <tbody className="text-sm font-mono">
                    {packets
                    .filter(p => activeFilter === 'ALL' || p.protocol === activeFilter)
                    .map((packet) => (
                    <tr key={packet.id} className={`border-b border-cyber-700/50 hover:bg-cyber-700/40 transition-colors ${selectedPacket?.id === packet.id ? 'bg-cyber-700/60' : ''}`}>
                        <td className="p-3">
                            <div className="text-cyan-300">{packet.sourceIp}</div>
                            <div className="text-xs text-slate-500">:{packet.port}</div>
                        </td>
                        <td className="p-3 text-slate-300">{packet.protocol}</td>
                        <td className="p-3 text-slate-500 max-w-[150px] truncate">{packet.payload}</td>
                        <td className="p-3">
                        <span className={`px-2 py-1 rounded text-[10px] font-bold border ${
                            packet.status === 'ALLOWED' ? 'bg-emerald-950/50 text-emerald-400 border-emerald-900' :
                            packet.status === 'ANALYZING' ? 'bg-slate-700 text-slate-300 border-slate-600' :
                            'bg-rose-950/50 text-rose-400 border-rose-900'
                        }`}>
                            {packet.status}
                        </span>
                        </td>
                        <td className="p-3">
                        <button 
                            onClick={() => inspectPacket(packet)}
                            className="text-xs bg-cyber-700 hover:bg-cyber-600 text-slate-300 px-2 py-1 rounded flex items-center gap-1 transition-colors"
                        >
                            <Eye className="w-3 h-3" /> Inspect
                        </button>
                        </td>
                    </tr>
                    ))}
                    {packets.length === 0 && (
                        <tr><td colSpan={5} className="p-10 text-center text-slate-500">No traffic captured. Start monitoring.</td></tr>
                    )}
                </tbody>
                </table>
            </div>
            </div>

            {/* Packet Inspector Panel */}
            <div className="col-span-4 bg-cyber-800 border border-cyber-700 rounded-xl p-6 shadow-xl overflow-y-auto">
            <h3 className="text-lg font-semibold text-slate-200 mb-4 flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" /> DPI Inspector
            </h3>
            
            {selectedPacket ? (
                <div className="space-y-4 animate-fade-in">
                <div className="bg-black/30 rounded-lg p-4 border border-cyber-700 font-mono text-xs space-y-2">
                    <div className="flex justify-between border-b border-white/5 pb-2">
                        <span className="text-slate-500">STATUS</span>
                        <span className={selectedPacket.status === 'ALLOWED' ? 'text-emerald-400' : selectedPacket.status === 'ANALYZING' ? 'text-slate-400' : 'text-rose-400'}>
                            {selectedPacket.status}
                        </span>
                    </div>
                    <div className="flex justify-between pt-2">
                        <span className="text-slate-500">SRC:</span>
                        <span className="text-cyan-400">{selectedPacket.sourceIp}</span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-slate-500">PROTO:</span>
                        <span className="text-slate-200">{selectedPacket.protocol}</span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-slate-500">PORT:</span>
                        <span className="text-slate-200">{selectedPacket.port}</span>
                    </div>
                </div>

                <div>
                    <h4 className="text-sm font-semibold text-slate-400 mb-2">Payload (L7 Data)</h4>
                    <div className="bg-cyber-900 p-3 rounded border border-cyber-700 font-mono text-xs text-slate-400 break-all">
                        {selectedPacket.payload}
                    </div>
                </div>

                {/* Logic for displaying verdict based on layer */}
                {analyzingPacket ? (
                    <div className="flex items-center gap-2 text-cyan-400 text-sm p-4 bg-cyan-900/10 border border-cyan-500/30 rounded">
                        <div className="animate-spin w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full"></div>
                        Running AI DPI Analysis...
                    </div>
                ) : (
                    <div className={`p-4 rounded border ${
                        selectedPacket.status.startsWith('BLOCKED')
                        ? 'bg-rose-950/30 border-rose-500/30' 
                        : selectedPacket.status === 'ANALYZING'
                        ? 'bg-slate-800 border-slate-600'
                        : 'bg-emerald-950/30 border-emerald-500/30'
                    }`}>
                        <h4 className="text-sm font-bold mb-1 flex items-center gap-2">
                            {selectedPacket.status.startsWith('BLOCKED') ? <AlertOctagon className="w-4 h-4 text-rose-500" /> : <Shield className="w-4 h-4 text-emerald-500" />}
                            Verdict
                        </h4>
                        <p className="text-xs text-slate-300 mt-2">
                            {selectedPacket.verdictReason || "Pending deep packet inspection..."}
                        </p>
                    </div>
                )}
                </div>
            ) : (
                <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-3 opacity-50">
                <Filter className="w-12 h-12" />
                <p className="text-sm">Select a packet to inspect</p>
                </div>
            )}
            </div>
        </div>
      ) : (
        /* RULES CONFIGURATION TAB */
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1 animate-slide-up">
            {/* Add New Rule */}
            <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700 h-fit">
                <h3 className="text-lg font-bold text-slate-200 mb-4 flex items-center gap-2">
                    <Settings className="w-5 h-5 text-cyan-400" /> Configure Firewall
                </h3>
                
                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-slate-400 mb-1">Rule Type</label>
                        <select 
                            value={newRuleType}
                            onChange={(e) => setNewRuleType(e.target.value as any)}
                            className="w-full bg-cyber-900 border border-cyber-700 text-slate-200 rounded p-3 outline-none focus:ring-1 focus:ring-cyan-500"
                        >
                            <option value="L4_PORT">Packet Filter (L4) - Block Port</option>
                            <option value="L4_IP">Packet Filter (L4) - Block IP</option>
                            <option value="L7_KEYWORD">Proxy Filter (L7) - Block Keyword</option>
                        </select>
                    </div>
                    
                    <div>
                        <label className="block text-sm font-medium text-slate-400 mb-1">Value</label>
                        <input 
                            type="text"
                            value={newRuleValue}
                            onChange={(e) => setNewRuleValue(e.target.value)}
                            placeholder={newRuleType === 'L4_PORT' ? 'e.g., 8080' : newRuleType === 'L4_IP' ? 'e.g., 192.168.1.50' : 'e.g., admin_panel'}
                            className="w-full bg-cyber-900 border border-cyber-700 text-slate-200 rounded p-3 outline-none focus:ring-1 focus:ring-cyan-500"
                        />
                    </div>

                    <button 
                        onClick={addRule}
                        className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-3 rounded-lg flex items-center justify-center gap-2 transition-all"
                    >
                        <Plus className="w-4 h-4" /> Add Rule
                    </button>
                </div>

                <div className="mt-6 p-4 bg-cyber-900/50 rounded-lg text-xs text-slate-400 space-y-2">
                    <p><strong className="text-cyan-400">L4 Packet Filter:</strong> Blocks traffic at the transport layer (TCP/UDP) based on ports or IPs. Very fast.</p>
                    <p><strong className="text-cyan-400">L7 Proxy Filter:</strong> Inspects application payload content for forbidden strings. Slower but deeper.</p>
                </div>
            </div>

            {/* Active Rules List */}
            <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
                <h3 className="text-lg font-bold text-slate-200 mb-4 flex items-center gap-2">
                    <Lock className="w-5 h-5 text-rose-400" /> Active Rules
                </h3>
                <div className="space-y-3">
                    {rules.length === 0 && <p className="text-slate-500 italic">No rules configured. All traffic allowed (unless flagged by AI).</p>}
                    {rules.map(rule => (
                        <div key={rule.id} className="flex items-center justify-between bg-cyber-900 p-3 rounded border border-cyber-700 group">
                            <div className="flex items-center gap-3">
                                <div className={`w-2 h-2 rounded-full ${rule.active ? 'bg-emerald-400 shadow-[0_0_5px_#10b981]' : 'bg-slate-600'}`}></div>
                                <div>
                                    <div className="text-sm font-mono text-slate-200">
                                        {rule.type === 'L4_PORT' && `BLOCK PORT: ${rule.value}`}
                                        {rule.type === 'L4_IP' && `BLOCK IP: ${rule.value}`}
                                        {rule.type === 'L7_KEYWORD' && `BLOCK CONTENT: "${rule.value}"`}
                                    </div>
                                    <div className="text-[10px] text-slate-500">{rule.type.split('_')[0]} Layer Protection</div>
                                </div>
                            </div>
                            <div className="flex items-center gap-2">
                                <button 
                                    onClick={() => toggleRule(rule.id)}
                                    className={`text-xs px-2 py-1 rounded border ${rule.active ? 'border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10' : 'border-slate-600 text-slate-500'}`}
                                >
                                    {rule.active ? 'Active' : 'Disabled'}
                                </button>
                                <button 
                                    onClick={() => deleteRule(rule.id)}
                                    className="p-1.5 text-slate-500 hover:text-rose-400 transition-colors"
                                >
                                    <Trash2 className="w-4 h-4" />
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
      )}
    </div>
  );
};