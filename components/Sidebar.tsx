import React from 'react';
import { TabView } from '../types';
import { 
  ShieldCheck, 
  Database, 
  MailWarning, 
  Network, 
  FileText, 
  Activity,
  Zap
} from 'lucide-react';

interface SidebarProps {
  activeTab: TabView;
  setActiveTab: (tab: TabView) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab }) => {
  const navItems = [
    { id: TabView.DASHBOARD, label: 'Overview', icon: Activity },
    { id: TabView.SQL_DETECTOR, label: 'SQL Guard', icon: Database },
    { id: TabView.PHISHING_MALWARE, label: 'Phishing & Malware', icon: MailWarning },
    { id: TabView.NETWORK_GUARD, label: 'NGFW & Packets', icon: Network },
    { id: TabView.DOS_GUARD, label: 'DDoS Protection', icon: Zap },
    { id: TabView.DOCUMENTATION, label: 'Documentation', icon: FileText },
  ];

  return (
    <div className="w-64 bg-cyber-800 border-r border-cyber-700 flex flex-col h-full fixed left-0 top-0 z-10">
      <div className="p-6 flex items-center gap-3 border-b border-cyber-700">
        <div className="w-8 h-8 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center">
          <ShieldCheck className="w-5 h-5 text-white" />
        </div>
        <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 to-blue-400">
          SentinAI
        </h1>
      </div>

      <nav className="flex-1 p-4 space-y-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                isActive 
                  ? 'bg-cyber-700 text-cyan-400 border-l-4 border-cyan-400 shadow-lg shadow-cyan-900/20' 
                  : 'text-slate-400 hover:bg-cyber-700/50 hover:text-slate-200'
              }`}
            >
              <Icon className={`w-5 h-5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
              <span className="font-medium">{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="p-4 border-t border-cyber-700">
        <div className="bg-cyber-900/50 rounded-lg p-3 text-xs text-slate-500">
          <p className="mb-1 font-semibold text-slate-400">System Status</p>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
            <span>Engine Active</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-blue-500"></span>
            <span>Gemini 2.5 Connected</span>
          </div>
        </div>
      </div>
    </div>
  );
};