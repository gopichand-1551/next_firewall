import React, { useState } from 'react';
import { Sidebar } from './Sidebar';
import { Dashboard } from './Dashboard';
import { SqlDetector } from './SqlDetector';
import { PhishingMalware } from './PhishingMalware';
import { NetworkGuard } from './NetworkGuard';
import { DosGuard } from './DosGuard';
import { Documentation } from './Documentation';
import { ThreatLog, TabView } from '../types';

export const Layout: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabView>(TabView.DASHBOARD);
  const [logs, setLogs] = useState<ThreatLog[]>([]);

  const addLog = (log: ThreatLog) => {
    setLogs(prev => [log, ...prev]);
  };

  const renderContent = () => {
    switch (activeTab) {
      case TabView.DASHBOARD:
        return <Dashboard logs={logs} />;
      case TabView.SQL_DETECTOR:
        return <SqlDetector addLog={addLog} />;
      case TabView.PHISHING_MALWARE:
        return <PhishingMalware addLog={addLog} />;
      case TabView.NETWORK_GUARD:
        return <NetworkGuard addLog={addLog} />;
      case TabView.DOS_GUARD:
        return <DosGuard addLog={addLog} />;
      case TabView.DOCUMENTATION:
        return <Documentation />;
      default:
        return <Dashboard logs={logs} />;
    }
  };

  return (
    <div className="min-h-screen bg-cyber-900 text-slate-200 font-sans">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      <main className="ml-64 p-8 h-screen overflow-y-auto">
        {renderContent()}
      </main>
    </div>
  );
};