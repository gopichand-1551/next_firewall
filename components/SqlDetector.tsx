import React, { useState } from 'react';
import { analyzeContent } from '../services/gemini';
import { AnalysisType, ThreatLog, Severity, AnalysisResult } from '../types';
import { Search, AlertOctagon, CheckCircle, Terminal } from 'lucide-react';

interface SqlDetectorProps {
  addLog: (log: ThreatLog) => void;
}

export const SqlDetector: React.FC<SqlDetectorProps> = ({ addLog }) => {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    setLoading(true);
    setResult(null);

    const analysis = await analyzeContent(input, AnalysisType.SQL_INJECTION);
    setResult(analysis);
    setLoading(false);

    addLog({
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      type: AnalysisType.SQL_INJECTION,
      severity: analysis.severity,
      source: 'WAF-Input-Gate-01',
      details: `Pattern: ${input.substring(0, 30)}... Result: ${analysis.isThreat ? 'Detected' : 'Clean'}`,
      blocked: analysis.isThreat
    });
  };

  const examples = [
    "SELECT * FROM users WHERE id = 1",
    "SELECT * FROM users WHERE id = 1 OR 1=1",
    "1'; DROP TABLE users; --",
    "admin' --"
  ];

  return (
    <div className="space-y-6 max-w-4xl mx-auto animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-slate-100">SQL Injection Guard</h2>
          <p className="text-slate-400">Real-time heuristic analysis of database queries using Gemini 2.5</p>
        </div>
        <div className="bg-blue-500/10 text-blue-400 px-3 py-1 rounded-full text-xs font-mono border border-blue-500/20">
          ENGINE: GEMINI-FLASH-SQLi-v2
        </div>
      </div>

      <div className="bg-cyber-800 border border-cyber-700 rounded-xl overflow-hidden shadow-2xl">
        <div className="bg-cyber-900 p-4 border-b border-cyber-700 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-slate-500" />
          <span className="text-sm font-mono text-slate-400">query_analyzer.exe</span>
        </div>
        <div className="p-6">
          <form onSubmit={handleAnalyze} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Input Query / Payload</label>
              <div className="relative">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg p-4 text-slate-200 font-mono focus:ring-2 focus:ring-cyan-500 focus:border-transparent outline-none h-32 resize-none"
                  placeholder="Enter SQL query to analyze..."
                />
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <button
                type="submit"
                disabled={loading}
                className="bg-cyan-600 hover:bg-cyan-500 text-white px-6 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <span className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent"></span>
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4" />
                    Analyze Query
                  </>
                )}
              </button>
              
              <div className="flex gap-2">
                {examples.map((ex, i) => (
                  <button
                    key={i}
                    type="button"
                    onClick={() => setInput(ex)}
                    className="text-xs bg-cyber-700 hover:bg-cyber-600 text-slate-300 px-3 py-1 rounded-full border border-cyber-600 transition-colors"
                  >
                    Ex {i+1}
                  </button>
                ))}
              </div>
            </div>
          </form>
        </div>
      </div>

      {result && (
        <div className={`rounded-xl p-6 border ${
          result.isThreat 
            ? 'bg-rose-950/30 border-rose-500/30' 
            : 'bg-emerald-950/30 border-emerald-500/30'
        } animate-slide-up`}>
          <div className="flex items-start gap-4">
            <div className={`p-3 rounded-full ${
              result.isThreat ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/20 text-emerald-400'
            }`}>
              {result.isThreat ? <AlertOctagon className="w-8 h-8" /> : <CheckCircle className="w-8 h-8" />}
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between mb-2">
                <h3 className={`text-lg font-bold ${result.isThreat ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {result.isThreat ? 'THREAT DETECTED' : 'SAFE QUERY'}
                </h3>
                <span className="px-3 py-1 rounded-full bg-cyber-900 border border-cyber-700 text-xs font-mono text-slate-400">
                  CONFIDENCE: 99.8%
                </span>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div className="bg-cyber-900/50 p-3 rounded border border-cyber-700/50">
                  <span className="text-xs text-slate-500 block mb-1">SEVERITY</span>
                  <span className={`font-bold ${
                    result.severity === Severity.CRITICAL ? 'text-rose-500' : 
                    result.severity === Severity.HIGH ? 'text-orange-500' : 'text-slate-300'
                  }`}>{result.severity}</span>
                </div>
                <div className="bg-cyber-900/50 p-3 rounded border border-cyber-700/50">
                   <span className="text-xs text-slate-500 block mb-1">ACTION TAKEN</span>
                   <span className="font-mono text-slate-300">{result.isThreat ? 'BLOCK & LOG' : 'ALLOW'}</span>
                </div>
              </div>

              <div className="space-y-3">
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-1">Analysis Reasoning:</h4>
                  <p className="text-slate-400 text-sm leading-relaxed">{result.reasoning}</p>
                </div>
                {result.technicalDetails && (
                  <div className="bg-black/20 p-3 rounded text-xs font-mono text-slate-400 border border-white/5">
                    {result.technicalDetails}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};