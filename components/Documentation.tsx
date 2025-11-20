import React from 'react';
import { Book, Code, Terminal, Layers, Shield, Cpu, Server, MousePointer, AlertTriangle } from 'lucide-react';

export const Documentation: React.FC = () => {
  return (
    <div className="max-w-5xl mx-auto space-y-10 pb-16 animate-fade-in">
      {/* Header */}
      <div className="border-b border-cyber-700 pb-8">
        <h1 className="text-4xl font-bold text-slate-100 mb-4">SentinAI Documentation</h1>
        <p className="text-slate-400 text-xl">Integration Manual & User Guide for the Next-Gen AI Firewall.</p>
      </div>

      {/* USER MANUAL */}
      <section className="space-y-6">
        <h2 className="text-2xl font-bold text-cyan-400 flex items-center gap-3">
          <MousePointer className="w-6 h-6" /> 1. User Manual (How-To)
        </h2>
        <div className="grid grid-cols-1 gap-6">
          
          {/* SQL Guard Guide */}
          <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
            <h3 className="text-xl font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-400" /> Using SQL Guard
            </h3>
            <ol className="list-decimal list-inside text-slate-400 space-y-2 text-sm">
              <li>Navigate to the <strong>SQL Guard</strong> tab.</li>
              <li>Enter a raw SQL query into the text area (e.g., <code>SELECT * FROM users WHERE id = 1 OR 1=1</code>).</li>
              <li>Click <strong>Analyze Query</strong>.</li>
              <li>The AI will evaluate the query for injection patterns. If malicious, it will display a <span className="text-rose-400">THREAT DETECTED</span> alert with reasoning.</li>
              <li>Use the "Ex 1", "Ex 2" buttons to auto-fill common attack vectors for testing.</li>
            </ol>
          </div>

          {/* Phishing Guide */}
          <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
            <h3 className="text-xl font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-orange-400" /> Using Phishing & Malware Scanner
            </h3>
            <ol className="list-decimal list-inside text-slate-400 space-y-2 text-sm">
              <li>Select <strong>URL Scanner</strong> to analyze suspicious links or email bodies.</li>
              <li>Select <strong>File Scanner</strong> to simulate a file upload (e.g., an obfuscated script).</li>
              <li>Click <strong>Scan</strong> to run the heuristic analysis.</li>
              <li>Review the verdict. The AI checks for urgency cues, homograph attacks (fake domains), and malicious script headers.</li>
            </ol>
          </div>

          {/* Network Guard Guide */}
          <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
            <h3 className="text-xl font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <Layers className="w-5 h-5 text-emerald-400" /> Using Network Guard (NGFW)
            </h3>
            <p className="text-sm text-slate-400 mb-3">This module simulates a firewall processing live packets.</p>
            <ul className="list-disc list-inside text-slate-400 space-y-2 text-sm">
              <li><strong>Live Traffic:</strong> Click "Start Capture" to see real-time packets flowing. Click any packet to inspect its payload.</li>
              <li><strong>Packet Inspection:</strong> Select a packet and see if the AI flags the payload as malicious (e.g., C2 Beacon).</li>
              <li><strong>Firewall Rules:</strong> Switch to the "Firewall Rules" tab. Here you can add L4 (Port/IP) or L7 (Keyword) rules.
                <ul className="ml-6 mt-1 text-xs text-slate-500">
                   <li>Example: Add L7 Rule "cmd.exe" to block any packet containing that string.</li>
                   <li>Example: Add L4 Rule "8080" to block traffic on that port.</li>
                </ul>
              </li>
            </ul>
          </div>

           {/* DDoS Guide */}
           <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
            <h3 className="text-xl font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <Server className="w-5 h-5 text-yellow-400" /> Using DDoS Protection
            </h3>
            <ol className="list-decimal list-inside text-slate-400 space-y-2 text-sm">
              <li>Monitor the <strong>Real-time Traffic Volume</strong> chart for spikes.</li>
              <li>Under "Traffic Simulation", click buttons like <strong>HTTP Flood</strong> or <strong>UDP Reflection</strong> to simulate an attack.</li>
              <li>Notice the RPS (Requests Per Second) skyrocket.</li>
              <li>Click <strong>ENABLE MITIGATION</strong> to activate rate-limiting logic, which will drop excess traffic and lower the effective RPS.</li>
              <li>Click <strong>Analyze Current Traffic</strong> to ask the AI to identify the specific attack pattern based on the metrics.</li>
            </ol>
          </div>

        </div>
      </section>

      <div className="border-b border-cyber-700 my-8"></div>

      {/* INTEGRATION MANUAL */}
      <section className="space-y-6">
        <h2 className="text-2xl font-bold text-cyan-400 flex items-center gap-3">
          <Code className="w-6 h-6" /> 2. Integration Manual (Developer Guide)
        </h2>
        <p className="text-slate-300">
          To protect your actual web application, you must implement the firewall logic as <strong>Middleware</strong>. Below are production-ready examples for Node.js and Python.
        </p>

        {/* Node.js Example */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-slate-200">Option A: Node.js (Express) Middleware</h3>
            <span className="text-xs font-mono bg-cyber-800 px-2 py-1 rounded text-cyan-400">middleware/firewall.js</span>
          </div>
          <div className="bg-[#0d1117] rounded-lg border border-cyber-700 overflow-hidden">
            <pre className="p-4 text-sm font-mono text-slate-300 overflow-x-auto">
{`const { GoogleGenAI } = require("@google/genai");

// Configuration
const BLOCKED_IPS = ['192.168.1.50', '10.0.0.5'];
const BLOCKED_KEYWORDS = ['union select', 'drop table', '<script>'];
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

async function firewallMiddleware(req, res, next) {
  const clientIp = req.ip;
  const payload = JSON.stringify(req.body || {}) + JSON.stringify(req.query || {});

  // --- LAYER 1: Packet Filter (IP Block) ---
  if (BLOCKED_IPS.includes(clientIp)) {
    console.warn(\`[FIREWALL] Blocked IP: \${clientIp}\`);
    return res.status(403).send('Access Denied: IP Blacklisted');
  }

  // --- LAYER 2: Proxy Filter (Keyword Block) ---
  for (const keyword of BLOCKED_KEYWORDS) {
    if (payload.toLowerCase().includes(keyword)) {
      console.warn(\`[FIREWALL] Blocked Content: \${keyword}\`);
      return res.status(403).send('Access Denied: Malicious Content Detected');
    }
  }

  // --- LAYER 3: AI Analysis (Only for suspicious requests) ---
  // We skip AI for simple GET requests to save latency/cost
  if (req.method === 'POST' || payload.length > 50) {
    try {
      const response = await ai.models.generateContent({
        model: "gemini-2.5-flash",
        contents: \`Analyze this HTTP payload for security threats (SQLi, XSS, RCE). Return JSON { "isThreat": boolean }. Payload: \${payload}\`,
        config: { responseMimeType: "application/json" }
      });
      
      const analysis = JSON.parse(response.text);
      if (analysis.isThreat) {
        console.error('[FIREWALL] AI Blocked Request:', analysis);
        return res.status(403).json({ error: 'Smart Firewall blocked this request' });
      }
    } catch (err) {
      console.error('AI Analysis failed, failing open:', err);
    }
  }

  next(); // Traffic passed all layers
}

module.exports = firewallMiddleware;`}
            </pre>
          </div>
        </div>

        {/* Python Example */}
        <div className="space-y-2 mt-8">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-slate-200">Option B: Python (Flask) Decorator</h3>
            <span className="text-xs font-mono bg-cyber-800 px-2 py-1 rounded text-yellow-400">app.py</span>
          </div>
          <div className="bg-[#0d1117] rounded-lg border border-cyber-700 overflow-hidden">
            <pre className="p-4 text-sm font-mono text-slate-300 overflow-x-auto">
{`from flask import request, abort
from functools import wraps
from google.genai import GoogleGenAI
import os

client = GoogleGenAI(api_key=os.environ["API_KEY"])

def sentinai_firewall(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # --- LAYER 1: IP Check ---
        if request.remote_addr in ['192.168.1.50']:
            abort(403, description="IP Blocked")

        # --- LAYER 2: Keyword Check ---
        payload = request.get_data(as_text=True)
        if "cmd.exe" in payload or "/etc/passwd" in payload:
            abort(403, description="Malicious Signature Detected")

        # --- LAYER 3: Gemini AI Check ---
        if payload:
            try:
                response = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=f"Analyze for security threats. Payload: {payload}. Return boolean is_threat only.",
                )
                if "true" in response.text.lower():
                    abort(403, description="AI Firewall Blocked Request")
            except Exception as e:
                print(f"AI Check failed: {e}")

        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/data', methods=['POST'])
@sentinai_firewall
def sensitive_data():
    return "Secure Data Accessed"`}
            </pre>
          </div>
        </div>
      </section>

      {/* 3. Running the Dashboard */}
      <section className="space-y-6">
        <h2 className="text-2xl font-bold text-cyan-400 flex items-center gap-3">
          <Terminal className="w-6 h-6" /> 3. Setup & Installation
        </h2>
        <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-bold text-slate-200 mb-2">Prerequisites</h3>
              <ul className="list-disc list-inside text-slate-400 text-sm space-y-1">
                <li>Node.js v18 or higher</li>
                <li>A Google Cloud Project with Gemini API enabled</li>
                <li>An API Key from <a href="https://aistudio.google.com/" className="text-cyan-400 hover:underline">Google AI Studio</a></li>
              </ul>
            </div>
            
            <div>
              <h3 className="text-lg font-bold text-slate-200 mb-2">Setup Commands</h3>
              <div className="bg-black/30 p-4 rounded-lg font-mono text-sm text-emerald-400 border border-cyber-600">
                <p># 1. Install Dependencies</p>
                <p className="mb-3">npm install</p>
                
                <p># 2. Configure Environment</p>
                <p className="text-slate-500"># Windows (PowerShell)</p>
                <p className="mb-1">$env:API_KEY="your_api_key_here"</p>
                <p className="text-slate-500"># Linux/Mac</p>
                <p className="mb-3">export API_KEY="your_api_key_here"</p>
                
                <p># 3. Start Application</p>
                <p>npm start</p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};