
// Initialize Icons
lucide.createIcons();

// State
let logs = [];
let packets = [];
let rules = [
    { id: '1', type: 'L4_PORT', value: 8080, active: true },
    { id: '2', type: 'L7_KEYWORD', value: 'cmd.exe', active: true }
];
let monitoring = false;
let monitorInterval = null;
let dosMode = 'NORMAL';
let mitigation = false;
let dosChartInstance = null;

// Navigation
const views = ['dashboard', 'sql', 'phishing', 'network', 'dos', 'docs'];
const navItems = [
    { id: 'dashboard', label: 'Overview', icon: 'activity' },
    { id: 'sql', label: 'SQL Guard', icon: 'database' },
    { id: 'phishing', label: 'Phishing & Malware', icon: 'mail-warning' },
    { id: 'network', label: 'NGFW & Packets', icon: 'network' },
    { id: 'dos', label: 'DDoS Protection', icon: 'zap' },
    { id: 'docs', label: 'Documentation', icon: 'file-text' }
];

function initNav() {
    const container = document.getElementById('nav-menu');
    container.innerHTML = navItems.map(item => `
        <button onclick="switchView('${item.id}')" id="nav-${item.id}" 
            class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 text-slate-400 hover:bg-cyber-700/50 hover:text-slate-200">
            <i data-lucide="${item.icon}" class="w-5 h-5"></i>
            <span class="font-medium">${item.label}</span>
        </button>
    `).join('');
    lucide.createIcons();
    switchView('dashboard');
    initDashboardCharts();
    initDosChart();
    renderRules();
}

function switchView(id) {
    document.querySelectorAll('.view-section').forEach(el => el.classList.add('hidden'));
    document.getElementById(`view-${id}`).classList.remove('hidden');
    
    document.querySelectorAll('nav button').forEach(btn => {
        btn.classList.remove('bg-cyber-700', 'text-cyan-400', 'border-l-4', 'border-cyan-400', 'shadow-lg');
        btn.classList.add('text-slate-400');
    });
    const activeBtn = document.getElementById(`nav-${id}`);
    activeBtn.classList.add('bg-cyber-700', 'text-cyan-400', 'border-l-4', 'border-cyan-400', 'shadow-lg');
    activeBtn.classList.remove('text-slate-400');
}

// --- LOGIC: LOGS ---
function addLog(log) {
    logs.unshift(log);
    updateDashboard();
}

function updateDashboard() {
    document.getElementById('stat-threats').innerText = logs.filter(l => l.severity !== 'SAFE').length;
    document.getElementById('stat-blocked').innerText = logs.filter(l => l.blocked).length;
    
    const tbody = document.getElementById('logs-body');
    tbody.innerHTML = logs.slice(0, 5).map(log => `
        <tr class="border-b border-cyber-700/50">
            <td class="p-3 font-mono text-xs">${log.timestamp.split('T')[1].split('.')[0]}</td>
            <td class="p-3">${log.type}</td>
            <td class="p-3"><span class="px-2 py-1 rounded text-xs font-bold ${getSeverityClass(log.severity)}">${log.severity}</span></td>
            <td class="p-3 truncate max-w-xs text-slate-400">${log.details}</td>
            <td class="p-3 ${log.blocked ? 'text-emerald-400' : 'text-rose-400'}">${log.blocked ? 'BLOCKED' : 'ALERT'}</td>
        </tr>
    `).join('');
    updateCharts();
}

function getSeverityClass(s) {
    if (s === 'CRITICAL') return 'bg-rose-950 text-rose-400';
    if (s === 'HIGH') return 'bg-orange-950 text-orange-400';
    if (s === 'MEDIUM') return 'bg-yellow-950 text-yellow-400';
    return 'bg-blue-950 text-blue-400';
}

// --- LOGIC: SQL & PHISHING ---
async function analyzeSql() {
    const content = document.getElementById('sql-input').value;
    if (!content) return;
    
    const resultDiv = document.getElementById('sql-result');
    resultDiv.classList.remove('hidden');
    resultDiv.innerHTML = `<div class="text-cyan-400 p-4">Analyzing with Gemini...</div>`;

    const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ content, type: 'SQL_INJECTION' })
    });
    const data = await res.json();
    
    addLog({
        timestamp: new Date().toISOString(),
        type: 'SQL_INJECTION',
        severity: data.severity,
        details: `Query Analysis: ${data.isThreat ? 'Threat' : 'Safe'}`,
        blocked: data.isThreat
    });

    resultDiv.innerHTML = renderResultCard(data);
}

async function analyzePhishing() {
    const content = document.getElementById('phishing-input').value;
    if (!content) return;
    
    const resultDiv = document.getElementById('phishing-result');
    resultDiv.classList.remove('hidden');
    resultDiv.innerHTML = `<div class="text-cyan-400 p-4">Scanning URL...</div>`;

    const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ content, type: 'PHISHING' })
    });
    const data = await res.json();

    addLog({
        timestamp: new Date().toISOString(),
        type: 'PHISHING',
        severity: data.severity,
        details: `URL Scan: ${data.isThreat ? 'Malicious' : 'Clean'}`,
        blocked: data.isThreat
    });

    resultDiv.innerHTML = renderResultCard(data);
}

function renderResultCard(data) {
    const color = data.isThreat ? 'rose' : 'emerald';
    return `
        <div class="rounded-xl p-6 border bg-${color}-950/30 border-${color}-500/30">
            <h3 class="text-lg font-bold text-${color}-400 mb-2">${data.isThreat ? 'THREAT DETECTED' : 'SAFE'}</h3>
            <p class="text-slate-300 mb-2"><strong>Reasoning:</strong> ${data.reasoning}</p>
            <p class="text-slate-400 text-xs font-mono">Action: ${data.suggestedAction}</p>
        </div>
    `;
}

// --- LOGIC: NETWORK GUARD ---
function toggleNetworkTab(tab) {
    document.getElementById('net-tab-traffic').classList.toggle('hidden', tab !== 'TRAFFIC');
    document.getElementById('net-tab-rules').classList.toggle('hidden', tab !== 'RULES');
    document.getElementById('btn-tab-traffic').className = tab === 'TRAFFIC' ? 'px-4 py-2 rounded text-sm font-medium bg-cyan-600 text-white' : 'px-4 py-2 rounded text-sm font-medium text-slate-400';
    document.getElementById('btn-tab-rules').className = tab === 'RULES' ? 'px-4 py-2 rounded text-sm font-medium bg-cyan-600 text-white' : 'px-4 py-2 rounded text-sm font-medium text-slate-400';
}

function toggleMonitoring() {
    monitoring = !monitoring;
    const btn = document.getElementById('btn-monitor');
    if (monitoring) {
        btn.innerHTML = `<i data-lucide="pause" class="w-4 h-4"></i> Stop Capture`;
        btn.className = "flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm bg-rose-500/20 text-rose-400 border border-rose-500/30";
        lucide.createIcons();
        monitorInterval = setInterval(generatePacket, 1500);
    } else {
        btn.innerHTML = `<i data-lucide="play" class="w-4 h-4"></i> Start Capture`;
        btn.className = "flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
        lucide.createIcons();
        clearInterval(monitorInterval);
    }
}

async function generatePacket() {
    // Generate local mock first for speed
    const protocols = ['TCP', 'UDP', 'HTTP'];
    const port = Math.floor(Math.random() * 10000);
    const srcIp = `192.168.1.${Math.floor(Math.random() * 255)}`;
    
    // Fetch random payload from API
    const res = await fetch('/api/mock-packet');
    const { payload } = await res.json();

    let status = 'ANALYZING';
    let blocked = false;

    // Local Rule Check
    if (rules.some(r => r.active && r.type === 'L4_PORT' && r.value == port)) status = 'BLOCKED_L4';
    if (rules.some(r => r.active && r.type === 'L7_KEYWORD' && payload.includes(r.value))) status = 'BLOCKED_L7';

    if (status.startsWith('BLOCKED')) {
        blocked = true;
        addLog({
            timestamp: new Date().toISOString(),
            type: 'PACKET_INSPECTION',
            severity: 'MEDIUM',
            details: `Firewall Rule Block: ${status}`,
            blocked: true
        });
    }

    const packet = { id: Date.now(), srcIp, port, protocol: protocols[Math.floor(Math.random()*3)], payload, status };
    packets.unshift(packet);
    if (packets.length > 50) packets.pop();
    
    document.getElementById('packet-count').innerText = packets.length;
    renderPackets();
}

function renderPackets() {
    const container = document.getElementById('packet-list');
    container.innerHTML = packets.map(p => `
        <tr class="border-b border-cyber-700/50 hover:bg-cyber-700/40 cursor-pointer" onclick='inspectPacket(${JSON.stringify(p)})'>
            <td class="p-3"><div class="text-cyan-300">${p.srcIp}</div><div class="text-xs text-slate-500">:${p.port}</div></td>
            <td class="p-3 text-slate-300">${p.protocol}</td>
            <td class="p-3 text-slate-500 truncate max-w-[100px]">${p.payload}</td>
            <td class="p-3"><span class="px-2 py-1 rounded text-[10px] border ${getStatusClass(p.status)}">${p.status}</span></td>
            <td class="p-3"><button class="text-xs bg-cyber-700 px-2 py-1 rounded">Inspect</button></td>
        </tr>
    `).join('');
}

function getStatusClass(s) {
    if (s === 'ALLOWED') return 'bg-emerald-950/50 text-emerald-400 border-emerald-900';
    if (s === 'ANALYZING') return 'bg-slate-700 text-slate-300 border-slate-600';
    return 'bg-rose-950/50 text-rose-400 border-rose-900';
}

async function inspectPacket(p) {
    const container = document.getElementById('packet-details');
    
    if (p.status === 'ANALYZING') {
        container.innerHTML = `<div class="text-cyan-400 flex items-center gap-2"><div class="animate-spin w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full"></div> Running AI DPI...</div>`;
        // Call AI
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ content: `Payload: ${p.payload}`, type: 'PACKET_INSPECTION' })
        });
        const analysis = await res.json();
        p.status = analysis.isThreat ? 'BLOCKED_AI' : 'ALLOWED';
        p.verdict = analysis.reasoning;
        renderPackets(); // Update list status
    }

    container.innerHTML = `
        <div class="bg-black/30 rounded-lg p-4 border border-cyber-700 font-mono text-xs space-y-2">
            <div class="flex justify-between"><span class="text-slate-500">SRC</span><span class="text-cyan-400">${p.srcIp}:${p.port}</span></div>
            <div class="flex justify-between"><span class="text-slate-500">PROTO</span><span>${p.protocol}</span></div>
            <div class="mt-2"><div class="text-slate-500 mb-1">PAYLOAD</div><div class="bg-cyber-900 p-2 rounded break-all">${p.payload}</div></div>
            <div class="mt-4 p-2 rounded border ${getStatusClass(p.status)} text-center font-bold">${p.status}</div>
            <div class="text-slate-400 mt-2">${p.verdict || ''}</div>
        </div>
    `;
}

// --- RULES ---
function renderRules() {
    document.getElementById('rules-list').innerHTML = rules.map(r => `
        <div class="flex justify-between bg-cyber-900 p-3 rounded border border-cyber-700">
            <div class="text-sm text-slate-200">${r.type}: ${r.value}</div>
            <button onclick="rules = rules.filter(x => x.id !== '${r.id}'); renderRules();" class="text-rose-400"><i data-lucide="trash-2" class="w-4 h-4"></i></button>
        </div>
    `).join('');
    lucide.createIcons();
}

function addRule() {
    const type = document.getElementById('rule-type').value;
    const value = document.getElementById('rule-value').value;
    if(value) {
        rules.push({ id: Date.now().toString(), type, value, active: true });
        renderRules();
        document.getElementById('rule-value').value = '';
    }
}

// --- DOS GUARD ---
function toggleMitigation() {
    mitigation = !mitigation;
    const btn = document.getElementById('btn-mitigation');
    if(mitigation) {
        btn.innerText = "MITIGATION ACTIVE";
        btn.className = "px-4 py-2 rounded-lg font-bold text-sm bg-emerald-500/20 text-emerald-400 border border-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.3)]";
    } else {
        btn.innerText = "ENABLE MITIGATION";
        btn.className = "px-4 py-2 rounded-lg font-bold text-sm border bg-cyber-800 text-slate-400 border-cyber-700";
    }
}

function setDosMode(mode) {
    dosMode = mode;
}

function initDosChart() {
    const ctx = document.getElementById('dosChart').getContext('2d');
    dosChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(20).fill(''),
            datasets: [{
                label: 'Requests Per Second',
                data: Array(20).fill(0),
                borderColor: '#38bdf8',
                backgroundColor: 'rgba(56, 189, 248, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            scales: { y: { beginAtZero: true, grid: { color: '#334155' } }, x: { display: false } },
            plugins: { legend: { display: false } }
        }
    });

    setInterval(() => {
        let rps = 20 + Math.random() * 30;
        if (dosMode === 'HTTP_FLOOD') rps = 800 + Math.random() * 400;
        if (dosMode === 'UDP_FLOOD') rps = 2000 + Math.random() * 1000;
        if (mitigation && dosMode !== 'NORMAL') rps *= 0.1;

        document.getElementById('dos-rps').innerText = Math.floor(rps);
        document.getElementById('dos-ips').innerText = Math.floor(rps / 5);

        const data = dosChartInstance.data.datasets[0].data;
        data.push(rps);
        data.shift();
        dosChartInstance.update();
    }, 1000);
}

async function analyzeDos() {
    const rps = document.getElementById('dos-rps').innerText;
    const content = `Traffic Analysis Report: Current RPS: ${rps}, Mode: ${dosMode}. Identify attack type.`;
    
    const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ content, type: 'DOS_DDOS' })
    });
    const data = await res.json();
    
    addLog({
        timestamp: new Date().toISOString(),
        type: 'DOS_DDOS',
        severity: data.severity,
        details: data.reasoning,
        blocked: mitigation
    });
    alert(`AI Analysis:\n${data.reasoning}`);
}

// --- DASHBOARD CHARTS ---
let severityChart, typeChart;

function initDashboardCharts() {
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = '#334155';
    
    const ctx1 = document.getElementById('chartSeverity');
    if (ctx1) {
        severityChart = new Chart(ctx1, {
            type: 'bar',
            data: {
                labels: ['Low', 'Medium', 'High', 'Critical'],
                datasets: [{
                    label: 'Threats',
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#38bdf8', '#facc15', '#f97316', '#f43f5e']
                }]
            },
            options: { responsive: true, plugins: { legend: { display: false } } }
        });
    }

    const ctx2 = document.getElementById('chartType');
    if (ctx2) {
        typeChart = new Chart(ctx2, {
            type: 'doughnut',
            data: {
                labels: ['SQLi', 'Phishing', 'Malware', 'Network'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#38bdf8', '#facc15', '#f97316', '#f43f5e'],
                    borderWidth: 0
                }]
            },
            options: { responsive: true }
        });
    }
}

function updateCharts() {
    if (!severityChart || !typeChart) return;
    
    const severityCounts = { 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0 };
    logs.forEach(l => { if(severityCounts[l.severity] !== undefined) severityCounts[l.severity]++ });
    severityChart.data.datasets[0].data = Object.values(severityCounts);
    severityChart.update();

    const typeCounts = { 'SQL_INJECTION': 0, 'PHISHING': 0, 'MALWARE': 0, 'PACKET_INSPECTION': 0 };
    logs.forEach(l => { if(typeCounts[l.type] !== undefined) typeCounts[l.type]++ });
    typeChart.data.datasets[0].data = Object.values(typeCounts);
    typeChart.update();
}

function setSqlEx(n) {
    document.getElementById('sql-input').value = n===1 ? "SELECT * FROM users WHERE id = 1 OR 1=1" : "admin' --";
}

// Start
window.onload = initNav;
