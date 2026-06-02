/**
 * DMARC Report Analyzer - Frontend JavaScript
 * Handles file upload, API calls, and results visualization
 */

let currentReport = null;
let currentAnalysis = null;

// DOM Elements
const uploadBox = document.getElementById('uploadBox');
const fileInput = document.getElementById('fileInput');
const fileSelectBtn = document.getElementById('fileSelectBtn');
const analyzeBtn = document.getElementById('analyzeBtn');
const progressContainer = document.getElementById('progressContainer');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');
const errorContainer = document.getElementById('errorContainer');
const errorText = document.getElementById('errorText');
const resultsSection = document.getElementById('resultsSection');

// Setup event listeners
setupEventListeners();

function setupEventListeners() {
  fileSelectBtn.addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      updateUploadUI(e.target.files[0]);
    }
  });

  // Drag and drop
  uploadBox.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadBox.classList.add('drag-over');
  });

  uploadBox.addEventListener('dragleave', () => {
    uploadBox.classList.remove('drag-over');
  });

  uploadBox.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadBox.classList.remove('drag-over');
    if (e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      updateUploadUI(e.dataTransfer.files[0]);
    }
  });

  analyzeBtn.addEventListener('click', analyzeReport);
}

function updateUploadUI(file) {
  uploadBox.innerHTML = `
    <div style="color: #10b981; font-size: 2rem; margin-bottom: 10px;">✅</div>
    <p style="color: #fff; margin: 0;"><strong>${file.name}</strong></p>
    <p style="color: #9ca3af; margin: 5px 0 0 0; font-size: 0.9rem;">${(file.size / 1024).toFixed(2)} KB</p>
  `;
  analyzeBtn.disabled = false;
}

async function analyzeReport() {
  if (!fileInput.files.length) {
    showError('No file selected');
    return;
  }

  const file = fileInput.files[0];
  showProgress('Uploading and parsing DMARC report...');
  hideError();

  try {
    // Step 1: Upload and parse
    const formData = new FormData();
    formData.append('file', file);

    const uploadResponse = await fetch('/api/dmarc/upload', {
      method: 'POST',
      body: formData
    });

    if (!uploadResponse.ok) {
      const error = await uploadResponse.json();
      throw new Error(error.error || 'Failed to upload file');
    }

    const uploadData = await uploadResponse.json();
    if (!uploadData.success) {
      throw new Error(uploadData.error || 'Failed to parse report');
    }

    currentReport = uploadData.data;
    updateProgress('Analyzing report data...');

    // Step 2: Analyze
    const analyzeResponse = await fetch('/api/dmarc/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(currentReport)
    });

    if (!analyzeResponse.ok) {
      const error = await analyzeResponse.json();
      throw new Error(error.error || 'Failed to analyze report');
    }

    const analyzeData = await analyzeResponse.json();
    if (!analyzeData.success) {
      throw new Error(analyzeData.error || 'Analysis failed');
    }

    currentAnalysis = analyzeData.analysis;
    updateProgress('Rendering results...', 100);

    setTimeout(() => {
      hideProgress();
      displayResults();
    }, 500);
  } catch (error) {
    hideProgress();
    showError(error.message);
  }
}

function displayResults() {
  if (!currentAnalysis) return;

  const { summary, authenticationStats, mailServers, suspiciousActivity, spoofingDetection, riskAssessment, recommendations } = currentAnalysis;

  // Summary
  document.getElementById('orgName').textContent = summary.organization;
  document.getElementById('domain').textContent = summary.domain;
  document.getElementById('totalEmails').textContent = summary.totalEmails.toLocaleString();
  document.getElementById('reportPeriod').textContent = formatDateRange(summary.reportDate);
  document.getElementById('enforcement').textContent = summary.policy.enforcement;

  const policyBadge = document.getElementById('dmarcPolicy');
  policyBadge.textContent = summary.policy.mode.toUpperCase();
  policyBadge.classList.add(summary.policy.mode);

  // Authentication Stats
  const total = authenticationStats.spf.pass + authenticationStats.spf.fail;
  const spfRate = total > 0 ? (authenticationStats.spf.pass / total) * 100 : 0;
  const dkimRate = total > 0 ? (authenticationStats.dkim.pass / total) * 100 : 0;
  const alignmentRate = total > 0 ? (authenticationStats.alignment.aligned / total) * 100 : 0;

  document.getElementById('spfPass').textContent = authenticationStats.spf.pass.toLocaleString();
  document.getElementById('spfFail').textContent = authenticationStats.spf.fail.toLocaleString();
  document.getElementById('spfRate').textContent = spfRate.toFixed(1);
  document.getElementById('spfPassBar').style.width = spfRate + '%';

  document.getElementById('dkimPass').textContent = authenticationStats.dkim.pass.toLocaleString();
  document.getElementById('dkimFail').textContent = authenticationStats.dkim.fail.toLocaleString();
  document.getElementById('dkimRate').textContent = dkimRate.toFixed(1);
  document.getElementById('dkimPassBar').style.width = dkimRate + '%';

  document.getElementById('alignedEmails').textContent = authenticationStats.alignment.aligned.toLocaleString();
  document.getElementById('failedEmails').textContent = authenticationStats.alignment.failed.toLocaleString();
  document.getElementById('alignmentRate').textContent = alignmentRate.toFixed(1);
  document.getElementById('alignmentBar').style.width = alignmentRate + '%';

  // Mail Servers
  const serversList = document.getElementById('serversList');
  document.getElementById('serverCount').textContent = mailServers.count;

  if (mailServers.servers.length === 0) {
    serversList.innerHTML = '<p style="color: #9ca3af;">No mail servers found.</p>';
  } else {
    serversList.innerHTML = mailServers.servers.map(server => `
      <div class="server-item">
        <div class="server-header">
          <div>
            <div class="server-ip">${server.ip}</div>
            <div class="server-domain">${server.domain}</div>
          </div>
          <div class="server-count">${server.emailCount} emails</div>
        </div>
        <div class="server-details">
          <div class="server-detail">SPF: <strong>${server.spf.domains.length} domain(s)</strong></div>
          <div class="server-detail">DKIM: <strong>${server.dkim.domains.length} signature(s)</strong></div>
          <div class="server-detail">Senders: <strong>${server.senders.length}</strong></div>
        </div>
      </div>
    `).join('');
  }

  // Suspicious Activity
  const suspiciousContainer = document.getElementById('suspiciousContainer');
  document.getElementById('suspiciousCount').textContent = suspiciousActivity.suspiciousIPs.length;

  if (suspiciousActivity.suspiciousIPs.length === 0) {
    suspiciousContainer.innerHTML = '<p style="color: #86efac; padding: 15px;">✅ No suspicious IPs detected</p>';
    document.getElementById('suspiciousCard').style.display = 'none';
  } else {
    suspiciousContainer.innerHTML = suspiciousActivity.suspiciousIPs.map(ip => `
      <div class="suspicious-item">
        <div class="suspicious-label">${ip.ip} (Risk Score: ${ip.riskScore})</div>
        ${ip.reasons.map(reason => `<div class="suspicious-reason">• ${reason}</div>`).join('')}
      </div>
    `).join('');
  }

  // Spoofing Detection
  const spoofingContainer = document.getElementById('spoofingContainer');
  if (spoofingDetection.detected) {
    document.getElementById('spoofingCard').style.display = 'block';
    spoofingContainer.innerHTML = `
      <div class="spoofing-status detected">⚠️ Spoofing Indicators Detected (${spoofingDetection.confidence}% confidence)</div>
      <p style="color: #9ca3af; margin-bottom: 15px;">${spoofingDetection.affectedEmails} suspicious email(s) detected</p>
      <div class="spoofing-indicators">
        ${spoofingDetection.indicators.slice(0, 5).map(indicator => `
          <div class="indicator">
            ${indicator.type === 'header-envelope-mismatch' ? `From/Envelope Mismatch: ${indicator.headerFrom} vs ${indicator.envelopeFrom}` :
              indicator.type === 'auth-double-fail' ? `Double Auth Failure from ${indicator.ip}` :
              indicator.type === 'policy-reject' ? `Policy Rejection for ${indicator.headerFrom}` :
              indicator.type}
            (${indicator.count} email${indicator.count > 1 ? 's' : ''})
          </div>
        `).join('')}
      </div>
    `;
  } else {
    document.getElementById('spoofingCard').style.display = 'none';
  }

  // Risk Assessment
  const riskMeter = document.getElementById('riskMeter');
  const riskScore = riskAssessment.overallRiskScore;
  const riskLevel = riskAssessment.riskLevel;

  riskMeter.setAttribute('data-score', riskScore);
  document.getElementById('riskLabel').textContent = riskLevel;
  document.getElementById('riskLabel').parentElement.style.color =
    riskLevel === 'CRITICAL' ? '#ef4444' :
    riskLevel === 'HIGH' ? '#f59e0b' :
    riskLevel === 'MEDIUM' ? '#3b82f6' :
    '#10b981';

  const riskFactors = document.getElementById('riskFactors');
  riskFactors.innerHTML = riskAssessment.factors.map(factor =>
    `<div class="risk-factor">• ${factor}</div>`
  ).join('');

  // Recommendations
  const recommendationsList = document.getElementById('recommendationsList');
  recommendationsList.innerHTML = recommendations.map(rec => `
    <div class="recommendation ${rec.priority.toLowerCase()}">
      <div class="recommendation-header">
        <span class="priority-badge ${rec.priority.toLowerCase()}">${rec.priority}</span>
        <span class="category-tag">${rec.category}</span>
      </div>
      <div class="recommendation-title">${rec.issue}</div>
      <div class="recommendation-desc">🔧 ${rec.action}</div>
      <div class="recommendation-impact">📌 ${rec.impact}</div>
    </div>
  `).join('');

  // Show results
  resultsSection.style.display = 'block';
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function formatDateRange(dateRange) {
  if (!dateRange || !dateRange.start) return '-';
  const start = new Date(dateRange.start);
  const end = new Date(dateRange.end);
  return `${start.toLocaleDateString()} to ${end.toLocaleDateString()}`;
}

function showProgress(message = 'Processing...') {
  progressText.textContent = message;
  progressContainer.style.display = 'block';
  progressFill.style.width = '30%';
}

function updateProgress(message, percent = null) {
  if (message) progressText.textContent = message;
  if (percent !== null) progressFill.style.width = percent + '%';
}

function hideProgress() {
  progressContainer.style.display = 'none';
  progressFill.style.width = '0';
}

function showError(message) {
  errorText.textContent = message;
  errorContainer.style.display = 'flex';
}

function hideError() {
  errorContainer.style.display = 'none';
}
