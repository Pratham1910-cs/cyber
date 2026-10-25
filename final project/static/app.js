(() => {
  "use strict";

  // Application State
  const state = {
    activeView: "ai-analyst",
    scanId: null,
    alerts: [],
    alertFilter: "all",
    couraaBarChart: null,
    timelineChart: null,
    attackerChart: null,
    selectedBlockTarget: null,
    toastTimer: null,
    currentPlaybook: {
      id: "block_perimeter",
      label: "Run block_perimeter Playbook",
      targets: ["185.190.141.22", "218.92.0.182", "198.51.100.45", "185.220.101.5", "5.160.245.10"]
    }
  };

  // DOM Elements Cache
  const els = {
    // Topbar
    globalSearch: document.querySelector("#global-search"),
    searchResultsDropdown: document.querySelector("#search-results-dropdown"),
    searchResultsContent: document.querySelector("#search-results-content"),
    notificationsBtn: document.querySelector("#notifications-btn"),
    notificationsDropdown: document.querySelector("#notifications-dropdown"),
    notifItemsList: document.querySelector("#notif-items-list"),
    notifUnreadCount: document.querySelector("#notif-unread-count"),
    notificationsIndicatorDot: document.querySelector("#notifications-indicator-dot"),
    markAllReadBtn: document.querySelector("#mark-all-read-btn"),
    notifViewAllAlertsBtn: document.querySelector("#notif-view-all-alerts-btn"),
    topbarUploadBtn: document.querySelector("#topbar-upload-btn"),
    hiddenFileInput: document.querySelector("#hidden-file-input"),
    navAlertsBadge: document.querySelector("#nav-alerts-badge"),

    // Nav items
    navBtns: document.querySelectorAll(".nav-btn"),
    viewPanels: document.querySelectorAll(".view-panel"),

    // AI Analyst View
    aiInput: document.querySelector("#ai-analyst-input"),
    aiGenerateBtn: document.querySelector("#ai-generate-btn"),
    promptPills: document.querySelectorAll(".prompt-pill"),
    splTime: document.querySelector("#spl-execution-time"),
    splCode: document.querySelector("#spl-code-display"),
    copySplBtn: document.querySelector("#copy-spl-btn"),
    resultsTitle: document.querySelector("#results-count-title"),
    resultsTableBody: document.querySelector("#results-table-body"),
    refreshQueryBtn: document.querySelector("#refresh-query-btn"),

    // Chat
    chatThread: document.querySelector("#chat-thread-container"),
    chatInput: document.querySelector("#chat-followup-input"),
    chatSendBtn: document.querySelector("#chat-send-btn"),
    runPlaybookBtn: document.querySelector("#run-playbook-btn"),
    playbookBtnLabel: document.querySelector("#playbook-btn-label"),
    aiFindingsList: document.querySelector("#ai-findings-list"),
    aiSummaryText: document.querySelector("#ai-summary-text"),
    aiRecommendationText: document.querySelector("#ai-recommendation-text"),
    chatUserQueryText: document.querySelector("#chat-user-query-text"),

    // Alerts View
    alertsTableBody: document.querySelector("#alerts-table-body"),
    alertsCountText: document.querySelector("#alerts-count-text"),
    refreshAlertsBtn: document.querySelector("#refresh-alerts-btn"),
    alertFilterBtns: document.querySelectorAll("[data-alert-filter]"),

    // Dashboard View
    dashTotal: document.querySelector("#dash-total-attempts"),
    dashFailed: document.querySelector("#dash-failed-logins"),
    dashAttacks: document.querySelector("#dash-detected-attacks"),
    dashCritical: document.querySelector("#dash-critical-alerts"),

    // Log Explorer View
    uploadDropzone: document.querySelector("#upload-dropzone"),
    browseFileBtn: document.querySelector("#browse-file-btn"),
    uploadProgressBox: document.querySelector("#upload-progress-box"),
    uploadProgressFill: document.querySelector("#upload-progress-fill"),
    uploadStatusLabel: document.querySelector("#upload-status-label"),

    // Modal & Toast
    blockDialog: document.querySelector("#block-confirm-dialog"),
    dialogIpTarget: document.querySelector("#dialog-ip-target"),
    dialogStatusMsg: document.querySelector("#dialog-status-msg"),
    dialogCancelBtn: document.querySelector("#dialog-cancel-btn"),
    dialogConfirmBtn: document.querySelector("#dialog-confirm-btn"),
    toast: document.querySelector("#couraa-toast")
  };

  // Helper Utilities
  const formatNumber = num => Number(num || 0).toLocaleString("en-US");

  function showToast(message, isError = false) {
    if (!els.toast) return;
    els.toast.textContent = message;
    els.toast.style.borderLeftColor = isError ? "var(--crimson-attack)" : "var(--astralock-orange)";
    els.toast.classList.add("visible");
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => {
      els.toast.classList.remove("visible");
    }, 4000);
  }

  async function apiRequest(url, options = {}) {
    const headers = new Headers(options.headers || {});
    const apiKey = sessionStorage.getItem("astralock-api-key") || sessionStorage.getItem("couraa-api-key");
    if (apiKey) headers.set("X-API-Key", apiKey);

    let res = await fetch(url, { ...options, headers });
    if (res.status === 401 && options.method === "POST" && !apiKey) {
      const entered = window.prompt("Security Authorization Required. Enter API Key:");
      if (entered) {
        sessionStorage.setItem("astralock-api-key", entered);
        sessionStorage.setItem("couraa-api-key", entered);
        headers.set("X-API-Key", entered);
        res = await fetch(url, { ...options, headers });
      }
    }

    const payload = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(payload.error || `Request failed with status ${res.status}`);
    }
    return payload;
  }

  // ==========================================================================
  // NAVIGATION & VIEW SWITCHING
  // ==========================================================================
  function switchView(viewName) {
    const targetPanel = document.querySelector(`#view-${viewName}`);
    if (!targetPanel) {
      showToast(`Module '${viewName}' is currently in standby preview.`);
      return;
    }

    state.activeView = viewName;

    // Update sidebar buttons
    const navBtns = document.querySelectorAll(".nav-btn");
    navBtns.forEach(btn => {
      const isMatch = btn.dataset.view === viewName;
      btn.classList.toggle("active", isMatch);
      const parentItem = btn.closest(".nav-item");
      if (parentItem) parentItem.classList.toggle("active", isMatch);
    });

    // Update panels
    const allPanels = document.querySelectorAll(".view-panel");
    allPanels.forEach(panel => {
      panel.classList.toggle("active", panel.id === `view-${viewName}`);
    });

    // Trigger view-specific loads
    if (viewName === "alerts") {
      loadAlerts();
    } else if (viewName === "dashboard") {
      loadDashboard();
    } else if (viewName === "assets") {
      loadAssets();
    } else if (viewName === "threat-intel") {
      loadThreatIntel();
    } else if (viewName === "soar") {
      loadSoar();
    } else if (viewName === "red-team") {
      loadRedTeam();
    } else if (viewName === "endpoints") {
      loadEndpoints();
    } else if (viewName === "compliance") {
      loadCompliance();
    } else if (viewName === "reports") {
      loadReports();
    } else if (viewName === "settings") {
      loadSettings();
    } else if (viewName === "ai-analyst") {
      // Ensure Chart.js canvas resizes cleanly when switching back to AI Analyst tab
      if (state.couraaBarChart) {
        requestAnimationFrame(() => {
          try {
            state.couraaBarChart.resize();
            state.couraaBarChart.update();
          } catch (e) {
            console.warn("Chart resize:", e);
          }
        });
      }
    }
  }

  // ==========================================================================
  // AI ANALYST & COPILOT CORE (MATCHING USER PHOTO)
  // ==========================================================================
  async function runAiAnalystQuery(queryPrompt) {
    if (!queryPrompt || !queryPrompt.trim()) return;

    if (els.aiGenerateBtn) {
      els.aiGenerateBtn.disabled = true;
      els.aiGenerateBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Generating...';
    }

    try {
      const data = await apiRequest("/api/ai-analyst/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: queryPrompt })
      });

      // 1. Update SPL execution bar
      if (els.splTime) els.splTime.textContent = `${data.execution_time_ms || 142}ms`;
      if (els.splCode) {
        els.splCode.innerHTML = highlightSpl(data.query_spl);
      }

      // 2. Update Results Header
      if (els.resultsTitle) {
        els.resultsTitle.textContent = `Query Results (${formatNumber(data.total_events)} events)`;
      }

      // 3. Update Bar Chart
      renderCouraaBarChart(data.chart_data);

      // 4. Update Table
      renderResultsTable(data.table_data);

      // 5. Update Chat Thread
      updateChatThread(queryPrompt, data.ai_response);

      // 6. Update playbook state
      if (data.ai_response && data.ai_response.playbook) {
        state.currentPlaybook = data.ai_response.playbook;
        if (els.playbookBtnLabel) els.playbookBtnLabel.textContent = data.ai_response.playbook.label;
        if (els.runPlaybookBtn) {
          els.runPlaybookBtn.classList.remove("executed");
          els.runPlaybookBtn.disabled = false;
        }
      }

    } catch (err) {
      showToast(err.message || "Failed to execute AI Copilot query", true);
    } finally {
      if (els.aiGenerateBtn) {
        els.aiGenerateBtn.disabled = false;
        els.aiGenerateBtn.innerHTML = "<span>Generate</span>";
      }
    }
  }

  function highlightSpl(rawSpl) {
    if (!rawSpl) return "";
    return rawSpl
      .replace(/(index=\w+)/g, '<span class="spl-idx">$1</span>')
      .replace(/(\w+="[^"]+")/g, '<span class="spl-prop">$1</span>')
      .replace(/(\|)/g, '<span class="spl-pipe">$1</span>')
      .replace(/(stats count[a-z_\s]+|sort -count|head \d+|dc\([a-zA-Z_]+\))/g, '<span class="spl-fn">$1</span>');
  }

  function renderCouraaBarChart(chartData) {
    const canvas = document.querySelector("#couraa-bar-chart");
    if (!canvas || !window.Chart) return;

    if (state.couraaBarChart) {
      state.couraaBarChart.destroy();
    }

    const ctx = canvas.getContext("2d");
    
    // Crimson gradient for bars matching photo
    const barGradient = ctx.createLinearGradient(0, 0, 0, canvas.clientHeight || 180);
    barGradient.addColorStop(0, "#e63946");
    barGradient.addColorStop(1, "#7f1d1d");

    state.couraaBarChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: chartData.labels || ["RU", "CN", "US", "GB", "IR", "DE", "BR", "NL"],
        datasets: [{
          data: chartData.values || [942, 418, 186, 86, 52, 38, 24, 18],
          backgroundColor: barGradient,
          borderColor: "#ff4d4f",
          borderWidth: 1,
          borderRadius: 3,
          barThickness: 26,
          maxBarThickness: 32
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#0d0f14",
            borderColor: "#252b38",
            borderWidth: 1,
            titleColor: "#f3f4f6",
            bodyColor: "#ff4d4f",
            titleFont: { family: "Inter", size: 12, weight: "600" },
            bodyFont: { family: "JetBrains Mono", size: 12, weight: "600" },
            padding: 10,
            displayColors: false,
            callbacks: {
              label: function(ctx) {
                return ` ${ctx.parsed.y} failed logins`;
              }
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            border: { color: "#1e222a" },
            ticks: {
              color: "#8a92a0",
              font: { family: "Inter", size: 11, weight: "500" }
            }
          },
          y: {
            beginAtZero: true,
            border: { display: false },
            grid: { color: "rgba(255, 255, 255, 0.04)" },
            ticks: {
              color: "#6b7280",
              font: { family: "JetBrains Mono", size: 10 },
              precision: 0
            }
          }
        }
      }
    });
  }

  function renderResultsTable(tableData) {
    if (!els.resultsTableBody) return;
    els.resultsTableBody.innerHTML = "";

    const rows = tableData || [
      { country: "Russia (RU)", code: "RU", count: 942, pct: "43.5%", top_user: "admin", sample_ip: "185.190.141.22" },
      { country: "China (CN)", code: "CN", count: 418, pct: "12.9%", top_user: "root", sample_ip: "218.92.0.182" },
      { country: "United States (US)", code: "US", count: 186, pct: "12.5%", top_user: "administrator", sample_ip: "198.51.100.45" },
      { country: "United Kingdom (GB)", code: "GB", count: 86, pct: "6.7%", top_user: "db_admin", sample_ip: "185.220.101.5" },
      { country: "Iran (IR)", code: "IR", count: 52, pct: "4.1%", top_user: "admin", sample_ip: "5.160.245.10" }
    ];

    rows.forEach(item => {
      const tr = document.createElement("tr");

      const tdGeo = document.createElement("td");
      tdGeo.className = "td-geo";
      tdGeo.innerHTML = `<span class="geo-code-badge">${item.code}</span> ${item.country}`;
      tr.appendChild(tdGeo);

      const tdCount = document.createElement("td");
      tdCount.className = "td-count count-crimson";
      tdCount.textContent = formatNumber(item.count);
      tr.appendChild(tdCount);

      const tdPct = document.createElement("td");
      tdPct.className = "td-pct";
      tdPct.textContent = item.pct;
      tr.appendChild(tdPct);

      const tdUser = document.createElement("td");
      tdUser.className = "td-user";
      tdUser.textContent = item.top_user;
      tr.appendChild(tdUser);

      const tdAction = document.createElement("td");
      tdAction.className = "td-action";
      const blockBtn = document.createElement("button");
      blockBtn.className = "row-block-btn";
      blockBtn.textContent = "Block";
      blockBtn.type = "button";
      blockBtn.addEventListener("click", () => {
        openBlockModal(item.sample_ip || item.country);
      });
      tdAction.appendChild(blockBtn);

      const askGeminiBtn = document.createElement("button");
      askGeminiBtn.className = "row-gemini-btn";
      askGeminiBtn.innerHTML = "✦ Ask Gemini";
      askGeminiBtn.type = "button";
      askGeminiBtn.title = "Ask Gemini AI to triage this threat event";
      askGeminiBtn.addEventListener("click", () => {
        askGeminiAboutRow(item);
      });
      tdAction.appendChild(askGeminiBtn);

      tr.appendChild(tdAction);

      els.resultsTableBody.appendChild(tr);
    });
  }

  function askGeminiAboutRow(item) {
    if (!els.chatInput) return;
    const targetDesc = item.country || item.code || "unknown target";
    const ip = item.sample_ip || item.ip || "N/A";
    const user = item.top_user || item.user || "admin";
    const count = item.count ? `${item.count} events` : "suspicious activity";
    els.chatInput.value = `Triage threat from ${targetDesc} (IP: ${ip}, targeted account: '${user}', ${count}). What attack vector is this, what is the MITRE technique, and what should our immediate containment action be?`;
    sendFollowUp();
  }

  function updateChatThread(queryText, aiResponse) {
    if (!els.chatThread) return;

    const initialUser = document.querySelector("#initial-user-msg");
    const initialAi = document.querySelector("#initial-ai-msg");

    // On initial page bootstrap, update the default template cards
    if (initialUser && initialAi && els.chatThread.children.length <= 2) {
      if (els.chatUserQueryText) {
        els.chatUserQueryText.textContent = queryText;
      }

      if (aiResponse) {
        if (els.aiSummaryText) els.aiSummaryText.textContent = aiResponse.summary;

        if (els.aiFindingsList && aiResponse.key_findings) {
          els.aiFindingsList.innerHTML = "";
          aiResponse.key_findings.forEach(finding => {
            const li = document.createElement("li");
            li.textContent = finding;
            els.aiFindingsList.appendChild(li);
          });
        }

        if (els.aiRecommendationText && aiResponse.call_to_action) {
          els.aiRecommendationText.textContent = aiResponse.call_to_action;
        }
      }
    } else {
      // Subsequent queries append new conversation messages
      appendChatMessage("user", queryText, false);

      let extraHtml = "";
      if (aiResponse && aiResponse.key_findings && aiResponse.key_findings.length > 0) {
        extraHtml += `
          <div class="ai-findings-block" style="margin-top: 10px;">
            <div class="findings-heading">Key Findings:</div>
            <ul class="findings-list">
              ${aiResponse.key_findings.map(f => `<li>${f}</li>`).join("")}
            </ul>
          </div>
        `;
      }

      if (aiResponse && (aiResponse.playbook || aiResponse.call_to_action)) {
        const cta = aiResponse.call_to_action || "Recommended action:";
        const pb = (aiResponse.playbook && aiResponse.playbook.label) || "Execute Playbook";
        extraHtml += `
          <div class="ai-action-recommendation" style="margin-top: 12px;">
            <p class="recommendation-text">${cta}</p>
            <button class="run-playbook-btn" type="button" onclick="window.astralockExecutePlaybook()">
              <i class="fa-solid fa-play"></i>
              <span>${pb}</span>
            </button>
          </div>
        `;
      }

      appendChatMessage("ai", (aiResponse && aiResponse.summary) || "I've converted your request into SPL and run the query.", true, extraHtml);
    }

    els.chatThread.scrollTop = els.chatThread.scrollHeight;
  }

  function appendChatMessage(sender, text, isAi = false, extraHtml = "") {
    if (!els.chatThread) return;

    const msgDiv = document.createElement("div");
    msgDiv.className = `chat-message ${isAi ? "ai-message" : "user-message"}`;

    if (isAi) {
      msgDiv.innerHTML = `
        <div class="ai-avatar-red">AI</div>
        <div class="ai-bubble">
          <p class="ai-summary-text">${text}</p>
          ${extraHtml}
        </div>
      `;
    } else {
      msgDiv.innerHTML = `
        <div class="user-bubble">
          <p class="user-query-text">${text}</p>
        </div>
        <div class="chat-avatar user-avatar-badge">AD</div>
      `;
    }

    els.chatThread.appendChild(msgDiv);
    els.chatThread.scrollTop = els.chatThread.scrollHeight;
  }

  // Follow-up interaction
  async function sendFollowUp() {
    if (!els.chatInput) return;
    const text = els.chatInput.value.trim();
    if (!text) return;

    els.chatInput.value = "";
    appendChatMessage("user", text, false);

    // Render animated typing indicator
    const typingIndicator = document.createElement("div");
    typingIndicator.className = "chat-message ai-message typing-indicator-msg";
    typingIndicator.innerHTML = `
      <div class="ai-avatar-red">AI</div>
      <div class="ai-bubble">
        <div class="ai-typing-indicator">
          <span></span><span></span><span></span>
        </div>
      </div>
    `;
    els.chatThread.appendChild(typingIndicator);
    els.chatThread.scrollTop = els.chatThread.scrollHeight;

    try {
      const activePrompt = els.aiInput ? els.aiInput.value : "";
      const geminiKey = sessionStorage.getItem("astralock-gemini-key") || sessionStorage.getItem("couraa-gemini-key") || "";
      const data = await apiRequest("/api/ai-analyst/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text, active_prompt: activePrompt, api_key: geminiKey })
      });

      typingIndicator.remove();

      // If query requires workspace investigation sync (e.g. Find lateral movement from Laptop-352)
      if (data.update_workspace && data.workspace_data) {
        const ws = data.workspace_data;
        if (els.aiInput) els.aiInput.value = ws.prompt;
        if (els.splTime) els.splTime.textContent = `${ws.execution_time_ms || 142}ms`;
        if (els.splCode) els.splCode.innerHTML = highlightSpl(ws.query_spl);
        if (els.resultsTitle) els.resultsTitle.textContent = `Query Results (${formatNumber(ws.total_events)} events)`;
        renderCouraaBarChart(ws.chart_data);
        renderResultsTable(ws.table_data);

        if (ws.ai_response && ws.ai_response.playbook) {
          state.currentPlaybook = ws.ai_response.playbook;
          if (els.playbookBtnLabel) els.playbookBtnLabel.textContent = ws.ai_response.playbook.label;
          if (els.runPlaybookBtn) {
            els.runPlaybookBtn.classList.remove("executed");
            els.runPlaybookBtn.disabled = false;
          }
        }
      }

      // If playbook is attached to response
      if (data.playbook) {
        state.currentPlaybook = data.playbook;
        if (els.playbookBtnLabel) els.playbookBtnLabel.textContent = data.playbook.label;
        if (els.runPlaybookBtn) {
          els.runPlaybookBtn.classList.remove("executed");
          els.runPlaybookBtn.disabled = false;
        }
      }

      // Build rich extraHtml for chat message
      let extraHtml = "";

      if (data.key_findings && data.key_findings.length > 0) {
        extraHtml += `
          <div class="ai-findings-block" style="margin-top: 10px;">
            <div class="findings-heading">Key Findings:</div>
            <ul class="findings-list">
              ${data.key_findings.map(f => `<li>${f}</li>`).join("")}
            </ul>
          </div>
        `;
      }

      if (data.playbook || data.call_to_action) {
        const ctaText = data.call_to_action || "Recommended containment action:";
        const pbLabel = (data.playbook && data.playbook.label) || "Execute Containment Playbook";
        extraHtml += `
          <div class="ai-action-recommendation" style="margin-top: 12px;">
            <p class="recommendation-text">${ctaText}</p>
            <button class="run-playbook-btn" type="button" onclick="window.astralockExecutePlaybook()">
              <i class="fa-solid fa-play"></i>
              <span>${pbLabel}</span>
            </button>
          </div>
        `;
      }

      appendChatMessage("ai", data.reply || "Analysis completed.", true, extraHtml);

    } catch (err) {
      typingIndicator.remove();
      appendChatMessage("ai", `I encountered an issue analyzing telemetry: ${err.message}`, true);
    }
  }

  // Playbook execution
  async function executePlaybook() {
    if (!els.runPlaybookBtn) return;
    const originalText = els.playbookBtnLabel.textContent;

    els.runPlaybookBtn.classList.add("executing");
    els.playbookBtnLabel.textContent = "Deploying firewall rules...";

    try {
      const res = await apiRequest("/api/run-playbook", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          playbook_id: state.currentPlaybook.id || "block_perimeter",
          targets: state.currentPlaybook.targets || []
        })
      });

      els.runPlaybookBtn.classList.remove("executing");
      els.runPlaybookBtn.classList.add("executed");
      els.playbookBtnLabel.textContent = "✔ Playbook Executed";

      appendChatMessage("ai", `✔ <b>${state.currentPlaybook.name || "block_perimeter Playbook"}</b> executed successfully.<br>Applied 5 firewall DROP rules across edge routers. Incident logged with audit ticket #SOC-${Math.floor(Math.random() * 8999 + 1000)}.`, true);
      showToast("Playbook executed: 5 edge firewall rules applied!");

    } catch (err) {
      els.runPlaybookBtn.classList.remove("executing");
      els.playbookBtnLabel.textContent = originalText;
      showToast(err.message || "Playbook execution failed", true);
    }
  }

  // Expose for dynamic chat playbook button callbacks
  window.astralockExecutePlaybook = window.couraaExecutePlaybook = executePlaybook;

  // ==========================================================================
  // VIEW 2: ALERTS & REAL-TIME DETECTION FEED
  // ==========================================================================
  async function loadAlerts() {
    if (!els.alertsTableBody) return;

    try {
      const queryParam = state.alertFilter === "all" ? "" : `?classification=${encodeURIComponent(state.alertFilter)}`;
      const data = await apiRequest(`/api/alerts${queryParam}`);
      state.alerts = data;
      renderAlertsTable(data);

      if (els.navAlertsBadge) {
        els.navAlertsBadge.textContent = data.length || "0";
      }
      if (els.alertsCountText) {
        els.alertsCountText.textContent = `${formatNumber(data.length)} detection events`;
      }
    } catch (err) {
      els.alertsTableBody.innerHTML = `<tr><td colspan="7" class="loading-state" style="color:var(--crimson-attack);">Error loading alerts: ${err.message}</td></tr>`;
    }
  }

  function renderAlertsTable(alerts) {
    if (!els.alertsTableBody) return;
    els.alertsTableBody.innerHTML = "";

    if (!alerts || alerts.length === 0) {
      els.alertsTableBody.innerHTML = `<tr><td colspan="7" class="loading-state">No alerts found. Upload an auth.log file to begin scanning.</td></tr>`;
      return;
    }

    alerts.forEach(alert => {
      const tr = document.createElement("tr");

      // Timestamp
      const tdTs = document.createElement("td");
      tdTs.style.fontFamily = "var(--font-mono)";
      tdTs.style.fontSize = "11.5px";
      tdTs.style.color = "var(--text-secondary)";
      tdTs.textContent = alert.timestamp ? new Date(`${alert.timestamp}Z`).toLocaleTimeString() : "--:--:--";
      tr.appendChild(tdTs);

      // Source IP
      const tdIp = document.createElement("td");
      tdIp.style.fontFamily = "var(--font-mono)";
      tdIp.style.fontWeight = "600";
      tdIp.style.color = "var(--text-white)";
      tdIp.textContent = alert.source_ip;
      tr.appendChild(tdIp);

      // Attempts
      const tdAtt = document.createElement("td");
      tdAtt.style.fontFamily = "var(--font-mono)";
      tdAtt.textContent = formatNumber(alert.attempt_count);
      tr.appendChild(tdAtt);

      // Anomalous Signatures
      const tdSig = document.createElement("td");
      const sigList = alert.anomalous_signatures || [];
      sigList.slice(0, 2).forEach(sig => {
        const span = document.createElement("span");
        span.className = "signature-chip";
        span.textContent = sig;
        tdSig.appendChild(span);
      });
      tr.appendChild(tdSig);

      // Risk Score
      const tdRisk = document.createElement("td");
      const risk = Math.round(alert.risk_score || 0);
      tdRisk.innerHTML = `
        <div class="risk-bar-wrap">
          <div class="risk-bar-track">
            <div class="risk-bar-fill" style="width: ${Math.min(100, Math.max(0, risk))}%;"></div>
          </div>
          <span class="risk-val" style="color:${risk >= 80 ? '#ff6879' : '#fbbf24'}">${risk}%</span>
        </div>
      `;
      tr.appendChild(tdRisk);

      // Classification
      const tdClass = document.createElement("td");
      const isAttack = alert.classification === "Brute-Force Attack";
      tdClass.innerHTML = `<span class="badge-classification ${isAttack ? 'attack' : 'anomalous'}">${alert.classification}</span>`;
      tr.appendChild(tdClass);

      // Action
      const tdAct = document.createElement("td");
      const btn = document.createElement("button");
      btn.className = `row-block-btn ${alert.blocked ? 'blocked-done' : ''}`;
      btn.textContent = alert.blocked ? "Blocked" : "Block IP";
      btn.disabled = Boolean(alert.blocked);
      btn.type = "button";
      btn.addEventListener("click", () => openBlockModal(alert.source_ip));
      tdAct.appendChild(btn);
      tr.appendChild(tdAct);

      els.alertsTableBody.appendChild(tr);
    });
  }

  // ==========================================================================
  // VIEW 3: DASHBOARD & METRICS
  // ==========================================================================
  async function loadDashboard() {
    try {
      const stats = await apiRequest("/api/stats");
      if (els.dashTotal) els.dashTotal.textContent = formatNumber(stats.total_ssh_attempts || 1480);
      if (els.dashFailed) els.dashFailed.textContent = formatNumber(stats.failed_logins || 1244);
      if (els.dashAttacks) els.dashAttacks.textContent = formatNumber(stats.detected_attacks || 5);
      if (els.dashCritical) els.dashCritical.textContent = formatNumber(stats.critical_alerts || 3);

      const chartData = await apiRequest("/api/chart-data");
      renderTimelineChart(chartData.timeline);
      renderAttackerChart(chartData.top_attackers);
    } catch (err) {
      console.warn("Could not refresh dashboard telemetry:", err);
    }
  }

  function renderTimelineChart(timeline) {
    const canvas = document.querySelector("#timeline-chart");
    if (!canvas || !window.Chart) return;

    if (state.timelineChart) state.timelineChart.destroy();

    const labels = (timeline && timeline.labels && timeline.labels.length)
      ? timeline.labels.map(l => new Date(`${l}Z`).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }))
      : ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"];

    const failedData = (timeline && timeline.failed && timeline.failed.length)
      ? timeline.failed
      : [32, 145, 412, 180, 245, 98];

    const successData = (timeline && timeline.successful && timeline.successful.length)
      ? timeline.successful
      : [8, 12, 24, 45, 32, 18];

    state.timelineChart = new Chart(canvas, {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Failed Logins",
            data: failedData,
            borderColor: "#ff4d4f",
            backgroundColor: "rgba(255, 77, 79, 0.08)",
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointRadius: 0
          },
          {
            label: "Success Logins",
            data: successData,
            borderColor: "#10b981",
            backgroundColor: "transparent",
            borderWidth: 2,
            tension: 0.35,
            pointRadius: 0
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { display: false },
            border: { display: false },
            ticks: { color: "#6b7280", font: { family: "JetBrains Mono", size: 10 } }
          },
          y: {
            border: { display: false },
            grid: { color: "rgba(255, 255, 255, 0.04)" },
            ticks: { color: "#6b7280", font: { family: "JetBrains Mono", size: 10 } }
          }
        }
      }
    });
  }

  function renderAttackerChart(topAttackers) {
    const canvas = document.querySelector("#attacker-chart");
    if (!canvas || !window.Chart) return;

    if (state.attackerChart) state.attackerChart.destroy();

    const data = topAttackers && topAttackers.length ? topAttackers : [
      { source_ip: "203.0.113.45", failed_attempts: 942 },
      { source_ip: "192.0.2.99", failed_attempts: 418 },
      { source_ip: "198.51.100.7", failed_attempts: 186 },
      { source_ip: "198.18.0.5", failed_attempts: 86 },
      { source_ip: "198.51.100.23", failed_attempts: 52 }
    ];

    state.attackerChart = new Chart(canvas, {
      type: "bar",
      data: {
        labels: data.map(d => d.source_ip),
        datasets: [{
          data: data.map(d => d.failed_attempts),
          backgroundColor: "#ff5520",
          borderRadius: 4,
          barThickness: 16
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.04)" },
            border: { display: false },
            ticks: { color: "#6b7280", font: { family: "JetBrains Mono", size: 10 } }
          },
          y: {
            grid: { display: false },
            border: { display: false },
            ticks: { color: "#d1d5db", font: { family: "JetBrains Mono", size: 11 } }
          }
        }
      }
    });
  }

  // ==========================================================================
  // VIEW 4: FILE UPLOAD (AUTH.LOG)
  // ==========================================================================
  async function handleFileUpload(file) {
    if (!file) return;

    if (els.uploadProgressBox) els.uploadProgressBox.style.display = "block";
    if (els.uploadProgressFill) els.uploadProgressFill.style.width = "45%";
    if (els.uploadStatusLabel) els.uploadStatusLabel.textContent = `Uploading ${file.name}...`;

    try {
      const formData = new FormData();
      formData.append("file", file);

      if (els.uploadProgressFill) els.uploadProgressFill.style.width = "75%";
      if (els.uploadStatusLabel) els.uploadStatusLabel.textContent = "Parsing syslog & running Isolation Forest / Random Forest models...";

      const res = await apiRequest("/api/upload-log", {
        method: "POST",
        body: formData
      });

      if (els.uploadProgressFill) els.uploadProgressFill.style.width = "100%";
      if (els.uploadStatusLabel) els.uploadStatusLabel.textContent = `Scan #${res.scan_id} complete: ${formatNumber(res.events_parsed)} events processed.`;

      state.scanId = res.scan_id;
      showToast(`Analyzed ${formatNumber(res.events_parsed)} events. Detected ${res.detected_attacks} brute-force attackers!`);

      // Switch to AI Analyst and summarize the newly uploaded log
      switchView("ai-analyst");
      if (els.aiInput) els.aiInput.value = `Analyze active SSH brute-force detections from ${file.name}`;
      runAiAnalystQuery(`Analyze active SSH brute-force detections from ${file.name}`);

    } catch (err) {
      if (els.uploadStatusLabel) els.uploadStatusLabel.textContent = `Error: ${err.message}`;
      showToast(err.message || "Failed to analyze auth.log", true);
    } finally {
      if (els.hiddenFileInput) els.hiddenFileInput.value = "";
    }
  }

  // ==========================================================================
  // BLOCK IP MODAL
  // ==========================================================================
  function openBlockModal(target) {
    state.selectedBlockTarget = target;
    if (els.dialogIpTarget) els.dialogIpTarget.textContent = target;
    if (els.dialogStatusMsg) els.dialogStatusMsg.textContent = "";
    if (els.dialogConfirmBtn) {
      els.dialogConfirmBtn.disabled = false;
      els.dialogConfirmBtn.innerHTML = '<i class="fa-solid fa-ban"></i> Confirm Block';
    }
    if (els.blockDialog && typeof els.blockDialog.showModal === "function") {
      els.blockDialog.showModal();
    }
  }

  async function confirmBlockAction() {
    if (!state.selectedBlockTarget) return;

    if (els.dialogConfirmBtn) {
      els.dialogConfirmBtn.disabled = true;
      els.dialogConfirmBtn.textContent = "Deploying firewall rule...";
    }

    try {
      // Determine if target is raw IP or ASN string
      const ipMatch = state.selectedBlockTarget.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      const cleanIp = ipMatch ? ipMatch[0] : state.selectedBlockTarget;

      const res = await apiRequest("/api/block-ip", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: cleanIp })
      });

      if (els.dialogStatusMsg) {
        els.dialogStatusMsg.textContent = `✔ Rule added: ${res.command || cleanIp} (${res.status})`;
      }
      showToast(`Blocked IP ${cleanIp} on edge firewall`);
      
      setTimeout(() => {
        if (els.blockDialog) els.blockDialog.close();
        loadAlerts();
      }, 1000);

    } catch (err) {
      if (els.dialogStatusMsg) {
        els.dialogStatusMsg.textContent = err.message;
        els.dialogStatusMsg.style.color = "var(--crimson-attack)";
      }
      if (els.dialogConfirmBtn) {
        els.dialogConfirmBtn.disabled = false;
        els.dialogConfirmBtn.innerHTML = '<i class="fa-solid fa-rotate-right"></i> Retry';
      }
    }
  }

  // ==========================================================================
  // VIEW 6: ASSETS INVENTORY & ATTACK SURFACE
  // ==========================================================================
  async function loadAssets() {
    const tbody = document.querySelector("#assets-table-body");
    if (!tbody) return;

    try {
      const data = await apiRequest("/api/assets");
      tbody.innerHTML = "";

      if (!data.assets || data.assets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="loading-state">No assets found in enterprise inventory.</td></tr>';
        return;
      }

      data.assets.forEach(asset => {
        const tr = document.createElement("tr");
        const riskColor = asset.risk_score >= 80 ? "#ff6879" : (asset.risk_score >= 60 ? "#fbbf24" : "var(--emerald-green)");
        const isIsolated = asset.status === "isolated";
        const statusBadge = isIsolated
          ? '<span class="badge-classification attack"><i class="fa-solid fa-lock"></i> Isolated</span>'
          : (asset.status === "warning"
            ? '<span class="badge-classification anomalous"><i class="fa-solid fa-triangle-exclamation"></i> Warning</span>'
            : '<span class="status-badge-healthy"><i class="fa-solid fa-circle-check"></i> Healthy</span>');

        tr.innerHTML = `
          <td style="font-family:var(--font-mono); font-weight:600; color:var(--text-white);">
            <i class="fa-solid fa-server" style="margin-right:7px; color:var(--text-muted);"></i>${asset.hostname}
          </td>
          <td style="font-family:var(--font-mono); color:var(--text-secondary);">${asset.ip}</td>
          <td>
            <div style="font-size:12px; color:var(--text-white);">${asset.role}</div>
            <div style="font-size:10.5px; color:var(--text-muted); font-family:var(--font-mono);">${asset.os}</div>
          </td>
          <td><span class="signature-chip">${asset.zone}</span></td>
          <td>
            <div class="risk-bar-wrap">
              <div class="risk-bar-track">
                <div class="risk-bar-fill" style="width:${asset.risk_score}%; background:${riskColor};"></div>
              </div>
              <span class="risk-val" style="color:${riskColor};">${asset.risk_score}%</span>
            </div>
          </td>
          <td>${statusBadge}</td>
          <td>
            <button class="row-block-btn ${isIsolated ? 'blocked-done' : ''}" type="button" style="padding:4px 10px; font-size:11px;" onclick="window.astralockAssetAction('${asset.hostname}', '${asset.ip}')">
              ${isIsolated ? '<i class="fa-solid fa-shield"></i> Isolated' : '<i class="fa-solid fa-ban"></i> Isolate Host'}
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="7" class="loading-state" style="color:var(--crimson-attack);">Error loading assets: ${err.message}</td></tr>`;
    }
  }

  // ==========================================================================
  // VIEW 7: THREAT INTEL FEEDS & IOCS
  // ==========================================================================
  async function loadThreatIntel() {
    const tbody = document.querySelector("#intel-table-body");
    if (!tbody) return;

    try {
      const data = await apiRequest("/api/threat-intel");
      tbody.innerHTML = "";

      if (!data.indicators || data.indicators.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="loading-state">No threat indicators found.</td></tr>';
        return;
      }

      data.indicators.forEach(ioc => {
        const tr = document.createElement("tr");
        const confColor = ioc.confidence >= 95 ? "#ff6879" : "#fbbf24";

        tr.innerHTML = `
          <td style="font-family:var(--font-mono); font-weight:600; color:#38bdf8;">
            <i class="fa-solid fa-crosshairs" style="margin-right:6px; color:var(--text-muted);"></i>${ioc.indicator}
          </td>
          <td><span class="signature-chip">${ioc.type}</span></td>
          <td style="color:var(--text-white);">${ioc.category}</td>
          <td style="font-family:var(--font-mono); font-size:11.5px; color:var(--text-secondary);">${ioc.asn}</td>
          <td>
            <div class="risk-bar-wrap">
              <div class="risk-bar-track">
                <div class="risk-bar-fill" style="width:${ioc.confidence}%; background:${confColor};"></div>
              </div>
              <span class="risk-val" style="color:${confColor};">${ioc.confidence}%</span>
            </div>
          </td>
          <td><span class="badge-classification attack">${ioc.status}</span></td>
          <td>
            <button class="row-block-btn blocked-done" type="button" style="padding:4px 10px; font-size:11px;" onclick="window.astralockAskGeminiIntel('${ioc.indicator}', '${ioc.category}', '${ioc.asn}')">
              <i class="fa-solid fa-sparkles"></i> Intel Dossier
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="7" class="loading-state" style="color:var(--crimson-attack);">Error loading threat intelligence: ${err.message}</td></tr>`;
    }
  }

  // ==========================================================================
  // VIEW 8: SOAR PLAYBOOKS & AUTOMATION
  // ==========================================================================
  async function loadSoar() {
    const tbody = document.querySelector("#soar-playbooks-table-body");
    if (!tbody) return;

    try {
      const data = await apiRequest("/api/soar");
      tbody.innerHTML = "";

      if (!data.playbooks || data.playbooks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading-state">No playbooks found in catalog.</td></tr>';
        return;
      }

      data.playbooks.forEach(pb => {
        const tr = document.createElement("tr");
        const isPending = pb.status && pb.status.includes("Pending");

        tr.innerHTML = `
          <td style="font-weight:600; color:var(--text-white);">
            <i class="fa-solid fa-bolt" style="color:var(--astralock-orange); margin-right:8px;"></i>${pb.name}
          </td>
          <td style="font-size:11.5px; color:var(--text-secondary); max-width:280px;">${pb.desc}</td>
          <td><span class="signature-chip">${pb.mode}</span></td>
          <td style="font-family:var(--font-mono);">${pb.runs} runs (${pb.success_rate})</td>
          <td>
            <span class="badge-classification ${isPending ? 'anomalous' : 'attack'}" style="${!isPending ? 'background:rgba(16,185,129,0.15); color:var(--emerald-green); border-color:rgba(16,185,129,0.3);' : ''}">
              ${pb.status}
            </span>
          </td>
          <td>
            <button class="run-playbook-btn" type="button" style="padding:5px 12px; font-size:11px;" onclick="window.astralockTriggerSoarPlaybook('${pb.id}', '${pb.name}')">
              <i class="fa-solid fa-play"></i> Execute
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="6" class="loading-state" style="color:var(--crimson-attack);">Error loading SOAR playbooks: ${err.message}</td></tr>`;
    }
  }

  // ==========================================================================
  // VIEW 9: RED TEAM BREACH & ATTACK SIMULATION
  // ==========================================================================
  async function loadRedTeam() {
    const tbody = document.querySelector("#redteam-table-body");
    if (!tbody) return;

    try {
      const data = await apiRequest("/api/red-team");
      tbody.innerHTML = "";

      if (!data.simulations || data.simulations.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading-state">No adversary simulation exercises registered.</td></tr>';
        return;
      }

      data.simulations.forEach(sim => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td style="font-family:var(--font-mono); font-weight:600; color:#38bdf8;">${sim.id}</td>
          <td style="font-weight:600; color:var(--text-white);">${sim.name}</td>
          <td style="font-family:var(--font-mono); color:var(--text-secondary);">${sim.target}</td>
          <td><span class="badge-classification attack" style="background:rgba(16,185,129,0.15); color:var(--emerald-green); border-color:rgba(16,185,129,0.3);"><i class="fa-solid fa-circle-check"></i> ${sim.status}</span></td>
          <td>
            <button class="row-block-btn" type="button" id="btn-run-${sim.id}" style="padding:4px 12px; font-size:11px;" onclick="window.astralockRunSimulation('${sim.id}')">
              <i class="fa-solid fa-bullseye"></i> Launch Attack
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="5" class="loading-state" style="color:var(--crimson-attack);">Error loading simulations: ${err.message}</td></tr>`;
    }
  }

  // ==========================================================================
  // VIEW 10: ENDPOINTS FLEET & DIAGNOSTICS
  // ==========================================================================
  async function loadEndpoints() {
    const tbody = document.querySelector("#endpoints-table-body");
    if (!tbody) return;

    try {
      const data = await apiRequest("/api/endpoints");
      tbody.innerHTML = "";

      if (!data.endpoints || data.endpoints.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="loading-state">No endpoints found in fleet telemetry.</td></tr>';
        return;
      }

      data.endpoints.forEach(ep => {
        const tr = document.createElement("tr");
        const riskColor = ep.risk >= 80 ? "#ff6879" : (ep.risk >= 50 ? "#fbbf24" : "var(--emerald-green)");
        const isIsolated = ep.status === "Isolated";

        tr.innerHTML = `
          <td style="font-family:var(--font-mono); font-weight:600; color:var(--text-white);">
            <i class="fa-solid fa-laptop" style="margin-right:7px; color:var(--text-muted);"></i>${ep.hostname}
          </td>
          <td style="font-family:var(--font-mono); color:var(--text-secondary);">${ep.ip}</td>
          <td>${ep.os}</td>
          <td style="font-family:var(--font-mono); color:#fbbf24;">${ep.user}</td>
          <td><span class="signature-chip">${ep.edr}</span></td>
          <td>
            <div class="risk-bar-wrap">
              <div class="risk-bar-track">
                <div class="risk-bar-fill" style="width:${ep.risk}%; background:${riskColor};"></div>
              </div>
              <span class="risk-val" style="color:${riskColor};">${ep.risk}%</span>
            </div>
          </td>
          <td>
            <button class="row-block-btn ${isIsolated ? 'blocked-done' : ''}" type="button" style="padding:4px 10px; font-size:11px;" onclick="window.astralockEndpointAction('${ep.hostname}', '${ep.ip}')">
              ${isIsolated ? '<i class="fa-solid fa-lock"></i> Isolated' : '<i class="fa-solid fa-shield"></i> Isolate'}
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="7" class="loading-state" style="color:var(--crimson-attack);">Error loading endpoints: ${err.message}</td></tr>`;
    }
  }

  // ==========================================================================
  // VIEW 11: COMPLIANCE GOVERNANCE & AUDIT
  // ==========================================================================
  async function loadCompliance() {
    const tbody = document.querySelector("#compliance-table-body");
    if (!tbody) return;

    try {
      const data = await apiRequest("/api/compliance");
      tbody.innerHTML = "";

      if (!data.controls || data.controls.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading-state">No compliance controls found.</td></tr>';
        return;
      }

      data.controls.forEach(ctrl => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td style="font-family:var(--font-mono); font-weight:600; color:#38bdf8;">${ctrl.code}</td>
          <td><span class="signature-chip">${ctrl.framework}</span></td>
          <td style="color:var(--text-white); font-weight:500;">${ctrl.desc}</td>
          <td style="font-size:11.5px; color:var(--text-secondary);">${ctrl.evidence}</td>
          <td><span class="badge-classification attack" style="background:rgba(16,185,129,0.15); color:var(--emerald-green); border-color:rgba(16,185,129,0.3);"><i class="fa-solid fa-circle-check"></i> ${ctrl.status}</span></td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="5" class="loading-state" style="color:var(--crimson-attack);">Error loading compliance controls: ${err.message}</td></tr>`;
    }
  }

  // ==========================================================================
  // VIEW 12: EXECUTIVE BRIEFS & REPORTS
  // ==========================================================================
  async function loadReports() {
    const tbody = document.querySelector("#reports-table-body");
    if (!tbody) return;

    try {
      const data = await apiRequest("/api/reports");
      tbody.innerHTML = "";

      if (!data.templates || data.templates.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading-state">No report templates registered.</td></tr>';
        return;
      }

      data.templates.forEach(tpl => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td style="font-weight:600; color:var(--text-white);">
            <i class="fa-solid fa-file-lines" style="color:#38bdf8; margin-right:8px;"></i>${tpl.title}
          </td>
          <td style="font-size:11.5px; color:var(--text-secondary); max-width:280px;">${tpl.desc}</td>
          <td><span class="signature-chip">${tpl.schedule}</span></td>
          <td><span class="badge-classification anomalous" style="font-size:10px;">${tpl.format}</span></td>
          <td>
            <button class="row-block-btn" type="button" id="btn-rep-${tpl.id}" style="padding:4px 12px; font-size:11px;" onclick="window.astralockGenerateReport('${tpl.id}', '${tpl.title}')">
              <i class="fa-solid fa-download"></i> Generate
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="5" class="loading-state" style="color:var(--crimson-attack);">Error loading reports: ${err.message}</td></tr>`;
    }
  }

  // ==========================================================================
  // VIEW 13: SETTINGS & DEFENSE POLICIES
  // ==========================================================================
  async function loadSettings() {
    try {
      const settings = await apiRequest("/api/settings");
      const blockModeSel = document.querySelector("#settings-block-mode");
      const riskThresh = document.querySelector("#settings-risk-threshold");
      const neverBlock = document.querySelector("#settings-never-block");

      if (blockModeSel && settings.block_mode) blockModeSel.value = settings.block_mode;
      if (riskThresh && settings.critical_risk_threshold) riskThresh.value = settings.critical_risk_threshold;
      if (neverBlock && settings.never_block) neverBlock.value = settings.never_block;
    } catch (err) {
      console.warn("Could not load settings:", err);
    }
  }

  async function saveSettings() {
    const saveBtn = document.querySelector("#save-settings-btn");
    const blockModeSel = document.querySelector("#settings-block-mode");
    const riskThresh = document.querySelector("#settings-risk-threshold");
    const neverBlock = document.querySelector("#settings-never-block");

    const origHtml = saveBtn ? saveBtn.innerHTML : "";
    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
    }

    try {
      const blockMode = blockModeSel ? blockModeSel.value : "simulate";
      const res = await apiRequest("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          block_mode: blockMode,
          critical_risk_threshold: riskThresh ? parseInt(riskThresh.value, 10) : 90,
          never_block: neverBlock ? neverBlock.value : ""
        })
      });

      if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.innerHTML = '<i class="fa-solid fa-check"></i> Saved';
        setTimeout(() => { saveBtn.innerHTML = origHtml; }, 2000);
      }
      showToast(`Settings saved successfully! Containment mode: ${blockMode}`);
    } catch (err) {
      if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.innerHTML = origHtml;
      }
      showToast("Failed to save settings: " + err.message, true);
    }
  }

  // ==========================================================================
  // GLOBAL INTERACTIVE CALLBACKS
  // ==========================================================================
  window.astralockRunSimulation = window.couraaRunSimulation = async function(simId) {
    const btn = document.querySelector(`#btn-run-${simId}`);
    const origHtml = btn ? btn.innerHTML : "";
    if (btn) {
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Emulating...';
      btn.disabled = true;
    }
    try {
      const res = await apiRequest("/api/red-team/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sim_id: simId })
      });
      showToast(res.message || `Simulation ${simId} neutralized!`);
      if (btn) {
        btn.innerHTML = `<i class="fa-solid fa-shield-check"></i> Defended (${res.detection_latency_ms}ms)`;
        btn.classList.add("blocked-done");
      }
    } catch (err) {
      if (btn) {
        btn.innerHTML = origHtml;
        btn.disabled = false;
      }
      showToast("Simulation failed: " + err.message, true);
    }
  };

  window.astralockGenerateReport = window.couraaGenerateReport = async function(templateId, title) {
    const btn = document.querySelector(`#btn-rep-${templateId}`);
    const origHtml = btn ? btn.innerHTML : "";
    if (btn) {
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Compiling...';
      btn.disabled = true;
    }
    try {
      const res = await apiRequest("/api/reports/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ template_id: templateId })
      });
      showToast(res.message || `Report '${title}' compiled!`);
      if (btn) {
        btn.innerHTML = '<i class="fa-solid fa-check"></i> Compiled';
        btn.classList.add("blocked-done");
      }
    } catch (err) {
      if (btn) {
        btn.innerHTML = origHtml;
        btn.disabled = false;
      }
      showToast("Failed to compile report: " + err.message, true);
    }
  };

  window.astralockAssetAction = window.couraaAssetAction = function(hostname, ip) {
    openBlockModal(ip);
  };

  window.astralockEndpointAction = window.couraaEndpointAction = function(hostname, ip) {
    openBlockModal(ip);
  };

  window.astralockTriggerSoarPlaybook = window.couraaTriggerSoarPlaybook = async function(id, name) {
    state.currentPlaybook = {
      id: id,
      name: name,
      label: `Run ${name}`,
      targets: ["185.190.141.22", "218.92.0.182", "198.51.100.45", "185.220.101.5", "5.160.245.10"]
    };
    await executePlaybook();
  };

  window.astralockAskGeminiIntel = window.couraaAskGeminiIntel = function(indicator, category, asn) {
    switchView("ai-analyst");
    const prompt = `Perform IOC threat attribution on ${indicator} (${category}, ASN: ${asn}). Detail threat actors, attack infrastructure, and mitigation tactics.`;
    if (els.aiInput) els.aiInput.value = prompt;
    runAiAnalystQuery(prompt);
  };

  // ==========================================================================
  // NOTIFICATIONS SYSTEM
  // ==========================================================================
  const notificationsState = [
    {
      id: "ntf-1",
      type: "critical",
      icon: "fa-solid fa-triangle-exclamation",
      title: "Active Attack: AS48282 Selectel RU",
      time: "2m ago",
      desc: "1,244 SSH brute-force attempts from 185.190.141.22. Edge firewall DROP rule deployed.",
      view: "alerts",
      unread: true
    },
    {
      id: "ntf-2",
      type: "warning",
      icon: "fa-solid fa-laptop-code",
      title: "Host Spotlight: Laptop-352 Kerberos Flag",
      time: "12m ago",
      desc: "Anomalous SMB / Pass-the-Ticket kerberos injection detected towards DC-01.",
      view: "endpoints",
      unread: true
    },
    {
      id: "ntf-3",
      type: "success",
      icon: "fa-solid fa-bolt",
      title: "SOAR Automation: Perimeter Rules Pushed",
      time: "38m ago",
      desc: "Playbook block_perimeter applied 5 iptables rules across edge routers.",
      view: "soar",
      unread: true
    },
    {
      id: "ntf-4",
      type: "info",
      icon: "fa-solid fa-rotate",
      title: "Threat Intel Sinkhole Synced",
      time: "1h ago",
      desc: "1,420 IOCs synchronized with AlienVault OTX, CISA AIS, and abuse.ch.",
      view: "threat-intel",
      unread: true
    },
    {
      id: "ntf-5",
      type: "success",
      icon: "fa-solid fa-clipboard-check",
      title: "Compliance Audit: SOC 2 96%",
      time: "2h ago",
      desc: "Continuous monitoring verified 48/50 security requirements.",
      view: "compliance",
      unread: false
    }
  ];

  function renderNotifications() {
    const list = document.querySelector("#notif-items-list");
    const countBadge = document.querySelector("#notif-unread-count");
    const dot = document.querySelector("#notifications-indicator-dot");

    const unreadCount = notificationsState.filter(n => n.unread).length;

    if (countBadge) {
      countBadge.textContent = unreadCount > 0 ? `${unreadCount} New` : "All Read";
      countBadge.style.color = unreadCount > 0 ? "#ff6879" : "var(--emerald-green)";
    }
    if (dot) {
      dot.style.display = unreadCount > 0 ? "block" : "none";
    }

    if (!list) return;
    list.innerHTML = "";

    notificationsState.forEach(notif => {
      const item = document.createElement("div");
      item.className = `notif-item ${notif.unread ? "unread" : ""}`;
      item.innerHTML = `
        <div class="notif-icon-box ${notif.type}">
          <i class="${notif.icon}"></i>
        </div>
        <div class="notif-body">
          <div class="notif-body-top">
            <span class="notif-item-title">${notif.title}</span>
            <span class="notif-time">${notif.time}</span>
          </div>
          <div class="notif-desc">${notif.desc}</div>
        </div>
      `;
      item.addEventListener("click", () => {
        notif.unread = false;
        renderNotifications();
        closeNotifications();
        switchView(notif.view);
        showToast(`Navigated to ${notif.view.toUpperCase()} module`);
      });
      list.appendChild(item);
    });
  }

  function toggleNotifications() {
    const dropdown = document.querySelector("#notifications-dropdown");
    if (!dropdown) return;
    const isHidden = dropdown.style.display === "none" || !dropdown.style.display;
    if (isHidden) {
      dropdown.style.display = "block";
      renderNotifications();
      closeSearchResults();
    } else {
      dropdown.style.display = "none";
    }
  }

  function closeNotifications() {
    const dropdown = document.querySelector("#notifications-dropdown");
    if (dropdown) dropdown.style.display = "none";
  }

  // ==========================================================================
  // GLOBAL SEARCH ENGINE
  // ==========================================================================
  const searchCorpus = [
    // Modules
    { type: "Module", title: "AI Analyst & Investigation", desc: "Autonomous SOC copilot, natural language SPL & chart queries", view: "ai-analyst", icon: "fa-solid fa-sparkles", keywords: "ai analyst copilot spl query investigation gemini llm chat" },
    { type: "Module", title: "Attack Correlation Graph", desc: "Multi-stage kill chain, incident #INC-4819 propagation", view: "correlation", icon: "fa-solid fa-diagram-project", keywords: "correlation kill chain attack graph lateral movement incident inc-4819" },
    { type: "Module", title: "Security Alerts & Real-Time Feed", desc: "1,244 authentication events, brute force detection feed & firewall blocks", view: "alerts", icon: "fa-solid fa-bell", keywords: "alerts detections brute force failed logins syslog auth.log drop" },
    { type: "Module", title: "Enterprise Assets Inventory", desc: "142 managed endpoints, cloud servers & vulnerability surface", view: "assets", icon: "fa-solid fa-server", keywords: "assets enterprise inventory vulnerability surface dc-01 bastion fileserver" },
    { type: "Module", title: "Threat Intelligence Feeds", desc: "1,420 high-fidelity sinkhole IOCs & threat actors (APT28, Storm-0501)", view: "threat-intel", icon: "fa-solid fa-crosshairs", keywords: "threat intel feeds iocs indicators alienvault cisa virustotal abuse.ch apt28 storm-0501" },
    { type: "Module", title: "SOAR Defense Playbooks", desc: "Automated perimeter firewall DROP & Kerberos isolation execution catalog", view: "soar", icon: "fa-solid fa-bolt", keywords: "soar playbooks automation containment firewall block iptables palo alto" },
    { type: "Module", title: "Red Team Breach Simulation", desc: "Adversary emulation exercises & 84.6% MITRE ATT&CK coverage", view: "red-team", icon: "fa-solid fa-cubes", keywords: "red team simulation mitre attack adversary emulation password spray" },
    { type: "Module", title: "Endpoints Fleet & Sysmon Diagnostics", desc: "124 EDR nodes, process trees & compromised host Laptop-352", view: "endpoints", icon: "fa-solid fa-laptop", keywords: "endpoints fleet edr sysmon laptop-352 process tree powershell mimikatz" },
    { type: "Module", title: "Compliance Governance & Audits", desc: "SOC 2 Type II (96%), CIS Benchmark v8, and PCI-DSS Req 10", view: "compliance", icon: "fa-solid fa-clipboard-check", keywords: "compliance audit soc 2 cis benchmark pci-dss iso 27001 regulatory" },
    { type: "Module", title: "Executive Briefs & Reports", desc: "Weekly threat briefings, forensic dossiers & export compiler", view: "reports", icon: "fa-solid fa-file-lines", keywords: "reports executive briefs forensic dossier pdf export audit" },
    { type: "Module", title: "Platform Settings & Controls", desc: "Firewall containment mode, whitelist IP policy & webhook channels", view: "settings", icon: "fa-solid fa-sliders", keywords: "settings configuration firewall mode simulate execute whitelist slack" },
    { type: "Module", title: "Log Explorer & File Ingestion", desc: "Syslog & auth.log upload, anomaly scoring & feature extraction", view: "log-explorer", icon: "fa-solid fa-file-code", keywords: "log explorer auth.log upload parser ingestion isolation forest" },
    { type: "Module", title: "Executive SOC Dashboard", desc: "Real-time telemetry trends, attack origin breakdown & MTTD metrics", view: "dashboard", icon: "fa-solid fa-chart-pie", keywords: "dashboard stats metrics charts timeline attackers overview" },

    // Known Threat IPs & ASNs
    { type: "Threat IP", title: "185.190.141.22", desc: "Selectel RU (AS48282) - 1,244 brute force attempts - Active DROP", view: "threat-intel", icon: "fa-solid fa-ban", keywords: "185.190.141.22 selectel ru russia brute force drop" },
    { type: "Threat IP", title: "218.92.0.182", desc: "Chinanet CN (AS4134) - Password spray scanner - Active DROP", view: "threat-intel", icon: "fa-solid fa-ban", keywords: "218.92.0.182 chinanet cn china spray scanner" },
    { type: "Threat IP", title: "194.26.29.112", desc: "Cobalt Strike C2 Beacon (AS398324 NL) - Sinkholed", view: "threat-intel", icon: "fa-solid fa-virus", keywords: "194.26.29.112 cobalt strike c2 beacon sinkholed netherlands" },

    // Endpoints & Hosts
    { type: "Endpoint", title: "Laptop-352 (10.0.12.35)", desc: "Corporate LAN - Compromised host exhibiting SMB Pass-the-Ticket to DC-01", view: "endpoints", icon: "fa-solid fa-laptop-medical", keywords: "laptop-352 10.0.12.35 analyst_dev pass-the-ticket kerberos" },
    { type: "Asset", title: "DC-01.corp.internal (10.0.4.10)", desc: "Primary Domain Controller - Tier-0 Core Asset - Risk Score 94%", view: "assets", icon: "fa-solid fa-shield-halved", keywords: "dc-01 10.0.4.10 domain controller tier-0 windows server" },
    { type: "Asset", title: "Bastion-SSH-01 (10.0.1.5)", desc: "DMZ Perimeter SSH Gateway - Ubuntu 22.04 LTS", view: "assets", icon: "fa-solid fa-server", keywords: "bastion-ssh-01 10.0.1.5 dmz ssh gateway perimeter" },

    // Playbooks
    { type: "SOAR Playbook", title: "block_perimeter", desc: "Deploy edge firewall DROP rules against attacking ASNs", view: "soar", icon: "fa-solid fa-play", keywords: "block_perimeter firewall drop rules iptables edge" },
    { type: "SOAR Playbook", title: "isolate_endpoint", desc: "Isolate compromised host network interfaces & purge Kerberos TGT", view: "soar", icon: "fa-solid fa-play", keywords: "isolate_endpoint host isolation purge kerberos tgt" }
  ];

  function renderSearchResults(query = "") {
    const dropdown = document.querySelector("#search-results-dropdown");
    const container = document.querySelector("#search-results-content");
    if (!dropdown || !container) return;

    const q = (query || "").trim().toLowerCase();
    container.innerHTML = "";

    // If query is non-empty, provide the prominent "Ask Gemini Copilot" action at top
    if (q) {
      const geminiSection = document.createElement("div");
      geminiSection.className = "search-section";
      geminiSection.innerHTML = `
        <div class="search-section-header">Generative AI Copilot</div>
        <div class="search-item gemini-item" id="search-ask-gemini-item">
          <div class="search-item-icon"><i class="fa-solid fa-sparkles"></i></div>
          <div class="search-item-info">
            <div class="search-item-title">
              <span>Ask Gemini: "${escapeHtml(query)}"</span>
              <span class="search-item-badge" style="background:rgba(56,189,248,0.15); color:#38bdf8;">AI REASONING</span>
            </div>
            <div class="search-item-desc">Execute deep SOC triage and autonomous correlation for this inquiry</div>
          </div>
        </div>
      `;
      geminiSection.querySelector("#search-ask-gemini-item").addEventListener("click", () => {
        closeSearchResults();
        switchView("ai-analyst");
        if (els.aiInput) els.aiInput.value = query;
        runAiAnalystQuery(query);
      });
      container.appendChild(geminiSection);
    }

    // Filter corpus items
    let matched = searchCorpus.filter(item => {
      if (!q) return item.type === "Module"; // Show all modules by default
      return item.title.toLowerCase().includes(q) ||
             item.desc.toLowerCase().includes(q) ||
             item.keywords.toLowerCase().includes(q);
    });

    if (matched.length > 0) {
      // Group by type
      const groups = {};
      matched.forEach(item => {
        if (!groups[item.type]) groups[item.type] = [];
        groups[item.type].push(item);
      });

      Object.keys(groups).forEach(groupName => {
        const sec = document.createElement("div");
        sec.className = "search-section";
        sec.innerHTML = `<div class="search-section-header">${groupName}s</div>`;

        groups[groupName].forEach(item => {
          const row = document.createElement("div");
          row.className = "search-item";
          row.innerHTML = `
            <div class="search-item-icon"><i class="${item.icon}"></i></div>
            <div class="search-item-info">
              <div class="search-item-title">
                <span>${item.title}</span>
                <span class="search-item-badge">${item.type}</span>
              </div>
              <div class="search-item-desc">${item.desc}</div>
            </div>
          `;
          row.addEventListener("click", () => {
            closeSearchResults();
            switchView(item.view);
            showToast(`Opened ${item.title}`);
          });
          sec.appendChild(row);
        });

        container.appendChild(sec);
      });
    } else if (!q) {
      // Empty query default hint
      const sec = document.createElement("div");
      sec.className = "search-section";
      sec.innerHTML = `
        <div class="search-section-header">Quick Navigations</div>
        <div style="padding:10px 14px; font-size:11.5px; color:var(--text-secondary);">
          Type any IP, hostname (e.g. <code>Laptop-352</code>), MITRE tactic, or prompt to search or ask Gemini.
        </div>
      `;
      container.appendChild(sec);
    }

    dropdown.style.display = "block";
  }

  function closeSearchResults() {
    const dropdown = document.querySelector("#search-results-dropdown");
    if (dropdown) dropdown.style.display = "none";
  }

  function escapeHtml(str) {
    return String(str || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // ==========================================================================
  // EVENT LISTENERS INITIALIZATION
  // ==========================================================================
  function setupEventListeners() {
    // Navigation items
    els.navBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        const view = btn.dataset.view;
        if (view) switchView(view);
      });
    });

    // AI Generate Button
    if (els.aiGenerateBtn) {
      els.aiGenerateBtn.addEventListener("click", () => {
        const val = els.aiInput ? els.aiInput.value : "";
        runAiAnalystQuery(val);
      });
    }

    // AI Input Enter key
    if (els.aiInput) {
      els.aiInput.addEventListener("keydown", e => {
        if (e.key === "Enter") {
          runAiAnalystQuery(els.aiInput.value);
        }
      });
    }

    // Prompt suggestion pills
    els.promptPills.forEach(pill => {
      pill.addEventListener("click", () => {
        const prompt = pill.dataset.prompt;
        if (els.aiInput) els.aiInput.value = prompt;
        runAiAnalystQuery(prompt);
      });
    });

    // Copy SPL
    if (els.copySplBtn && els.splCode) {
      els.copySplBtn.addEventListener("click", () => {
        navigator.clipboard.writeText(els.splCode.textContent).then(() => {
          showToast("SPL query copied to clipboard");
        });
      });
    }

    // Refresh Query
    if (els.refreshQueryBtn) {
      els.refreshQueryBtn.addEventListener("click", () => {
        const val = els.aiInput ? els.aiInput.value : "";
        runAiAnalystQuery(val);
      });
    }

    // Chat follow-up
    if (els.chatSendBtn) {
      els.chatSendBtn.addEventListener("click", sendFollowUp);
    }
    if (els.chatInput) {
      els.chatInput.addEventListener("keydown", e => {
        if (e.key === "Enter") sendFollowUp();
      });
    }

    // Run Playbook
    if (els.runPlaybookBtn) {
      els.runPlaybookBtn.addEventListener("click", executePlaybook);
    }

    // Alerts Filters
    els.alertFilterBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        els.alertFilterBtns.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        state.alertFilter = btn.dataset.alertFilter;
        loadAlerts();
      });
    });

    if (els.refreshAlertsBtn) {
      els.refreshAlertsBtn.addEventListener("click", loadAlerts);
    }

    // File Upload hooks
    if (els.topbarUploadBtn && els.hiddenFileInput) {
      els.topbarUploadBtn.addEventListener("click", () => els.hiddenFileInput.click());
    }
    if (els.browseFileBtn && els.hiddenFileInput) {
      els.browseFileBtn.addEventListener("click", () => els.hiddenFileInput.click());
    }
    if (els.hiddenFileInput) {
      els.hiddenFileInput.addEventListener("change", e => {
        if (e.target.files && e.target.files[0]) {
          handleFileUpload(e.target.files[0]);
        }
      });
    }

    // Drag and drop
    if (els.uploadDropzone) {
      els.uploadDropzone.addEventListener("dragover", e => {
        e.preventDefault();
        els.uploadDropzone.classList.add("dragover");
      });
      els.uploadDropzone.addEventListener("dragleave", () => {
        els.uploadDropzone.classList.remove("dragover");
      });
      els.uploadDropzone.addEventListener("drop", e => {
        e.preventDefault();
        els.uploadDropzone.classList.remove("dragover");
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
          handleFileUpload(e.dataTransfer.files[0]);
        }
      });
    }

    // Dialog buttons
    if (els.dialogCancelBtn && els.blockDialog) {
      els.dialogCancelBtn.addEventListener("click", () => els.blockDialog.close());
    }
    if (els.dialogConfirmBtn) {
      els.dialogConfirmBtn.addEventListener("click", confirmBlockAction);
    }

    // Brand link and Copilot badge to return to AI Analyst view
    const brandLink = document.querySelector("#brand-link");
    if (brandLink) {
      brandLink.addEventListener("click", e => {
        e.preventDefault();
        switchView("ai-analyst");
      });
    }

    const copilotBadge = document.querySelector(".copilot-badge");
    if (copilotBadge) {
      copilotBadge.style.cursor = "pointer";
      copilotBadge.addEventListener("click", () => switchView("ai-analyst"));
    }

    // URL hash navigation support
    window.addEventListener("hashchange", () => {
      const hash = window.location.hash.replace("#", "");
      if (hash) switchView(hash);
    });

    // Static row buttons for Ask Gemini
    document.querySelectorAll(".row-gemini-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const geo = btn.getAttribute("data-geo") || "Foreign IP";
        const ip = btn.getAttribute("data-ip") || "Unknown IP";
        const user = btn.getAttribute("data-user") || "admin";
        const count = btn.getAttribute("data-count") || "many";
        askGeminiAboutRow({ country: geo, sample_ip: ip, top_user: user, count: count });
      });
    });

    // Gemini Deep Triage Button
    const deepTriageBtn = document.querySelector("#gemini-deep-triage-btn");
    if (deepTriageBtn) {
      deepTriageBtn.addEventListener("click", () => {
        if (!els.chatInput) return;
        const activeP = els.aiInput ? els.aiInput.value : "Failed Administrative Logins";
        els.chatInput.value = `Perform a comprehensive deep triage for our current investigation: "${activeP}". Break down the threat landscape, identify primary attack origin ASNs, evaluate credential stuffing / brute-force risk, and formulate a step-by-step mitigation plan.`;
        sendFollowUp();
      });
    }

    // Google Gemini Dialog and API Integration
    const geminiBtn = document.querySelector("#gemini-key-btn");
    const geminiStatusText = document.querySelector("#gemini-status-text");
    const geminiDialog = document.querySelector("#gemini-modal-dialog");
    const closeGeminiBtn = document.querySelector("#close-gemini-modal-btn");
    const geminiKeyInput = document.querySelector("#gemini-key-input");
    const geminiModelSelect = document.querySelector("#gemini-model-select");
    const toggleGeminiVisBtn = document.querySelector("#toggle-gemini-key-vis");
    const geminiStatusDot = document.querySelector("#gemini-status-dot");
    const geminiStatusPrimary = document.querySelector("#gemini-status-primary");
    const geminiStatusSecondary = document.querySelector("#gemini-status-secondary");
    const geminiFeedbackMsg = document.querySelector("#gemini-feedback-msg");
    const testGeminiBtn = document.querySelector("#test-gemini-btn");
    const saveGeminiBtn = document.querySelector("#save-gemini-btn");
    const disconnectGeminiBtn = document.querySelector("#disconnect-gemini-btn");

    async function syncGeminiStatus() {
      try {
        const res = await apiRequest("/api/ai-analyst/gemini-config");
        const storedKey = sessionStorage.getItem("astralock-gemini-key") || sessionStorage.getItem("couraa-gemini-key") || "";
        const isConfigured = res.configured || !!storedKey;

        if (geminiBtn && geminiStatusText) {
          if (isConfigured) {
            geminiBtn.classList.add("active");
            geminiStatusText.textContent = "✦ Gemini LLM Active";
          } else {
            geminiBtn.classList.remove("active");
            geminiStatusText.textContent = "Connect Gemini AI";
          }
        }

        if (geminiStatusDot && geminiStatusPrimary && geminiStatusSecondary) {
          if (isConfigured) {
            geminiStatusDot.className = "status-indicator-dot active";
            const preview = res.key_preview || (storedKey ? `${storedKey.substring(0, 6)}...${storedKey.substring(storedKey.length - 4)}` : "");
            geminiStatusPrimary.textContent = `Connected: Google Gemini (${res.active_model || 'Auto-Detected'})`;
            geminiStatusSecondary.textContent = `Live Copilot reasoning enabled • Key: ${preview}`;
            if (disconnectGeminiBtn) disconnectGeminiBtn.style.display = "inline-flex";
          } else {
            geminiStatusDot.className = "status-indicator-dot";
            geminiStatusPrimary.textContent = "Engine: ASTRALOCK Local Rule Engine";
            geminiStatusSecondary.textContent = "Connect Gemini API key to activate cloud LLM reasoning";
            if (disconnectGeminiBtn) disconnectGeminiBtn.style.display = "none";
          }
        }

        if (geminiModelSelect && res.models && res.models.length > 0) {
          const prevVal = geminiModelSelect.value;
          geminiModelSelect.innerHTML = res.models.map(m => `<option value="${m.id}">${m.name}</option>`).join("");
          if (res.active_model && res.models.some(m => m.id === res.active_model)) {
            geminiModelSelect.value = res.active_model;
          } else if (prevVal) {
            geminiModelSelect.value = prevVal;
          }
        }

        if (geminiKeyInput && !geminiKeyInput.value && storedKey) {
          geminiKeyInput.value = storedKey;
        }
      } catch (e) {
        console.warn("Failed to check Gemini status:", e);
      }
    }

    function openGeminiModal() {
      if (!geminiDialog) return;
      if (geminiFeedbackMsg) {
        geminiFeedbackMsg.textContent = "";
        geminiFeedbackMsg.className = "dialog-feedback-msg";
      }
      const storedKey = sessionStorage.getItem("astralock-gemini-key") || sessionStorage.getItem("couraa-gemini-key") || "";
      if (geminiKeyInput && storedKey) geminiKeyInput.value = storedKey;
      syncGeminiStatus();
      geminiDialog.showModal();
    }

    function closeGeminiModal() {
      if (geminiDialog) geminiDialog.close();
    }

    if (geminiBtn) {
      geminiBtn.addEventListener("click", openGeminiModal);
    }

    if (closeGeminiBtn) {
      closeGeminiBtn.addEventListener("click", closeGeminiModal);
    }

    if (toggleGeminiVisBtn && geminiKeyInput) {
      toggleGeminiVisBtn.addEventListener("click", () => {
        const isPass = geminiKeyInput.type === "password";
        geminiKeyInput.type = isPass ? "text" : "password";
        toggleGeminiVisBtn.innerHTML = isPass ? '<i class="fa-regular fa-eye-slash"></i>' : '<i class="fa-regular fa-eye"></i>';
      });
    }

    if (testGeminiBtn) {
      testGeminiBtn.addEventListener("click", async () => {
        const key = (geminiKeyInput ? geminiKeyInput.value.trim() : "") || sessionStorage.getItem("astralock-gemini-key") || sessionStorage.getItem("couraa-gemini-key") || "";
        const model = (geminiModelSelect ? geminiModelSelect.value : "auto");
        if (!key) {
          if (geminiFeedbackMsg) {
            geminiFeedbackMsg.className = "dialog-feedback-msg error";
            geminiFeedbackMsg.textContent = "Please enter an API key to test.";
          }
          return;
        }

        const origText = testGeminiBtn.innerHTML;
        testGeminiBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Discovering Models...';
        testGeminiBtn.disabled = true;

        try {
          const res = await apiRequest("/api/ai-analyst/gemini-config", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ api_key: key, model: model, action: "test" })
          });
          testGeminiBtn.innerHTML = origText;
          testGeminiBtn.disabled = false;
          if (res.success) {
            if (geminiModelSelect && res.available_models && res.available_models.length > 0) {
              geminiModelSelect.innerHTML = `<option value="auto">Auto-Detect Best Available Model</option>` +
                res.available_models.map(m => `<option value="${m}">${m}</option>`).join("");
              if (res.model) geminiModelSelect.value = res.model;
            }
            if (geminiFeedbackMsg) {
              geminiFeedbackMsg.className = "dialog-feedback-msg success";
              geminiFeedbackMsg.textContent = `✔ ${res.message}`;
            }
          } else {
            if (geminiFeedbackMsg) {
              geminiFeedbackMsg.className = "dialog-feedback-msg error";
              geminiFeedbackMsg.textContent = `✖ ${res.error || 'Connection failed'}`;
            }
          }
        } catch (err) {
          testGeminiBtn.innerHTML = origText;
          testGeminiBtn.disabled = false;
          if (geminiFeedbackMsg) {
            geminiFeedbackMsg.className = "dialog-feedback-msg error";
            geminiFeedbackMsg.textContent = `✖ ${err.message}`;
          }
        }
      });
    }

    if (saveGeminiBtn) {
      saveGeminiBtn.addEventListener("click", async () => {
        const key = (geminiKeyInput ? geminiKeyInput.value.trim() : "");
        const model = (geminiModelSelect ? geminiModelSelect.value : "auto");
        if (!key) {
          if (geminiFeedbackMsg) {
            geminiFeedbackMsg.className = "dialog-feedback-msg error";
            geminiFeedbackMsg.textContent = "Please enter an API key to save.";
          }
          return;
        }

        const origText = saveGeminiBtn.innerHTML;
        saveGeminiBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
        saveGeminiBtn.disabled = true;

        try {
          const res = await apiRequest("/api/ai-analyst/gemini-config", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ api_key: key, model: model, action: "save" })
          });
          saveGeminiBtn.innerHTML = origText;
          saveGeminiBtn.disabled = false;

          if (res.success) {
            sessionStorage.setItem("astralock-gemini-key", key);
            sessionStorage.setItem("couraa-gemini-key", key);
            syncGeminiStatus();
            showToast(`Google Gemini Connected (${res.model || model})!`);
            closeGeminiModal();
          } else {
            if (geminiFeedbackMsg) {
              geminiFeedbackMsg.className = "dialog-feedback-msg error";
              geminiFeedbackMsg.textContent = `✖ ${res.error || 'Save failed'}`;
            }
          }
        } catch (err) {
          saveGeminiBtn.innerHTML = origText;
          saveGeminiBtn.disabled = false;
          if (geminiFeedbackMsg) {
            geminiFeedbackMsg.className = "dialog-feedback-msg error";
            geminiFeedbackMsg.textContent = `✖ ${err.message}`;
          }
        }
      });
    }

    if (disconnectGeminiBtn) {
      disconnectGeminiBtn.addEventListener("click", async () => {
        sessionStorage.removeItem("astralock-gemini-key");
        sessionStorage.removeItem("couraa-gemini-key");
        if (geminiKeyInput) geminiKeyInput.value = "";
        try {
          await apiRequest("/api/ai-analyst/gemini-config", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: "clear" })
          });
        } catch (e) {}
        syncGeminiStatus();
        showToast("Disconnected from Gemini. Using built-in SOC AI.");
        closeGeminiModal();
      });
    }

    syncGeminiStatus();

    // Module Action Buttons
    const saveSettingsBtn = document.querySelector("#save-settings-btn");
    if (saveSettingsBtn) saveSettingsBtn.addEventListener("click", saveSettings);

    const refreshAssetsBtn = document.querySelector("#refresh-assets-btn");
    if (refreshAssetsBtn) refreshAssetsBtn.addEventListener("click", loadAssets);

    const refreshRedteamBtn = document.querySelector("#refresh-redteam-btn");
    if (refreshRedteamBtn) refreshRedteamBtn.addEventListener("click", loadRedTeam);

    const corrBtn = document.querySelector("#gemini-correlation-btn");
    if (corrBtn) {
      corrBtn.addEventListener("click", () => {
        switchView("ai-analyst");
        const p = "Perform deep kill chain correlation and forensic graph analysis for incident #INC-4819 (Host Laptop-352 SMB Pass-the-Ticket propagation)";
        if (els.aiInput) els.aiInput.value = p;
        runAiAnalystQuery(p);
      });
    }

    const intelBtn = document.querySelector("#gemini-intel-btn");
    if (intelBtn) {
      intelBtn.addEventListener("click", () => {
        switchView("ai-analyst");
        const p = "Generate comprehensive threat intelligence brief on active IOCs 185.190.141.22 (Selectel RU) and 218.92.0.182 (Chinanet) and correlate with APT28 activity";
        if (els.aiInput) els.aiInput.value = p;
        runAiAnalystQuery(p);
      });
    }

    const soarBtn = document.querySelector("#gemini-soar-btn");
    if (soarBtn) {
      soarBtn.addEventListener("click", () => {
        switchView("ai-analyst");
        const p = "Evaluate current active threat telemetry and recommend automated SOAR containment playbooks";
        if (els.aiInput) els.aiInput.value = p;
        runAiAnalystQuery(p);
      });
    }

    const epBtn = document.querySelector("#gemini-endpoints-btn");
    if (epBtn) {
      epBtn.addEventListener("click", () => {
        switchView("ai-analyst");
        const p = "Diagnose compromised host Laptop-352 process tree: explorer.exe (PID 1140) -> cmd.exe (PID 4820) -> powershell.exe Pass-the-Ticket (PID 6128)";
        if (els.aiInput) els.aiInput.value = p;
        runAiAnalystQuery(p);
      });
    }

    const repBtn = document.querySelector("#gemini-report-btn");
    if (repBtn) {
      repBtn.addEventListener("click", () => {
        switchView("ai-analyst");
        const p = "Draft an executive security brief detailing the 24-hour brute-force campaign, blocked adversary ASNs, and zero-breach containment metrics";
        if (els.aiInput) els.aiInput.value = p;
        runAiAnalystQuery(p);
      });
    }

    const expCompBtn = document.querySelector("#export-compliance-btn");
    if (expCompBtn) {
      expCompBtn.addEventListener("click", async () => {
        try {
          const comp = await apiRequest("/api/compliance");
          const blob = new Blob([JSON.stringify(comp, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `astralock-compliance-audit-evidence-${new Date().toISOString().split("T")[0]}.json`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          showToast("Compliance audit evidence exported (SOC 2, CIS, PCI-DSS)!");
        } catch (e) {
          showToast("Failed to export compliance evidence: " + e.message, true);
        }
      });
    }

    // Global search input & shortcut
    if (els.globalSearch) {
      els.globalSearch.addEventListener("focus", () => {
        closeNotifications();
        renderSearchResults(els.globalSearch.value);
      });

      els.globalSearch.addEventListener("input", e => {
        renderSearchResults(e.target.value);
      });

      els.globalSearch.addEventListener("keydown", e => {
        if (e.key === "Enter") {
          const val = els.globalSearch.value.trim();
          if (val) {
            closeSearchResults();
            // Check if matches a known view or title
            const matched = searchCorpus.find(item =>
              item.title.toLowerCase() === val.toLowerCase() ||
              item.view.toLowerCase() === val.toLowerCase()
            );
            if (matched) {
              switchView(matched.view);
              showToast(`Navigated to ${matched.title}`);
            } else {
              switchView("ai-analyst");
              if (els.aiInput) els.aiInput.value = val;
              runAiAnalystQuery(val);
            }
          }
        } else if (e.key === "Escape") {
          closeSearchResults();
          els.globalSearch.blur();
        }
      });
    }

    // Notifications Button & Panel
    const notifBtn = document.querySelector("#notifications-btn") || document.querySelector(".notifications-btn");
    if (notifBtn) {
      notifBtn.addEventListener("click", e => {
        e.stopPropagation();
        toggleNotifications();
      });
    }

    const markAllReadBtn = document.querySelector("#mark-all-read-btn");
    if (markAllReadBtn) {
      markAllReadBtn.addEventListener("click", e => {
        e.stopPropagation();
        notificationsState.forEach(n => n.unread = false);
        renderNotifications();
        showToast("All security notifications marked as read");
      });
    }

    const notifViewAllBtn = document.querySelector("#notif-view-all-alerts-btn");
    if (notifViewAllBtn) {
      notifViewAllBtn.addEventListener("click", () => {
        closeNotifications();
        switchView("alerts");
      });
    }

    // Close search & notification popups on outside click
    document.addEventListener("click", e => {
      const searchBox = document.querySelector(".topbar-center");
      if (searchBox && !searchBox.contains(e.target)) {
        closeSearchResults();
      }

      const notifArea = document.querySelector(".topbar-right");
      if (notifArea && !notifArea.contains(e.target)) {
        closeNotifications();
      }
    });

    // Global search shortcut (Ctrl+K or Cmd+K)
    window.addEventListener("keydown", e => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (els.globalSearch) {
          els.globalSearch.focus();
          renderSearchResults(els.globalSearch.value);
        }
      }
    });
  }

  // ==========================================================================
  // INITIAL BOOTSTRAP
  // ==========================================================================
  function init() {
    setupEventListeners();

    // Initialize notification status on load
    renderNotifications();

    // Check URL hash for direct view navigation
    if (window.location.hash) {
      const hash = window.location.hash.replace("#", "");
      if (hash && document.querySelector(`#view-${hash}`)) {
        switchView(hash);
        return;
      }
    }

    // Initialize Default View (AI Analyst matching photo)
    const initialPrompt = (els.aiInput && els.aiInput.value) || "Show me failed administrative logins over the last 24 hours grouped by country";
    runAiAnalystQuery(initialPrompt);

    // Background prefetch for dashboard & alerts count
    loadAlerts();
    loadDashboard();
  }

  // Run on DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();