/**
 * Airlock AI - Enterprise Privacy Proxy Console
 * Main Frontend Controller
 */

(function () {
    "use strict";

    // ============================================================
    // APPLICATION STATE
    // ============================================================
    const state = {
        activeView: "gateway",
        activeDiffTab: "sanitized",
        isStreaming: false,
        activePolicy: {
            rules: {},
            allowlist: [],
            all_known_types: []
        },
        vaultEntries: [],
        telemetry: {
            total_requests: 0,
            sanitized_requests: 0,
            blocked_requests: 0,
            total_entities_shielded: 0,
            average_latency_ms: 0,
            recent_events: []
        }
    };

    // ============================================================
    // PRESET PROMPT DATASETS
    // ============================================================
    const PRESETS = {
        customer: "Write a personalized email to Rahul Sharma (email: rahul@gmail.com, phone: +91 9876543210) thanking him for his order of ₹45,000 for Acme Corp.",
        benchmark: "I built a high-performance backend using Flask and FastAPI on Ubuntu Linux for Acme Corp. Rahul Sharma (rahul@gmail.com) tested the API endpoints.",
        devops: "URGENT: Server 192.168.1.42 has an authentication failure. Revoke AWS secret AKIAIOSFODNN7EXAMPLE immediately and notify DevOps engineer Alice Smith at alice@company.com.",
        executive: "Review performance appraisal for employee John Doe (SSN 123-45-6789, email: jdoe@enterprise.com). Confirm his salary increment to $145,000 at Boston headquarters."
    };

    // ============================================================
    // DOM REFERENCES
    // ============================================================
    const DOM = {
        // Navigation
        navTabs: document.querySelectorAll(".nav-tab"),
        views: document.querySelectorAll(".view-panel"),
        healthStatusText: document.getElementById("healthStatusText"),
        footerModel: document.getElementById("footerModel"),

        // Gateway
        promptInput: document.getElementById("promptInput"),
        charCount: document.getElementById("charCount"),
        streamToggle: document.getElementById("streamToggle"),
        runProxyBtn: document.getElementById("runProxyBtn"),
        clearPromptBtn: document.getElementById("clearPromptBtn"),
        pipelineTracker: document.getElementById("pipelineTracker"),
        pipelineSteps: document.querySelectorAll(".pipeline-step"),
        metricVerdict: document.getElementById("metricVerdict"),
        metricProtected: document.getElementById("metricProtected"),
        metricLatency: document.getElementById("metricLatency"),
        metricExposure: document.getElementById("metricExposure"),
        gatewayEntityChips: document.getElementById("gatewayEntityChips"),
        shieldCountIndicator: document.getElementById("shieldCountIndicator"),

        // Diff Tabs & Displays
        diffTabs: document.querySelectorAll(".diff-tab"),
        diffContents: document.querySelectorAll(".diff-content"),
        sanitizedText: document.getElementById("sanitizedText"),
        rawLLMText: document.getElementById("rawLLMText"),
        rehydratedText: document.getElementById("rehydratedText"),

        // Detector Studio
        detectorInput: document.getElementById("detectorInput"),
        scanDetectorBtn: document.getElementById("scanDetectorBtn"),
        acceptedTableBody: document.getElementById("acceptedTableBody"),
        acceptedCount: document.getElementById("acceptedCount"),
        suppressedTableBody: document.getElementById("suppressedTableBody"),
        suppressedCount: document.getElementById("suppressedCount"),

        // Policy Matrix
        policyTableBody: document.getElementById("policyTableBody"),
        allowlistInput: document.getElementById("allowlistInput"),
        addAllowlistBtn: document.getElementById("addAllowlistBtn"),
        allowlistTagCloud: document.getElementById("allowlistTagCloud"),
        savePolicyBtn: document.getElementById("savePolicyBtn"),

        // Vault
        vaultTableBody: document.getElementById("vaultTableBody"),
        vaultEntryCount: document.getElementById("vaultEntryCount"),
        purgeVaultBtn: document.getElementById("purgeVaultBtn"),

        // Telemetry
        kpiTotal: document.getElementById("kpiTotal"),
        kpiShielded: document.getElementById("kpiShielded"),
        kpiBlocked: document.getElementById("kpiBlocked"),
        kpiLatency: document.getElementById("kpiLatency"),
        auditTableBody: document.getElementById("auditTableBody"),
        exportAuditBtn: document.getElementById("exportAuditBtn"),

        // Preset Chips & Copy Buttons
        presetChips: document.querySelectorAll(".preset-chip"),
        copyBtns: document.querySelectorAll(".copy-btn")
    };

    // ============================================================
    // TRAVERSING ROUTER (MULTI-PAGE NAVIGATION)
    // ============================================================

    function switchView(viewName) {
        if (!viewName) return;
        state.activeView = viewName;

        // Update nav tabs
        DOM.navTabs.forEach(tab => {
            if (tab.dataset.view === viewName) {
                tab.classList.add("active");
            } else {
                tab.classList.remove("active");
            }
        });

        // Update view panels
        DOM.views.forEach(panel => {
            if (panel.dataset.view === viewName) {
                panel.classList.add("active");
            } else {
                panel.classList.remove("active");
            }
        });

        // Sync URL hash
        if (window.location.hash !== `#${viewName}`) {
            history.pushState(null, "", `#${viewName}`);
        }

        // On tab switch actions
        if (viewName === "policy") {
            loadPolicyConfig();
        } else if (viewName === "telemetry") {
            loadTelemetry();
        } else if (viewName === "vault") {
            renderVaultTable();
        }
    }

    function initRouter() {
        DOM.navTabs.forEach(tab => {
            tab.addEventListener("click", () => {
                switchView(tab.dataset.view);
            });
        });

        // Popstate handler for browser back/forward
        window.addEventListener("popstate", () => {
            const hash = window.location.hash.replace("#", "") || "gateway";
            switchView(hash);
        });

        // Initial hash navigation
        const initialHash = window.location.hash.replace("#", "") || "gateway";
        switchView(initialHash);

        // Keyboard navigation (1-6 to switch views, unless inside an input/textarea)
        window.addEventListener("keydown", (e) => {
            const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : "";
            if (activeTag === "input" || activeTag === "textarea") {
                // If Ctrl+Enter or Cmd+Enter inside promptInput, trigger proxy execution
                if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && document.activeElement === DOM.promptInput) {
                    e.preventDefault();
                    executeSecureProxy();
                }
                return;
            }

            const num = parseInt(e.key, 10);
            if (!isNaN(num) && num >= 1 && num <= 6) {
                const views = ["gateway", "detector", "policy", "vault", "telemetry", "docs"];
                switchView(views[num - 1]);
            }
        });
    }

    // ============================================================
    // PROMPT COMPOSER CONTROLLER
    // ============================================================

    function updateCharCount() {
        if (!DOM.promptInput || !DOM.charCount) return;
        const len = DOM.promptInput.value.length;
        DOM.charCount.textContent = `${len} character${len === 1 ? "" : "s"}`;
    }

    function initComposer() {
        DOM.promptInput.addEventListener("input", updateCharCount);
        updateCharCount();

        DOM.clearPromptBtn.addEventListener("click", () => {
            DOM.promptInput.value = "";
            updateCharCount();
            DOM.promptInput.focus();
        });

        // Preset Chips
        DOM.presetChips.forEach(chip => {
            chip.addEventListener("click", () => {
                const presetKey = chip.dataset.preset;
                if (PRESETS[presetKey]) {
                    DOM.promptInput.value = PRESETS[presetKey];
                    updateCharCount();
                    DOM.promptInput.focus();
                }
            });
        });

        DOM.runProxyBtn.addEventListener("click", executeSecureProxy);
    }

    // ============================================================
    // PIPELINE PROGRESS TRACKER
    // ============================================================

    function resetPipeline() {
        DOM.pipelineSteps.forEach(s => {
            s.classList.remove("active", "completed");
        });
    }

    function setPipelineStep(stepName, isActive, isCompleted) {
        DOM.pipelineSteps.forEach(s => {
            if (s.dataset.step === stepName) {
                if (isActive) s.classList.add("active");
                if (isCompleted) {
                    s.classList.remove("active");
                    s.classList.add("completed");
                }
            }
        });
    }

    // ============================================================
    // DIFF VIEWER CONTROLLER
    // ============================================================

    function initDiffTabs() {
        DOM.diffTabs.forEach(tab => {
            tab.addEventListener("click", () => {
                const target = tab.dataset.tab;
                state.activeDiffTab = target;

                DOM.diffTabs.forEach(t => t.classList.remove("active"));
                tab.classList.add("active");

                DOM.diffContents.forEach(c => {
                    if (c.id === `diff${capitalize(target)}`) {
                        c.classList.add("active");
                    } else {
                        c.classList.remove("active");
                    }
                });
            });
        });

        // Copy buttons
        DOM.copyBtns.forEach(btn => {
            btn.addEventListener("click", () => {
                const targetId = btn.dataset.target;
                const el = document.getElementById(targetId);
                if (el) {
                    const text = el.textContent || el.innerText;
                    navigator.clipboard.writeText(text).then(() => {
                        const originalText = btn.textContent;
                        btn.textContent = "Copied!";
                        setTimeout(() => {
                            btn.textContent = originalText;
                        }, 1800);
                    });
                }
            });
        });
    }

    function capitalize(str) {
        if (!str) return "";
        if (str === "raw-llm") return "RawLLM";
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    // ============================================================
    // SECURE PROXY GATEWAY EXECUTION (FASTAPI INTEGRATION)
    // ============================================================

    async function executeSecureProxy() {
        const prompt = DOM.promptInput.value.trim();
        if (!prompt) {
            alert("Please enter a prompt to execute.");
            DOM.promptInput.focus();
            return;
        }

        // Set UI loading state
        DOM.runProxyBtn.disabled = true;
        DOM.runProxyBtn.style.opacity = "0.7";
        resetPipeline();
        DOM.metricVerdict.textContent = "SCANNING...";
        DOM.metricVerdict.className = "metric-val highlight-blue";
        DOM.metricLatency.textContent = "...";
        DOM.sanitizedText.textContent = "Processing local privacy scan...";
        DOM.rawLLMText.textContent = "Awaiting sanitized prompt...";
        DOM.rehydratedText.textContent = "Awaiting response rehydration...";
        DOM.gatewayEntityChips.innerHTML = `<span class="empty-hint">Scanning locally with Regex & spaCy NER...</span>`;

        const isStreaming = DOM.streamToggle.checked;

        if (isStreaming) {
            await executeWithSSE(prompt);
        } else {
            await executeWithJSON(prompt);
        }

        DOM.runProxyBtn.disabled = false;
        DOM.runProxyBtn.style.opacity = "1";
    }

    // Stream Execution via FastAPI Server-Sent Events (SSE)
    async function executeWithSSE(prompt) {
        setPipelineStep("detect", true, false);

        try {
            const response = await fetch("/api/v1/secure-chat/stream", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ prompt: prompt, stream: true })
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.detail || err.message || "Failed to execute streaming proxy request");
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = "";
            let rawLLMAccumulator = "";

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split("\n\n");
                buffer = lines.pop(); // keep last incomplete chunk

                for (const chunk of lines) {
                    if (!chunk.trim()) continue;
                    const eventMatch = chunk.match(/^event:\s*(\w+)/m);
                    const dataMatch = chunk.match(/^data:\s*(.+)$/m);

                    if (eventMatch && dataMatch) {
                        const eventName = eventMatch[1];
                        const eventData = JSON.parse(dataMatch[1]);
                        handleSSEEvent(eventName, eventData, (text) => {
                            rawLLMAccumulator += text;
                            DOM.rawLLMText.textContent = rawLLMAccumulator;
                        });
                    }
                }
            }

        } catch (err) {
            console.error("SSE stream error:", err);
            handleProxyError(err.message);
        }
    }

    function handleSSEEvent(eventName, data, onChunk) {
        if (eventName === "stage") {
            if (data.stage === "detecting") {
                setPipelineStep("detect", true, false);
            } else if (data.stage === "llm_generating") {
                setPipelineStep("policy", false, true);
                setPipelineStep("vault", false, true);
                setPipelineStep("llm", true, false);
                DOM.rawLLMText.textContent = "";
            } else if (data.stage === "rehydrating") {
                setPipelineStep("llm", false, true);
                setPipelineStep("rehydrate", true, false);
            }
        } else if (eventName === "scan") {
            setPipelineStep("detect", false, true);
            setPipelineStep("policy", true, false);
            renderGatewayEntityChips(data.detections);
        } else if (eventName === "policy") {
            DOM.metricVerdict.textContent = data.decision;
            if (data.decision === "BLOCK") {
                DOM.metricVerdict.className = "metric-val highlight-amber";
            } else {
                DOM.metricVerdict.className = "metric-val highlight-green";
            }
        } else if (eventName === "blocked") {
            handleProxyBlocked(data.reason, data.blocked_types);
        } else if (eventName === "sanitized") {
            setPipelineStep("vault", false, true);
            DOM.sanitizedText.textContent = data.sanitized_prompt;
            DOM.metricProtected.textContent = (data.protected_items || []).length;
            state.vaultEntries = data.protected_items || [];
            renderVaultTable();
        } else if (eventName === "llm_chunk") {
            if (data.chunk) {
                onChunk(data.chunk);
            }
        } else if (eventName === "complete") {
            setPipelineStep("rehydrate", false, true);
            DOM.rehydratedText.textContent = data.final_response;
            DOM.metricLatency.textContent = `${data.metadata.processing_time_ms} ms`;
            DOM.metricExposure.textContent = "0.0% PII";
            // Refresh telemetry in background
            loadTelemetry();
        }
    }

    // Standard Non-Streaming JSON Execution
    async function executeWithJSON(prompt) {
        setPipelineStep("detect", true, false);

        try {
            const response = await fetch("/api/v1/secure-chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ prompt: prompt, stream: false })
            });

            const data = await response.json();

            if (response.status === 403 || data.blocked) {
                handleProxyBlocked(data.message, data.policy ? data.policy.blocked_types : []);
                return;
            }

            if (!response.ok || !data.success) {
                throw new Error(data.error || data.detail || "Server error occurred");
            }

            // Mark pipeline all complete
            DOM.pipelineSteps.forEach(s => s.classList.add("completed"));

            // Populate UI metrics
            DOM.metricVerdict.textContent = data.policy.decision;
            DOM.metricVerdict.className = "metric-val highlight-green";
            DOM.metricProtected.textContent = data.protected_items.length;
            DOM.metricLatency.textContent = `${data.metadata.processing_time_ms} ms`;
            DOM.metricExposure.textContent = "0.0% PII";

            renderGatewayEntityChips(data.detections);
            DOM.sanitizedText.textContent = data.sanitized_prompt;
            DOM.rawLLMText.textContent = data.llm_response;
            DOM.rehydratedText.textContent = data.final_response;

            state.vaultEntries = data.protected_items || [];
            renderVaultTable();
            loadTelemetry();

        } catch (err) {
            console.error("Proxy error:", err);
            handleProxyError(err.message);
        }
    }

    function handleProxyBlocked(reason, blockedTypes) {
        DOM.metricVerdict.textContent = "BLOCKED";
        DOM.metricVerdict.className = "metric-val highlight-amber";
        DOM.metricExposure.textContent = "0.0% (Zero Leakage)";
        DOM.sanitizedText.textContent = "REQUEST HALTED BY POLICY:\n\n" + (reason || "Blocked credential leakage");
        DOM.rawLLMText.textContent = "Not transmitted to external LLM.";
        DOM.rehydratedText.textContent = `Blocked by Airlock Security Policy.\n\nDetected blocked credentials: ${(blockedTypes || []).join(", ")}`;
        loadTelemetry();
    }

    function handleProxyError(msg) {
        DOM.metricVerdict.textContent = "ERROR";
        DOM.metricVerdict.className = "metric-val highlight-amber";
        DOM.sanitizedText.textContent = `Error: ${msg}`;
        DOM.rawLLMText.textContent = "Request failed.";
        DOM.rehydratedText.textContent = "An error occurred while processing the request.";
    }

    function renderGatewayEntityChips(detections) {
        if (!detections || detections.length === 0) {
            DOM.gatewayEntityChips.innerHTML = `<span class="empty-hint">No sensitive PII detected. Prompt passed clean.</span>`;
            DOM.shieldCountIndicator.textContent = "0 detected";
            return;
        }

        DOM.shieldCountIndicator.textContent = `${detections.length} shielded`;
        DOM.gatewayEntityChips.innerHTML = "";

        detections.forEach(d => {
            const pill = document.createElement("div");
            pill.className = "token-pill";
            pill.innerHTML = `
                <span class="token-pill-type">${escapeHtml(d.type)}</span>
                <span>${escapeHtml(d.value)}</span>
            `;
            DOM.gatewayEntityChips.appendChild(pill);
        });
    }

    // ============================================================
    // PAGE 2: DETECTION ENGINE STUDIO CONTROLLER
    // ============================================================

    async function runDetectorAnalysis() {
        const text = DOM.detectorInput.value.trim();
        if (!text) return;

        DOM.scanDetectorBtn.disabled = true;
        DOM.acceptedTableBody.innerHTML = `<tr><td colspan="5" class="empty-cell">Scanning with Regex, spaCy NER, and false-positive filter...</td></tr>`;
        DOM.suppressedTableBody.innerHTML = `<tr><td colspan="3" class="empty-cell">Evaluating false-positive heuristics...</td></tr>`;

        try {
            const response = await fetch("/api/v1/detect", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text: text })
            });

            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || "Detector scan failed");

            renderDetectorResults(data);

        } catch (err) {
            console.error("Detector analysis error:", err);
            DOM.acceptedTableBody.innerHTML = `<tr><td colspan="5" class="empty-cell error">Error: ${escapeHtml(err.message)}</td></tr>`;
        } finally {
            DOM.scanDetectorBtn.disabled = false;
        }
    }

    function renderDetectorResults(data) {
        // Render Accepted Entities
        const accepted = data.detections || [];
        DOM.acceptedCount.textContent = `${accepted.length} verified`;

        if (accepted.length === 0) {
            DOM.acceptedTableBody.innerHTML = `<tr><td colspan="5" class="empty-cell">No sensitive entities found.</td></tr>`;
        } else {
            DOM.acceptedTableBody.innerHTML = accepted.map(a => `
                <tr>
                    <td><span class="token-pill-type">${escapeHtml(a.type)}</span></td>
                    <td><strong>${escapeHtml(a.value)}</strong></td>
                    <td><code>${escapeHtml(a.source)}</code></td>
                    <td>${(a.confidence * 100).toFixed(0)}%</td>
                    <td>${a.start}–${a.end}</td>
                </tr>
            `).join("");
        }

        // Render Suppressed Entities (Crucial for showing the Flask solution!)
        const suppressed = data.suppressed_false_positives || [];
        DOM.suppressedCount.textContent = `${suppressed.length} suppressed`;

        if (suppressed.length === 0) {
            DOM.suppressedTableBody.innerHTML = `<tr><td colspan="3" class="empty-cell">No false positives detected in this sample.</td></tr>`;
        } else {
            DOM.suppressedTableBody.innerHTML = suppressed.map(s => `
                <tr>
                    <td><strong>${escapeHtml(s.value)}</strong></td>
                    <td><span class="badge-pill">${escapeHtml(s.raw_type)}</span></td>
                    <td><span class="highlight-amber">✓ ${escapeHtml(s.reason)}</span></td>
                </tr>
            `).join("");
        }
    }

    function initDetectorStudio() {
        DOM.scanDetectorBtn.addEventListener("click", runDetectorAnalysis);
    }

    // ============================================================
    // PAGE 3: POLICY MATRIX CONTROLLER
    // ============================================================

    async function loadPolicyConfig() {
        try {
            const response = await fetch("/api/v1/policy");
            if (!response.ok) throw new Error("Could not fetch policy configuration");
            const data = await response.json();
            state.activePolicy = data;
            renderPolicyTable();
            renderAllowlist();
        } catch (err) {
            console.error("Policy load error:", err);
        }
    }

    function renderPolicyTable() {
        const rules = state.activePolicy.rules || {};
        const types = state.activePolicy.all_known_types || Object.keys(rules);

        const descriptions = {
            PERSON: "Personal first/last names (e.g. John Doe, Rahul Sharma)",
            EMAIL: "Electronic mail addresses (e.g. user@domain.com)",
            PHONE: "International and domestic telephone numbers",
            CREDIT_CARD: "Credit/debit card numbers with Luhn checksum validation",
            IP_ADDRESS: "IPv4 and IPv6 network endpoint addresses",
            NATIONAL_ID: "SSN, Aadhaar, or official national identification numbers",
            ORGANIZATION: "Company, enterprise, and corporate entities",
            LOCATION: "Cities, states, countries, and geographic locations",
            API_KEY: "Bearer tokens, OpenAI keys, Slack secrets, JWTs",
            AWS_ACCESS_KEY: "Amazon Web Services Access Key IDs (AKIA...)",
            URL: "Web hyperlinks and URI endpoints",
            UUID: "Standard 128-bit unique identifiers"
        };

        DOM.policyTableBody.innerHTML = types.map(t => {
            const rule = rules[t] || { action: "SANITIZE" };
            const currentAction = rule.action || "SANITIZE";
            const desc = descriptions[t] || "Sensitive entity category";

            return `
                <tr data-type="${t}">
                    <td><strong>${escapeHtml(t)}</strong></td>
                    <td>${escapeHtml(desc)}</td>
                    <td>
                        <div class="policy-btn-group">
                            <button type="button" class="policy-opt-btn ${currentAction === "ALLOW" ? "active allow" : ""}" data-action="ALLOW">ALLOW</button>
                            <button type="button" class="policy-opt-btn ${currentAction === "SANITIZE" ? "active sanitize" : ""}" data-action="SANITIZE">SANITIZE</button>
                            <button type="button" class="policy-opt-btn ${currentAction === "BLOCK" ? "active block" : ""}" data-action="BLOCK">BLOCK</button>
                        </div>
                    </td>
                </tr>
            `;
        }).join("");

        // Attach event listeners to policy toggle buttons
        DOM.policyTableBody.querySelectorAll(".policy-opt-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const tr = e.target.closest("tr");
                const type = tr.dataset.type;
                const newAction = e.target.dataset.action;

                tr.querySelectorAll(".policy-opt-btn").forEach(b => {
                    b.className = "policy-opt-btn";
                });
                e.target.className = `policy-opt-btn active ${newAction.toLowerCase()}`;

                if (state.activePolicy.rules[type]) {
                    state.activePolicy.rules[type].action = newAction;
                }
            });
        });
    }

    function renderAllowlist() {
        const terms = state.activePolicy.allowlist || [];
        DOM.allowlistTagCloud.innerHTML = terms.map(term => `
            <span class="allow-tag">
                <span>${escapeHtml(term)}</span>
                <button class="tag-remove-btn" data-term="${escapeHtml(term)}">&times;</button>
            </span>
        `).join("");

        // Attach delete events
        DOM.allowlistTagCloud.querySelectorAll(".tag-remove-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                const term = btn.dataset.term;
                removeAllowlistTerm(term);
            });
        });
    }

    function addAllowlistTerm(term) {
        if (!term) return;
        term = term.trim().toLowerCase();
        if (!state.activePolicy.allowlist.includes(term)) {
            state.activePolicy.allowlist.push(term);
            renderAllowlist();
        }
    }

    function removeAllowlistTerm(term) {
        state.activePolicy.allowlist = state.activePolicy.allowlist.filter(t => t !== term);
        renderAllowlist();
    }

    async function savePolicyChanges() {
        const rules = state.activePolicy.rules || {};
        const blocked = [];
        const sanitize = [];
        const allow = [];

        Object.keys(rules).forEach(t => {
            const action = rules[t].action;
            if (action === "BLOCK") blocked.push(t);
            else if (action === "ALLOW") allow.push(t);
            else sanitize.push(t);
        });

        const payload = {
            blocked: blocked,
            sanitize: sanitize,
            allow: allow,
            add_allowlist_terms: state.activePolicy.allowlist
        };

        DOM.savePolicyBtn.disabled = true;
        DOM.savePolicyBtn.textContent = "Saving...";

        try {
            const response = await fetch("/api/v1/policy", {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!response.ok) throw new Error("Failed to update policy");
            const data = await response.json();
            alert("Security policy updated and active across the proxy gateway.");
        } catch (err) {
            console.error("Save policy error:", err);
            alert(`Error saving policy: ${err.message}`);
        } finally {
            DOM.savePolicyBtn.disabled = false;
            DOM.savePolicyBtn.textContent = "Save Policy Changes";
        }
    }

    function initPolicyStudio() {
        DOM.addAllowlistBtn.addEventListener("click", () => {
            const val = DOM.allowlistInput.value.trim();
            if (val) {
                addAllowlistTerm(val);
                DOM.allowlistInput.value = "";
            }
        });

        DOM.allowlistInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                DOM.addAllowlistBtn.click();
            }
        });

        DOM.savePolicyBtn.addEventListener("click", savePolicyChanges);
    }

    // ============================================================
    // PAGE 4: PRIVACY VAULT CONTROLLER
    // ============================================================

    function renderVaultTable() {
        const entries = state.vaultEntries || [];
        DOM.vaultEntryCount.textContent = `${entries.length} tokens`;

        if (entries.length === 0) {
            DOM.vaultTableBody.innerHTML = `<tr><td colspan="5" class="empty-cell">No surrogate tokens in active memory. Execute a prompt in the Gateway to inspect.</td></tr>`;
            return;
        }

        DOM.vaultTableBody.innerHTML = entries.map(e => `
            <tr>
                <td><span class="token-pill"><code>${escapeHtml(e.token)}</code></span></td>
                <td><span class="token-pill-type">${escapeHtml(e.type)}</span></td>
                <td><code>${escapeHtml(e.masked_value)}</code></td>
                <td>${e.char_length} chars (Reversible)</td>
                <td>${new Date(e.created_at * 1000).toLocaleTimeString()}</td>
            </tr>
        `).join("");
    }

    async function purgePrivacyVault() {
        if (!confirm("Are you sure you want to zeroize and flush all active in-memory vaults?")) {
            return;
        }

        try {
            const response = await fetch("/api/v1/vault/purge", { method: "DELETE" });
            const data = await response.json();
            state.vaultEntries = [];
            renderVaultTable();
            alert(data.message || "Active privacy vaults zeroized from memory.");
        } catch (err) {
            console.error("Vault purge error:", err);
            alert("Failed to purge vaults: " + err.message);
        }
    }

    function initVaultStudio() {
        DOM.purgeVaultBtn.addEventListener("click", purgePrivacyVault);
    }

    // ============================================================
    // PAGE 5: SOC AUDIT & TELEMETRY CONTROLLER
    // ============================================================

    async function loadTelemetry() {
        try {
            const response = await fetch("/api/v1/telemetry");
            if (!response.ok) return;
            const data = await response.json();
            state.telemetry = data;

            // Update KPI cards
            DOM.kpiTotal.textContent = data.total_requests || 0;
            DOM.kpiShielded.textContent = data.total_entities_shielded || 0;
            DOM.kpiBlocked.textContent = data.blocked_requests || 0;
            DOM.kpiLatency.textContent = `${data.average_latency_ms || 0} ms`;

            // Update Audit Table
            renderAuditTable(data.recent_events || []);
        } catch (err) {
            console.error("Telemetry load error:", err);
        }
    }

    function renderAuditTable(events) {
        if (!events || events.length === 0) {
            DOM.auditTableBody.innerHTML = `<tr><td colspan="8" class="empty-cell">No transactions recorded yet. Run a prompt in the Gateway to generate audit telemetry.</td></tr>`;
            return;
        }

        DOM.auditTableBody.innerHTML = events.map(evt => {
            const decisionClass = evt.decision === "BLOCK" ? "status-rose" : "status-green";
            return `
                <tr>
                    <td><code>${escapeHtml(evt.id)}</code></td>
                    <td>${escapeHtml(evt.timestamp)}</td>
                    <td><span class="tag-action ${evt.decision.toLowerCase()}">${escapeHtml(evt.decision)}</span></td>
                    <td><strong>${evt.entities_shielded}</strong></td>
                    <td><code>${(evt.types || []).join(", ") || "-"}</code></td>
                    <td>${evt.latency_ms} ms</td>
                    <td><code>${escapeHtml(evt.model)}</code></td>
                    <td><span class="table-preview" title="${escapeHtml(evt.preview)}">${escapeHtml(evt.preview)}</span></td>
                </tr>
            `;
        }).join("");
    }

    function exportAuditLog() {
        const jsonStr = JSON.stringify(state.telemetry, null, 2);
        const blob = new Blob([jsonStr], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `airlock_audit_log_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    function initTelemetryStudio() {
        DOM.exportAuditBtn.addEventListener("click", exportAuditLog);
    }

    // ============================================================
    // SYSTEM HEALTH MONITORING
    // ============================================================

    async function checkSystemHealth() {
        try {
            const response = await fetch("/api/v1/health");
            if (response.ok) {
                const data = await response.json();
                DOM.healthStatusText.textContent = data.gemini_live ? "Proxy Active • Live Gemini" : "Proxy Active • Sandbox";
                if (DOM.footerModel) {
                    DOM.footerModel.textContent = data.gemini_model;
                }
            } else {
                DOM.healthStatusText.textContent = "Offline";
            }
        } catch {
            DOM.healthStatusText.textContent = "Disconnected";
        }
    }

    // ============================================================
    // UTILITIES
    // ============================================================

    function escapeHtml(str) {
        if (!str && str !== 0) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // ============================================================
    // INITIALIZATION ENTRY POINT
    // ============================================================

    function initApp() {
        initRouter();
        initComposer();
        initDiffTabs();
        initDetectorStudio();
        initPolicyStudio();
        initVaultStudio();
        initTelemetryStudio();

        // Initial fetch
        checkSystemHealth();
        loadPolicyConfig();
        loadTelemetry();

        // Heartbeat timer every 15s
        setInterval(checkSystemHealth, 15000);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initApp);
    } else {
        initApp();
    }

})();
