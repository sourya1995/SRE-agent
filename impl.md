# AI Incident Response Agent: Complete Blueprint

## Simulation Overview

This document presents a comprehensive blueprint for building an AI agent that can automatically detect, analyze, and respond to production incidents using free and self-hosted tools.

---

## Simulation Run: High API Error Rate Alert

### Phase 1: Alert Detection & Incident Creation

**AI Agent Action:** The agent detects a new alert from Grafana.

**Simulated Alert Received:**
```json
{
  "alertName": "High API Error Rate",
  "service": "stock-tracker-app",
  "severity": "Critical",
  "threshold": ">5% 5xx errors for 1 minute",
  "currentValue": "15% 5xx errors (over last 1 minute)",
  "timestamp": "2025-09-28T10:30:00Z",
  "labels": {
    "job": "nextjs-app",
    "instance": "host.docker.internal:3000"
  }
}
```

**AI Agent Action:** The agent processes the alert and creates an incident ticket in the simulated ITSM system.

**Simulated ITSM Incident Ticket Created:**
```
Incident ID: INC-20250928-001
Title: Critical: High API Error Rate Detected in stock-tracker-app
Description:
  - Alert: High API Error Rate
  - Service: stock-tracker-app
  - Severity: Critical
  - Current 5xx Error Rate: 15%
  - Timestamp: 2025-09-28T10:30:00Z
Status: Open
Priority: P1 - Critical
Assigned To: AI Agent (Automated Triage)
Impact: High - User-facing API functionality is degraded
Urgency: High - Immediate investigation required
```

### Phase 2: Log Correlation & Understanding

**AI Agent Action:** The agent queries Loki for logs from the stock-tracker-app within the alert time window.

**Simulated Loki Query:**
```logql
{app="stock-tracker-app"} | logfmt | trace_id != "" | level = "error" | __time__ >= 2025-09-28T10:29:00Z and __time__ <= 2025-09-28T10:31:00Z
```

**Simulated Log Snippets (from Loki):**
```
2025-09-28T10:29:35Z level=error msg="Error in stock search." error="Error: Fetch failed 500: Internal Server Error" query="" trace_id="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" span_id="1234567890abcdef"

2025-09-28T10:29:40Z level=error msg="Error in stock search." error="Error: Fetch failed 500: Internal Server Error" query="AAPL" trace_id="b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7" span_id="234567890abcdef1"

2025-09-28T10:29:45Z level=error msg="Error in stock search." error="Error: Fetch failed 500: Internal Server Error" query="GOOG" trace_id="c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8" span_id="34567890abcdef12"
```

**AI Agent Understanding:**
> Multiple error logs with level=error and message "Error in stock search." are observed. The error field indicates "Fetch failed 500: Internal Server Error". These errors are directly linked to the searchStocks function, as confirmed by the log context and the trace_ids.

### Phase 3: Problem Reproduction & Evidence Collection

**AI Agent Action:** The agent attempts to reproduce the problem by interacting with the application.

**Simulated Reproduction Steps:**
1. The agent navigates to `http://localhost:3000/stocks`
2. The agent performs a search for a common stock symbol (e.g., "AAPL")
3. The agent observes the UI response

**AI Agent Observation:**
> Upon performing a stock search, the UI displays an empty results list or a generic error message, indicating that data could not be fetched. The network request to `/api/stocks/search` returns a 500 Internal Server Error.

**AI Agent Action:** The agent captures a screenshot of the problem and tracks logs during reproduction.

**Simulated Evidence:**
- **Screenshot Captured:** `screenshot_stock_search_error_20250928_103130.png` (showing empty search results or error message)
- **Logs Tracked:** Additional logs confirming the 500 Internal Server Error during the reproduction attempt are collected

### Phase 4: Codebase Analysis & Root Cause Determination

**AI Agent Action:** The agent analyzes the codebase, specifically focusing on the searchStocks function in `lib/actions/finnhub.actions.ts` and its dependencies.

**AI Agent Analysis:**
> The searchStocks function in `lib/actions/finnhub.actions.ts` (specifically around line 100, within the main try...catch block) is designed to call an external Finnhub API. The recent fix ensures that if fetchJSON (which calls the Finnhub API) fails, the error is re-thrown, leading to a 500 response from our server. The logs show "Fetch failed 500: Internal Server Error" originating from the fetchJSON utility. This strongly suggests the root cause is an external dependency issue – the Finnhub API is returning 5xx errors or is otherwise unavailable.

### Phase 5: Create Task Ticket

**AI Agent Action:** Based on the analysis, the agent determines this is an external dependency issue and creates a task ticket in the simulated task management system.

**Simulated Task Ticket Created:**
```
Ticket ID: TASK-20250928-001
Title: External Dependency Issue: Finnhub API Returning Errors
Description:
  **Problem:** The stock-tracker-app is experiencing a high rate of 5xx errors when attempting to fetch stock data from the Finnhub API. This is impacting user-facing search and news features.
  
  **Alert Triggered:** High API Error Rate (INC-20250928-001)
  
  **Logs:** Repeated `Error in stock search.` with `Fetch failed 500: Internal Server Error` from `finnhub.actions.ts`.
  
  **Reproduction Steps:**
  1. Navigate to http://localhost:3000/stocks
  2. Perform any stock search (e.g., "AAPL")
  3. Observe empty results or error message
  
  **Screenshot:** Attached `screenshot_stock_search_error_20250928_103130.png`
  
  **Timestamp of Occurrence:** 2025-09-28T10:30:00Z
  
  **Root Cause Analysis:** The issue originates from the external Finnhub API returning 5xx errors. Our application's `searchStocks` function (lib/actions/finnhub.actions.ts, around line 100) correctly propagates this error.

Type: Bug / External Dependency
Priority: High
Assigned To: SRE Team / External Integrations Team
```

### Phase 6: Remediation Analysis & Recommendations

**AI Agent Action:** Since this is identified as an external dependency issue, the agent determines that a direct code fix within our application is not the primary solution. Instead, it provides a list of potential reasons for the external failure and corresponding mitigation steps.

**AI Agent Remediation Analysis:**
> No immediate code change is required within the stock-tracker-app codebase as the application is correctly handling and reporting the external API failure. The issue lies with the Finnhub API itself. However, here are the top 5 potential reasons for this type of external API failure and recommended next steps:

#### Top 5 Potential Reasons & Fixing Steps

1. **Finnhub API Outage/Downtime**
   - **Fixing Steps:**
     - Check Finnhub's official status page (e.g., status.finnhub.io)
     - Monitor their social media/announcement channels
     - If confirmed outage, inform stakeholders and await resolution

2. **Finnhub API Rate Limiting**
   - **Fixing Steps:**
     - Verify our application's API usage against Finnhub's rate limits
     - Implement or adjust client-side rate limiting/throttling
     - Implement exponential backoff and retry logic for API calls
     - Consider upgrading Finnhub plan if limits are consistently hit

3. **Incorrect or Expired Finnhub API Key**
   - **Fixing Steps:**
     - Verify the FINNHUB_API_KEY in environment variables (e.g., .env, GitHub Secrets)
     - Generate a new API key in the Finnhub dashboard and update the application's configuration

4. **Network Connectivity Issues from Our Server to Finnhub**
   - **Fixing Steps:**
     - Check network connectivity from the application's host to finnhub.io (e.g., ping finnhub.io, traceroute finnhub.io)
     - Review firewall rules or security group configurations
     - Consult with network operations team

5. **Malformed Request to Finnhub API**
   - **Fixing Steps:**
     - Review recent changes to finnhub.actions.ts that construct the API request URL or parameters
     - Inspect the exact request being sent to Finnhub (e.g., by adding debug logging before the fetchJSON call)
     - Compare with Finnhub API documentation

---

## AI Agent Architecture & Implementation Blueprint

### Overall Agent Architecture

The agent operates as a persistent service, likely running in its own Docker container on a dedicated machine. It continuously monitors for alerts, processes them, and orchestrates a series of automated steps.

```
+-------------------+       +-------------------+       +-------------------+
|  Grafana Alerting | ----> |  Agent Service    | ----> |  ITSM/Incident    |
|   (Webhook)       |       |  (Node.js/Python) |       |  (Trello/Kanboard)|
+-------------------+       +-------------------+       +-------------------+
                                   |     ^
                                   |     |
                                   v     |
+-------------------+       +-------------------+       +-------------------+
|  Loki (Logs)      | <----> |  Log Analysis     | <---->|  Codebase Analysis|
|  Tempo (Traces)   |        |  (LLM Integration)|       |  (LLM Integration)|
+-------------------+       +-------------------+       +-------------------+
                                   |     ^
                                   |     |
                                   v     |
+-------------------+       +-------------------+       +-------------------+
|  Next.js App      | <----> |  Problem          | ----> |  Task Management  |
|  (UI/API)         |        |  Reproduction     |       |  (Trello/ClickUp) |
|                   |        |  (Playwright)     |       |                   |
+-------------------+       +-------------------+       +-------------------+
```

### Component Implementation

#### A. Alert Detection & Ingestion

**Functionality:** The agent needs to be notified when an alert fires.
**Tool:** Grafana's Alerting Webhook
**Agent Component:** A simple HTTP server within your agent service

```javascript
// agent-service/src/alert-receiver.js
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const PORT = 8080; // Or any available port

app.use(bodyParser.json());

app.post('/grafana-webhook', (req, res) => {
    const alert = req.body;
    console.log('Received Grafana Alert:', JSON.stringify(alert, null, 2));

    // Process the alert (e.g., extract name, status, labels, annotations)
    const alertName = alert.alerts[0].labels.alertname;
    const status = alert.alerts[0].status;
    const startsAt = alert.alerts[0].startsAt;
    const endsAt = alert.alerts[0].endsAt || 'N/A';
    const summary = alert.alerts[0].annotations.summary;

    if (status === 'firing') {
        console.log(`Alert FIRING: ${alertName} - ${summary}`);
        // Trigger incident creation and further analysis
        // incidentManager.createIncident(alert); // Call next step
    } else if (status === 'resolved') {
        console.log(`Alert RESOLVED: ${alertName}`);
        // Resolve incident in ITSM
        // incidentManager.resolveIncident(alert);
    }

    res.status(200).send('Alert received');
});

app.listen(PORT, () => {
    console.log(`Alert receiver listening on port ${PORT}`);
});

// How to configure in Grafana:
// 1. In Grafana, go to Alerting -> Contact points.
// 2. Add a new contact point.
// 3. Type: Webhook.
// 4. URL: http://<agent-service-ip>:8080/grafana-webhook
```

#### B. Incident Management (ServiceNow-like)

**Functionality:** Create and manage incident tickets
**Tool:** Trello (free tier) or Kanboard (self-hosted, open-source)
**Conceptual Code:** API calls to Trello to create a card (incident ticket)

```javascript
// agent-service/src/incident-manager.js
const axios = require('axios');

const TRELLO_API_KEY = process.env.TRELLO_API_KEY; // Get from Trello developer settings
const TRELLO_API_TOKEN = process.env.TRELLO_API_TOKEN; // Get from Trello developer settings
const TRELLO_INCIDENT_BOARD_ID = process.env.TRELLO_INCIDENT_BOARD_ID; // ID of your Trello board
const TRELLO_INCIDENT_LIST_ID = process.env.TRELLO_INCIDENT_LIST_ID; // ID of the 'Open Incidents' list

async function createIncident(alert) {
    const title = `INCIDENT: ${alert.alerts[0].labels.alertname} - ${alert.alerts[0].annotations.summary}`;
    const description = `
        **Alert Details:**
        - Name: ${alert.alerts[0].labels.alertname}
        - Severity: ${alert.alerts[0].labels.severity}
        - Status: ${alert.alerts[0].status}
        - Starts At: ${alert.alerts[0].startsAt}
        - Description: ${alert.alerts[0].annotations.description || 'N/A'}

        **Source:** Grafana Alerting
        **Incident ID:** INC-${Date.now()}
    `;

    try {
        const response = await axios.post(`https://api.trello.com/1/cards`, null, {
            params: {
                key: TRELLO_API_KEY,
                token: TRELLO_API_TOKEN,
                idList: TRELLO_INCIDENT_LIST_ID,
                name: title,
                desc: description,
                pos: 'top',
            }
        });
        console.log('Trello Incident Card Created:', response.data.url);
        return response.data.id; // Return card ID for later updates
    } catch (error) {
        console.error('Failed to create Trello incident:', error.response ? error.response.data : error.message);
        return null;
    }
}

// You'd also have functions to updateIncident, resolveIncident, etc.
module.exports = { createIncident };
```

#### C. Log Correlation & Analysis

**Functionality:** Query Loki for relevant logs based on alert context (time, labels)
**Tool:** Loki's HTTP API
**Agent Component:** HTTP client to query Loki, LLM for log understanding

```javascript
// agent-service/src/log-analyzer.js
const axios = require('axios');

const LOKI_URL = 'http://loki:3100'; // Or wherever your Loki is accessible

async function getLogsForAlert(alert, timeWindowMinutes = 5) {
    const alertTime = new Date(alert.alerts[0].startsAt);
    const endTime = alertTime.getTime() * 1_000_000; // Convert to nanoseconds
    const startTime = (alertTime.getTime() - (timeWindowMinutes * 60 * 1000)) * 1_000_000;

    // Construct a basic LogQL query based on common labels
    const query = `{app="stock-tracker-app", level="error"} | json | trace_id=\`${alert.alerts[0].labels.trace_id || ''}\``;

    try {
        const response = await axios.get(`${LOKI_URL}/loki/api/v1/query_range`, {
            params: {
                query: query,
                start: startTime.toString(),
                end: endTime.toString(),
                limit: 1000, // Max 1000 log lines
                direction: 'backward',
            }
        });

        const streams = response.data.data.result;
        if (streams.length === 0) {
            console.log('No relevant logs found in Loki.');
            return [];
        }

        const relevantLogs = streams.flatMap(stream =>
            stream.values.map(([timestamp, line]) => ({ timestamp, line }))
        );
        console.log(`Found ${relevantLogs.length} relevant logs.`);

        // Use LLM to summarize/understand logs
        const logSummary = await analyzeLogsWithLLM(relevantLogs);
        return { rawLogs: relevantLogs, summary: logSummary };

    } catch (error) {
        console.error('Failed to query Loki:', error.response ? error.response.data : error.message);
        return { rawLogs: [], summary: 'Failed to retrieve logs.' };
    }
}

async function analyzeLogsWithLLM(logs) {
    // This is where you'd integrate with an LLM API (e.g., Gemini API, OpenAI API, or a local LLM)
    // For a free solution, you might run a local LLM (e.g., Llama 3 via Ollama) if hardware permits.
    const prompt = `Analyze the following log entries and summarize the core problem, identifying key error messages and potential causes:\n\n${logs.map(l => l.line).join('\n')}`;
    // const llmResponse = await callLLMAPI(prompt); // Conceptual LLM API call
    const llmResponse = "Simulated LLM analysis: Logs indicate repeated 500 errors from Finnhub API calls within the searchStocks function.";
    return llmResponse;
}

module.exports = { getLogsForAlert };
```

#### D. Problem Reproduction & Evidence Collection

**Functionality:** Interact with the application UI to reproduce the issue and capture visual evidence
**Tool:** Playwright (Node.js/Python)
**Agent Component:** Playwright script

```javascript
// agent-service/src/reproducer.js
const { chromium } = require('playwright');
const fs = require('fs').promises;

async function reproduceProblem(alertContext, incidentId) {
    const browser = await chromium.launch(); // or .launch({ headless: false }) for visual debugging
    const page = await browser.newPage();

    try {
        await page.goto('http://localhost:3000/stocks'); // Assuming app is accessible
        console.log('Navigated to stock search page.');

        // Simulate user action based on alert context (e.g., search for a stock)
        await page.fill('input[placeholder="Search stocks..."]', 'AAPL');
        await page.press('input[placeholder="Search stocks..."]', 'Enter');
        console.log('Performed simulated search.');

        // Wait for results or error message
        await page.waitForSelector('.error-message, .no-results-message, .stock-list-item', { timeout: 10000 });

        const screenshotPath = `./screenshots/repro_${incidentId}.png`;
        await page.screenshot({ path: screenshotPath });
        console.log(`Screenshot captured: ${screenshotPath}`);

        // Capture console logs and network requests during reproduction
        const reproductionLogs = [];
        page.on('console', msg => reproductionLogs.push(`[Browser Console] ${msg.text()}`));
        page.on('requestfailed', request => reproductionLogs.push(`[Network Failed] ${request.method()} ${request.url()} - ${request.failure().errorText}`));
        // You'd need to integrate with Loki again for server-side logs during this period

        return { screenshotPath, reproductionLogs };

    } catch (error) {
        console.error('Failed to reproduce problem:', error);
        return { screenshotPath: null, reproductionLogs: [`Reproduction failed: ${error.message}`] };
    } finally {
        await browser.close();
    }
}

module.exports = { reproduceProblem };
```

#### E. Codebase Analysis & Root Cause

**Functionality:** Determine if the issue is internal code or external dependency
**Tool:** Local file system access, LLM for analysis
**Agent Component:** File reader, LLM prompt

```javascript
// agent-service/src/code-analyzer.js
const fs = require('fs').promises;
const path = require('path');

async function analyzeCodebase(logSummary, reproductionLogs, incidentId) {
    // Read relevant code files (e.g., finnhub.actions.ts, lib/metrics.ts, middleware/index.ts)
    const finnhubActionsCode = await fs.readFile(path.join(__dirname, '../../lib/actions/finnhub.actions.ts'), 'utf8');
    const middlewareCode = await fs.readFile(path.join(__dirname, '../../middleware/index.ts'), 'utf8');

    const prompt = `
        An alert fired for "High API Error Rate".
        Logs indicate: "${logSummary}".
        Reproduction attempts show: "${reproductionLogs.join('\n')}".

        Here is relevant code:
        --- lib/actions/finnhub.actions.ts ---
        ${finnhubActionsCode}
        --- middleware/index.ts ---
        ${middlewareCode}

        Based on the alert, logs, reproduction, and code:
        1. Is this issue primarily due to our application's code or an external dependency?
        2. If it's our code, identify the exact file, function, and line number.
        3. If it's an external dependency, identify which one and how our code handles it.
        4. Suggest top 5 potential reasons for the problem and high-level fixing steps.
    `;

    // const llmResponse = await callLLMAPI(prompt); // Conceptual LLM API call
    const llmResponse = `
        **Analysis:** The issue is primarily due to an **external dependency (Finnhub API)**.
        Our code in \`lib/actions/finnhub.actions.ts\` (specifically the \`searchStocks\` function, around line 100) correctly handles the external API failure by re-throwing the error, which results in a 5xx response from our server. The problem is upstream.

        **Top 5 Potential Reasons & Fixing Steps:**
        1. **Finnhub API Outage:** Check Finnhub status page.
        2. **Finnhub Rate Limiting:** Review usage, implement retries/backoff.
        3. **Incorrect API Key:** Verify FINNHUB_API_KEY in environment.
        4. **Network Connectivity:** Check server's network to finnhub.io.
        5. **Malformed Request:** Review recent code changes to Finnhub API calls.
    `;
    return llmResponse;
}

module.exports = { analyzeCodebase };
```

#### F. Task Management (ClickUp-like)

**Functionality:** Create detailed task tickets with findings
**Tool:** Trello (same API as incident management)
**Conceptual Code:** API calls to Trello to create a card (task ticket)

```javascript
// agent-service/src/task-manager.js
const axios = require('axios');

const TRELLO_API_KEY = process.env.TRELLO_API_KEY;
const TRELLO_API_TOKEN = process.env.TRELLO_API_TOKEN;
const TRELLO_TASK_BOARD_ID = process.env.TRELLO_TASK_BOARD_ID; // ID of your Trello board
const TRELLO_TASK_LIST_ID = process.env.TRELLO_TASK_LIST_ID; // ID of the 'To Do' list

async function createTaskTicket(analysisResult, screenshotPath, incidentId) {
    const title = `Investigate: ${analysisResult.includes('external dependency') ? 'External API Failure' : 'Internal Code Issue'}`;
    const description = `
        **Incident ID:** ${incidentId}
        **Analysis:** ${analysisResult}
        **Screenshot:** [Link to uploaded screenshot if hosted, or mention attachment]
        **Timestamp:** ${new Date().toISOString()}
    `;

    try {
        const response = await axios.post(`https://api.trello.com/1/cards`, null, {
            params: {
                key: TRELLO_API_KEY,
                token: TRELLO_API_TOKEN,
                idList: TRELLO_TASK_LIST_ID,
                name: title,
                desc: description,
                pos: 'top',
            }
        });
        console.log('Trello Task Card Created:', response.data.url);
        // Attach screenshot to card if possible (Trello API supports this)
        return response.data.id;
    } catch (error) {
        console.error('Failed to create Trello task:', error.response ? error.response.data : error.message);
        return null;
    }
}

module.exports = { createTaskTicket };
```

#### G. Automated Remediation & PR (Conceptual)

**Functionality:** Generate code fixes and create a Pull Request
**Tool:** LLM for code generation, Git CLI, GitHub API
**Agent Component:** LLM prompt, Git commands, GitHub API client

```javascript
// agent-service/src/remediator.js
const { exec } = require('child_process');
const axios = require('axios'); // For GitHub API

const GITHUB_REPO_OWNER = process.env.GITHUB_REPO_OWNER;
const GITHUB_REPO_NAME = process.env.GITHUB_REPO_NAME;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN; // GitHub Personal Access Token with repo scope

async function proposeCodeFix(analysisResult, incidentId) {
    // This step is only feasible if the LLM is "absolutely sure" of the fix.
    // For an external dependency issue, a direct code fix is unlikely.
    if (analysisResult.includes('external dependency')) {
        console.log('No direct code fix proposed for external dependency issue.');
        return null;
    }

    // Conceptual LLM call to generate fix
    const fixPrompt = `Given the following problem analysis and code, generate a code fix.
        Problem: ${analysisResult}
        Code: [Relevant code snippets]
        Generate only the changed code block.`;
    // const proposedFix = await callLLMAPI(fixPrompt); // Conceptual LLM API call
    const proposedFix = `// Simulated fix: Added a timeout to external API call
    const res = await fetch(url, { ...options, timeout: 5000 });`;

    // Simulate applying fix, creating branch, committing, and raising PR
    try {
        const branchName = `fix/incident-${incidentId}`;
        await execCommand(`git checkout -b ${branchName}`);
        // await fs.writeFile('path/to/file.ts', applyFix(originalCode, proposedFix)); // Apply fix
        await execCommand(`git add .`);
        await execCommand(`git commit -m "fix: Automated fix for ${incidentId}"`);
        await execCommand(`git push origin ${branchName}`);

        const prTitle = `fix(${incidentId}): Automated fix for ${incidentId}`;
        const prBody = `
            This PR contains an automated fix generated by the AI agent for incident ${incidentId}.
            **Problem:** ${analysisResult}
            **Proposed Fix:**
            \`\`\`typescript
            ${proposedFix}
            \`\`\`
            Please review and merge.
        `;

        const githubResponse = await axios.post(`https://api.github.com/repos/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}/pulls`, {
            title: prTitle,
            head: branchName,
            base: 'main', // Target branch
            body: prBody,
        }, {
            headers: { Authorization: `token ${GITHUB_TOKEN}` }
        });
        console.log('Pull Request created:', githubResponse.data.html_url);
        return githubResponse.data.html_url;

    } catch (error) {
        console.error('Failed to propose code fix or create PR:', error);
        return null;
    }
}

function execCommand(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`exec error: ${error}`);
                return reject(error);
            }
            console.log(`stdout: ${stdout}`);
            console.error(`stderr: ${stderr}`);
            resolve(stdout);
        });
    });
}

module.exports = { proposeCodeFix };
```

#### H. Chaos Injection & Fault Tolerance Testing

**Functionality:** The agent can dynamically create and apply Chaos Mesh experiments to inject faults into the application's containers. This can be used for:
- **Hypothesis Testing:** "If the database is slow, does the application degrade gracefully?"
- **Root Cause Confirmation:** "Is the external API truly slow, or is it a network issue from our side?"
- **Resilience Validation:** After a fix, inject the original fault to ensure the system now handles it correctly.

**Tool:** Chaos Mesh (via kubectl commands)
**Agent Component:** A module to generate Chaos Mesh YAML and execute shell commands (kubectl)

```javascript
// agent-service/src/chaos-injector.js
const { exec } = require('child_process');
const yaml = require('js-yaml'); // npm install js-yaml

async function injectChaos(experimentType, targetContainer, params, duration = '60s') {
    let chaosExperimentYaml = '';
    const experimentName = `${experimentType.toLowerCase()}-${targetContainer.replace(/[^a-z0-9-]/g, '-')}-${Date.now()}`;

    switch (experimentType) {
        case 'NetworkLatency':
            chaosExperimentYaml = yaml.dump({
                apiVersion: 'chaos-mesh.org/v1alpha1',
                kind: 'NetworkChaos',
                metadata: { name: experimentName },
                spec: {
                    action: 'latency',
                    mode: 'one',
                    selector: {
                        containers: [targetContainer],
                    },
                    delay: { latency: params.latency || '100ms' },
                    duration: duration,
                    direction: params.direction || 'to', // 'to' or 'from'
                    target: params.target || { mode: 'all' }, // Target all other containers by default
                },
            });
            break;
        case 'ContainerKill':
            chaosExperimentYaml = yaml.dump({
                apiVersion: 'chaos-mesh.org/v1alpha1',
                kind: 'ContainerKillChaos',
                metadata: { name: experimentName },
                spec: {
                    action: 'kill',
                    mode: 'one',
                    selector: {
                        containers: [targetContainer],
                    },
                    duration: duration,
                },
            });
            break;
        case 'CPUStress':
            chaosExperimentYaml = yaml.dump({
                apiVersion: 'chaos-mesh.org/v1alpha1',
                kind: 'StressChaos',
                metadata: { name: experimentName },
                spec: {
                    mode: 'one',
                    selector: {
                        containers: [targetContainer],
                    },
                    stressors: {
                        cpu: {
                            workers: params.workers || 1,
                            load: params.load || 50,
                        },
                    },
                    duration: duration,
                },
            });
            break;
        // Add more chaos types as needed (e.g., HTTPChaos, PodChaos)
        default:
            throw new Error(`Unsupported chaos experiment type: ${experimentType}`);
    }

    console.log(`Injecting chaos: ${experimentName}`);
    try {
        // Apply the YAML to the Kubernetes cluster where Chaos Mesh is running
        await execCommand(`echo '${chaosExperimentYaml.replace(/'/g, "'\\''")}' | kubectl apply -f -`);
        console.log(`Chaos experiment ${experimentName} started.`);
        return experimentName;
    } catch (error) {
        console.error(`Failed to inject chaos: ${error.message}`);
        throw error;
    }
}

async function cleanChaos(experimentName) {
    console.log(`Cleaning up chaos experiment: ${experimentName}`);
    try {
        await execCommand(`kubectl delete chaos ${experimentName}`);
        console.log(`Chaos experiment ${experimentName} deleted.`);
    } catch (error) {
        console.error(`Failed to clean up chaos: ${error.message}`);
        throw error;
    }
}

function execCommand(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`exec error: ${error}`);
                return reject(error);
            }
            console.log(`stdout: ${stdout}`);
            console.error(`stderr: ${stderr}`);
            resolve(stdout);
        });
    });
}

module.exports = { injectChaos, cleanChaos };
```

### Integration into Agent Workflow

This capability would be integrated into the agent's workflow at several points:

#### 1. During Problem Reproduction (Phase 3)
If initial reproduction attempts are inconclusive, the agent could inject a known fault (e.g., database latency) and then re-attempt reproduction to see if the application's behavior changes in a predictable way. This helps isolate the problem.

**Example:** If logs suggest database issues, inject NetworkLatency on the db container and observe if the error rate spikes further.

#### 2. For Root Cause Confirmation (Phase 4)
If the agent has a hypothesis (e.g., "The Finnhub API is slow"), it could inject NetworkLatency targeting finnhub.io from the web container. If the application's performance degrades further, it confirms the hypothesis.

#### 3. For Resilience Validation (Post-Remediation)
After a code fix is proposed and applied (or even manually), the agent could automatically re-run the chaos experiment that initially exposed the bug to ensure the fix actually works and the system is now resilient to that specific fault.

---

## Deployment Considerations

To run this agent, you would:

### 1. Create a Dedicated Project
A Node.js or Python application containing all the conceptual code above.

### 2. Containerize the Agent
Create a Dockerfile for your agent service.

```dockerfile
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm ci --only=production

# Install kubectl for Chaos Mesh integration
RUN apk add --no-cache curl && \
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

# Install Playwright browsers
RUN npx playwright install --with-deps chromium

# Copy application code
COPY . .

EXPOSE 8080

CMD ["node", "src/index.js"]
```

### 3. Deploy the Agent
Run the agent's Docker container on a dedicated server or VM. This container would need network access to:
- Your Grafana instance (to receive webhooks)
- Your Loki instance (to query logs)
- Your Next.js application (for reproduction via Playwright)
- Trello/Kanboard API
- GitHub API
- (Optionally) A local LLM if you choose that route

### 4. Environment Variables
All API keys and tokens (Trello, GitHub, LLM) would need to be securely provided to the agent's container as environment variables.

```bash
# Example environment variables
TRELLO_API_KEY=your_trello_api_key
TRELLO_API_TOKEN=your_trello_token
TRELLO_INCIDENT_BOARD_ID=board_id
TRELLO_INCIDENT_LIST_ID=list_id
TRELLO_TASK_BOARD_ID=board_id
TRELLO_TASK_LIST_ID=list_id
GITHUB_REPO_OWNER=your_username
GITHUB_REPO_NAME=your_repo
GITHUB_TOKEN=your_github_token
LOKI_URL=http://loki:3100
```

### Deployment Considerations for Chaos Injection

- The agent's Docker container would need kubectl installed
- The agent's container would need access to the kind cluster's kubeconfig file (mounted as a volume) or direct network access to the Kubernetes API server
- For a local setup, running the agent on the same host as kind simplifies kubectl access

---

## Free and Self-Hosted Tool Stack

This blueprint uses entirely free and self-hosted tools:

### Monitoring & Alerting
- **Grafana**: Free, open-source monitoring and alerting
- **Loki**: Free log aggregation system
- **Tempo**: Free distributed tracing (optional)

### Incident Management
- **Trello**: Free tier for ticket management
- **Kanboard**: Self-hosted, open-source alternative

### Automation Platform
- **Node.js/Python**: Free runtime environments
- **Playwright**: Free browser automation
- **Docker**: Free containerization

### Chaos Engineering
- **Chaos Mesh**: Free, open-source chaos engineering platform
- **kind**: Free local Kubernetes cluster

### Code Management
- **Git**: Free version control
- **GitHub**: Free public repositories

### LLM Integration Options
- **Local LLM (Ollama + Llama)**: Free if you have hardware
- **OpenAI API**: Pay-per-use (minimal cost for this use case)
- **Google Gemini API**: Free tier available

---

## Conclusion

This blueprint provides a comprehensive foundation for building an AI-powered incident response agent using entirely free and self-hosted tools. The agent can:

1. **Detect** alerts from Grafana
2. **Create** incident tickets automatically
3. **Correlate** logs from Loki
4. **Reproduce** problems using browser automation
5. **Analyze** codebases with LLM assistance
6. **Generate** task tickets with detailed analysis
7. **Propose** code fixes and create pull requests
8. **Inject** chaos for testing and validation

The modular architecture allows you to implement components incrementally, making it suitable for a phased rollout and C-suite demonstration. The reliance on free tools keeps costs minimal while providing enterprise-grade capabilities.
