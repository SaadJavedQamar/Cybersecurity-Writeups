
# 🚩 Incident Advisory: Bitwarden CLI Supply Chain Attack (v2026.4.0)

## ℹ️ Overview
- **Incident Type:** Supply Chain Compromise / Malicious Dependency Injection
- **Affected Package:** `@bitwarden/cli` (via npm)
- **Compromised Version:** `2026.4.0`
- **Threat Actor Group:** Associated with the **Checkmarx Supply Chain Campaign**
- **Malicious Payload:** `bw1.js`

## 🛡️ Executive Summary
A critical supply chain attack has been identified in the **Bitwarden CLI**. Attackers compromised the **GitHub Actions** build workflow, allowing them to inject a malicious script named `bw1.js` into the official npm distribution. This allows for the silent theft of environment variables, credentials, and CI/CD secrets from systems where this specific version is installed.

## 🔍 Technical Analysis
- **Vector:** Breach of the CI/CD pipeline (GitHub Actions).
- **Execution:** The malicious code is bundled within the standard package and executes during installation or runtime.
- **Objective:** Data exfiltration, specifically targeting developer secrets and organizational API keys.
- **Scope Awareness:** - ❌ **Infected:** npm-based Bitwarden CLI (v2026.4.0).
    - ✅ **Safe:** Desktop App, Mobile App, and Browser Extensions.

## 🛠️ Remediation & Mitigation
1. **Identify:** Check current version via terminal: `bw --version`.
2. **Uninstall:** Remove the infected package: `npm uninstall -g @bitwarden/cli`.
3. **Rollback:** Install a known safe version (e.g., `2026.3.0`) or the latest patched release.
4. **Credential Rotation:** **Mandatory** rotation of the Bitwarden Master Password and any API keys/tokens exposed to the CLI.

---

# 🛡️ Cortex XDR / XQL Threat Hunting Queries

Since you are working with **Cortex XDR**, you can use these **XQL queries** in your Query Builder to hunt for this threat across your environment.

### 1. Identify Installation of Compromised CLI
This query searches for endpoints where the specific infected version was installed via npm.

```sql
dataset = xdr_data
| filter event_type = ENUM.PROCESS 
| filter process_image_name = "npm"
| filter process_cmd_line contains "install" and process_cmd_line contains "@bitwarden/cli@2026.4.0"
| fields _time, agent_hostname, agent_ip_addresses, process_cmd_line, actor_process_image_name
```

### 2. Detect Execution of Malicious Script (`bw1.js`)
Use this query to find any file creation or process execution activity related to the malicious payload.

```sql
dataset = xdr_data
| filter event_type in (ENUM.FILE, ENUM.PROCESS)
| filter action_file_name ~= "bw1\.js" or process_cmd_line ~= ".*bw1\.js.*"
| fields _time, agent_hostname, action_file_path, process_cmd_line, actor_process_image_name
```

### 3. Hunt for Suspicious Data Exfiltration
This query monitors the Bitwarden CLI process (or its parent Node.js process) making unexpected external network connections, which could indicate credential exfiltration.

```sql
dataset = xdr_data
| filter actor_process_image_name contains "bw" or actor_process_command_line contains "bitwarden"
| filter event_sub_type = ENUM.NETWORK_CONN_SUCCEEDED
| filter remote_ip !in ("127.0.0.1", "0.0.0.0") 
| fields _time, agent_hostname, remote_ip, remote_port, actor_process_command_line, dns_query_name
```

---

> **Pro Tip:** If you find any hits on the `bw1.js` query, isolate those endpoints immediately using the **Action Center** in Cortex XDR to prevent further data leakage.
