Zaroor, ek Security Analyst ke liye GitHub-style Markdown format sabse behtareen hota hai taake woh professional lage aur readability bhi achi ho.

Niche Bitwarden incident ka writeup aur Cortex XDR ke liye XQL queries di gayi hain taake aap apne environment mein is threat ko hunt kar saken.

---

# 🚩 Incident Writeup: Bitwarden CLI Supply Chain Attack

## ℹ️ Overview
- **Incident Type:** Supply Chain Attack (Malicious Dependency Injection)
- **Target:** `@bitwarden/cli` (via npm)
- **Affected Version:** `2026.4.0`
- **Discovery Date:** April 2026
- **Malicious Payload:** `bw1.js`

## 🛡️ Executive Summary
Bitwarden CLI version `2026.4.0` was found to be compromised. Attackers leveraged a breach in the **GitHub Actions** build workflow to inject a malicious script (`bw1.js`) directly into the official npm package. This allows attackers to steal environment variables, API keys, and user credentials from developer machines and CI/CD pipelines.



## 🔍 Technical Analysis
- **Vector:** Compromised CI/CD (GitHub Actions).
- **Execution:** The script runs automatically upon package installation or execution.
- **Goal:** Data exfiltration (Credential theft and pipeline hijacking).
- **Scope:** **Limited to npm CLI only.** Desktop, Mobile, and Browser extensions are NOT affected.

## 🛠️ Remediation Steps
1. **Identify:** Check installed version using `bw --version`.
2. **Remove:** Uninstall the compromised version: `npm uninstall -g @bitwarden/cli`.
3. **Clean:** Clear npm cache: `npm cache clean --force`.
4. **Rotate:** Change Bitwarden Master Password and any API secrets used in the CLI.

---

# 🛡️ Cortex XDR / XQL Hunting Queries

Kyuki aap **Cortex XDR** par kaam karte hain, toh aap niche di gayi **XQL queries** ka istemal karke apne endpoints par is malicious activity ko dhoond sakte hain:

### 1. Identify Installation of Compromised Version
Yeh query un systems ko dhundegi jahan `npm` ke zariye Bitwarden CLI v2026.4.0 install ki gayi hai:

```sql
dataset = xdr_data
| filter event_type = ENUM.PROCESS 
| filter process_image_name = "npm"
| filter process_cmd_load_path contains "install" and process_cmd_load_path contains "@bitwarden/cli@2026.4.0"
| fields _time, agent_hostname, agent_ip_addresses, process_cmd_load_path, actor_process_image_name
```

### 2. Hunting for Malicious File Execution (`bw1.js`)
Hacker ne `bw1.js` naam ki file inject ki thi. Yeh query check karegi ke kya yeh file aapke kisi endpoint par create ya execute hui hai:

```sql
dataset = xdr_data
| filter event_type = ENUM.FILE 
| filter action_file_name ~= "bw1\.js" 
| fields _time, agent_hostname, action_file_path, action_file_name, actor_process_image_name, actor_process_command_line
```

### 3. Suspicious Network Activity from CLI
Agar CLI kisi unknown IP ya domain par data bhej rahi hai (Exfiltration), toh yeh query help karegi:

```sql
dataset = xdr_data
| filter actor_process_image_name contains "bw" or actor_process_image_name contains "node"
| filter actor_process_command_line contains "bitwarden"
| filter event_sub_type = ENUM.NETWORK_CONN_SUCCEEDED
| filter remote_ip !in (127.0.0.1, 0.0.0.0) // Exclude local traffic
| fields _time, agent_hostname, remote_ip, remote_port, actor_process_command_line
```

---

> **Note:** Markdown format mein `dataset = xdr_data` se query shuru hoti hai jo Cortex XDR ka standard hai. In queries ko aap apne **Query Builder** mein copy-paste kar sakte hain.
