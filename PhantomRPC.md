# PhantomRPC Detection & Mitigation Research

## 🛡️ Overview
This repository provides research and detection logic for the **PhantomRPC** vulnerability. Unlike standard memory corruption exploits, PhantomRPC is an architectural design flaw in the Windows RPC runtime (`rpcrt4.dll`) that enables **Local Privilege Escalation (LPE)** to `NT AUTHORITY\SYSTEM`.

### The Vulnerability
The flaw exists in how the Windows RPC runtime handles connections to offline or disabled RPC servers. When a high-privileged process attempts an RPC call to an unavailable server, the runtime fails to verify the legitimacy of the responding entity. Attackers can exploit this to impersonate a service and escalate their privileges across almost all versions of Windows.

---

## 🔍 Detection Rules

### 1. Palo Alto Cortex XDR (XQL Query)
This query identifies cases where a process involving the RPC runtime library (`rpcrt4.dll`) transitions from a standard user integrity level to a **SYSTEM** integrity level.

```sql
dataset = xdr_data
| filter event_type = ENUM.PROCESS_EXECUTE
| filter (
    action_process_image_path contains "rpcrt4.dll" 
    or action_process_image_command_line contains "rpcrt4.dll"
  )
| filter actor_process_integrity_level != ENUM.INTEGRITY_SYSTEM
| filter action_process_integrity_level = ENUM.INTEGRITY_SYSTEM
| fields _time, agent_hostname, actor_process_image_name, action_process_image_name, action_process_integrity_level
| sort desc _time
