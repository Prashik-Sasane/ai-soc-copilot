SEED_PLAYBOOKS = [
    {
        "title": "Credential Dumping via LSASS Memory - Response Playbook",
        "category": "playbook",
        "source_ref": "ATT&CK-T1003.001-Playbook",
        "content": """# Credential Dumping via LSASS Memory Playbook
## 1. Overview
LSASS (Local Security Authority Subsystem Service) memory dumping is a post-exploitation technique where attackers extract user credentials and NTLM hashes directly from process memory. Common tools include Mimikatz, rundll32 with comsvcs.dll, and Procdump.

## 2. Detection Criteria
- Suspicious calls to `MiniDump` function via `rundll32.exe C:\\Windows\\System32\\comsvcs.dll`.
- EDR process memory access alerts targeting `lsass.exe`.
- Creation of dump files in `C:\\Windows\\Temp\\` or `%TEMP%`.

## 3. Containment & Remediation Steps
1. Immediately isolate the host from the local network via EDR agent.
2. Terminate parent processes associated with command-line execution.
3. Force password reset for all user accounts logged into the compromised host.
4. Revoke active Kerberos ticket granting tickets (TGT) and Azure AD/Entra ID SSO refresh tokens.
5. Ingest file hash into global EDR blocklist.

## 4. Investigative Questions
- What process spawned the LSASS dump utility?
- Did lateral movement occur prior to or after LSASS memory read?
- Were domain admin credentials cached in host LSASS memory?
"""
    },
    {
        "title": "Obfuscated PowerShell & Command Interpreter Playbook",
        "category": "playbook",
        "source_ref": "ATT&CK-T1059.001-Playbook",
        "content": """# Obfuscated PowerShell Execution Playbook
## 1. Overview
Attackers use Base64-encoded command lines (`-Enc`, `-EncodedCommand`) or hidden windows (`-W Hidden`, `-WindowStyle Hidden`) in PowerShell to evade static command-line inspection and download secondary stages.

## 2. Detection Criteria
- `powershell.exe` spawned by Microsoft Office applications (`winword.exe`, `excel.exe`) or PDF readers.
- Presence of string flags: `-NoP -NonI -W Hidden -Enc`.
- Network socket connection initiated directly by `powershell.exe`.

## 3. Recommended Actions
1. Decode the Base64 payload to reveal the inner script and target URL/IP.
2. Inspect DNS logs for outbound domains queried during the execution window.
3. Block external IP addresses and domain indicators on perimeter firewalls.
4. Quarantine downloadable payload files (`.ps1`, `.vbs`, `.exe`).
"""
    },
    {
        "title": "Outbound Command and Control (C2) TLS Beaconing Playbook",
        "category": "playbook",
        "source_ref": "ATT&CK-T1071.001-Playbook",
        "content": """# Outbound C2 Beaconing Playbook
## 1. Overview
Command and Control (C2) beaconing involves periodic or asynchronous communication between an infected host and external attacker infrastructure using standard application layer protocols such as HTTPS/TLS.

## 2. Detection Criteria
- Regular, repeating connection intervals (heartbeats) to unranked or low-reputation IP addresses.
- Connections using self-signed TLS certificates or mismatched SNI domain names.
- High volume DNS queries for newly registered domains (NRDs).

## 3. Containment Actions
1. Add target IP/domain to perimeter firewall egress blocklist.
2. Isolate internal host from internet gateways.
3. Perform memory analysis on host to locate active DLL injection or beacon process.
"""
    }
]
