# Red ELISAR — Attack Chain Report

**Generated:** 2026-04-28T05:27:43.006811+00:00
**Scenario:** Credential theft and lateral movement in enterprise network.
**Target Environment:** Enterprise Windows Active Directory network
**Faithfulness Score:** 100%

---

## Attack Chain

### Step 1: 

- **Technique ID:** `T1199`
- **Tactic:** initial-access
- **Description:** Establish a trusted relationship with a remote service using a compromised account.
- **Rationale:** 
- **Prerequisites:** 
- **Detection:** 
- **Mitigation:** General Best Practices: Apply defense-in-depth principles: network segmentation, least-privilege access, endpoint detection and response (EDR), security awareness training, regular patching, and monitoring.

### Step 2: 

- **Technique ID:** `T1021`
- **Tactic:** initial-access
- **Description:** Use Remote Services to connect to the compromised account.
- **Rationale:** 
- **Prerequisites:** 
- **Detection:** 
- **Mitigation:** Multi-factor Authentication: Enforce MFA for remote services (SMB, RDP, WinRM). Restrict lateral movement paths using network segmentation and privileged access workstations.
- **Tool Commands:**
  - `psexec.exe \\target -u admin -p password cmd.exe`
  - `crackmapexec smb target -u admin -p password -x 'whoami'`
  - `evil-winrm -i target -u admin -p password`

### Step 3: 

- **Technique ID:** `T1550`
- **Tactic:** initial-access
- **Description:** Use Alternate Authentication Material to bypass MFA on the compromised account.
- **Rationale:** 
- **Prerequisites:** 
- **Detection:** 
- **Mitigation:** General Best Practices: Apply defense-in-depth principles: network segmentation, least-privilege access, endpoint detection and response (EDR), security awareness training, regular patching, and monitoring.

### Step 4: 

- **Technique ID:** `T1078`
- **Tactic:** credential-access
- **Description:** Obtain valid accounts using the compromised account's credentials.
- **Rationale:** 
- **Prerequisites:** 
- **Detection:** 
- **Mitigation:** Multi-factor Authentication: Enforce MFA for all remote access and privileged accounts. Monitor for anomalous login patterns, impossible travel, and credential stuffing.
- **Tool Commands:**
  - `hydra -l admin -P passwords.txt rdp://target`
  - `crackmapexec smb 10.0.0.0/24 -u user -p password`
  - `spray.sh -smb 10.0.0.0/24 user passwords.txt`

### Step 5: 

- **Technique ID:** `T1586`
- **Tactic:** credential-access
- **Description:** Compromise additional accounts using the obtained valid accounts.
- **Rationale:** 
- **Prerequisites:** 
- **Detection:** 
- **Mitigation:** General Best Practices: Apply defense-in-depth principles: network segmentation, least-privilege access, endpoint detection and response (EDR), security awareness training, regular patching, and monitoring.

### Step 6: 

- **Technique ID:** `T1649`
- **Tactic:** credential-access
- **Description:** Steal or forge authentication certificates to gain access to sensitive areas.
- **Rationale:** 
- **Prerequisites:** 
- **Detection:** 
- **Mitigation:** General Best Practices: Apply defense-in-depth principles: network segmentation, least-privilege access, endpoint detection and response (EDR), security awareness training, regular patching, and monitoring.

### Step 7: 

- **Technique ID:** `T1657`
- **Tactic:** impact
- **Description:** Use the compromised accounts to steal financial information.
- **Rationale:** 
- **Prerequisites:** 
- **Detection:** 
- **Mitigation:** General Best Practices: Apply defense-in-depth principles: network segmentation, least-privilege access, endpoint detection and response (EDR), security awareness training, regular patching, and monitoring.

### Step 8: 

- **Technique ID:** `T1199`
- **Tactic:** persistence
- **Description:** Establish a trusted relationship with a remote service using a compromised account to maintain persistence.
- **Rationale:** 
- **Prerequisites:** 
- **Detection:** 
- **Mitigation:** General Best Practices: Apply defense-in-depth principles: network segmentation, least-privilege access, endpoint detection and response (EDR), security awareness training, regular patching, and monitoring.

### Step 9: 

- **Technique ID:** `T1078`
- **Tactic:** persistence
- **Description:** Use the compromised accounts to maintain access to sensitive areas.
- **Rationale:** 
- **Prerequisites:** 
- **Detection:** 
- **Mitigation:** Multi-factor Authentication: Enforce MFA for all remote access and privileged accounts. Monitor for anomalous login patterns, impossible travel, and credential stuffing.
- **Tool Commands:**
  - `hydra -l admin -P passwords.txt rdp://target`
  - `crackmapexec smb 10.0.0.0/24 -u user -p password`
  - `spray.sh -smb 10.0.0.0/24 user passwords.txt`

### Step 10: 

- **Technique ID:** `T1550`
- **Tactic:** persistence
- **Description:** Use Alternate Authentication Material to maintain access to the compromised accounts.
- **Rationale:** 
- **Prerequisites:** 
- **Detection:** 
- **Mitigation:** General Best Practices: Apply defense-in-depth principles: network segmentation, least-privilege access, endpoint detection and response (EDR), security awareness training, regular patching, and monitoring.

### Step 11: 

- **Technique ID:** `T1021`
- **Tactic:** command-and-control
- **Description:** Use Remote Services to maintain command and control over the compromised accounts.
- **Rationale:** 
- **Prerequisites:** 
- **Detection:** 
- **Mitigation:** Multi-factor Authentication: Enforce MFA for remote services (SMB, RDP, WinRM). Restrict lateral movement paths using network segmentation and privileged access workstations.
- **Tool Commands:**
  - `psexec.exe \\target -u admin -p password cmd.exe`
  - `crackmapexec smb target -u admin -p password -x 'whoami'`
  - `evil-winrm -i target -u admin -p password`

### Step 12: 

- **Technique ID:** `T1657`
- **Tactic:** impact
- **Description:** Continue to steal financial information using the compromised accounts.
- **Rationale:** 
- **Prerequisites:** 
- **Detection:** 
- **Mitigation:** General Best Practices: Apply defense-in-depth principles: network segmentation, least-privilege access, endpoint detection and response (EDR), security awareness training, regular patching, and monitoring.

---

## Retrieved Techniques (Context)

| Technique ID | Name | Relevance Score | Tactics |
|:---|:---|:---|:---|
| `T1586` | Compromise Accounts | 0.4575 | resource-development |
| `T1199` | Trusted Relationship | 0.5258 | initial-access |
| `T1078.003` | Local Accounts | 0.5047 | defense-evasion,  persistence,  privilege-escalation,  initial-access |
| `T1078` | Valid Accounts | 0.4935 | defense-evasion,  persistence,  privilege-escalation,  initial-access |
| `T1550` | Use Alternate Authentication Material | 0.4525 | defense-evasion,  lateral-movement |
| `T1649` | Steal or Forge Authentication Certificates | 0.5035 | credential-access |
| `T1021` | Remote Services | 0.4482 | lateral-movement |
| `T1657` | Financial Theft | 0.4529 | impact |

---

## Performance Metrics

- **Total Pipeline Latency:** 10.86s
- **Retrieval Latency:** 8342ms
- **LLM Generation Latency:** 2.45s
- **Tokens/Second:** 482.6

## Analysis

- **Tactical Coverage:** 36% (5 / 14 tactics)
- **Unique Techniques:** 7
- **Detection Coverage:** 0%
- **Hallucinated Steps:** 0

---

*Generated by Red ELISAR — Privacy-Preserving Autonomous Offensive Security Agent*