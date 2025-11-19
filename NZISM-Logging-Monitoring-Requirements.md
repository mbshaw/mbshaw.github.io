# NZISM Logging and Monitoring Compliance Requirements

**Document Version:** 1.0
**Date:** 2025-10-13
**NZISM Version:** 3.9 (Current)
**Reference Section:** 16.6 Event Monitoring, Logging and Auditing

## Executive Summary

This document outlines the logging and monitoring compliance requirements from the New Zealand Information Security Manual (NZISM) for a solution architecture comprising:
- **SaaS Products:** Salesforce, Mulesoft, Adobe Experience Manager
- **Identity Management:** Microsoft Entra ID
- **Central Logging Platform:** Azure (Defender for Cloud, Sentinel, Azure Monitor)

---

## NZISM Compliance Framework

### Requirement Levels
- **MUST/MUST NOT:** Essential controls that cannot be effectively risk-managed without jeopardizing information assurance
- **SHOULD/SHOULD NOT:** Controls that may be risk-managed by agencies with documented risk assessment

---

## 1. Azure Central Logging Platform

### 1.1 Microsoft Sentinel (SIEM)

#### Core Requirements
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| CID:2013 | Maintain system management logs | SHOULD | Enable Sentinel data connectors for all systems | Verify data connectors configured for all systems; Review data ingestion logs |
| CID:2013 | Log additional events | SHOULD | Configure custom log ingestion for SaaS products | Confirm custom log sources present in Sentinel; Test log flow from each SaaS product |
| CID:7496 | Enable logging and alerting in public cloud | MUST | Deploy Sentinel with alerting rules | Verify Sentinel workspace operational; Confirm minimum 10 active alert rules deployed |
| CID:2022 | Protect event logs | MUST | Enable log integrity and immutability features | Verify immutable storage policy configured; Test log deletion prevention |

#### Implementation Actions
- Deploy Microsoft Sentinel workspace in Azure
- Configure data retention policies (recommend minimum 12 months for compliance)
- Enable Sentinel Analytics rules for security event detection
- Implement Logic Apps for automated incident response
- Configure data connectors for:
  - Azure Active Directory (Entra ID)
  - Microsoft Defender for Cloud
  - Azure Activity Logs
  - Custom connectors for SaaS applications

---

### 1.2 Microsoft Defender for Cloud

#### Core Requirements
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| CID:7496 | Enable logging and alerting in public cloud | MUST | Enable Defender for all Azure resources | Verify Defender enabled on all subscriptions; Check Defender plan coverage report |
| N/A | Continuous compliance monitoring | MUST | Enable NZISM regulatory compliance framework | Confirm NZISM framework visible in Defender dashboard; Review compliance score |
| N/A | Security posture management | SHOULD | Enable secure score monitoring | Verify secure score visible; Confirm recommendations are being generated |

#### Implementation Actions
- Enable Microsoft Defender for Cloud on all subscriptions
- Enable the NZISM Regulatory Compliance dashboard
- Configure Defender for Cloud Apps integration
- Enable continuous export to Sentinel
- Configure security alerts and recommendations
- Enable Defender for:
  - Servers
  - App Service
  - Storage
  - Key Vault
  - APIs

---

### 1.3 Azure Monitor and Log Analytics

#### Core Requirements
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| CID:1998 | Maintain system management logs | SHOULD | Configure diagnostic settings for all Azure resources | Audit all Azure resources for diagnostic settings; Verify logs flowing to Log Analytics |
| CID:2022 | Protect event logs | MUST | Enable log immutability and access controls | Review RBAC assignments for log workspace; Test unauthorized access is denied |
| CID:2082 | Encrypt logs | MUST | Enable encryption at rest and in transit | Verify TLS 1.2+ enforced; Confirm storage encryption enabled on Log Analytics workspace |

#### Implementation Actions
- Create centralized Log Analytics workspace
- Configure diagnostic settings for all Azure resources
- Enable resource logs for:
  - Virtual networks
  - Network security groups
  - Azure Key Vault
  - Azure Storage
  - API Management
- Configure log retention (minimum 90 days operational, 12 months for compliance)
- Enable Azure Monitor Alerts
- Implement log query access controls

---

## 2. Microsoft Entra ID (Azure Active Directory)

### 2.1 Identity and Access Logging

#### Core Requirements
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| CID:6860 | Monitor privileged access management logs | MUST | Enable Entra ID audit logs and sign-in logs | Query Sentinel for PIM activation logs; Verify privileged sign-ins are logged |
| CID:2013 | Log additional events | SHOULD | Enable detailed sign-in diagnostics | Review sign-in logs for detailed attributes; Confirm location, device, app info captured |
| N/A | Conditional Access logging | MUST | Log all Conditional Access decisions | Query for CA policy evaluations; Verify both success and failure results logged |
| N/A | MFA authentication events | MUST | Log all MFA challenges and results | Search for MFA events in sign-in logs; Verify method and result captured |

#### Events to Log (Minimum Requirements)
- User sign-in activities (successful and failed)
- Multi-factor authentication events
- Password reset and change events
- Privileged role activations (PIM)
- Conditional Access policy evaluations
- Service principal and application authentications
- Directory changes (user/group/app modifications)
- Consent grant operations
- Token issuance events

#### Implementation Actions
- Enable Entra ID Premium P2 for advanced logging
- Configure audit logs streaming to Sentinel
- Enable sign-in logs diagnostic settings
- Export logs to Log Analytics workspace
- Configure Entra ID Connect Health monitoring
- Enable Privileged Identity Management (PIM) logging
- Implement Entra ID Identity Protection logging
- Configure log retention: 30 days in Entra ID, long-term in Sentinel

---

## 3. Salesforce

### 3.1 Application and Security Logging

#### Core Requirements
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| CID:2013 | Maintain system management logs | SHOULD | Enable Event Monitoring and Shield Event Monitoring | Verify Event Monitoring license active; Check EventLogFile objects are generated daily |
| CID:7496 | Enable logging and alerting in public cloud | MUST | Configure real-time event monitoring | Confirm Platform Events or Streaming API enabled; Test real-time delivery to Azure |
| CID:2022 | Protect event logs | MUST | Enable Event Log File retention and archival | Verify Event Log Files archived to Azure; Check 12-month retention policy configured |

#### Events to Log (Minimum Requirements)
- Login events (successful and failed)
- Logout events
- URI (page view) events
- Report export events
- API call events
- Apex trigger events
- Permission set assignments
- Data export events
- Setup audit trail changes
- File download events
- Transaction security policy events

#### Implementation Actions
- Enable Salesforce Event Monitoring (requires Event Monitoring add-on)
- Configure Event Log File storage
- Implement EventLogFile API integration with Azure Sentinel
- Use Salesforce Shield for enhanced logging (if available)
- Configure Transaction Security policies
- Set up Setup Audit Trail monitoring (retain 6-12 months)
- Implement real-time event streaming to Azure Event Hub
- Configure log forwarding using:
  - Salesforce Event Monitoring API
  - Platform Events
  - Custom Azure Function for log ingestion

#### Integration with Azure
```
Salesforce → Event Monitoring API → Azure Function → Azure Event Hub → Sentinel
```

---

## 4. MuleSoft Anypoint Platform

### 4.1 API and Integration Logging

#### Core Requirements
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| CID:2013 | Log API events | SHOULD | Enable API Manager audit logging | Verify API Manager audit events in Anypoint; Check policy changes are logged |
| CID:7496 | Enable logging and alerting in public cloud | MUST | Configure CloudHub logging and monitoring | Confirm logs flowing from CloudHub to Azure; Test alert generation on errors |
| CID:2022 | Protect event logs | MUST | Secure log transmission and storage | Verify HTTPS/TLS for log transmission; Confirm logs encrypted in Azure Storage |

#### Events to Log (Minimum Requirements)
- API request and response logs
- Policy violation events
- Runtime application logs
- Access management events (user login/logout)
- API contract changes
- Deployment events
- Runtime fabric events
- Data gateway transactions
- Integration flow executions
- Error and exception events

#### Implementation Actions
- Enable MuleSoft Anypoint Monitoring
- Configure API Manager audit logging
- Enable Runtime Manager application logs
- Set up CloudHub log forwarding
- Implement custom log4j2 configuration for detailed logging
- Configure log levels per environment:
  - Production: WARN or ERROR
  - Non-Production: INFO or DEBUG
- Forward logs to Azure using:
  - HTTP Event Collector to Azure Log Analytics
  - Azure Log Analytics agent on Runtime Fabric
  - Custom logging policy in API Manager
- Enable Anypoint Visualizer for dependency tracking

#### Integration with Azure
```
MuleSoft CloudHub → Log4j2 HTTP Appender → Azure Log Analytics → Sentinel
MuleSoft Runtime Fabric → Azure Monitor Agent → Log Analytics → Sentinel
```

---

## 5. Adobe Experience Manager (AEM)

### 5.1 Content Management and Security Logging

#### Core Requirements
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| CID:2013 | Maintain system management logs | SHOULD | Enable AEM audit logging | Verify audit.log contains authentication and content events; Check log rotation configured |
| CID:7496 | Enable logging and alerting | MUST | Configure AEM as a Cloud Service logging | Confirm Cloud Manager API integration active; Verify logs accessible in Azure |
| CID:2022 | Protect event logs | MUST | Secure log access and transmission | Verify log access restricted via RBAC; Confirm TLS for log forwarding |

#### Events to Log (Minimum Requirements)
- User authentication events (successful and failed logins)
- Content creation, modification, and deletion
- Asset upload and download events
- Page activation/deactivation (publishing)
- Replication events
- Workflow events
- Package installations
- Configuration changes (OSGi configurations)
- User and group management changes
- Access control (ACL) modifications
- Dispatcher cache invalidations
- Error logs (application errors)

#### Implementation Actions for AEM as a Cloud Service
- Enable AEM Cloud Service audit logs
- Configure log forwarding from Cloud Manager
- Access logs via:
  - Cloud Manager API
  - Adobe I/O Events
  - Log forwarding to splunk/SIEM
- Implement custom audit framework for business events
- Configure Apache/Dispatcher access logs
- Enable request logging with appropriate detail level

#### Implementation Actions for AEM On-Premise/Managed Services
- Enable AEM audit.log
- Configure custom AuditLogSearchServlet
- Implement Sling Authentication logging
- Configure Oak audit logging
- Set up log rotation policies
- Forward logs to Azure using:
  - Azure Log Analytics agent (Linux/Windows)
  - Logstash or Fluentd to Azure Event Hub
  - Custom servlet to push logs to Azure

#### Integration with Azure
```
AEM Cloud Service → Cloud Manager API → Azure Function → Log Analytics → Sentinel
AEM On-Premise → Azure Monitor Agent → Log Analytics → Sentinel
```

---

## 6. Cross-System Requirements

### 6.1 Additional Logging Requirements

#### 6.1.1 Multifunction Devices and Network Printers
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 11.8.13.C.01 [CID:7537] | Use of MFDs for printing, scanning, and copying purposes SHOULD be centrally logged | SHOULD (TS/S/C) | Configure MFD/printer logging to central syslog server; Forward printer logs to Azure Monitor via Log Analytics agent | Verify printer device logs in Sentinel; Review print job audit trail; Test log retention compliance |

#### 6.1.2 Data Transfer Logging
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 13.3.9.C.01 [CID:4111] | Data transfers between systems of different classification SHOULD be logged in an auditable log or register | SHOULD (All) | Implement Azure Purview data lineage; Log file transfers via Azure Storage account analytics; Maintain data transfer register | Verify data transfer logs captured; Review transfer register completeness; Test log tamper-protection |
| 20.1.10.C.02 [CID:4168] | Agencies importing data to a system MUST log each import event and monitor to detect overuse/unusual usage patterns | MUST (TS/S/C) | Enable Azure Monitor for bulk data imports; Configure Azure Sentinel analytics rules for import anomalies; Log all import events with user, timestamp, data volume | Verify import events logged; Test anomaly detection rules; Review monitoring alerts for unusual patterns |
| 20.1.11.C.01 [CID:4239] | Agencies exporting formatted textual data MUST log each export event and monitor to detect overuse/unusual usage patterns | MUST (TS/S/C) | Enable DLP policies for data export monitoring; Log export events to Sentinel; Configure usage pattern analytics | Verify export events logged; Test usage pattern detection; Review alert thresholds for overuse |
| 20.1.12.C.01 [CID:4245] | Agencies exporting other data MUST log each event and monitor to detect overuse/unusual usage patterns | MUST (TS/S/C) | Implement comprehensive DLP logging; Enable Microsoft Purview Audit; Monitor blob storage and file share exports | Verify all export types logged; Test pattern analysis; Review export volume baselines |

#### 6.1.3 Gateway and Cross Domain Solution Logging
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 19.1.12.C.01 [CID:3562] | Agencies MUST ensure gateways provide sufficient logging and audit capabilities to detect information security incidents, attempted intrusions or anomalous usage patterns; and provide real-time alerts | MUST (All) | Enable Azure Firewall logging; Configure NSG flow logs; Implement Azure Application Gateway WAF logs; Enable real-time alerting via Sentinel | Verify gateway logs comprehensive; Test intrusion detection alerts; Review anomaly detection rules; Confirm real-time alerting operational |
| 19.1.13.C.01 [CID:3578] | Gateways connecting networks in different security domains MUST include firewall configured to log network traffic; be configured to save event logs to separate, secure log server | MUST (All) | Configure Azure Firewall to log to dedicated Log Analytics workspace; Enable immutable storage for gateway logs; Implement separate RBAC for gateway log access | Verify firewall logging enabled; Test log delivery to secure server; Confirm log segregation; Review access controls |
| 19.2.20.C.01 [CID:3936] | All data exported from a security domain MUST be logged | MUST (TS/S/C) | Implement cross-domain data transfer logging; Enable comprehensive export tracking; Maintain audit register of all domain exports | Verify all domain exports logged; Review export register; Test log completeness for cross-domain transfers |
| 20.2.6.C.02 [CID:4281] | When agencies import data through gateways, full or partial audits of event logs MUST be performed at least monthly | MUST (TS/S/C) | Schedule monthly gateway import log reviews; Implement automated log analysis; Document audit findings and remediation | Review monthly audit schedule; Verify audit completion records; Check findings documentation; Confirm remediation tracking |
| 20.2.8.C.01 [CID:4289] | Export of highly formatted textual data through gateways MUST implement full or partial audits of event logs performed at least monthly | MUST (TS/S/C) | Automate gateway export log reviews; Generate monthly audit reports; Track audit completion and exceptions | Verify monthly audit reports; Review audit methodology; Confirm exception handling process |
| 20.2.9.C.02 [CID:4293] | If complete monthly audits not performed, MUST perform randomly timed audits of random subsets of data transfer logs on weekly basis | MUST (TS/S/C) | Implement random audit scheduling; Automate random log sampling; Document weekly audit execution | Verify random audit execution; Review sampling methodology; Confirm weekly schedule compliance |
| 20.3.15.C.02 [CID:4421] | When importing data through gateways, agencies MUST audit complete data transfer logs at least monthly | MUST (TS/S/C) | Schedule comprehensive monthly import log audits; Generate audit reports; Track remediation actions | Review monthly audit completion; Verify report generation; Confirm findings addressed |

#### 6.1.4 Privileged Access Management Logging
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 16.1.28.C.01 [CID:1837] | If agencies allow shared, non user-specific accounts they MUST ensure independent means of determining system user identification is implemented and logged | MUST (All) | Avoid shared accounts where possible; If required, implement session recording and attribute access to individuals; Log all shared account activity with user attribution | Verify shared account inventory; Review identification mechanism; Test individual attribution; Confirm comprehensive logging |
| 16.1.42.C.01 [CID:1892] | Agencies MUST record all successful and failed logon attempts | MUST (All) | Enable Entra ID sign-in logs; Configure log retention; Monitor for anomalous patterns | Verify all logon attempts logged; Test log completeness; Review retention compliance |
| 16.4.41.C.01 [CID:6859] | Agencies MUST create, implement and maintain robust system of continuous discovery, monitoring and review of privileged accounts and access rights and credentials | MUST (All) | Implement Entra ID Privileged Identity Management; Enable continuous access reviews; Configure privileged account monitoring | Verify PIM operational; Review access review schedule; Test privileged account discovery; Confirm continuous monitoring |
| 16.4.41.C.02 [CID:6860] | Privileged account monitoring systems MUST monitor and record: individual user activity including out of hours access; activity from unauthorised sources; unusual use patterns; any creation of unauthorised privileges access credentials | MUST (All) | Configure PIM alerting for all privileged activities; Enable UEBA for privileged accounts; Implement out-of-hours alerting; Monitor credential creation | Verify comprehensive privileged activity logging; Test out-of-hours alerts; Review unusual pattern detection; Confirm credential creation monitoring |
| 16.4.41.C.03 [CID:6861] | Agencies MUST protect and limit access to activity and audit logs and records | MUST (All) | Implement strict RBAC for log access; Enable log access auditing; Configure immutable log storage | Verify log access controls; Test unauthorized access prevention; Review log access audit trail |
| 16.5.11.C.01 [CID:1977] | Agencies MUST NOT allow remote privileged access from untrusted domain, including logging in as unprivileged user then escalating privileges | MUST NOT (TS/S/C) | Implement Conditional Access policies blocking untrusted remote privileged access; Enable monitoring for privilege escalation; Alert on policy violations | Verify CA policies block untrusted access; Test privilege escalation detection; Review violation logs |
| 16.7.42.C.07 [CID:6952] | Design of agency MFA SHOULD include: logging, monitoring and reporting of activity; review of logs for orphaned accounts and inappropriate user access including unsuccessful authentication | SHOULD (All) | Enable comprehensive MFA logging; Implement automated orphaned account detection; Monitor failed MFA attempts | Verify MFA activity logging; Test orphaned account detection; Review failed authentication monitoring; Confirm log review schedule |

#### 6.1.5 Web Application and Email Logging
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 14.3.6.C.02 [CID:1593] | Agency Web proxy SHOULD authenticate system users and provide logging including: URL, time/date, system user, internal IP address, external IP address | SHOULD (All) | Configure Azure Application Gateway or third-party proxy with authentication; Enable comprehensive web access logging; Forward logs to Sentinel | Verify proxy authentication enabled; Review log completeness (all required fields); Test log forwarding; Confirm user attribution |
| 15.2.40.C.02 [CID:1761] | Agencies SHOULD configure systems to log every occurrence of blocked email | SHOULD (All) | Enable Exchange Online Protection logging; Configure Microsoft Defender for Office 365 logging; Log all email blocks | Verify blocked email logging; Review block reason capture; Test log completeness |
| 15.2.41.C.01 [CID:1764] | Agencies MUST configure email systems to reject, log and report inbound emails with protective markings indicating content exceeds accreditation of receiving system | MUST (All) | Implement protective marking detection in email gateway; Configure automated rejection and logging; Enable real-time reporting | Verify protective marking detection; Test email rejection; Review logging and reporting; Confirm real-time alerts |

#### 6.1.6 Network Security and Intrusion Detection Logging
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 18.3.19.C.01 [CID:3785] | Denial of Service response plan SHOULD include monitoring and use of: router and switch logging and flow data; packet captures; proxy and call manager logs; firewall logs | SHOULD (All) | Enable NSG flow logs; Configure Azure DDoS Protection logging; Implement packet capture capability; Log firewall and proxy activity | Verify network device logging; Review DDoS monitoring; Test packet capture; Confirm DoS detection capabilities |
| 18.4.7.C.01 [CID:3802] | Agencies MUST develop IDS/IPS strategy including: audit analysis of event logs including IDS/IPS logs; capability to detect incidents and attempted network intrusions on gateways with real-time alerts | MUST (TS/S/C) | Deploy Microsoft Defender for Endpoint with network protection; Enable Azure Firewall threat intelligence; Configure Sentinel IDS/IPS log analysis; Implement real-time alerting | Verify IDS/IPS operational; Test intrusion detection; Review audit analysis automation; Confirm real-time alerts functional |
| 18.4.7.C.02 [CID:3803] | Agencies SHOULD develop IDS/IPS strategy including: audit analysis of event logs including IDS/IPS logs | SHOULD (All) | Implement network intrusion detection; Enable automated log analysis; Configure detection rules | Verify IDS/IPS logs ingested; Test log analysis automation; Review detection rule coverage |
| 18.4.11.C.01 [CID:3857] | IDS/IPSs inside firewall SHOULD generate log entry and alert for information flows that contravene firewall rule set | SHOULD (All) | Configure Azure Firewall to alert on policy violations; Enable NSG diagnostic logging; Implement rule violation detection | Verify violation logging; Test alert generation; Review rule compliance monitoring |
| 18.4.12.C.01 [CID:3875] | Agencies SHOULD deploy tools for: management and archive of security event information; correlation of suspicious events across all agency networks | SHOULD (All) | Deploy Azure Sentinel as SIEM; Enable cross-network event correlation; Implement automated archive to blob storage | Verify Sentinel operational; Test cross-network correlation; Review archive retention; Confirm event management procedures |
| 18.5.8.C.04 [CID:3965] | Dynamically assigned IPv6 addresses SHOULD be configured with DHCPv6 in stateful manner with lease information logged and stored in centralised logging facility | SHOULD (All) | Enable IPv6 DHCP logging; Forward to central log repository; Maintain lease history | Verify IPv6 DHCP logging; Review lease tracking; Confirm central storage |

#### 6.1.7 Database and Application Logging
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 20.4.5.C.01 [CID:4444] | Agencies MUST enable logging and auditing of system users' actions | MUST (TS) | Enable Azure SQL Database auditing; Configure Cosmos DB diagnostic logs; Implement application-level user activity logging | Verify database audit logs enabled; Test user action tracking; Review log completeness; Confirm user attribution |
| 21.4.11.C.12 [CID:4666] | BYOD MUST have MDM solution with auditing and logging enabled | MUST (All) | Deploy Microsoft Intune for BYOD; Enable comprehensive device activity logging; Log policy compliance and violations | Verify Intune logging enabled; Review device activity logs; Test compliance tracking; Confirm violation alerts |

#### 6.1.8 System Management and Configuration Logging
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 14.1.8.C.01 [CID:1149] | Hardened SOE SHOULD include: configuration of remote logging or transfer of local event logs to central server; protection of audit logs through one-way pipe | SHOULD (All) | Configure Azure Monitor agent on all systems; Enable log forwarding to Log Analytics; Implement write-once storage for critical logs | Verify all systems forward logs centrally; Test log forwarding reliability; Review log protection mechanisms; Confirm one-way transmission |
| 16.6.6.C.01 [CID:1997] | Agencies MUST maintain system management logs for life of system | MUST (TS) | Configure indefinite retention for system management logs; Archive to immutable storage; Document log retention policy | Verify system management logs retained; Review retention period; Confirm archive processes; Test log retrieval |
| 16.6.6.C.02 [CID:1998] | Agencies SHOULD determine policy for retention of system management logs | SHOULD (All) | Document log retention policy; Define retention periods by log type and classification; Implement automated retention management | Review retention policy documentation; Verify retention periods defined; Confirm policy implementation; Test retention automation |
| 16.6.7.C.01 [CID:2001] | System management log SHOULD record: system start-up and shutdown; system changes; user changes; failures; maintenance activities; backup activities; recovery activities; special or out of hours activities | SHOULD (All) | Enable comprehensive Azure Monitor system logs; Configure Azure Activity Log retention; Log all system events listed | Verify all required events logged; Review log content completeness; Test event capture; Confirm out-of-hours flagging |
| 16.6.15.C.01 [CID:7560] | Agencies SHOULD have monitoring solution implemented that enables detection of incidents as they occur so appropriate responses can be taken in adequate timeframes | SHOULD (All) | Deploy Azure Sentinel with real-time analytics; Enable automated response playbooks; Implement incident response automation | Verify real-time monitoring operational; Test incident detection speed; Review response timeframes; Confirm automation functional |
| 16.6.15.C.02 [CID:7561] | Agencies SHOULD have systems for processing system event logs to identify and correlate events indicating behavioural anomalies or potential security compromise in near real-time | SHOULD (All) | Enable Azure Sentinel UEBA; Configure behavioral analytics; Implement anomaly detection rules; Enable real-time correlation | Verify UEBA operational; Test anomaly detection; Review correlation rules; Confirm near real-time processing |

#### 6.1.9 Physical and Personnel Security Logging
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 8.2.7.C.01 [CID:1357] | Site Security Plan MUST include: regular inspection of generated audit trails and logs | MUST (All) | Integrate physical access logs with Azure Sentinel; Schedule regular log reviews; Document inspection procedures | Verify physical access log integration; Review inspection schedule; Confirm documentation; Test log analysis |
| 9.4.10.C.01 [CID:1589] | Agencies with TOP SECRET area MUST maintain separate log from general visitor log | MUST (TS) | Implement segregated visitor logging system; Restrict access to TS visitor logs; Maintain separate retention | Verify separate TS visitor log; Review access controls; Confirm segregation; Test retrieval procedures |

#### 6.1.10 VoIP and Unified Communications Logging
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 19.5.27.C.02 [CID:4738] | Protected communication channel for administrators MUST be logged | MUST (All) | Enable Teams admin activity logging; Log all privileged communication access; Monitor administrative channels | Verify admin channel logging; Review log completeness; Test privileged access tracking |
| 19.5.27.C.06 [CID:4742] | Event logs covering all VoIP and UC services SHOULD be maintained per NZISM sections 16.6 and 13.1.12 | SHOULD (All) | Enable Microsoft Teams audit logging; Configure call detail records; Maintain logs per retention requirements | Verify Teams comprehensive logging; Review CDR capture; Confirm retention compliance |

#### 6.1.11 Secure Shell (SSH) Configuration
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 17.5.6.C.01 [CID:2647] | SSH settings SHOULD include login banner configuration (logging related aspects) | SHOULD (All) | Configure SSH with login banner; Enable SSH session logging; Log all SSH authentication attempts | Verify SSH login banner; Review SSH logs; Test authentication logging; Confirm session tracking |

#### 6.1.12 SOPs and Documentation Requirements
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 5.5.4.C.01 [CID:849] | ITSM SOPs SHOULD document audit log review procedures, particularly for privileged users | SHOULD (All) | Document audit log review procedures in SOPs; Define review frequency and scope; Assign responsibilities | Review SOP documentation; Verify review procedures defined; Confirm privileged user log review schedule; Test procedure compliance |
| 5.5.5.C.01 [CID:865] | System Administrator SOPs SHOULD document system backup and recovery procedures including backing up audit logs | SHOULD (All) | Document audit log backup procedures; Define recovery processes; Test backup restoration | Review SOP documentation; Verify backup procedures defined; Test audit log restoration; Confirm recovery capabilities |

#### 6.1.13 Accreditation and Cloud Adoption
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| 2.2.5.C.01 [CID:216] | Third party review report utilising ISAE 3402 covering logging controls | MUST (All) | Obtain ISAE 3402/SOC 2 reports from cloud providers; Review logging control coverage; Assess control effectiveness | Review ISAE 3402/SOC 2 reports; Verify logging controls included; Confirm control testing results; Document any gaps |
| 2.3.25.C.02 [CID:7046] | Cloud adoption plan SHOULD cover logging and alerting as foundation service | SHOULD (All) | Document cloud logging strategy; Include logging in adoption plan; Define centralized logging architecture | Review cloud adoption plan; Verify logging strategy documented; Confirm architecture defined; Test implementation |
| 4.4.5.C.04 [CID:602] | Agencies SHOULD ensure information security monitoring, logging and auditing conducted on all accredited systems | SHOULD (All) | Include logging requirements in system accreditation; Verify monitoring operational before accreditation; Test logging compliance | Review accreditation documentation; Verify logging included; Confirm monitoring operational; Test compliance |

### 6.2 Log Retention

| System | Minimum Retention (Operational) | Compliance Retention | Storage Location | Assessment Criteria |
|--------|--------------------------------|---------------------|------------------|---------------------|
| Azure Sentinel | 90 days | 12-24 months | Azure Storage Archive Tier | Query logs older than 90 days from archive; Verify data lifecycle policy configured |
| Entra ID Audit Logs | 30 days (in Entra ID) | 12 months | Azure Sentinel | Check audit log export to Sentinel configured; Query 6-month old logs successfully |
| Salesforce Event Logs | 30 days (in Salesforce) | 12 months | Azure Blob Storage | Verify Event Log Files archived to blob storage; Check 12-month old logs accessible |
| MuleSoft Logs | 30 days (in CloudHub) | 12 months | Azure Log Analytics | Query Log Analytics for logs >30 days old; Verify retention policy set to 365 days |
| AEM Audit Logs | 90 days (in AEM) | 12 months | Azure Blob Storage | Confirm audit logs forwarded daily; Verify 12-month archive in blob storage |

**Note:** NZISM doesn't specify exact retention periods, but common practice for government compliance is 12 months minimum. Consult with your agency's information security team for specific retention requirements.

---

### 6.3 Log Protection and Integrity

#### Core Requirements
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| CID:2022 | Protect event logs | MUST | All systems must protect log integrity | Verify immutable storage configured; Test log modification/deletion is prevented |
| CID:2082 | Encrypt logs | MUST | Encrypt logs at rest and in transit | Confirm TLS 1.2+ enforced on all log connections; Verify storage encryption enabled |

#### Implementation Actions (All Systems)
- Enable encryption in transit (TLS 1.2 or higher)
- Enable encryption at rest for all log storage
- Implement role-based access control (RBAC) for log access
- Enable log file validation and integrity checking where available
- Implement immutable storage for compliance logs
- Configure audit trails for log access and modifications
- Use Azure Private Link for secure log transmission
- Enable Azure Storage immutability policies for archived logs

---

### 6.4 Monitoring and Alerting

#### Core Requirements
| Control ID | Requirement | Compliance Level | Implementation | Assessment Criteria |
|------------|-------------|------------------|----------------|---------------------|
| CID:7496 | Enable alerting in public cloud | MUST | Configure real-time alerting for security events | Verify alert rules cover all critical events; Test alert generation and notification delivery |
| N/A | Continuous monitoring | MUST | Monitor for security events 24/7 | Confirm SOC operational hours or managed service contract; Review incident response logs |

#### Critical Events Requiring Alerts (Minimum)
1. **Authentication Failures**
   - Multiple failed login attempts (5+ in 5 minutes)
   - Failed MFA attempts
   - Impossible travel scenarios

2. **Privileged Access**
   - Privileged role activations
   - Global administrator sign-ins
   - Conditional Access policy changes

3. **Data Access**
   - Mass data downloads
   - Sensitive data access outside business hours
   - Data export events

4. **Configuration Changes**
   - Security policy modifications
   - API policy changes
   - Firewall rule changes

5. **Security Events**
   - Malware detection
   - Brute force attacks
   - Suspicious API usage patterns
   - DDoS attempts

#### Implementation Actions
- Configure Azure Sentinel Analytics Rules for all critical event types
- Create Sentinel Playbooks (Logic Apps) for automated response
- Enable Microsoft Defender for Cloud Apps policies
- Configure Entra ID Identity Protection risk policies
- Set up Azure Monitor Alert Rules
- Implement PagerDuty/ServiceNow integration for incident management
- Configure notification channels (email, SMS, Teams)
- Establish 24/7 SOC monitoring or managed service

---

## 7. Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)
1. Deploy Azure Sentinel workspace
2. Enable Microsoft Defender for Cloud
3. Configure Entra ID log streaming to Sentinel
4. Enable Azure resource diagnostic settings
5. Establish log retention policies

### Phase 2: SaaS Integration (Weeks 5-8)
1. Configure Salesforce Event Monitoring and API integration
2. Set up MuleSoft log forwarding to Azure
3. Implement AEM log collection and forwarding
4. Deploy Azure Functions for custom log ingestion
5. Configure data connectors in Sentinel

### Phase 3: Monitoring and Alerting (Weeks 9-12)
1. Configure Sentinel Analytics Rules
2. Create automated response playbooks
3. Set up alert notification channels
4. Implement dashboard and reporting
5. Enable NZISM compliance tracking in Defender for Cloud

### Phase 4: Optimization and Tuning (Weeks 13-16)
1. Tune alert rules to reduce false positives
2. Optimize log ingestion costs
3. Implement advanced threat hunting queries
4. Conduct compliance audit
5. Document processes and runbooks

---

## 8. Compliance Checklist

### Azure Platform
- [ ] Sentinel workspace deployed
- [ ] NZISM regulatory compliance framework enabled in Defender for Cloud
- [ ] Log Analytics workspace configured with 12-month retention
- [ ] Azure Monitor diagnostic settings enabled for all resources
- [ ] Log encryption enabled (at rest and in transit)
- [ ] Immutable storage configured for compliance logs
- [ ] RBAC implemented for log access

### Entra ID
- [ ] Audit logs streaming to Sentinel
- [ ] Sign-in logs diagnostic settings enabled
- [ ] Privileged Identity Management logging enabled
- [ ] Conditional Access logging configured
- [ ] MFA events logged
- [ ] Identity Protection alerts configured
- [ ] 12-month log retention in Sentinel

### Salesforce
- [ ] Event Monitoring enabled
- [ ] Setup Audit Trail configured
- [ ] Event Log File API integration with Azure
- [ ] Real-time event monitoring configured
- [ ] Login anomaly detection enabled
- [ ] Critical event alerts configured
- [ ] Log retention 12 months in Azure

### MuleSoft
- [ ] Anypoint Monitoring enabled
- [ ] API Manager audit logging configured
- [ ] CloudHub logs forwarding to Azure
- [ ] Runtime application logging enabled
- [ ] Custom log4j2 configuration deployed
- [ ] API policy violation alerts configured
- [ ] Log retention 12 months in Azure

### Adobe Experience Manager
- [ ] AEM audit logs enabled
- [ ] Log forwarding to Azure configured
- [ ] Authentication events logged
- [ ] Content change tracking enabled
- [ ] Configuration change logging enabled
- [ ] Error logs monitored
- [ ] Log retention 12 months in Azure

### Cross-System
- [ ] All logs encrypted in transit (TLS 1.2+)
- [ ] All logs encrypted at rest
- [ ] Log integrity protection enabled
- [ ] Centralized SIEM (Sentinel) operational
- [ ] Real-time alerting for critical events configured
- [ ] Automated incident response playbooks deployed
- [ ] 24/7 monitoring established
- [ ] Compliance reporting dashboard created

---

## 9. Key Considerations

### Cost Management
- Azure Sentinel pricing is based on data ingestion volume ($/GB)
- Implement data sampling for high-volume, low-value logs
- Use Basic logs tier for troubleshooting logs
- Archive logs to Azure Storage for long-term retention (lower cost)
- Set up cost alerts and budgets

### Performance
- Distribute log ingestion across multiple data collection endpoints
- Use workspace-based log collection where possible
- Implement log filtering at source to reduce ingestion volume
- Monitor Sentinel query performance

### Security
- Use Azure Private Link for secure connectivity
- Implement network security groups to restrict log access
- Enable Azure Sentinel User and Entity Behavior Analytics (UEBA)
- Configure Sentinel watchlists for authorized IPs and users
- Implement Conditional Access policies for Sentinel access

### Compliance Documentation
- Maintain risk assessment documentation for any SHOULD controls not implemented
- Document any deviations from MUST controls with compensating controls
- Keep audit trail of compliance reviews
- Retain evidence of log protection measures
- Document incident response procedures

---

## 10. References

1. **NZISM Documentation**
   - NZISM v3.9 (May 2025): https://nzism.gcsb.govt.nz/ism-document
   - NZISM Section 16.6: Event Monitoring, Logging and Auditing
   - NZISM Logging Resources: https://nzism.gcsb.govt.nz/resources/information-security-topics/logging

2. **Microsoft Documentation**
   - NZISM Compliance Guide: https://learn.microsoft.com/en-us/compliance/anz/nzism-guide
   - Azure Sentinel Documentation: https://learn.microsoft.com/en-us/azure/sentinel/
   - Microsoft Defender for Cloud: https://learn.microsoft.com/en-us/azure/defender-for-cloud/

3. **Vendor-Specific Documentation**
   - Salesforce Event Monitoring: https://help.salesforce.com/
   - MuleSoft Anypoint Monitoring: https://docs.mulesoft.com/
   - Adobe Experience Manager Logging: https://experienceleague.adobe.com/

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-10-13 | System Architect | Initial creation based on NZISM v3.9 requirements |

**Review Schedule:** Quarterly or when NZISM is updated

**Approval Required:** Information Security Manager, Solution Architect, Compliance Officer

---

## Appendix A: NZISM Control Reference

### Event Logging and Auditing Controls (Section 16.6)

| CID | Control Summary | Compliance Level | Applicable Systems | Assessment Criteria |
|-----|----------------|------------------|-------------------|---------------------|
| 1998 | Maintain system management logs | SHOULD | All systems | Verify system logs captured from all sources; Review log completeness |
| 2013 | Log additional events | SHOULD | All systems | Confirm security-relevant events logged beyond basic system logs |
| 2022 | Protect event logs | MUST | All systems | Test log integrity protection; Verify access controls |
| 2082 | Encrypt logs | MUST | All systems | Verify encryption at rest and in transit for all log storage |
| 6860 | Monitor privileged access management logs | MUST | Entra ID, Azure | Query for privileged access logs; Confirm monitoring alerts configured |
| 7496 | Enable logging and alerting in public cloud | MUST | All cloud systems | Verify cloud logging enabled; Test alerting functionality |

**Note:** Control IDs (CIDs) are derived from AWS NZISM conformance pack. Consult the official NZISM document for complete control text and context.

---

### Detecting Information Security Incidents (Section 7.1)

| Control Reference | Control Summary | Compliance Level | Applicable Systems | Implementation | Assessment Criteria |
|-------------------|----------------|------------------|-------------------|----------------|---------------------|
| 7.1.7.C.01 [CID:1153] | Develop, implement and maintain tools and procedures covering detection of potential information security incidents, incorporating: user awareness and training; counter-measures against malicious code, known attack methods and types; intrusion detection strategies; data egress monitoring & control; access control anomalies; audit analysis; system integrity checking; and vulnerability assessments | MUST (TS/S/C) | All classified systems | Deploy Azure Sentinel with: IDS/IPS integration (Defender for Endpoint), malware detection (Defender Antivirus), data loss prevention (Purview DLP), UEBA for access anomalies, automated audit analysis, vulnerability scanning (Defender Vulnerability Management) | Verify all detection components operational; Test detection of simulated threats (malware, data exfiltration, access anomaly); Review audit analysis automation; Confirm vulnerability assessment schedule |
| 7.1.7.C.02 [CID:1154] | Develop, implement and maintain tools and procedures covering detection of potential information security incidents, incorporating: user awareness and training; counter-measures against malicious code, known attack methods and types; intrusion detection strategies; dynamic network defence (protective DNS and/or NGFW); data egress monitoring & control; access control anomalies; audit analysis; system integrity checking; and vulnerability assessments | SHOULD (All) | All systems | Implement dynamic network defence with Azure Firewall Premium (NGFW) or Azure DNS Private Resolver with threat intelligence; Enable Defender for Cloud threat detection across all workloads | Verify protective DNS or NGFW deployed; Test threat blocking capabilities; Confirm threat intelligence feeds active; Review blocked threat logs |
| 7.1.7.C.03 [CID:1155] | Use results of security risk assessment to determine appropriate balance of resources allocated to prevention versus resources allocated to detection of information security incidents | SHOULD (All) | All systems | Document security risk assessment informing detection vs prevention resource allocation; Justify monitoring tool selection based on risk assessment | Review risk assessment documentation; Verify resource allocation aligns with identified risks; Confirm high-risk areas have enhanced detection |
| 7.2.21.C.01 [CID:1226] | Agencies that outsource their information technology services and functions MUST ensure that the service provider advises and consults with the agency when an information security incident occurs | MUST (All) | SaaS platforms (Salesforce, MuleSoft, AEM) | Establish SLA requirements for incident notification in vendor contracts; Configure automated incident notifications from vendor platforms to agency SIEM | Review vendor SLAs for incident notification clauses; Test incident notification procedures; Verify incident escalation paths documented |
| 7.3.11.C.01 [CID:1297] | Transfer copy of raw audit trails and other relevant data onto media for secure archiving; ensure personnel involved in investigation maintain record of actions undertaken to support investigation | SHOULD (All) | All systems | Configure Azure Sentinel log export to immutable blob storage; Implement investigation case management system for tracking forensic activities | Verify log archival to immutable storage; Test log export and retrieval for investigation; Review investigation tracking procedures and records |

**Implementation Guidance:**
- Deploy Azure Sentinel with UEBA (User and Entity Behavior Analytics)
- Enable Microsoft Defender for Cloud threat detection across all subscriptions
- Configure Entra ID Identity Protection for identity-based threats
- Implement Microsoft Defender for Endpoint for host-based IDS/IPS
- Deploy Azure Firewall Premium for NGFW and threat intelligence filtering
- Enable Microsoft Purview Data Loss Prevention for data egress monitoring
- Configure Azure Monitor for system integrity and configuration monitoring
- Implement threat intelligence feeds in Sentinel (Microsoft Defender TI)
- Establish security awareness training program with incident reporting procedures
- Create automated response playbooks for common detection scenarios
- Conduct regular threat hunting activities using Sentinel hunting queries
- Enable Defender Vulnerability Management for continuous vulnerability assessment
- Configure immutable blob storage for forensic log retention
- Establish case management procedures for incident investigation

---

### Logging and Alerting in Public Cloud (Section 23.5)

| Control Reference | Control Summary | Compliance Level | Applicable Systems | Implementation | Assessment Criteria |
|-------------------|----------------|------------------|-------------------|----------------|---------------------|
| 23.5.10.C.01 [CID:7494] | Agencies MUST understand the range of logging capabilities provided by their cloud service providers and determine whether they are sufficient for agency needs | MUST (All) | Azure, Salesforce, MuleSoft, AEM | Document logging capabilities assessment for each cloud provider; Create gap analysis for insufficient capabilities; Implement supplementary logging where native capabilities inadequate | Review logging capability assessment documentation; Verify gap analysis completed; Confirm supplementary logging deployed where needed; Test log coverage meets agency requirements |
| 23.5.11.C.01 [CID:7496] | Agencies MUST ensure that logs associated with public cloud services are collected, protected, and that their integrity can be confirmed in accordance with the agency's documented logging requirements | MUST (All) | Azure, Salesforce, MuleSoft, AEM | Enable comprehensive diagnostic settings for all Azure resources; Configure SaaS application logging with integrity protection; Implement immutable storage for log retention; Enable log signing/hashing for integrity verification | Verify all cloud resources have diagnostic settings enabled; Test log immutability protections; Confirm log integrity verification mechanisms operational; Review log collection completeness report |
| 23.5.12.C.01 [CID:7498] | Agencies MUST ensure that cloud service provider logs are incorporated into overall enterprise logging and alerting systems or procedures in a timely manner to detect information security incidents | MUST (All) | Azure Sentinel, all cloud services | Configure real-time log streaming from all cloud services to Azure Sentinel; Implement data connectors with <15 minute latency; Enable correlation rules across cloud and on-premises logs | Verify log ingestion latency <15 minutes; Test cross-cloud log correlation; Confirm incident detection rules operational; Review alert response times |
| 23.5.12.C.02 [CID:7499] | Agencies SHOULD ensure that tools and procedures used to detect potential information security incidents account for the public cloud services being consumed by the agency | SHOULD (All) | Azure Sentinel, Defender for Cloud | Configure cloud-specific detection rules (e.g., impossible travel, anonymous proxy access, cloud admin activity); Enable UEBA for cloud identities; Implement workload-specific threat detection | Verify cloud-specific detection rules deployed; Test detection of cloud-specific threats (crypto-mining, cloud resource abuse); Review coverage of cloud attack techniques (MITRE ATT&CK for Cloud) |

**Implementation Guidance:**
- Enable Azure Monitor diagnostic settings for all resource types
- Configure Azure Sentinel data connectors for all cloud services
- Implement Azure Storage immutability policies for compliance logs
- Enable Azure Private Link for secure log transmission
- Configure Defender for Cloud Apps for SaaS security monitoring
- Establish baseline logging for all API endpoints
- Create centralized logging dashboard for cloud resources

**Cloud-Specific Logging Requirements:**

| Service Category | Minimum Logging Requirements | NZISM Control Reference |
|------------------|------------------------------|------------------------|
| API Gateway | Request/response logs, policy violations, throttling events | 23.5.11.C.01 [CID:7496] |
| Databases | Connection attempts, query execution, privilege changes, data access | 23.5.11.C.01 [CID:7496] |
| Storage | Access logs, data modifications, permission changes | 23.5.3.C.01 [CID:7496] |
| Identity Services | Authentication events, authorization decisions, privilege escalations | 16.6.x [CID:6860] |
| Network Services | Traffic logs, firewall decisions, DDoS events, VPN connections | 23.5.3.C.01 [CID:7496] |
| Compute Resources | System logs, security events, configuration changes, patch status | 23.5.3.C.01 [CID:7496] |
| Web Application Firewall | Attack patterns, blocked requests, rule violations | 23.5.11.C.01 [CID:7496] |
| Content Delivery Networks | Access logs, cache behaviors, geographic access patterns | 23.5.3.C.01 [CID:7496] |

**Assessment Evidence Required:**
1. Screenshots of enabled diagnostic settings for all Azure resources
2. Sentinel workbook showing log ingestion from all sources
3. Test results demonstrating log immutability
4. Alert rule documentation with test results
5. Evidence of log retention policies (12+ months)
6. RBAC assignments for log access
7. Encryption certificates for log transmission (TLS 1.2+)
8. Incident detection and response procedure documentation
9. User awareness training records
10. Threat intelligence integration configuration

---

## Appendix B: Log Schema Mapping

### Sample KQL Queries for NZISM Compliance

#### Query: Failed Login Attempts (CID 2013)
```kql
SigninLogs
| where ResultType != "0"
| where TimeGenerated > ago(24h)
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, AppDisplayName
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

#### Query: Privileged Role Activations (CID 6860)
```kql
AuditLogs
| where OperationName == "Add member to role completed (PIM activation)"
| where TimeGenerated > ago(7d)
| project TimeGenerated, Identity, TargetResources, ActivityDisplayName
| order by TimeGenerated desc
```

#### Query: Conditional Access Policy Changes (CID 2013)
```kql
AuditLogs
| where OperationName contains "conditional access policy"
| where TimeGenerated > ago(30d)
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
| order by TimeGenerated desc
```

---

**END OF DOCUMENT**
