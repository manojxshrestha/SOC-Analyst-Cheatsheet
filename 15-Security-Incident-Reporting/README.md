# Security Incident Reporting

## SOC Analyst Cheatsheet - Module 15/15

---

## 0. Overview

> 📌 **Security Incident Reporting** - Learn to accurately identify, categorize, and document security incidents with professionalism.

### Module Description

Tailored to provide a holistic understanding, this Hack The Box Academy module ensures participants are adept at identifying, categorizing, and documenting security incidents with utmost accuracy and professionalism. The module meticulously breaks down the elements of a robust incident report and then presents participants with a real-world incident report, offering practical insights into the application of the concepts discussed.

### Module Summary

Embark on a comprehensive journey into security incident reporting with Hack The Box Academy. This module equips learners with the skills to accurately identify, categorize, and document security incidents, emphasizing real-world applications and best practices.

### Key Takeaways

- Explore the art of identifying and classifying security incidents
- Understand the systematic process of incident documentation
- Perfect communication strategies during incidents
- Dive into the critical components of a detailed incident report
- Analyze a real-world incident report following best practices

### Prerequisites

- Incident Handling Process
- Security Monitoring & SIEM Fundamentals

### Module Classification

- **Difficulty:** Easy
- **Assumes:** Basic knowledge of how Windows operate and common attack principles

### Creators

- sebh24
- dbougioukas

---

## Table of Contents

0. [Overview](#overview)
1. [Introduction](#introduction)
   - 1.1 [Introduction to Security Incident Reporting](#introduction-to-security-incident-reporting)
   - 1.2 [The Incident Reporting Process](#the-incident-reporting-process)
   - 1.3 [Elements of a Proper Incident Report](#elements-of-a-proper-incident-report)
2. [Communications](#communications)
3. [Real-world Incident Report](#real-world-incident-report)
4. [Interview Questions](#interview-questions)
5. [Additional Resources](#additional-resources)

---

## 1. Introduction

### 1.1 Introduction to Security Incident Reporting

In today's landscape, the question isn't whether a security incident will transpire, but rather when it will occur. Enterprises, governmental bodies, and individual users have grown exceedingly dependent on technology, which serves as the cornerstone for the vast majority of our activities.

While this technological advancement has augmented operational efficiency, revenue generation, and output, it has concomitantly escalated the associated risks. These technological platforms have become fertile grounds for malevolent actors, sponsored by both state and non-state entities. A meticulously designed and streamlined incident reporting mechanism is pivotal for any organization's preparedness to counter these emerging threats effectively.

> 📌 Security incident reporting serves as a conduit between the identification and remediation of threats.

**Benefits of Incident Reporting:**

- Facilitates archival of past incidents
- Provides invaluable repository for lessons learned
- Integrated into broader strategy for preempting future threats
- Essential for regulatory compliance (legal departments)
- Risk assessment for executive management
- Financial repercussions evaluation for CFOs

> 📌 Effective incident reporting should strike a balance between granularity and accessibility.

---

### 1.2 Incident Identification and Categorisation

Navigating the labyrinthine array of cybersecurity threats necessitates a methodical approach to identifying and classifying security incidents. This enables rapid allocation of resources and expedites threat mitigation.

#### Identifying Security Incidents

Security incidents can emanate from diverse sources and manifest as detections, anomalies, or deviations from established baselines.

| Source | Description |
|--------|-------------|
| **Security Systems/Tooling** | IDS/IPS, EDR/XDR, SIEM tools, anti-virus alerts, NetFlow data |
| **Human Observations** | Users reporting suspicious activities, unusual emails, abnormal system behavior |
| **Third Party Notifications** | Partners, vendors, or customers informing about vulnerabilities or breaches |

#### Categorising Security Incidents

Upon identification, categorizing incidents facilitates prioritization and resource allocation.

**Examples of Incident Types:**

| Type | Description |
|------|-------------|
| **Malware** | Viruses, worms, ransomware |
| **Phishing** | Fraudulent endeavors to exfiltrate sensitive information via email |
| **DDoS Attacks** | Deliberate attempts to inundate a system or network |
| **Unauthorized Access** | Unauthorized entities gaining access to systems or data |
| **Data Leakage** | Inadvertent exposure of confidential data |
| **Physical Breach** | Unauthorized physical access to secure locations |

**Incident Severity Levels:**

| Severity | Level | Description |
|----------|-------|-------------|
| **Critical** | P1 | Imminent threats jeopardizing core business or sensitive data - immediate intervention required |
| **High** | P2 | Latent threats to business operations - elevated priority |
| **Medium** | P3 | Incidents warranting timely attention but not immediate threat |
| **Low** | P4 | Trivial incidents or routine anomalies |

> 📌 Incidents frequently straddle multiple categories and can dynamically shift as additional intelligence is gathered during analysis.

---

### 1.3 The Incident Reporting Process

A meticulously structured incident reporting process ensures comprehensive documentation and effective response.

#### Key Components of Incident Reporting

1. **Initial Detection** - First indication that something may be wrong
2. **Triage** - Assess nature, scope, and severity of the incident
3. **Investigation** - Deep dive into the what, how, and who
4. **Containment** - Actions taken to prevent further damage
5. **Eradication** - Remove threat from environment
6. **Recovery** - Restore systems to normal operation
7. **Lessons Learned** - Document what happened and how to improve

#### Documentation Requirements

- Timestamp of all activities
- Systems and data affected
- Attack vector and timeline
- Response actions taken
- Evidence preserved
- Communication logs

---

## 2. Communications

### Stakeholder Communication

Effective communication is critical during incident response.

| Stakeholder | Information Needed |
|-------------|---------------------|
| **Technical Team** | Technical details, IOCs, containment actions |
| **Management** | Business impact, resource needs, timeline |
| **Legal/Compliance** | Regulatory requirements, notification obligations |
| **Customers** | Impact to their data/services, remediation steps |
| **Public Relations** | Pre-approved statements, fact-checking |

### Communication Best Practices

- Use clear, non-technical language when communicating with non-technical stakeholders
- Provide regular updates even when there's no new information
- Document all communications
- Establish communication channels in advance
- Have escalation procedures defined

---

## 3. Elements of a Proper Incident Report

The Executive Summary serves as the gateway to the report, designed for a broad audience including non-technical stakeholders. It should provide a succinct overview, key findings, immediate actions, and stakeholder impact. Since many stakeholders may only read this section, it's imperative to nail this section.

### 3.1 Executive Summary

| Section | Description |
|---------|-------------|
| **Incident ID** | Unique identifier for the incident |
| **Incident Overview** | Concise summary of events (initial detection), incident type (ransomware, data breach, etc.), estimated date/time, duration, affected systems/data, status (ongoing/resolved/escalated) |
| **Key Findings** | Salient findings, root cause, CVE exploited, data compromised/exfiltrated |
| **Immediate Actions Taken** | Response measures, system isolation, root cause identification, third-party services engaged |
| **Stakeholder Impact** | Customer downtime, financial ramifications, employee data compromised, proprietary information at risk |

### 3.2 Technical Analysis

The most voluminous part of the incident report - deep technical aspects of the incident.

#### Affected Systems & Data
- All systems potentially/confirmed compromised
- Volume/quantity of exfiltrated data (if ascertainable)

#### Evidence Sources & Analysis
- Evidence scrutinized, results, analytical methodology
- Include screenshots for documentation
- Hash files to ensure evidence integrity (crucial for criminal cases)

#### Indicators of Compromise (IoCs)
- Abnormal outbound traffic
- Unfamiliar processes and scheduled tasks
- Can attribute attack to specific threat groups
- Used for hunting across environment/partner organizations

#### Root Cause Analysis
- Detailed root cause
- Vulnerabilities exploited
- Failure points

#### Technical Timeline
- Reconnaissance → Initial Compromise → C2 Communications → Enumeration → Lateral Movement → Data Access & Exfiltration → Malware Deployment/Process Injection/Persistence → Containment → Eradication → Recovery

#### Nature of the Attack
- Type of attack
- TTPs (Tactics, Techniques, Procedures) employed by attacker

#### Impact Analysis
- Adverse effects on data, operations, reputation
- Systems/processes/data compromised
- Business implications: financial loss, regulatory penalties, reputational damage

### 3.3 Response and Recovery Analysis

#### Immediate Response Actions

**Revocation of Access**
- How compromised accounts/systems identified (tools, methodologies)
- Timeframe of detection and revocation (to the minute)
- Method of revocation (disable accounts, change permissions, alter firewall rules)
- Impact assessment

**Containment Strategy**
- Short-term: isolate affected systems from network
- Long-term: network segmentation, zero-trust architecture
- Effectiveness evaluation

**Eradication Measures**

*Malware Removal*
- Identification procedures (EDR, forensic analysis)
- Removal techniques (tools, manual methods)
- Verification (checksum, heuristic analysis)

*System Patching*
- Vulnerability identification (CVE identifiers)
- Patch management (testing, deployment, verification)
- Fallback procedures

#### Recovery Steps

**Data Restoration**
- Backup validation procedures
- Restoration process (including decryption)
- Data integrity checks

**System Validation**
- Security measures before going live (firewall reconfiguration, IDS updates)
- Operational checks (production readiness)

### 3.4 Post-Incident Actions

#### Monitoring
- Enhanced monitoring plans for ongoing detection
- Tools and technologies for holistic view

#### Lessons Learned
- Gap analysis (what failed and why)
- Recommendations for improvement (prioritized by timeline)
- Future strategy: policy, architecture, personnel training changes

### 3.5 Diagrams

Visual aids to simplify complex incidents:

| Diagram | Purpose |
|---------|---------|
| **Incident Flowchart** | Attack progression from entry to propagation |
| **Affected Systems Map** | Network topology with compromised nodes (color-coded severity) |
| **Attack Vector Diagram** | Attacker's navigation through defenses visually |

### 3.6 Appendices

Supplementary material for comprehensive understanding:

- Log Files
- Network Diagrams (pre and post-incident)
- Forensic Evidence (disk images, memory dumps)
- Code snippets
- Incident Response Checklist
- Communication Records
- Legal/Regulatory Documents (compliance forms, NDAs)
- Glossary and Acronyms

### 3.7 Best Practices

- **Root Cause Analysis**: Always find root cause to prevent future occurrences
- **Community Sharing**: Share non-sensitive details with defender community
- **Regular Updates**: Keep all stakeholders updated throughout
- **External Review**: Consider third-party specialists to validate findings

### 3.8 Conclusion

A meticulously crafted incident report is non-negotiable following a security breach. These reports offer exhaustive analysis of what went wrong, what was effective, why, and future preventive strategies.

---

## 4. Interview Questions

### Q1: What is the primary purpose of security incident reporting?

**Answer:** To document security events in a structured manner that enables proper response, regulatory compliance, and future threat prevention through lessons learned.

---

### Q2: What are the three main sources of incident identification?

**Answer:** Security systems/tooling (IDS/IPS, EDR, SIEM), human observations, and third-party notifications.

---

### Q3: How do you prioritize incident severity?

**Answer:** Using severity levels (P1-Critical to P4-Low) based on business impact, data sensitivity, and threat immediacy.

---

### Q4: What should be included in an incident report?

**Answer:** Executive summary, incident details, technical analysis, response actions, and lessons learned.

---

### Q5: Why is stakeholder communication important during incidents?

**Answer:** Different stakeholders need different information - technical teams need IOCs, management needs business impact, legal needs compliance requirements.

---

## 5. Real-world Incident Report

A real-world incident report applies all the concepts above. Key elements to include:

- Complete executive summary with business context
- Detailed technical timeline with timestamps
- All IoCs identified during investigation
- Evidence preservation documentation
- Root cause analysis with supporting data
- Response actions with their effectiveness
- Lessons learned with actionable recommendations

---

## 6. Additional Resources

### External Links
- NIST Cybersecurity Framework
- SANS Incident Response Resources
- MITRE ATT&CK Framework
- ISO/IEC 27001 Incident Management

### Further Reading
- "The Incident Response Playbook" by Andrew J. Stewart
- "Security Engineering" by Ross Anderson
- SANS DFIR Reading Room

---

*Module 15/15 - Security Incident Reporting*
*For learning and SOC career preparation*