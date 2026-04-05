# Security Monitoring & SIEM Fundamentals
## SOC Analyst Cheatsheet - Module 2/15

---

## 0. Overview

This module covers the **foundations of SIEM and SOC operations**. You'll learn how SIEM solutions work, the Elastic Stack architecture, SOC organizational structures, MITRE ATT&CK framework applications, and how to develop effective SIEM use cases.

### Key Takeaways

| Concept | Description |
|---------|-------------|
| **SIEM** | Security Information and Event Management - centralizes log collection, normalization, and correlation |
| **Elastic Stack** | Elasticsearch + Logstash + Kibana + Beats |
| **SOC** | Security Operations Center - continuous monitoring and incident response |
| **Use Case** | Detection scenario that triggers alerts based on correlated events |
| **KQL** | Kibana Query Language |

---

## Table of Contents

1. [SIEM Definition & Fundamentals](#1-siem-definition--fundamentals)
2. [Introduction To The Elastic Stack](#2-introduction-to-the-elastic-stack)
3. [SOC Definition & Fundamentals](#3-soc-definition--fundamentals)
4. [MITRE ATT&CK & Security Operations](#4-mitre-attck--security-operations)
5. [SIEM Use Case Development](#5-siem-use-case-development)
6. [SIEM Visualization - Dashboard Development](#6-siem-visualization---dashboard-development)
7. [Additional Resources](#7-additional-resources)

---

## 1. SIEM Definition & Fundamentals

### What Is SIEM?

SIEM (Security Information and Event Management) combines:
- **SIM** (Security Information Management) - log storage, reporting, compliance
- **SEM** (Security Event Management) - real-time monitoring, correlation, alerting

**Core Capabilities:**

| Capability | Description |
|------------|-------------|
| **Log Aggregation** | Centralize logs from multiple sources |
| **Normalization** | Convert diverse log formats to common schema |
| **Correlation** | Link related events across sources |
| **Alerting** | Notify on detected threats |
| **Compliance** | Generate audit reports |

### How Does A SIEM Solution Work?

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'lineColor': '#999', 'nodeBorder': '#999'}}}%%
flowchart LR
    subgraph "Data Sources"
        A[Firewalls] --> D[SIEM]
        B[Servers] --> D
        C[Endpoints] --> D
    end
    
    subgraph "SIEM Pipeline"
        D --> G[Collection]
        G --> H[Normalization]
        H --> I[Correlation]
        I --> J[Alerting]
    end
    
    J --> K[Dashboard]
    
    classDef source fill:#fff3e0,stroke:#999,stroke-width:2px,color:#333;
    classDef process fill:#e3f2fd,stroke:#999,stroke-width:2px,color:#333;
    class A,B,C source;
    class D,G,H,I,J process;
    class K process;
```

### Data Flows Within A SIEM

| Stage | Description |
|-------|-------------|
| **1. Ingestion** | Collect logs from sources (agents, syslog, APIs) |
| **2. Normalization** | Convert raw data to common format |
| **3. Storage** | Index and store normalized data |
| **4. Correlation** | Apply rules to detect patterns |
| **5. Visualization** | Display via dashboards |

### SIEM Business Requirements

#### Log Aggregation & Normalization

- Centralize security data from firewalls, databases, applications
- Correlate events across different sources
- Improve threat visibility

#### Threat Alerting

- Real-time alerts based on detected threats
- Integration with threat intelligence
- Faster investigation and response

#### Contextualization

- Reduce alert fatigue by filtering false positives
- Provide context: who, what, when, where
- Determine actors involved, affected parts, timing

#### Compliance

| Regulation | Requirements |
|------------|--------------|
| **PCI DSS** | Real-time monitoring, log retention |
| **HIPAA** | Audit trails, access monitoring |
| **GDPR** | Data breach notification |
| **ISO 27001** | Security logging and monitoring |

### Benefits of SIEM

| Benefit | Description |
|---------|-------------|
| **Centralized View** | Single pane of glass for all logs |
| **Proactive Detection** | Detect threats before damage |
| **Faster Response** | Reduced MTTR |
| **Compliance** | Meet regulatory requirements |

---

## 2. Introduction To The Elastic Stack

### What Is The Elastic Stack?

The Elastic Stack is an open-source collection of applications:

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'lineColor': '#999', 'nodeBorder': '#999'}}}%%
flowchart TB
    subgraph "Ingest"
        A[Beats<br/>Filebeat, Metricbeat] --> B[Logstash]
    end
    
    subgraph "Store & Analyze"
        B --> C[Elasticsearch]
    end
    
    subgraph "Visualize"
        C --> D[Kibana]
    end
    
    classDef component fill:#e3f2fd,stroke:#999,stroke-width:2px,color:#333;
    class A,B,C,D component;
```

### Components

#### Beats (Data Shippers)

| Beat | Purpose |
|------|---------|
| **Filebeat** | Log files collection |
| **Metricbeat** | Metrics collection |
| **Winlogbeat** | Windows Event Logs |
| **Packetbeat** | Network traffic |

#### Logstash

Three main functions:
1. **Input** - Collect logs from files, syslog, network
2. **Filter** - Parse, enrich, normalize
3. **Output** - Send to Elasticsearch

#### Elasticsearch

- Distributed search and analytics engine
- JSON-based RESTful APIs
- Index and query log data

#### Kibana

- Visualization interface
- Create dashboards and charts
- Query data with KQL

### Data Flow Options

```
Beats -> Logstash -> Elasticsearch -> Kibana
Beats -> Elasticsearch -> Kibana
```

### Elastic Stack As SIEM

1. **Ingest** security data from firewalls, IDS/IPS, endpoints
2. **Store & Index** in Elasticsearch
3. **Analyze** using search and correlations
4. **Visualize** via Kibana dashboards

### Kibana Query Language (KQL)

#### Basic Structure

```kql
field:value
```

#### Free Text Search

```kql
"svc-sql1"
```

#### Logical Operators

```kql
event.code:4625 AND winlog.event_data.SubStatus:0xC0000072
```

#### Comparison Operators

```kql
@timestamp >= "2023-03-03T00:00:00.000Z"
```

#### Wildcards

```kql
user.name: admin*
```

### Elastic Common Schema (ECS)

ECS provides **consistent field formats** across data sources:

| Benefit | Description |
|---------|-------------|
| **Unified Data View** | Search across Windows, network, cloud |
| **Improved Search Efficiency** | Standard field names |
| **Enhanced Correlation** | Cross-source event correlation |
| **Better Visualizations** | Consistent dashboard creation |

---

## 3. SOC Definition & Fundamentals

### What Is A SOC?

A **Security Operations Center (SOC)** is a facility with a team responsible for:
- Continuous monitoring
- Threat detection
- Incident response
- Security event management

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'lineColor': '#999', 'nodeBorder': '#999'}}}%%
flowchart TB
    subgraph "SOC Functions"
        A[Monitor] --> B[Detect]
        B --> C[Analyze]
        C --> D[Respond]
    end
    
    classDef function fill:#e8f5e9,stroke:#999,stroke-width:2px,color:#333;
    class A,B,C,D function;
```

### SOC Team Roles

| Role | Responsibilities |
|------|------------------|
| **SOC Director** | Strategic planning, budgeting |
| **SOC Manager** | Day-to-day operations |
| **Tier 1 Analyst** | Alert triage, initial assessment |
| **Tier 2 Analyst** | Deep investigation |
| **Tier 3 Analyst** | Threat hunting, advanced forensics |
| **Detection Engineer** | Create detection rules |
| **Incident Responder** | Active incident handling |
| **Threat Intel Analyst** | Threat intelligence |

### SOC Tier Structure

| Tier | Focus | Skills Required |
|------|-------|-----------------|
| **Tier 1** | Triage | Basic log analysis, alert categorization |
| **Tier 2** | Investigation | Deep analysis, malware triage |
| **Tier 3** | Advanced | Forensics, threat hunting |

### SOC Evolution Stages

| Generation | Description |
|------------|-------------|
| **SOC 1.0** | Network-focused, separate tools |
| **SOC 2.0** | Integrated threat intel, anomaly detection |
| **Cognitive SOC** | AI/ML-assisted decision making |

---

## 4. MITRE ATT&CK & Security Operations

### What Is MITRE ATT&CK?

**ATT&CK** = Adversarial Tactics, Techniques, and Common Knowledge

A framework documenting adversary attack methods:
- **Tactics** - The goal/objective
- **Techniques** - How they achieve the goal

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'lineColor': '#999', 'nodeBorder': '#999'}}}%%
flowchart LR
    A[Recon] --> B[Initial Access]
    B --> C[Execution]
    C --> D[Persistence]
    D --> E[Priv Esc]
    E --> F[Defense Evasion]
    F --> G[Cred Access]
    G --> H[Discovery]
    H --> I[Lateral Movement]
    I --> J[Exfiltration]
    
    style A fill:#ffcdd2,stroke:#999
    style B fill:#ffcdd2,stroke:#999
    style C fill:#ffcdd2,stroke:#999
    style D fill:#fff9c4,stroke:#999
    style E fill:#fff9c4,stroke:#999
    style F fill:#c8e6c9,stroke:#999
    style G fill:#c8e6c9,stroke:#999
    style H fill:#bbdefb,stroke:#999
    style I fill:#bbdefb,stroke:#999
    style J fill:#e1bee7,stroke:#999
```

### ATT&CK Use Cases in Security Operations

| Use Case | Description |
|----------|-------------|
| **Detection & Response** | Design detection rules based on TTPs |
| **Gap Analysis** | Identify coverage gaps |
| **SOC Maturity** | Measure detection capability |
| **Threat Intel** | Common language for adversary activities |
| **Behavioral Analytics** | Map TTPs to detect anomalies |
| **Red Teaming** | Plan attack simulations |

---

## 5. SIEM Use Case Development

### What Is A SIEM Use Case?

A **use case** defines specific conditions that trigger an alert:

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'lineColor': '#999', 'nodeBorder': '#999'}}}%%
flowchart LR
    A[10 Failed Logins] --> B[SIEM Correlation]
    B --> C[Single Alert]
    C --> D[SOC Notification]
    
    style A fill:#fff3e0,stroke:#999
    style B fill:#e3f2fd,stroke:#999
    style C fill:#e3f2fd,stroke:#999
    style D fill:#e8f5e9,stroke:#999
```

### Use Case Development Lifecycle

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'lineColor': '#999', 'nodeBorder': '#999'}}}%%
flowchart TB
    A[Requirements] --> B[Data Points]
    B --> C[Log Validation]
    C --> D[Design]
    D --> E[Implementation]
    E --> F[Documentation]
    F --> G[Onboarding]
    G --> H[Testing]
    H --> I[Fine Tuning]
    
    style A fill:#e3f2fd,stroke:#999
    style B fill:#e3f2fd,stroke:#999
    style C fill:#e3f2fd,stroke:#999
    style D fill:#fff3e0,stroke:#999
    style E fill:#fff3e0,stroke:#999
    style F fill:#e8f5e9,stroke:#999
    style G fill:#e8f5e9,stroke:#999
    style H fill:#e8f5e9,stroke:#999
    style I fill:#fce4ec,stroke:#999
```

### Steps to Build SIEM Use Cases

| Step | Description |
|------|-------------|
| **1. Requirements** | Define what to detect |
| **2. Data Points** | Identify log sources |
| **3. Log Validation** | Ensure logs contain required fields |
| **4. Design** | Define condition, aggregation, priority |
| **5. Implementation** | Create detection rule |
| **6. Documentation** | Write SOP |
| **7. Onboarding** | Move to production |
| **8. Testing** | Validate with known scenarios |
| **9. Fine Tuning** | Reduce false positives |

### Use Case Design Parameters

| Parameter | Description |
|-----------|-------------|
| **Condition** | What triggers the alert |
| **Aggregation** | Time window and grouping |
| **Priority** | Severity (High/Medium/Low) |

### Example: MSBuild Detection

| Attribute | Value |
|-----------|-------|
| **Risk** | Attacker uses MSBuild to execute code |
| **Severity** | HIGH |
| **MITRE** | T1127.001 - MSBuild |
| **Tactic** | Execution, Defense Evasion |

---

## 6. SIEM Visualization - Dashboard Development

### Creating Failed Logon Attempts Dashboard

Dashboards in SIEM solutions serve as containers for multiple visualizations, allowing us to organize and display data in a meaningful way.

In this and the following sections, we will create a dashboard and some visualizations from scratch.

#### Step 1: Navigate to Dashboard

Navigate to http://[Target IP]:5601, click on the side navigation toggle, and click on "Dashboard".

Delete the existing "SOC-Alerts" dashboard as follows.

<img width="1337" height="559" alt="Delete existing SOC-Alerts dashboard" src="https://github.com/user-attachments/assets/75a0b506-1d57-4683-95b6-983577b90915" />

> **Description**: Elastic dashboard interface showing 'SOC-Alerts' with options to delete or create a dashboard.

When visiting the Dashboard page again we will be presented with a message indicating that no dashboards currently exist. Additionally, there will be an option available to create a new Dashboard and its first visualization. To initiate the creation of our first dashboard, we simply have to click on the "Create new dashboard" button.

<img width="1913" height="1169" alt="Create first dashboard" src="https://github.com/user-attachments/assets/224600e5-5fe3-4bb7-a976-7556a2b1b8dd" />

> **Description**: Elastic interface prompting to create the first dashboard with options to install sample data and create a new dashboard.

<img width="1913" height="1169" alt="Dashboard options" src="https://github.com/user-attachments/assets/fef349ef-1e9f-46ed-b5e7-6cbd427b9f21" />

#### Step 2: Create First Visualization

Now, to initiate the creation of our first visualization, we simply have to click on the "Create visualization" button.

<img width="1096" height="928" alt="Create visualization button" src="https://github.com/user-attachments/assets/25f03fbf-3322-4095-8e6e-b7fbff5bed7b" />

> **Description**: Elastic interface for editing a new dashboard, prompting to add the first visualization with options to create or add from library.

Upon initiating the creation of our first visualization, the following new window will appear with various options and settings.

Before proceeding with any configuration, it is important for us to first click on the calendar icon to open the time picker. Then, we need to specify the date range as "last 15 years". Finally, we can click on the "Apply" button to apply the specified date range to the data.

<img width="1030" height="638" alt="Time picker configuration" src="https://github.com/user-attachments/assets/018b5957-5c94-463b-ad6f-8219595c5418" />

> **Description**: Elastic dashboard creation interface with options to add filter, select index pattern 'windows*', search field names, and choose 'Bar vertical stacked' visualization.

There are four things for us to notice on this window:

1. **Filter Option** - A filter option that allows us to filter the data before creating a graph. For example, if our goal is to display failed logon attempts, we can use a filter to only consider event IDs that match 4625 – Failed logon attempt on a Windows system.

<img width="1029" height="637" alt="Add filter for event code" src="https://github.com/user-attachments/assets/6fc32ca5-8a3a-4d6d-8185-d8021b2b9895" />

> **Description**: Elastic dashboard interface with 'Add filter' option open, setting filter for 'event.code' to '4625' using operator 'is'.

2. **Index Pattern** - This field indicates the data set (index) that we are going to use. It is common for data from various infrastructure sources to be separated into different indices, such as network, Windows, Linux, etc. In this particular example, we will specify `windows*` in the "Index pattern".

3. **Field Search** - This search bar provides us with the ability to double-check the existence of a specific field within our data set. For example, let's say we are interested in the `user.name.keyword` field. We can use the search bar to quickly perform a search and verify if this field is present.

<img width="460" height="1043" alt="Search for user fields" src="https://github.com/user-attachments/assets/c6f52bfd-3ce2-4824-a68a-bca856749799" />

> **Description**: Elastic dashboard interface with a filter for 'event.code: 4625' and search for fields starting with 'user.' showing available fields like 'user.name.keyword'.

> **Note**: We should use the `.keyword` field when it comes to aggregations.

4. **Visualization Type** - This drop-down menu enables us to select the type of visualization we want to create. The default option is "Bar vertical stacked".

<img width="1030" height="793" alt="Visualization type options" src="https://github.com/user-attachments/assets/7e5a3f12-9cf9-47f4-999b-e3dcd5f9388f" />

> **Description**: Elastic interface showing visualization type options with 'Bar vertical stacked' selected, including other options like 'Metric' and 'Table'.

#### Step 3: Configure Table Visualization

For this visualization, let's select the "Table" option. After selecting the "Table", we can proceed to click on the "Rows" option. This will allow us to choose the specific data elements that we want to include in the table view.

<img width="711" height="712" alt="Table configuration" src="https://github.com/user-attachments/assets/09b89951-297c-4a84-b611-d5803bb542fc" />

> **Description**: Elastic table configuration interface with options to add or drag-and-drop fields for rows, columns, and metrics.

Let's configure the "Rows" settings as follows.

<img width="728" height="935" alt="Configure rows with user.name" src="https://github.com/user-attachments/assets/48a5227e-509b-48f5-a4a4-a03ca14f8d9d" />

> **Description**: Elastic interface for configuring rows, selecting 'user.name.keyword' field, displaying top 1000 values, ranked by count of records in descending order.

> **Note**: You will notice "Rank by Alphabetical" and not "Rank by Count of records" like in the screenshot above. This is OK. By the time you perform the next configuration below, Count of records will become available.

Moving forward, let's close the "Rows" window and proceed to enter the "Metrics" configuration.

<img width="703" height="839" alt="Metrics configuration" src="https://github.com/user-attachments/assets/4a1cdd58-0d8b-4788-838d-494cd92435e4" />

> **Description**: Elastic table configuration showing 'windows*' index pattern, with 'Top values of user.name.keyword' in rows, and options to add fields to columns and metrics.

In the "Metrics" window, let's select "count" as the desired metric.

<img width="606" height="554" alt="Select Count metric" src="https://github.com/user-attachments/assets/26b8d863-7f0f-491e-9680-d2a6243b332a" />

> **Description**: Elastic metrics configuration interface showing quick functions like Average, Count, and Sum, with 'Count' selected.

As soon as we select "Count" as the metric, we will observe that the table gets populated with data.

<img width="1029" height="504" alt="Table populated with data" src="https://github.com/user-attachments/assets/413427a5-f77a-4130-b2d4-27f09efa68d0" />

> **Description**: Elastic table showing top values of 'user.name.keyword' with counts, and metrics configuration set to 'Count' for records.

One final addition to the table is to include another "Rows" setting to show the machine where the failed logon attempt occurred. To do this, we will select the `host.hostname.keyword` field, which represents the computer reporting the failed logon attempt.

<img width="1033" height="398" alt="Add hostname row" src="https://github.com/user-attachments/assets/d992d2af-2443-4e07-b3b1-bc2d1222533b" />

> **Description**: Elastic table showing top values of 'user.name.keyword' and 'host.hostname.keyword' with record counts, configured in rows.

Now we can see three columns in the table, which contain the following information:

- The username of the individuals logging in (Note: It currently displays both users and computers. Ideally, a filter should be implemented to exclude computer devices and only display users)
- The machine on which the logon attempt occurred
- The number of times the event has occurred (based on the specified time frame or the entire data set, depending on the settings)

Finally, click on "Save and return", and you will observe that the new visualization is added to the dashboard.

<img width="1030" height="761" alt="Dashboard with table visualization" src="https://github.com/user-attachments/assets/88bb1297-59eb-4b78-b735-e2fc44a49ede" />

> **Description**: Elastic dashboard showing a table with top values of user names and hostnames, and their record counts.

Let's not forget to save the dashboard as well. We can do so by simply clicking on the "Save" button.

<img width="1917" height="1053" alt="Save dashboard dialog" src="https://github.com/user-attachments/assets/9f8f7c54-f9a1-425a-b54a-6e322ffbda10" />

> **Description**: Elastic interface showing 'Save dashboard' dialog with title 'SOC-Alerts', description for HTB Academy's SOC Analyst Job-Role Path, and option to store time with dashboard.

### Refining The Visualization

Suppose the SOC Manager suggested the following refinements:

- Clearer column names should be specified in the visualization
- The Logon Type should be included in the visualization
- The results in the visualization should be sorted
- The DESKTOP-DPOESND, WIN-OK9BH1BCKSD, and WIN-RMMGJA7T9TC usernames should not be monitored
- Computer accounts should not be monitored (not a good practice)

Let's refine the visualization we created, so that it fulfills the suggestions above.

Navigate to http://[Target IP]:5601, click on the side navigation toggle, and click on "Dashboard".

The dashboard we previously created should be visible. Let's click on the "pencil"/edit icon.

<img width="1888" height="652" alt="Edit dashboard" src="https://github.com/user-attachments/assets/6fce909a-de6a-4395-a9eb-0a1c728de829" />

> **Description**: Elastic dashboard interface showing a list with 'SOC-Alerts' and options to create or edit a dashboard.

Let's now click on the "gear" button at the upper-right corner of our visualization, and then click on "Edit lens".

<img width="1913" height="985" alt="Edit lens option" src="https://github.com/user-attachments/assets/7236e5f6-0c57-493e-bc36-ace8f5f852c7" />

> **Description**: Elastic dashboard editing 'SOC-Alerts' with a table of top user and hostnames, and options to edit lens, clone panel, or edit panel title.

#### Update Column Names

"Top values of user.name.keyword" should be changed as follows.

<img width="476" height="801" alt="Rename username column" src="https://github.com/user-attachments/assets/66081177-c2ba-4239-b932-49809e37bf56" />

> **Description**: Elastic interface for configuring rows, selecting 'user.name.keyword' field, displaying top 1000 values, ranked alphabetically in ascending order, with display name 'Username'.

"Top values of host.hostname.keyword" should be changed as follows.

<img width="473" height="789" alt="Rename hostname column" src="https://github.com/user-attachments/assets/fe6741ab-3c34-43fa-93f1-0f1e99438812" />

> **Description**: Elastic interface for configuring rows, selecting 'host.hostname.keyword' field, displaying top 1000 values, ranked by count of records in descending order, with display name 'Event logged by'.

The "Logon Type" can be added as follows (we will use the `winlog.logon.type.keyword` field).

<img width="456" height="791" alt="Add logon type field" src="https://github.com/user-attachments/assets/de706f04-fbe0-4a10-8744-bdcbfe95c8e4" />

> **Description**: Rows configuration panel with 'winlog.logon.type.keyword' field selected, number of values set to 1000, ranked by count of records in descending order, display name 'Logon Type'.

"Count of records" should be changed as follows.

<img width="459" height="1062" alt="Rename count metric" src="https://github.com/user-attachments/assets/02abd6e2-1484-41be-b9c8-f53a0519a201" />

> **Description**: Metrics panel with 'Count' function selected, field set to 'Records', display name '# of logins', text alignment 'Right'.

We can introduce result sorting as follows.

<img width="1915" height="1196" alt="Sorted results" src="https://github.com/user-attachments/assets/3b3a0711-ed53-4825-b59b-c9f725ade54c" />

> **Description**: Elastic dashboard showing a table with columns: Username, Event logged by, Logon Type, and '# of logins' sorted descending.

All we have to do now is click on "Save and return".

#### Exclude Specific Usernames

The DESKTOP-DPOESND, WIN-OK9BH1BCKSD, and WIN-RMMGJA7T9TC usernames can be excluded by specifying additional filters as follows.

<img width="1430" height="1046" alt="Exclude usernames filter" src="https://github.com/user-attachments/assets/50b992fa-8462-4492-a88d-55f7be415e27" />

> **Description**: Elastic dashboard with filter settings: Field 'user.name.keyword', operator 'is not', value 'DESKTOP-DPOESND'.

#### Exclude Computer Accounts

Computer accounts can be excluded by specifying the following KQL query and clicking on the "Update" button.

```kql
NOT user.name: *$ AND winlog.channel.keyword: Security
```

> **Note**: The `AND winlog.channel.keyword: Security` part is to ensure that no unrelated logs are accounted for.

<img width="1919" height="1063" alt="Final visualization with filters" src="https://github.com/user-attachments/assets/417227e8-8f9e-4caa-9860-41d76ae25c5e" />

> **Description**: Elastic dashboard with filters: NOT user.name:*$ AND winlog.channel.keyword: Security, showing a table with columns: Username, Event logged by, Logon Type, and '# of logins'.

This is our visualization after all the refinements we performed.

<img width="1917" height="1071" alt="Final refined dashboard" src="https://github.com/user-attachments/assets/df3e0567-bb2d-4444-a92d-dfd00d8839cc" />

> **Description**: Elastic dashboard with filters applied, displaying a table with columns: Username, Event logged by, Logon Type, and '# of logins'.

Finally, let's give our visualization a title by clicking on "No Title".

<img width="1917" height="1059" alt="Add panel title" src="https://github.com/user-attachments/assets/f7f6e2d1-e9e9-45f4-8208-0342a0fc54db" />

> **Description**: Customize panel dialog open with 'Show panel title' option.

Don't forget to click on the "Save" button (the one on the upper-right hand side of the window).

### Failed Logon Attempts (Disabled Users) - Visualization Example 2

This visualization builds upon the previous failed logon attempts dashboard but focuses specifically on detecting login attempts to **disabled user accounts** - a significant security indicator that may suggest account compromise or credential stuffing attacks.

> **Security Note**: When an attacker obtains credentials for a disabled account, they may attempt to use those credentials without knowing the account is disabled. Detecting these attempts is crucial as it could indicate:
> - Previous legitimate user credentials that were disabled (departed employee)
> - Stolen credentials from a decommissioned account
> - Credential stuffing attempts using old credential databases

#### Understanding the Windows Event

Windows Security Event **4625** (Failed Logon) includes a **SubStatus** field that indicates the reason for the failure. The SubStatus `0xC0000072` specifically indicates:

| SubStatus | Meaning |
|-----------|---------|
| `0xC0000072` | Account is currently disabled |

#### Step-by-Step Configuration

##### Step 1: Create New Visualization

Navigate to your dashboard in Kibana and create a new visualization using the same index pattern `windows*`.

##### Step 2: Add Filter for Disabled Accounts

Add a filter using the following criteria:

- **Field**: `winlog.event_data.SubStatus`
- **Operator**: `is`
- **Value**: `0xc0000072`

This filter ensures we only capture failed logon attempts where the account is disabled.

<img width="1029" height="637" alt="Filter for disabled accounts" src="https://github.com/user-attachments/assets/6fc32ca5-8a3a-4d6d-8185-d8021b2b9895" />

> **Description**: Elastic dashboard interface with 'Add filter' option, setting filter for SubStatus to 0xc0000072 to capture disabled account logon failures.

##### Step 3: Add Event Code Filter

Additionally, filter for Event ID 4625 (Failed Logon):

```kql
event.code:4625 AND winlog.event_data.SubStatus:0xc0000072
```

##### Step 4: Configure Table Visualization

Select **Table** visualization and configure the following **Rows**:

| Field | Display Name | Settings |
|-------|--------------|----------|
| `user.name.keyword` | Username | Top 1000 values, Rank by Count |
| `host.hostname.keyword` | Source Machine | Top 1000 values, Rank by Count |

##### Step 5: Configure Metrics

In the **Metrics** section:
- Select **Count** as the metric
- Display Name: `# of Failed Attempts`

##### Step 6: Add Time Range

Set the time picker to cover a significant period (e.g., last 30 days or last 15 years depending on data available).

##### Step 7: Exclude Computer Accounts

Add a KQL filter to exclude computer accounts (accounts ending with `$`):

```kql
NOT user.name: *$
```

##### Step 8: Save the Visualization

Save the visualization with an appropriate title such as "Failed Logon - Disabled Accounts".

#### Sample Query

The resulting KQL query should look like:

```kql
event.code:4625 AND winlog.event_data.SubStatus:0xc0000072 AND NOT user.name:*$
```

#### Why This Matters

| Aspect | Importance |
|--------|------------|
| **Detection** | Identifies unauthorized access attempts on disabled accounts |
| **Investigation** | Helps determine if attacker knows about old/departed user credentials |
| **Response** | May indicate need for credential rotation and account cleanup |
| **Compliance** | Provides audit trail for access attempts on sensitive accounts |

#### Investigation Workflow

When this alert triggers:

1. **Identify the target account** - Which disabled account is being targeted?
2. **Check source IP** - Is this from internal or external IP?
3. **Review frequency** - Is this a one-time attempt or part of a brute force campaign?
4. **Check for related alerts** - Are there similar attempts on other disabled accounts?
5. **Escalate** - If external source and frequent, escalate to Tier 2/3

---

## 7. Additional Resources

### Official Documentation

- [Elastic Documentation](https://www.elastic.co/guide/index.html)
- [ECS Fields](https://www.elastic.co/guide/en/ecs/current/index.html)
- [KQL Reference](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)

### MITRE ATT&CK

- [MITRE ATT&CK](https://attack.mitre.org)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

---

*Module 2 Complete - Security Monitoring & SIEM Fundamentals*


	
	
	
	
	
	
	
---

## 7. Additional Resources
	












---

### Successful RDP Logon (Service Accounts) - Visualization Example 3

This visualization monitors **successful RDP logons to service accounts** - a critical security indicator. Service accounts should never require remote interactive (RDP) access.

> **Security Note**: Service accounts typically have elevated privileges. Any RDP login to a service account is anomalous and could indicate:
> - Compromised service account credentials
> - Privilege escalation from a regular user account
> - Misconfiguration allowing unintended access
> - Attackers moving laterally using service account credentials

#### Understanding the Windows Event

| Event ID | Description | Logon Type |
|----------|-------------|------------|
| **4624** | An account was successfully logged on | **RemoteInteractive** (Type 10) |

#### Step-by-Step Configuration

##### Step 1: Create New Visualization

Navigate to your dashboard in Kibana and create a new visualization using the index pattern `windows*`.

##### Step 2: Add Filters

Add the following filters:

| Field | Operator | Value |
|-------|----------|-------|
| `event.code` | is | `4624` |
| `winlog.logon.type` | is | `RemoteInteractive` |

##### Step 3: Filter for Service Accounts

Add a KQL query to filter for service accounts (typically prefixed with `svc-`):

```kql
user.name: svc-*
```

> **Note**: In KQL queries, you typically don't need to use the `.keyword` field.

##### Step 4: Configure Table Visualization

Select **Table** visualization and configure the following **Rows**:

| Field | Display Name | Settings |
|-------|--------------|----------|
| `user.name.keyword` | Service Account | Top 1000 values, Rank by Count |
| `host.hostname.keyword` | Target Machine | Top 1000 values, Rank by Count |
| `related.ip.keyword` | Source IP | Top 1000 values, Rank by Count |

##### Step 5: Configure Metrics

In the **Metrics** section:
- Select **Count** as the metric
- Display Name: `# of RDP Sessions`

##### Step 6: Save the Visualization

Save the visualization with title "Successful RDP - Service Accounts".

#### Sample Query

```kql
event.code:4624 AND winlog.logon.type:RemoteInteractive AND user.name:svc-*
```

#### Resulting Table Columns

| Column | Description |
|--------|-------------|
| **Service Account** | The account used for RDP |
| **Target Machine** | Computer where RDP connection was made |
| **Source IP** | IP address initiating the RDP connection |
| **# of RDP Sessions** | Count of RDP sessions |

#### Why This Matters

| Aspect | Importance |
|--------|------------|
| **Lateral Movement** | Detects attackers using compromised service accounts |
| **Privilege Escalation** | Identifies unauthorized access to high-privilege accounts |
| **Compliance** | Service accounts should never have RDP access |
| **Forensics** | Provides audit trail of service account usage |

#### Investigation Workflow

When this alert triggers:

1. **Verify legitimacy** - Is this expected RDP usage for the service account?
2. **Check source machine** - Is the source IP from a legitimate workstation?
3. **Review timing** - Is this during business hours or unusual times?
4. **Check recent changes** - Any recent changes to this service account?
5. **Escalate** - If suspicious, escalate to Tier 2/3 for further investigation

---

*Module 2 Complete - Security Monitoring & SIEM Fundamentals*



































Security Monitoring & SIEM Fundamentals
Security Monitoring & SIEM Fundamentals 100%

Section 9 / 11
Go to Questions
SIEM Visualization Example 4: Users Added Or Removed From A Local Group (Within A Specific Timeframe)

In this SIEM visualization example, we aim to create a visualization to monitor user additions or removals from the local "Administrators" group from March 5th 2023 to date.

Our visualization will be based on the following Windows event logs.

    4732: A member was added to a security-enabled local group
    4733: A member was removed from a security-enabled local group

Navigate to the bottom of this section and click on Click here to spawn the target system!.

Navigate to http://[Target IP]:5601, click on the side navigation toggle, and click on "Dashboard".

A prebaked dashboard should be visible. Let's click on the "pencil"/edit icon.

<img width="1888" height="652" alt="image" src="https://github.com/user-attachments/assets/3ce288bd-06bb-4ab0-be2f-03f19c81e2d5" />


Elastic dashboard with SOC-Alerts listed, option to create or edit dashboards.

Now, to initiate the creation of our first visualization, we simply have to click on the "Create visualization" button.

Upon initiating the creation of our first visualization, the following new window will appear with various options and settings.
<img width="1030" height="638" alt="image" src="https://github.com/user-attachments/assets/15b262f1-ce57-4f92-aa4e-b0182803ec3d" />

Elastic dashboard: Add filter, select windows index, bar vertical stacked chart.

There are four things for us to notice on this window:

    A filter option that allows us to filter the data before creating a graph. In this case our goal is to display user additions or removals from the local "Administrators" group. We can use a filter to only consider event IDs that match 4732 – A member was added to a security-enabled local group and 4733 – A member was removed from a security-enabled local group. We can also use a filter to only consider 4732 and 4733 events where the local group is the "Administrators" one.

	<img width="1030" height="473" alt="image" src="https://github.com/user-attachments/assets/742ad714-9b9e-4af5-8b26-98d7446107ee" />

    Elastic dashboard filter: event.code is 4732 or 4733, group.name is administrators.

	
    This field indicates the data set (index) that we are going to use. It is common for data from various infrastructure sources to be separated into different indices, such as network, Windows, Linux, etc. In this particular example, we will specify windows* in the "Index pattern".
    This search bar provides us with the ability to double-check the existence of a specific field within our data set, serving as another way to ensure that we are looking at the correct data. We are interested in the user.name.keyword field. We can use the search bar to quickly perform a search and verify if this field is present and discovered within our selected data set. This allows us to confirm that we are accessing the desired field and working with accurate data.

	<img width="460" height="1043" alt="image" src="https://github.com/user-attachments/assets/30e53837-cc79-4272-ad78-fe0c1546bd7f" />

    Elastic dashboard: Filter event.code 4625, search user fields.
	
    Lastly, this drop-down menu enables us to select the type of visualization we want to create. The default option displayed in the earlier image is "Bar vertical stacked". If we click on that button, it will reveal additional available options (image redacted as not all options fit on the screen). From this expanded list, we can choose the desired visualization type that best suits our requirements and data presentation needs.

	<img width="1030" height="793" alt="image" src="https://github.com/user-attachments/assets/d2571940-3893-4c15-b615-90fc4e59bfca" />

    Visualization type menu: Bar vertical stacked selected.

For this visualization, let's select the "Table" option. After selecting the "Table", we can proceed to click on the "Rows" option. This will allow us to choose the specific data elements that we want to include in the table view.

<img width="711" height="712" alt="image" src="https://github.com/user-attachments/assets/f4eafe27-9e20-4e57-af3e-9c3efe0aec40" />

Table configuration: Add fields to Rows, Columns, and Metrics.

Let's configure the "Rows" settings as follows.
<img width="728" height="935" alt="image" src="https://github.com/user-attachments/assets/4093fecb-4d76-4985-93be-6859b7e09a84" />


Rows configuration: Select user.name.keyword, top 1000 values, ranked by count of records in descending order.

Moving forward, let's close the "Rows" window and proceed to enter the "Metrics" configuration.

<img width="703" height="839" alt="image" src="https://github.com/user-attachments/assets/05ed4b13-e9d0-4b77-af79-171375a2997f" />


Table configuration: Rows set to top values of user.name.keyword, add fields to Columns and Metrics.

In the "Metrics" window, let's select "count" as the desired metric.
<img width="606" height="554" alt="image" src="https://github.com/user-attachments/assets/cff3f641-c998-446f-a7b8-985921d94701" />


Metrics selection: Choose 'Count' function.

One final addition to the table is to include some more "Rows" settings to enhance our understanding.

    Which user was added to or removed from the group? (winlog.event_data.MemberSid.keyword field)
    To which group was the addition or the removal performed? (double-checking that it is the "Administrators" one) (group.name.keyword field)
	
    Was the user added to or removed from the group? (event.action.keyword field)
    On which machine did the action occur? (host.name.keyword field)
	<img width="1169" height="332" alt="image" src="https://github.com/user-attachments/assets/c5f57ee9-67ff-4fa2-8135-2ceee639b49c" />

    Table showing top values of user.name, winlog.event_data.MemberSid, group.name, event.action, host.name, with record counts.

Click on "Save and return", and you will observe that the new visualization is added to the dashboard.

As discussed, we want to monitor user additions or removals from the local "Administrators" group within a specific timeframe (March 5th 2023 to date).

We can narrow the scope of our visualization as follows.

<img width="1917" height="1413" alt="image" src="https://github.com/user-attachments/assets/4c34fc42-91f9-4383-98c6-28df2c378270" />


Dashboard showing failed logon attempts and RDP logon for service account, with options to edit lens and create drilldown.
<img width="1921" height="1409" alt="image" src="https://github.com/user-attachments/assets/82b72380-4396-461b-91f9-f320518c6fec" />


Dashboard showing failed logon attempts and RDP logon for service account, with options to customize time range.
<img width="1923" height="1403" alt="image" src="https://github.com/user-attachments/assets/7f45c2a0-49ac-4e17-ae74-f7bad5cd1612" />


Dashboard with failed logon attempts and RDP logon, showing panel time range customization to March 5, 2023.

Finally, let's click on the "Save" button so that all our edits persist.

Please allow 3-5 minutes for Kibana to become available after spawning the target of the questions below.





 Section 10 / 11
The Triaging Process
What Is Alert Triaging?

Alert triaging, performed by a Security Operations Center (SOC) analyst, is the process of evaluating and prioritizing security alerts generated by various monitoring and detection systems to determine their level of threat and potential impact on an organization's systems and data. It involves systematically reviewing and categorizing alerts to effectively allocate resources and respond to security incidents.

Escalation is an important aspect of alert triaging in a SOC environment. The escalation process typically involves notifying supervisors, incident response teams, or designated individuals within the organization who have the authority to make decisions and coordinate the response effort. The SOC analyst provides detailed information about the alert, including its severity, potential impact, and any relevant findings from the initial investigation. This allows the decision-makers to assess the situation and determine the appropriate course of action, such as involving specialized teams, initiating broader incident response procedures, or engaging external resources if necessary.

Escalation ensures that critical alerts receive prompt attention and facilitates effective coordination among different stakeholders, enabling a timely and efficient response to potential security incidents. It helps to leverage the expertise and decision-making capabilities of individuals who are responsible for managing and mitigating higher-level threats or incidents within the organization.
What Is The Ideal Triaging Process?

    Initial Alert Review:

    Thoroughly review the initial alert, including metadata, timestamp, source IP, destination IP, affected systems, and triggering rule/signature.
    Analyze associated logs (network traffic, system, application) to understand the alert's context.

    Alert Classification:

    Classify the alert based on severity, impact, and urgency using the organization's predefined classification system.

    Alert Correlation:

    Cross-reference the alert with related alerts, events, or incidents to identify patterns, similarities, or potential indicators of compromise (IOCs).
    Query the SIEM or log management system to gather relevant log data.
    Leverage threat intelligence feeds to check for known attack patterns or malware signatures.

    Enrichment of Alert Data:

    Gather additional information to enrich the alert data and gain context:
        Collect network packet captures, memory dumps, or file samples associated with the alert.
        Utilize external threat intelligence sources, open-source tools, or sandboxes to analyze suspicious files, URLs, or IP addresses.
        Conduct reconnaissance of affected systems for anomalies (network connections, processes, file modifications).

    Risk Assessment:

    Evaluate the potential risk and impact to critical assets, data, or infrastructure:
        Consider the value of affected systems, sensitivity of data, compliance requirements, and regulatory implications.
        Determine likelihood of a successful attack or potential lateral movement.

    Contextual Analysis:

    The analyst considers the context surrounding the alert, including the affected assets, their criticality, and the sensitivity of the data they handle.
    They evaluate the security controls in place, such as firewalls, intrusion detection/prevention systems, and endpoint protection solutions, to determine if the alert indicates a potential control failure or evasion technique.
    The analyst assesses the relevant compliance requirements, industry regulations, and contractual obligations to understand the implications of the alert on the organization's legal and regulatory compliance posture.

    Incident Response Planning:

    Initiate an incident response plan if the alert is significant:
        Document alert details, affected systems, observed behaviors, potential IOCs, and enrichment data.
        Assign incident response team members with defined roles and responsibilities.
        Coordinate with other teams (network operations, system administrators, vendors) as necessary.

    Consultation with IT Operations:

    Assess the need for additional context or missing information by consulting with IT operations or relevant departments:
        Engage in discussions or meetings to gather insights on the affected systems, recent changes, or ongoing maintenance activities.
        Collaborate to understand any known issues, misconfigurations, or network changes that could potentially generate false-positive alerts.
        Gain a holistic understanding of the environment and any non-malicious activities that might have triggered the alert.
        Document the insights and information obtained during the consultation.

    Response Execution:

    Based on the alert review, risk assessment, and consultation, determine the appropriate response actions.
    If the additional context resolves the alert or identifies it as a non-malicious event, take necessary actions without escalation.
    If the alert still indicates potential security concerns or requires further investigation, proceed with the incident response actions.

    Escalation:

    Identify triggers for escalation based on organization's policies and alert severity:
        Triggers may include compromise of critical systems/assets, ongoing attacks, unfamiliar/sophisticated techniques, widespread impact, or insider threats.
    Assess the alert against escalation triggers, considering potential consequences if not escalated.
    Follow internal escalation process, notifying higher-level teams/management responsible for incident response.
    Provide comprehensive alert summary, severity, potential impact, enrichment data, and risk assessment.
    Document all communication related to escalation.
    In some cases, escalate to external entities (law enforcement, incident response providers, CERTs) based on legal/regulatory requirements.

    Continuous Monitoring:

    Continuously monitor the situation and incident response progress.
    Maintain open communication with escalated teams, providing updates on developments, findings, or changes in severity/impact.
    Collaborate closely with escalated teams for a coordinated response.

    De-escalation:

    Evaluate the need for de-escalation as the incident response progresses and the situation is under control.
    De-escalate when the risk is mitigated, incident is contained, and further escalation is unnecessary.
    Notify relevant parties, providing a summary of actions taken, outcomes, and lessons learned.

Regularly review and update the process, aligning it with organizational policies, procedures, and guidelines. Adapt the process to address emerging threats and evolving needs.











 Section 11 / 11
Go to Questions
Skills Assessment
Dashboard Review & Critical Thinking Exercise

Congratulations,

You have been hired in Eagle as a SOC Tier 1 analyst. Yesterday was your on-boarding day with the company, and today you will be familiarized with the SOC. Your day will begin by meeting up with a senior analyst, who will provide insights into the environment, and afterwards, you are expected to begin monitoring alerts and security events in our home-cooked SOC dashboards.

The following are your notes after meeting the senior analyst, who provided insights into the environment:

    The organization has moved all hosting to the cloud; the old DMZ network is closed down, so no more servers exist there.
    The IT operation team (the core IT admins) consists of four people. They are the only ones with high privileges in the environment.
    The IT operation team often tends to use the default administrator account(s) even if they are told otherwise.
    All endpoint devices are hardened according to CIS hardening baselines. Whitelisting exists to a limited extent.
    IT security has created a privileged admin workstation (PAW) and requires that all admin activities be performed on this machine.
    The Linux environment is primarily 'left over' servers from back in the day, which have very little, if any, activity on a regular day. The root user account is not used; due to audit findings, the account was blocked from connecting remotely, and users who require those rights will need to escalate via the sudo command.
    Naming conventions exist and are strictly followed; for example, service accounts contain '-svc' as part of their name. Service accounts are created with long, complex passwords, and they perform a very specific task (most likely running services locally on machines).

If you had a running instance of the target please reset it by clicking on the "Reset Target" icon. This will ensure that you regain access to the preconfigured dashboard, that you may have deleted during the SIEM visualization-related sections.

Now you are free to take your seat and start monitoring. Navigate to http://[Target IP]:5601, click on the side navigation toggle, and click on "Dashboard". Review the SOC-Alerts dashboard.

    Visualization 1: Failed logon attempts (All users)
    Such a visualization might reveal potential brute force attacks. It's important to identify any single user with numerous failed attempts or perhaps, various users connecting to (or from) the same endpoint device. However, the current data does not point towards any such scenario. One anomaly is noticeable though. Hint: It is related to the "sql-svc1" account.
    Visualization 2: Failed logon attempts (Disabled user)
    It seems that there is one incident where the user "Anni" has tried to authenticate, despite the account being disabled.
    Visualization 3: Failed logon attempts (Admin users only)
    Hint: Check if all events took place on either Privileged Access Workstations (PAWs) or Domain Controllers.
    Visualization 4: RDP logon for service account
    Service accounts in this environment serve a very specialized function. Do you notice anything that warrants suspicion?
    Visualization 5: User added or removed from a local group
    An administrator has incorporated an individual (who is only represented by the SID value) into the "Administrators" group. Should you escalate to a Tier 2/3 analyst or consult with the IT Operations department first?
    Visualization 6: Admin logon not from PAW
    Administrators should exclusively utilize PAWs for server remote connections. Should you escalate to a Tier 2/3 analyst or consult with the IT Operations department first?
    Visualization 7: SSH Logins
    Be reminded that the root user account is not typically in use.

Go through the questions below and enter your answers.
