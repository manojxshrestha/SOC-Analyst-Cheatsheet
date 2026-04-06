# Understanding Log Sources & Investigating with Splunk
## SOC Analyst Cheatsheet - Module 5/15

---

## Table of Contents

0. [Overview](#0-overview)
1. [Introduction To Splunk & SPL](#1-introduction-to-splunk--spl)
2. [Splunk Architecture](#2-splunk-architecture)
3. [Splunk as a SIEM Solution](#3-splunk-as-a-siem-solution)
4. [SPL Commands Reference](#4-spl-commands-reference)
5. [How To Identify The Available Data](#5-how-to-identify-the-available-data)
6. [Practical Exercises](#6-practical-exercises)

---

## 0. Overview

> 📌 **WHY IT MATTERS**: Splunk is a highly scalable, versatile, and robust data analytics software solution known for its ability to ingest, index, analyze, and visualize massive amounts of machine data. Splunk drives a wide range of initiatives including cybersecurity, compliance, data pipelines, IT monitoring, observability, and overall IT and business management.

### Key Capabilities

- **Data Ingestion**: Collects machine data from various sources
- **Indexing**: Organizes and stores data in indexes
- **Analysis**: Enables searching, filtering, and transforming data
- **Visualization**: Provides dashboards, reports, and alerts

---

## 1. Introduction To Splunk & SPL

### What Is Splunk?

Splunk is a powerful data analytics platform that can:

- ✅ Ingest massive amounts of machine data
- ✅ Index and organize data efficiently
- ✅ Analyze and visualize data in real-time
- ✅ Power cybersecurity, compliance, and IT monitoring initiatives

![Splunk Data Sources](https://github.com/user-attachments/assets/587c96f2-965b-499c-abc0-72c733735eb9)

> 📌 **DATA SOURCES**:
> - Aggregated/API data → Heavy Forwarder
> - Event logs and OS stats → Universal Forwarder
> - Wire data → Splunk Stream or HTTP Event Collector
> - Local file monitoring → Universal Forwarder
> - DevOps, IoT, containers, syslog hosts

![Splunk Architecture](https://github.com/user-attachments/assets/a5dd7fbc-245e-4c9c-b3b3-2963adbedc46)

> 📌 **ARCHITECTURE**: Search Head for UI, Indexer for data processing, Forwarder for data collection. Includes agentless data sources like change tickets, logs, and metrics, with auto-load balanced indexing.

---

## 2. Splunk Architecture

### Core Components

```mermaid
graph LR
    F["Forwarder<br/>Data Collection"] -->|sends data| I["Indexer<br/>Data Processing"]
    I -->|stores| DB["(Indexes)"]
    SH["Search Head<br/>UI & Queries"] -->|searches| I
    
    style F fill:#cce5ff,stroke:#333,stroke-width:2px,color:#000
    style I fill:#e6ccff,stroke:#333,stroke-width:2px,color:#000
    style SH fill:#ffe5cc,stroke:#333,stroke-width:2px,color:#000
    style DB fill:#e0f2f1,stroke:#333,stroke-width:2px,color:#000
```

| Component | Function |
|-----------|----------|
| **Forwarders** | Data collection from various sources |
| **Indexers** | Receive, organize, and store data in indexes |
| **Search Heads** | Coordinate search jobs, provide UI, create Knowledge Objects |
| **Deployment Server** | Manage configuration for forwarders |
| **Cluster Master** | Coordinate indexers in clustered environment |
| **License Master** | Manage Splunk licensing |

### Forwarder Types

| Type | Description | Use Case |
|------|-------------|----------|
| **Universal Forwarder (UF)** | Lightweight agent, no preprocessing | Remote data collection, minimal impact |
| **Heavy Forwarder (HF)** | Parses data before forwarding, can route based on criteria | Data aggregation, firewall logs, API data |
| **HTTP Event Collector (HEC)** | Token-based JSON/raw API for applications | Direct data ingestion from apps |

> 🔴 **KEY DIFFERENCE**: Heavy Forwarders parse data BEFORE forwarding, Universal Forwarders forward raw data.

### Splunk Key Components

- **Splunk Web Interface**: GUI for searching, alerts, dashboards, reports
- **SPL (Search Processing Language)**: Query language for searching/filtering/manipulating data
- **Apps and Add-ons**: Extend functionality, found on Splunkbase
- **Knowledge Objects**: Fields, tags, event types, lookups, macros, data models, alerts

---

## 3. Splunk as a SIEM Solution

> 📌 **SIEM CAPABILITIES**: Splunk as a SIEM solution provides:

- 🔴 **Real-time data analysis** - Monitor events as they occur
- 🔴 **Historical data analysis** - Investigate past incidents
- 🔴 **Cybersecurity monitoring** - Detect and respond to threats
- 🔴 **Incident response** - Support investigation and remediation
- 🔴 **Threat hunting** - Proactively search for threats
- 🔴 **User Behavior Analytics (UBA)** - Detect anomalous user behavior

---

## 4. SPL Commands Reference

### Basic Searching

```splunk
search index="main" "UNKNOWN"
```

> 🔴 **KEY CONCEPT**: By default, a search returns all events, but it can be narrowed down with keywords, boolean operators (AND, OR, NOT), comparison operators, and wildcard characters.

**Example**: By specifying the index as main, the query narrows down the search to only the events stored in the main index. The term UNKNOWN is then used as a keyword to filter and retrieve events that include this specific term.

### Wildcard Search

```splunk
index="main" "*UNKNOWN*"
```

> 📌 Searches for events containing "UNKNOWN" anywhere in the event data. Wildcards (*) can replace any number of characters.

### Fields and Comparison Operators

```splunk
index="main" EventCode!=1
```

> 🔴 Searches for events where EventCode is NOT equal to 1. Splunk automatically identifies fields like source, sourcetype, host, EventCode, etc.

> 📌 **COMPARISON OPERATORS**: =, !=, <, >, <=, >=

### The fields Command

```splunk
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | fields - User
```

> 📌 The fields command specifies which fields should be included or excluded. After retrieving process creation events, this excludes the User field from results.

### The table Command

```splunk
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | table _time, host, Image
```

> 📌 Presents search results in tabular format with specified fields:
> - `_time`: timestamp of the event
> - `host`: name of the host where event occurred
> - `Image`: name of the executable file representing the process

### The rename Command

```splunk
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | rename Image as Process
```

> 📌 Renames a field in search results. Image field represents executable name; renaming it to Process allows subsequent references.

### The dedup Command

```splunk
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | dedup Image
```

> 📌 Removes duplicate entries based on Image field. If same process is created multiple times, it appears only once.

### The sort Command

```splunk
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | sort - _time
```

> 📌 Sorts results in descending order (most recent first). Use `-` for descending.

### The stats Command

```splunk
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | stats count by _time, Image
```

> 📌 Returns table where each row represents unique timestamp and process combination. Count shows network connection events per process at that time.

### The chart Command

```splunk
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | chart count by _time, Image
```

> 📌 Creates visualization where each column represents a unique process. Easily see network events over time for each process.

### The eval Command

```splunk
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | eval Process_Path=lower(Image)
```

> 📌 Creates new field with lowercase version of Image field. Does not change original field.

### The rex Command

```splunk
index="main" EventCode=4662 | rex max_match=0 "[^%](?<guid>{.*})" | table guid
```

> 🔴 **EXTRACTS GUIDs**: Useful because GUIDs are not automatically extracted from 4662 event logs.
> - `rex max_match=0` ensures all occurrences are extracted (not just first)
> - Pattern `{.*}` finds substrings beginning with { and ending with }
> - `[^%]` ensures match doesn't begin with % character

### The lookup Command

#### Step 1: Create Lookup CSV File

```csv
filename, is_malware
notepad.exe, false
cmd.exe, false
powershell.exe, false
sharphound.exe, true
randomfile.exe, true
```

#### Step 2: Add Lookup Table in Splunk UI

![Lookup Settings](https://github.com/user-attachments/assets/c76f03a1-85a1-44b3-9d1b-e6ddd66cd17a)

![Lookups Page](https://github.com/user-attachments/assets/91a165bf-c74c-4282-8b32-36c2dc310537)

![Lookup Table Files](https://github.com/user-attachments/assets/4491381a-b5ae-4860-8ed5-a190076ade47)

![Add Lookup File](https://github.com/user-attachments/assets/ec303f54-41e0-43fe-a1bc-90a0d45953c0)

#### Step 3: Use Lookup in SPL

```splunk
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 
| rex field=Image "(?P<filename>[^\\]+)$" 
| eval filename=lower(filename) 
| lookup malware_lookup.csv filename OUTPUTNEW is_malware 
| table filename, is_malware
```

**Step-by-step breakdown:**
1. `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1`: Search for Sysmon process creation events
2. `| rex field=Image "(?P<filename>[^\\]+)$"`: Extract filename after last backslash
3. `| eval filename=lower(filename)`: Convert to lowercase for case-insensitive match
4. `| lookup malware_lookup.csv filename OUTPUTNEW is_malware`: Check if malicious
5. `| table filename, is_malware`: Display results

#### Alternative with dedup

```splunk
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 
| eval filename=mvdedup(split(Image, "\\")) 
| eval filename=mvindex(filename, -1) 
| eval filename=lower(filename) 
| lookup malware_lookup.csv filename OUTPUTNEW is_malware 
| table filename, is_malware 
| dedup filename, is_malware
```

**Breakdown:**
- `mvdedup(split(Image, "\\"))`: Split path into multivalue field, remove duplicates
- `mvindex(filename, -1)`: Select last element (actual filename)
- `dedup`: Remove duplicate entries

### The inputlookup Command

```splunk
| inputlookup malware_lookup.csv
```

> 📌 Retrieves all records from lookup file without joining to search results. Used to verify lookup content.

### Time Range Commands

```splunk
index="main" earliest=-7d EventCode!=1
```

> 📌 Retrieves events from last 7 days where EventCode is NOT 1. Use negative numbers for relative time.

### The transaction Command

```splunk
index="main" sourcetype="WinEventLog:Sysmon" (EventCode=1 OR EventCode=3) 
| transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m 
| table Image 
| dedup Image
```

> 🔴 **THREAT HUNTING USE CASE**: Groups events sharing common characteristics.
> - Groups by Image field
> - Starts with EventCode=1 (process creation)
> - Ends with EventCode=3 (network connection)
> - Max 1-minute window
> - Identifies sequences of process creation followed by network connection - useful for detecting malware behavior

### Subsearches

```splunk
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 
NOT [ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | top limit=100 Image | fields Image ] 
| table _time, Image, CommandLine, User, ComputerName
```

> 🔴 **RARE PROCESS HUNTING**:
> - Main search: Process creation events
> - `NOT []`: Excludes subsearch results
> - Subsearch: Returns top 100 most common processes
> - Result: Shows rare processes not in top 100 - may indicate malicious activity

> ⚠️ **NOTE**: This type of search can generate a lot of noise in environments where new and unique processes are frequently created. Careful tuning and context are important.

---

## 5. How To Identify The Available Data

### Approach 1: Using SPL Commands

#### List All Indexes

```splunk
| eventcount summarize=false index=* | table index
```

> 📌 Uses eventcount to count events in all indexes. `summarize=false` shows counts separately.

#### List All Source Types

```splunk
| metadata type=sourcetypes
```

> 📌 Returns all sourcetypes with metadata: firstTime, lastTime, totalCount

#### List Source Types (Simplified)

```splunk
| metadata type=sourcetypes index=* | table sourcetype
```

#### List All Data Sources

```splunk
| metadata type=sources index=* | table source
```

#### View Raw Data for Specific Sourcetype

```splunk
sourcetype="WinEventLog:Security" | table _raw
```

> 📌 Shows raw event data for specified sourcetype

#### View All Fields for Sourcetype

```splunk
sourcetype="WinEventLog:Security" | table *
```

> ⚠️ Can produce very wide table if many fields exist

#### Specific Field Extraction

```splunk
sourcetype="WinEventLog:Security" | fields Account_Name, EventCode | table Account_Name, EventCode
```

#### Field Summary

```splunk
sourcetype="WinEventLog:Security" | fieldsummary
```

> 📌 **FIELDSUMMARY OUTPUT**:
> | Field | Description |
> |-------|-------------|
> | field | The name of the field |
> | count | Number of events containing the field |
> | distinct_count | Number of distinct values |
> | is_exact | Whether count is exact or estimated |
> | max | Maximum value |
> | mean | Mean value |
> | min | Minimum value |
> | numeric_count | Number of numeric values |
> | stdev | Standard deviation |
> | values | Sample values |
> | modes | The most common values |
> | numBuckets | Number of buckets used to estimate distinct count |

> ⚠️ Note: Values are calculated based on search results. Ensure time range is large enough to capture all possible fields.

#### Event Distribution Over Time

```splunk
index=* sourcetype=* | bucket _time span=1d | stats count by _time, index, sourcetype | sort - _time
```

> 📌 Groups events into 1-day buckets, counts by time/index/sourcetype

#### Rare Event Types

```splunk
index=* sourcetype=* | rare limit=10 index, sourcetype
```

> 📌 Finds 10 rarest combinations - may indicate abnormal behavior

#### Rare Parent Processes

```splunk
index="main" | rare limit=20 useother=f ParentImage
```

> 📌 Shows 20 least common ParentImage values

#### Fields with Low Count

```splunk
index=* sourcetype=* | fieldsummary | where count < 100 | table field, count, distinct_count
```

> 📌 Shows fields appearing in less than 100 events

#### Event Diversity

```splunk
index=* | sistats count by index, sourcetype, source, host
```

> 📌 Shows event diversity across indexes, sources, and hosts

#### Rare Field Combinations

```splunk
index=* sourcetype=* | rare limit=10 field1, field2, field3
```

> 📌 Find uncommon combinations of field values. Replace field1, field2, field3 with actual field names.

---

### Approach 2: Using Splunk User Interface

> 🔴 **UI-BASED IDENTIFICATION**:

1. **Data Sources**: Settings → Data inputs → Review input methods
2. **Data Events**: Search & Reporting app → Fast/Verbose mode
3. **Fields**: Click event → View Selected/Interesting/All fields
4. **Data Models**: Settings → Data Models → Explore hierarchical structures

#### Search Modes

![Fast Mode](https://github.com/user-attachments/assets/e67809cb-3ad2-404f-8580-c6f3cf6a4816)

> 📌 **Search Modes**:
> - **Fast Mode**: Quick scanning through data
> - **Verbose Mode**: Dive deep into event details
> - **Smart Mode**: Auto-detect best mode

#### Event Details

![Event Details](https://github.com/user-attachments/assets/9ccac67c-0a33-4c92-bb87-432d8c813242)

> 📌 Click any event to expand and view:
> - Raw event data
> - All extracted fields
> - Selected Fields (always shown: host, source, sourcetype)
> - Interesting Fields (appear in ≥20% of events)

#### Data Models

![Data Models](https://github.com/user-attachments/assets/e950f00b-efea-4346-9239-73b22afc4390)

> 📌 **Data Models** provide hierarchical view of data:
> - Access: Settings → Data Models
> - Each model has objects with relevant fields
> - No SPL knowledge required

#### Pivots

![Pivots](https://github.com/user-attachments/assets/91e34536-4e67-4dbb-b707-9d3d076c8bbf)

![Pivot Objects](https://github.com/user-attachments/assets/777196e0-65c5-40c6-b865-a4fe96aaab84)

> 📌 **Pivots**: Drag-and-drop interface for reports/visualizations without writing SPL

---

## 6. Practical Exercises

### Key Exercises Summary

> 📌 **SPLUNK PRACTICE TASKS**:

1. **Data Source Identification** - Use metadata commands to identify available indexes and sourcetypes
2. **Field Exploration** - Use fieldsummary to understand available fields
3. **Process Analysis** - Search for Sysmon EventCode=1 (process creation)
4. **Network Connection Analysis** - Search for EventCode=3 (network connections)
5. **Threat Hunting** - Use transaction command to identify malicious process sequences
6. **Lookup Enrichment** - Create and use lookup tables for malware detection

> 🔴 **Remember**: Always follow your organization's data governance policies when exploring data!

---

### SPL Reference Resources

- [Splunk Search Reference](https://docs.splunk.com/Documentation/SCS/current/SearchReference/Introduction)
- [Splunk Cloud Search Reference](https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/)
- [Splunk Cloud Search](https://docs.splunk.com/Documentation/SplunkCloud/latest/Search/)

---

### Common Sysmon Event Codes Reference

| Event ID | Description |
|----------|-------------|
| **1** | Process Create |
| **3** | Network Connection |
| **5** | Process Terminated |
| **6** | Driver Loaded |
| **8** | CreateRemoteThread |
| **10** | ProcessAccess |
| **11** | FileCreate |
| **12** | RegistryEvent (Object Create/Delete) |
| **13** | RegistryEvent (Value Set) |
| **15** | FileCreateStreamHash |
| **22** | DNSEvent |
| **23** | FileDelete |

---

*Module 5/15 - Understanding Log Sources & Investigating with Splunk*
*Built with research + HTB Academy materials*










































Understanding Log Sources & Investigating with Splunk
Understanding Log Sources & Investigating with Splunk 100%

Section 2 / 6
Go to Questions
Using Splunk Applications
Splunk Applications

Splunk applications, or apps, are packages that we add to our Splunk Enterprise or Splunk Cloud deployments to extend capabilities and manage specific types of operational data. Each application is tailored to handle data from specific technologies or use cases, effectively acting as a pre-built knowledge package for that data. Apps can provide capabilities ranging from custom data inputs, custom visualizations, dashboards, alerts, reports, and more.

Splunk Apps enable the coexistence of multiple workspaces on a single Splunk instance, catering to different use cases and user roles. These ready-made apps can be found on Splunkbase.

As an integral part of our cybersecurity operations, the Splunk apps designed for Security Information and Event Management (SIEM) purposes provide a range of capabilities to enhance our ability to detect, investigate, and respond to threats. They are designed to ingest, analyze, and visualize security-related data, enabling us to detect complex threats and perform in-depth investigations.

When using these apps in our Splunk environment, we need to consider factors such as data volume, hardware requirements, and licensing. Many apps can be resource-intensive, so we must ensure our Splunk deployment is sized correctly to handle the additional workload. Further, it's also important to ensure we have the correct licenses for any premium apps, and that we are aware of the potential for increased license usage due to the added data inputs.

In this segment, we'll be leveraging the Sysmon App for Splunk developed by Mike Haag.

To download, add, and use this application, follow the steps delineated below:

    Sign up for a free account at splunkbase

    <img width="2091" height="969" alt="image" src="https://github.com/user-attachments/assets/09c68d8d-e8fb-42a8-a0a7-79e110c1790c" />

    Splunkbase homepage with text 'Get more out of Splunk with applications' and icons for apps like AWS, Cisco, and Zoom. Options to submit an app or log in.



    
    Once registered, log into your account
    Head over to the Sysmon App for Splunk page to download the application. 
    
    <img width="2085" height="1339" alt="image" src="https://github.com/user-attachments/assets/67191690-2c77-4461-ade3-a284870d88a8" />

    Splunkbase page for Sysmon App for Splunk, offering insights and visibility into Sysmon deployments. Includes download button, app screenshots, version 2.0.0 details, compatibility with Splunk Enterprise, and a 5-star rating.

    
    Add the application as follows to your search head. 
    <img width="2085" height="727" alt="image" src="https://github.com/user-attachments/assets/8837ea63-83c8-402e-9786-12dacc22204e" />

    
    Splunk Enterprise home page with options for Search & Reporting, Splunk Essentials, Splunk Secure Gateway, and Upgrade Readiness App. Manage Apps gear icon highlighted.

    <img width="2089" height="583" alt="image" src="https://github.com/user-attachments/assets/c2046f3e-49fb-40ad-b174-20e665bb5d2c" />

    Splunk Apps page showing a list of apps like SplunkForwarder and Log Event Alert Action. Options to browse more apps, install from file, and create app. Actions include enabling and editing properties.

    <img width="2087" height="797" alt="image" src="https://github.com/user-attachments/assets/7dfc3530-8e07-4070-9310-23436c7768cd" />

    Splunk interface for uploading an app from a file. File selected: sysmon-app-for-splunk_200.tgz. Option to upgrade app if it exists, with 'Upload' and 'Cancel' buttons.


    
    Adjust the application's macro so that events are loaded as follows. 
    <img width="2155" height="897" alt="image" src="https://github.com/user-attachments/assets/75f01a1e-d193-4fad-bc10-e9c325f19164" />

    Splunk Enterprise home page with apps like Search & Reporting, Splunk Essentials, and Sysmon App for Splunk. Settings menu open with options including Advanced Search.

    <img width="2159" height="517" alt="image" src="https://github.com/user-attachments/assets/94e40a09-c907-4d43-bbd0-bd7434a339f7" />

    Splunk Advanced Search page with options to create and edit search macros and commands. Includes 'Add new' button for search macros and commands.

    <img width="2157" height="501" alt="image" src="https://github.com/user-attachments/assets/a7407ab0-87ff-4106-a221-fda07f2b25a4" />

    Splunk Enterprise interface showing 'Search macros' with one item: 'sysmon' under 'Sysmon App for Splunk', definition 'sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"'. Options for visibility, owner, and status are displayed


    <img width="2159" height="1053" alt="image" src="https://github.com/user-attachments/assets/b6bff189-d74d-4a68-acf8-dcce2caba3a6" />

    Splunk interface for editing 'sysmon' search macro, showing definition field with 'index="main" sourcetype="WinEventLog:Sysmon"', and options for arguments, validation expression, and error message.


Let's access the Sysmon App for Splunk by locating it in the "Apps" column on the Splunk home page and head over to the File Activity tab. 
<img width="2155" height="1257" alt="image" src="https://github.com/user-attachments/assets/189bc9eb-5caf-41f6-98ad-98d32fcd7585" />

Splunk interface showing 'File Creation Overview' with a warning about a missing dashboard version. Dropdown set to 'Last 24 hours' and 'Search is waiting for input' messages displayed.

Let's now specify "All time" on the time picker and click "Submit". Results are generated successfully; however, no results are appearing in the "Top Systems" section.

<img width="2159" height="1743" alt="image" src="https://github.com/user-attachments/assets/74765fce-ec62-4dc5-a2c8-0b52893ab44f" />

Splunk interface showing 'File Creation Overview' with a graph of file creation over time, a list of top files created, and 'Top Systems' section showing 'No results found'. Dropdown set to 'All time' and 'Edit' option visible.



We can fix that by clicking on "Edit" (upper right hand corner of the screen) and editing the search. 

<img width="2157" height="1663" alt="image" src="https://github.com/user-attachments/assets/5362c2aa-1d80-43ef-a157-8a39c4725a33" />

Splunk interface showing 'File Creation Overview' with a graph of file creation over time, a list of top files created, and 'Top Systems' section showing 'No results found'. Dropdown set to 'All time' and 'Edit search' option visible.


The Sysmon Events with ID 11 do not contain a field named Computer, but they do include a field called ComputerName. Let's fix that and click "Apply" 

<img width="2157" height="1477" alt="image" src="https://github.com/user-attachments/assets/9a13cee4-9dd7-46c2-a17d-36400594558c" />

Splunk 'Edit Search' interface with search string 'sysmon EventCode=11 | top ComputerName', options for time range, auto refresh delay, and refresh indicator. Apply and cancel buttons visible.

Results should now be generated successfully in the "Top Systems" section.
<img width="2161" height="1645" alt="image" src="https://github.com/user-attachments/assets/6ede27b9-5679-4602-8518-1694ad6d8f1c" />


Splunk 'File Creation Overview' dashboard with a graph of file creation over time, dropdown set to 'All time', and a list of top files created. Options to edit and save the dashboard are visible.

Feel free to explore and experiment with this Splunk application. An excellent exercise is to modify the searches when no results are generated due to non-existent fields being specified, continuing until the desired results are obtained.

Practical Exercises

Navigate to the bottom of this section and click on Click here to spawn the target system!

Now, navigate to http://[Target IP]:8000, open the Sysmon App for Splunk application, and answer the questions below.
Connect to HTB
Target(s)

Spawn the target system to get IPs and answer questions


    Question 1

    +1
    Access the Sysmon App for Splunk and go to the "Reports" tab. Fix the search associated with the "Net - net view" report and provide the complete executed command as your answer. Answer format: net view /Domain:_.local
    Question 2

    +1
    Access the Sysmon App for Splunk, go to the "Network Activity" tab, and choose "Network Connections". Fix the search and provide the number of connections that SharpHound.exe has initiated as your answer.

2 / 6 Se


