---
title: "Steampipe Table: crowdstrike_detection - Query CrowdStrike Detections using SQL"
description: "Allows users to query CrowdStrike Detections, specifically the detection of threats and incidents across the CrowdStrike platform."
---

# Table: crowdstrike_detection - Query CrowdStrike Detections using SQL

CrowdStrike Detections is a feature within the CrowdStrike Falcon platform that identifies potential threats and incidents. It uses advanced AI and indicator-of-compromise (IOC) sweeps to detect malicious activities and behaviors. CrowdStrike Detections provide detailed information about the threat, including the threat family, tactics, techniques, and procedures (TTPs), allowing for a comprehensive understanding of the threat landscape.

## Table Usage Guide

The `crowdstrike_detection` table provides insights into threat detections within the CrowdStrike Falcon platform. As a cybersecurity analyst, use this table to explore detailed information about detected threats, including their tactics, techniques, and procedures. Leverage it to gain a comprehensive understanding of the threat landscape, identify potential vulnerabilities, and enhance your organization's security posture.

## Examples

### Basic info
Explore which detections were made in your system, when they were identified, and the devices they originated from. This is particularly useful for understanding the security landscape of your network and identifying potential vulnerabilities.

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status
from
  crowdstrike_detection;
```

### List detections from the last 3 months
Explore recent security detections to understand potential vulnerabilities. This query is useful in identifying threats to your system over the past three months, helping to enhance your cybersecurity measures.

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status
from
  crowdstrike_detection
where
  created_timestamp > current_date - interval '3 months';
```

### List detections with a `severity` over a threshold
Explore which detections exceed a certain severity level to prioritize your security response. This is particularly useful in large systems where managing and responding to all detections may be overwhelming.

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status
from
  crowdstrike_detection
where
  max_severity > 50;
```

### List detections in devices which belong to a network
Explore which detections are linked to devices within a specific network to manage security threats effectively. This is useful in identifying potential vulnerabilities or breaches within a particular network segment.

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  device ->> 'external_ip' as external_ip,
  network((device ->> 'external_ip')::INET) as network
from
  crowdstrike_detection
where
  network((device ->> 'external_ip')::INET) = '119.18.0.0/28';
```

### List open detections
Identify instances where security threats remain unresolved. This query helps in monitoring and managing potential risks by pinpointing open detections in your system.

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status
from
  crowdstrike_detection
where
  status = 'open';
```

### List open detections from the last 4 days
Determine the areas in which open detections have occurred in the past four days, which can help in identifying potential security threats and ensuring timely response to the same.

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status
from
  crowdstrike_detection
where
  status = 'open'
  and now() - created_timestamp > interval '4 days';
```

### Get a specific detection
Explore specific security detections by identifying the corresponding device details and status. This is beneficial in scenarios where you need to understand the security status of a particular device and its operating system.

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status
from
  crowdstrike_detection
where
  detection_id = 'ldt:6f8d8xxxx5b44xxxxxxxxxxb04e0acfa:423017xxxxxxxxxx41';
```