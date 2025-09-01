---
title: "Steampipe Table: crowdstrike_alert - Query CrowdStrike Alerts using SQL"
description: "Allows users to query CrowdStrike Alerts, specifically the detection of threats and incidents across the CrowdStrike platform using the new Alerts API."
---

# Table: crowdstrike_alert - Query CrowdStrike Alerts using SQL

CrowdStrike Alerts is a feature within the CrowdStrike Falcon platform that identifies potential threats and incidents. It uses advanced AI and indicator-of-compromise (IOC) sweeps to detect malicious activities and behaviors. This table uses the new Alerts API (replacing the deprecated Detects API) and provides detailed information about the threat, including the threat family, tactics, techniques, and procedures (TTPs), allowing for a comprehensive understanding of the threat landscape.

## Table Usage Guide

The `crowdstrike_alert` table provides insights into threat alerts within the CrowdStrike Falcon platform using the new Alerts API. As a cybersecurity analyst, use this table to explore detailed information about detected threats, including their tactics, techniques, and procedures. Leverage it to gain a comprehensive understanding of the threat landscape, identify potential vulnerabilities, and enhance your organization's security posture.

**Note:** This table uses the new Alerts API which replaces the deprecated Detects API. The Detects API will reach end-of-life on September 30, 2025. For backward compatibility, the `crowdstrike_detection` table is still available but uses the deprecated API.

## Examples

### Basic info

Explore which alerts were made in your system, when they were identified, and the devices they originated from. This is particularly useful for understanding the security landscape of your network and identifying potential vulnerabilities.

```sql+postgres
select
  composite_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status,
  severity,
  confidence,
  display_name,
  description
from
  crowdstrike_alert;
```

```sql+sqlite
select
  composite_id,
  created_timestamp,
  json_extract(device, '$.device_id') as device_id,
  json_extract(device, '$.hostname') as hostname,
  json_extract(device, '$.platform_name') as platform_name,
  json_extract(device, '$.os_version') as os_version,
  status,
  severity,
  confidence,
  display_name,
  description
from
  crowdstrike_alert;
```

### List alerts from the last 3 months

Explore recent security alerts to understand potential vulnerabilities. This query is useful in identifying threats to your system over the past three months, helping to enhance your cybersecurity measures.

```sql+postgres
select
  composite_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status,
  severity,
  confidence,
  display_name
from
  crowdstrike_alert
where
  created_timestamp > current_date - interval '3 months';
```

```sql+sqlite
select
  composite_id,
  created_timestamp,
  json_extract(device, '$.device_id') as device_id,
  json_extract(device, '$.hostname') as hostname,
  json_extract(device, '$.platform_name') as platform_name,
  json_extract(device, '$.os_version') as os_version,
  status,
  severity,
  confidence,
  display_name
from
  crowdstrike_alert
where
  created_timestamp > date('now','-3 month');
```

### List alerts with a `severity` over a threshold

Explore which alerts exceed a certain severity level to prioritize your security response. This is particularly useful in large systems where managing and responding to all alerts may be overwhelming.

```sql+postgres
select
  composite_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status,
  severity,
  confidence,
  display_name,
  tactic,
  technique
from
  crowdstrike_alert
where
  severity > 50;
```

```sql+sqlite
select
  composite_id,
  created_timestamp,
  json_extract(device, '$.device_id') as device_id,
  json_extract(device, '$.hostname') as hostname,
  json_extract(device, '$.platform_name') as platform_name,
  json_extract(device, '$.os_version') as os_version,
  status,
  severity,
  confidence,
  display_name,
  tactic,
  technique
from
  crowdstrike_alert
where
  severity > 50;
```

### List alerts by MITRE ATT&CK tactic

Explore alerts grouped by MITRE ATT&CK tactics to understand the attack patterns and techniques being used against your environment.

```sql+postgres
select
  tactic,
  technique,
  count(*) as alert_count,
  avg(severity) as avg_severity,
  avg(confidence) as avg_confidence
from
  crowdstrike_alert
where
  tactic is not null
  and technique is not null
group by
  tactic, technique
order by
  alert_count desc;
```

```sql+sqlite
select
  tactic,
  technique,
  count(*) as alert_count,
  avg(severity) as avg_severity,
  avg(confidence) as avg_confidence
from
  crowdstrike_alert
where
  tactic is not null
  and technique is not null
group by
  tactic, technique
order by
  alert_count desc;
```

### List alerts with specific file hashes

Search for alerts associated with specific file hashes to track malware or suspicious files across your environment.

```sql+postgres
select
  composite_id,
  created_timestamp,
  device ->> 'hostname' as hostname,
  filename,
  filepath,
  md5,
  sha1,
  sha256,
  status,
  severity
from
  crowdstrike_alert
where
  md5 is not null
  or sha1 is not null
  or sha256 is not null;
```

```sql+sqlite
select
  composite_id,
  created_timestamp,
  json_extract(device, '$.hostname') as hostname,
  filename,
  filepath,
  md5,
  sha1,
  sha256,
  status,
  severity
from
  crowdstrike_alert
where
  md5 is not null
  or sha1 is not null
  or sha256 is not null;
```

### List alerts by platform

Analyze alerts by platform to understand which operating systems are being targeted and identify platform-specific security concerns.

```sql+postgres
select
  platform,
  count(*) as alert_count,
  avg(severity) as avg_severity,
  avg(confidence) as avg_confidence,
  count(distinct device ->> 'device_id') as unique_devices
from
  crowdstrike_alert
where
  platform is not null
group by
  platform
order by
  alert_count desc;
```

```sql+sqlite
select
  platform,
  count(*) as alert_count,
  avg(severity) as avg_severity,
  avg(confidence) as avg_confidence,
  count(distinct json_extract(device, '$.device_id')) as unique_devices
from
  crowdstrike_alert
where
  platform is not null
group by
  platform
order by
  alert_count desc;
```

### List alerts in devices which belong to a network

Explore which alerts are linked to devices within a specific network to manage security threats effectively. This is useful in identifying potential vulnerabilities or breaches within a particular network segment.

```sql+postgres
select
  composite_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  device ->> 'external_ip' as external_ip,
  network((device ->> 'external_ip')::INET) as network
from
  crowdstrike_alert
where
  network((device ->> 'external_ip')::INET) = '119.18.0.0/28';
```

```sql+sqlite
Error: SQLite does not support CIDR operations.
```

### List open alerts

Identify instances where security threats remain unresolved. This query helps in monitoring and managing potential risks by pinpointing open alerts in your system.

```sql+postgres
select
  composite_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status,
  display_name,
  severity
from
  crowdstrike_alert
where
  status = 'new';
```

```sql+sqlite
select
  composite_id,
  created_timestamp,
  json_extract(device, '$.device_id') as device_id,
  json_extract(device, '$.hostname') as hostname,
  json_extract(device, '$.platform_name') as platform_name,
  json_extract(device, '$.os_version') as os_version,
  status,
  display_name,
  severity
from
  crowdstrike_alert
where
  status = 'new';
```

### List alerts by aggregate_id

Group related alerts together using the aggregate_id, which represents the Agent ID & Process Tree ID, similar to the legacy detection_id.

```sql+postgres
select
  aggregate_id,
  count(*) as alert_count,
  min(created_timestamp) as first_alert,
  max(created_timestamp) as last_alert,
  max(severity) as max_severity,
  max(confidence) as max_confidence,
  array_agg(distinct display_name) as alert_types
from
  crowdstrike_alert
where
  aggregate_id is not null
group by
  aggregate_id
order by
  alert_count desc;
```

```sql+sqlite
select
  aggregate_id,
  count(*) as alert_count,
  min(created_timestamp) as first_alert,
  max(created_timestamp) as last_alert,
  max(severity) as max_severity,
  max(confidence) as max_confidence
from
  crowdstrike_alert
where
  aggregate_id is not null
group by
  aggregate_id
order by
  alert_count desc;
```

### List alerts with IOC context

Explore alerts that have Indicator of Compromise (IOC) information to understand the specific threats and indicators being detected.

```sql+postgres
select
  composite_id,
  created_timestamp,
  device ->> 'hostname' as hostname,
  ioc_type,
  ioc_value,
  ioc_description,
  ioc_source,
  status,
  severity
from
  crowdstrike_alert
where
  ioc_type is not null
  and ioc_value is not null;
```

```sql+sqlite
select
  composite_id,
  created_timestamp,
  json_extract(device, '$.hostname') as hostname,
  ioc_type,
  ioc_value,
  ioc_description,
  ioc_source,
  status,
  severity
from
  crowdstrike_alert
where
  ioc_type is not null
  and ioc_value is not null;
```

### Get a specific alert

Explore specific security alerts by identifying the corresponding device details and status. This is beneficial in scenarios where you need to understand the security status of a particular device and its operating system.

```sql+postgres
select
  composite_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status,
  severity,
  confidence,
  display_name,
  description,
  tactic,
  technique
from
  crowdstrike_alert
where
  composite_id = 'd615xxxxxxxx2158:ind:9a8dxxxxxxxxc74c:1336xxxxxxxx1294-32-7878xxxxxxxx1122';
```

```sql+sqlite
select
  composite_id,
  created_timestamp,
  json_extract(device, '$.device_id') as device_id,
  json_extract(device, '$.hostname') as hostname,
  json_extract(device, '$.platform_name') as platform_name,
  json_extract(device, '$.os_version') as os_version,
  status,
  severity,
  confidence,
  display_name,
  description,
  tactic,
  technique
from
  crowdstrike_alert
where
  composite_id = 'd615xxxxxxxx2158:ind:9a8dxxxxxxxxc74c:1336xxxxxxxx1294-32-7878xxxxxxxx1122';
```
