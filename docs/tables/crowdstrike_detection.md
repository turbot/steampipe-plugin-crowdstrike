---
title: "Steampipe Table: crowdstrike_detection - Query CrowdStrike Detections using SQL"
description: "Allows users to query CrowdStrike Detections, specifically details related to detection ID, status, and behavior. This provides insights into potential security threats and incidents."
---

# Table: crowdstrike_detection - Query CrowdStrike Detections using SQL

CrowdStrike is a cybersecurity technology firm that provides endpoint security, threat intelligence, and cyberattack response services. It offers a cloud-native endpoint security platform that combines next-generation antivirus, endpoint detection and response (EDR), cyber threat intelligence, and proactive threat hunting. CrowdStrike's platform is designed to stop breaches by preventing and responding to all types of attacks.

## Table Usage Guide

The `crowdstrike_detection` table provides insights into potential security threats and incidents within CrowdStrike's endpoint security platform. As a cybersecurity analyst, explore detection-specific details through this table, including detection ID, status, and behavior. Utilize it to uncover information about threats, such as their current status, associated behaviors, and the capabilities to respond to these threats.

## Examples

### Basic info
Explore which devices have reported detections, including details such as the platform and operating system. This can assist in understanding the scope of potential security threats and their distribution across different systems.

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
Explore recent security detections to identify potential threats and vulnerabilities. This query is particularly useful for maintaining an up-to-date understanding of your system's security landscape over the past three months.

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
Assess the elements within the CrowdStrike database to identify any detections that have a severity level exceeding a certain threshold. This can be useful for prioritizing responses to potential threats based on their severity.

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
Explore which detections have occurred on devices within a specific network. This can be useful for identifying potential security threats or breaches within that network.

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
Discover the segments that have open detections in the CrowdStrike system to understand potential security threats. This allows for proactive management of vulnerabilities and ensures prompt action can be taken to address them.

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
Explore recent open detections to identify potential security threats. This query is particularly useful for quickly assessing and responding to incidents that have occurred within the last four days.

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
This query is useful for identifying a specific security threat in a system, including when it was created and its current status. It helps in understanding the threat landscape of a particular device by providing details about the device's platform and operating system.

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