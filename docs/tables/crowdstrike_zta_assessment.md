---
title: "Steampipe Table: crowdstrike_zta_assessment - Query CrowdStrike ZTA Assessments using SQL"
description: "Allows users to query CrowdStrike ZTA Assessments, providing insights into the security posture of devices within an organization's network."
---

# Table: crowdstrike_zta_assessment - Query CrowdStrike ZTA Assessments using SQL

CrowdStrike ZTA Assessments is a feature within CrowdStrike Falcon that provides a security posture assessment of devices within an organization's network. It uses Zero Trust principles to evaluate and report on the security risks associated with each device. These assessments can help organizations identify vulnerabilities and enforce security policies.

## Table Usage Guide

The `crowdstrike_zta_assessment` table provides insights into the security posture of devices within an organization's network using CrowdStrike Falcon. As a security analyst or IT administrator, explore device-specific details through this table, including security risks and vulnerabilities. Utilize it to uncover information about the security posture of each device, helping to identify potential security risks and enforce security policies.

## Examples

### Basic info
Explore the security posture of your devices by assessing their risk levels and the platforms they operate on.

```sql
select
  device_id,
  aid,
  assessment,
  event_platform
from
  crowdstrike_zta_assessment;
```

### List Zero Trust assessments with assessment score over a threshold
Explore which Zero Trust assessments exceed a certain score threshold. This is useful for identifying devices that may require further investigation or action due to their high assessment scores.

```sql
select
  device_id,
  aid,
  assessment,
  event_platform,
  assessment ->> 'overall' as overall
from
  crowdstrike_zta_assessment
where
  (assessment ->> 'overall')::int > 92;
```

### List device IDs with firewalls disabled
Discover the segments that have their firewalls disabled, which allows you to identify potential security risks and take necessary actions to mitigate them. This is essential for maintaining the security integrity of your devices.

```sql
select
  device_id,
  event_platform
from
  crowdstrike_zta_assessment,
  jsonb_array_elements(assessment_items -> 'os_signals') as t
where
  t ->> 'signal_id' like 'application_firewall_%'
  and t ->> 'meets_criteria' = 'no'
```