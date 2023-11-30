---
title: "Steampipe Table: crowdstrike_zta_assessment - Query CrowdStrike Zero Trust Assessment using SQL"
description: "Allows users to query Zero Trust Assessments in CrowdStrike, providing detailed information about the security posture of their organization's devices."
---

# Table: crowdstrike_zta_assessment - Query CrowdStrike Zero Trust Assessment using SQL

CrowdStrike's Zero Trust Assessment is a security feature that evaluates the trustworthiness of devices in an organization's network. It provides a comprehensive view of the security posture of each device, allowing security teams to identify and mitigate potential threats. This assessment is an integral part of CrowdStrike's proactive approach to cybersecurity.

## Table Usage Guide

The `crowdstrike_zta_assessment` table provides insights into the Zero Trust Assessments within CrowdStrike. As a cybersecurity professional, explore device-specific details through this table, including security scores, risk levels, and associated metadata. Utilize it to uncover information about the security posture of devices, such as those with high-risk scores, and to aid in the identification and mitigation of potential threats.

## Examples

### Basic info
Explore the assessments and corresponding platforms for various devices to gain insights into the security status of your network. This is particularly useful in identifying potential weak spots and ensuring the robustness of your cybersecurity measures.

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
Analyze the Zero Trust assessments to identify devices with an assessment score exceeding a certain threshold. This can be useful in maintaining a high standard of network security by pinpointing devices that fall short.

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
Explore which devices have their firewalls disabled to understand potential security vulnerabilities. This can help in identifying areas that need immediate attention to ensure optimal security measures.

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