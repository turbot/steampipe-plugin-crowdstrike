---
title: "Steampipe Table: crowdstrike_zta_compliance - Query CrowdStrike Zero Trust Assessment Compliances using SQL"
description: "Allows users to query CrowdStrike Zero Trust Assessment Compliances, specifically the compliance of each device with the CrowdStrike security standards."
---

# Table: crowdstrike_zta_compliance - Query CrowdStrike Zero Trust Assessment Compliances using SQL

CrowdStrike Zero Trust Assessment (ZTA) is a security model that requires strict identity verification for every person and device trying to access resources on a private network, regardless of whether they are sitting within or outside of the network perimeter. CrowdStrike ZTA ensures that only authenticated and authorized users and devices can access applications and data. It minimizes the risk of attackers gaining access and moving laterally within the network.

## Table Usage Guide

The `crowdstrike_zta_compliance` table provides insights into device compliance with CrowdStrike's Zero Trust Assessment. As a security engineer, explore device-specific details through this table, including compliance status, device ID, and associated metadata. Utilize it to uncover information about device compliance, such as those not meeting CrowdStrike's security standards, and to verify the security posture of each device.

## Examples

### Basic info
Explore the average security score and the number of aids across different platforms. This analysis is useful for understanding the overall security compliance in your system.

```sql+postgres
select
  average_overall_score,
  num_aids,
  platforms
from
  crowdstrike_zta_compliance
```

```sql+sqlite
select
  average_overall_score,
  num_aids,
  platforms
from
  crowdstrike_zta_compliance
```

### List compliance information per platform
Explore compliance information for each operating system platform, understanding the average overall score and the number of assessments conducted. This can be useful in assessing the security posture and risk management across different platforms.

```sql+postgres
select
  p ->> 'name' as os_platform,
  p ->> 'average_overall_score' as overall_zta_score,
  p ->> 'num_aids' as no_of_assessments
from
  crowdstrike_zta_compliance,
  jsonb_array_elements(platforms) as p
```

```sql+sqlite
select
  json_extract(p.value, '$.name') as os_platform,
  json_extract(p.value, '$.average_overall_score') as overall_zta_score,
  json_extract(p.value, '$.num_aids') as no_of_assessments
from
  crowdstrike_zta_compliance,
  json_each(platforms) as p
```