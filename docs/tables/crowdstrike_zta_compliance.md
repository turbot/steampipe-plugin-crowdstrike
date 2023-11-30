---
title: "Steampipe Table: crowdstrike_zta_compliance - Query CrowdStrike Zero Trust Assessment Compliance using SQL"
description: "Allows users to query Zero Trust Assessment Compliance in CrowdStrike, providing insights into the compliance status of each device and potential security risks."
---

# Table: crowdstrike_zta_compliance - Query CrowdStrike Zero Trust Assessment Compliance using SQL

CrowdStrike Zero Trust Assessment (ZTA) Compliance is a feature within the CrowdStrike platform that provides a detailed assessment of each device's compliance status. It helps organizations understand their security posture by identifying devices that may pose a potential risk due to non-compliance with security policies. ZTA Compliance enables organizations to take proactive measures to ensure the security of their devices and data.

## Table Usage Guide

The `crowdstrike_zta_compliance` table provides insights into each device's compliance status within CrowdStrike Zero Trust Assessment. As a security analyst, you can use this table to understand the compliance status of each device, identify potential security risks, and take necessary actions to mitigate these risks. This table is instrumental in maintaining a strong security posture by ensuring all devices comply with your organization's security policies.

## Examples

### Basic info
Gain insights into the average security score across your digital assets, the number of aids associated, and the platforms they are on, to better understand your cybersecurity landscape and compliance status. This can help identify potential vulnerabilities and areas for improvement.

```sql
select
  average_overall_score,
  num_aids,
  platforms
from
  crowdstrike_zta_compliance
```

### List compliance information per platform
Determine the areas in which compliance is being maintained across different operating platforms. This query is useful for understanding the overall security posture and number of assessments conducted on each platform.

```sql
select
  p ->> 'name' as os_platform,
  p ->> 'average_overall_score' as overall_zta_score,
  p ->> 'num_aids' as no_of_assessments
from
  crowdstrike_zta_compliance,
  jsonb_array_elements(platforms) as p
```