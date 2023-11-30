---
title: "Steampipe Table: crowdstrike_intel_actor - Query CrowdStrike Intel Actors using SQL"
description: "Allows users to query CrowdStrike Intel Actors, specifically information about threat actors including their aliases, descriptions, and objectives."
---

# Table: crowdstrike_intel_actor - Query CrowdStrike Intel Actors using SQL

CrowdStrike Intel Actors are part of the CrowdStrike Falcon platform, providing comprehensive information about threat actors. They include details about the actor's aliases, descriptions, objectives, and more. This information is critical in understanding the nature of the threat, the actor's objectives, and potential methods of attack.

## Table Usage Guide

The `crowdstrike_intel_actor` table provides insights into threat actors within the CrowdStrike Falcon platform. As a cybersecurity analyst, you can explore detailed information about these actors through this table, including their aliases, descriptions, objectives, and more. Utilize it to gain a deeper understanding of potential threats, their methods, and objectives, thereby improving your organization's cybersecurity posture.

## Examples

### Basic info
Explore the variety of threat actors in the CrowdStrike intelligence database to gain insights into their characteristics and behaviour. This information can be useful in understanding the landscape of potential cyber threats and preparing appropriate security measures.

```sql
select
  name,
  slug,
  description,
  actor_type
from
  crowdstrike_intel_actor;
```

### List actors which have been active in the last 3 months
Discover the segments that have been active in the recent past in the crowdstrike intel actor database. This is useful for identifying potential threats or areas of interest, based on recent activity.

```sql
select
  name,
  slug,
  description,
  actor_type
from
  crowdstrike_intel_actor
where
  last_activity_date > current_date - interval '3 months';
```

### List actors from a specific origin
Discover the segments that contain actors of a specific origin to better understand their distribution and influence. This can be particularly useful for cybersecurity teams seeking to understand potential threats and their origins.

```sql
select
  id,
  known_as,
  name,
  url
from
  crowdstrike_intel_actor,
  jsonb_array_elements(origins) as o
where
  o ->> 'slug' = 'cn';
```