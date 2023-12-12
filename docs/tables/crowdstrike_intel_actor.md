---
title: "Steampipe Table: crowdstrike_intel_actor - Query CrowdStrike Intel Actors using SQL"
description: "Allows users to query CrowdStrike Intel Actors, specifically providing information about threat actors, their aliases, and associated metadata."
---

# Table: crowdstrike_intel_actor - Query CrowdStrike Intel Actors using SQL

CrowdStrike Intel Actors are entities that represent threat actors in the cybersecurity landscape. They are characterized by their aliases, motivations, capabilities, and the specific types of targets they are known to attack. This information is crucial for understanding potential threats and implementing appropriate security measures.

## Table Usage Guide

The `crowdstrike_intel_actor` table provides insights into threat actors within CrowdStrike's cybersecurity framework. As a cybersecurity analyst, explore actor-specific details through this table, including their aliases, motivations, and targets. Utilize it to uncover information about potential threats, their capabilities, and the specific types of targets they are known to attack.

## Examples

### Basic info
Explore the basic details of potential threat actors in the CrowdStrike intelligence database. This can help to understand the types of threats your system may face and inform your cybersecurity strategies.

```sql+postgres
select
  name,
  slug,
  description,
  actor_type
from
  crowdstrike_intel_actor;
```

```sql+sqlite
select
  name,
  slug,
  description,
  actor_type
from
  crowdstrike_intel_actor;
```

### List actors which have been active in the last 3 months
Discover actors who have recently been active in your network, specifically within the last three months. This query is useful in identifying potential security threats and understanding their nature.

```sql+postgres
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

```sql+sqlite
select
  name,
  slug,
  description,
  actor_type
from
  crowdstrike_intel_actor
where
  last_activity_date > date('now','-3 months');
```

### List actors from a specific origin
Explore which actors in your cybersecurity network originate from a specific location. This is useful for identifying potential security threats linked to that location.

```sql+postgres
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

```sql+sqlite
select
  id,
  known_as,
  name,
  url
from
  crowdstrike_intel_actor,
  json_each(origins) as o
where
  json_extract(o.value, '$.slug') = 'cn';
```