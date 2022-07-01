# Table: crowdstrike_intel_actor

With the Actors API, Falcon Intel subscribers can search for data about actors that CrowdStrike is tracking.

## Examples

### Basic info

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

```sql
select
  name,
  slug,
  description,
  actor_type
from
  crowdstrike_intel_actor
where
  last_activity_date > (current_date - (interval '3months'));
```

### List actors from a specific origin

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
