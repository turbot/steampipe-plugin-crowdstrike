# Table: crowdstrike_intel_actor

A threat actor, also known as a malicious actor, is any person or organization that intentionally causes harm in the digital sphere.

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
  last_activity_date > current_date - interval '3 months';
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
